//! [Module] search/pipeline.zig
//! [Layer] Layer 4 — Slice Materialization & Streaming Search Driver (`materialize`, `searchPrepared`, `drive`)
//! [Role] Orchestrates decompression, BOM/charset transcoding, offset map wiring, sliding buffer management,
//!        and streaming `Reader` execution.
//! [Invariants]
//!   1. Pure UTF-8/raw slice searches execute with zero heap allocation.
//!   2. Streaming reader searches bound buffer growth to `max_line_len` and enforce per-source/per-request byte and time budgets.
//! [HotPath] `searchPrepared` (in-memory slice path) and `drive` (streaming reader path).

const std = @import("std");
const decompress = @import("../codec/decompress.zig");
const encoding = @import("../codec/encoding.zig");
const matcher_mod = @import("../matcher.zig");
const memchr = @import("../finder/memchr.zig");
const regex_mod = @import("../regex.zig");
const sink_mod = @import("../sink.zig");
const cfg_mod = @import("config.zig");
const state_mod = @import("state.zig");
const ring_mod = @import("context_ring.zig");
const format_mod = @import("format.zig");
const line_matcher_mod = @import("line_matcher.zig");
const long_line_mod = @import("long_line.zig");

const SearchConfig = cfg_mod.SearchConfig;
const SliceError = cfg_mod.SliceError;
const ReadError = cfg_mod.ReadError;
const Result = cfg_mod.Result;
const Span = cfg_mod.Span;
const width = cfg_mod.width;
const validateBudgets = cfg_mod.validateBudgets;
const decodeCap = cfg_mod.decodeCap;
const beforeCount = cfg_mod.beforeCount;
const beforeContextCapacity = cfg_mod.beforeContextCapacity;
const bufferWindow = cfg_mod.bufferWindow;
const watchesBinary = cfg_mod.watchesBinary;
const effectiveAllocator = cfg_mod.effectiveAllocator;
const State = state_mod.State;
const resetStats = state_mod.resetStats;
const lineStart = state_mod.lineStart;
const lineEnd = state_mod.lineEnd;
const armClock = state_mod.armClock;
const restoreCounters = state_mod.restoreCounters;
const finishSink = state_mod.finishSink;
const logDetail = state_mod.logDetail;
const noteLimit = state_mod.noteLimit;
const callOpt = state_mod.callOpt;
const noteRejected = state_mod.noteRejected;
const budgetView = state_mod.budgetView;
const stopForBudget = state_mod.stopForBudget;
const stopInMatch = state_mod.stopInMatch;
const maybeProgress = state_mod.maybeProgress;
const rejectEmptyResults = state_mod.rejectEmptyResults;
const preceding = state_mod.preceding;
const canFuse = state_mod.canFuse;
const noteBinary = state_mod.noteBinary;
const isMultilineMatcher = state_mod.isMultilineMatcher;
const isStartAnchoredMatcher = state_mod.isStartAnchoredMatcher;
const multilineWindow = state_mod.multilineWindow;
const lastComplete = state_mod.lastComplete;
const countLines = state_mod.countLines;
const rollConsumed = state_mod.rollConsumed;
const grow = state_mod.grow;
const readClock = state_mod.readClock;
const flagIsSet = state_mod.flagIsSet;
const cancelIsSet = state_mod.cancelIsSet;
const liveIsClosed = state_mod.liveIsClosed;
const pastDeadline = state_mod.pastDeadline;
const overBytes = state_mod.overBytes;
const scanRemaining = state_mod.scanRemaining;
const overDecompressed = state_mod.overDecompressed;
const rememberBefore = ring_mod.rememberBefore;
const matchBuffer = line_matcher_mod.matchBuffer;
const longTail = long_line_mod.longTail;
const pumpLong = long_line_mod.pumpLong;
const makeRoom = long_line_mod.makeRoom;
const compactBuf = long_line_mod.compactBuf;

pub const Prepared = struct {
    bytes: []const u8,
    owned: []u8 = &.{},
    transformed: bool = false,
    alloc: ?std.mem.Allocator = null,
    base_searchable_offset: u64 = 0,
    offset_map: decompress.OffsetMap = .{},
    decompress_map: decompress.OffsetMap = .{},
    decompressed_bytes: u64 = 0,
    decompress_limit_hit: bool = false,
    corrupt_stream: bool = false,

    pub fn deinit(self: *Prepared) void {
        if (self.owned.len != 0) if (self.alloc) |alloc| alloc.free(self.owned);
        if (self.alloc) |alloc| {
            self.offset_map.deinit(alloc);
            self.decompress_map.deinit(alloc);
        }
    }
};

fn stashDecompressedInScratch(prep: *Prepared, config: SearchConfig) error{OutOfMemory}!void {
    if (config.scratch_pool) |sp| {
        if (prep.owned.len != 0) {
            const dec = prep.owned;
            if (sp.decode_buf.len < dec.len) {
                if (sp.decode_buf.len == 0) {
                    sp.decode_buf = try sp.allocator.alloc(u8, dec.len);
                } else {
                    sp.decode_buf = try sp.allocator.realloc(sp.decode_buf, dec.len);
                }
            }
            @memcpy(sp.decode_buf[0..dec.len], dec);
            if (prep.alloc) |alloc| alloc.free(dec);
            prep.owned = &.{};
            prep.bytes = sp.decode_buf[0..dec.len];
        }
    }
}

pub fn materialize(haystack: []const u8, config: SearchConfig) SliceError!Prepared {
    var prep = Prepared{
        .bytes = haystack,
        .decompressed_bytes = config.decompressed_bytes,
    };
    errdefer prep.deinit();

    var current = haystack;
    var was_decompressed = false;
    if (config.compression != .none) {
        const det = if (config.compression == .auto) decompress.sniff(haystack, true) else .gzip;
        if (det != .raw and det != .need_more) {
            const alloc = effectiveAllocator(config) orelse return error.OutOfMemory;
            prep.alloc = alloc;
            const max_dec = config.max_decompressed_bytes orelse config.max_source_bytes;
            if (decompress.decompressSlice(
                alloc,
                haystack,
                config.compression,
                config.decompressed_bytes,
                max_dec,
                config.max_compression_ratio,
                &prep.decompressed_bytes,
                &prep.decompress_map,
            )) |maybe_dec| {
                if (maybe_dec) |dec_buf| {
                    prep.owned = dec_buf;
                    prep.transformed = true;
                    prep.bytes = dec_buf;
                    current = dec_buf;
                    was_decompressed = true;
                }
            } else |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.DecompressLimit => {
                    prep.bytes = &.{};
                    prep.decompress_limit_hit = true;
                    return prep;
                },
                error.CorruptStream => {
                    prep.bytes = &.{};
                    prep.corrupt_stream = true;
                    return prep;
                },
            }
        }
    }

    const resolved = encoding.resolveHint(config.encoding, config.charset);
    if (resolved == .none) {
        if (was_decompressed) try stashDecompressedInScratch(&prep, config);
        return prep;
    }

    const resume_raw: ?usize = if (!was_decompressed and config.resume_from > 0 and config.continuation != null) blk: {
        const rr = config.continuation.?.raw_resume_at;
        if (rr > 0 and rr <= current.len) break :blk @intCast(rr);
        break :blk null;
    } else null;

    const cap = decodeCap(config);
    const bom_kind = encoding.sniff(current, true);
    switch (bom_kind) {
        .raw, .need_more => {
            const target: encoding.Sniff = switch (resolved) {
                .auto => {
                    if (was_decompressed) try stashDecompressedInScratch(&prep, config);
                    return prep;
                },
                .none => {
                    if (was_decompressed) try stashDecompressedInScratch(&prep, config);
                    return prep;
                },
                .utf8 => if (encoding.validUtf8(current)) {
                    if (was_decompressed) try stashDecompressedInScratch(&prep, config);
                    return prep;
                } else .utf8,
                .utf16le => .utf16le,
                .utf16be => .utf16be,
                .gbk => .gbk,
                .latin1 => .latin1,
            };
            const src_slice = if (resume_raw) |rr| current[rr..] else current;
            const init_raw: u64 = if (resume_raw) |rr| @intCast(rr) else 0;
            if (encoding.decodedSize(target, src_slice) > cap) return error.DecodeLimit;
            const alloc = effectiveAllocator(config) orelse return error.OutOfMemory;
            prep.alloc = alloc;
            prep.transformed = true;
            if (config.scratch_pool) |sp| {
                const decoded = try encoding.convertScratchWithMap(sp.allocator, &sp.decode_buf, alloc, target, src_slice, init_raw, &prep.offset_map);
                if (prep.owned.len != 0) {
                    alloc.free(prep.owned);
                    prep.owned = &.{};
                }
                prep.bytes = decoded;
            } else {
                const owned = try encoding.convertAllocWithMap(alloc, target, src_slice, init_raw, &prep.offset_map);
                if (prep.owned.len != 0) alloc.free(prep.owned);
                prep.owned = owned;
                prep.bytes = owned;
            }
            if (resume_raw != null) prep.base_searchable_offset = config.resume_from;
            return prep;
        },
        .utf8 => {
            const rest = if (current.len >= 3) current[3..] else current[0..0];
            prep.offset_map.base_raw_offset = 3;
            if (encoding.validUtf8(rest)) {
                if (was_decompressed) {
                    try stashDecompressedInScratch(&prep, config);
                    prep.bytes = if (prep.bytes.len >= 3) prep.bytes[3..] else prep.bytes[0..0];
                } else {
                    prep.bytes = rest;
                }
                return prep;
            }
            const src_slice = if (resume_raw) |rr| (if (rr >= 3) current[rr..] else rest) else rest;
            const init_raw: u64 = if (resume_raw) |rr| (if (rr >= 3) @intCast(rr) else 3) else 3;
            if (encoding.decodedSize(.utf8, src_slice) > cap) return error.DecodeLimit;
            const alloc = effectiveAllocator(config) orelse return error.OutOfMemory;
            prep.alloc = alloc;
            prep.transformed = true;
            if (config.scratch_pool) |sp| {
                const decoded = try encoding.convertScratchWithMap(sp.allocator, &sp.decode_buf, alloc, .utf8, src_slice, init_raw, &prep.offset_map);
                if (prep.owned.len != 0) {
                    alloc.free(prep.owned);
                    prep.owned = &.{};
                }
                prep.bytes = decoded;
            } else {
                const owned = try encoding.convertAllocWithMap(alloc, .utf8, src_slice, init_raw, &prep.offset_map);
                if (prep.owned.len != 0) alloc.free(prep.owned);
                prep.owned = owned;
                prep.bytes = owned;
            }
            if (resume_raw != null and resume_raw.? >= 3) prep.base_searchable_offset = config.resume_from;
            return prep;
        },
        .utf16le, .utf16be => |kind| {
            const payload = if (current.len >= 2) current[2..] else current[0..0];
            const src_slice = if (resume_raw) |rr| (if (rr >= 2) current[rr..] else payload) else payload;
            const init_raw: u64 = if (resume_raw) |rr| (if (rr >= 2) @intCast(rr) else 2) else 2;
            if (encoding.decodedSize(kind, src_slice) > cap) {
                return error.DecodeLimit;
            }
            const alloc = effectiveAllocator(config) orelse return error.OutOfMemory;
            prep.alloc = alloc;
            prep.transformed = true;
            if (config.scratch_pool) |sp| {
                const decoded = try encoding.convertScratchWithMap(sp.allocator, &sp.decode_buf, alloc, kind, src_slice, init_raw, &prep.offset_map);
                if (prep.owned.len != 0) {
                    alloc.free(prep.owned);
                    prep.owned = &.{};
                }
                prep.bytes = decoded;
            } else {
                const owned = try encoding.convertAllocWithMap(alloc, kind, src_slice, init_raw, &prep.offset_map);
                if (prep.owned.len != 0) alloc.free(prep.owned);
                prep.owned = owned;
                prep.bytes = owned;
            }
            if (resume_raw != null and resume_raw.? >= 2) prep.base_searchable_offset = config.resume_from;
            return prep;
        },
        .gbk, .latin1 => unreachable,
    }
}

/// Legacy callback entry point that searches `haystack`. Line slices point directly into `haystack` when no BOM or transcoding is involved.
/// `name` is passed only to legacy `begin`. The service entry point is `searchSourceSlice`.

fn isAnyMatcherRegex(any_m: matcher_mod.AnyMatcher) bool {
    if (any_m.vtable.is_capture_regex) return true;
    var dummy: regex_mod.Regex = undefined;
    const ptr_mut: *regex_mod.Regex = &dummy;
    const ptr_const: *const regex_mod.Regex = &dummy;
    return any_m.vtable == matcher_mod.AnyMatcher.init(regex_mod.Regex, ptr_mut).vtable or
        any_m.vtable == matcher_mod.AnyMatcher.init(regex_mod.Regex, ptr_const).vtable or
        any_m.vtable == matcher_mod.AnyMatcher.init(*regex_mod.Regex, ptr_mut).vtable or
        any_m.vtable == matcher_mod.AnyMatcher.init(*const regex_mod.Regex, ptr_const).vtable;
}

pub fn searchPrepared(
    comptime S: type,
    sink: *S,
    prepared: *const Prepared,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) SliceError!Result {
    const haystack = prepared.bytes;
    validateBudgets(config) catch |err| {
        logDetail(config, name, err);
        return err;
    };
    resetStats(matcher);
    var state = State{};
    const MChild = state_mod.MatcherType(@TypeOf(matcher));
    if (MChild == regex_mod.Regex) {
        state.capture_regex = if (@typeInfo(@TypeOf(matcher)) == .pointer) matcher else &matcher;
    } else if (MChild == matcher_mod.AnyMatcher) {
        const any_m: matcher_mod.AnyMatcher = if (@typeInfo(@TypeOf(matcher)) == .pointer) matcher.* else matcher;
        if (isAnyMatcherRegex(any_m)) {
            state.capture_regex = @ptrCast(@alignCast(any_m.ctx));
        }
    }
    state.label = name;
    state.decompressed_bytes = prepared.decompressed_bytes;
    state.offset_map = &prepared.offset_map;
    state.offset_map_base = prepared.base_searchable_offset;
    state.decompress_map = &prepared.decompress_map;
    armClock(&state, config);
    const pool_alloc = if (config.scratch_pool) |sp| sp.allocator else effectiveAllocator(config);
    state.text_alloc = pool_alloc;
    if (config.scratch_pool) |sp| {
        state.text_buf = sp.text_buf;
        state.replace_buf = sp.replace_buf;
        state.span_buf = sp.span_buf;
    }
    defer {
        if (config.scratch_pool) |sp| {
            sp.text_buf = state.text_buf;
            sp.replace_buf = state.replace_buf;
            sp.span_buf = state.span_buf;
        } else if (state.text_alloc) |alloc| {
            if (state.text_buf.len != 0) alloc.free(state.text_buf);
            if (state.replace_buf.len != 0) alloc.free(state.replace_buf);
            if (state.span_buf.len != 0) alloc.free(state.span_buf);
        }
    }
    state.ring.cap = beforeCount(config);
    state.ring.stride = config.max_line_len;
    if (config.line_numbers) state.line_number = 1;
    restoreCounters(&state, config);
    if (prepared.decompress_limit_hit) {
        _ = callOpt(S, "begin", sink, .{name});
        noteLimit(&state, .decompressed_bytes);
        return finishSink(S, sink, &state, config);
    }
    if (prepared.corrupt_stream) {
        _ = callOpt(S, "begin", sink, .{name});
        state.soft_error = .read_failed;
        return finishSink(S, sink, &state, config);
    }
    const view = budgetView(haystack, prepared.base_searchable_offset, &state, config);
    if (!callOpt(S, "begin", sink, .{name})) {
        noteRejected(S, &state, sink);
        if (state.paused) {
            state.resume_at = state.abs_base;
            state.resume_line = state.line_number orelse 1;
        }
        return finishSink(S, sink, &state, config);
    }
    if (rejectEmptyResults(&state, config)) return finishSink(S, sink, &state, config);
    if (stopForBudget(&state, config)) return finishSink(S, sink, &state, config);

    if (watchesBinary(config) and config.binary == .quit and canFuse(matcher, config, &state)) {
        const need_ls = line_matcher_mod.needLineStart(S, &state, config);
        const direct_sink = ((comptime !@hasDecl(S, "matched")) or config.match_mode == .earliest) and
            config.resume_from == 0 and !config.files_without_match;
        while (state.pos < view.len and !state.stopped) {
            if (state.exceeded(config) or flagIsSet(config) or stopInMatch(&state, config) or !maybeProgress(S, sink, &state, config)) {
                if (state.exceeded(config)) state.need_close = true;
                state.stopped = true;
                break;
            }
            var nul_at: ?usize = null;
            const found = if (comptime @hasDecl(state_mod.MatcherType(@TypeOf(matcher)), "findWatched"))
                matcher.findWatched(view, state.pos, &nul_at)
            else
                unreachable;
            if (nul_at) |nul| {
                const safe_end = lineStart(view, nul, config);
                if (safe_end > state.pos) {
                    if (!try matchBuffer(S, sink, matcher, view[0..safe_end], &state, config)) {
                        state.stopped = true;
                        break;
                    }
                }
                noteBinary(&state, config, state.abs_base + nul);
                _ = callOpt(S, "binary", sink, .{state.nul_offset.?});
                if (state.hit_byte_cap) noteLimit(&state, .max_bytes);
                return finishSink(S, sink, &state, config);
            }
            const hit = found orelse {
                state.pos = view.len;
                if (flagIsSet(config) or stopInMatch(&state, config) or !maybeProgress(S, sink, &state, config)) state.stopped = true;
                break;
            };
            const hit_line_end = lineEnd(view, @max(hit.end, hit.start), config);
            if (memchr.find(width, view[hit.start..hit_line_end], 0, 0)) |rel| {
                const nul = hit.start + rel;
                const safe_end = lineStart(view, nul, config);
                if (safe_end > state.pos) {
                    if (!try matchBuffer(S, sink, matcher, view[0..safe_end], &state, config)) {
                        state.stopped = true;
                        break;
                    }
                }
                noteBinary(&state, config, state.abs_base + nul);
                _ = callOpt(S, "binary", sink, .{state.nul_offset.?});
                if (state.hit_byte_cap) noteLimit(&state, .max_bytes);
                return finishSink(S, sink, &state, config);
            }
            if (direct_sink and hit.start < view.len and (config.progress_interval == null or config.progress_interval.? == 0)) {
                const ls = if (need_ls) lineStart(view, hit.start, config) else state.pos;
                if (need_ls and ls > state.pos) {
                    countLines(view, ls, &state, config);
                }
                state.limit_count += 1;
                state.pos = hit_line_end;
                const known = state_mod.BufMatch{ .start = hit.start, .end = hit.end, .pattern_id = hit.pattern_id };
                if (!try format_mod.sinkMatched(S, sink, matcher, view[0..hit_line_end], .{ .start = ls, .end = hit_line_end }, known, &state, config)) {
                    state.stopped = true;
                    break;
                }
                if (state.exceeded(config)) {
                    state.stopped = true;
                    state.need_close = true;
                    break;
                }
                continue;
            }
            if (config.progress_interval == null or config.progress_interval.? == 0) {
                const ls = lineStart(view, hit.start, config);
                if (ls > state.pos) {
                    countLines(view, ls, &state, config);
                    state.pos = ls;
                }
            }
            if (!try matchBuffer(S, sink, matcher, view[0..hit_line_end], &state, config)) {
                state.stopped = true;
                break;
            }
        }
        const consumed_w = (!state.stopped or state.pos >= view.len) and !state.output_blocked;
        if (consumed_w and !state.hit_byte_cap and state.soft_error == null) state.scanned_all = true;
        if (state.hit_byte_cap) noteLimit(&state, .max_bytes);
        return finishSink(S, sink, &state, config);
    }

    var skip_match = false;
    if (watchesBinary(config)) {
        var nul_at: ?usize = null;
        if (view.len > 0 and canFuse(matcher, config, &state)) {
            const found = if (comptime @hasDecl(state_mod.MatcherType(@TypeOf(matcher)), "findWatched")) matcher.findWatched(view, 0, &nul_at) else unreachable;
            if (nul_at == null) {
                if (found) |hit| {
                    if (memchr.find(width, view[hit.start..], 0, 0)) |rel| {
                        nul_at = hit.start + rel;
                    } else if (config.progress_interval == null or config.progress_interval.? == 0) {
                        state.pos = lineStart(view, hit.start, config);
                    }
                } else {
                    skip_match = true;
                    state.pos = view.len;
                }
            }
        } else {
            nul_at = memchr.find(width, view, 0, 0);
        }
        if (nul_at) |nul| {
            if (config.binary == .quit) {
                const safe_end = lineStart(view, nul, config);
                if (safe_end > state.pos) {
                    if (!try matchBuffer(S, sink, matcher, view[0..safe_end], &state, config)) {
                        state.stopped = true;
                    }
                }
                if (!state.stopped) {
                    noteBinary(&state, config, state.abs_base + nul);
                    _ = callOpt(S, "binary", sink, .{state.nul_offset.?});
                    state.stopped = true;
                }
                if (state.hit_byte_cap) noteLimit(&state, .max_bytes);
                return finishSink(S, sink, &state, config);
            }
            noteBinary(&state, config, state.abs_base + nul);
            const cont = callOpt(S, "binary", sink, .{state.nul_offset.?});
            if (!cont) state.stopped = true;
        }
    }

    if (!state.stopped) {
        if (skip_match) {
            if (flagIsSet(config) or stopInMatch(&state, config) or !maybeProgress(S, sink, &state, config)) state.stopped = true;
        } else {
            if (!try matchBuffer(S, sink, matcher, view, &state, config)) state.stopped = true;
        }
    }
    const consumed = (!state.stopped or state.pos >= view.len) and !state.output_blocked;
    if (consumed and !state.hit_byte_cap and state.soft_error == null) state.scanned_all = true;
    if (state.hit_byte_cap) noteLimit(&state, .max_bytes);
    return finishSink(S, sink, &state, config);
}


pub fn drive(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    matcher: anytype,
    config: SearchConfig,
    name: []const u8,
    comptime readFn: anytype,
    read_ctx: *anyopaque,
) ReadError!Result {
    validateBudgets(config) catch |err| {
        logDetail(config, name, err);
        return err;
    };
    const pool_alloc = if (config.scratch_pool) |sp| sp.allocator else (effectiveAllocator(config) orelse allocator);
    const stream_alloc = if (config.scratch == null and config.scratch_pool != null)
        config.scratch_pool.?.allocator
    else
        allocator;

    var state = State{};
    const MChild = state_mod.MatcherType(@TypeOf(matcher));
    if (MChild == regex_mod.Regex) {
        state.capture_regex = if (@typeInfo(@TypeOf(matcher)) == .pointer) matcher else &matcher;
    } else if (MChild == matcher_mod.AnyMatcher) {
        const any_m: matcher_mod.AnyMatcher = if (@typeInfo(@TypeOf(matcher)) == .pointer) matcher.* else matcher;
        if (isAnyMatcherRegex(any_m)) {
            state.capture_regex = @ptrCast(@alignCast(any_m.ctx));
        }
    }
    state.label = name;
    state.decompressed_bytes = config.decompressed_bytes;
    armClock(&state, config);
    state.from_reader = true;
    state.text_alloc = pool_alloc;
    if (config.scratch_pool) |sp| {
        state.text_buf = sp.text_buf;
        state.replace_buf = sp.replace_buf;
        state.span_buf = sp.span_buf;
    }
    defer {
        if (config.scratch_pool) |sp| {
            sp.text_buf = state.text_buf;
            sp.replace_buf = state.replace_buf;
            sp.span_buf = state.span_buf;
        } else {
            if (state.text_buf.len != 0) pool_alloc.free(state.text_buf);
            if (state.replace_buf.len != 0) pool_alloc.free(state.replace_buf);
            if (state.span_buf.len != 0) pool_alloc.free(state.span_buf);
        }
    }
    state.ring.cap = beforeCount(config);
    state.ring.stride = config.max_line_len;
    if (state.ring.cap > 0) {
        const bytes = beforeContextCapacity(config);
        if (bytes > 0) {
            if (config.scratch_pool) |sp| {
                if (sp.ring_storage.len < bytes) {
                    if (sp.ring_storage.len == 0) {
                        sp.ring_storage = try sp.allocator.alloc(u8, bytes);
                    } else {
                        sp.ring_storage = try sp.allocator.realloc(sp.ring_storage, bytes);
                    }
                }
                state.ring.storage = sp.ring_storage[0..bytes];
            } else {
                state.ring.storage = try pool_alloc.alloc(u8, bytes);
            }
        }
        state.ring.owned = true;
    }
    defer if (config.scratch_pool == null and state.ring.storage.len != 0) pool_alloc.free(state.ring.storage);
    var hold: []u8 = if (config.scratch_pool) |sp| sp.long_hold else &.{};
    var seen: []bool = if (config.scratch_pool) |sp| sp.long_seen else &.{};
    defer {
        if (config.scratch_pool) |sp| {
            sp.long_hold = hold;
            sp.long_seen = seen;
        } else {
            if (hold.len != 0) pool_alloc.free(hold);
            if (seen.len != 0) pool_alloc.free(seen);
        }
    }
    if (config.line_numbers) state.line_number = 1;
    restoreCounters(&state, config);
    if (!callOpt(S, "begin", sink, .{name})) {
        noteRejected(S, &state, sink);
        if (state.paused) {
            state.resume_at = state.abs_base;
            state.resume_line = state.line_number orelse 1;
        }
        return finishSink(S, sink, &state, config);
    }
    if (rejectEmptyResults(&state, config)) return finishSink(S, sink, &state, config);

    const initial = if (isMultilineMatcher(matcher))
        @max(bufferWindow(config), multilineWindow(matcher, config))
    else
        bufferWindow(config);
    const cap0 = @max(initial, 1);
    const stream_slot: ?*[]u8 = if (config.scratch_pool) |sp|
        &sp.stream_buf
    else if (config.scratch) |slot|
        slot
    else
        null;
    var buf: []u8 = undefined;
    if (stream_slot) |slot| {
        if (slot.len < cap0) {
            if (slot.len == 0) {
                slot.* = try stream_alloc.alloc(u8, cap0);
            } else {
                slot.* = try stream_alloc.realloc(slot.*, cap0);
            }
        }
        buf = slot.*;
    } else {
        buf = try stream_alloc.alloc(u8, cap0);
    }
    defer {
        if (stream_slot) |slot| {
            slot.* = buf;
        } else {
            stream_alloc.free(buf);
        }
    }
    var filled: usize = 0;
    var offset_map = decompress.OffsetMap{};
    defer offset_map.deinit(pool_alloc);
    var decompress_map = decompress.OffsetMap{};
    defer decompress_map.deinit(allocator);
    state.offset_map = &offset_map;
    state.decompress_map = &decompress_map;
    var decoder = encoding.Decoder.initWithHint(config.encoding, config.charset);
    decoder.max_in = decodeCap(config);
    decoder.offset_map = &offset_map;
    if (config.scratch_pool) |sp| {
        decoder.raw_buf = sp.decode_buf;
    }
    defer {
        if (config.scratch_pool) |sp| {
            sp.decode_buf = decoder.raw_buf;
            decoder.raw_buf = &.{};
        }
        decoder.deinit(pool_alloc);
    }
    var upstream = Upstream{
        .inner = read_ctx,
        .state = &state,
        .config = config,
        .sink = @ptrCast(sink),
    };
    var decompressed_stream: ?[]u8 = null;
    defer if (decompressed_stream) |ds| allocator.free(ds);
    var decompressed_pos: usize = 0;

    if (config.compression != .none) {
        var sniff_buf: [6]u8 = undefined;
        var sniff_len: usize = 0;
        var sniff_eof = false;
        var read_err = false;
        if (config.compression == .auto) {
            while (decompress.sniff(sniff_buf[0..sniff_len], sniff_eof) == .need_more and !stopForBudget(&state, config)) {
                var max_sniff = sniff_buf.len - sniff_len;
                if (scanRemaining(&state, config)) |left| {
                    if (left == 0) {
                        noteLimit(&state, .max_bytes);
                        break;
                    }
                    if (max_sniff > left) max_sniff = @intCast(left);
                }
                const rn = readUpstream(S, readFn, &upstream, sniff_buf[sniff_len .. sniff_len + max_sniff]) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    state.soft_error = .read_failed;
                    logDetail(config, name, err);
                    state.need_close = true;
                    read_err = true;
                    break;
                };
                state.bytes_read += rn;
                sniff_len += rn;
                if (rn == 0) {
                    sniff_eof = true;
                    break;
                }
            }
            if (read_err or state.limit_hit != .none) {
                return finishSink(S, sink, &state, config);
            }
        }
        const is_raw_auto = config.compression == .auto and decompress.sniff(sniff_buf[0..sniff_len], true) == .raw;
        if (is_raw_auto) {
            @memcpy(upstream.prefix[0..sniff_len], sniff_buf[0..sniff_len]);
            upstream.prefix_len = @intCast(sniff_len);
            upstream.prefix_pos = 0;
            state.bytes_read -= sniff_len;
        } else {
            var raw_compressed = std.ArrayList(u8).empty;
            defer raw_compressed.deinit(allocator);
            if (sniff_len > 0) try raw_compressed.appendSlice(allocator, sniff_buf[0..sniff_len]);
            var raw_chunk: [16384]u8 = undefined;
            while (!sniff_eof and !stopForBudget(&state, config)) {
                var max_chunk = raw_chunk.len;
                if (scanRemaining(&state, config)) |left| {
                    if (left == 0) {
                        noteLimit(&state, .max_bytes);
                        break;
                    }
                    if (max_chunk > left) max_chunk = @intCast(left);
                }
                const rn = readUpstream(S, readFn, &upstream, raw_chunk[0..max_chunk]) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    state.soft_error = .read_failed;
                    logDetail(config, name, err);
                    state.need_close = true;
                    read_err = true;
                    break;
                };
                state.bytes_read += rn;
                if (rn == 0) break;
                try raw_compressed.appendSlice(allocator, raw_chunk[0..rn]);
            }
            if (read_err or state.limit_hit != .none) {
                return finishSink(S, sink, &state, config);
            }
            const max_dec = config.max_decompressed_bytes orelse config.max_source_bytes;
            if (decompress.decompressSlice(
                allocator,
                raw_compressed.items,
                config.compression,
                state.decompressed_bytes,
                max_dec,
                config.max_compression_ratio,
                &state.decompressed_bytes,
                &decompress_map,
            )) |maybe_dec| {
                if (maybe_dec) |dec_buf| {
                    decompressed_stream = dec_buf;
                } else {
                    decompressed_stream = try raw_compressed.toOwnedSlice(allocator);
                }
            } else |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.DecompressLimit => {
                    noteLimit(&state, .decompressed_bytes);
                    state.need_close = true;
                    return finishSink(S, sink, &state, config);
                },
                error.CorruptStream => {
                    state.soft_error = .read_failed;
                    state.need_close = true;
                    return finishSink(S, sink, &state, config);
                },
            }
        }
    }

    while (!state.stopped) {
        if (state.exceeded(config)) {
            state.stopped = true;
            break;
        }
        if (flagIsSet(config)) {
            state.stopped = true;
            break;
        }
        if (stopForBudget(&state, config)) break;
        if (filled == buf.len) {
            if (try grow(stream_alloc, buf, config)) |next| {
                buf = next;
                if (stream_slot) |slot| slot.* = buf;
            } else if (!try makeRoom(S, pool_alloc, sink, matcher, &buf, &filled, &hold, &seen, &state, config)) {
                state.stopped = true;
                break;
            } else if (stream_slot) |slot| slot.* = buf;
        }
        var dest = buf[filled..];
        if (filled == 0 and state.bytes_read == 0 and watchesBinary(config) and config.binary == .quit and dest.len > 64 * 1024) {
            dest = dest[0 .. 64 * 1024];
        }
        if (scanRemaining(&state, config)) |left| {
            if (left == 0) {
                noteLimit(&state, .max_bytes);
                break;
            }
            if (dest.len > left) dest = dest[0..left];
        }
        var raw_read_sink: u64 = 0;
        const pulled = if (decompressed_stream) |ds| blk: {
            const SliceCtx = struct {
                data: []const u8,
                pos: *usize,
                fn read(ctx: *anyopaque, out: []u8) error{}!usize {
                    const self: *@This() = @ptrCast(@alignCast(ctx));
                    const avail = self.data.len - self.pos.*;
                    const n = @min(avail, out.len);
                    if (n > 0) @memcpy(out[0..n], self.data[self.pos.* .. self.pos.* + n]);
                    self.pos.* += n;
                    return n;
                }
            };
            var sctx = SliceCtx{ .data = ds, .pos = &decompressed_pos };
            break :blk decoder.pull(pool_alloc, SliceCtx.read, &sctx, bufferWindow(config), dest, &raw_read_sink) catch |err| {
                if (err == error.OutOfMemory) return error.OutOfMemory;
                if (err == error.DecodeLimit) return error.DecodeLimit;
                unreachable;
            };
        } else decoder.pull(pool_alloc, struct {
            fn read(ctx: *anyopaque, out: []u8) readRet(readFn) {
                return readUpstream(S, readFn, ctx, out);
            }
        }.read, &upstream, bufferWindow(config), dest, &state.bytes_read) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            if (err == error.DecodeLimit) return error.DecodeLimit;
            state.soft_error = .read_failed;
            logDetail(config, name, err);
            state.need_close = true;
            break;
        };
        const eof = pulled.eof;
        if (pulled.n == 0 and !eof and filled == 0) continue;
        var chunk_at = filled;
        if (pulled.n != 0) filled += pulled.n;

        if (state.long_active or longTail(buf[0..filled], eof, config)) {
            const cont = try pumpLong(
                S,
                pool_alloc,
                sink,
                matcher,
                &buf,
                &filled,
                &hold,
                &seen,
                chunk_at,
                eof,
                &state,
                config,
            );
            if (stream_slot) |slot| slot.* = buf;
            if (!cont) {
                state.stopped = true;
                break;
            }
            if (state.long_active) {
                if (eof) break;
                continue;
            }
            chunk_at = 0;
        }

        const exact_max = state_mod.exactMatcherMaxLen(matcher);
        const can_fuse_chunk = canFuse(matcher, config, &state);
        const fuse_full_buf = can_fuse_chunk and exact_max != null and exact_max.? > 0 and filled > state.pos;
        var search_end: usize = 0;
        var view_end: usize = 0;
        var skip_match = false;
        var fast_consumed: ?usize = null;
        var fast_next_pos: ?usize = null;

        if (fuse_full_buf) {
            var nul_rel: ?usize = null;
            const found = if (comptime @hasDecl(state_mod.MatcherType(@TypeOf(matcher)), "findWatched"))
                matcher.findWatched(buf[0..filled], state.pos, &nul_rel)
            else
                unreachable;
            if (nul_rel == null) {
                if (found) |hit| {
                    if (memchr.find(width, buf[hit.start..filled], 0, 0)) |rel| {
                        nul_rel = hit.start + rel;
                    } else {
                        search_end = if (eof) filled else lastComplete(buf[0..filled], config);
                        view_end = if (eof) filled else search_end;
                        if (hit.start < search_end) {
                            if (hit.start < state.pos + 4096) {
                                state.prefer_prepass = true;
                            }
                            if (config.progress_interval == null or config.progress_interval.? == 0) {
                                state.pos = lineStart(buf[0..view_end], hit.start, config);
                            }
                        } else {
                            skip_match = true;
                            state.pos = view_end;
                        }
                    }
                } else {
                    skip_match = true;
                    const keep_overlap = exact_max.? -| 1;
                    const can_drop_incomplete = (comptime !@hasDecl(S, "matched") and !@hasDecl(S, "context")) and
                        state.line_number == null and
                        config.max_output_bytes == null and
                        config.max_queued_event_bytes == null and
                        !state.long_active;
                    if (eof) {
                        search_end = filled;
                        view_end = filled;
                        state.pos = filled;
                    } else if (can_drop_incomplete) {
                        const cons = filled -| keep_overlap;
                        search_end = cons;
                        view_end = cons;
                        state.pos = cons;
                        fast_consumed = cons;
                    } else {
                        search_end = lastComplete(buf[0..filled], config);
                        view_end = search_end;
                        state.pos = view_end;
                        const rem = filled - search_end;
                        fast_next_pos = rem -| keep_overlap;
                    }
                }
            }
            if (nul_rel) |rel| {
                if (config.binary == .quit) {
                    const safe_end = lineStart(buf[0..rel], rel, config);
                    if (safe_end > state.pos) {
                        if (!try matchBuffer(S, sink, matcher, buf[0..safe_end], &state, config)) {
                            state.stopped = true;
                            break;
                        }
                    }
                    noteBinary(&state, config, state.abs_base + rel);
                    _ = callOpt(S, "binary", sink, .{state.nul_offset.?});
                    filled = safe_end;
                    state.stopped = true;
                    break;
                }
                noteBinary(&state, config, state.abs_base + rel);
                const cont = callOpt(S, "binary", sink, .{state.nul_offset.?});
                if (!cont) {
                    filled = chunk_at;
                    state.stopped = true;
                    break;
                }
                skip_match = false;
                search_end = if (eof) filled else lastComplete(buf[0..filled], config);
                view_end = if (eof) filled else search_end;
            }
        } else {
            search_end = if (eof) filled else lastComplete(buf[0..filled], config);
            view_end = if (eof) filled else search_end;
            const fuse = search_end > state.pos and can_fuse_chunk;
            if (fuse) {
                var nul_rel: ?usize = null;
                const found = if (comptime @hasDecl(state_mod.MatcherType(@TypeOf(matcher)), "findWatched")) matcher.findWatched(buf[0..search_end], state.pos, &nul_rel) else unreachable;
                if (nul_rel == null) {
                    if (found) |hit| {
                        if (memchr.find(width, buf[hit.start..filled], 0, 0)) |rel| {
                            nul_rel = hit.start + rel;
                        } else {
                            if (hit.start < state.pos + 4096) {
                                state.prefer_prepass = true;
                            }
                            if (config.progress_interval == null or config.progress_interval.? == 0) {
                                state.pos = lineStart(buf[0..view_end], hit.start, config);
                            }
                        }
                    } else {
                        if (search_end < filled) {
                            if (memchr.find(width, buf[search_end..filled], 0, 0)) |rel| nul_rel = search_end + rel;
                        }
                        if (nul_rel == null) {
                            skip_match = true;
                            state.pos = view_end;
                        }
                    }
                }
                if (nul_rel) |rel| {
                    if (config.binary == .quit) {
                        const safe_end = lineStart(buf[0..rel], rel, config);
                        if (safe_end > state.pos) {
                            if (!try matchBuffer(S, sink, matcher, buf[0..safe_end], &state, config)) {
                                state.stopped = true;
                                break;
                            }
                        }
                        noteBinary(&state, config, state.abs_base + rel);
                        _ = callOpt(S, "binary", sink, .{state.nul_offset.?});
                        filled = safe_end;
                        state.stopped = true;
                        break;
                    }
                    noteBinary(&state, config, state.abs_base + rel);
                    const cont = callOpt(S, "binary", sink, .{state.nul_offset.?});
                    if (!cont) {
                        filled = chunk_at;
                        state.stopped = true;
                        break;
                    }
                    skip_match = false;
                }
            } else if (chunk_at < filled and watchesBinary(config) and state.nul_offset == null) {
                if (memchr.find(width, buf[chunk_at..filled], 0, 0)) |rel| {
                    const nul_idx = chunk_at + rel;
                    if (config.binary == .quit) {
                        const safe_end = lineStart(buf[0..nul_idx], nul_idx, config);
                        if (safe_end > state.pos) {
                            if (!try matchBuffer(S, sink, matcher, buf[0..safe_end], &state, config)) {
                                state.stopped = true;
                                break;
                            }
                        }
                        noteBinary(&state, config, state.abs_base + nul_idx);
                        _ = callOpt(S, "binary", sink, .{state.nul_offset.?});
                        filled = safe_end;
                        state.stopped = true;
                        break;
                    }
                    noteBinary(&state, config, state.abs_base + nul_idx);
                    const cont = callOpt(S, "binary", sink, .{state.nul_offset.?});
                    if (!cont) {
                        filled = chunk_at;
                        state.stopped = true;
                        break;
                    }
                }
            }
        }

        const is_ml = isMultilineMatcher(matcher);
        const ml_win = if (is_ml) multilineWindow(matcher, config) else 0;
        if (is_ml and !eof and filled < ml_win and !config.passthru and !config.invert) {
            if (matcher.find(buf[0..search_end], state.pos, config.match_mode) == null) {
                continue;
            }
        }

        if (!skip_match and (search_end > state.pos or eof)) {
            if (!try matchBuffer(S, sink, matcher, buf[0..view_end], &state, config)) {
                state.stopped = true;
                if (eof and state.pos >= view_end and !state.output_blocked) state.scanned_all = true;
                break;
            }
        } else if (skip_match) {
            if (!maybeProgress(S, sink, &state, config)) {
                state.stopped = true;
                break;
            }
        }

        if (is_ml and isStartAnchoredMatcher(matcher) and state.abs_base + filled >= ml_win) {
            state.stopped = true;
            state.need_close = true;
            break;
        }

        if (eof) {
            state.scanned_all = !state.output_blocked and state.soft_error == null;
            break;
        }
        if (state.stopped) break;

        const consumed = if (fast_consumed) |fc|
            fc
        else if (is_ml and search_end > ml_win)
            @max(state.last_line_visited, lineEnd(buf[0..search_end], search_end - ml_win, config))
        else
            search_end;
        if (is_ml and consumed < search_end) {
            state.pos = consumed;
        }
        rememberBefore(matcher, buf, &state, config, consumed);
        countLines(buf, consumed, &state, config);
        const remain = filled - consumed;
        if (consumed > 0 and remain > 0) {
            std.mem.copyForwards(u8, buf[0..remain], buf[consumed..filled]);
        }
        filled = remain;
        state.pos = if (fast_next_pos) |fnp| fnp else if (state.pos >= consumed) state.pos - consumed else 0;
        state.last_line_visited = 0;
        state.last_line_counted = 0;
        state.remembered_until = 0;
        state.abs_base += consumed;
    }

    return finishSink(S, sink, &state, config);
}


pub const Upstream = struct {
    inner: *anyopaque,
    state: *State,
    config: SearchConfig,
    sink: *anyopaque,
    spins: u8 = 0,
    spin_at: i128 = 0,
    have_spin: bool = false,
    prefix: [6]u8 = undefined,
    prefix_len: u8 = 0,
    prefix_pos: u8 = 0,
};

pub fn readRet(comptime readFn: anytype) type {
    return @typeInfo(@TypeOf(readFn)).@"fn".return_type.?;
}

pub fn readUpstream(comptime S: type, comptime readFn: anytype, ctx: *anyopaque, dest: []u8) readRet(readFn) {
    const box: *Upstream = @ptrCast(@alignCast(ctx));
    if (box.prefix_pos < box.prefix_len) {
        const avail: usize = box.prefix_len - box.prefix_pos;
        const n = @min(avail, dest.len);
        @memcpy(dest[0..n], box.prefix[box.prefix_pos .. box.prefix_pos + n]);
        box.prefix_pos += @intCast(n);
        return n;
    }
    if (!box.config.live) return readFn(box.inner, dest);
    const sink: *S = @ptrCast(@alignCast(box.sink));
    while (!box.state.stopped) {
        const n = try readFn(box.inner, dest);
        if (n != 0) {
            box.state.last_input_ns = readClock(box.config);
            box.state.idle_sent = false;
            box.spins = 0;
            box.have_spin = false;
            return n;
        }
        if (liveIsClosed(box.config)) return 0;
        const now = readClock(box.config);
        if (box.have_spin and now == box.spin_at) {
            box.spins += 1;
            if (box.spins > 8) return 0;
        } else {
            box.spin_at = now;
            box.have_spin = true;
            box.spins = 0;
        }
        const timeout: i128 = @intCast(box.config.idle_timeout_ns orelse 0);
        if (!box.state.idle_sent and now - box.state.last_input_ns >= timeout) {
            const at = box.state.abs_base + @as(u64, box.state.pos);
            const keep = callOpt(S, "heartbeat", sink, .{ at, box.state.matches, box.state.matched_lines });
            box.state.idle_sent = true;
            if (!keep) {
                noteRejected(S, box.state, sink);
                return 0;
            }
        }
        if (stopForBudget(box.state, box.config)) return 0;
    }
    return 0;
}

