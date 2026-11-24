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
const afterCount = cfg_mod.afterCount;
const beforeContextCapacity = cfg_mod.beforeContextCapacity;
const bufferWindow = cfg_mod.bufferWindow;
const watchesBinary = cfg_mod.watchesBinary;
const effectiveAllocator = cfg_mod.effectiveAllocator;
const State = state_mod.State;
const resetStats = state_mod.resetStats;
const lineStart = state_mod.lineStart;
const lineEnd = line_matcher_mod.fastLineEnd;
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
const pumpLongAligned = long_line_mod.pumpLongAligned;
const makeRoomAligned = long_line_mod.makeRoomAligned;

const align_slack: usize = 64;

inline fn alignPad(storage_ptr: usize, raw_cursor: u64, remain: usize) usize {
    const cursor_usize: usize = @truncate(raw_cursor);
    return (cursor_usize -% storage_ptr -% remain) & 63;
}

inline fn realignSlice(buf_storage: []u8, buf: *[]u8, drop: usize, len: usize, raw_cursor: u64, slack: usize) usize {
    const remain = len - drop;
    if (slack == 0) {
        if (remain > 0 and drop > 0) @memmove(buf.*[0..remain], buf.*[drop..len]);
        return remain;
    }
    const usable_cap = buf_storage.len - slack;
    const pad = alignPad(@intFromPtr(buf_storage.ptr), raw_cursor, remain);
    const next_buf = buf_storage[pad .. pad + usable_cap];
    if (remain > 0 and (drop > 0 or next_buf.ptr != buf.*.ptr)) {
        @memmove(next_buf[0..remain], buf.*[drop..len]);
    }
    buf.* = next_buf;
    return remain;
}

fn growAligned(
    allocator: std.mem.Allocator,
    buf_storage: *[]u8,
    buf: *[]u8,
    filled: usize,
    limit: usize,
    raw_cursor: u64,
    slack: usize,
) error{OutOfMemory}!bool {
    const usable_cap = buf_storage.len - slack;
    if (usable_cap >= limit) return false;
    const doubled = if (usable_cap > limit / 2) limit else usable_cap * 2;
    const next_usable = @min(limit, @max(doubled, usable_cap + 1));
    if (next_usable <= usable_cap) return false;
    const old_pad = @intFromPtr(buf.*.ptr) - @intFromPtr(buf_storage.ptr);
    const next_storage = try allocator.realloc(buf_storage.*, next_usable + slack);
    buf_storage.* = next_storage;
    if (slack == 0) {
        buf.* = next_storage;
        return true;
    }
    const new_pad = alignPad(@intFromPtr(next_storage.ptr), raw_cursor, filled);
    const next_buf = next_storage[new_pad .. new_pad + next_usable];
    if (filled > 0 and new_pad != old_pad) {
        @memmove(next_buf[0..filled], next_storage[old_pad .. old_pad + filled]);
    }
    buf.* = next_buf;
    return true;
}

fn setDecoderRawMidStream(decoder: *encoding.Decoder, config: SearchConfig) void {
    const saved_raw = decoder.raw_buf;
    const saved_max_in = decoder.max_in;
    const saved_map = decoder.offset_map;
    if (encoding.resolveHint(config.encoding, config.charset) == .auto) {
        decoder.* = encoding.Decoder.init(.none);
    } else {
        decoder.* = encoding.Decoder.initWithHint(config.encoding, config.charset);
    }
    decoder.raw_buf = saved_raw;
    decoder.max_in = saved_max_in;
    decoder.offset_map = saved_map;
}

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
                sp.decode_buf = try sp.allocator.realloc(sp.decode_buf, dec.len);
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
                .detect => blk: {
                    const det = encoding.detectEncoding(current);
                    if (det == .utf8 and encoding.validUtf8(current)) {
                        if (was_decompressed) try stashDecompressedInScratch(&prep, config);
                        return prep;
                    }
                    break :blk encoding.encodingToSniff(det);
                },
                .utf8 => if (encoding.validUtf8(current)) {
                    if (was_decompressed) try stashDecompressedInScratch(&prep, config);
                    return prep;
                } else .utf8,
                else => encoding.encodingToSniff(resolved),
            };
            const src_slice = if (resume_raw) |rr| current[rr..] else current;
            const init_raw: u64 = if (resume_raw) |rr| @intCast(rr) else 0;
            const decoded_len = encoding.decodedSize(target, src_slice);
            if (decoded_len > cap) return error.DecodeLimit;
            const alloc = effectiveAllocator(config) orelse return error.OutOfMemory;
            prep.alloc = alloc;
            prep.transformed = true;
            if (config.scratch_pool) |sp| {
                const decoded = try encoding.convertScratchWithMapKnownLen(sp.allocator, &sp.decode_buf, alloc, target, src_slice, init_raw, &prep.offset_map, decoded_len);
                if (prep.owned.len != 0) {
                    alloc.free(prep.owned);
                    prep.owned = &.{};
                }
                prep.bytes = decoded;
            } else {
                const owned = try encoding.convertAllocWithMapKnownLen(alloc, target, src_slice, init_raw, &prep.offset_map, decoded_len);
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
            const decoded_len = encoding.decodedSize(.utf8, src_slice);
            if (decoded_len > cap) return error.DecodeLimit;
            const alloc = effectiveAllocator(config) orelse return error.OutOfMemory;
            prep.alloc = alloc;
            prep.transformed = true;
            if (config.scratch_pool) |sp| {
                const decoded = try encoding.convertScratchWithMapKnownLen(sp.allocator, &sp.decode_buf, alloc, .utf8, src_slice, init_raw, &prep.offset_map, decoded_len);
                if (prep.owned.len != 0) {
                    alloc.free(prep.owned);
                    prep.owned = &.{};
                }
                prep.bytes = decoded;
            } else {
                const owned = try encoding.convertAllocWithMapKnownLen(alloc, .utf8, src_slice, init_raw, &prep.offset_map, decoded_len);
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
            const decoded_len = encoding.decodedSize(kind, src_slice);
            if (decoded_len > cap) {
                return error.DecodeLimit;
            }
            const alloc = effectiveAllocator(config) orelse return error.OutOfMemory;
            prep.alloc = alloc;
            prep.transformed = true;
            if (config.scratch_pool) |sp| {
                const decoded = try encoding.convertScratchWithMapKnownLen(sp.allocator, &sp.decode_buf, alloc, kind, src_slice, init_raw, &prep.offset_map, decoded_len);
                if (prep.owned.len != 0) {
                    alloc.free(prep.owned);
                    prep.owned = &.{};
                }
                prep.bytes = decoded;
            } else {
                const owned = try encoding.convertAllocWithMapKnownLen(alloc, kind, src_slice, init_raw, &prep.offset_map, decoded_len);
                if (prep.owned.len != 0) alloc.free(prep.owned);
                prep.owned = owned;
                prep.bytes = owned;
            }
            if (resume_raw != null and resume_raw.? >= 2) prep.base_searchable_offset = config.resume_from;
            return prep;
        },
        .utf32le, .utf32be => |kind| {
            const payload = current[4..];
            const src_slice = if (resume_raw) |rr| (if (rr > 4) current[rr..] else payload) else payload;
            const init_raw: u64 = if (resume_raw) |rr| @intCast(@max(rr, 4)) else 4;
            const decoded_len = encoding.decodedSize(kind, src_slice);
            if (decoded_len > cap) return error.DecodeLimit;
            const alloc = effectiveAllocator(config) orelse return error.OutOfMemory;
            prep.alloc = alloc;
            prep.transformed = true;
            prep.offset_map.base_raw_offset = 4;
            if (config.scratch_pool) |sp| {
                const decoded = try encoding.convertScratchWithMapKnownLen(sp.allocator, &sp.decode_buf, alloc, kind, src_slice, init_raw, &prep.offset_map, decoded_len);
                if (prep.owned.len != 0) {
                    alloc.free(prep.owned);
                    prep.owned = &.{};
                }
                prep.bytes = decoded;
            } else {
                const owned = try encoding.convertAllocWithMapKnownLen(alloc, kind, src_slice, init_raw, &prep.offset_map, decoded_len);
                if (prep.owned.len != 0) alloc.free(prep.owned);
                prep.owned = owned;
                prep.bytes = owned;
            }
            if (resume_raw != null and resume_raw.? >= 4) prep.base_searchable_offset = config.resume_from;
            return prep;
        },
        else => unreachable,
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

inline fn shouldSwitchToPrepass(
    config: SearchConfig,
    fused_hits: usize,
    initial_pos: usize,
    pos: usize,
    view_len: usize,
) bool {
    if (config.max_count != null or config.max_results != null or config.exists) return false;
    if (fused_hits < 4) return false;
    return (pos <= initial_pos +| (32 * 1024) and view_len > pos +| (64 * 1024)) or
        (pos <= initial_pos +| (64 * 1024) and view_len > pos +| (256 * 1024));
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
    state.is_pure_empty = format_mod.isPureEmptyPattern(matcher);
    state.compiled_repl = format_mod.compileReplacement(config.replacement, matcher);
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
    if (state.ring.cap > SearchConfig.context_lines_hard_cap) {
        const needed_slots: usize = state.ring.cap;
        if (config.scratch_pool) |sp| {
            if (sp.ring_slots.len < needed_slots) {
                sp.ring_slots = try sp.allocator.realloc(sp.ring_slots, needed_slots);
            }
            state.ring.heap_slots = sp.ring_slots[0..needed_slots];
        } else {
            const alloc = pool_alloc orelse return error.BufferLimit;
            state.ring.heap_slots = try alloc.alloc(cfg_mod.RingSlot, needed_slots);
        }
    }
    defer if (config.scratch_pool == null and state.ring.heap_slots.len != 0) {
        if (pool_alloc) |alloc| alloc.free(state.ring.heap_slots);
    };
    const eff_start_slice = state_mod.effectiveRangeStart(config);
    state_mod.initLineNumber(&state, config, eff_start_slice);
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
    switch (state_mod.callSinkAction(S, "begin", sink, .{name})) {
        .cont => {},
        .skip_to => |target| {
            if (target > state.abs_base) state.pending_skip_to = target;
        },
        .pause => {
            state.paused = true;
            state.stopped = true;
            state.resume_at = state.abs_base;
            state.resume_line = state.line_number orelse 0;
            return finishSink(S, sink, &state, config);
        },
        .stop => {
            state.stopped = true;
            return finishSink(S, sink, &state, config);
        },
    }
    if (rejectEmptyResults(&state, config)) return finishSink(S, sink, &state, config);
    if (stopForBudget(&state, config)) return finishSink(S, sink, &state, config);
    if (state.pending_skip_to != null) {
        _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
        state.pending_skip_to = null;
    }

    if (comptime line_matcher_mod.isFinderFastEligibleType(S, @TypeOf(matcher))) {
        if (line_matcher_mod.canUseFinderFast(S, matcher, &state, config)) {
            const keep = if (watchesBinary(config))
                try line_matcher_mod.scanFinderFast(S, true, sink, matcher, view, &state, config)
            else
                try line_matcher_mod.scanFinderFast(S, false, sink, matcher, view, &state, config);
            if (!keep) {
                if (state.pending_skip_to != null) {
                    state.pending_skip_to = null;
                } else {
                    state.stopped = true;
                }
            }
            const consumed_f = state.nul_offset == null and (!state.stopped or state.pos >= view.len) and !state.output_blocked;
            if (consumed_f and !state.hit_byte_cap and state.soft_error == null) state.scanned_all = true;
            if (state.hit_byte_cap) noteLimit(&state, .max_bytes);
            return finishSink(S, sink, &state, config);
        }
    }

    var switched_to_prepass = false;
    if (watchesBinary(config) and config.binary == .quit and canFuse(matcher, config, &state)) {
        const is_ml = state_mod.effectiveMultiline(matcher, config);
        const ml_win = if (is_ml) state_mod.effectiveMultilineWindow(matcher, config) else 0;
        const watched_exact = state_mod.watchedMatchIsExact(matcher, config);
        const watched_exact_start = state_mod.watchedMatchHasExactStart(matcher, config);
        const need_ls = line_matcher_mod.needLineStart(S, &state, config);
        const direct_sink = !is_ml and ((comptime !@hasDecl(S, "matched")) or config.match_mode == .earliest) and
            config.resume_from == 0 and !config.files_without_match and config.line_filter == null;
        const initial_pos = state.pos;
        var fused_hits: usize = 0;
        while (state.pos < view.len and !state.stopped) {
            if (state.exceeded(config) or flagIsSet(config) or stopInMatch(&state, config) or !maybeProgress(S, sink, &state, config)) {
                if (state.exceeded(config)) state.need_close = true;
                state.stopped = true;
                break;
            }
            if (state.pending_skip_to != null) {
                _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                state.pending_skip_to = null;
                continue;
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
                        if (state.pending_skip_to != null) {
                            _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                            state.pending_skip_to = null;
                            if (state.pos > nul) continue;
                        } else {
                            state.stopped = true;
                            break;
                        }
                    }
                }
                if (state.pending_skip_to != null) {
                    _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                    state.pending_skip_to = null;
                    if (state.pos > nul) continue;
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
            if (is_ml) {
                const saved_pos = state.pos;
                const saved_ln = state.line_number;
                const saved_llc = state.last_line_counted;
                if (watched_exact) {
                    state.setCachedMatch(view, state.pos, hit);
                }
                const safe_from = if (watched_exact_start) hit.start else @max(state.pos, hit.start -| ml_win);
                if (config.progress_interval == null or config.progress_interval.? == 0) {
                    const ls = if (need_ls or safe_from >= view.len) lineStart(view, safe_from, config) else safe_from;
                    if (ls > state.pos) {
                        if (need_ls) countLines(view, ls, &state, config);
                        state.pos = ls;
                    }
                }
                if (try line_matcher_mod.findLineLimitOpts(matcher, view, &state, hit.start + 1, config, need_ls)) |line| {
                    if (std.mem.findScalar(u8, view[hit.start..line.end], 0)) |rel| {
                        const nul = hit.start + rel;
                        const safe_end = lineStart(view, nul, config);
                        state.pos = saved_pos;
                        state.line_number = saved_ln;
                        state.last_line_counted = saved_llc;
                        if (safe_end > state.pos) {
                            if (!try matchBuffer(S, sink, matcher, view[0..safe_end], &state, config)) {
                                if (state.pending_skip_to != null) {
                                    _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                                    state.pending_skip_to = null;
                                    if (state.pos > nul) continue;
                                } else {
                                    state.stopped = true;
                                    break;
                                }
                            }
                        }
                        if (state.pending_skip_to != null) {
                            _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                            state.pending_skip_to = null;
                            if (state.pos > nul) continue;
                        }
                        noteBinary(&state, config, state.abs_base + nul);
                        _ = callOpt(S, "binary", sink, .{state.nul_offset.?});
                        if (state.hit_byte_cap) noteLimit(&state, .max_bytes);
                        return finishSink(S, sink, &state, config);
                    }
                    if (state.abs_base + @as(u64, line.start) < config.resume_from) {
                        state.pos = line.end;
                        continue;
                    }
                    if (config.files_without_match) {
                        state.limit_count += 1;
                        state.matched_lines += 1;
                        state.matches += 1;
                        state.results_out += 1;
                        state.pos = line.end;
                        state.stopped = true;
                        state.need_close = true;
                        break;
                    }
                    state.limit_count += 1;
                    state.pos = line.end;
                    const known = state_mod.BufMatch{ .start = line.mstart, .end = line.mend, .pattern_id = line.mpid, .single_match = line.single_match };
                    if (!try format_mod.sinkMatched(S, sink, matcher, view, line.range(), known, &state, config)) {
                        state.stopped = true;
                        break;
                    }
                    if (state.pending_skip_to != null) {
                        _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                        state.pending_skip_to = null;
                    }
                    if (state.exceeded(config)) {
                        state.stopped = true;
                        state.need_close = true;
                        break;
                    }
                    fused_hits += 1;
                    if (shouldSwitchToPrepass(config, fused_hits, initial_pos, state.pos, view.len)) {
                        switched_to_prepass = true;
                        break;
                    }
                    continue;
                } else {
                    const first_le = lineEnd(view, safe_from, config);
                    const nul_check_end = @max(hit.start, first_le);
                    if (nul_check_end > hit.start) {
                        if (std.mem.findScalar(u8, view[hit.start..nul_check_end], 0)) |rel| {
                            const nul = hit.start + rel;
                            const safe_end = lineStart(view, nul, config);
                            state.pos = saved_pos;
                            state.line_number = saved_ln;
                            state.last_line_counted = saved_llc;
                            if (safe_end > state.pos) {
                                if (!try matchBuffer(S, sink, matcher, view[0..safe_end], &state, config)) {
                                    if (state.pending_skip_to != null) {
                                        _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                                        state.pending_skip_to = null;
                                        if (state.pos > nul) continue;
                                    } else {
                                        state.stopped = true;
                                        break;
                                    }
                                }
                            }
                            if (state.pending_skip_to != null) {
                                _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                                state.pending_skip_to = null;
                                if (state.pos > nul) continue;
                            }
                            noteBinary(&state, config, state.abs_base + nul);
                            _ = callOpt(S, "binary", sink, .{state.nul_offset.?});
                            if (state.hit_byte_cap) noteLimit(&state, .max_bytes);
                            return finishSink(S, sink, &state, config);
                        }
                    }
                    state.pos = @max(first_le, safe_from + 1);
                    continue;
                }
            }
            const hit_line_end = lineEnd(view, @max(hit.end, hit.start), config);
            if (std.mem.findScalar(u8, view[hit.start..hit_line_end], 0)) |rel| {
                const nul = hit.start + rel;
                const safe_end = lineStart(view, nul, config);
                if (safe_end > state.pos) {
                    if (!try matchBuffer(S, sink, matcher, view[0..safe_end], &state, config)) {
                        if (state.pending_skip_to != null) {
                            _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                            state.pending_skip_to = null;
                            if (state.pos > nul) continue;
                        } else {
                            state.stopped = true;
                            break;
                        }
                    }
                }
                if (state.pending_skip_to != null) {
                    _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                    state.pending_skip_to = null;
                    if (state.pos > nul) continue;
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
                if (state.pending_skip_to != null) {
                    _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                    state.pending_skip_to = null;
                }
                if (state.exceeded(config)) {
                    state.stopped = true;
                    state.need_close = true;
                    break;
                }
                fused_hits += 1;
                if (shouldSwitchToPrepass(config, fused_hits, initial_pos, state.pos, view.len)) {
                    switched_to_prepass = true;
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
                if (state.pending_skip_to != null) {
                    _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                    state.pending_skip_to = null;
                    continue;
                }
                state.stopped = true;
                break;
            }
            if (state.pending_skip_to != null) {
                _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                state.pending_skip_to = null;
            } else if (!state.stopped and !state.exceeded(config) and state.pos == hit_line_end) {
                fused_hits += 1;
                if (shouldSwitchToPrepass(config, fused_hits, initial_pos, state.pos, view.len)) {
                    switched_to_prepass = true;
                    break;
                }
            }
        }
        if (!switched_to_prepass) {
            const consumed_w = (!state.stopped or state.pos >= view.len) and !state.output_blocked;
            if (consumed_w and !state.hit_byte_cap and state.soft_error == null) state.scanned_all = true;
            if (state.hit_byte_cap) noteLimit(&state, .max_bytes);
            return finishSink(S, sink, &state, config);
        }
    }

    var skip_match = false;
    if (watchesBinary(config)) {
        const is_ml_prep = state_mod.effectiveMultiline(matcher, config);
        if (config.binary == .quit and
            (switched_to_prepass or !canFuse(matcher, config, &state)) and
            view.len > state.pos and view.len - state.pos > 512 * 1024 and
            !is_ml_prep and
            !config.invert and
            beforeCount(config) == 0 and
            afterCount(config) == 0 and
            !config.passthru and
            !config.stop_on_nonmatch)
        {
            const chunk_target: usize = 128 * 1024;
            const sep = cfg_mod.recordSep(config);
            while (state.pos < view.len and !state.stopped) {
                if (state.exceeded(config) or flagIsSet(config) or stopInMatch(&state, config) or !maybeProgress(S, sink, &state, config)) {
                    if (state.exceeded(config)) state.need_close = true;
                    state.stopped = true;
                    break;
                }
                if (state.pending_skip_to != null) {
                    _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                    state.pending_skip_to = null;
                    continue;
                }
                const chunk_start = state.pos;
                const raw_end = @min(view.len, chunk_start + chunk_target);
                const chunk_end = if (raw_end < view.len)
                    (if (raw_end > chunk_start and view[raw_end - 1] == sep) raw_end else lineEnd(view, raw_end, config))
                else
                    view.len;
                if (std.mem.findScalar(u8, view[chunk_start..chunk_end], 0)) |rel| {
                    var cur_nul: ?usize = chunk_start + rel;
                    while (cur_nul) |nul| {
                        const safe_end = lineStart(view, nul, config);
                        if (safe_end > state.pos) {
                            if (!try matchBuffer(S, sink, matcher, view[0..safe_end], &state, config)) {
                                if (state.pending_skip_to != null) {
                                    _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                                    state.pending_skip_to = null;
                                } else {
                                    state.stopped = true;
                                    break;
                                }
                            }
                        }
                        if (state.pending_skip_to != null) {
                            _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                            state.pending_skip_to = null;
                        }
                        if (state.pos > nul) {
                            if (state.pos < chunk_end) {
                                cur_nul = std.mem.findScalarPos(u8, view[0..chunk_end], state.pos, 0);
                                continue;
                            }
                            break;
                        }
                        noteBinary(&state, config, state.abs_base + nul);
                        _ = callOpt(S, "binary", sink, .{state.nul_offset.?});
                        state.stopped = true;
                        if (state.hit_byte_cap) noteLimit(&state, .max_bytes);
                        return finishSink(S, sink, &state, config);
                    }
                    if (state.stopped) break;
                    if (state.pos >= chunk_end) continue;
                }
                if (!try matchBuffer(S, sink, matcher, view[0..chunk_end], &state, config)) {
                    if (state.pending_skip_to != null) {
                        _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                        state.pending_skip_to = null;
                        continue;
                    }
                    state.stopped = true;
                    break;
                }
                if (state.pending_skip_to != null) {
                    _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                    state.pending_skip_to = null;
                }
            }
            const consumed_c = (!state.stopped or state.pos >= view.len) and !state.output_blocked;
            if (consumed_c and !state.hit_byte_cap and state.soft_error == null) state.scanned_all = true;
            if (state.hit_byte_cap) noteLimit(&state, .max_bytes);
            return finishSink(S, sink, &state, config);
        }
        var nul_at: ?usize = null;
        if (switched_to_prepass) {
            nul_at = std.mem.findScalarPos(u8, view, state.pos, 0);
        } else if (view.len > 0 and canFuse(matcher, config, &state)) {
            const is_ml = state_mod.effectiveMultiline(matcher, config);
            const ml_win = if (is_ml) state_mod.effectiveMultilineWindow(matcher, config) else 0;
            const found = if (comptime @hasDecl(state_mod.MatcherType(@TypeOf(matcher)), "findWatched")) matcher.findWatched(view, state.pos, &nul_at) else unreachable;
            if (nul_at == null) {
                if (found) |hit| {
                    if (std.mem.findScalar(u8, view[hit.start..], 0)) |rel| {
                        nul_at = hit.start + rel;
                    } else {
                        if (state_mod.watchedMatchIsExact(matcher, config)) {
                            state.setCachedMatch(view, state.pos, hit);
                        }
                        if (config.progress_interval == null or config.progress_interval.? == 0) {
                            const safe_hit = if (!is_ml or state_mod.watchedMatchHasExactStart(matcher, config))
                                hit.start
                            else
                                @max(state.pos, hit.start -| ml_win);
                            state.pos = lineStart(view, safe_hit, config);
                        }
                    }
                } else {
                    skip_match = true;
                    state.pos = view.len;
                }
            }
        } else {
            nul_at = std.mem.findScalar(u8, view, 0);
        }
        if (nul_at) |initial_nul| {
            if (config.binary == .quit) {
                var cur_nul: ?usize = initial_nul;
                while (cur_nul) |nul| {
                    const safe_end = lineStart(view, nul, config);
                    if (safe_end > state.pos) {
                        if (!try matchBuffer(S, sink, matcher, view[0..safe_end], &state, config)) {
                            if (state.pending_skip_to != null) {
                                _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                                state.pending_skip_to = null;
                            } else {
                                state.stopped = true;
                                break;
                            }
                        }
                    }
                    if (state.pending_skip_to != null) {
                        _ = line_matcher_mod.applyInBufferSkip(view, view.len, &state, config);
                        state.pending_skip_to = null;
                    }
                    if (state.pos > nul) {
                        cur_nul = if (state.pos < view.len) std.mem.findScalarPos(u8, view, state.pos, 0) else null;
                        continue;
                    }
                    noteBinary(&state, config, state.abs_base + nul);
                    _ = callOpt(S, "binary", sink, .{state.nul_offset.?});
                    state.stopped = true;
                    if (state.hit_byte_cap) noteLimit(&state, .max_bytes);
                    return finishSink(S, sink, &state, config);
                }
                if (state.stopped) {
                    if (state.hit_byte_cap) noteLimit(&state, .max_bytes);
                    return finishSink(S, sink, &state, config);
                }
            } else {
                noteBinary(&state, config, state.abs_base + initial_nul);
                const cont = callOpt(S, "binary", sink, .{state.nul_offset.?});
                if (!cont) state.stopped = true;
            }
        }
    }

    if (!state.stopped) {
        if (skip_match) {
            if (flagIsSet(config) or stopInMatch(&state, config) or !maybeProgress(S, sink, &state, config)) state.stopped = true;
        } else {
            if (!try matchBuffer(S, sink, matcher, view, &state, config)) {
                if (state.pending_skip_to != null) {
                    state.pending_skip_to = null;
                } else {
                    state.stopped = true;
                }
            }
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
    state.is_pure_empty = format_mod.isPureEmptyPattern(matcher);
    state.compiled_repl = format_mod.compileReplacement(config.replacement, matcher);
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
    if (state.ring.cap > SearchConfig.context_lines_hard_cap) {
        const needed_slots: usize = state.ring.cap;
        if (config.scratch_pool) |sp| {
            if (sp.ring_slots.len < needed_slots) {
                sp.ring_slots = try sp.allocator.realloc(sp.ring_slots, needed_slots);
            }
            state.ring.heap_slots = sp.ring_slots[0..needed_slots];
        } else {
            state.ring.heap_slots = try pool_alloc.alloc(cfg_mod.RingSlot, needed_slots);
        }
    }
    defer if (config.scratch_pool == null and state.ring.heap_slots.len != 0) pool_alloc.free(state.ring.heap_slots);
    if (state.ring.cap > 0) {
        const bytes = beforeContextCapacity(config);
        if (bytes > 0) {
            if (config.scratch_pool) |sp| {
                if (sp.ring_storage.len < bytes) {
                    sp.ring_storage = try sp.allocator.realloc(sp.ring_storage, bytes);
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
    const eff_start = state_mod.effectiveRangeStart(config);
    if (config.byte_range != null or config.stream_offset != null) {
        state.is_range_search = true;
        state.range_base_offset = eff_start;
    }
    state_mod.initLineNumber(&state, config, eff_start);
    restoreCounters(&state, config);
    switch (state_mod.callSinkAction(S, "begin", sink, .{name})) {
        .cont => {},
        .skip_to => |target| {
            if (target > eff_start) state.pending_skip_to = target;
        },
        .pause => {
            state.paused = true;
            state.stopped = true;
            state.abs_base = eff_start;
            state.resume_at = eff_start;
            state.resume_line = state.line_number orelse 0;
            return finishSink(S, sink, &state, config);
        },
        .stop => {
            state.stopped = true;
            state.abs_base = eff_start;
            return finishSink(S, sink, &state, config);
        },
    }
    if (rejectEmptyResults(&state, config)) {
        state.abs_base = eff_start;
        state.resume_at = eff_start;
        return finishSink(S, sink, &state, config);
    }

    const is_ml = state_mod.effectiveMultiline(matcher, config);
    const ml_win = if (is_ml) state_mod.effectiveMultilineWindow(matcher, config) else 0;
    const hold_limit = if (is_ml and ml_win > 0) state_mod.multilineHoldLimit(config, ml_win) else cfg_mod.lineHoldLimit(config);
    const initial = if (is_ml)
        @max(bufferWindow(config), ml_win)
    else
        bufferWindow(config);
    const cap0 = @max(initial, 1);
    const slack: usize = if (cap0 >= 4096 and hold_limit >= 4096) align_slack else 0;
    const raw_cap0 = cap0 + slack;
    const stream_slot: ?*[]u8 = if (config.scratch_pool) |sp|
        &sp.stream_buf
    else if (config.scratch) |slot|
        slot
    else
        null;
    var buf_storage: []u8 = undefined;
    if (stream_slot) |slot| {
        if (slot.len < raw_cap0) {
            slot.* = try stream_alloc.realloc(slot.*, raw_cap0);
        }
        buf_storage = slot.*;
    } else {
        buf_storage = try stream_alloc.alloc(u8, raw_cap0);
    }
    defer {
        if (stream_slot) |slot| {
            slot.* = buf_storage;
        } else {
            stream_alloc.free(buf_storage);
        }
    }
    const init_pad: usize = if (slack != 0) alignPad(@intFromPtr(buf_storage.ptr), config.stream_offset orelse 0, 0) else 0;
    var buf: []u8 = buf_storage[init_pad .. init_pad + (buf_storage.len - slack)];
    var filled: usize = 0;
    var offset_map = decompress.OffsetMap{};
    defer offset_map.deinit(pool_alloc);
    var decompress_map = decompress.OffsetMap{};
    defer decompress_map.deinit(allocator);
    state.offset_map = &offset_map;
    state.decompress_map = &decompress_map;
    var decoder = encoding.Decoder.initWithHint(config.encoding, config.charset);
    decoder.max_in = decodeCap(config);
    const sink_skips_offset_map = (comptime (!@hasDecl(S, "matched") and !@hasDecl(S, "context")) or
        (@hasDecl(S, "matched_fast_line") and S.matched_fast_line) or
        (@hasDecl(S, "matched_raw_spans") and S.matched_raw_spans)) and
        config.max_results == null and
        config.binary != .report and
        config.continuation == null;
    decoder.offset_map = if (sink_skips_offset_map) null else &offset_map;
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
        .raw_cursor = config.stream_offset orelse 0,
    };
    var decompressed_stream: ?[]u8 = null;
    defer if (decompressed_stream) |ds| allocator.free(ds);
    var decompressed_pos: usize = 0;
    var decompressed_end: usize = 0;

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
            if (decompressed_stream) |ds| decompressed_end = ds.len;
        }
    }

    const range_end: ?u64 = if (config.byte_range) |br| br.end else null;
    const sep = cfg_mod.recordSep(config);
    var range_eof = false;
    var extending_past_range_end = false;

    if (decompressed_stream) |ds| {
        decompressed_end = ds.len;
        if (eff_start > 0 or range_end != null) {
            var s_idx: usize = @intCast(@min(eff_start, @as(u64, ds.len)));
            if (config.range_align_lines and config.continuation == null and eff_start > 0 and s_idx > 0 and s_idx < ds.len and ds[s_idx - 1] != sep) {
                s_idx = if (std.mem.findScalarPos(u8, ds, s_idx, sep)) |d| d + 1 else ds.len;
            }
            var e_idx: usize = ds.len;
            if (range_end) |re_end| {
                const raw_e: usize = @intCast(@min(re_end, @as(u64, ds.len)));
                if (raw_e <= s_idx) {
                    e_idx = s_idx;
                } else if (config.range_align_lines and raw_e < ds.len and ds[raw_e - 1] != sep) {
                    e_idx = if (std.mem.findScalarPos(u8, ds, raw_e, sep)) |d| d + 1 else ds.len;
                } else {
                    e_idx = raw_e;
                }
            }
            decompressed_pos = s_idx;
            decompressed_end = e_idx;
            state.abs_base = @intCast(s_idx);
            if (state.is_range_search) state.range_base_offset = state.abs_base;
            if (s_idx > 0) setDecoderRawMidStream(&decoder, config);
            if (s_idx >= e_idx) range_eof = true;
        }
    } else if (eff_start > 0) {
        const align_start = config.range_align_lines and config.continuation == null;
        if (config.read_at != null or config.seek_input != null) {
            setDecoderRawMidStream(&decoder, config);
            const check_prev = align_start and eff_start > 0;
            const seek_target = if (check_prev) eff_start - 1 else eff_start;
            if (config.read_at == null) {
                if (config.seek_input) |seek_fn| {
                    seek_fn(config.seek_ctx, seek_target) catch |err| {
                        state.soft_error = .read_failed;
                        logDetail(config, name, err);
                        state.need_close = true;
                        return finishSink(S, sink, &state, config);
                    };
                }
            }
            upstream.raw_cursor = seek_target;
            state.abs_base = eff_start;
            if (check_prev) {
                var prev_b: [1]u8 = undefined;
                const prev_n = readUpstream(S, readFn, &upstream, prev_b[0..1]) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    state.soft_error = .read_failed;
                    logDetail(config, name, err);
                    state.need_close = true;
                    return finishSink(S, sink, &state, config);
                };
                if (prev_n == 0) {
                    range_eof = true;
                } else if (prev_b[0] != sep) {
                    _ = realignSlice(buf_storage, &buf, 0, 0, upstream.raw_cursor, slack);
                    while (!stopForBudget(&state, config)) {
                        var max_align = buf.len;
                        if (range_end) |re_end| {
                            if (state.abs_base >= re_end) {
                                range_eof = true;
                                break;
                            }
                            const rem_r = re_end - state.abs_base;
                            if (@as(u64, max_align) > rem_r) max_align = @intCast(rem_r);
                        }
                        if (scanRemaining(&state, config)) |left| {
                            if (left == 0) {
                                noteLimit(&state, .max_bytes);
                                break;
                            }
                            if (max_align > left) max_align = left;
                        }
                        const rn = readUpstream(S, readFn, &upstream, buf[0..max_align]) catch |err| {
                            if (err == error.OutOfMemory) return error.OutOfMemory;
                            state.soft_error = .read_failed;
                            logDetail(config, name, err);
                            state.need_close = true;
                            return finishSink(S, sink, &state, config);
                        };
                        state.bytes_read += rn;
                        if (rn == 0) {
                            range_eof = true;
                            break;
                        }
                        if (std.mem.findScalar(u8, buf[0..rn], sep)) |nl_rel| {
                            const drop = nl_rel + 1;
                            state.abs_base += drop;
                            filled = realignSlice(buf_storage, &buf, drop, rn, upstream.raw_cursor, slack);
                            break;
                        }
                        state.abs_base += rn;
                        _ = realignSlice(buf_storage, &buf, 0, 0, upstream.raw_cursor, slack);
                    }
                    if (state.limit_hit != .none) return finishSink(S, sink, &state, config);
                } else {
                    _ = realignSlice(buf_storage, &buf, 0, 0, upstream.raw_cursor, slack);
                }
            } else {
                _ = realignSlice(buf_storage, &buf, 0, 0, upstream.raw_cursor, slack);
            }
            if (state.is_range_search) state.range_base_offset = state.abs_base;
        } else if (upstream.raw_cursor == eff_start) {
            setDecoderRawMidStream(&decoder, config);
            state.abs_base = eff_start;
            _ = realignSlice(buf_storage, &buf, 0, 0, upstream.raw_cursor, slack);
            if (align_start) {
                while (!stopForBudget(&state, config)) {
                    var max_align = buf.len;
                    if (range_end) |re_end| {
                        if (state.abs_base >= re_end) {
                            range_eof = true;
                            break;
                        }
                        const rem_r = re_end - state.abs_base;
                        if (@as(u64, max_align) > rem_r) max_align = @intCast(rem_r);
                    }
                    if (scanRemaining(&state, config)) |left| {
                        if (left == 0) {
                            noteLimit(&state, .max_bytes);
                            break;
                        }
                        if (max_align > left) max_align = left;
                    }
                    const rn = readUpstream(S, readFn, &upstream, buf[0..max_align]) catch |err| {
                        if (err == error.OutOfMemory) return error.OutOfMemory;
                        state.soft_error = .read_failed;
                        logDetail(config, name, err);
                        state.need_close = true;
                        return finishSink(S, sink, &state, config);
                    };
                    state.bytes_read += rn;
                    if (rn == 0) {
                        range_eof = true;
                        break;
                    }
                    if (std.mem.findScalar(u8, buf[0..rn], sep)) |nl_rel| {
                        const drop = nl_rel + 1;
                        state.abs_base += drop;
                        filled = realignSlice(buf_storage, &buf, drop, rn, upstream.raw_cursor, slack);
                        break;
                    }
                    state.abs_base += rn;
                    _ = realignSlice(buf_storage, &buf, 0, 0, upstream.raw_cursor, slack);
                }
                if (state.limit_hit != .none) return finishSink(S, sink, &state, config);
            }
            if (state.is_range_search) state.range_base_offset = state.abs_base;
        } else {
            var cur_decoded: u64 = upstream.raw_cursor;
            var prev_b: u8 = sep;
            while (cur_decoded < eff_start and !stopForBudget(&state, config)) {
                var max_skip = buf.len;
                if (!state.is_range_search) {
                    if (scanRemaining(&state, config)) |left| {
                        if (left == 0) {
                            noteLimit(&state, .max_bytes);
                            break;
                        }
                        if (max_skip > left) max_skip = left;
                    }
                }
                var skip_read_bytes: u64 = 0;
                const pulled_skip = decoder.pull(pool_alloc, struct {
                    fn read(ctx: *anyopaque, out: []u8) anyerror!usize {
                        return readUpstream(S, readFn, ctx, out);
                    }
                }.read, &upstream, bufferWindow(config), buf[0..max_skip], &skip_read_bytes) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    if (err == error.DecodeLimit) return error.DecodeLimit;
                    state.soft_error = .read_failed;
                    logDetail(config, name, err);
                    state.need_close = true;
                    return finishSink(S, sink, &state, config);
                };
                if (!state.is_range_search) state.bytes_read += skip_read_bytes;
                if (cur_decoded + pulled_skip.n >= eff_start) {
                    const cut: usize = @intCast(eff_start - cur_decoded);
                    if (cut > 0) prev_b = buf[cut - 1];
                    filled = realignSlice(buf_storage, &buf, cut, pulled_skip.n, upstream.raw_cursor, slack);
                    if (state.is_range_search) state.bytes_read += filled;
                    cur_decoded = eff_start;
                    if (pulled_skip.eof and filled == 0) range_eof = true;
                    break;
                }
                if (pulled_skip.n > 0) prev_b = buf[pulled_skip.n - 1];
                cur_decoded += pulled_skip.n;
                if (pulled_skip.eof) {
                    range_eof = true;
                    break;
                }
            }
            if (state.limit_hit != .none) return finishSink(S, sink, &state, config);
            state.abs_base = cur_decoded;
            if (!range_eof and align_start and prev_b != sep) {
                while (true) {
                    const check_len: usize = if (range_end) |re_end|
                        @intCast(@min(@as(u64, filled), re_end -| state.abs_base))
                    else
                        filled;
                    if (std.mem.findScalar(u8, buf[0..check_len], sep)) |nl_rel| {
                        const drop = nl_rel + 1;
                        filled = realignSlice(buf_storage, &buf, drop, filled, upstream.raw_cursor, slack);
                        state.abs_base += drop;
                        break;
                    }
                    if (range_end) |re_end| {
                        if (state.abs_base + @as(u64, check_len) >= re_end) {
                            filled = 0;
                            state.abs_base = re_end;
                            range_eof = true;
                            break;
                        }
                    }
                    state.abs_base += filled;
                    filled = 0;
                    _ = realignSlice(buf_storage, &buf, 0, 0, upstream.raw_cursor, slack);
                    if (stopForBudget(&state, config)) break;
                    var align_read: u64 = 0;
                    const p_al = decoder.pull(pool_alloc, struct {
                        fn read(ctx: *anyopaque, out: []u8) anyerror!usize {
                            return readUpstream(S, readFn, ctx, out);
                        }
                    }.read, &upstream, bufferWindow(config), buf, &align_read) catch |err| {
                        if (err == error.OutOfMemory) return error.OutOfMemory;
                        if (err == error.DecodeLimit) return error.DecodeLimit;
                        state.soft_error = .read_failed;
                        logDetail(config, name, err);
                        state.need_close = true;
                        return finishSink(S, sink, &state, config);
                    };
                    state.bytes_read += align_read;
                    filled = p_al.n;
                    if (p_al.eof and filled == 0) {
                        range_eof = true;
                        break;
                    }
                }
                if (state.limit_hit != .none) return finishSink(S, sink, &state, config);
            }
            if (state.is_range_search) state.range_base_offset = state.abs_base;
        }
    }

    if (range_end) |re_end| {
        if (state.abs_base >= re_end) {
            filled = 0;
            state.scanned_all = !state.output_blocked and state.soft_error == null;
            return finishSink(S, sink, &state, config);
        }
    }

    var checked_incomplete_nul: usize = 0;
    while (!state.stopped) {
        if (state.pending_skip_to) |skip_target| {
            checked_incomplete_nul = 0;
            state.pending_skip_to = null;
            state.after_left = 0;
            state.ring.clear();
            if (skip_target > state.abs_base + @as(u64, state.pos)) {
                if (range_end) |re_end| {
                    if (skip_target >= re_end and (!config.range_align_lines or skip_target > re_end)) {
                        filled = 0;
                        state.pos = 0;
                        state.abs_base = re_end;
                        state.scanned_all = !state.output_blocked and state.soft_error == null;
                        break;
                    }
                }
                const cur_buf_end = state.abs_base + @as(u64, filled);
                if (skip_target <= cur_buf_end) {
                    const drop: usize = @intCast(skip_target - state.abs_base);
                    countLines(buf[0..filled], drop, &state, config);
                    filled = realignSlice(buf_storage, &buf, drop, filled, upstream.raw_cursor, slack);
                    state.pos = 0;
                    state.last_line_visited = 0;
                    state.last_line_counted = 0;
                    state.remembered_until = 0;
                    state.abs_base = skip_target;
                    state.bytes_searched = @max(state.bytes_searched, state_mod.searchedSpanAt(&state, config, state.abs_base));
                } else {
                    countLines(buf[0..filled], filled, &state, config);
                    filled = 0;
                    state.pos = 0;
                    state.last_line_visited = 0;
                    state.last_line_counted = 0;
                    state.remembered_until = 0;
                    if (decompressed_stream) |ds| {
                        const clamped_t: usize = @intCast(@min(skip_target, @as(u64, decompressed_end)));
                        if (clamped_t > decompressed_pos) {
                            if (state.line_number) |ln| {
                                state.line_number = ln + memchr.count(width, ds, decompressed_pos, clamped_t, sep);
                            }
                        }
                        decompressed_pos = clamped_t;
                        state.abs_base = @intCast(clamped_t);
                        setDecoderRawMidStream(&decoder, config);
                        if (clamped_t >= decompressed_end) range_eof = true;
                    } else if (config.read_at != null) {
                        state.line_number = null;
                        state.resume_line = 0;
                        setDecoderRawMidStream(&decoder, config);
                        upstream.raw_cursor = skip_target;
                        state.abs_base = skip_target;
                        _ = realignSlice(buf_storage, &buf, 0, 0, upstream.raw_cursor, slack);
                    } else if (config.seek_input) |seek_fn| {
                        state.line_number = null;
                        state.resume_line = 0;
                        seek_fn(config.seek_ctx, skip_target) catch |err| {
                            state.soft_error = .read_failed;
                            logDetail(config, name, err);
                            state.need_close = true;
                            break;
                        };
                        setDecoderRawMidStream(&decoder, config);
                        upstream.raw_cursor = skip_target;
                        state.abs_base = skip_target;
                        _ = realignSlice(buf_storage, &buf, 0, 0, upstream.raw_cursor, slack);
                    } else {
                        var cur_off = cur_buf_end;
                        _ = realignSlice(buf_storage, &buf, 0, 0, upstream.raw_cursor, slack);
                        while (cur_off < skip_target and !stopForBudget(&state, config)) {
                            var sk_bytes: u64 = 0;
                            const p_sk = decoder.pull(pool_alloc, struct {
                                fn read(ctx: *anyopaque, out: []u8) anyerror!usize {
                                    return readUpstream(S, readFn, ctx, out);
                                }
                            }.read, &upstream, bufferWindow(config), buf, &sk_bytes) catch |err| {
                                if (err == error.OutOfMemory) return error.OutOfMemory;
                                if (err == error.DecodeLimit) return error.DecodeLimit;
                                state.soft_error = .read_failed;
                                logDetail(config, name, err);
                                state.need_close = true;
                                break;
                            };
                            if (!state.is_range_search) state.bytes_read += sk_bytes;
                            if (cur_off + p_sk.n >= skip_target) {
                                const cut: usize = @intCast(skip_target - cur_off);
                                if (state.line_number) |ln| {
                                    state.line_number = ln + memchr.count(width, buf, 0, cut, sep);
                                }
                                filled = realignSlice(buf_storage, &buf, cut, p_sk.n, upstream.raw_cursor, slack);
                                if (state.is_range_search) state.bytes_read += filled;
                                cur_off = skip_target;
                                if (p_sk.eof and filled == 0) range_eof = true;
                                break;
                            }
                            if (state.line_number) |ln| {
                                state.line_number = ln + memchr.count(width, buf, 0, p_sk.n, sep);
                            }
                            cur_off += p_sk.n;
                            if (p_sk.eof) {
                                range_eof = true;
                                break;
                            }
                            _ = realignSlice(buf_storage, &buf, 0, 0, upstream.raw_cursor, slack);
                        }
                        if (state.soft_error != null or state.limit_hit != .none) break;
                        state.abs_base = cur_off;
                    }
                    state.bytes_searched = @max(state.bytes_searched, state_mod.searchedSpanAt(&state, config, state.abs_base));
                }
            }
        }
        if (state.exceeded(config)) {
            state.stopped = true;
            break;
        }
        if (flagIsSet(config)) {
            state.stopped = true;
            break;
        }
        if (stopForBudget(&state, config)) break;
        if (range_end) |re_end| {
            if (!extending_past_range_end and state.abs_base >= re_end) {
                state.scanned_all = !state.output_blocked and state.soft_error == null;
                break;
            }
            if (filled > 0 and state.abs_base + @as(u64, filled) >= re_end) {
                if (!config.range_align_lines) {
                    filled = @intCast(re_end - state.abs_base);
                    range_eof = true;
                } else if (state.abs_base < re_end) {
                    const rel_re: usize = @intCast(re_end - state.abs_base);
                    if (buf[rel_re - 1] == sep) {
                        filled = rel_re;
                        range_eof = true;
                    } else if (std.mem.findScalarPos(u8, buf[0..filled], rel_re, sep)) |nl_idx| {
                        filled = nl_idx + 1;
                        range_eof = true;
                    } else {
                        extending_past_range_end = true;
                    }
                } else if (std.mem.findScalar(u8, buf[0..filled], sep)) |nl_idx| {
                    filled = nl_idx + 1;
                    range_eof = true;
                }
            }
        }
        if (!range_eof and filled == buf.len) {
            const backing: ?long_line_mod.BufBacking = if (slack != 0) .{
                .storage = buf_storage,
                .raw_cursor = upstream.raw_cursor,
            } else null;
            if (try growAligned(stream_alloc, &buf_storage, &buf, filled, hold_limit, upstream.raw_cursor, slack)) {
                if (stream_slot) |slot| slot.* = buf_storage;
            } else if (!try makeRoomAligned(S, pool_alloc, sink, matcher, &buf, &filled, &hold, &seen, &state, config, backing)) {
                state.stopped = true;
                break;
            } else {
                checked_incomplete_nul = 0;
            }
            if (state.pending_skip_to != null) continue;
        }
        var chunk_at = filled;
        var eof = range_eof;
        if (!range_eof) {
            var dest = buf[filled..];
            if (filled == 0 and state.bytes_read == 0 and watchesBinary(config) and config.binary == .quit and dest.len > 64 * 1024) {
                dest = dest[0 .. 64 * 1024];
            }
            if (range_end) |re_end| {
                if (!config.range_align_lines) {
                    const cur_end = state.abs_base + @as(u64, filled);
                    if (cur_end >= re_end) {
                        dest = dest[0..0];
                        range_eof = true;
                    } else {
                        const max_r = re_end - cur_end;
                        if (@as(u64, dest.len) > max_r) dest = dest[0..@intCast(max_r)];
                    }
                }
            }
            if (!range_eof) {
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
                        end: usize,
                        fn read(ctx: *anyopaque, out: []u8) error{}!usize {
                            const self: *@This() = @ptrCast(@alignCast(ctx));
                            const avail = self.end -| self.pos.*;
                            const n = @min(avail, out.len);
                            if (n > 0) @memcpy(out[0..n], self.data[self.pos.* .. self.pos.* + n]);
                            self.pos.* += n;
                            return n;
                        }
                    };
                    var sctx = SliceCtx{ .data = ds, .pos = &decompressed_pos, .end = decompressed_end };
                    break :blk decoder.pull(pool_alloc, SliceCtx.read, &sctx, bufferWindow(config), dest, &raw_read_sink) catch |err| {
                        if (err == error.OutOfMemory) return error.OutOfMemory;
                        if (err == error.DecodeLimit) return error.DecodeLimit;
                        unreachable;
                    };
                } else decoder.pull(pool_alloc, struct {
                    fn read(ctx: *anyopaque, out: []u8) anyerror!usize {
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
                eof = pulled.eof;
                if (pulled.n == 0 and !eof and filled == 0) continue;
                chunk_at = filled;
                if (pulled.n != 0) filled += pulled.n;
                if (range_end) |re_end| {
                    if (state.abs_base + @as(u64, filled) >= re_end) {
                        if (!config.range_align_lines) {
                            filled = @intCast(re_end - state.abs_base);
                            range_eof = true;
                            eof = true;
                        } else if (state.abs_base < re_end) {
                            const rel_re: usize = @intCast(re_end - state.abs_base);
                            if (buf[rel_re - 1] == sep) {
                                filled = rel_re;
                                range_eof = true;
                                eof = true;
                            } else if (std.mem.findScalarPos(u8, buf[0..filled], rel_re, sep)) |nl_idx| {
                                filled = nl_idx + 1;
                                range_eof = true;
                                eof = true;
                            } else {
                                extending_past_range_end = true;
                            }
                        } else if (std.mem.findScalar(u8, buf[chunk_at..filled], sep)) |rel_nl| {
                            filled = chunk_at + rel_nl + 1;
                            range_eof = true;
                            eof = true;
                        }
                    }
                }
            } else {
                eof = true;
            }
        }
        if (filled == 0 and eof) {
            state.scanned_all = !state.output_blocked and state.soft_error == null;
            break;
        }

        const exact_max = state_mod.exactMatcherMaxLen(matcher);
        const can_fast_count_no_nul = (comptime !@hasDecl(S, "matched") and !@hasDecl(S, "context") and !@hasDecl(S, "contextBreak") and !@hasDecl(S, "context_break")) and
            !watchesBinary(config) and
            !config.null_data and
            !is_ml and
            !isStartAnchoredMatcher(matcher) and
            exact_max != null and exact_max.? > 0 and
            state.line_number == null and
            !config.invert and
            !config.whole_word and
            !config.whole_line and
            beforeCount(config) == 0 and
            afterCount(config) == 0 and
            !config.passthru and
            !config.stop_on_nonmatch and
            config.contains.len == 0 and
            config.excludes.len == 0 and
            config.contains_regexes.len == 0 and
            config.excludes_regexes.len == 0 and
            config.line_filter == null and
            config.max_output_bytes == null and
            config.max_queued_event_bytes == null and
            config.resume_from == 0 and
            !state.long_active;
        var fast_no_nul_done = false;
        var fast_no_nul_hit: ?matcher_mod.Match = null;
        if (can_fast_count_no_nul and filled > state.pos) {
            if (matcher.find(buf[0..filled], state.pos, config.match_mode)) |hit| {
                fast_no_nul_hit = hit;
            } else {
                fast_no_nul_done = true;
            }
        }

        if (!fast_no_nul_done and (state.long_active or longTail(buf[0..filled], eof, config))) {
            const backing: ?long_line_mod.BufBacking = if (slack != 0) .{
                .storage = buf_storage,
                .raw_cursor = upstream.raw_cursor,
            } else null;
            const cont = try pumpLongAligned(
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
                backing,
            );
            if (!cont) {
                if (state.pending_skip_to != null and !state.paused) continue;
                state.stopped = true;
                break;
            }
            if (state.pending_skip_to != null and !state.paused) continue;
            if (state.long_active) {
                if (eof) break;
                continue;
            }
            chunk_at = 0;
            fast_no_nul_hit = null;
            checked_incomplete_nul = 0;
        }

        const can_fuse_chunk = canFuse(matcher, config, &state);
        const fuse_full_buf = !fast_no_nul_done and !is_ml and can_fuse_chunk and exact_max != null and exact_max.? > 0 and filled > state.pos;
        var search_end: usize = 0;
        var view_end: usize = 0;
        var skip_match = false;
        var fast_consumed: ?usize = null;
        var fast_next_pos: ?usize = null;

        const no_more_reads = eof or state_mod.overBytes(&state, config) or state_mod.overDecompressed(&state, config);
        const saved_pos_before_fuse = state.pos;
        var finder_fast_handled = false;
        if (comptime line_matcher_mod.isFinderFastEligibleType(S, @TypeOf(matcher))) {
            if (watchesBinary(config) and line_matcher_mod.canUseFinderFast(S, matcher, &state, config)) {
                finder_fast_handled = true;
                search_end = if (eof) filled else lastComplete(buf[0..filled], config);
                view_end = search_end;
                skip_match = true;
                if (search_end > state.pos) {
                    if (!try line_matcher_mod.scanFinderFast(S, true, sink, matcher, buf[0..search_end], &state, config)) {
                        if (state.pending_skip_to != null and !state.paused) {
                            checked_incomplete_nul = 0;
                            continue;
                        }
                        if (state.nul_offset != null) {
                            filled = state.pos;
                        } else if (eof and state.pos >= view_end and !state.output_blocked and !state.paused) {
                            state.scanned_all = true;
                        }
                        state.stopped = true;
                        break;
                    }
                }
                if (!eof and search_end < filled) {
                    const tail_from = @max(search_end, checked_incomplete_nul);
                    if (tail_from < filled) {
                        if (memchr.find(width, buf[0..filled], tail_from, 0)) |nul_idx| {
                            noteBinary(&state, config, state.abs_base + @as(u64, nul_idx));
                            _ = callOpt(S, "binary", sink, .{state.nul_offset.?});
                            filled = search_end;
                            state.pos = search_end;
                            state.stopped = true;
                            break;
                        }
                    }
                    checked_incomplete_nul = filled - search_end;
                } else {
                    checked_incomplete_nul = 0;
                }
            }
        }
        if (finder_fast_handled) {
            // Single-pass Finder fast loop already scanned [0..search_end] and verified trailing partial line NUL-free.
        } else if (fast_no_nul_done) {
            skip_match = true;
            if (eof) {
                search_end = filled;
                view_end = filled;
                state.pos = filled;
            } else {
                const keep_overlap = exact_max.? -| 1;
                const cons = filled -| keep_overlap;
                search_end = cons;
                view_end = cons;
                state.pos = cons;
                fast_consumed = cons;
            }
        } else if (fast_no_nul_hit) |hit| {
            search_end = if (eof) filled else lastComplete(buf[0..filled], config);
            view_end = if (eof) filled else search_end;
            if (hit.start < search_end) {
                if (hit.end <= view_end) {
                    state.setCachedMatch(buf[0..view_end], state.pos, hit);
                }
                if (config.progress_interval == null or config.progress_interval.? == 0) {
                    state.pos = lineStart(buf[0..view_end], hit.start, config);
                }
            } else {
                skip_match = true;
                state.pos = view_end;
            }
        } else if (fuse_full_buf) {
            var nul_rel: ?usize = null;
            const found = if (comptime @hasDecl(state_mod.MatcherType(@TypeOf(matcher)), "findWatched"))
                matcher.findWatched(buf[0..filled], state.pos, &nul_rel)
            else
                unreachable;
            if (nul_rel == null) {
                if (found) |hit| {
                    if (std.mem.findScalar(u8, buf[hit.start..filled], 0)) |rel| {
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
            const fuse = search_end > state.pos and can_fuse_chunk and (!is_ml or no_more_reads or (filled >= ml_win and search_end > ml_win));
            if (fuse) {
                var nul_rel: ?usize = null;
                const found = if (comptime @hasDecl(state_mod.MatcherType(@TypeOf(matcher)), "findWatched")) matcher.findWatched(buf[0..search_end], state.pos, &nul_rel) else unreachable;
                if (nul_rel == null) {
                    if (found) |hit| {
                        if (std.mem.findScalar(u8, buf[hit.start..filled], 0)) |rel| {
                            nul_rel = hit.start + rel;
                        } else {
                            if (hit.start < state.pos + 4096) {
                                state.prefer_prepass = true;
                            }
                            if (state_mod.watchedMatchIsExact(matcher, config)) {
                                state.setCachedMatch(buf[0..view_end], state.pos, hit);
                            }
                            if (config.progress_interval == null or config.progress_interval.? == 0) {
                                const safe_hit = if (!is_ml or state_mod.watchedMatchHasExactStart(matcher, config))
                                    hit.start
                                else
                                    @max(state.pos, hit.start -| ml_win);
                                state.pos = lineStart(buf[0..view_end], safe_hit, config);
                            }
                        }
                    } else {
                        if (search_end < filled) {
                            if (std.mem.findScalar(u8, buf[search_end..filled], 0)) |rel| nul_rel = search_end + rel;
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
                if (std.mem.findScalar(u8, buf[chunk_at..filled], 0)) |rel| {
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

        var commit_end: usize = view_end;
        var start_anchored_done = false;
        if (is_ml and ml_win > 0 and !no_more_reads) {
            const sa_eligible = isStartAnchoredMatcher(matcher) and state.abs_base == 0 and !config.invert and !config.passthru and filled >= ml_win;
            var start_anchored_ready = false;
            if (sa_eligible) {
                if (matcher.find(buf[0..filled], 0, config.match_mode)) |sa_hit| {
                    const need_end = line_matcher_mod.matchLineEnd(buf[0..filled], 0, sa_hit, config);
                    if (need_end <= search_end or filled >= hold_limit) {
                        start_anchored_ready = true;
                        start_anchored_done = true;
                    }
                } else {
                    if (state.after_left == 0) {
                        state.bytes_searched = @max(state.bytes_searched, state_mod.searchedSpanAt(&state, config, state.abs_base + filled));
                        state.stopped = true;
                        state.need_close = true;
                        break;
                    }
                    start_anchored_ready = true;
                    start_anchored_done = true;
                }
            }
            if (!start_anchored_ready) {
                if (filled < ml_win and filled < hold_limit) {
                    state.pos = saved_pos_before_fuse;
                    continue;
                }
                if (search_end <= ml_win) {
                    if (filled < hold_limit) {
                        state.pos = saved_pos_before_fuse;
                        continue;
                    }
                    commit_end = if (search_end > 0) lineEnd(buf[0..search_end], 0, config) else 0;
                } else {
                    var ce = lineStart(buf[0..search_end], search_end - ml_win, config);
                    if (!config.null_data and !config.whole_line and !config.invert) {
                        if (state_mod.effectiveMaxNewlines(matcher, config)) |max_nl| {
                            if (max_nl <= 8) {
                                var nl_pos = search_end;
                                var rem_nl: u32 = max_nl + 2;
                                while (rem_nl > 0 and nl_pos > 0) : (rem_nl -= 1) {
                                    if (memchr.findLast(width, buf, 0, nl_pos, cfg_mod.recordSep(config))) |at| {
                                        nl_pos = at;
                                    } else {
                                        nl_pos = 0;
                                        break;
                                    }
                                }
                                if (nl_pos > 0) {
                                    ce = @max(ce, nl_pos + 1);
                                }
                            }
                        }
                        const pend = state_mod.effectiveEarliestPendingStart(matcher, buf[0..search_end], ce);
                        if (pend > ce) {
                            const pend_ce = lineStart(buf[0..search_end], pend, config);
                            ce = @max(ce, pend_ce);
                        }
                    }
                    if (ce == 0) {
                        if (filled < hold_limit) {
                            state.pos = saved_pos_before_fuse;
                            continue;
                        }
                        ce = lineEnd(buf[0..search_end], 0, config);
                    }
                    commit_end = ce;
                }
                if (skip_match or state.pos > commit_end) {
                    state.pos = commit_end;
                }
            }
        }

        if (!skip_match and (commit_end > state.pos or eof)) {
            const can_hold_zero = is_ml and !no_more_reads and filled < hold_limit;
            if (!try line_matcher_mod.matchBufferWithLimit(S, sink, matcher, buf[0..view_end], commit_end, can_hold_zero, &state, config)) {
                if (state.pending_skip_to != null and !state.paused) continue;
                state.stopped = true;
                if (eof and state.pos >= view_end and !state.output_blocked) state.scanned_all = true;
                break;
            }
            if (state.pending_skip_to != null and !state.paused) continue;
        } else if (skip_match) {
            countLines(buf[0..filled], @min(state.pos, filled), &state, config);
            if (!maybeProgress(S, sink, &state, config)) {
                state.stopped = true;
                break;
            }
            if (state.pending_skip_to != null and !state.paused) continue;
        }

        if (is_ml and isStartAnchoredMatcher(matcher) and !config.invert and !config.passthru and
            (start_anchored_done or (state.abs_base > 0 and eff_start == 0)) and state.after_left == 0)
        {
            state.bytes_searched = @max(state.bytes_searched, state_mod.searchedSpanAt(&state, config, state.abs_base + filled));
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
        else if (is_ml)
            state.pos
        else
            search_end;
        rememberBefore(matcher, buf, &state, config, consumed);
        countLines(buf, consumed, &state, config);
        filled = realignSlice(buf_storage, &buf, consumed, filled, upstream.raw_cursor, slack);
        state.pos = if (fast_next_pos) |fnp| fnp else if (state.pos >= consumed) state.pos - consumed else 0;
        state.last_line_visited = 0;
        state.last_line_counted = 0;
        state.remembered_until = 0;
        state.abs_base += consumed;
        state.bytes_searched = @max(state.bytes_searched, state_mod.searchedSpanAt(&state, config, state.abs_base));
    }

    return finishSink(S, sink, &state, config);
}


pub const Upstream = struct {
    inner: *anyopaque,
    state: *State,
    config: SearchConfig,
    sink: *anyopaque,
    raw_cursor: u64 = 0,
    spins: u8 = 0,
    spin_at: i128 = 0,
    have_spin: bool = false,
    prefix: [6]u8 = undefined,
    prefix_len: u8 = 0,
    prefix_pos: u8 = 0,
};

fn readRawOnce(comptime readFn: anytype, box: *Upstream, dest: []u8) anyerror!usize {
    if (box.config.read_at) |rat| {
        const n = try rat(box.config.read_at_ctx, box.raw_cursor, dest);
        box.raw_cursor += n;
        return n;
    }
    const n = try readFn(box.inner, dest);
    box.raw_cursor += n;
    return n;
}

pub fn readUpstream(comptime S: type, comptime readFn: anytype, ctx: *anyopaque, dest: []u8) anyerror!usize {
    const box: *Upstream = @ptrCast(@alignCast(ctx));
    if (box.prefix_pos < box.prefix_len) {
        const avail: usize = box.prefix_len - box.prefix_pos;
        const n = @min(avail, dest.len);
        @memcpy(dest[0..n], box.prefix[box.prefix_pos .. box.prefix_pos + n]);
        box.prefix_pos += @intCast(n);
        return n;
    }
    if (!box.config.live) return readRawOnce(readFn, box, dest);
    const sink: *S = @ptrCast(@alignCast(box.sink));
    while (!box.state.stopped) {
        const n = try readRawOnce(readFn, box, dest);
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
            const action = state_mod.callSinkAction(S, "heartbeat", sink, .{ at, box.state.matches, box.state.matched_lines });
            box.state.idle_sent = true;
            switch (action) {
                .cont => {},
                .skip_to => |target| {
                    if (target > at) {
                        box.state.after_left = 0;
                        box.state.ring.clear();
                        box.state.pending_skip_to = target;
                        return 0;
                    }
                },
                .pause => {
                    box.state.paused = true;
                    box.state.resume_at = at;
                    box.state.resume_line = box.state.line_number orelse 0;
                    box.state.stopped = true;
                    return 0;
                },
                .stop => {
                    box.state.stopped = true;
                    return 0;
                },
            }
        }
        if (stopForBudget(box.state, box.config)) return 0;
    }
    return 0;
}

