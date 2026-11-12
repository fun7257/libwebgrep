//! [Module] search/pull.zig
//! [Layer] Layer 4 — Service Event Bridge & Pull-Based Event Iterator (`SourcePull`)
//! [Role] Adapts legacy line callbacks into structured service `Event` streams (`EventBridge`)
//!        and provides the pull-based `SourcePull` iterator (`openSourcePull`).
//! [Invariants]
//!   1. Sources with zero matches still emit `begin` and `end`.
//!   2. `summary` is emitted only when the source is completely scanned without pause or open live stream.

const std = @import("std");
const sink_mod = @import("../sink.zig");
const searcher = @import("../searcher.zig");
const cfg_mod = @import("config.zig");
const state_mod = @import("state.zig");
const decompress_mod = @import("../codec/decompress.zig");
const encoding_mod = @import("../codec/encoding.zig");
const memchr = @import("../finder/memchr.zig");
const regex_mod = @import("../regex.zig");
const matcher_mod = @import("../matcher.zig");
const ring_mod = @import("context_ring.zig");
const format_mod = @import("format.zig");
const line_matcher_mod = @import("line_matcher.zig");
const long_line_mod = @import("long_line.zig");
const pipeline_mod = @import("pipeline.zig");

const SearchConfig = cfg_mod.SearchConfig;
const Event = cfg_mod.Event;
const Flow = cfg_mod.Flow;
const Line = cfg_mod.Line;
const Result = cfg_mod.Result;
const Summary = cfg_mod.Summary;
const Span = cfg_mod.Span;
const BinaryStatus = cfg_mod.BinaryStatus;
const Outcome = cfg_mod.Outcome;
const binaryStatus = cfg_mod.binaryStatus;
const liveIsClosed = state_mod.liveIsClosed;
const searchSourceSlice = searcher.searchSourceSlice;

pub fn eventFlow(inner: anytype, ev: Event) Flow {
    const Ret = @typeInfo(@TypeOf(@field(@TypeOf(inner.*), "event"))).@"fn".return_type.?;
    if (Ret == bool) return if (inner.event(ev)) .cont else .stop;
    if (Ret == Flow) return inner.event(ev);
    @compileError("event must return bool or Flow");
}

pub fn EventBridge(comptime S: type) type {
    return struct {
        inner: *S,
        source_id: []const u8,
        config: SearchConfig,
        last_flow: Flow = .cont,

        const Bridge = @This();

        pub fn control(self: *Bridge) Flow {
            return self.last_flow;
        }

        fn deliver(self: *Bridge, ev: Event) bool {
            const flow = eventFlow(self.inner, ev);
            self.last_flow = flow;
            return flow == .cont;
        }

        pub fn begin(self: *Bridge, _: []const u8) bool {
            if (self.config.continuation) |saved| if (saved.skip_begin) return true;
            return self.deliver(.{ .begin = .{ .source_id = self.source_id } });
        }

        pub fn matched(self: *Bridge, line: Line) bool {
            return self.deliver(.{ .match = lineEvent(self.source_id, line) });
        }

        pub fn context(self: *Bridge, line: Line) bool {
            return self.deliver(.{ .context = lineEvent(self.source_id, line) });
        }

        pub fn contextBreak(self: *Bridge) bool {
            return self.deliver(.{ .context_break = .{ .source_id = self.source_id } });
        }

        pub fn progress(self: *Bridge, bytes_searched: u64, match_count: u64, matched_lines: u64) bool {
            return self.deliver(.{ .progress = .{
                .source_id = self.source_id,
                .bytes_searched = bytes_searched,
                .matches = match_count,
                .matched_lines = matched_lines,
            } });
        }

        pub fn heartbeat(self: *Bridge, bytes_searched: u64, match_count: u64, matched_lines: u64) bool {
            return self.deliver(.{ .heartbeat = .{
                .source_id = self.source_id,
                .bytes_searched = bytes_searched,
                .matches = match_count,
                .matched_lines = matched_lines,
            } });
        }

        pub fn finish(self: *Bridge, result: Result) bool {
            if (result.paused) return true;
            return self.deliver(.{ .end = .{
                .source_id = self.source_id,
                .binary_status = binaryStatus(self.config, result.nul_offset),
                .binary_offset = result.binary_offset,
                .matched_lines = result.matched_lines,
                .matches = result.matches,
                .bytes_read = result.bytes_read,
                .outcome = result.outcome,
                .limit_hit = result.limit_hit,
                .partial = result.partial,
                .resume_at = result.resume_at,
                .soft_error = result.soft_error,
            } });
        }
    };
}

pub fn shouldSummarize(config: SearchConfig, result: Result) bool {
    if (result.paused or !result.scanned_all) return false;
    if (config.live and !liveIsClosed(config)) return false;
    return true;
}

pub fn makeSummary(source_id: []const u8, result: Result) Summary {
    return .{
        .source_id = source_id,
        .elapsed = result.elapsed_ns,
        .searches = 1,
        .searches_with_match = if (result.matched_lines > 0) 1 else 0,
        .bytes_searched = result.bytes_searched,
        .bytes_printed = result.output_bytes,
        .matched_lines = result.matched_lines,
        .matches = result.matches,
        .bytes_read_raw = result.bytes_read,
        .sources_failed = if (result.soft_error != null) 1 else 0,
    };
}

pub fn emitSummary(comptime S: type, sink: *S, source_id: []const u8, config: SearchConfig, result: Result) void {
    if (!shouldSummarize(config, result)) return;
    _ = eventFlow(sink, .{ .summary = makeSummary(source_id, result) });
}

/// A single event yielded by the pull iterator. Slices remain valid until `SourcePull.deinit`.
pub const PullEvent = struct {
    kind: enum { begin, match, context, context_break, progress, heartbeat, end, summary },
    source_id: []u8,
    line_number: u64 = 0,
    column: ?u64 = null,
    u16_column: ?u64 = null,
    absolute_offset: u64 = 0,
    raw_offset: u64 = 0,
    bytes: []u8 = &.{},
    replaced: ?[]u8 = null,
    spans: []Span = &.{},
    truncated: bool = false,
    line_len: u64 = 0,
    window_start: u64 = 0,
    binary_status: BinaryStatus = .none,
    binary_offset: ?u64 = null,
    outcome: Outcome = .complete,
    limit_hit: sink_mod.LimitHit = .none,
    partial: bool = false,
    resume_at: ?u64 = null,
    soft_error: ?sink_mod.SoftError = null,
    matched_lines: u64 = 0,
    matches: u64 = 0,
    bytes_read: u64 = 0,
    bytes_searched: u64 = 0,
    elapsed: u64 = 0,
    searches: u64 = 0,
    searches_with_match: u64 = 0,
    bytes_printed: u64 = 0,
    bytes_read_raw: u64 = 0,
    sources_failed: u64 = 0,

    pub fn deinit(self: *PullEvent, allocator: std.mem.Allocator) void {
        if (self.source_id.len != 0) allocator.free(self.source_id);
        if (self.bytes.len != 0) allocator.free(self.bytes);
        if (self.replaced) |r| if (r.len != 0) allocator.free(r);
        if (self.spans.len != 0) allocator.free(self.spans);
    }
};

/// Pull interface yielding `begin`, `context`, `match`, and `end` events.
/// By contrast, single-line `SliceIter` carries neither context nor source lifecycle events.
pub fn SourcePull(comptime M: type) type {
    return struct {
        allocator: std.mem.Allocator,
        matcher: M,
        source_id: []const u8,
        haystack: []const u8,
        config: SearchConfig,
        items: std.ArrayList(PullEvent) = .empty,
        index: usize = 0,
        loaded: bool = false,

        const Self = @This();

        pub fn deinit(self: *Self) void {
            for (self.items.items) |*item| item.deinit(self.allocator);
            self.items.deinit(self.allocator);
        }

        pub fn next(self: *Self) !?PullEvent {
            if (!self.loaded) {
                try self.load();
                self.loaded = true;
            }
            if (self.index >= self.items.items.len) return null;
            const ev = self.items.items[self.index];
            self.index += 1;
            return ev;
        }

        fn load(self: *Self) !void {
            const Collect = struct {
                pull: *Self,
                failed: bool = false,

                pub fn event(c: *@This(), ev: Event) bool {
                    const copied = copyPull(c.pull.allocator, ev) catch {
                        c.failed = true;
                        return false;
                    };
                    c.pull.items.append(c.pull.allocator, copied) catch {
                        var doomed = copied;
                        doomed.deinit(c.pull.allocator);
                        c.failed = true;
                        return false;
                    };
                    return true;
                }
            };
            var collect = Collect{ .pull = self };
            var cfg = self.config;
            if (cfg.allocator == null and cfg.decode_allocator == null and cfg.scratch_pool == null) {
                cfg.allocator = self.allocator;
            }
            _ = searchSourceSlice(Collect, &collect, self.source_id, self.haystack, self.matcher, cfg) catch |err| return err;
            if (collect.failed) return error.OutOfMemory;
        }
    };
}

pub fn openSourcePull(
    allocator: std.mem.Allocator,
    matcher: anytype,
    source_id: []const u8,
    haystack: []const u8,
    config: SearchConfig,
) SourcePull(@TypeOf(matcher)) {
    return .{
        .allocator = allocator,
        .matcher = matcher,
        .source_id = source_id,
        .haystack = haystack,
        .config = config,
    };
}

pub const PrefixedReader = struct {
    reader: std.Io.Reader,
    upstream: *std.Io.Reader,
    total_upstream_read: u64 = 0,
    prefix: [8]u8 = undefined,
    prefix_len: usize = 0,
    prefix_pos: usize = 0,
    read_buf: [4096]u8 = undefined,

    const vtable: std.Io.Reader.VTable = .{
        .stream = streamFn,
    };

    pub fn init(upstream: *std.Io.Reader, prefix_bytes: []const u8) PrefixedReader {
        var res = PrefixedReader{
            .reader = .{
                .vtable = &vtable,
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },
            .upstream = upstream,
            .prefix_len = prefix_bytes.len,
            .prefix_pos = 0,
        };
        @memcpy(res.prefix[0..prefix_bytes.len], prefix_bytes);
        return res;
    }

    pub fn totalRead(self: *const PrefixedReader) u64 {
        const pulled = self.total_upstream_read + self.prefix_pos;
        const buffered: u64 = @intCast(self.reader.end -| self.reader.seek);
        return pulled -| buffered;
    }

    fn streamFn(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *PrefixedReader = @fieldParentPtr("reader", r);
        if (self.prefix_pos < self.prefix_len) {
            const avail = self.prefix[self.prefix_pos..self.prefix_len];
            const max_len = limit.minInt(avail.len);
            if (max_len > 0) {
                const n = try w.write(avail[0..max_len]);
                self.prefix_pos += n;
                return n;
            }
        }
        const n = try self.upstream.stream(w, limit);
        self.total_upstream_read += n;
        return n;
    }
};

pub const StreamDecompressor = struct {
    pub const Kind = enum { raw, gzip, zstd, xz };

    kind: Kind,
    allocator: std.mem.Allocator,
    prefixed: PrefixedReader,

    flate_dec: ?std.compress.flate.Decompress = null,
    flate_window: ?[]u8 = null,

    zstd_dec: ?std.compress.zstd.Decompress = null,
    zstd_window: ?[]u8 = null,

    xz_dec: ?std.compress.xz.Decompress = null,

    decompressed_bytes: u64 = 0,
    max_decompressed_bytes: ?u64 = null,
    max_compression_ratio: u64 = 100,
    raw_consumed: u64 = 0,
    decompress_map: ?*decompress_mod.OffsetMap = null,
    eof_reached: bool = false,
    corrupt_on_init: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        upstream: *std.Io.Reader,
        mode: cfg_mod.Compression,
        initial_decompressed: u64,
        max_decompressed_bytes: ?u64,
        max_compression_ratio: ?u64,
        decompress_map: ?*decompress_mod.OffsetMap,
    ) !*StreamDecompressor {
        var sniff_buf: [6]u8 = undefined;
        var sniff_len: usize = 0;
        var sniff_eof = false;
        var init_corrupt = false;

        if (mode == .auto) {
            while (sniff_len < 6 and !sniff_eof) {
                const rn = upstream.readSliceShort(sniff_buf[sniff_len..]) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    init_corrupt = true;
                    break;
                };
                sniff_len += rn;
                if (rn == 0) sniff_eof = true;
                const detected = decompress_mod.sniff(sniff_buf[0..sniff_len], sniff_eof);
                if (detected != .need_more) break;
            }
        }

        const kind: Kind = switch (mode) {
            .none => .raw,
            .gzip => .gzip,
            .zstd => .zstd,
            .xz => .xz,
            .auto => switch (decompress_mod.sniff(sniff_buf[0..sniff_len], true)) {
                .gzip => .gzip,
                .zstd => .zstd,
                .xz => .xz,
                else => .raw,
            },
        };

        const self = try allocator.create(StreamDecompressor);
        errdefer allocator.destroy(self);
        self.* = StreamDecompressor{
            .kind = kind,
            .allocator = allocator,
            .prefixed = PrefixedReader.init(upstream, sniff_buf[0..sniff_len]),
            .decompressed_bytes = initial_decompressed,
            .max_decompressed_bytes = max_decompressed_bytes,
            .max_compression_ratio = max_compression_ratio orelse decompress_mod.default_max_compression_ratio,
            .decompress_map = decompress_map,
            .raw_consumed = sniff_len,
            .corrupt_on_init = init_corrupt,
        };
        if (kind != .raw) {
            self.prefixed.reader.buffer = &self.prefixed.read_buf;
        }

        if (!init_corrupt) {
            switch (kind) {
                .raw => {},
                .gzip => {
                    const win = try allocator.alloc(u8, std.compress.flate.max_window_len);
                    self.flate_window = win;
                    self.flate_dec = std.compress.flate.Decompress.init(&self.prefixed.reader, .gzip, win);
                },
                .zstd => {
                    const win_size = std.compress.zstd.default_window_len + std.compress.zstd.block_size_max;
                    const win = try allocator.alloc(u8, win_size);
                    self.zstd_window = win;
                    self.zstd_dec = std.compress.zstd.Decompress.init(&self.prefixed.reader, win, .{});
                },
                .xz => {
                    self.xz_dec = std.compress.xz.Decompress.init(&self.prefixed.reader, allocator, &.{}) catch |err| blk: {
                        if (@as(anyerror, err) == error.OutOfMemory) return error.OutOfMemory;
                        self.corrupt_on_init = true;
                        break :blk null;
                    };
                },
            }
        }

        return self;
    }

    pub fn read(self: *StreamDecompressor, dest: []u8) !usize {
        if (self.corrupt_on_init) return error.CorruptStream;
        if (self.eof_reached) return 0;
        var max_read = if (self.kind == .raw) dest.len else @min(dest.len, 16384);
        if (self.kind != .raw) {
            if (self.max_decompressed_bytes) |cap| {
                const rem = if (cap >= self.decompressed_bytes) (cap - self.decompressed_bytes) + 1 else 1;
                if (max_read > rem) max_read = @intCast(rem);
            }
        }
        const slice_dest = dest[0..max_read];
        const raw_before = self.prefixed.totalRead();
        const out_before = self.decompressed_bytes;
        var n: usize = 0;
        switch (self.kind) {
            .raw => {
                n = self.prefixed.reader.readSliceShort(slice_dest) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    return error.CorruptStream;
                };
                self.raw_consumed = self.prefixed.totalRead();
            },
            .gzip => {
                n = self.flate_dec.?.reader.readSliceShort(slice_dest) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    return error.CorruptStream;
                };
                self.raw_consumed = self.prefixed.totalRead();
            },
            .zstd => {
                n = self.zstd_dec.?.reader.readSliceShort(slice_dest) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    return error.CorruptStream;
                };
                self.raw_consumed = self.prefixed.totalRead();
            },
            .xz => {
                n = self.xz_dec.?.reader.readSliceShort(slice_dest) catch |err| {
                    if (err == error.OutOfMemory) return error.OutOfMemory;
                    return error.CorruptStream;
                };
                self.raw_consumed = self.prefixed.totalRead();
            },
        }

        if (n == 0) {
            self.eof_reached = true;
            if (self.kind != .raw) {
                if (self.decompress_map) |dm| {
                    try dm.record(self.allocator, self.decompressed_bytes, self.raw_consumed);
                }
            }
            return 0;
        }

        if (self.kind != .raw) {
            if (self.decompress_map) |dm| {
                try dm.record(self.allocator, out_before, raw_before);
            }
        }

        self.decompressed_bytes = std.math.add(u64, self.decompressed_bytes, n) catch return error.DecompressLimit;
        if (self.max_decompressed_bytes) |cap| {
            if (self.decompressed_bytes > cap) return error.DecompressLimit;
        }

        if (self.decompressed_bytes >= decompress_mod.ratio_check_min_bytes and self.kind != .raw) {
            const raw_at_least = @max(1, self.raw_consumed);
            const max_allowed = std.math.mul(u64, raw_at_least, self.max_compression_ratio) catch std.math.maxInt(u64);
            if (self.decompressed_bytes > max_allowed) return error.DecompressLimit;
        }

        return n;
    }

    pub fn deinit(self: *StreamDecompressor) void {
        if (self.flate_window) |win| self.allocator.free(win);
        if (self.zstd_window) |win| self.allocator.free(win);
        if (self.xz_dec) |*dec| self.allocator.free(dec.reader.buffer);
        self.allocator.destroy(self);
    }
};

fn PullBridge(comptime M: type) type {
    return struct {
        pull: *ReaderPull(M),

        pub fn deliver(self: *@This(), ev: Event) bool {
            const copied = copyPull(self.pull.allocator, ev) catch {
                return false;
            };
            self.pull.items.append(self.pull.allocator, copied) catch {
                var doomed = copied;
                doomed.deinit(self.pull.allocator);
                return false;
            };
            return true;
        }

        pub fn matched(self: *@This(), line: Line) bool {
            return self.deliver(.{ .match = lineEvent(self.pull.source_id, line) });
        }

        pub fn context(self: *@This(), line: Line) bool {
            return self.deliver(.{ .context = lineEvent(self.pull.source_id, line) });
        }

        pub fn contextBreak(self: *@This()) bool {
            return self.deliver(.{ .context_break = .{ .source_id = self.pull.source_id } });
        }

        pub fn progress(self: *@This(), bytes_searched: u64, match_count: u64, matched_lines: u64) bool {
            return self.deliver(.{ .progress = .{
                .source_id = self.pull.source_id,
                .bytes_searched = bytes_searched,
                .matches = match_count,
                .matched_lines = matched_lines,
            } });
        }

        pub fn heartbeat(self: *@This(), bytes_searched: u64, match_count: u64, matched_lines: u64) bool {
            return self.deliver(.{ .heartbeat = .{
                .source_id = self.pull.source_id,
                .bytes_searched = bytes_searched,
                .matches = match_count,
                .matched_lines = matched_lines,
            } });
        }

        pub fn binary(self: *@This(), offset: u64) bool {
            _ = self;
            _ = offset;
            return true;
        }

        pub fn control(self: *@This()) Flow {
            return if (self.pull.state.stopped) .stop else .cont;
        }
    };
}

/// Streaming pull iterator over a `*std.Io.Reader`.
/// Yields `begin`, `context`, `match`, `progress`, `heartbeat`, `end`, and `summary` events.
/// Slices in returned `PullEvent` remain valid until `ReaderPull.deinit`.
pub fn ReaderPull(comptime M: type) type {
    return struct {
        allocator: std.mem.Allocator,
        matcher: M,
        source_id: []const u8,
        reader: *std.Io.Reader,
        config: SearchConfig,

        pool_alloc: std.mem.Allocator,
        stream_alloc: std.mem.Allocator,
        stream_slot: ?*[]u8 = null,
        buf: []u8 = &.{},
        filled: usize = 0,
        hold: []u8 = &.{},
        seen: []bool = &.{},

        state: state_mod.State = .{},
        offset_map: decompress_mod.OffsetMap = .{},
        decompress_map: decompress_mod.OffsetMap = .{},
        decoder: encoding_mod.Decoder,
        decompressor: *StreamDecompressor,

        items: std.ArrayList(PullEvent) = .empty,
        index: usize = 0,
        phase: Phase = .init,
        search_ended: bool = false,
        scanned_all: bool = false,

        const Self = @This();

        const Phase = enum {
            init,
            reading,
            done,
        };

        pub fn init(
            allocator: std.mem.Allocator,
            matcher: M,
            source_id: []const u8,
            reader: *std.Io.Reader,
            config: SearchConfig,
        ) cfg_mod.ReadError!Self {
            matcher_mod.validateMatcher(M);
            state_mod.resetStats(matcher);
            try cfg_mod.validateBudgets(config);

            const pool_alloc = if (config.scratch_pool) |sp| sp.allocator else (cfg_mod.effectiveAllocator(config) orelse allocator);
            const stream_alloc = if (config.scratch == null and config.scratch_pool != null)
                config.scratch_pool.?.allocator
            else
                allocator;

            const initial = if (state_mod.isMultilineMatcher(matcher))
                @max(cfg_mod.bufferWindow(config), state_mod.multilineWindow(matcher, config))
            else
                cfg_mod.bufferWindow(config);
            const cap0 = @max(initial, 1);

            const stream_slot: ?*[]u8 = if (config.scratch) |slot|
                slot
            else if (config.scratch_pool) |sp|
                &sp.stream_buf
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
            errdefer if (stream_slot == null) stream_alloc.free(buf);

            const hold: []u8 = if (config.scratch_pool) |sp| sp.long_hold else &.{};
            const seen: []bool = if (config.scratch_pool) |sp| sp.long_seen else &.{};

            var state = state_mod.State{};
            const MChild = state_mod.MatcherType(M);
            if (MChild == regex_mod.Regex) {
                state.capture_regex = if (@typeInfo(M) == .pointer) matcher else null;
            } else if (MChild == matcher_mod.AnyMatcher) {
                const any_m: matcher_mod.AnyMatcher = if (@typeInfo(M) == .pointer) matcher.* else matcher;
                var dummy: regex_mod.Regex = undefined;
                const ptr_mut: *regex_mod.Regex = &dummy;
                const ptr_const: *const regex_mod.Regex = &dummy;
                if (any_m.vtable.is_capture_regex or
                    any_m.vtable == matcher_mod.AnyMatcher.init(regex_mod.Regex, ptr_mut).vtable or
                    any_m.vtable == matcher_mod.AnyMatcher.init(regex_mod.Regex, ptr_const).vtable or
                    any_m.vtable == matcher_mod.AnyMatcher.init(*regex_mod.Regex, ptr_mut).vtable or
                    any_m.vtable == matcher_mod.AnyMatcher.init(*const regex_mod.Regex, ptr_const).vtable)
                {
                    state.capture_regex = @ptrCast(@alignCast(any_m.ctx));
                }
            }
            state.label = source_id;
            state.decompressed_bytes = config.decompressed_bytes;
            state_mod.armClock(&state, config);
            state.from_reader = true;
            state.text_alloc = pool_alloc;

            if (config.scratch_pool) |sp| {
                state.text_buf = sp.text_buf;
                state.replace_buf = sp.replace_buf;
                state.span_buf = sp.span_buf;
            }

            state.ring.cap = cfg_mod.beforeCount(config);
            state.ring.stride = config.max_line_len;
            if (state.ring.cap > SearchConfig.context_lines_hard_cap) {
                const needed_slots: usize = state.ring.cap;
                if (config.scratch_pool) |sp| {
                    if (sp.ring_slots.len < needed_slots) {
                        if (sp.ring_slots.len == 0) {
                            sp.ring_slots = try sp.allocator.alloc(cfg_mod.RingSlot, needed_slots);
                        } else {
                            sp.ring_slots = try sp.allocator.realloc(sp.ring_slots, needed_slots);
                        }
                    }
                    state.ring.heap_slots = sp.ring_slots[0..needed_slots];
                } else {
                    state.ring.heap_slots = try allocator.alloc(cfg_mod.RingSlot, needed_slots);
                }
            }
            errdefer if (config.scratch_pool == null and state.ring.heap_slots.len != 0) allocator.free(state.ring.heap_slots);
            if (state.ring.cap > 0) {
                const bytes = cfg_mod.beforeContextCapacity(config);
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
                        state.ring.storage = try allocator.alloc(u8, bytes);
                    }
                }
                state.ring.owned = true;
            }
            errdefer if (config.scratch_pool == null and state.ring.storage.len != 0) allocator.free(state.ring.storage);

            var offset_map = decompress_mod.OffsetMap{};
            var decompress_map = decompress_mod.OffsetMap{};
            state.offset_map = &offset_map;
            state.decompress_map = &decompress_map;

            var decoder = encoding_mod.Decoder.initWithHint(config.encoding, config.charset);
            decoder.max_in = cfg_mod.decodeCap(config);
            decoder.offset_map = &offset_map;
            if (config.scratch_pool) |sp| {
                decoder.raw_buf = sp.decode_buf;
            }

            const max_dec = config.max_decompressed_bytes orelse config.max_source_bytes;
            const decompressor = StreamDecompressor.init(
                allocator,
                reader,
                config.compression,
                config.decompressed_bytes,
                max_dec,
                config.max_compression_ratio,
                &decompress_map,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
            };

            var self = Self{
                .allocator = allocator,
                .matcher = matcher,
                .source_id = source_id,
                .reader = reader,
                .config = config,
                .pool_alloc = pool_alloc,
                .stream_alloc = stream_alloc,
                .stream_slot = stream_slot,
                .buf = buf,
                .filled = 0,
                .hold = hold,
                .seen = seen,
                .state = state,
                .offset_map = offset_map,
                .decompress_map = decompress_map,
                .decoder = decoder,
                .decompressor = decompressor,
                .items = .empty,
                .index = 0,
                .phase = .init,
                .search_ended = false,
                .scanned_all = false,
            };
            self.state.offset_map = &self.offset_map;
            self.state.decompress_map = &self.decompress_map;
            self.decoder.offset_map = &self.offset_map;
            self.decompressor.decompress_map = &self.decompress_map;
            return self;
        }

        pub fn next(self: *Self) !?PullEvent {
            self.state.offset_map = &self.offset_map;
            self.state.decompress_map = &self.decompress_map;
            self.decoder.offset_map = &self.offset_map;
            self.decompressor.decompress_map = &self.decompress_map;

            if (self.index < self.items.items.len) {
                const ev = self.items.items[self.index];
                self.index += 1;
                return ev;
            }

            if (self.phase == .init) {
                if (self.config.line_numbers) self.state.line_number = 1;
                state_mod.restoreCounters(&self.state, self.config);

                var bridge = PullBridge(M){ .pull = self };
                if (self.config.continuation == null or !self.config.continuation.?.skip_begin) {
                    _ = bridge.deliver(.{ .begin = .{ .source_id = self.source_id } });
                }
                if (state_mod.rejectEmptyResults(&self.state, self.config) or state_mod.stopForBudget(&self.state, self.config)) {
                    self.state.stopped = true;
                    self.finishSearch();
                    self.phase = .done;
                } else {
                    self.phase = .reading;
                }
                if (self.index < self.items.items.len) {
                    const ev = self.items.items[self.index];
                    self.index += 1;
                    return ev;
                }
            }

            while (self.phase == .reading and self.index >= self.items.items.len) {
                const cont = try self.step();
                if (!cont) break;
            }

            if (self.index < self.items.items.len) {
                const ev = self.items.items[self.index];
                self.index += 1;
                return ev;
            }

            return null;
        }

        fn step(self: *Self) !bool {
            if (self.phase == .done or self.state.stopped) {
                if (!self.search_ended) {
                    self.finishSearch();
                }
                self.phase = .done;
                return false;
            }

            if (self.state.exceeded(self.config)) {
                self.state.stopped = true;
                self.finishSearch();
                self.phase = .done;
                return false;
            }
            if (state_mod.flagIsSet(self.config)) {
                self.state.stopped = true;
                self.finishSearch();
                self.phase = .done;
                return false;
            }
            if (state_mod.stopForBudget(&self.state, self.config)) {
                self.state.stopped = true;
                self.finishSearch();
                self.phase = .done;
                return false;
            }

            var bridge = PullBridge(M){ .pull = self };

            if (self.filled == self.buf.len) {
                if (try state_mod.grow(self.stream_alloc, self.buf, self.config)) |grown| {
                    self.buf = grown;
                    if (self.stream_slot) |slot| slot.* = self.buf;
                } else if (!try long_line_mod.makeRoom(PullBridge(M), self.pool_alloc, &bridge, self.matcher, &self.buf, &self.filled, &self.hold, &self.seen, &self.state, self.config)) {
                    self.state.stopped = true;
                    self.finishSearch();
                    self.phase = .done;
                    return false;
                } else if (self.stream_slot) |slot| slot.* = self.buf;
            }

            var dest = self.buf[self.filled..];
            if (state_mod.scanRemaining(&self.state, self.config)) |left| {
                if (left == 0) {
                    state_mod.noteLimit(&self.state, .max_bytes);
                    self.state.stopped = true;
                    self.finishSearch();
                    self.phase = .done;
                    return false;
                }
                if (dest.len > left) dest = dest[0..left];
            }

            const ReadCtx = struct {
                dec: *StreamDecompressor,
                fn readFn(ctx: *anyopaque, out: []u8) !usize {
                    const d: *StreamDecompressor = @ptrCast(@alignCast(ctx));
                    return d.read(out);
                }
            };

            var raw_read_sink: u64 = 0;
            const pulled = self.decoder.pull(
                self.pool_alloc,
                ReadCtx.readFn,
                self.decompressor,
                cfg_mod.bufferWindow(self.config),
                dest,
                &raw_read_sink,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                error.DecodeLimit => return error.DecodeLimit,
                error.DecompressLimit => {
                    self.state.decompressed_bytes = self.decompressor.decompressed_bytes;
                    state_mod.noteLimit(&self.state, .decompressed_bytes);
                    self.state.stopped = true;
                    self.finishSearch();
                    self.phase = .done;
                    return false;
                },
                error.CorruptStream => {
                    self.state.decompressed_bytes = self.decompressor.decompressed_bytes;
                    self.state.soft_error = .read_failed;
                    self.state.stopped = true;
                    self.finishSearch();
                    self.phase = .done;
                    return false;
                },
            };

            self.state.decompressed_bytes = self.decompressor.decompressed_bytes;
            if (self.decompressor.kind == .raw) {
                self.state.bytes_read += raw_read_sink;
            } else {
                self.state.bytes_read = self.decompressor.raw_consumed;
            }
            const eof = pulled.eof;
            if (pulled.n == 0 and !eof and self.filled == 0) return true;

            var chunk_at = self.filled;
            if (pulled.n != 0) self.filled += pulled.n;

            if (self.state.long_active or long_line_mod.longTail(self.buf[0..self.filled], eof, self.config)) {
                const cont = try long_line_mod.pumpLong(
                    PullBridge(M),
                    self.pool_alloc,
                    &bridge,
                    self.matcher,
                    &self.buf,
                    &self.filled,
                    &self.hold,
                    &self.seen,
                    chunk_at,
                    eof,
                    &self.state,
                    self.config,
                );
                if (self.stream_slot) |slot| slot.* = self.buf;
                if (!cont) {
                    self.state.stopped = true;
                    self.finishSearch();
                    self.phase = .done;
                    return false;
                }
                if (self.state.long_active) {
                    if (eof) {
                        self.finishSearch();
                        self.phase = .done;
                        return false;
                    }
                    return true;
                }
                chunk_at = 0;
            }

            const search_end = if (eof) self.filled else state_mod.lastComplete(self.buf[0..self.filled], self.config);
            const view_end = if (eof) self.filled else search_end;

            const fuse = search_end > self.state.pos and state_mod.canFuse(self.matcher, self.config, &self.state);
            var skip_match = false;
            if (fuse) {
                var nul_rel: ?usize = null;
                const found = if (comptime @hasDecl(state_mod.MatcherType(@TypeOf(self.matcher)), "findWatched")) self.matcher.findWatched(self.buf[0..search_end], self.state.pos, &nul_rel) else unreachable;
                if (nul_rel == null and search_end < self.filled) {
                    if (memchr.find(cfg_mod.width, self.buf[search_end..self.filled], 0, 0)) |rel| nul_rel = search_end + rel;
                }
                if (nul_rel == null) {
                    if (found) |hit| {
                        if (memchr.find(cfg_mod.width, self.buf[hit.start..self.filled], 0, 0)) |rel| {
                            nul_rel = hit.start + rel;
                        } else {
                            if (hit.start < self.state.pos + 4096) {
                                self.state.prefer_prepass = true;
                            }
                            if (self.config.progress_interval == null or self.config.progress_interval.? == 0) {
                                self.state.pos = state_mod.lineStart(self.buf[0..view_end], hit.start, self.config);
                            }
                        }
                    } else {
                        skip_match = true;
                        self.state.pos = view_end;
                    }
                }
                if (nul_rel) |rel| {
                    if (self.config.binary == .quit) {
                        const safe_end = state_mod.lineStart(self.buf[0..rel], rel, self.config);
                        if (safe_end > self.state.pos) {
                            if (!try line_matcher_mod.matchBuffer(PullBridge(M), &bridge, self.matcher, self.buf[0..safe_end], &self.state, self.config)) {
                                self.state.stopped = true;
                                self.finishSearch();
                                self.phase = .done;
                                return false;
                            }
                        }
                        state_mod.noteBinary(&self.state, self.config, self.state.abs_base + rel);
                        _ = bridge.binary(self.state.nul_offset.?);
                        self.filled = safe_end;
                        self.state.stopped = true;
                        self.finishSearch();
                        self.phase = .done;
                        return false;
                    }
                    state_mod.noteBinary(&self.state, self.config, self.state.abs_base + rel);
                    const cont = bridge.binary(self.state.nul_offset.?);
                    if (!cont) {
                        self.filled = chunk_at;
                        self.state.stopped = true;
                        self.finishSearch();
                        self.phase = .done;
                        return false;
                    }
                    skip_match = false;
                }
            } else if (chunk_at < self.filled and cfg_mod.watchesBinary(self.config) and self.state.nul_offset == null) {
                if (memchr.find(cfg_mod.width, self.buf[chunk_at..self.filled], 0, 0)) |rel| {
                    const nul_idx = chunk_at + rel;
                    if (self.config.binary == .quit) {
                        const safe_end = state_mod.lineStart(self.buf[0..nul_idx], nul_idx, self.config);
                        if (safe_end > self.state.pos) {
                            if (!try line_matcher_mod.matchBuffer(PullBridge(M), &bridge, self.matcher, self.buf[0..safe_end], &self.state, self.config)) {
                                self.state.stopped = true;
                                self.finishSearch();
                                self.phase = .done;
                                return false;
                            }
                        }
                        state_mod.noteBinary(&self.state, self.config, self.state.abs_base + nul_idx);
                        _ = bridge.binary(self.state.nul_offset.?);
                        self.filled = safe_end;
                        self.state.stopped = true;
                        self.finishSearch();
                        self.phase = .done;
                        return false;
                    }
                    state_mod.noteBinary(&self.state, self.config, self.state.abs_base + nul_idx);
                    const cont = bridge.binary(self.state.nul_offset.?);
                    if (!cont) {
                        self.filled = chunk_at;
                        self.state.stopped = true;
                        self.finishSearch();
                        self.phase = .done;
                        return false;
                    }
                }
            }

            const is_ml = state_mod.isMultilineMatcher(self.matcher);
            const ml_win = if (is_ml) state_mod.multilineWindow(self.matcher, self.config) else 0;
            if (is_ml and !eof and self.filled < ml_win and !self.config.passthru and !self.config.invert) {
                if (self.matcher.find(self.buf[0..search_end], self.state.pos, self.config.match_mode) == null) {
                    return true;
                }
            }

            if (!skip_match and (search_end > self.state.pos or eof)) {
                if (!try line_matcher_mod.matchBuffer(PullBridge(M), &bridge, self.matcher, self.buf[0..view_end], &self.state, self.config)) {
                    self.state.stopped = true;
                    if (eof and self.state.pos >= view_end and !self.state.output_blocked) self.scanned_all = true;
                    self.finishSearch();
                    self.phase = .done;
                    return false;
                }
            } else if (skip_match) {
                if (!state_mod.maybeProgress(PullBridge(M), &bridge, &self.state, self.config)) {
                    self.state.stopped = true;
                    self.finishSearch();
                    self.phase = .done;
                    return false;
                }
            }

            if (is_ml and state_mod.isStartAnchoredMatcher(self.matcher) and self.state.abs_base + self.filled >= ml_win) {
                self.state.stopped = true;
                self.finishSearch();
                self.phase = .done;
                return false;
            }

            if (eof) {
                self.scanned_all = !self.state.output_blocked and self.state.soft_error == null;
                self.finishSearch();
                self.phase = .done;
                return false;
            }

            const consumed = if (is_ml and search_end > ml_win)
                @max(self.state.last_line_visited, state_mod.lineEnd(self.buf[0..search_end], search_end - ml_win, self.config))
            else
                search_end;
            if (is_ml and consumed < search_end) {
                self.state.pos = consumed;
            }
            ring_mod.rememberBefore(self.matcher, self.buf, &self.state, self.config, consumed);
            state_mod.countLines(self.buf, consumed, &self.state, self.config);
            const remain = self.filled - consumed;
            if (consumed > 0 and remain > 0) {
                std.mem.copyForwards(u8, self.buf[0..remain], self.buf[consumed..self.filled]);
            }
            self.filled = remain;
            self.state.pos = if (self.state.pos >= consumed) self.state.pos - consumed else 0;
            self.state.last_line_visited = 0;
            self.state.last_line_counted = 0;
            self.state.remembered_until = 0;
            self.state.abs_base += consumed;

            return true;
        }

        fn finishSearch(self: *Self) void {
            if (self.search_ended) return;
            self.search_ended = true;

            const cursor = self.state.abs_base + @as(u64, self.state.pos);
            if (cursor > self.state.bytes_searched) self.state.bytes_searched = cursor;
            state_mod.closeOnce(&self.state, self.config);

            var outcome: Outcome = if (self.state.stopped) .stopped else .complete;
            if (self.state.nul_offset != null and self.config.binary == .quit) outcome = .binary_quit;
            if (self.state.nul_offset != null and self.config.binary == .report and self.state.matched_lines > 0) {
                outcome = .binary_matched;
            }
            const partial = (self.state.limit_hit != .none or self.state.output_blocked or self.state.soft_error != null) and !self.scanned_all;

            const end_ev = Event{
                .end = .{
                    .source_id = self.source_id,
                    .binary_status = binaryStatus(self.config, self.state.nul_offset),
                    .binary_offset = self.state.nul_offset,
                    .matched_lines = self.state.matched_lines,
                    .matches = self.state.matches,
                    .bytes_read = self.state.bytes_read,
                    .outcome = outcome,
                    .limit_hit = self.state.limit_hit,
                    .partial = partial,
                    .resume_at = self.state.resume_at,
                    .soft_error = self.state.soft_error,
                },
            };
            var bridge = PullBridge(M){ .pull = self };
            _ = bridge.deliver(end_ev);

            if (self.scanned_all and self.state.soft_error == null and !self.state.paused) {
                const res = Result{
                    .matches = self.state.matches,
                    .matched_lines = self.state.matched_lines,
                    .bytes_searched = self.state.bytes_searched,
                    .output_bytes = self.state.output_bytes,
                    .bytes_read = self.state.bytes_read,
                    .elapsed_ns = state_mod.elapsedOf(&self.state, self.config),
                    .scanned_all = true,
                    .outcome = outcome,
                    .limit_hit = self.state.limit_hit,
                    .soft_error = self.state.soft_error,
                };
                const summary_ev = Event{ .summary = makeSummary(self.source_id, res) };
                _ = bridge.deliver(summary_ev);
            }
        }

        pub fn deinit(self: *Self) void {
            for (self.items.items) |*item| item.deinit(self.allocator);
            self.items.deinit(self.allocator);

            if (self.config.scratch_pool) |sp| {
                sp.text_buf = self.state.text_buf;
                sp.replace_buf = self.state.replace_buf;
                sp.span_buf = self.state.span_buf;
                sp.long_hold = self.hold;
                sp.long_seen = self.seen;
                sp.decode_buf = self.decoder.raw_buf;
                self.decoder.raw_buf = &.{};
            } else {
                if (self.state.text_buf.len != 0) self.pool_alloc.free(self.state.text_buf);
                if (self.state.replace_buf.len != 0) self.pool_alloc.free(self.state.replace_buf);
                if (self.state.span_buf.len != 0) self.pool_alloc.free(self.state.span_buf);
                if (self.hold.len != 0) self.pool_alloc.free(self.hold);
                if (self.seen.len != 0) self.pool_alloc.free(self.seen);
            }

            if (self.config.scratch_pool == null and self.state.ring.heap_slots.len != 0) {
                self.allocator.free(self.state.ring.heap_slots);
            }
            if (self.config.scratch_pool == null and self.state.ring.storage.len != 0) {
                self.allocator.free(self.state.ring.storage);
            }

            if (self.stream_slot) |slot| {
                slot.* = self.buf;
            } else {
                self.stream_alloc.free(self.buf);
            }

            self.decoder.deinit(self.pool_alloc);
            self.offset_map.deinit(self.pool_alloc);
            self.decompress_map.deinit(self.allocator);
            self.decompressor.deinit();
        }
    };
}

/// Initializes a streaming pull iterator over `reader` with caller-assigned `source_id` and `matcher`.
/// Reads chunks on demand during `next()` without buffering the entire stream.
/// Validates multi-tenant budgets upfront.
pub fn openReaderPull(
    allocator: std.mem.Allocator,
    matcher: anytype,
    source_id: []const u8,
    reader: *std.Io.Reader,
    config: SearchConfig,
) cfg_mod.ReadError!ReaderPull(@TypeOf(matcher)) {
    const cfg = cfg_mod.serviceConfig(config);
    return ReaderPull(@TypeOf(matcher)).init(allocator, matcher, source_id, reader, cfg);
}

pub fn copyPull(allocator: std.mem.Allocator, ev: Event) !PullEvent {
    switch (ev) {
        .begin => |b| return .{ .kind = .begin, .source_id = try allocator.dupe(u8, b.source_id) },
        .context_break => |b| return .{ .kind = .context_break, .source_id = try allocator.dupe(u8, b.source_id) },
        .progress => |p| return .{
            .kind = .progress,
            .source_id = try allocator.dupe(u8, p.source_id),
            .bytes_searched = p.bytes_searched,
            .matches = p.matches,
            .matched_lines = p.matched_lines,
        },
        .heartbeat => |h| return .{
            .kind = .heartbeat,
            .source_id = try allocator.dupe(u8, h.source_id),
            .bytes_searched = h.bytes_searched,
            .matches = h.matches,
            .matched_lines = h.matched_lines,
        },
        .end => |e| return .{
            .kind = .end,
            .source_id = try allocator.dupe(u8, e.source_id),
            .binary_status = e.binary_status,
            .binary_offset = e.binary_offset,
            .matched_lines = e.matched_lines,
            .matches = e.matches,
            .bytes_read = e.bytes_read,
            .outcome = e.outcome,
            .limit_hit = e.limit_hit,
            .partial = e.partial,
            .resume_at = e.resume_at,
            .soft_error = e.soft_error,
        },
        .summary => |s| return .{
            .kind = .summary,
            .source_id = try allocator.dupe(u8, s.source_id),
            .matched_lines = s.matched_lines,
            .matches = s.matches,
            .bytes_searched = s.bytes_searched,
            .elapsed = s.elapsed,
            .searches = s.searches,
            .searches_with_match = s.searches_with_match,
            .bytes_printed = s.bytes_printed,
            .bytes_read_raw = s.bytes_read_raw,
            .sources_failed = s.sources_failed,
        },
        .match, .context => |line| {
            const id = try allocator.dupe(u8, line.source_id);
            errdefer allocator.free(id);
            var bytes: []u8 = &.{};
            errdefer if (bytes.len != 0) allocator.free(bytes);
            if (line.bytes.len != 0) bytes = try allocator.dupe(u8, line.bytes);
            var replaced: ?[]u8 = null;
            errdefer if (replaced) |r| if (r.len != 0) allocator.free(r);
            if (line.replaced) |r| replaced = try allocator.dupe(u8, r);
            var spans: []Span = &.{};
            errdefer if (spans.len != 0) allocator.free(spans);
            if (line.matches.len != 0) spans = try allocator.dupe(Span, line.matches);
            return .{
                .kind = if (ev == .match) .match else .context,
                .source_id = id,
                .line_number = line.line_number,
                .column = line.column,
                .u16_column = line.u16_column,
                .absolute_offset = line.absolute_offset,
                .raw_offset = line.raw_offset,
                .bytes = bytes,
                .replaced = replaced,
                .spans = spans,
                .truncated = line.truncated,
                .line_len = line.line_len,
                .window_start = line.window_start,
                .binary_status = line.binary_status,
                .matched_lines = 0,
                .matches = @intCast(line.matches.len),
            };
        },
    }
}

pub fn lineEvent(source_id: []const u8, line: Line) sink_mod.LineEvent {
    const u16_column = if (line.matches.len > 0)
        @as(u64, line.matches[0].u16_start) + 1
    else
        line.u16_column;
    return .{
        .source_id = source_id,
        .line_number = line.number orelse 0,
        .column = line.column,
        .u16_column = u16_column,
        .absolute_offset = line.offset,
        .raw_offset = line.raw_offset,
        .bytes = line.bytes,
        .text = if (line.text.len == 0) line.bytes else line.text,
        .raw = if (line.raw.len == 0) line.bytes else line.raw,
        .replaced = line.replaced,
        .matches = line.matches,
        .truncated = line.truncated,
        .line_len = line.line_len,
        .window_start = line.window_start,
        .binary_status = line.binary_status,
    };
}

test "openReaderPull streams chunks and emits events incrementally" {
    const raw_text = "first line\nmatch here: alpha\nthird line\nmatch here: beta\nlast line\n";
    var reader = std.Io.Reader.fixed(raw_text);
    var f = try @import("../finder/finder.zig").Finder.init("match here", .{});

    var pull = try openReaderPull(std.testing.allocator, &f, "stream-1", &reader, .{});
    defer pull.deinit();

    // 1. First event should be begin
    const ev1 = (try pull.next()) orelse return error.TestExpectedNotNull;
    try std.testing.expectEqual(ev1.kind, .begin);
    try std.testing.expectEqualStrings("stream-1", ev1.source_id);

    // 2. Second event should be match: alpha
    const ev2 = (try pull.next()) orelse return error.TestExpectedNotNull;
    try std.testing.expectEqual(ev2.kind, .match);
    try std.testing.expectEqualStrings("match here: alpha", ev2.bytes);
    try std.testing.expectEqual(@as(u64, 2), ev2.line_number);

    // 3. Third event should be match: beta
    const ev3 = (try pull.next()) orelse return error.TestExpectedNotNull;
    try std.testing.expectEqual(ev3.kind, .match);
    try std.testing.expectEqualStrings("match here: beta", ev3.bytes);
    try std.testing.expectEqual(@as(u64, 4), ev3.line_number);

    // 4. Fourth event should be end
    const ev4 = (try pull.next()) orelse return error.TestExpectedNotNull;
    try std.testing.expectEqual(ev4.kind, .end);
    try std.testing.expectEqual(@as(u64, 2), ev4.matched_lines);
    try std.testing.expectEqual(@as(u64, 2), ev4.matches);

    // 5. Fifth event should be summary
    const ev5 = (try pull.next()) orelse return error.TestExpectedNotNull;
    try std.testing.expectEqual(ev5.kind, .summary);
    try std.testing.expectEqual(@as(u64, 2), ev5.matches);

    // 6. Sixth call should be null
    try std.testing.expect(try pull.next() == null);
}

test "openReaderPull decompresses gzip streaming chunks on the fly" {
    const raw_text = "compressed match line 1\nregular line\ncompressed match line 2\n";
    const compressed = try decompress_mod.compressGzipStoredAlloc(std.testing.allocator, raw_text);
    defer std.testing.allocator.free(compressed);

    var reader = std.Io.Reader.fixed(compressed);
    var f = try @import("../finder/finder.zig").Finder.init("compressed match", .{});

    var pull = try openReaderPull(std.testing.allocator, &f, "gz-stream", &reader, .{
        .compression = .gzip,
    });
    defer pull.deinit();

    var match_count: usize = 0;
    while (try pull.next()) |ev| {
        if (ev.kind == .match) {
            match_count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 2), match_count);
}

test "openReaderPull early break stops reading" {
    const raw_text = "match 1\nmatch 2\nmatch 3\n";
    var reader = std.Io.Reader.fixed(raw_text);
    var f = try @import("../finder/finder.zig").Finder.init("match", .{});

    var pull = try openReaderPull(std.testing.allocator, &f, "break-stream", &reader, .{});
    defer pull.deinit();

    _ = try pull.next(); // begin
    const m1 = try pull.next(); // match 1
    try std.testing.expect(m1 != null);
}

