//! [Module] search/parallel_source.zig
//! [Layer] Layer 4 — Intra-Source Parallel Search (`searchSourceSliceParallel`, `searchSourceParallelAt`,
//!         `countSliceParallel`, `countParallelAt`)
//! [Role] Splits ONE large source into record-aligned chunks, scans the chunks concurrently on
//!        `std.Io.Group.concurrent` workers (plus the calling thread) with the unmodified sequential engine,
//!        and replays the recorded results strictly in byte order on the calling thread, so sinks observe the
//!        same event stream as the sequential entry points.
//! [Invariants]
//!   1. Sink callbacks run only on the calling thread, in ascending byte order, never interleaved.
//!   2. Memory is bounded: at most `max_inflight` chunks are scanned ahead of the in-order emitter, recorded
//!      events never exceed `max_buffered_bytes`, and each RandomAccess worker holds one chunk buffer
//!      (`chunk_size + 256 KiB`). Slice inputs are borrowed and never copied.
//!   3. Global limits (`max_count`, `max_results`, `exists`, `max_output_bytes`, `max_queued_event_bytes`) and
//!      sink flow (`stop`, `pause`, `skip_to`) are applied during in-order replay with the same helpers the
//!      sequential engine uses. Chunk tails the replay cannot reproduce exactly (NUL bytes, recording overflow,
//!      oversized lines, mid-chunk `skip_to`) are re-run sequentially with counters seeded via `ResumeState`.
//!   4. Configurations the chunked model cannot reproduce exactly (context lines, passthru, invert, multiline matchers,
//!      input-anchored regexes, transcoding, decompression, `line_filter`, live streams, resumption, progress
//!      events, `BinaryPolicy.report`) fall back to the sequential engine before any sink callback runs.
//! [HotPath] `scanChunk` (workers) and `deliver` (emitter replay).

const std = @import("std");
const builtin = @import("builtin");
const decompress = @import("../codec/decompress.zig");
const encoding = @import("../codec/encoding.zig");
const matcher_mod = @import("../matcher.zig");
const memchr = @import("../finder/memchr.zig");
const probe_mod = @import("../probe.zig");
const regex_mod = @import("../regex.zig");
const sink_mod = @import("../sink.zig");
const cfg_mod = @import("config.zig");
const state_mod = @import("state.zig");
const pipeline_mod = @import("pipeline.zig");
const pull_mod = @import("pull.zig");
const searcher = @import("../searcher.zig");

const RandomAccess = probe_mod.RandomAccess;
const SearchConfig = cfg_mod.SearchConfig;
const SliceError = cfg_mod.SliceError;
const ReadError = cfg_mod.ReadError;
const Result = cfg_mod.Result;
const Line = cfg_mod.Line;
const Span = cfg_mod.Span;
const State = state_mod.State;
const width = cfg_mod.width;

/// Default nominal bytes per chunk task. 256 KiB keeps each scanner's working set in its core-private L2
/// cache; on an 8-core Apple M2 it matches 1 MiB chunks in throughput at roughly half the peak RSS.
pub const default_chunk_size: usize = 256 * 1024;
/// Default cap on bytes held by recorded line events across all in-flight chunks.
pub const default_max_buffered_bytes: usize = 4 * 1024 * 1024;
/// Hard cap on concurrent scanners (including the calling thread).
pub const max_workers_hard_cap: u32 = 64;
/// Extra bytes a RandomAccess worker buffer may hold beyond `chunk_size` for lines that straddle a chunk end.
const ra_overhang: usize = 256 * 1024;

/// Tuning knobs for intra-source parallel search.
pub const ParallelOptions = struct {
    /// Total concurrent scanners including the calling thread. `null` uses `SearchConfig.max_concurrency`,
    /// then the logical CPU count. Clamped to `1..max_workers_hard_cap`.
    workers: ?u32 = null,
    /// Nominal bytes per chunk task. Chunks are re-aligned to record boundaries.
    chunk_size: usize = default_chunk_size,
    /// Maximum chunks scanned ahead of the in-order emitter. `null` uses `2 * workers`.
    max_inflight: ?u32 = null,
    /// Upper bound on bytes held by recorded line events across all in-flight chunks.
    max_buffered_bytes: usize = default_max_buffered_bytes,
    /// Searchable regions smaller than this run sequentially. `null` uses `2 * chunk_size`.
    min_parallel_bytes: ?usize = null,

    /// `default_chunk_size` expressed in KiB (for CLIs and benchmarks).
    pub const default_chunk_kib: usize = default_chunk_size / 1024;
};

/// Resolves the effective scanner count (including the calling thread) for `opts` and `config`.
pub fn resolveWorkers(opts: ParallelOptions, config: SearchConfig) u32 {
    if (builtin.single_threaded) return 1;
    const requested: u32 = opts.workers orelse config.max_concurrency orelse blk: {
        const n = std.Thread.getCpuCount() catch 1;
        break :blk @intCast(@min(n, @as(usize, max_workers_hard_cap)));
    };
    return @max(1, @min(requested, max_workers_hard_cap));
}

// ============================================================================
// Eligibility
// ============================================================================

fn instsHaveInputAnchor(insts: []const regex_mod.Inst) bool {
    for (insts) |inst| switch (inst) {
        .assert => |a| switch (a.kind) {
            .start_input, .end_input, .end_input_before_nl => return true,
            else => {},
        },
        else => {},
    };
    return false;
}

fn anyMatcherIs(comptime M: type, any_m: matcher_mod.AnyMatcher) bool {
    var dummy: M = undefined;
    const ptr_mut: *M = &dummy;
    const ptr_const: *const M = &dummy;
    return any_m.vtable == matcher_mod.AnyMatcher.init(M, ptr_mut).vtable or
        any_m.vtable == matcher_mod.AnyMatcher.init(M, ptr_const).vtable or
        any_m.vtable == matcher_mod.AnyMatcher.init(*M, ptr_mut).vtable or
        any_m.vtable == matcher_mod.AnyMatcher.init(*const M, ptr_const).vtable;
}

/// True when the matcher contains `\A`, `\z`, or `\Z`, whose meaning depends on the haystack boundaries.
fn hasInputAnchors(matcher: anytype) bool {
    const T = state_mod.MatcherType(@TypeOf(matcher));
    if (T == regex_mod.Regex or T == regex_mod.RegexSet) return instsHaveInputAnchor(matcher.insts);
    if (T == matcher_mod.AnyMatcher) {
        const any_m: matcher_mod.AnyMatcher = if (@typeInfo(@TypeOf(matcher)) == .pointer) matcher.* else matcher;
        if (any_m.vtable.is_capture_regex or anyMatcherIs(regex_mod.Regex, any_m)) {
            const re: *const regex_mod.Regex = @ptrCast(@alignCast(any_m.ctx));
            return instsHaveInputAnchor(re.insts);
        }
        if (anyMatcherIs(regex_mod.RegexSet, any_m)) {
            const rs: *const regex_mod.RegexSet = @ptrCast(@alignCast(any_m.ctx));
            return instsHaveInputAnchor(rs.insts);
        }
    }
    return false;
}

/// Configuration-level eligibility. Data-dependent checks (BOM, compression magic, size) happen later.
fn configEligible(matcher: anytype, config: SearchConfig) bool {
    if (builtin.single_threaded) return false;
    if (state_mod.effectiveMultiline(matcher, config)) return false;
    if (state_mod.isStartAnchoredMatcher(matcher)) return false;
    if (hasInputAnchors(matcher)) return false;
    if (cfg_mod.beforeCount(config) > 0 or cfg_mod.afterCount(config) > 0) return false;
    // Inverted search advances past the next matching line (possibly chunks later) before emitting a gap.
    if (config.invert) return false;
    if (config.passthru or config.files_without_match or config.stop_on_nonmatch) return false;
    if (config.line_filter != null) return false;
    if (config.live or config.continuation != null or config.resume_from != 0 or config.stream_offset != null) return false;
    if (config.progress_interval) |p| if (p != 0) return false;
    if (config.binary == .report) return false;
    if (config.compression != .none and config.compression != .auto) return false;
    const enc = encoding.resolveHint(config.encoding, config.charset);
    if (enc != .none and enc != .auto) return false;
    return true;
}

/// True when the source header would make the sequential engine decompress or transcode.
fn headerNeedsTransform(head: []const u8, config: SearchConfig) bool {
    if (config.compression == .auto) {
        const det = decompress.sniff(head, true);
        if (det != .raw and det != .need_more) return true;
    }
    if (encoding.resolveHint(config.encoding, config.charset) == .auto) {
        const bom = encoding.sniff(head, true);
        if (bom != .raw and bom != .need_more) return true;
    }
    return false;
}

// ============================================================================
// Recorded events
// ============================================================================

const Ref = struct {
    tag: enum(u8) { none, hay, arena } = .none,
    off: usize = 0,
    len: usize = 0,
};

const SpanRec = struct {
    span: Span,
    repl: ?Ref,
};

const Rec = struct {
    offset: u64,
    raw_offset: u64,
    line_end: u64,
    number: ?u64,
    ends_sep: bool,
    bytes: Ref,
    text: Ref,
    raw: Ref,
    replaced: ?Ref,
    spans_off: usize,
    spans_len: usize,
    match: ?SpanRec,
    column: ?u64,
    u16_column: ?u64,
    binary_status: sink_mod.BinaryStatus,
    truncated: bool,
    line_len: u64,
    window_start: u64,
};

const SlotState = enum(u8) { free, busy, done };

const Slot = struct {
    state: SlotState = .free,
    chunk: usize = 0,
    start: u64 = 0,
    end: u64 = 0,
    newlines: u64 = 0,
    counted: bool = false,
    result: Result = .{},
    err: ?anyerror = null,
    read_failed: bool = false,
    oversized: bool = false,
    overflow: bool = false,
    overflow_offset: u64 = 0,
    overflow_number: ?u64 = null,
    recs: std.ArrayList(Rec) = .empty,
    arena: std.ArrayList(u8) = .empty,
    spans: std.ArrayList(SpanRec) = .empty,

    fn reset(self: *Slot) void {
        self.start = 0;
        self.end = 0;
        self.newlines = 0;
        self.counted = false;
        self.result = .{};
        self.err = null;
        self.read_failed = false;
        self.oversized = false;
        self.overflow = false;
        self.overflow_offset = 0;
        self.overflow_number = null;
        self.recs.clearRetainingCapacity();
        self.arena.clearRetainingCapacity();
        self.spans.clearRetainingCapacity();
    }

    fn deinit(self: *Slot, allocator: std.mem.Allocator) void {
        self.recs.deinit(allocator);
        self.arena.deinit(allocator);
        self.spans.deinit(allocator);
    }
};

/// Records matched lines of one chunk. Slice inputs are borrowed by offset; other bytes are copied.
const Recorder = struct {
    allocator: std.mem.Allocator,
    slot: *Slot,
    base: u64,
    data: []const u8,
    hay: ?[]const u8,
    cap: usize,
    used: usize = 0,
    sep: u8,
    null_data: bool,

    fn within(hay: []const u8, s: []const u8) bool {
        const lo = @intFromPtr(hay.ptr);
        const p = @intFromPtr(s.ptr);
        return p >= lo and p + s.len <= lo + hay.len;
    }

    fn costOf(self: *const Recorder, s: []const u8) usize {
        if (s.len == 0) return 0;
        if (self.hay) |h| if (within(h, s)) return 0;
        return s.len;
    }

    fn ref(self: *Recorder, s: []const u8) error{OutOfMemory}!Ref {
        if (s.len == 0) return .{};
        if (self.hay) |h| if (within(h, s)) return .{ .tag = .hay, .off = @intFromPtr(s.ptr) - @intFromPtr(h.ptr), .len = s.len };
        const off = self.slot.arena.items.len;
        try self.slot.arena.appendSlice(self.allocator, s);
        return .{ .tag = .arena, .off = off, .len = s.len };
    }

    fn spanRec(self: *Recorder, sp: Span) error{OutOfMemory}!SpanRec {
        var plain = sp;
        plain.replacement = null;
        return .{ .span = plain, .repl = if (sp.replacement) |r| try self.ref(r) else null };
    }

    fn record(self: *Recorder, line: Line, rel: usize, line_end_rel: usize, ends_sep: bool) error{OutOfMemory}!void {
        const same_text = line.text.ptr == line.bytes.ptr and line.text.len == line.bytes.len;
        const same_raw = line.raw.ptr == line.bytes.ptr and line.raw.len == line.bytes.len;
        const bytes_ref = try self.ref(line.bytes);
        const text_ref = if (same_text) bytes_ref else try self.ref(line.text);
        const raw_ref = if (same_raw) bytes_ref else try self.ref(line.raw);
        const replaced_ref: ?Ref = if (line.replaced) |r| try self.ref(r) else null;
        const spans_off = self.slot.spans.items.len;
        for (line.matches) |sp| try self.slot.spans.append(self.allocator, try self.spanRec(sp));
        const match_rec: ?SpanRec = if (line.match) |m| try self.spanRec(m) else null;
        try self.slot.recs.append(self.allocator, .{
            .offset = self.base + @as(u64, rel),
            .raw_offset = self.base + line.raw_offset,
            .line_end = self.base + @as(u64, line_end_rel),
            .number = line.number,
            .ends_sep = ends_sep,
            .bytes = bytes_ref,
            .text = text_ref,
            .raw = raw_ref,
            .replaced = replaced_ref,
            .spans_off = spans_off,
            .spans_len = line.matches.len,
            .match = match_rec,
            .column = line.column,
            .u16_column = line.u16_column,
            .binary_status = line.binary_status,
            .truncated = line.truncated,
            .line_len = line.line_len,
            .window_start = line.window_start,
        });
    }

    pub fn matched(self: *Recorder, line: Line) bool {
        const rel: usize = @intCast(line.offset);
        var e: usize = rel + @as(usize, @intCast(line.line_len));
        if (!self.null_data and e < self.data.len and self.data[e] == '\r') e += 1;
        const ends_sep = e < self.data.len and self.data[e] == self.sep;
        if (ends_sep) e += 1;

        var need: usize = @sizeOf(Rec) + line.matches.len * @sizeOf(SpanRec);
        need += self.costOf(line.bytes);
        if (!(line.text.ptr == line.bytes.ptr and line.text.len == line.bytes.len)) need += self.costOf(line.text);
        if (!(line.raw.ptr == line.bytes.ptr and line.raw.len == line.bytes.len)) need += self.costOf(line.raw);
        if (line.replaced) |r| need += self.costOf(r);
        for (line.matches) |sp| if (sp.replacement) |r| {
            need += self.costOf(r);
        };
        if (line.match) |m| if (m.replacement) |r| {
            need += self.costOf(r);
        };

        if (self.used + need > self.cap) return self.overflowAt(line, rel);
        self.record(line, rel, e, ends_sep) catch return self.overflowAt(line, rel);
        self.used += need;
        return true;
    }

    fn overflowAt(self: *Recorder, line: Line, rel: usize) bool {
        self.slot.overflow = true;
        self.slot.overflow_offset = self.base + @as(u64, rel);
        self.slot.overflow_number = line.number;
        return false;
    }
};

/// Count-only sink: lacks `matched`, so the engine takes its allocation-free counting path.
const CountSink = struct {};

/// Forwards a sequential re-run of one chunk tail to the outer sink, shifting offsets to absolute positions.
/// `begin_skip` (absolute) reproduces an in-stream `skip_to` that lands inside the re-run view.
fn DirectSink(comptime B: type) type {
    if (@hasDecl(B, "matched")) {
        return struct {
            inner: *B,
            shift: u64,
            begin_skip: ?u64 = null,
            last_skip: ?u64 = null,

            pub fn begin(self: *@This(), _: []const u8) sink_mod.FlowAction {
                if (self.begin_skip) |t| return .{ .skip_to = t -| self.shift };
                return .cont;
            }

            pub fn matched(self: *@This(), line: Line) sink_mod.FlowAction {
                var l = line;
                l.offset += self.shift;
                l.raw_offset += self.shift;
                const act = state_mod.callSinkAction(B, "matched", self.inner, .{l});
                return switch (act) {
                    .skip_to => |t| blk: {
                        self.last_skip = t;
                        break :blk .{ .skip_to = t -| self.shift };
                    },
                    else => act,
                };
            }

            pub fn binary(self: *@This(), offset: u64) bool {
                return state_mod.callOpt(B, "binary", self.inner, .{offset + self.shift});
            }
        };
    }
    return struct {
        inner: *B,
        shift: u64,
        begin_skip: ?u64 = null,
        last_skip: ?u64 = null,

        pub fn begin(self: *@This(), _: []const u8) sink_mod.FlowAction {
            if (self.begin_skip) |t| return .{ .skip_to = t -| self.shift };
            return .cont;
        }

        pub fn binary(self: *@This(), offset: u64) bool {
            return state_mod.callOpt(B, "binary", self.inner, .{offset + self.shift});
        }
    };
}

fn sequentialSlice(comptime S: type, sink: *S, haystack: []const u8, name: []const u8, matcher: anytype, config: SearchConfig) SliceError!Result {
    var prepared = try pipeline_mod.materialize(haystack, config);
    defer prepared.deinit();
    var result = try pipeline_mod.searchPrepared(S, sink, &prepared, name, matcher, config);
    if (prepared.owned.len != 0 or prepared.transformed) result.bytes_read = haystack.len;
    return result;
}

// ============================================================================
// Workers
// ============================================================================

const Input = union(enum) {
    slice: []const u8,
    ra: RandomAccess,
};

const Worker = struct {
    scratch: cfg_mod.Scratch,
    buf: []u8 = &.{},

    fn init(allocator: std.mem.Allocator) Worker {
        return .{ .scratch = cfg_mod.Scratch.init(allocator) };
    }

    fn deinit(self: *Worker, allocator: std.mem.Allocator) void {
        self.scratch.deinit();
        if (self.buf.len != 0) allocator.free(self.buf);
        self.buf = &.{};
    }

    fn ensureBuf(self: *Worker, allocator: std.mem.Allocator, n: usize) error{OutOfMemory}![]u8 {
        if (self.buf.len >= n) return self.buf;
        if (self.buf.len != 0) allocator.free(self.buf);
        self.buf = &.{};
        self.buf = try allocator.alloc(u8, n);
        return self.buf;
    }
};

const Term = enum { stop, nul };

fn Run(comptime B: type, comptime MT: type) type {
    return struct {
        const Self = @This();
        const count_mode = !@hasDecl(B, "matched");
        const DS = DirectSink(B);

        allocator: std.mem.Allocator,
        io: std.Io,
        matcher: MT,
        config: SearchConfig,
        wcfg: SearchConfig,
        input: Input,
        vs: u64,
        ve: u64,
        chunk: u64,
        n_chunks: usize,
        slots: []Slot,
        window: usize,
        rec_cap: usize,
        buf_cap: usize,
        numbering: bool,
        sep: u8,
        mu: std.Io.Mutex = .init,
        cv: std.Io.Condition = .init,
        next_chunk: usize = 0,
        consumed: usize = 0,
        abort: std.atomic.Value(bool) = .init(false),
        total_read: std.atomic.Value(u64) = .init(0),
        span_tmp: std.ArrayList(Span) = .empty,

        // ---------------- scheduling ----------------

        fn workerMain(self: *Self) std.Io.Cancelable!void {
            var w = Worker.init(self.allocator);
            defer w.deinit(self.allocator);
            while (self.claim()) |k| {
                self.scanChunk(&w, k);
                self.publish(k);
            }
        }

        fn claim(self: *Self) ?usize {
            self.mu.lockUncancelable(self.io);
            defer self.mu.unlock(self.io);
            while (true) {
                if (self.abort.load(.acquire)) return null;
                const j = self.next_chunk;
                if (j >= self.n_chunks) return null;
                if (j < self.consumed + self.window) {
                    self.next_chunk = j + 1;
                    const slot = &self.slots[j % self.window];
                    slot.state = .busy;
                    slot.chunk = j;
                    return j;
                }
                self.cv.waitUncancelable(self.io, &self.mu);
            }
        }

        fn publish(self: *Self, k: usize) void {
            self.mu.lockUncancelable(self.io);
            self.slots[k % self.window].state = .done;
            self.cv.broadcast(self.io);
            self.mu.unlock(self.io);
        }

        /// Waits for chunk `k`, scanning other claimable chunks on the calling thread meanwhile.
        fn waitChunk(self: *Self, k: usize, ew: *Worker) *Slot {
            const slot = &self.slots[k % self.window];
            self.mu.lockUncancelable(self.io);
            while (!(slot.state == .done and slot.chunk == k)) {
                const j = self.next_chunk;
                if (j < self.n_chunks and j < self.consumed + self.window) {
                    self.next_chunk = j + 1;
                    const s = &self.slots[j % self.window];
                    s.state = .busy;
                    s.chunk = j;
                    self.mu.unlock(self.io);
                    self.scanChunk(ew, j);
                    self.mu.lockUncancelable(self.io);
                    s.state = .done;
                    self.cv.broadcast(self.io);
                    continue;
                }
                self.cv.waitUncancelable(self.io, &self.mu);
            }
            self.mu.unlock(self.io);
            return slot;
        }

        fn release(self: *Self, k: usize) void {
            self.mu.lockUncancelable(self.io);
            self.slots[k % self.window].state = .free;
            self.consumed = k + 1;
            self.cv.broadcast(self.io);
            self.mu.unlock(self.io);
        }

        fn stopAll(self: *Self) void {
            self.mu.lockUncancelable(self.io);
            self.abort.store(true, .release);
            self.cv.broadcast(self.io);
            self.mu.unlock(self.io);
        }

        // ---------------- chunk geometry ----------------

        fn alignSlice(self: *const Self, hay: []const u8, nom: u64) u64 {
            if (nom <= self.vs) return self.vs;
            if (nom >= self.ve) return self.ve;
            const n: usize = @intCast(nom);
            if (hay[n - 1] == self.sep) return nom;
            const end: usize = @intCast(self.ve);
            const i = memchr.find(width, hay[0..end], n, self.sep) orelse return self.ve;
            return @as(u64, i) + 1;
        }

        fn alignRa(self: *Self, ra: RandomAccess, nom: u64) anyerror!u64 {
            if (nom <= self.vs) return self.vs;
            if (nom >= self.ve) return self.ve;
            var one: [1]u8 = undefined;
            const n1 = try ra.readAtFull(nom - 1, &one);
            _ = self.total_read.fetchAdd(n1, .monotonic);
            if (n1 == 0) return self.ve;
            if (one[0] == self.sep) return nom;
            var probe: [16 * 1024]u8 = undefined;
            var cur = nom;
            while (cur < self.ve) {
                const want: usize = @intCast(@min(@as(u64, probe.len), self.ve - cur));
                const got = try ra.readAtFull(cur, probe[0..want]);
                _ = self.total_read.fetchAdd(got, .monotonic);
                if (got == 0) return self.ve;
                if (memchr.find(width, probe[0..got], 0, self.sep)) |i| return cur + i + 1;
                cur += got;
            }
            return self.ve;
        }

        fn bounds(self: *Self, k: usize) anyerror!struct { u64, u64 } {
            const nom_s = self.vs + @as(u64, k) * self.chunk;
            const nom_e = @min(self.ve, nom_s + self.chunk);
            const last = k + 1 == self.n_chunks;
            switch (self.input) {
                .slice => |hay| {
                    const a = if (k == 0) self.vs else self.alignSlice(hay, nom_s);
                    const b = if (last) self.ve else self.alignSlice(hay, nom_e);
                    return .{ a, @max(a, b) };
                },
                .ra => |ra| {
                    const a = if (k == 0) self.vs else try self.alignRa(ra, nom_s);
                    const b = if (last) self.ve else try self.alignRa(ra, nom_e);
                    return .{ a, @max(a, b) };
                },
            }
        }

        fn countSeps(self: *Self, a: u64, b: u64) anyerror!u64 {
            if (b <= a) return 0;
            switch (self.input) {
                .slice => |hay| return memchr.count(width, hay, @intCast(a), @intCast(b), self.sep),
                .ra => |ra| {
                    var probe: [16 * 1024]u8 = undefined;
                    var cur = a;
                    var n: u64 = 0;
                    while (cur < b) {
                        const want: usize = @intCast(@min(@as(u64, probe.len), b - cur));
                        const got = try ra.readAtFull(cur, probe[0..want]);
                        _ = self.total_read.fetchAdd(got, .monotonic);
                        if (got == 0) break;
                        n += memchr.count(width, probe[0..got], 0, got, self.sep);
                        cur += got;
                    }
                    return n;
                },
            }
        }

        // ---------------- scanning ----------------

        fn scanChunk(self: *Self, w: *Worker, k: usize) void {
            const slot = &self.slots[k % self.window];
            slot.reset();
            const ab = self.bounds(k) catch {
                slot.read_failed = true;
                return;
            };
            slot.start = ab[0];
            slot.end = ab[1];
            if (slot.start >= slot.end) return;
            if (self.abort.load(.acquire)) return;
            switch (self.input) {
                .slice => |hay| self.scanData(w, slot, hay[@intCast(slot.start)..@intCast(slot.end)], hay),
                .ra => |ra| {
                    const len: usize = @intCast(slot.end - slot.start);
                    if (len > self.buf_cap) {
                        slot.oversized = true;
                        return;
                    }
                    const buf = w.ensureBuf(self.allocator, len) catch {
                        slot.err = error.OutOfMemory;
                        return;
                    };
                    const got = ra.readAtFull(slot.start, buf[0..len]) catch {
                        slot.read_failed = true;
                        return;
                    };
                    _ = self.total_read.fetchAdd(got, .monotonic);
                    if (got != len) {
                        slot.read_failed = true;
                        return;
                    }
                    self.scanData(w, slot, buf[0..len], null);
                },
            }
        }

        fn scanData(self: *Self, w: *Worker, slot: *Slot, data: []const u8, hay: ?[]const u8) void {
            if (self.numbering) slot.newlines = memchr.count(width, data, 0, data.len, self.sep);
            slot.counted = true;
            var cfg = self.wcfg;
            cfg.scratch_pool = &w.scratch;
            if (count_mode) {
                var cs = CountSink{};
                slot.result = sequentialSlice(CountSink, &cs, data, "", self.matcher, cfg) catch |err| {
                    slot.err = err;
                    return;
                };
            } else {
                var rec = Recorder{
                    .allocator = self.allocator,
                    .slot = slot,
                    .base = slot.start,
                    .data = data,
                    .hay = hay,
                    .cap = self.rec_cap,
                    .sep = self.sep,
                    .null_data = self.config.null_data,
                };
                slot.result = sequentialSlice(Recorder, &rec, data, "", self.matcher, cfg) catch |err| {
                    slot.err = err;
                    return;
                };
            }
        }

        // ---------------- in-order replay ----------------

        fn resolve(self: *const Self, slot: *const Slot, r: Ref) []const u8 {
            return switch (r.tag) {
                .none => &.{},
                .hay => self.input.slice[r.off..][0..r.len],
                .arena => slot.arena.items[r.off..][0..r.len],
            };
        }

        fn resolveSpan(self: *const Self, slot: *const Slot, sr: SpanRec) Span {
            var sp = sr.span;
            sp.replacement = if (sr.repl) |r| self.resolve(slot, r) else null;
            return sp;
        }

        fn deliver(self: *Self, sink: *B, G: *State, slot: *const Slot, rec: Rec, line_base: ?u64) SliceError!?Term {
            self.span_tmp.clearRetainingCapacity();
            for (slot.spans.items[rec.spans_off..][0..rec.spans_len]) |sr| {
                try self.span_tmp.append(self.allocator, self.resolveSpan(slot, sr));
            }
            const num: ?u64 = if (rec.number) |n| (if (line_base) |b| b + n - 1 else null) else null;
            const line = Line{
                .bytes = self.resolve(slot, rec.bytes),
                .text = self.resolve(slot, rec.text),
                .raw = self.resolve(slot, rec.raw),
                .replaced = if (rec.replaced) |r| self.resolve(slot, r) else null,
                .offset = rec.offset,
                .raw_offset = rec.raw_offset,
                .number = num,
                .match = if (rec.match) |m| self.resolveSpan(slot, m) else null,
                .u16_column = rec.u16_column,
                .matches = self.span_tmp.items,
                .column = rec.column,
                .binary_status = rec.binary_status,
                .truncated = rec.truncated,
                .line_len = rec.line_len,
                .window_start = rec.window_start,
            };

            // Mirrors `matchBuffer` + `sinkMatched` for sinks that implement `matched`.
            G.limit_count += 1;
            G.pos = @intCast(rec.line_end - self.vs);
            G.line_number = num;
            if (!try state_mod.guardLine(G, self.config, line.bytes.len)) return .stop;
            const action = state_mod.callSinkAction(B, "matched", sink, .{line});
            state_mod.releaseQueue(G);
            G.last_abs_end = rec.line_end;
            G.has_sunk = true;
            G.matched_lines += 1;
            G.matches += if (line.matches.len > 0) @as(u64, @intCast(line.matches.len)) else 1;
            G.results_out += 1;
            const next_num: ?u64 = if (num) |n| n + @intFromBool(rec.ends_sep) else null;
            var keep = true;
            switch (action) {
                .cont => {},
                .skip_to => |t| if (t > rec.line_end) {
                    G.pending_skip_to = t;
                },
                .pause => {
                    G.paused = true;
                    G.resume_at = rec.line_end;
                    G.resume_line = next_num orelse 0;
                    G.stopped = true;
                    keep = false;
                },
                .stop => {
                    G.stopped = true;
                    keep = false;
                },
            }
            G.line_number = next_num;
            if (G.paused) return .stop;
            if (!state_mod.noteHitLimit(G, self.config, rec.line_end)) return .stop;
            if (!keep) return .stop;
            if (G.exceeded(self.config)) {
                G.stopped = true;
                G.need_close = true;
                return .stop;
            }
            return null;
        }

        /// Re-runs `[start, end)` sequentially with counters seeded from `G`, delivering straight to `sink`.
        /// `ln` is the line number at `start`. `begin_skip` (absolute, inside the view) replays a pending
        /// `skip_to`; the engine counts lines up to it, so the resulting line number is always adopted.
        fn direct(self: *Self, sink: *B, G: *State, start: u64, end: u64, ln: ?u64, begin_skip: ?u64, ew: *Worker) ReadError!?Term {
            if (start >= end) {
                G.pos = @intCast(end - self.vs);
                return null;
            }
            var saved = sink_mod.ResumeState{
                .matched_lines = G.matched_lines,
                .matches = G.matches,
                .bytes_read = 0,
                .bytes_searched = 0,
                .output_bytes = G.output_bytes,
                .results_out = G.results_out,
                .limit_count = G.limit_count,
                .line_number = ln orelse 0,
                .started_ns = G.started_ns,
                .deadline_armed = G.deadline_armed,
                .skip_begin = true,
            };
            var cfg = self.config;
            cfg.byte_range = null;
            cfg.range_align_lines = false;
            cfg.stream_offset = null;
            cfg.resume_from = 0;
            cfg.encoding = .none;
            cfg.charset = null;
            cfg.compression = .none;
            cfg.max_source_bytes = null;
            cfg.max_request_bytes = null;
            cfg.continuation = &saved;
            cfg.line_numbers = self.numbering;
            cfg.line_number_mode = if (self.numbering) .from_one else .unknown;
            cfg.initial_line_number = null;
            cfg.close_input = null;
            cfg.close_ctx = null;
            cfg.scratch = null;
            cfg.scratch_pool = &ew.scratch;
            cfg.allocator = self.allocator;

            var ds = DS{ .inner = sink, .shift = start, .begin_skip = begin_skip };
            var rel_shift: u64 = start;
            const prev_matched = G.matched_lines;
            const r: Result = switch (self.input) {
                .slice => |hay| try sequentialSlice(DS, &ds, hay[@intCast(start)..@intCast(end)], "", self.matcher, cfg),
                .ra => |ra| blk: {
                    const len: usize = @intCast(end - start);
                    if (len <= self.buf_cap) {
                        const buf = try ew.ensureBuf(self.allocator, len);
                        const got = ra.readAtFull(start, buf[0..len]) catch |err| {
                            state_mod.logDetail(self.config, G.label, err);
                            G.soft_error = .read_failed;
                            G.stopped = true;
                            return .stop;
                        };
                        _ = self.total_read.fetchAdd(got, .monotonic);
                        if (got != len) {
                            G.soft_error = .read_failed;
                            G.stopped = true;
                            return .stop;
                        }
                        break :blk try sequentialSlice(DS, &ds, buf[0..len], "", self.matcher, cfg);
                    }
                    ds.shift = 0;
                    rel_shift = 0;
                    const rr = try searcher.searchRange(DS, self.allocator, &ds, ra, .{ .start = start, .end = end }, "", self.matcher, cfg);
                    _ = self.total_read.fetchAdd(rr.bytes_read, .monotonic);
                    break :blk rr;
                },
            };

            G.matched_lines = r.matched_lines;
            G.matches = r.matches;
            G.output_bytes = r.output_bytes;
            G.results_out = r.resume_state.results_out;
            G.limit_count = r.resume_state.limit_count;
            G.pos = @intCast(start + r.bytes_searched - self.vs);
            // The engine counts lines only at matches (or up to a `skip_to` target); otherwise keep `G` unchanged.
            if (self.numbering and (r.matched_lines != prev_matched or begin_skip != null)) {
                G.line_number = if (r.resume_state.line_number == 0) null else r.resume_state.line_number;
            }
            if (r.paused) {
                G.paused = true;
                G.stopped = true;
                G.resume_at = if (r.resume_at) |ra| ra + rel_shift else start + r.bytes_searched;
                G.resume_line = r.resume_state.line_number;
                return .stop;
            }
            if (r.nul_offset) |n| {
                state_mod.noteBinary(G, self.config, n + rel_shift);
                return .nul;
            }
            if (r.soft_error) |e| {
                G.soft_error = e;
                G.stopped = true;
                return .stop;
            }
            if (r.limit_hit != .none) {
                state_mod.noteLimit(G, r.limit_hit);
                if (r.limit_hit == .max_results) {
                    if (r.resume_at) |ra| G.resume_at = ra + rel_shift;
                }
                return .stop;
            }
            if (r.partial) {
                G.output_blocked = true;
                G.stopped = true;
                G.need_close = true;
                return .stop;
            }
            if (r.outcome == .stopped) {
                G.stopped = true;
                if (G.exceeded(self.config) or (self.config.exists and G.matched_lines > 0)) G.need_close = true;
                return .stop;
            }
            if (ds.last_skip) |t| {
                if (t > end) G.pending_skip_to = t;
            }
            return null;
        }

        fn processChunk(self: *Self, sink: *B, G: *State, slot: *Slot, line_base: ?u64, ew: *Worker) ReadError!?Term {
            if (slot.read_failed) {
                // Recompute the geometry on the calling thread; a persistent failure becomes a soft error.
                const ab = self.bounds(slot.chunk) catch |err| {
                    state_mod.logDetail(self.config, G.label, err);
                    G.soft_error = .read_failed;
                    G.stopped = true;
                    return .stop;
                };
                slot.start = ab[0];
                slot.end = ab[1];
                slot.counted = false;
                slot.recs.clearRetainingCapacity();
                slot.overflow = false;
                slot.oversized = true;
            }
            if (self.numbering and !slot.counted and slot.end > slot.start) {
                slot.newlines = self.countSeps(slot.start, slot.end) catch {
                    G.soft_error = .read_failed;
                    G.stopped = true;
                    return .stop;
                };
                slot.counted = true;
            }

            if (G.pending_skip_to) |t| {
                if (t <= slot.start) {
                    // The sequential engine lands exactly on this chunk start and counts lines up to it.
                    G.pending_skip_to = null;
                    if (self.numbering) G.line_number = line_base;
                } else if (t >= slot.end) {
                    G.pos = @intCast(slot.end - self.vs);
                    return null;
                } else {
                    G.pending_skip_to = null;
                    return self.directFrom(sink, G, slot, t, line_base, ew);
                }
            }

            if (slot.start >= slot.end) {
                G.pos = @intCast(slot.end - self.vs);
                return null;
            }

            if (slot.err != null or slot.oversized) {
                return self.direct(sink, G, slot.start, slot.end, line_base, null, ew);
            }

            const r = slot.result;
            if (count_mode) {
                if (state_mod.flagIsSet(self.config)) {
                    G.stopped = true;
                    return .stop;
                }
                if (state_mod.stopInMatch(G, self.config)) return .stop;
                const rs = r.resume_state;
                var clean = r.scanned_all or r.nul_offset != null;
                if (clean and r.matched_lines > 0) {
                    if (self.config.max_count) |cap| if (G.limit_count + rs.limit_count >= cap) {
                        clean = false;
                    };
                    if (self.config.max_results) |cap| if (G.results_out + rs.results_out >= cap) {
                        clean = false;
                    };
                    if (self.config.exists) clean = false;
                    if (self.config.max_output_bytes) |cap| if (G.output_bytes + r.output_bytes >= cap) {
                        clean = false;
                    };
                }
                if (!clean) return self.direct(sink, G, slot.start, slot.end, line_base, null, ew);
                G.matched_lines += r.matched_lines;
                G.matches += r.matches;
                G.limit_count += rs.limit_count;
                G.results_out += rs.results_out;
                G.output_bytes += r.output_bytes;
                // The engine counts lines only at matches, so adopt the worker's numbering only when it matched.
                if (r.matched_lines > 0) self.adoptLineNumber(G, r, line_base);
                if (r.nul_offset) |n| {
                    G.pos = @intCast(slot.start + r.bytes_searched - self.vs);
                    state_mod.noteBinary(G, self.config, slot.start + n);
                    _ = state_mod.callOpt(B, "binary", sink, .{G.nul_offset.?});
                    return .nul;
                }
                G.pos = @intCast(slot.end - self.vs);
                return null;
            }

            for (slot.recs.items) |rec| {
                if (G.pending_skip_to != null) break;
                if (G.stopped) return .stop;
                if (state_mod.flagIsSet(self.config)) {
                    G.stopped = true;
                    return .stop;
                }
                if (state_mod.stopInMatch(G, self.config)) return .stop;
                if (try self.deliver(sink, G, slot, rec, line_base)) |t| return t;
            }
            if (G.pending_skip_to) |t| {
                if (t >= slot.end) {
                    G.pos = @intCast(slot.end - self.vs);
                    return null;
                }
                G.pending_skip_to = null;
                return self.directFrom(sink, G, slot, t, line_base, ew);
            }
            if (slot.overflow) {
                const ln: ?u64 = if (slot.overflow_number) |n| (if (line_base) |b| b + n - 1 else null) else null;
                return self.direct(sink, G, slot.overflow_offset, slot.end, ln, null, ew);
            }
            if (r.nul_offset) |n| {
                // Line numbers were already advanced by the replayed matches; the NUL path counts nothing.
                G.pos = @intCast(slot.start + r.bytes_searched - self.vs);
                state_mod.noteBinary(G, self.config, slot.start + n);
                _ = state_mod.callOpt(B, "binary", sink, .{G.nul_offset.?});
                return .nul;
            }
            if (!r.scanned_all) {
                // The worker stopped early (local limit or abort); continue sequentially after its last record.
                const resume_at = if (slot.recs.items.len > 0) slot.recs.items[slot.recs.items.len - 1].line_end else slot.start;
                const ln: ?u64 = if (line_base) |b| b + (self.countSeps(slot.start, resume_at) catch 0) else null;
                return self.direct(sink, G, resume_at, slot.end, ln, null, ew);
            }
            G.pos = @intCast(slot.end - self.vs);
            return null;
        }

        /// Converts a worker's chunk-relative final line number into the global numbering.
        fn adoptLineNumber(self: *const Self, G: *State, r: Result, line_base: ?u64) void {
            if (!self.numbering) return;
            const b = line_base orelse return;
            const rel = r.resume_state.line_number;
            if (rel == 0) return;
            G.line_number = b + rel - 1;
        }

        /// Start of the record containing `t`, searching back no further than `lo` (a record start).
        fn recordStart(self: *Self, lo: u64, t: u64) anyerror!u64 {
            if (t <= lo) return lo;
            switch (self.input) {
                .slice => |hay| {
                    const i = memchr.findLast(width, hay, @intCast(lo), @intCast(t), self.sep) orelse return lo;
                    return @as(u64, i) + 1;
                },
                .ra => |ra| {
                    var probe: [16 * 1024]u8 = undefined;
                    var cur = t;
                    while (cur > lo) {
                        const want: usize = @intCast(@min(@as(u64, probe.len), cur - lo));
                        const from = cur - want;
                        const got = try ra.readAtFull(from, probe[0..want]);
                        _ = self.total_read.fetchAdd(got, .monotonic);
                        if (got != want) return error.ReadFailed;
                        if (memchr.findLast(width, probe[0..got], 0, got, self.sep)) |i| return from + i + 1;
                        cur = from;
                    }
                    return lo;
                },
            }
        }

        /// Replays a `skip_to` landing at `t` inside `slot`: the sequential engine resumes scanning at `t`
        /// but still reports whole records, so the re-run view starts at the record containing `t`.
        fn directFrom(self: *Self, sink: *B, G: *State, slot: *const Slot, t: u64, line_base: ?u64, ew: *Worker) ReadError!?Term {
            const ls = self.recordStart(slot.start, t) catch {
                G.soft_error = .read_failed;
                G.stopped = true;
                return .stop;
            };
            const ln: ?u64 = if (line_base) |b| blk: {
                const n = self.countSeps(slot.start, ls) catch {
                    G.soft_error = .read_failed;
                    G.stopped = true;
                    return .stop;
                };
                break :blk b + n;
            } else null;
            return self.direct(sink, G, ls, slot.end, ln, t, ew);
        }
    };
}

// ============================================================================
// Core driver
// ============================================================================

const View = struct {
    vs: u64,
    ve: u64,
};

/// Computes the searchable view of a RandomAccess source exactly like `state.budgetView` does for slices.
fn raView(ra: RandomAccess, size: u64, sep: u8, G: *State, config: SearchConfig) anyerror!View {
    const eff_start = state_mod.effectiveRangeStart(config);
    var start: u64 = @min(eff_start, size);
    if (config.range_align_lines and eff_start > 0 and start > 0 and start < size) {
        start = try raAlign(ra, start, size, sep);
    }
    var end: u64 = size;
    if (config.byte_range) |br| {
        G.is_range_search = true;
        if (br.end) |be| {
            const raw_end = @min(be, size);
            if (raw_end <= start) {
                end = start;
            } else if (config.range_align_lines and raw_end < size) {
                end = try raAlign(ra, raw_end, size, sep);
            } else {
                end = raw_end;
            }
        }
    }
    G.abs_base = start;
    if (G.is_range_search) G.range_base_offset = start;
    if (cfg_mod.scanCap(config)) |cap| {
        if (end - start > cap) {
            end = start + cap;
            G.hit_byte_cap = true;
        }
    }
    return .{ .vs = start, .ve = end };
}

fn raAlign(ra: RandomAccess, pos: u64, size: u64, sep: u8) anyerror!u64 {
    var one: [1]u8 = undefined;
    if (try ra.readAtFull(pos - 1, &one) == 0) return size;
    if (one[0] == sep) return pos;
    var probe: [16 * 1024]u8 = undefined;
    var cur = pos;
    while (cur < size) {
        const want: usize = @intCast(@min(@as(u64, probe.len), size - cur));
        const got = try ra.readAtFull(cur, probe[0..want]);
        if (got == 0) return size;
        if (memchr.find(width, probe[0..got], 0, sep)) |i| return cur + i + 1;
        cur += got;
    }
    return size;
}

/// Runs the parallel path, or returns `null` (before any sink callback) when the sequential engine must be used.
fn tryParallel(
    comptime B: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: *B,
    input: Input,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
    opts: ParallelOptions,
) ReadError!?Result {
    if (!configEligible(matcher, config)) return null;
    const workers = resolveWorkers(opts, config);
    if (workers <= 1) return null;
    const sep = cfg_mod.recordSep(config);
    const chunk: u64 = @max(@as(u64, opts.chunk_size), 16);
    const min_bytes: u64 = opts.min_parallel_bytes orelse 2 * chunk;

    var G = State{};
    G.label = name;
    var view: View = undefined;
    switch (input) {
        .slice => |hay| {
            if (headerNeedsTransform(hay[0..@min(hay.len, 64)], config)) return null;
            const v = state_mod.budgetView(hay, 0, &G, config);
            view = .{ .vs = G.abs_base, .ve = G.abs_base + v.len };
        },
        .ra => |ra| {
            const size = ra.size orelse return null;
            var head: [64]u8 = undefined;
            const hn = ra.readAtFull(0, head[0..@intCast(@min(size, 64))]) catch return null;
            if (headerNeedsTransform(head[0..hn], config)) return null;
            G.from_reader = true;
            view = raView(ra, size, sep, &G, config) catch return null;
        },
    }
    const view_len = view.ve - view.vs;
    if (view_len < min_bytes or view_len <= chunk) return null;
    try cfg_mod.validateBudgets(config);

    const n_chunks: usize = @intCast((view_len + chunk - 1) / chunk);
    const window: usize = @max(2, @min(n_chunks, @as(usize, opts.max_inflight orelse 2 * workers)));
    const R = Run(B, @TypeOf(matcher));

    var wcfg = config;
    wcfg.byte_range = null;
    wcfg.range_align_lines = false;
    wcfg.stream_offset = null;
    wcfg.encoding = .none;
    wcfg.charset = null;
    wcfg.compression = .none;
    wcfg.continuation = null;
    wcfg.resume_from = 0;
    wcfg.initial_line_number = null;
    wcfg.max_source_bytes = null;
    wcfg.max_request_bytes = null;
    wcfg.time_budget_ns = null;
    wcfg.clock = null;
    wcfg.clock_ctx = null;
    wcfg.log = null;
    wcfg.log_ctx = null;
    wcfg.close_input = null;
    wcfg.close_ctx = null;
    wcfg.scratch = null;
    wcfg.allocator = allocator;
    wcfg.decode_allocator = null;
    wcfg.seek_input = null;
    wcfg.seek_ctx = null;
    wcfg.read_at = null;
    wcfg.read_at_ctx = null;
    if (R.count_mode) {
        // Count-mode workers keep exact output accounting but never block; the emitter applies the real cap.
        if (config.max_output_bytes != null) wcfg.max_output_bytes = std.math.maxInt(u64);
    } else {
        // Record-mode replay applies output and queue caps exactly, line by line.
        wcfg.max_output_bytes = null;
        wcfg.max_queued_event_bytes = null;
    }

    state_mod.armClock(&G, config);
    state_mod.initLineNumber(&G, config, state_mod.effectiveRangeStart(config));
    const numbering = G.line_number != null;
    wcfg.line_numbers = numbering;
    wcfg.line_number_mode = if (numbering) .from_one else .unknown;

    const slots = try allocator.alloc(Slot, window);
    for (slots) |*s| s.* = .{};
    defer {
        for (slots) |*s| s.deinit(allocator);
        allocator.free(slots);
    }

    var run = R{
        .allocator = allocator,
        .io = io,
        .matcher = matcher,
        .config = config,
        .wcfg = wcfg,
        .input = input,
        .vs = view.vs,
        .ve = view.ve,
        .chunk = chunk,
        .n_chunks = n_chunks,
        .slots = slots,
        .window = window,
        .rec_cap = @max(opts.max_buffered_bytes / window, 1),
        .buf_cap = @intCast(chunk + ra_overhang),
        .numbering = numbering,
        .sep = sep,
    };
    run.wcfg.stop = &run.abort;
    defer run.span_tmp.deinit(allocator);

    var ew = Worker.init(allocator);
    defer ew.deinit(allocator);

    const finish = struct {
        fn f(r: *R, s: *B, g: *State) Result {
            if (r.input == .ra) g.bytes_read = r.total_read.load(.monotonic);
            return state_mod.finishSink(B, s, g, r.config);
        }
    }.f;

    switch (state_mod.callSinkAction(B, "begin", sink, .{name})) {
        .cont => {},
        .skip_to => |target| {
            if (target > G.abs_base) G.pending_skip_to = target;
        },
        .pause => {
            G.paused = true;
            G.stopped = true;
            G.resume_at = G.abs_base;
            G.resume_line = G.line_number orelse 0;
            return finish(&run, sink, &G);
        },
        .stop => {
            G.stopped = true;
            return finish(&run, sink, &G);
        },
    }
    if (state_mod.rejectEmptyResults(&G, config)) return finish(&run, sink, &G);
    if (state_mod.stopForBudget(&G, config)) return finish(&run, sink, &G);

    var group: std.Io.Group = .init;
    {
        const helpers: usize = @min(@as(usize, workers - 1), n_chunks - 1);
        var i: usize = 0;
        while (i < helpers) : (i += 1) {
            group.concurrent(io, R.workerMain, .{&run}) catch break;
        }
    }
    defer {
        run.stopAll();
        group.await(io) catch {};
    }

    var line_base: ?u64 = G.line_number;
    var term: ?Term = null;
    var k: usize = 0;
    while (k < n_chunks) : (k += 1) {
        const slot = run.waitChunk(k, &ew);
        const t = run.processChunk(sink, &G, slot, line_base, &ew) catch |err| {
            run.release(k);
            return err;
        };
        if (line_base) |b| line_base = b + slot.newlines;
        run.release(k);
        if (t) |tt| {
            term = tt;
            break;
        }
    }
    run.stopAll();

    if (term) |tt| if (tt == .nul) {
        if (G.hit_byte_cap) state_mod.noteLimit(&G, .max_bytes);
        return finish(&run, sink, &G);
    };
    if (term == null) {
        G.pos = @intCast(view_len);
        if (G.pending_skip_to != null) {
            // A skip past the view end makes the sequential engine count lines through the whole view.
            G.pending_skip_to = null;
            if (numbering) G.line_number = line_base;
        }
    }
    const consumed_w = (!G.stopped or G.pos >= view_len) and !G.output_blocked;
    if (consumed_w and !G.hit_byte_cap and G.soft_error == null) G.scanned_all = true;
    if (G.hit_byte_cap) state_mod.noteLimit(&G, .max_bytes);
    return finish(&run, sink, &G);
}

fn narrowSlice(err: ReadError) SliceError {
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.ContextLinesExceeded => error.ContextLinesExceeded,
        error.BufferLimit => error.BufferLimit,
        error.BudgetExceeded => error.BudgetExceeded,
        error.DecodeLimit => error.DecodeLimit,
        else => unreachable, // slice inputs perform no reads
    };
}

// ============================================================================
// Public entry points
// ============================================================================

/// Legacy callback entry point: parallel equivalent of `searchSlice` (`Line` callbacks on the calling thread).
/// `allocator` must be thread-safe. Falls back to `searchSlice` when the configuration is not chunk-safe.
pub fn searchSliceParallel(
    comptime S: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: *S,
    haystack: []const u8,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
    opts: ParallelOptions,
) SliceError!Result {
    matcher_mod.validateMatcher(@TypeOf(matcher));
    state_mod.resetStats(matcher);
    const maybe = tryParallel(S, allocator, io, sink, .{ .slice = haystack }, name, matcher, config, opts) catch |err| return narrowSlice(err);
    if (maybe) |res| return res;
    return sequentialSlice(S, sink, haystack, name, matcher, config);
}

/// Service entry point: parallel equivalent of `searchSourceSlice` for one large in-memory source.
/// Events are delivered on the calling thread in byte order. `allocator` must be thread-safe.
pub fn searchSourceSliceParallel(
    comptime S: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: *S,
    source_id: []const u8,
    haystack: []const u8,
    matcher: anytype,
    config: SearchConfig,
    opts: ParallelOptions,
) SliceError!Result {
    const cfg = cfg_mod.serviceConfig(config);
    var bridge = pull_mod.EventBridge(S){
        .inner = sink,
        .source_id = source_id,
        .config = cfg,
    };
    const result = try searchSliceParallel(pull_mod.EventBridge(S), allocator, io, &bridge, haystack, "", matcher, cfg, opts);
    pull_mod.emitSummary(S, sink, source_id, cfg, result);
    return result;
}

/// Legacy callback entry point: parallel search of `config.byte_range` (or the whole source) over a
/// handle-free `RandomAccess` source. Falls back to `searchRange` when the configuration is not chunk-safe
/// or `source.size` is unknown. `allocator` must be thread-safe.
pub fn searchParallelAt(
    comptime S: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: *S,
    source: RandomAccess,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
    opts: ParallelOptions,
) ReadError!Result {
    matcher_mod.validateMatcher(@TypeOf(matcher));
    state_mod.resetStats(matcher);
    if (try tryParallel(S, allocator, io, sink, .{ .ra = source }, name, matcher, config, opts)) |res| return res;
    return searcher.searchRange(S, allocator, sink, source, config.byte_range orelse .{}, name, matcher, config);
}

/// Service entry point: parallel search of `config.byte_range` (or the whole source) over a handle-free
/// `RandomAccess` source with multi-tenant budgets. Events are delivered on the calling thread in byte order.
pub fn searchSourceParallelAt(
    comptime S: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: *S,
    source: RandomAccess,
    source_id: []const u8,
    matcher: anytype,
    config: SearchConfig,
    opts: ParallelOptions,
) ReadError!Result {
    const cfg = cfg_mod.serviceConfig(config);
    var bridge = pull_mod.EventBridge(S){
        .inner = sink,
        .source_id = source_id,
        .config = cfg,
    };
    const result = try searchParallelAt(pull_mod.EventBridge(S), allocator, io, &bridge, source, "", matcher, cfg, opts);
    pull_mod.emitSummary(S, sink, source_id, cfg, result);
    return result;
}

/// Counts matching lines of one in-memory source in parallel without delivering line events.
/// Equivalent to `searchSlice` with a sink that has no `matched` callback.
pub fn countSliceParallel(
    allocator: std.mem.Allocator,
    io: std.Io,
    haystack: []const u8,
    matcher: anytype,
    config: SearchConfig,
    opts: ParallelOptions,
) SliceError!Result {
    var cs = CountSink{};
    return searchSliceParallel(CountSink, allocator, io, &cs, haystack, "", matcher, config, opts);
}

/// Counts matching lines of a `RandomAccess` source in parallel without delivering line events.
pub fn countParallelAt(
    allocator: std.mem.Allocator,
    io: std.Io,
    source: RandomAccess,
    matcher: anytype,
    config: SearchConfig,
    opts: ParallelOptions,
) ReadError!Result {
    var cs = CountSink{};
    return searchParallelAt(CountSink, allocator, io, &cs, source, "", matcher, config, opts);
}
