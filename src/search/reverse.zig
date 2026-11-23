//! [Module] search/reverse.zig
//! [Layer] Layer 4 — Reverse Tail Search Engine (`searchReverseSlice`, `searchReverseAt`)
//! [Role] Scans backward from the end of an in-memory slice or `probe.RandomAccess` source in bounded chunks,
//!        yielding matching lines newest-first (highest byte offset first) in O(tail) reads and CPU time.
//! [Invariants]
//!   1. Zero filesystem path, file-handle, or directory-handle references; all positional I/O uses `probe.RandomAccess`.
//!   2. Pre-quota `line_filter`, `max_count`, `max_results`, and `FlowAction` (`cont`, `pause`, `stop`, `skip_to`)
//!      are evaluated strictly in reverse (newest-first) order.
//!   3. When `max_results` or `Flow.pause` stops on a line starting at `line_abs`, `Result.resume_at` is set to `line_abs`
//!      so callers can paginate further backward with `byte_range = .{ .start = start, .end = res.resume_at }`.

const std = @import("std");
const decompress = @import("../codec/decompress.zig");
const encoding = @import("../codec/encoding.zig");
const matcher_mod = @import("../matcher.zig");
const memchr = @import("../finder/memchr.zig");
const probe_mod = @import("../probe.zig");
const regex_mod = @import("../regex.zig");
const sink_mod = @import("../sink.zig");
const cfg_mod = @import("config.zig");
const state_mod = @import("state.zig");
const ring_mod = @import("context_ring.zig");
const format_mod = @import("format.zig");
const line_matcher_mod = @import("line_matcher.zig");
const pipeline_mod = @import("pipeline.zig");
const pull_mod = @import("pull.zig");

pub const RandomAccess = probe_mod.RandomAccess;
pub const SearchConfig = cfg_mod.SearchConfig;
pub const SliceError = cfg_mod.SliceError;
pub const ReadError = cfg_mod.ReadError;
pub const Result = cfg_mod.Result;
pub const Span = cfg_mod.Span;

const width = cfg_mod.width;
const State = state_mod.State;
const Range = state_mod.Range;
const BufMatch = state_mod.BufMatch;

const RevCandidate = struct {
    start: usize,
    end: usize,
    mstart: usize,
    mend: usize,
    mpid: ?u32 = null,
    single_match: bool = false,
};

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

fn bindCaptureRegex(state: *State, matcher: anytype) void {
    const MChild = state_mod.MatcherType(@TypeOf(matcher));
    if (MChild == regex_mod.Regex) {
        state.capture_regex = if (@typeInfo(@TypeOf(matcher)) == .pointer) matcher else &matcher;
    } else if (MChild == matcher_mod.AnyMatcher) {
        const any_m: matcher_mod.AnyMatcher = if (@typeInfo(@TypeOf(matcher)) == .pointer) matcher.* else matcher;
        if (isAnyMatcherRegex(any_m)) {
            state.capture_regex = @ptrCast(@alignCast(any_m.ctx));
        }
    }
}

fn linesInSlice(bytes: []const u8, sep: u8) u64 {
    if (bytes.len == 0) return 0;
    const nls = memchr.count(width, bytes, 0, bytes.len, sep);
    return if (bytes[bytes.len - 1] == sep) nls else nls + 1;
}

fn adjustLastLineForJump(haystack: []const u8, start_idx: usize, clamped: usize, cursor_end: usize, last_ln: u64, sep: u8) u64 {
    if (clamped >= cursor_end) return last_ln;
    if (clamped <= start_idx) return 1;
    const raw_lines = linesInSlice(haystack[clamped..cursor_end], sep);
    const mid_line: u64 = @intFromBool(haystack[clamped - 1] != sep);
    return last_ln -| (raw_lines -| mid_line);
}

fn appendCandidate(
    alloc: ?std.mem.Allocator,
    inline_buf: []RevCandidate,
    heap_buf: *[]RevCandidate,
    len: *usize,
    item: RevCandidate,
) SliceError![]RevCandidate {
    var cur = if (heap_buf.len > 0) heap_buf.* else inline_buf;
    if (len.* == cur.len) {
        const a = alloc orelse return error.OutOfMemory;
        const new_cap = @max(cur.len * 2, 512);
        if (heap_buf.len == 0) {
            const grown = try a.alloc(RevCandidate, new_cap);
            @memcpy(grown[0..len.*], inline_buf[0..len.*]);
            heap_buf.* = grown;
        } else {
            heap_buf.* = try a.realloc(heap_buf.*, new_cap);
        }
        cur = heap_buf.*;
    }
    cur[len.*] = item;
    len.* += 1;
    return cur;
}

const ReverseAction = union(enum) {
    cont,
    stopped,
    jump_back: u64,
};

fn emitReverseMatched(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    chunk: []const u8,
    chunk_abs_origin: u64,
    cand: RevCandidate,
    line_num: ?u64,
    state: *State,
    config: SearchConfig,
) SliceError!ReverseAction {
    const line = Range{ .start = cand.start, .end = cand.end };
    const line_abs = chunk_abs_origin + @as(u64, cand.start);
    const known: ?BufMatch = if (config.invert)
        null
    else
        .{ .start = cand.mstart, .end = cand.mend, .pattern_id = cand.mpid, .single_match = cand.single_match };

    state.abs_base = chunk_abs_origin;
    state.line_number = line_num;
    state.last_line_counted = cand.end;

    if (comptime !@hasDecl(S, "matched")) {
        const withheld = config.binary == .report and state.nul_offset != null;
        if (!withheld and (config.max_queued_event_bytes != null or config.max_output_bytes != null)) {
            const content_end = state_mod.contentEnd(chunk, line, config);
            const raw_len = content_end - line.start;
            const capped_len = if (config.max_line_len == 0 or raw_len <= config.max_line_len) raw_len else config.max_line_len;
            if (!try state_mod.guardLine(state, config, capped_len)) return .stopped;
        }
        state_mod.releaseQueue(state);
        state.has_sunk = true;
        state.matched_lines += 1;
        state.matches += 1;
        state.results_out += 1;
        if (!state_mod.maybeProgress(S, sink, state, config)) {
            if (state.paused) {
                state.resume_at = line_abs;
                state.resume_line = if (line_num) |ln| ln -| 1 else 0;
            }
            return .stopped;
        }
        if (!state_mod.noteHitLimit(state, config, line_abs)) {
            if (state.limit_hit == .max_results) {
                state.resume_at = line_abs;
                state.resume_line = if (line_num) |ln| ln -| 1 else 0;
            }
            return .stopped;
        }
        return .cont;
    }

    const preview = ring_mod.previewLine(chunk, line, known, config);
    const withheld = config.binary == .report and state.nul_offset != null;
    const bytes = if (withheld) chunk[line.start..line.start] else chunk[preview.start..preview.end];
    var inline_spans: [32]Span = undefined;
    const matches = if (withheld) inline_spans[0..0] else try format_mod.gatherSpans(
        state.text_alloc,
        &inline_spans,
        &state.span_buf,
        matcher,
        chunk,
        line,
        preview,
        known,
        state,
        config,
    );
    if (!try state_mod.guardLine(state, config, bytes.len)) return .stopped;
    const action = format_mod.sinkLineAction(
        S,
        "matched",
        sink,
        state,
        bytes,
        if (withheld) bytes else chunk,
        if (withheld) 0 else preview.start,
        if (withheld) 0 else line.end,
        config.match_mode,
        if (withheld) null else preview.span,
        matches,
        line_abs,
        line_num,
        preview.truncated and !withheld,
        preview.line_len,
        if (withheld) 0 else preview.window_start,
        if (withheld) null else config.replacement,
    );
    state_mod.releaseQueue(state);
    state.has_sunk = true;
    state.matched_lines += 1;
    state.matches += if (matches.len > 0) @as(u64, @intCast(matches.len)) else 1;
    state.results_out += 1;

    var jump_target: ?u64 = null;
    switch (action) {
        .cont => {},
        .skip_to => |target| {
            if (target < line_abs) jump_target = target;
        },
        .pause => {
            state.paused = true;
            state.resume_at = line_abs;
            state.resume_line = if (line_num) |ln| ln -| 1 else 0;
            state.stopped = true;
            return .stopped;
        },
        .stop => {
            state.stopped = true;
            return .stopped;
        },
    }

    if (!state_mod.maybeProgress(S, sink, state, config)) {
        if (state.paused) {
            state.resume_at = line_abs;
            state.resume_line = if (line_num) |ln| ln -| 1 else 0;
        }
        return .stopped;
    }
    if (!state_mod.noteHitLimit(state, config, line_abs)) {
        if (state.limit_hit == .max_results) {
            state.resume_at = line_abs;
            state.resume_line = if (line_num) |ln| ln -| 1 else 0;
        }
        return .stopped;
    }
    if (jump_target) |jt| return .{ .jump_back = jt };
    return .cont;
}

const AbsRange = struct {
    start: u64,
    end: u64,
};

const LineSource = union(enum) {
    slice: []const u8,
    random_access: RandomAccess,
};

fn emitReverseContextLine(
    comptime S: type,
    sink: *S,
    line_bytes: []const u8,
    line_abs: u64,
    line_num: ?u64,
    state: *State,
    config: SearchConfig,
) SliceError!ReverseAction {
    if (comptime !@hasDecl(S, "context")) return .cont;
    const line = Range{ .start = 0, .end = line_bytes.len };
    const preview = ring_mod.previewLine(line_bytes, line, null, config);
    const withheld = config.binary == .report and state.nul_offset != null;
    const bytes = if (withheld) line_bytes[0..0] else line_bytes[preview.start..preview.end];
    if (!try state_mod.guardLine(state, config, bytes.len)) return .stopped;
    state.abs_base = line_abs;
    state.line_number = line_num;
    const action = format_mod.sinkLineAction(
        S,
        "context",
        sink,
        state,
        bytes,
        if (withheld) bytes else line_bytes,
        if (withheld) 0 else preview.start,
        if (withheld) 0 else line.end,
        config.match_mode,
        null,
        &.{},
        line_abs,
        line_num,
        preview.truncated and !withheld,
        preview.line_len,
        if (withheld) 0 else preview.window_start,
        null,
    );
    state_mod.releaseQueue(state);
    state.has_sunk = true;
    switch (action) {
        .cont => return .cont,
        .skip_to => |target| {
            if (target < line_abs) return .{ .jump_back = target };
            return .cont;
        },
        .pause => {
            state.paused = true;
            state.resume_at = line_abs;
            state.resume_line = if (line_num) |ln| ln -| 1 else 0;
            state.stopped = true;
            return .stopped;
        },
        .stop => {
            state.stopped = true;
            return .stopped;
        },
    }
}

const ReverseContext = struct {
    before_n: u32 = 0,
    after_n: u32 = 0,
    min_off: u64 = 0,
    max_off: u64 = 0,
    sep: u8 = '\n',
    last_emitted_start: ?u64 = null,
    pending_before: u32 = 0,
    pending_before_end: u64 = 0,
    pending_before_ln: ?u64 = null,
    alloc: ?std.mem.Allocator = null,
    io_buf: []u8 = &.{},
    after_heap: []AbsRange = &.{},
    bytes_read: *u64,

    fn active(self: *const ReverseContext) bool {
        return self.before_n > 0 or self.after_n > 0;
    }

    fn deinit(self: *ReverseContext) void {
        if (self.alloc) |a| {
            if (self.io_buf.len != 0) a.free(self.io_buf);
            if (self.after_heap.len != 0) a.free(self.after_heap);
        }
        self.io_buf = &.{};
        self.after_heap = &.{};
    }

    fn ensureIoBuf(self: *ReverseContext, want: usize) SliceError![]u8 {
        if (self.io_buf.len >= want) return self.io_buf;
        const a = self.alloc orelse return error.OutOfMemory;
        const cap = @max(want, @max(self.io_buf.len * 2, 4096));
        self.io_buf = try a.realloc(self.io_buf, cap);
        return self.io_buf;
    }

    fn readRange(self: *ReverseContext, src: LineSource, start: u64, end: u64) SliceError!?[]const u8 {
        if (end <= start) return &.{};
        switch (src) {
            .slice => |s| {
                const s_i: usize = @intCast(@min(start, @as(u64, s.len)));
                const e_i: usize = @intCast(@min(end, @as(u64, s.len)));
                return s[s_i..e_i];
            },
            .random_access => |ra| {
                const len: usize = @intCast(end - start);
                const buf = try self.ensureIoBuf(len);
                const got = ra.readAtFull(start, buf[0..len]) catch return null;
                self.bytes_read.* += got;
                return buf[0..got];
            },
        }
    }

    fn nextLineAfter(self: *ReverseContext, src: LineSource, off: u64, upper: u64) SliceError!?AbsRange {
        if (off >= upper) return null;
        switch (src) {
            .slice => |s| {
                const s_i: usize = @intCast(@min(off, @as(u64, s.len)));
                const u_i: usize = @intCast(@min(upper, @as(u64, s.len)));
                if (s_i >= u_i) return null;
                const end_i = if (std.mem.findScalarPos(u8, s[0..u_i], s_i, self.sep)) |nl| nl + 1 else u_i;
                return .{ .start = s_i, .end = end_i };
            },
            .random_access => |ra| {
                var cur = off;
                var tmp: [4096]u8 = undefined;
                while (cur < upper) {
                    const want: usize = @intCast(@min(@as(u64, tmp.len), upper - cur));
                    const got = ra.readAtFull(cur, tmp[0..want]) catch return null;
                    self.bytes_read.* += got;
                    if (got == 0) break;
                    if (std.mem.findScalar(u8, tmp[0..got], self.sep)) |nl| {
                        return .{ .start = off, .end = cur + nl + 1 };
                    }
                    cur += got;
                }
                if (cur > off) return .{ .start = off, .end = cur };
                return null;
            },
        }
    }

    fn prevLineBefore(self: *ReverseContext, src: LineSource, end_off: u64, lower: u64) SliceError!?AbsRange {
        if (end_off <= lower) return null;
        switch (src) {
            .slice => |s| {
                const e_i: usize = @intCast(@min(end_off, @as(u64, s.len)));
                const l_i: usize = @intCast(@min(lower, @as(u64, s.len)));
                if (e_i <= l_i) return null;
                const scan_hi = if (s[e_i - 1] == self.sep) e_i - 1 else e_i;
                const start_i = if (scan_hi > l_i)
                    (if (memchr.findLast(width, s, l_i, scan_hi, self.sep)) |nl| nl + 1 else l_i)
                else
                    l_i;
                return .{ .start = start_i, .end = e_i };
            },
            .random_access => |ra| {
                var scan_end = end_off;
                var last_b: [1]u8 = undefined;
                const got1 = ra.readAtFull(end_off - 1, &last_b) catch return null;
                self.bytes_read.* += got1;
                if (got1 == 0) return null;
                if (last_b[0] == self.sep) scan_end = end_off - 1;

                var tmp: [4096]u8 = undefined;
                var cur = scan_end;
                while (cur > lower) {
                    const want: usize = @intCast(@min(@as(u64, tmp.len), cur - lower));
                    const lo = cur - want;
                    const got = ra.readAtFull(lo, tmp[0..want]) catch return null;
                    self.bytes_read.* += got;
                    if (got == 0) break;
                    if (memchr.findLast(width, tmp[0..got], 0, got, self.sep)) |nl| {
                        return .{ .start = lo + nl + 1, .end = end_off };
                    }
                    cur = lo;
                }
                return .{ .start = lower, .end = end_off };
            },
        }
    }

    fn flushPendingBefore(
        self: *ReverseContext,
        comptime S: type,
        sink: *S,
        state: *State,
        config: SearchConfig,
        src: LineSource,
        stop_at: u64,
    ) SliceError!ReverseAction {
        if (self.pending_before == 0) return .cont;
        const lower = @max(self.min_off, stop_at);
        while (self.pending_before > 0 and self.pending_before_end > lower and !state.stopped) {
            const r = (try self.prevLineBefore(src, self.pending_before_end, lower)) orelse {
                self.pending_before = 0;
                break;
            };
            const bytes = (try self.readRange(src, r.start, r.end)) orelse {
                state.soft_error = .read_failed;
                state.stopped = true;
                return .stopped;
            };
            const ln: ?u64 = if (self.pending_before_ln) |pln| (if (pln > 1) pln - 1 else 1) else null;
            const act = try emitReverseContextLine(S, sink, bytes, r.start, ln, state, config);
            self.last_emitted_start = r.start;
            self.pending_before_end = r.start;
            self.pending_before_ln = ln;
            self.pending_before -= 1;
            switch (act) {
                .cont => {},
                .stopped => return .stopped,
                .jump_back => |t| {
                    self.pending_before = 0;
                    return .{ .jump_back = t };
                },
            }
        }
        if (self.pending_before_end <= lower) self.pending_before = 0;
        return .cont;
    }

    fn beforeMatch(
        self: *ReverseContext,
        comptime S: type,
        sink: *S,
        state: *State,
        config: SearchConfig,
        src: LineSource,
        match_start: u64,
        match_end: u64,
        match_ln: ?u64,
    ) SliceError!ReverseAction {
        if (!self.active()) return .cont;
        const f_act = try self.flushPendingBefore(S, sink, state, config, src, match_end);
        if (f_act != .cont) return f_act;

        var inline_after: [64]AbsRange = undefined;
        var after_buf: []AbsRange = &inline_after;
        if (self.after_n > inline_after.len) {
            if (self.after_heap.len < self.after_n) {
                const a = self.alloc orelse return error.OutOfMemory;
                self.after_heap = try a.realloc(self.after_heap, self.after_n);
            }
            after_buf = self.after_heap;
        }

        const upper = if (self.last_emitted_start) |les| @min(self.max_off, les) else self.max_off;
        var after_len: usize = 0;
        var cur = match_end;
        while (after_len < self.after_n and cur < upper) {
            const r = (try self.nextLineAfter(src, cur, upper)) orelse break;
            after_buf[after_len] = r;
            after_len += 1;
            cur = r.end;
        }

        const top_end = if (after_len > 0) after_buf[after_len - 1].end else match_end;
        if (self.last_emitted_start) |les| {
            if (top_end < les) {
                switch (state_mod.callSinkAction(S, "contextBreak", sink, .{})) {
                    .cont => {},
                    .skip_to => |t| {
                        if (t < match_start) return .{ .jump_back = t };
                    },
                    .pause => {
                        state.paused = true;
                        state.resume_at = match_start;
                        state.resume_line = if (match_ln) |ln| ln -| 1 else 0;
                        state.stopped = true;
                        return .stopped;
                    },
                    .stop => {
                        state.stopped = true;
                        return .stopped;
                    },
                }
            }
        }

        var i = after_len;
        while (i > 0 and !state.stopped) {
            i -= 1;
            const r = after_buf[i];
            const bytes = (try self.readRange(src, r.start, r.end)) orelse {
                state.soft_error = .read_failed;
                state.stopped = true;
                return .stopped;
            };
            const ln: ?u64 = if (match_ln) |mln| mln + @as(u64, i) + 1 else null;
            const act = try emitReverseContextLine(S, sink, bytes, r.start, ln, state, config);
            self.last_emitted_start = r.start;
            switch (act) {
                .cont => {},
                .stopped => return .stopped,
                .jump_back => |t| return .{ .jump_back = t },
            }
        }
        return .cont;
    }

    fn afterMatch(self: *ReverseContext, match_start: u64, match_ln: ?u64) void {
        if (!self.active()) return;
        self.last_emitted_start = match_start;
        self.pending_before = self.before_n;
        self.pending_before_end = match_start;
        self.pending_before_ln = match_ln;
    }
};

/// Processes a single window `chunk` (`[overlap_lo .. cursor_end)`) where `rel_commit = commit_lo - overlap_lo`.
/// May lower `commit_lo_io.*` if a cross-line match straddles `commit_lo`.
fn processReverseWindow(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    chunk: []const u8,
    overlap_lo: u64,
    commit_lo_io: *u64,
    cur_last_ln: *?u64,
    state: *State,
    config: SearchConfig,
    alloc: ?std.mem.Allocator,
    heap_cands: *[]RevCandidate,
    rev_ctx: *ReverseContext,
    line_src: LineSource,
) SliceError!ReverseAction {
    var rel_commit: usize = @intCast(commit_lo_io.* - overlap_lo);
    if (rel_commit >= chunk.len) return .cont;

    const sep = cfg_mod.recordSep(config);
    var binary_quit_rel: ?usize = null;
    var binary_abs: ?u64 = null;
    var report_nul_line_end: ?usize = null;
    var report_nul_abs: ?u64 = null;

    if (cfg_mod.watchesBinary(config) and state.nul_offset == null) {
        if (memchr.findLast(width, chunk, rel_commit, chunk.len, 0)) |last_nul| {
            const nul_abs = overlap_lo + @as(u64, last_nul);
            const after_nul_line = state_mod.lineEnd(chunk, last_nul, config);
            if (config.binary == .quit) {
                binary_abs = nul_abs;
                binary_quit_rel = after_nul_line;
            } else {
                report_nul_abs = nul_abs;
                report_nul_line_end = after_nul_line;
            }
        }
    }

    const effective_rel_commit = if (binary_quit_rel) |bqr| @max(rel_commit, bqr) else rel_commit;

    var inline_cands: [256]RevCandidate = undefined;
    var cand_len: usize = 0;
    var cands: []RevCandidate = &inline_cands;

    if (effective_rel_commit < chunk.len) {
        var scan_cfg = config;
        scan_cfg.max_count = null;
        scan_cfg.line_filter = null;

        var scan_state = State{};
        scan_state.abs_base = overlap_lo;
        scan_state.pos = if (binary_quit_rel != null) effective_rel_commit else 0;

        if (!config.invert) {
            while (scan_state.pos < chunk.len) {
                if (state_mod.stopInMatch(state, config)) return .stopped;
                const fl = (try line_matcher_mod.findLineLimitOpts(matcher, chunk, &scan_state, chunk.len, scan_cfg, true)) orelse break;
                scan_state.pos = fl.end;
                if (fl.end <= effective_rel_commit) continue;
                if (fl.start < effective_rel_commit) {
                    if (binary_quit_rel != null) continue;
                    rel_commit = fl.start;
                    commit_lo_io.* = overlap_lo + @as(u64, fl.start);
                }
                cands = try appendCandidate(alloc, &inline_cands, heap_cands, &cand_len, .{
                    .start = fl.start,
                    .end = fl.end,
                    .mstart = fl.mstart,
                    .mend = fl.mend,
                    .mpid = fl.mpid,
                    .single_match = fl.single_match,
                });
            }
        } else {
            while (scan_state.pos < chunk.len) {
                if (state_mod.stopInMatch(state, config)) return .stopped;
                const maybe_excl = try line_matcher_mod.findLineLimitOpts(matcher, chunk, &scan_state, chunk.len, scan_cfg, true);
                const gap_start = scan_state.pos;
                const gap_end = if (maybe_excl) |ex| blk: {
                    if (ex.start < effective_rel_commit and ex.end > effective_rel_commit and binary_quit_rel == null) {
                        rel_commit = ex.start;
                        commit_lo_io.* = overlap_lo + @as(u64, ex.start);
                    }
                    scan_state.pos = ex.end;
                    break :blk ex.start;
                } else blk: {
                    scan_state.pos = chunk.len;
                    break :blk chunk.len;
                };
                var cur = @max(gap_start, @max(rel_commit, effective_rel_commit));
                while (state_mod.nextLine(chunk, cur, gap_end, config)) |ln_r| {
                    cur = ln_r.end;
                    const ce = state_mod.contentEnd(chunk, ln_r, config);
                    if (!line_matcher_mod.linePassesFilters(chunk, ln_r.start, ce, config)) continue;
                    cands = try appendCandidate(alloc, &inline_cands, heap_cands, &cand_len, .{
                        .start = ln_r.start,
                        .end = ln_r.end,
                        .mstart = ln_r.start,
                        .mend = ln_r.start,
                        .mpid = null,
                        .single_match = true,
                    });
                }
            }
        }
    }

    const committed_slice = chunk[rel_commit..];
    const total_lines_in_commit = if (cur_last_ln.* != null) linesInSlice(committed_slice, sep) else 0;
    const chunk_first_ln: ?u64 = if (cur_last_ln.*) |last_ln|
        if (total_lines_in_commit == 0) last_ln else (last_ln + 1) -| total_lines_in_commit
    else
        null;

    var idx = cand_len;
    while (idx > 0) {
        idx -= 1;
        const cand = cands[idx];
        if (state_mod.flagIsSet(config)) {
            state.stopped = true;
            return .stopped;
        }
        if (state_mod.stopInMatch(state, config)) return .stopped;

        const ce = state_mod.contentEnd(chunk, .{ .start = cand.start, .end = cand.end }, config);
        if (config.line_filter != null) {
            const first_sp: Span = if (!config.invert) blk: {
                const rs = @min(@max(cand.mstart, cand.start), ce) - cand.start;
                const re = @max(rs, @min(@max(cand.mend, cand.start), ce) - cand.start);
                break :blk .{ .start = rs, .end = re, .pattern_id = cand.mpid };
            } else .{ .start = 0, .end = 0 };
            state.abs_base = overlap_lo;
            if (!line_matcher_mod.linePassesUserFilter(chunk, cand.start, ce, cand.end, first_sp, config.invert, state, config)) {
                continue;
            }
        }

        if (config.files_without_match) {
            state.limit_count += 1;
            state.matched_lines += 1;
            state.matches += 1;
            state.results_out += 1;
            state.stopped = true;
            state.need_close = true;
            return .stopped;
        }

        const line_num: ?u64 = if (chunk_first_ln) |base_ln|
            base_ln + memchr.count(width, chunk, rel_commit, cand.start, sep)
        else
            null;

        if (report_nul_line_end) |rnle| {
            if (state.nul_offset == null and cand.start < rnle) {
                state_mod.noteBinary(state, config, report_nul_abs.?);
                if (!state_mod.callOpt(S, "binary", sink, .{state.nul_offset.?})) {
                    state.stopped = true;
                    return .stopped;
                }
            }
        }

        state.limit_count += 1;
        if (rev_ctx.active()) {
            const match_start_abs = overlap_lo + @as(u64, cand.start);
            const match_end_abs = overlap_lo + @as(u64, cand.end);
            const ctx_act = try rev_ctx.beforeMatch(S, sink, state, config, line_src, match_start_abs, match_end_abs, line_num);
            switch (ctx_act) {
                .cont => {},
                .stopped => return .stopped,
                .jump_back => |target| {
                    while (idx > 0) {
                        const prev_cand = cands[idx - 1];
                        if (overlap_lo + @as(u64, prev_cand.end) <= target) break;
                        idx -= 1;
                    }
                    if (target < commit_lo_io.*) {
                        return .{ .jump_back = target };
                    }
                    continue;
                },
            }
        }
        const act = try emitReverseMatched(S, sink, matcher, chunk, overlap_lo, cand, line_num, state, config);
        rev_ctx.afterMatch(overlap_lo + @as(u64, cand.start), line_num);
        switch (act) {
            .cont => {},
            .stopped => return .stopped,
            .jump_back => |target| {
                rev_ctx.pending_before = 0;
                while (idx > 0) {
                    const prev_cand = cands[idx - 1];
                    if (overlap_lo + @as(u64, prev_cand.end) <= target) break;
                    idx -= 1;
                }
                if (target < commit_lo_io.*) {
                    return .{ .jump_back = target };
                }
            },
        }
        if (state.exceeded(config)) {
            state.stopped = true;
            state.need_close = true;
            return .stopped;
        }
    }

    if (report_nul_abs) |r_abs| {
        if (state.nul_offset == null) {
            state_mod.noteBinary(state, config, r_abs);
            if (!state_mod.callOpt(S, "binary", sink, .{state.nul_offset.?})) {
                state.stopped = true;
                return .stopped;
            }
        }
    }

    if (binary_abs) |b_abs| {
        state_mod.noteBinary(state, config, b_abs);
        _ = state_mod.callOpt(S, "binary", sink, .{state.nul_offset.?});
        state.stopped = true;
        return .stopped;
    }

    if (chunk_first_ln) |first_ln| {
        cur_last_ln.* = first_ln -| 1;
    }
    return .cont;
}

fn finalizeReverse(comptime S: type, sink: *S, state: *State, config: SearchConfig, bytes_scanned: u64, bytes_read: u64, scanned_all: bool) Result {
    const base_s: u64 = if (config.continuation) |s| s.bytes_searched else 0;
    const base_r: u64 = if (config.continuation) |s| s.bytes_read else 0;
    state.bytes_searched = base_s + bytes_scanned;
    state.bytes_read = base_r + bytes_read;
    state.scanned_all = scanned_all and !state.output_blocked and state.soft_error == null and !state.paused;
    state.abs_base = 0;
    state.pos = 0;
    return state_mod.finishSink(S, sink, state, config);
}

/// Searches `haystack` backward from the end of `haystack` (or `config.byte_range`), emitting matches newest-first.
pub fn searchReverseSlice(
    comptime S: type,
    sink: *S,
    haystack: []const u8,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) SliceError!Result {
    matcher_mod.validateMatcher(@TypeOf(matcher));
    cfg_mod.validateBudgets(config) catch |err| {
        state_mod.logDetail(config, name, err);
        return err;
    };
    state_mod.resetStats(matcher);

    var state = State{};
    bindCaptureRegex(&state, matcher);
    state.label = name;
    state_mod.armClock(&state, config);
    const pool_alloc = if (config.scratch_pool) |sp| sp.allocator else cfg_mod.effectiveAllocator(config);
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

    var heap_cands: []RevCandidate = &.{};
    defer if (heap_cands.len != 0) if (pool_alloc) |alloc| alloc.free(heap_cands);

    var prep = try pipeline_mod.materialize(haystack, config);
    defer prep.deinit();
    state.decompressed_bytes = prep.decompressed_bytes;
    if (prep.offset_map.active) state.offset_map = &prep.offset_map;
    if (prep.decompress_map.active) state.decompress_map = &prep.decompress_map;

    if (prep.decompress_limit_hit or prep.corrupt_stream) {
        if (prep.decompress_limit_hit) {
            state_mod.noteLimit(&state, .decompressed_bytes);
        } else {
            state.soft_error = .read_failed;
        }
        _ = state_mod.callOpt(S, "begin", sink, .{name});
        return finalizeReverse(S, sink, &state, config, 0, haystack.len, false);
    }

    const data = prep.bytes;
    const sep = cfg_mod.recordSep(config);
    var start_idx: usize = if (config.byte_range) |br| @intCast(@min(br.start, @as(u64, data.len))) else 0;
    var end_idx: usize = if (config.byte_range) |br|
        (if (br.end) |be| @intCast(@min(be, @as(u64, data.len))) else data.len)
    else
        data.len;

    if (config.range_align_lines) {
        if (start_idx > 0 and start_idx < data.len and data[start_idx - 1] != sep) {
            start_idx = if (std.mem.findScalarPos(u8, data, start_idx, sep)) |d| d + 1 else data.len;
        }
        if (end_idx <= start_idx) {
            end_idx = start_idx;
        } else if (end_idx < data.len and data[end_idx - 1] != sep) {
            end_idx = if (std.mem.findScalarPos(u8, data, end_idx, sep)) |d| d + 1 else data.len;
        }
    } else if (end_idx < start_idx) {
        end_idx = start_idx;
    }

    if (cfg_mod.scanCap(config)) |cap| {
        if (@as(u64, end_idx - start_idx) > cap) {
            start_idx = end_idx - @as(usize, @intCast(cap));
            state.hit_byte_cap = true;
        }
    }

    state_mod.restoreCounters(&state, config);
    var cur_last_ln: ?u64 = switch (config.line_number_mode) {
        .unknown => null,
        .from_one => if (config.initial_line_number) |n| n else if (end_idx > start_idx) linesInSlice(data[start_idx..end_idx], sep) else 1,
        .auto => config.initial_line_number,
    };

    var cursor_end: usize = end_idx;
    switch (state_mod.callSinkAction(S, "begin", sink, .{name})) {
        .cont => {},
        .skip_to => |target| {
            if (target < @as(u64, cursor_end)) {
                const clamped: usize = @intCast(@max(@as(u64, start_idx), target));
                if (cur_last_ln) |lln| {
                    cur_last_ln = adjustLastLineForJump(data, start_idx, clamped, cursor_end, lln, sep);
                }
                cursor_end = clamped;
            }
        },
        .pause => {
            state.paused = true;
            state.stopped = true;
            state.resume_at = @intCast(cursor_end);
            state.resume_line = cur_last_ln orelse 0;
            return finalizeReverse(S, sink, &state, config, 0, 0, false);
        },
        .stop => {
            state.stopped = true;
            return finalizeReverse(S, sink, &state, config, 0, 0, false);
        },
    }

    if (state_mod.rejectEmptyResults(&state, config)) {
        state.resume_at = @intCast(cursor_end);
        return finalizeReverse(S, sink, &state, config, 0, 0, false);
    }
    if (state_mod.stopForBudget(&state, config)) {
        return finalizeReverse(S, sink, &state, config, 0, 0, false);
    }

    var dummy_ctx_reads: u64 = 0;
    var rev_ctx = ReverseContext{
        .before_n = cfg_mod.beforeCount(config),
        .after_n = cfg_mod.afterCount(config),
        .min_off = @intCast(start_idx),
        .max_off = @intCast(end_idx),
        .sep = sep,
        .alloc = pool_alloc,
        .bytes_read = &dummy_ctx_reads,
    };
    defer rev_ctx.deinit();
    const line_src = LineSource{ .slice = data };

    const is_ml = state_mod.effectiveMultiline(matcher, config);
    const ml_win = if (is_ml) state_mod.effectiveMultilineWindow(matcher, config) else 0;
    const step_sz = @max(cfg_mod.bufferWindow(config), if (is_ml) @max(ml_win *| 2, 64) else 64);

    var bytes_scanned: u64 = 0;
    while (cursor_end > start_idx and !state.stopped) {
        var commit_lo_idx: usize = if (cursor_end - start_idx <= step_sz) start_idx else cursor_end - step_sz;
        if (commit_lo_idx > start_idx and data[commit_lo_idx - 1] != sep) {
            if (std.mem.findScalarPos(u8, data[0..cursor_end], commit_lo_idx, sep)) |nl_at| {
                if (nl_at + 1 < cursor_end) {
                    commit_lo_idx = nl_at + 1;
                } else if (memchr.findLast(width, data, start_idx, commit_lo_idx, sep)) |prev_nl| {
                    commit_lo_idx = prev_nl + 1;
                } else {
                    commit_lo_idx = start_idx;
                }
            } else if (memchr.findLast(width, data, start_idx, commit_lo_idx, sep)) |prev_nl| {
                commit_lo_idx = prev_nl + 1;
            } else {
                commit_lo_idx = start_idx;
            }
        }

        const overlap_lo_idx: usize = if (is_ml and ml_win > 0 and commit_lo_idx > start_idx) blk: {
            const raw_ov = if (commit_lo_idx - start_idx <= ml_win) start_idx else commit_lo_idx - ml_win;
            if (raw_ov > start_idx and data[raw_ov - 1] != sep) {
                if (memchr.findLast(width, data, start_idx, raw_ov, sep)) |pnl| break :blk pnl + 1;
                break :blk start_idx;
            }
            break :blk raw_ov;
        } else commit_lo_idx;

        var commit_lo_u64: u64 = @intCast(commit_lo_idx);
        const chunk = data[overlap_lo_idx..cursor_end];
        const act = try processReverseWindow(
            S,
            sink,
            matcher,
            chunk,
            @intCast(overlap_lo_idx),
            &commit_lo_u64,
            &cur_last_ln,
            &state,
            config,
            pool_alloc,
            &heap_cands,
            &rev_ctx,
            line_src,
        );
        const actual_commit: usize = @intCast(commit_lo_u64);
        bytes_scanned += @intCast(cursor_end - actual_commit);
        switch (act) {
            .cont => {
                cursor_end = actual_commit;
            },
            .stopped => break,
            .jump_back => |target| {
                rev_ctx.pending_before = 0;
                const clamped: usize = @intCast(@max(@as(u64, start_idx), target));
                const next_end = @min(clamped, actual_commit);
                if (cur_last_ln) |lln| {
                    cur_last_ln = adjustLastLineForJump(data, start_idx, next_end, cursor_end, lln, sep);
                }
                cursor_end = next_end;
            },
        }
    }

    if (!state.stopped and rev_ctx.pending_before > 0) {
        _ = try rev_ctx.flushPendingBefore(S, sink, &state, config, line_src, @intCast(start_idx));
    }

    const reached_start = (cursor_end <= start_idx) and !state.stopped;
    if (reached_start and state.hit_byte_cap) state_mod.noteLimit(&state, .max_bytes);
    const reported_read: u64 = if (prep.transformed) @intCast(haystack.len) else bytes_scanned;
    return finalizeReverse(S, sink, &state, config, bytes_scanned, reported_read, reached_start and !state.hit_byte_cap);
}

/// Service entry point: reverse tail search over an in-memory byte slice.
pub fn searchSourceReverseSlice(
    comptime S: type,
    sink: *S,
    source_id: []const u8,
    haystack: []const u8,
    matcher: anytype,
    config: SearchConfig,
) SliceError!Result {
    const cfg = cfg_mod.serviceConfig(config);
    var bridge = pull_mod.EventBridge(S){
        .inner = sink,
        .source_id = source_id,
        .config = cfg,
    };
    const result = try searchReverseSlice(pull_mod.EventBridge(S), &bridge, haystack, "", matcher, cfg);
    pull_mod.emitSummary(S, sink, source_id, cfg, result);
    return result;
}

fn discoverSourceEnd(source: RandomAccess, start_hint: u64, bytes_read: *u64) ?u64 {
    if (source.size) |sz| return sz;
    var probe_buf: [16384]u8 = undefined;
    var off = start_hint;
    while (true) {
        const n = source.readAtFull(off, &probe_buf) catch return null;
        bytes_read.* += n;
        off += n;
        if (n < probe_buf.len) return off;
    }
}

/// Searches backward over a handle-free, path-free `probe.RandomAccess` source in O(tail) positional reads.
pub fn searchReverseAt(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    source: RandomAccess,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) ReadError!Result {
    matcher_mod.validateMatcher(@TypeOf(matcher));
    cfg_mod.validateBudgets(config) catch |err| {
        state_mod.logDetail(config, name, err);
        return err;
    };
    state_mod.resetStats(matcher);

    const pool_alloc = if (config.scratch_pool) |sp| sp.allocator else (cfg_mod.effectiveAllocator(config) orelse allocator);
    const stream_alloc = if (config.scratch == null and config.scratch_pool != null)
        config.scratch_pool.?.allocator
    else
        allocator;

    // Check if decompression or explicit non-UTF-8 encoding transcoding requires materialized input.
    // Default (`compression == .none` and `encoding == .auto` with no charset) stays strictly on
    // the O(tail) RandomAccess path without probing offset 0.
    const resolved_enc = encoding.resolveHint(config.encoding, config.charset);
    var needs_materialize = (config.compression != .none and config.compression != .auto) or
        (resolved_enc != .none and resolved_enc != .auto);
    if (!needs_materialize and config.compression == .auto) {
        var hdr: [6]u8 = undefined;
        const hn = source.readAtFull(0, &hdr) catch 0;
        const hslice = hdr[0..hn];
        const c_det = decompress.sniff(hslice, hn < hdr.len);
        if (c_det != .raw and c_det != .need_more) needs_materialize = true;
    }
    if (needs_materialize) {
        const cap_u64: u64 = @min(
            cfg_mod.scanCap(config) orelse std.math.maxInt(u64),
            @as(u64, cfg_mod.decodeCap(config)),
        );
        var raw_list: std.ArrayList(u8) = .empty;
        defer raw_list.deinit(pool_alloc);
        var off: u64 = 0;
        var chunk_buf: [16384]u8 = undefined;
        var read_err = false;
        while (off < cap_u64) {
            const want: usize = @intCast(@min(@as(u64, chunk_buf.len), cap_u64 - off));
            const n = source.readAtFull(off, chunk_buf[0..want]) catch |err| {
                state_mod.logDetail(config, name, err);
                read_err = true;
                break;
            };
            if (n == 0) break;
            try raw_list.appendSlice(pool_alloc, chunk_buf[0..n]);
            off += n;
            if (n < want) break;
        }
        if (read_err) {
            var err_state = State{};
            err_state.label = name;
            err_state.from_reader = true;
            err_state.soft_error = .read_failed;
            _ = state_mod.callOpt(S, "begin", sink, .{name});
            return finalizeReverse(S, sink, &err_state, config, 0, off, false);
        }
        var slice_cfg = config;
        if (slice_cfg.allocator == null) slice_cfg.allocator = pool_alloc;
        return try searchReverseSlice(S, sink, raw_list.items, name, matcher, slice_cfg);
    }

    var state = State{};
    bindCaptureRegex(&state, matcher);
    state.label = name;
    state.from_reader = true;
    state_mod.armClock(&state, config);
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

    var heap_cands: []RevCandidate = &.{};
    defer if (heap_cands.len != 0) pool_alloc.free(heap_cands);

    const is_ml = state_mod.effectiveMultiline(matcher, config);
    const ml_win = if (is_ml) state_mod.effectiveMultilineWindow(matcher, config) else 0;
    const step_sz = @max(cfg_mod.bufferWindow(config), if (is_ml) @max(ml_win *| 2, 64) else 64);
    const align_cap = @max(step_sz, 256);
    const hold_limit = if (is_ml and ml_win > 0) state_mod.multilineHoldLimit(config, ml_win) else cfg_mod.lineHoldLimit(config);
    const buf_cap0 = @max(step_sz +| ml_win +| align_cap, 512);

    const stream_slot: ?*[]u8 = if (config.scratch_pool) |sp|
        &sp.stream_buf
    else if (config.scratch) |slot|
        slot
    else
        null;

    var buf: []u8 = undefined;
    if (stream_slot) |slot| {
        if (slot.len < buf_cap0) {
            slot.* = try stream_alloc.realloc(slot.*, buf_cap0);
        }
        buf = slot.*;
    } else {
        buf = try stream_alloc.alloc(u8, buf_cap0);
    }
    defer {
        if (stream_slot) |slot| {
            slot.* = buf;
        } else {
            stream_alloc.free(buf);
        }
    }

    var total_bytes_read: u64 = 0;
    const sep = cfg_mod.recordSep(config);

    var start_off: u64 = if (config.byte_range) |br| br.start else 0;
    var end_off: u64 = if (config.byte_range) |br|
        (if (br.end) |be| (if (source.size) |sz| @min(be, sz) else be) else (discoverSourceEnd(source, start_off, &total_bytes_read) orelse {
            state.soft_error = .read_failed;
            _ = state_mod.callOpt(S, "begin", sink, .{name});
            return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
        }))
    else
        (discoverSourceEnd(source, start_off, &total_bytes_read) orelse {
            state.soft_error = .read_failed;
            _ = state_mod.callOpt(S, "begin", sink, .{name});
            return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
        });

    if (source.size) |sz| {
        if (start_off > sz) start_off = sz;
    }

    if (config.range_align_lines) {
        if (start_off > 0 and start_off < end_off) {
            var prev_b: [1]u8 = undefined;
            const pn = source.readAtFull(start_off - 1, prev_b[0..1]) catch |err| {
                state.soft_error = .read_failed;
                state_mod.logDetail(config, name, err);
                _ = state_mod.callOpt(S, "begin", sink, .{name});
                return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
            };
            total_bytes_read += pn;
            if (pn == 0) {
                end_off = start_off;
            } else if (prev_b[0] != sep) {
                var cur = start_off;
                while (cur < end_off) {
                    const want: usize = @intCast(@min(@as(u64, 4096), end_off - cur));
                    const rn = source.readAtFull(cur, buf[0..want]) catch |err| {
                        state.soft_error = .read_failed;
                        state_mod.logDetail(config, name, err);
                        _ = state_mod.callOpt(S, "begin", sink, .{name});
                        return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
                    };
                    total_bytes_read += rn;
                    if (rn == 0) {
                        start_off = cur;
                        end_off = cur;
                        break;
                    }
                    if (std.mem.findScalar(u8, buf[0..rn], sep)) |nl_rel| {
                        start_off = cur + nl_rel + 1;
                        break;
                    }
                    cur += rn;
                }
                if (start_off > end_off) end_off = start_off;
            }
        }
        if (end_off > start_off) {
            var last_b: [1]u8 = undefined;
            const ln_n = source.readAtFull(end_off - 1, last_b[0..1]) catch |err| {
                state.soft_error = .read_failed;
                state_mod.logDetail(config, name, err);
                _ = state_mod.callOpt(S, "begin", sink, .{name});
                return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
            };
            total_bytes_read += ln_n;
            if (ln_n > 0 and last_b[0] != sep) {
                var cur = end_off;
                while (true) {
                    const rn = source.readAtFull(cur, buf[0..4096]) catch |err| {
                        state.soft_error = .read_failed;
                        state_mod.logDetail(config, name, err);
                        _ = state_mod.callOpt(S, "begin", sink, .{name});
                        return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
                    };
                    total_bytes_read += rn;
                    if (rn == 0) {
                        end_off = cur;
                        break;
                    }
                    if (std.mem.findScalar(u8, buf[0..rn], sep)) |nl_rel| {
                        end_off = cur + nl_rel + 1;
                        break;
                    }
                    cur += rn;
                }
            }
        }
    } else if (end_off < start_off) {
        end_off = start_off;
    }

    if (cfg_mod.scanCap(config)) |cap| {
        if (end_off - start_off > cap) {
            start_off = end_off - cap;
            state.hit_byte_cap = true;
        }
    }

    state_mod.restoreCounters(&state, config);
    var cur_last_ln: ?u64 = switch (config.line_number_mode) {
        .unknown => null,
        .auto => config.initial_line_number,
        .from_one => if (config.initial_line_number) |n| n else blk: {
            if (end_off <= start_off) break :blk @as(?u64, 1);
            var nls: u64 = 0;
            var last_seen_byte: u8 = sep;
            var cur = start_off;
            while (cur < end_off) {
                const want: usize = @intCast(@min(@as(u64, buf.len), end_off - cur));
                const rn = source.readAtFull(cur, buf[0..want]) catch |err| {
                    state.soft_error = .read_failed;
                    state_mod.logDetail(config, name, err);
                    _ = state_mod.callOpt(S, "begin", sink, .{name});
                    return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
                };
                total_bytes_read += rn;
                if (rn == 0) {
                    end_off = cur;
                    break;
                }
                nls += memchr.count(width, buf[0..rn], 0, rn, sep);
                last_seen_byte = buf[rn - 1];
                cur += rn;
            }
            break :blk if (end_off == start_off) @as(?u64, 1) else if (last_seen_byte == sep) nls else nls + 1;
        },
    };

    var cursor_end = end_off;
    switch (state_mod.callSinkAction(S, "begin", sink, .{name})) {
        .cont => {},
        .skip_to => |target| {
            if (target < cursor_end) {
                cursor_end = @max(start_off, target);
                if (config.line_number_mode == .auto or cur_last_ln != null) {
                    cur_last_ln = null;
                }
            }
        },
        .pause => {
            state.paused = true;
            state.stopped = true;
            state.resume_at = cursor_end;
            state.resume_line = cur_last_ln orelse 0;
            return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
        },
        .stop => {
            state.stopped = true;
            return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
        },
    }

    if (state_mod.rejectEmptyResults(&state, config)) {
        state.resume_at = cursor_end;
        return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
    }

    var rev_ctx = ReverseContext{
        .before_n = cfg_mod.beforeCount(config),
        .after_n = cfg_mod.afterCount(config),
        .min_off = start_off,
        .max_off = end_off,
        .sep = sep,
        .alloc = pool_alloc,
        .bytes_read = &total_bytes_read,
    };
    defer rev_ctx.deinit();
    const line_src = LineSource{ .random_access = source };

    var bytes_scanned: u64 = 0;
    var cur_step_sz: u64 = @intCast(step_sz);
    while (cursor_end > start_off and !state.stopped) {
        state.bytes_read = total_bytes_read;
        if (state_mod.stopForBudget(&state, config)) break;

        const target_lo: u64 = if (cursor_end - start_off <= cur_step_sz) start_off else cursor_end - cur_step_sz;
        const overlap_lo: u64 = if (is_ml and ml_win > 0 and target_lo > start_off)
            (if (target_lo - start_off <= @as(u64, ml_win)) start_off else target_lo - @as(u64, ml_win))
        else
            target_lo;

        // Ensure `buf` can hold `cursor_end - overlap_lo` (+ room to align backward to line boundary)
        const extra_align: u64 = if (overlap_lo > start_off) @min(overlap_lo - start_off, @as(u64, align_cap)) else 0;
        while (true) {
            const read_lo_cand: u64 = overlap_lo - extra_align;
            const want_u64 = cursor_end - read_lo_cand;
            if (want_u64 > @as(u64, buf.len)) {
                if (try state_mod.growWithLimit(stream_alloc, buf, @max(hold_limit, @as(usize, @intCast(@min(want_u64, hold_limit)))))) |grown| {
                    buf = grown;
                    if (stream_slot) |slot| slot.* = buf;
                } else {
                    // Clamp read_lo if single line exceeds hold_limit
                    break;
                }
            } else break;
        }

        const max_window: u64 = @intCast(buf.len);
        var read_lo: u64 = overlap_lo - extra_align;
        if (cursor_end - read_lo > max_window) read_lo = cursor_end - max_window;

        const want_len: usize = @intCast(cursor_end - read_lo);
        const got_len = source.readAtFull(read_lo, buf[0..want_len]) catch |err| {
            state.soft_error = .read_failed;
            state_mod.logDetail(config, name, err);
            state.need_close = true;
            break;
        };
        total_bytes_read += got_len;
        if (got_len == 0) {
            cursor_end = read_lo;
            continue;
        }
        if (got_len < want_len) {
            cursor_end = read_lo + got_len;
        }
        const raw_window = buf[0..got_len];

        // Align `overlap_lo` and `commit_lo` inside `raw_window`
        var rel_overlap: usize = 0;
        if (read_lo > start_off) {
            if (std.mem.findScalar(u8, raw_window, sep)) |first_nl| {
                if (first_nl + 1 < raw_window.len) {
                    rel_overlap = first_nl + 1;
                }
            }
        }
        const aligned_overlap_lo = read_lo + @as(u64, rel_overlap);

        var rel_commit: usize = if (target_lo <= aligned_overlap_lo)
            rel_overlap
        else
            @intCast(@min(@as(u64, raw_window.len), target_lo - read_lo));

        if (read_lo + @as(u64, rel_commit) > start_off and rel_commit > 0 and rel_commit < raw_window.len and raw_window[rel_commit - 1] != sep) {
            if (std.mem.findScalarPos(u8, raw_window, rel_commit, sep)) |nl_at| {
                if (nl_at + 1 < raw_window.len) {
                    rel_commit = nl_at + 1;
                } else if (memchr.findLast(width, raw_window, rel_overlap, rel_commit, sep)) |prev_nl| {
                    rel_commit = prev_nl + 1;
                } else {
                    rel_commit = rel_overlap;
                }
            } else if (memchr.findLast(width, raw_window, rel_overlap, rel_commit, sep)) |prev_nl| {
                rel_commit = prev_nl + 1;
            } else {
                rel_commit = rel_overlap;
            }
        }

        // If the entire window has no newline and read_lo > start_off (a single line exceeding step_sz),
        // expand left up to `max_line_len` so normal lines <= max_line_len are never split!
        if (rel_commit == rel_overlap and read_lo > start_off and std.mem.findScalar(u8, raw_window, sep) == null) {
            const line_span_so_far = cursor_end - read_lo;
            if (line_span_so_far <= @as(u64, config.max_line_len) and buf.len < hold_limit) {
                if (try state_mod.growWithLimit(stream_alloc, buf, hold_limit)) |grown| {
                    buf = grown;
                    if (stream_slot) |slot| slot.* = buf;
                    cur_step_sz = @min(@as(u64, hold_limit), @max(cur_step_sz * 2, @as(u64, buf.len)));
                    continue;
                }
            }
        }

        cur_step_sz = @intCast(step_sz);
        const chunk = raw_window[rel_overlap..];
        var commit_lo_u64 = read_lo + @as(u64, rel_commit);
        const act = try processReverseWindow(
            S,
            sink,
            matcher,
            chunk,
            aligned_overlap_lo,
            &commit_lo_u64,
            &cur_last_ln,
            &state,
            config,
            pool_alloc,
            &heap_cands,
            &rev_ctx,
            line_src,
        );
        bytes_scanned += cursor_end -| commit_lo_u64;
        switch (act) {
            .cont => {
                cursor_end = commit_lo_u64;
            },
            .stopped => break,
            .jump_back => |target| {
                rev_ctx.pending_before = 0;
                const clamped = @max(start_off, target);
                if (clamped < commit_lo_u64) {
                    cur_last_ln = null;
                    cursor_end = clamped;
                } else {
                    cursor_end = commit_lo_u64;
                }
            },
        }
    }

    if (!state.stopped and rev_ctx.pending_before > 0) {
        _ = try rev_ctx.flushPendingBefore(S, sink, &state, config, line_src, start_off);
    }

    const reached_start = (cursor_end <= start_off) and !state.stopped and state.soft_error == null;
    if (reached_start and state.hit_byte_cap) state_mod.noteLimit(&state, .max_bytes);
    return finalizeReverse(S, sink, &state, config, bytes_scanned, total_bytes_read, reached_start and !state.hit_byte_cap);
}

/// Service entry point: reverse tail search over a `probe.RandomAccess` source.
pub fn searchSourceReverseAt(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    source: RandomAccess,
    source_id: []const u8,
    matcher: anytype,
    config: SearchConfig,
) ReadError!Result {
    const cfg = cfg_mod.serviceConfig(config);
    var bridge = pull_mod.EventBridge(S){
        .inner = sink,
        .source_id = source_id,
        .config = cfg,
    };
    const result = try searchReverseAt(pull_mod.EventBridge(S), allocator, &bridge, source, "", matcher, cfg);
    pull_mod.emitSummary(S, sink, source_id, cfg, result);
    return result;
}

test "reverse search v0.8: -B/-A/-C context lines, deduplication, and contextBreak (slice & RandomAccess)" {
    const gpa = std.testing.allocator;
    const lz4_mod = @import("../codec/lz4.zig");

    const text =
        "L1 plain\n" ++
        "L2 hit-one\n" ++
        "L3 mid\n" ++
        "L4 plain\n" ++
        "L5 plain\n" ++
        "L6 before\n" ++
        "L7 hit-two\n" ++
        "L8 hit-three\n" ++
        "L9 after\n";

    const RecKind = enum { matched, context, brk };
    const Rec = struct {
        kind: RecKind,
        text: []u8 = &.{},
        num: ?u64 = null,
    };
    const Collect = struct {
        alloc: std.mem.Allocator,
        items: std.ArrayList(Rec) = .empty,

        pub fn matched(self: *@This(), line: sink_mod.Line) bool {
            self.items.append(self.alloc, .{
                .kind = .matched,
                .text = self.alloc.dupe(u8, line.bytes) catch unreachable,
                .num = line.number,
            }) catch unreachable;
            return true;
        }
        pub fn context(self: *@This(), line: sink_mod.Line) bool {
            self.items.append(self.alloc, .{
                .kind = .context,
                .text = self.alloc.dupe(u8, line.bytes) catch unreachable,
                .num = line.number,
            }) catch unreachable;
            return true;
        }
        pub fn contextBreak(self: *@This()) bool {
            self.items.append(self.alloc, .{ .kind = .brk }) catch unreachable;
            return true;
        }
        fn deinit(self: *@This()) void {
            for (self.items.items) |it| {
                if (it.text.len != 0) self.alloc.free(it.text);
            }
            self.items.deinit(self.alloc);
        }
    };

    var m = try regex_mod.Regex.init(gpa, "hit", .{});
    defer m.deinit();

    // Slice with context = 1 (before=1, after=1)
    var s1 = Collect{ .alloc = gpa };
    defer s1.deinit();
    const res1 = try searchReverseSlice(Collect, &s1, text, "log", &m, .{
        .allocator = gpa,
        .context = 1,
        .line_number_mode = .from_one,
    });
    try std.testing.expectEqual(@as(u64, 3), res1.matched_lines);
    // Expected newest-first order:
    // L9 (ctx), L8 (match), L7 (match), L6 (ctx), [break], L3 (ctx), L2 (match), L1 (ctx)
    try std.testing.expectEqual(@as(usize, 8), s1.items.items.len);
    try std.testing.expectEqual(RecKind.context, s1.items.items[0].kind);
    try std.testing.expectEqualStrings("L9 after", s1.items.items[0].text);
    try std.testing.expectEqual(RecKind.matched, s1.items.items[1].kind);
    try std.testing.expectEqualStrings("L8 hit-three", s1.items.items[1].text);
    try std.testing.expectEqual(RecKind.matched, s1.items.items[2].kind);
    try std.testing.expectEqualStrings("L7 hit-two", s1.items.items[2].text);
    try std.testing.expectEqual(RecKind.context, s1.items.items[3].kind);
    try std.testing.expectEqualStrings("L6 before", s1.items.items[3].text);
    try std.testing.expectEqual(RecKind.brk, s1.items.items[4].kind);
    try std.testing.expectEqual(RecKind.context, s1.items.items[5].kind);
    try std.testing.expectEqualStrings("L3 mid", s1.items.items[5].text);
    try std.testing.expectEqual(RecKind.matched, s1.items.items[6].kind);
    try std.testing.expectEqualStrings("L2 hit-one", s1.items.items[6].text);
    try std.testing.expectEqual(RecKind.context, s1.items.items[7].kind);
    try std.testing.expectEqualStrings("L1 plain", s1.items.items[7].text);

    // RandomAccess with identical context = 1
    var s2 = Collect{ .alloc = gpa };
    defer s2.deinit();
    const text_slice: []const u8 = text;
    const ra = RandomAccess.fromSlice(&text_slice);
    const res2 = try searchReverseAt(Collect, gpa, &s2, ra, "log", &m, .{
        .context = 1,
        .line_number_mode = .from_one,
    });
    try std.testing.expectEqual(@as(u64, 3), res2.matched_lines);
    try std.testing.expectEqual(s1.items.items.len, s2.items.items.len);
    for (s1.items.items, s2.items.items) |a, b| {
        try std.testing.expectEqual(a.kind, b.kind);
        try std.testing.expectEqualStrings(a.text, b.text);
        try std.testing.expectEqual(a.num, b.num);
    }

    // Reverse search over UTF-16LE with BOM (both slice and RandomAccess)
    const utf16le = [_]u8{
        0xFF, 0xFE,
        'h',  0,    'i', 0, 't', 0, '1', 0, '\n', 0,
        'o',  0,    'k', 0, '\n', 0,
        'h',  0,    'i', 0, 't', 0, '2', 0, '\n', 0,
    };
    var s3 = Collect{ .alloc = gpa };
    defer s3.deinit();
    const res3 = try searchReverseSlice(Collect, &s3, &utf16le, "u16", &m, .{
        .allocator = gpa,
        .encoding = .auto,
    });
    try std.testing.expectEqual(@as(u64, 2), res3.matched_lines);
    try std.testing.expectEqualStrings("hit2", s3.items.items[0].text);
    try std.testing.expectEqualStrings("hit1", s3.items.items[1].text);

    // Reverse search over LZ4 compressed data via RandomAccess (.auto decompression)
    const compressed = try lz4_mod.compressLz4StoredAlloc(gpa, text);
    defer gpa.free(compressed);
    var s4 = Collect{ .alloc = gpa };
    defer s4.deinit();
    const comp_slice: []const u8 = compressed;
    const ra_lz4 = RandomAccess.fromSlice(&comp_slice);
    const res4 = try searchReverseAt(Collect, gpa, &s4, ra_lz4, "log.lz4", &m, .{
        .compression = .auto,
    });
    try std.testing.expectEqual(@as(u64, 3), res4.matched_lines);
    try std.testing.expectEqualStrings("L8 hit-three", s4.items.items[0].text);
    try std.testing.expectEqualStrings("L7 hit-two", s4.items.items[1].text);
    try std.testing.expectEqualStrings("L2 hit-one", s4.items.items[2].text);
}
