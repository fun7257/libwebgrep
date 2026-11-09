//! [Module] search/state.zig
//! [Layer] Layer 4 — Search Execution State, Quotas, & Line Framing Primitives
//! [Role] Manages per-search `State`, monotonic clock deadlines, cancellation tokens,
//!        byte/result/output quotas, binary NUL tracking, and SIMD line boundary helpers.
//! [Invariants]
//!   1. `State` holds zero global state; all counters and buffers are scoped to a single search invocation.
//!   2. Line framing (`lineStart`, `lineEnd`, `nextLine`, `lastComplete`, `countLines`) uses vectorized `memchr`.
//! [HotPath] `lastComplete`, `lineStart`, `lineEnd`, `nextLine`, `countLines`, `stopInMatch`.

const std = @import("std");
const decompress = @import("../codec/decompress.zig");
const memchr = @import("../finder/memchr.zig");
const regex_mod = @import("../regex.zig");
const sink_mod = @import("../sink.zig");
const cfg_mod = @import("config.zig");
const ring_mod = @import("context_ring.zig");

pub const SearchConfig = cfg_mod.SearchConfig;
pub const SliceError = cfg_mod.SliceError;
pub const ReadError = cfg_mod.ReadError;
pub const Result = cfg_mod.Result;
pub const Outcome = cfg_mod.Outcome;
pub const ResumeState = cfg_mod.ResumeState;
pub const Span = cfg_mod.Span;
pub const width = cfg_mod.width;
const BeforeRing = ring_mod.BeforeRing;
const scanCap = cfg_mod.scanCap;
const lineHoldLimit = cfg_mod.lineHoldLimit;
const beforeCount = cfg_mod.beforeCount;
const afterCount = cfg_mod.afterCount;
const recordSep = cfg_mod.recordSep;
const watchesBinary = cfg_mod.watchesBinary;
const binaryStatus = cfg_mod.binaryStatus;

pub const Range = struct {
    start: usize,
    end: usize,
};

pub const BufMatch = struct {
    start: usize,
    end: usize,
};

pub const State = struct {
    pos: usize = 0,
    abs_base: u64 = 0,
    /// When non-null, holds the 1-based line number at `last_line_counted`.
    line_number: ?u64 = null,
    last_line_counted: usize = 0,
    last_line_visited: usize = 0,
    after_left: u32 = 0,
    has_sunk: bool = false,
    /// Match count that consumes `max_count` quota. Lines promoted to matches inside context windows do not increment this.
    limit_count: u64 = 0,
    matched_lines: u64 = 0,
    matches: u64 = 0,
    bytes_read: u64 = 0,
    bytes_searched: u64 = 0,
    nul_offset: ?u64 = null,
    binary_status: sink_mod.BinaryStatus = .none,
    stopped: bool = false,
    /// Absolute end offset (including newline) of the last line delivered to Sink. Used to detect context breaks independent of buffer indices.
    last_abs_end: u64 = 0,
    /// Complete lines before this offset have either been emitted or pushed into the before-context ring.
    remembered_until: usize = 0,
    ring: BeforeRing = .{},
    long_active: bool = false,
    long_origin: u64 = 0,
    long_dropped: u64 = 0,
    long_number: ?u64 = null,
    long_has_match: bool = false,
    long_excluded: bool = false,
    long_hold_len: usize = 0,
    long_window_start: u64 = 0,
    long_line_len: u64 = 0,
    long_match_start: usize = 0,
    long_match_end: usize = 0,
    /// 0: no window held, 1: line-prefix window, 2: match window.
    long_hold_kind: u2 = 0,
    /// An early match occurred in the current chunk; subsequent chunks revert to pre-scanning for NUL to avoid scanning dense chunks twice.
    prefer_prepass: bool = false,
    /// Used when lossy text does not fit in the stack buffer. Valid only until the callback returns.
    text_alloc: ?std.mem.Allocator = null,
    text_buf: []u8 = &.{},
    replace_buf: []u8 = &.{},
    capture_regex: ?*const regex_mod.Regex = null,
    offset_map: ?*const decompress.OffsetMap = null,
    offset_map_base: u64 = 0,
    decompress_map: ?*const decompress.OffsetMap = null,
    /// Source name used in diagnostic logs; never included in returned errors.
    label: []const u8 = "",
    started_ns: i128 = 0,
    deadline_armed: bool = false,
    limit_hit: sink_mod.LimitHit = .none,
    resume_at: ?u64 = null,
    soft_error: ?sink_mod.SoftError = null,
    need_close: bool = false,
    closed: bool = false,
    output_bytes: u64 = 0,
    output_blocked: bool = false,
    results_out: u64 = 0,
    queued_bytes: usize = 0,
    hit_byte_cap: bool = false,
    scanned_all: bool = false,
    decompressed_bytes: u64 = 0,
    from_reader: bool = false,
    paused: bool = false,
    resume_line: u64 = 1,
    next_progress: u64 = 0,
    last_input_ns: i128 = 0,
    idle_sent: bool = false,

    pub fn exceeded(self: *const State, config: SearchConfig) bool {
        const limit = config.max_count orelse return false;
        return self.limit_count >= limit;
    }
};


pub fn flagIsSet(config: SearchConfig) bool {
    const flag = config.stop orelse return false;
    return flag.load(.acquire);
}

pub fn cancelIsSet(config: SearchConfig) bool {
    const flag = config.cancel orelse return false;
    return flag.load(.acquire);
}

pub fn logDetail(config: SearchConfig, label: []const u8, err: anyerror) void {
    const log = config.log orelse return;
    var buf: [192]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "{s}: {s}", .{ label, @errorName(err) }) catch label;
    log(config.log_ctx, msg);
}

pub fn monotonicNs() i128 {
    var ts: std.posix.timespec = undefined;
    switch (std.posix.errno(std.posix.system.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts))) {
        .SUCCESS => {
            const sec: i128 = ts.sec;
            const nsec: i128 = ts.nsec;
            return sec * std.time.ns_per_s + nsec;
        },
        else => return 0,
    }
}

pub fn readClock(config: SearchConfig) i128 {
    if (config.clock) |clock| return clock(config.clock_ctx);
    return monotonicNs();
}

pub fn armClock(state: *State, config: SearchConfig) void {
    if (config.continuation) |saved| {
        state.started_ns = saved.started_ns;
        state.deadline_armed = saved.deadline_armed;
        state.last_input_ns = saved.started_ns;
        return;
    }
    state.started_ns = readClock(config);
    state.last_input_ns = state.started_ns;
    if (config.time_budget_ns != null) state.deadline_armed = true;
}

pub fn restoreCounters(state: *State, config: SearchConfig) void {
    const saved = config.continuation orelse return;
    state.matched_lines = saved.matched_lines;
    state.matches = saved.matches;
    if (!state.from_reader) state.bytes_read = saved.bytes_read;
    state.bytes_searched = saved.bytes_searched;
    state.output_bytes = saved.output_bytes;
    state.results_out = saved.results_out;
    state.limit_count = saved.limit_count;
    if (config.line_numbers and (!state.from_reader or config.resume_from == 0)) {
        state.line_number = saved.line_number;
    }
}

pub fn liveIsClosed(config: SearchConfig) bool {
    if (!config.live) return true;
    const flag = config.live_closed orelse return false;
    return flag.load(.acquire);
}


pub fn noteRejected(comptime S: type, state: *State, sink: *S) void {
    if (@hasDecl(S, "control") and sink.control() == .pause) state.paused = true;
    state.stopped = true;
}

pub fn isPause(comptime S: type, sink: *S) bool {
    return @hasDecl(S, "control") and sink.control() == .pause;
}

pub fn pastDeadline(state: *const State, config: SearchConfig) bool {
    if (!state.deadline_armed) return false;
    const budget = config.time_budget_ns orelse return false;
    return readClock(config) - state.started_ns >= @as(i128, budget);
}


pub fn overBytes(state: *const State, config: SearchConfig) bool {
    const cap = scanCap(config) orelse return false;
    return state.bytes_read >= cap;
}

pub fn scanRemaining(state: *const State, config: SearchConfig) ?usize {
    const cap = scanCap(config) orelse return null;
    if (state.bytes_read >= cap) return 0;
    const left = cap - state.bytes_read;
    if (left > std.math.maxInt(usize)) return std.math.maxInt(usize);
    return @intCast(left);
}

pub fn overDecompressed(state: *const State, config: SearchConfig) bool {
    const cap = config.max_decompressed_bytes orelse return false;
    return state.decompressed_bytes >= cap;
}

pub fn noteLimit(state: *State, reason: sink_mod.LimitHit) void {
    if (state.limit_hit == .none) state.limit_hit = reason;
    state.stopped = true;
    state.need_close = true;
}

pub fn stopForBudget(state: *State, config: SearchConfig) bool {
    if (pastDeadline(state, config)) {
        noteLimit(state, .deadline);
        return true;
    }
    if (cancelIsSet(config)) {
        noteLimit(state, .cancelled);
        return true;
    }
    if (overBytes(state, config)) {
        noteLimit(state, .max_bytes);
        return true;
    }
    if (overDecompressed(state, config)) {
        noteLimit(state, .decompressed_bytes);
        return true;
    }
    return false;
}

pub fn stopInMatch(state: *State, config: SearchConfig) bool {
    if (pastDeadline(state, config)) {
        noteLimit(state, .deadline);
        return true;
    }
    if (cancelIsSet(config)) {
        noteLimit(state, .cancelled);
        return true;
    }
    return false;
}

pub fn rejectEmptyResults(state: *State, config: SearchConfig) bool {
    const cap = config.max_results orelse return false;
    if (cap != 0) return false;
    state.resume_at = state.abs_base;
    noteLimit(state, .max_results);
    return true;
}

pub fn closeOnce(state: *State, config: SearchConfig) void {
    if (state.closed or !state.need_close) return;
    state.closed = true;
    if (config.close_input) |close| close(config.close_ctx);
}


pub fn budgetView(haystack: []const u8, prepared_base: u64, state: *State, config: SearchConfig) []const u8 {
    var bytes = haystack;
    if (prepared_base > 0) {
        state.abs_base = prepared_base;
    } else if (config.resume_from > 0) {
        const off: usize = if (config.resume_from >= haystack.len) haystack.len else @intCast(config.resume_from);
        state.abs_base = off;
        bytes = haystack[off..];
    }
    if (scanCap(config)) |cap| {
        if (@as(u64, bytes.len) > cap) {
            bytes = bytes[0..@intCast(cap)];
            state.hit_byte_cap = true;
        }
    }
    return bytes;
}


pub fn releaseQueue(state: *State) void {
    state.queued_bytes = 0;
}

pub fn guardLine(state: *State, config: SearchConfig, nbytes: usize) error{BufferLimit}!bool {
    if (config.max_queued_event_bytes) |cap| {
        if (nbytes > cap) {
            logDetail(config, state.label, error.BufferLimit);
            return error.BufferLimit;
        }
        state.queued_bytes = nbytes;
    }
    if (config.max_output_bytes) |cap| {
        const used = state.output_bytes;
        if (used >= cap or @as(u64, nbytes) > cap - used) {
            state.output_blocked = true;
            state.stopped = true;
            state.need_close = true;
            state.queued_bytes = 0;
            return false;
        }
        state.output_bytes = used + nbytes;
    }
    return true;
}

/// A matched line has been emitted. Returns false if no further matches should be sought.
pub fn noteHitLimit(state: *State, config: SearchConfig, end_abs: u64) bool {
    if (config.exists) {
        state.stopped = true;
        state.need_close = true;
        return false;
    }
    if (config.max_results) |cap| {
        if (state.results_out >= cap) {
            state.resume_at = end_abs;
            noteLimit(state, .max_results);
            return false;
        }
    }
    return true;
}

pub fn grow(allocator: std.mem.Allocator, buf: []u8, config: SearchConfig) error{OutOfMemory}!?[]u8 {
    const limit = lineHoldLimit(config);
    if (buf.len >= limit) return null;
    const doubled = if (buf.len > limit / 2) limit else buf.len * 2;
    const next = @min(limit, @max(doubled, buf.len + 1));
    if (next <= buf.len) return null;
    return try allocator.realloc(buf, next);
}

pub fn isMultilineMatcher(matcher: anytype) bool {
    const T = @TypeOf(matcher.*);
    if (@hasDecl(T, "isMultiline")) return matcher.isMultiline();
    return false;
}

pub fn isStartAnchoredMatcher(matcher: anytype) bool {
    const T = @TypeOf(matcher.*);
    if (@hasDecl(T, "isStartAnchored")) return matcher.isStartAnchored();
    return false;
}

pub fn multilineWindow(matcher: anytype, config: SearchConfig) usize {
    const T = @TypeOf(matcher.*);
    const cap = if (config.max_line_len == 0) 1 else config.max_line_len;
    if (@hasDecl(T, "multilineWindow")) return @min(matcher.multilineWindow(), cap);
    return cap;
}

pub fn canFuse(matcher: anytype, config: SearchConfig, state: *const State) bool {
    if (config.null_data) return false;
    if (isMultilineMatcher(matcher)) return false;
    if (config.passthru or config.stop_on_nonmatch) return false;
    if (state.prefer_prepass or state.nul_offset != null) return false;
    if (config.binary == .none or config.invert or beforeCount(config) != 0 or afterCount(config) != 0) return false;
    if (config.whole_word or config.whole_line or config.contains.len != 0 or config.excludes.len != 0 or config.contains_regexes.len != 0 or config.excludes_regexes.len != 0) return false;
    return @hasDecl(@TypeOf(matcher.*), "findWatched");
}


pub fn noteBinary(state: *State, config: SearchConfig, offset: u64) void {
    if (state.nul_offset == null) state.nul_offset = offset;
    state.binary_status = binaryStatus(config, state.nul_offset);
}


pub fn lastComplete(buf: []const u8, config: SearchConfig) usize {
    if (memchr.findLast(width, buf, 0, buf.len, recordSep(config))) |i| return i + 1;
    return 0;
}


pub fn nextLineNumber(state: *const State, buf: []const u8, line: Range, config: SearchConfig) u64 {
    var n = state.line_number orelse 1;
    if (line.end > line.start and line.end <= buf.len and buf[line.end - 1] == recordSep(config)) n += 1;
    return n;
}

pub fn maybeProgress(comptime S: type, sink: *S, state: *State, config: SearchConfig) bool {
    const step = config.progress_interval orelse return true;
    if (step == 0) return true;
    const at = state.abs_base + @as(u64, state.pos);
    if (state.next_progress == 0) state.next_progress = step;
    if (at < state.next_progress) return true;
    state.next_progress = at + step;
    const keep = callOpt(S, "progress", sink, .{ at, state.matches, state.matched_lines });
    if (!keep) {
        noteRejected(S, state, sink);
        return false;
    }
    return true;
}


pub fn contentEnd(buf: []const u8, line: Range, config: SearchConfig) usize {
    var end = line.end;
    const sep = recordSep(config);
    if (end > line.start and end <= buf.len and buf[end - 1] == sep) end -= 1;
    if (!config.null_data and end > line.start and end <= buf.len and buf[end - 1] == '\r') end -= 1;
    return end;
}

pub fn countLines(buf: []const u8, upto: usize, state: *State, config: SearchConfig) void {
    if (state.line_number == null) return;
    if (state.last_line_counted >= upto) return;
    const n = memchr.count(width, buf, state.last_line_counted, upto, recordSep(config));
    state.line_number = (state.line_number orelse return) + n;
    state.last_line_counted = upto;
}

pub fn rollConsumed(buf: []const u8, state: *const State, config: SearchConfig) usize {
    _ = state;
    _ = config;
    return buf.len;
}

pub fn lineStart(buf: []const u8, pos: usize, config: SearchConfig) usize {
    const upto = @min(pos, buf.len);
    if (memchr.findLast(width, buf, 0, upto, recordSep(config))) |i| return i + 1;
    return 0;
}

pub fn lineEnd(buf: []const u8, from: usize, config: SearchConfig) usize {
    if (from >= buf.len) return buf.len;
    if (memchr.find(width, buf, from, recordSep(config))) |i| return i + 1;
    return buf.len;
}

pub fn nextLine(buf: []const u8, pos: usize, end: usize, config: SearchConfig) ?Range {
    if (pos >= end or pos >= buf.len) return null;
    const limit = @min(end, buf.len);
    if (memchr.find(width, buf, pos, recordSep(config))) |i| {
        if (i >= limit) return .{ .start = pos, .end = limit };
        return .{ .start = pos, .end = i + 1 };
    }
    return .{ .start = pos, .end = limit };
}

/// Returns the start of the last line when `count` is 0.
pub fn preceding(bytes: []const u8, count: usize) usize {
    if (bytes.len == 0) return 0;
    var pos: usize = bytes.len;
    var left = count;
    if (bytes[pos - 1] == '\n') pos -= 1;
    while (true) {
        const at = memchr.findLast(width, bytes, 0, pos, '\n') orelse return 0;
        if (left == 0) return at + 1;
        if (at == 0) return 0;
        left -= 1;
        pos = at;
    }
}

pub fn finishSink(comptime S: type, sink: *S, state: *State, config: SearchConfig) Result {
    const cursor = state.abs_base + @as(u64, state.pos);
    if (cursor > state.bytes_searched) state.bytes_searched = cursor;
    if (!state.from_reader) {
        state.bytes_read = @max(state.bytes_read, state.bytes_searched);
    } else if (config.continuation) |saved| {
        state.bytes_read = @max(state.bytes_read, saved.bytes_read);
    }
    const elapsed = elapsedOf(state, config);
    if (state.paused and state.resume_at == null) state.resume_at = cursor;
    const r_at = state.resume_at orelse cursor;
    const has_decomp = if (state.decompress_map) |dm| (dm.anchors.items.len != 0 or dm.base_raw_offset != 0) else false;
    const raw_resume_at: u64 = if (!has_decomp)
        (if (state.offset_map) |m| m.map(r_at -| state.offset_map_base) else r_at)
    else
        0;
    const resume_state = ResumeState{
        .matched_lines = state.matched_lines,
        .matches = state.matches,
        .bytes_read = state.bytes_read,
        .bytes_searched = state.bytes_searched,
        .output_bytes = state.output_bytes,
        .results_out = state.results_out,
        .limit_count = state.limit_count,
        .line_number = state.resume_line,
        .started_ns = state.started_ns,
        .deadline_armed = state.deadline_armed,
        .skip_begin = true,
        .raw_resume_at = raw_resume_at,
    };
    if (state.paused) {
        return .{
            .outcome = .stopped,
            .paused = true,
            .matched_lines = state.matched_lines,
            .matches = state.matches,
            .nul_offset = state.nul_offset,
            .binary_offset = state.nul_offset,
            .bytes_read = state.bytes_read,
            .bytes_searched = state.bytes_searched,
            .output_bytes = state.output_bytes,
            .elapsed_ns = elapsed,
            .resume_at = state.resume_at,
            .resume_state = resume_state,
            .limit_hit = .none,
            .partial = false,
            .scanned_all = false,
        };
    }
    if (state.exceeded(config)) state.need_close = true;
    closeOnce(state, config);
    var outcome: Outcome = if (state.stopped) .stopped else .complete;
    if (state.nul_offset != null and config.binary == .quit) outcome = .binary_quit;
    if (state.nul_offset != null and config.binary == .report and state.matched_lines > 0) {
        outcome = .binary_matched;
    }
    const partial = (state.limit_hit != .none or state.output_blocked) and !state.scanned_all;
    const result = Result{
        .outcome = outcome,
        .matched_lines = state.matched_lines,
        .matches = state.matches,
        .nul_offset = state.nul_offset,
        .binary_offset = state.nul_offset,
        .bytes_read = state.bytes_read,
        .bytes_searched = state.bytes_searched,
        .output_bytes = state.output_bytes,
        .elapsed_ns = elapsed,
        .limit_hit = state.limit_hit,
        .partial = partial,
        .resume_at = state.resume_at,
        .soft_error = state.soft_error,
        .scanned_all = state.scanned_all,
        .resume_state = resume_state,
    };
    _ = callOpt(S, "finish", sink, .{result});
    return result;
}

pub fn elapsedOf(state: *const State, config: SearchConfig) u64 {
    const now = readClock(config);
    const delta = now - state.started_ns;
    if (delta <= 0) return 0;
    if (delta > std.math.maxInt(u64)) return std.math.maxInt(u64);
    return @intCast(delta);
}

pub fn resetStats(matcher: anytype) void {
    const T = @TypeOf(matcher);
    const Child = switch (@typeInfo(T)) {
        .pointer => |p| if (p.size == .one) p.child else return,
        else => return,
    };
    if (@hasDecl(Child, "resetStats")) matcher.resetStats();
}

pub fn callOpt(comptime S: type, comptime name: []const u8, sink: *S, args: anytype) bool {
    if (!@hasDecl(S, name)) return true;
    return @call(.auto, @field(S, name), .{sink} ++ args);
}


pub fn needleLen(matcher: anytype) usize {
    const T = @TypeOf(matcher.*);
    if (@hasField(T, "pattern")) return matcher.pattern.len;
    if (@hasField(T, "patterns")) {
        var max: usize = 0;
        for (matcher.patterns) |pat| max = @max(max, pat.len);
        return max;
    }
    return 1;
}

pub fn overlapKeep(matcher: anytype, config: SearchConfig) usize {
    var n = needleLen(matcher);
    for (config.contains) |pat| n = @max(n, pat.len);
    for (config.excludes) |pat| n = @max(n, pat.len);
    for (config.contains_regexes) |*re| {
        const req_len = if (re.requiredLiteral()) |lit| lit.bytes.len + lit.offset_in_match else 256;
        n = @max(n, @max(req_len, 256));
    }
    for (config.excludes_regexes) |*re| {
        const req_len = if (re.requiredLiteral()) |lit| lit.bytes.len + lit.offset_in_match else 256;
        n = @max(n, @max(req_len, 256));
    }
    if (config.whole_word) n += 4;
    if (n == 0) n = 1;
    const cap = if (config.max_line_len == 0) 1 else config.max_line_len;
    return @min(n, cap);
}

