//! [Module] search/long_line.zig
//! [Layer] Layer 4 — Constant-Memory Sliding Window for Ultra-Long Lines
//! [Role] Handles lines exceeding `max_line_len` without unbounded buffer growth (`beginLong`, `pumpLong`, `finishLong`),
//!        preserving pattern overlap across sliding windows and capturing a bounded preview window around the first match.
//! [Invariants]
//!   1. Memory usage for arbitrarily long lines is strictly bounded by `buffer_size + max_line_len`.
//!   2. Sliding window retains `overlapKeep(matcher, config)` bytes so matches straddling chunk boundaries are never missed.
//! [HotPath] Cold path relative to normal lines; hot loop inside `noteLong` when scanning multi-megabyte single-line blobs.

const std = @import("std");
const matcher_mod = @import("../matcher.zig");
const memchr = @import("../finder/memchr.zig");
const cfg_mod = @import("config.zig");
const state_mod = @import("state.zig");
const ring_mod = @import("context_ring.zig");
const format_mod = @import("format.zig");
const line_matcher_mod = @import("line_matcher.zig");

const SearchConfig = cfg_mod.SearchConfig;
const SliceError = cfg_mod.SliceError;
const ReadError = cfg_mod.ReadError;
const Span = cfg_mod.Span;
const width = cfg_mod.width;
const beforeCount = cfg_mod.beforeCount;
const afterCount = cfg_mod.afterCount;
const recordSep = cfg_mod.recordSep;
const watchesBinary = cfg_mod.watchesBinary;
const State = state_mod.State;
const lastComplete = state_mod.lastComplete;
const overlapKeep = state_mod.overlapKeep;
const guardLine = state_mod.guardLine;
const releaseQueue = state_mod.releaseQueue;
const noteRejected = state_mod.noteRejected;
const noteHitLimit = state_mod.noteHitLimit;
const countLines = state_mod.countLines;
const stopInMatch = state_mod.stopInMatch;
const noteBinary = state_mod.noteBinary;
const callOpt = state_mod.callOpt;
const Preview = ring_mod.Preview;
const windowOrigin = ring_mod.windowOrigin;
const rememberBefore = ring_mod.rememberBefore;
const emitRing = ring_mod.emitRing;
const sinkBreakAt = format_mod.sinkBreakAt;
const sinkLineAction = format_mod.sinkLineAction;
const sliceContainsFilter = line_matcher_mod.sliceContainsFilter;
const nextMatch = line_matcher_mod.nextMatch;
const matchBuffer = line_matcher_mod.matchBuffer;

pub fn longTail(buf: []const u8, eof: bool, config: SearchConfig) bool {
    if (eof or buf.len <= config.max_line_len) return false;
    const end = lastComplete(buf, config);
    return buf.len - end > config.max_line_len;
}


pub fn containsDone(seen: []const bool, config: SearchConfig) bool {
    const total = config.contains.len + config.contains_regexes.len;
    if (total == 0) return true;
    if (seen.len < total) return false;
    for (seen[0..total]) |ok| if (!ok) return false;
    return true;
}

pub fn ensureHold(allocator: std.mem.Allocator, hold: *[]u8, n: usize) error{OutOfMemory}!void {
    if (n == 0 or hold.len >= n) return;
    hold.* = try allocator.realloc(hold.*, n);
}

pub fn compactBuf(buf: []u8, filled: *usize, drop: usize, state: *State) void {
    if (drop == 0 or drop > filled.*) return;
    const remain = filled.* - drop;
    if (remain > 0) @memmove(buf[0..remain], buf[drop..filled.*]);
    filled.* = remain;
    state.pos = if (state.pos >= drop) state.pos - drop else 0;
    state.last_line_visited = if (state.last_line_visited >= drop) state.last_line_visited - drop else 0;
    state.last_line_counted = if (state.last_line_counted >= drop) state.last_line_counted - drop else 0;
    state.remembered_until = if (state.remembered_until >= drop) state.remembered_until - drop else 0;
    state.abs_base += drop;
}

pub fn noteLong(
    allocator: std.mem.Allocator,
    matcher: anytype,
    bytes: []const u8,
    hold: *[]u8,
    seen: *[]bool,
    state: *State,
    config: SearchConfig,
    commit: bool,
) error{OutOfMemory}!void {
    if (!state.long_excluded) {
        for (config.excludes) |pat| {
            if (sliceContainsFilter(bytes, pat, config.filter_case_insensitive, config.filter_smart_case)) {
                state.long_excluded = true;
                break;
            }
        }
        if (!state.long_excluded and config.excludes_regexes.len > 0) {
            for (config.excludes_regexes) |*re| {
                if (re.findReadOnly(bytes, 0, .earliest) != null) {
                    state.long_excluded = true;
                    break;
                }
            }
        }
    }
    const total_contains = config.contains.len + config.contains_regexes.len;
    if (!state.long_excluded and seen.len >= total_contains) {
        for (config.contains, 0..) |pat, i| {
            if (!seen.*[i] and sliceContainsFilter(bytes, pat, config.filter_case_insensitive, config.filter_smart_case)) seen.*[i] = true;
        }
        for (config.contains_regexes, 0..) |*re, i| {
            const idx = config.contains.len + i;
            if (!seen.*[idx] and re.findReadOnly(bytes, 0, .earliest) != null) {
                seen.*[idx] = true;
            }
        }
    }
    if (state.long_has_match or config.whole_line) return;
    const keep = if (commit) 0 else overlapKeep(matcher, config);
    const left_ctx: usize = if (!commit and config.whole_word) (if (config.whole_word_unicode) @as(usize, 4) else @as(usize, 1)) else 0;
    const stable = if (bytes.len > keep) @min(bytes.len, (bytes.len - keep) + left_ctx) else 0;
    var pos: usize = 0;
    while (pos < stable) {
        const hit = nextMatch(matcher, bytes, pos, config) orelse break;
        if (hit.start >= stable) break;
        if (config.whole_word and !commit) {
            var right_truncated = hit.end >= bytes.len;
            if (!right_truncated and config.whole_word_unicode and bytes[hit.end] >= 0x80) {
                if (std.unicode.utf8ByteSequenceLength(bytes[hit.end])) |seq_len| {
                    if (hit.end + seq_len > bytes.len) right_truncated = true;
                } else |_| {}
            }
            if (right_truncated) {
                pos = @min(bytes.len, hit.start + 1);
                continue;
            }
        }
        if (config.whole_word and state.long_dropped > 0) {
            if (hit.start == 0 or (config.whole_word_unicode and hit.start < 4 and bytes.len > 0 and (bytes[0] & 0xC0) == 0x80)) {
                pos = @min(bytes.len, hit.start + 1);
                continue;
            }
        }
        try saveMatchWindow(allocator, bytes, hit, hold, state, config);
        state.long_has_match = true;
        break;
    }
}

pub fn saveMatchWindow(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    hit: matcher_mod.Match,
    hold: *[]u8,
    state: *State,
    config: SearchConfig,
) error{OutOfMemory}!void {
    const limit = config.max_line_len;
    if (limit == 0) return;
    try ensureHold(allocator, hold, limit);
    const avail = bytes.len;
    const local = windowOrigin(avail, limit, hit.start, @min(hit.end, avail));
    const end = @min(avail, local + limit);
    if (end < local) return;
    if (hit.start >= end) return;
    const n = end - local;
    @memcpy(hold.*[0..n], bytes[local..end]);
    state.long_hold_len = n;
    state.long_window_start = state.long_dropped + local;
    state.long_match_start = hit.start - local;
    state.long_match_end = @min(hit.end, end) - local;
    state.long_match_pid = hit.pattern_id;
    state.long_hold_kind = 2;
}

pub fn savePrefix(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    hold: *[]u8,
    state: *State,
    config: SearchConfig,
) error{OutOfMemory}!void {
    const limit = config.max_line_len;
    if (limit == 0 or state.long_hold_kind == 2) return;
    const n = @min(limit, bytes.len);
    if (n == 0) return;
    try ensureHold(allocator, hold, limit);
    @memcpy(hold.*[0..n], bytes[0..n]);
    state.long_hold_len = n;
    state.long_window_start = state.long_dropped;
    state.long_hold_kind = 1;
}

pub fn slideLong(buf: *[]u8, filled: *usize, matcher: anytype, state: *State, config: SearchConfig) void {
    const keep = overlapKeep(matcher, config);
    if (filled.* <= keep) return;
    var drop = filled.* - keep;
    if (config.whole_word and config.whole_word_unicode) {
        var back: usize = 0;
        while (drop > 0 and back < 3 and (buf.*[drop] & 0xC0) == 0x80) : (back += 1) {
            drop -= 1;
        }
        if (drop == 0) return;
    }
    const actual_keep = filled.* - drop;
    if (state.line_number) |ln| {
        const nls = memchr.count(width, buf.*[0..drop], 0, drop, recordSep(config));
        state.line_number = ln + nls;
    }
    @memmove(buf.*[0..actual_keep], buf.*[drop..filled.*]);
    filled.* = actual_keep;
    state.long_dropped += drop;
    state.abs_base += drop;
}

pub fn emitHold(
    comptime S: type,
    sink: *S,
    hold: []const u8,
    state: *State,
    config: SearchConfig,
    as_match: bool,
    end_abs: u64,
    next_line_num: u64,
) SliceError!bool {
    const withheld = config.binary == .report and state.nul_offset != null;
    const n = @min(state.long_hold_len, hold.len);
    const raw = hold[0..n];
    const span: ?Span = if (withheld or state.long_hold_kind != 2) null else .{
        .start = state.long_match_start,
        .end = state.long_match_end,
        .pattern_id = state.long_match_pid,
    };
    if (!try sinkBreakAt(S, sink, state.long_origin, state, config)) return false;
    const bytes = if (withheld) raw[0..0] else raw;
    if (!try guardLine(state, config, bytes.len)) return false;
    const truncated = state.long_line_len > config.max_line_len and !withheld;
    const window = if (withheld) 0 else state.long_window_start;
    var none: [0]Span = .{};
    const repl = if (withheld) null else config.replacement;
    const action = if (as_match)
        sinkLineAction(S, "matched", sink, state, bytes, bytes, 0, bytes.len, config.match_mode, span, &none, state.long_origin, state.long_number, truncated, state.long_line_len, window, repl)
    else
        sinkLineAction(S, "context", sink, state, bytes, bytes, 0, bytes.len, config.match_mode, span, &none, state.long_origin, state.long_number, truncated, state.long_line_len, window, repl);
    releaseQueue(state);
    if (as_match) {
        state.matched_lines += 1;
        state.matches += 1;
        state.results_out += 1;
    }
    state.last_abs_end = end_abs;
    state.has_sunk = true;
    var keep = true;
    switch (action) {
        .cont => {},
        .skip_to => |target| {
            if (target > end_abs) {
                state.after_left = 0;
                state.ring.clear();
                state.pending_skip_to = target;
            }
        },
        .pause => {
            state.paused = true;
            state.resume_at = end_abs;
            state.resume_line = next_line_num;
            state.stopped = true;
            keep = false;
        },
        .stop => {
            state.stopped = true;
            keep = false;
        },
    }
    if (as_match and !noteHitLimit(state, config, end_abs)) return false;
    return keep and !state.paused;
}

pub fn finishLong(
    comptime S: type,
    sink: *S,
    buf: *[]u8,
    filled: *usize,
    hold: []const u8,
    seen: []const bool,
    state: *State,
    config: SearchConfig,
    content_in_buf: usize,
    drop_buf: usize,
) SliceError!bool {
    state.long_line_len = state.long_dropped + content_in_buf;
    const filters_ok = !state.long_excluded and containsDone(seen, config);
    const matched_pat = state.long_has_match and !config.whole_line;
    var is_hit = if (config.invert) !matched_pat else matched_pat;
    if (!filters_ok) is_hit = false;
    if (is_hit and config.line_filter != null) {
        const raw = hold[0..@min(state.long_hold_len, hold.len)];
        const first_sp: Span = if (!config.invert and state.long_hold_kind == 2) .{
            .start = state.long_match_start,
            .end = state.long_match_end,
            .pattern_id = state.long_match_pid,
        } else .{ .start = 0, .end = 0 };
        if (config.line_filter) |cb| {
            if (!cb(config.line_filter_ctx, .{
                .bytes = raw,
                .raw_bytes = raw,
                .absolute_offset = state.long_origin,
                .first_match = first_sp,
                .is_inverted = config.invert,
            })) {
                is_hit = false;
            }
        }
    }
    const end_abs = state.abs_base + drop_buf;
    const clamped_drop = @min(drop_buf, filled.*);
    const next_ln: u64 = if (state.line_number) |ln|
        ln + memchr.count(width, buf.*, state.last_line_counted, clamped_drop, recordSep(config))
    else
        0;
    if (is_hit and !state.exceeded(config)) {
        if (!config.passthru) {
            if (!try emitRing(S, sink, buf.*, state, config)) {
                if (state.pending_skip_to != null) {
                    countLines(buf.*, clamped_drop, state, config);
                    compactBuf(buf.*, filled, clamped_drop, state);
                    state.pos = 0;
                    state.last_line_visited = 0;
                    state.remembered_until = 0;
                    state.long_active = false;
                    state.long_hold_kind = 0;
                    state.long_has_match = false;
                    state.long_match_pid = null;
                    return !state.stopped;
                }
                return false;
            }
        }
        state.limit_count += 1;
        if (!try emitHold(S, sink, hold, state, config, true, end_abs, next_ln)) return false;
        if (state.pending_skip_to == null) state.after_left = afterCount(config);
    } else if (!is_hit and config.stop_on_nonmatch and state.matched_lines > 0) {
        state.stopped = true;
        state.need_close = true;
    } else if (config.passthru and !state.exceeded(config)) {
        if (!try emitHold(S, sink, hold, state, config, false, end_abs, next_ln)) return false;
    } else if (state.after_left > 0) {
        if (!try emitHold(S, sink, hold, state, config, is_hit, end_abs, next_ln)) return false;
        if (state.after_left > 0) state.after_left -= 1;
    } else if (beforeCount(config) > 0) {
        const raw = hold[0..@min(state.long_hold_len, hold.len)];
        const preview = Preview{
            .start = 0,
            .end = raw.len,
            .truncated = state.long_line_len > config.max_line_len,
            .line_len = state.long_line_len,
            .window_start = state.long_window_start,
            .span = if (state.long_hold_kind == 2) .{
                .start = state.long_match_start,
                .end = state.long_match_end,
                .pattern_id = state.long_match_pid,
            } else null,
        };
        state.ring.pushBytes(raw, preview, state.long_origin, end_abs, state.long_number);
    }
    countLines(buf.*, clamped_drop, state, config);
    compactBuf(buf.*, filled, clamped_drop, state);
    state.pos = 0;
    state.last_line_visited = 0;
    state.remembered_until = 0;
    state.long_active = false;
    state.long_hold_kind = 0;
    state.long_has_match = false;
    state.long_match_pid = null;
    return !state.stopped;
}

pub fn beginLongWithMatch(
    allocator: std.mem.Allocator,
    matcher: anytype,
    buf: *[]u8,
    filled: *usize,
    hold: *[]u8,
    seen: *[]bool,
    state: *State,
    config: SearchConfig,
    preset_match: ?matcher_mod.Match,
) error{OutOfMemory}!void {
    state.long_active = true;
    state.long_origin = state.abs_base;
    state.long_dropped = 0;
    state.long_has_match = false;
    state.long_excluded = false;
    state.long_hold_kind = 0;
    state.long_hold_len = 0;
    state.long_window_start = 0;
    state.long_match_pid = null;
    state.long_number = state.line_number;
    const total_contains = config.contains.len + config.contains_regexes.len;
    if (total_contains > seen.len) {
        seen.* = try allocator.realloc(seen.*, total_contains);
    }
    if (seen.len > 0) @memset(seen.*, false);
    const bytes = buf.*[0..filled.*];
    if (preset_match) |pm| {
        try saveMatchWindow(allocator, bytes, pm, hold, state, config);
        state.long_has_match = true;
    } else if (config.invert or config.passthru or beforeCount(config) > 0 or state.after_left > 0) {
        try savePrefix(allocator, bytes, hold, state, config);
    }
    try noteLong(allocator, matcher, bytes, hold, seen, state, config, false);
    slideLong(buf, filled, matcher, state, config);
}

pub fn beginLong(
    allocator: std.mem.Allocator,
    matcher: anytype,
    buf: *[]u8,
    filled: *usize,
    hold: *[]u8,
    seen: *[]bool,
    state: *State,
    config: SearchConfig,
) error{OutOfMemory}!void {
    return beginLongWithMatch(allocator, matcher, buf, filled, hold, seen, state, config, null);
}

fn transitionToLong(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    matcher: anytype,
    buf: *[]u8,
    filled: *usize,
    initial_search_end: usize,
    hold: *[]u8,
    seen: *[]bool,
    state: *State,
    config: SearchConfig,
) ReadError!bool {
    var search_end = initial_search_end;
    if (search_end > 0) {
        if (!state_mod.effectiveMultiline(matcher, config) or config.whole_line) {
            if (!try matchBuffer(S, sink, matcher, buf.*[0..search_end], state, config)) {
                if (state.pending_skip_to != null) return true;
                return false;
            }
            rememberBefore(matcher, buf.*, state, config, search_end);
            countLines(buf.*, search_end, state, config);
            compactBuf(buf.*, filled, search_end, state);
        } else {
            const ml_win = state_mod.effectiveMultilineWindow(matcher, config);
            const safe_ce = state_mod.lineStart(buf.*[0..search_end], search_end -| ml_win, config);
            if (safe_ce > 0) {
                if (!try line_matcher_mod.matchBufferWithLimit(S, sink, matcher, buf.*[0..filled.*], safe_ce, true, state, config)) {
                    if (state.pending_skip_to != null) return true;
                    return false;
                }
                const drop = state.pos;
                if (drop > 0) {
                    rememberBefore(matcher, buf.*, state, config, drop);
                    countLines(buf.*, drop, state, config);
                    compactBuf(buf.*, filled, drop, state);
                    search_end = lastComplete(buf.*[0..filled.*], config);
                    if (filled.* - search_end <= config.max_line_len) return !state.stopped;
                }
            }
            var bridged = false;
            while (search_end > 0 and state.pos < search_end) {
                const m_opt = nextMatch(matcher, buf.*[0..filled.*], state.pos, config);
                if (m_opt == null or m_opt.?.start >= search_end) {
                    if (!try matchBuffer(S, sink, matcher, buf.*[0..search_end], state, config)) {
                        if (state.pending_skip_to != null) return true;
                        return false;
                    }
                    rememberBefore(matcher, buf.*, state, config, search_end);
                    countLines(buf.*, search_end, state, config);
                    compactBuf(buf.*, filled, search_end, state);
                    break;
                }
                const hit = m_opt.?;
                const ls = state_mod.lineStart(buf.*[0..search_end], hit.start, config);
                var end_line = line_matcher_mod.matchLineEnd(buf.*[0..filled.*], ls, hit, config);
                if (end_line <= search_end) {
                    var cur = hit;
                    while (true) {
                        const next_from = if (cur.end == cur.start) cur.end + 1 else cur.end;
                        if (next_from >= end_line or next_from > filled.*) break;
                        const probe_lim = line_matcher_mod.bridgingProbeLimit(matcher, buf.*[0..filled.*], end_line, config);
                        const m2 = nextMatch(matcher, buf.*[0..probe_lim], next_from, config) orelse break;
                        if (m2.start >= end_line) break;
                        const end2 = line_matcher_mod.matchLineEnd(buf.*[0..filled.*], ls, m2, config);
                        if (end2 > end_line) end_line = end2;
                        cur = m2;
                    }
                }
                if (end_line <= search_end) {
                    if (!try line_matcher_mod.matchBufferWithLimit(S, sink, matcher, buf.*[0..search_end], end_line, false, state, config)) {
                        if (state.pending_skip_to != null) return true;
                        return false;
                    }
                    if (state.pos < end_line) state.pos = end_line;
                } else {
                    if (ls > state.pos) {
                        if (!try matchBuffer(S, sink, matcher, buf.*[0..ls], state, config)) {
                            if (state.pending_skip_to != null) return true;
                            return false;
                        }
                    }
                    if (ls > 0) {
                        rememberBefore(matcher, buf.*, state, config, ls);
                        countLines(buf.*, ls, state, config);
                        compactBuf(buf.*, filled, ls, state);
                    }
                    const shifted = matcher_mod.Match{
                        .start = hit.start - ls,
                        .end = hit.end - ls,
                        .pattern_id = hit.pattern_id,
                    };
                    try beginLongWithMatch(allocator, matcher, buf, filled, hold, seen, state, config, shifted);
                    bridged = true;
                    break;
                }
            }
            if (bridged) return !state.stopped;
            if (search_end > 0 and filled.* >= search_end and lastComplete(buf.*[0..filled.*], config) > 0) {
                const rem_se = lastComplete(buf.*[0..filled.*], config);
                if (rem_se > 0) {
                    if (!try matchBuffer(S, sink, matcher, buf.*[0..rem_se], state, config)) {
                        if (state.pending_skip_to != null) return true;
                        return false;
                    }
                    rememberBefore(matcher, buf.*, state, config, rem_se);
                    countLines(buf.*, rem_se, state, config);
                    compactBuf(buf.*, filled, rem_se, state);
                }
            }
        }
    }
    try beginLong(allocator, matcher, buf, filled, hold, seen, state, config);
    return !state.stopped;
}

pub fn makeRoom(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    matcher: anytype,
    buf: *[]u8,
    filled: *usize,
    hold: *[]u8,
    seen: *[]bool,
    state: *State,
    config: SearchConfig,
) ReadError!bool {
    if (state.long_active) {
        const before = filled.*;
        slideLong(buf, filled, matcher, state, config);
        return filled.* < buf.len and filled.* < before;
    }
    const end = lastComplete(buf.*[0..filled.*], config);
    if (end > 0) {
        if (!state_mod.effectiveMultiline(matcher, config)) {
            if (!try matchBuffer(S, sink, matcher, buf.*[0..end], state, config)) {
                if (state.pending_skip_to != null) return true;
                return false;
            }
            rememberBefore(matcher, buf.*, state, config, end);
            countLines(buf.*, end, state, config);
            compactBuf(buf.*, filled, end, state);
            return filled.* < buf.len;
        }
        const ml_win = state_mod.effectiveMultilineWindow(matcher, config);
        const safe_ce = state_mod.lineStart(buf.*[0..end], end -| ml_win, config);
        if (safe_ce > 0) {
            if (!try line_matcher_mod.matchBufferWithLimit(S, sink, matcher, buf.*[0..filled.*], safe_ce, true, state, config)) {
                if (state.pending_skip_to != null) return true;
                return false;
            }
            const drop = state.pos;
            if (drop > 0) {
                rememberBefore(matcher, buf.*, state, config, drop);
                countLines(buf.*, drop, state, config);
                compactBuf(buf.*, filled, drop, state);
                return filled.* < buf.len;
            }
        }
        if (filled.* - end > config.max_line_len) {
            if (!try transitionToLong(S, allocator, sink, matcher, buf, filled, end, hold, seen, state, config)) return false;
            return filled.* < buf.len;
        }
    }
    if (filled.* > config.max_line_len) {
        try beginLong(allocator, matcher, buf, filled, hold, seen, state, config);
        return filled.* < buf.len;
    }
    return false;
}

pub fn pumpLong(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    matcher: anytype,
    buf: *[]u8,
    filled: *usize,
    hold: *[]u8,
    seen: *[]bool,
    new_at: usize,
    eof: bool,
    state: *State,
    config: SearchConfig,
) ReadError!bool {
    if (stopInMatch(state, config)) return false;
    if (watchesBinary(config) and state.nul_offset == null and new_at < filled.*) {
        if (std.mem.findScalar(u8, buf.*[new_at..filled.*], 0)) |rel| {
            const nul_idx = new_at + rel;
            const abs_nul = state.abs_base + nul_idx;
            if (config.binary == .quit) {
                if (state.long_active) {
                    if (std.mem.findScalar(u8, buf.*[0..nul_idx], recordSep(config))) |nl| {
                        var content_len = nl;
                        if (!config.null_data and nl > 0 and buf.*[nl - 1] == '\r') content_len = nl - 1;
                        try noteLong(allocator, matcher, buf.*[0..content_len], hold, seen, state, config, true);
                        if (!try finishLong(S, sink, buf, filled, hold.*, seen.*, state, config, content_len, nl + 1)) return false;
                        const rem_nul = nul_idx - (nl + 1);
                        const safe_end = state_mod.lineStart(buf.*[0..rem_nul], rem_nul, config);
                        if (safe_end > state.pos) {
                            if (!try matchBuffer(S, sink, matcher, buf.*[0..safe_end], state, config)) return false;
                        }
                    }
                } else {
                    const safe_end = state_mod.lineStart(buf.*[0..nul_idx], nul_idx, config);
                    if (safe_end > state.pos) {
                        if (!try matchBuffer(S, sink, matcher, buf.*[0..safe_end], state, config)) return false;
                    }
                }
                noteBinary(state, config, abs_nul);
                _ = callOpt(S, "binary", sink, .{state.nul_offset.?});
                return false;
            }
            noteBinary(state, config, abs_nul);
            const cont = callOpt(S, "binary", sink, .{state.nul_offset.?});
            if (!cont) return false;
        }
    }
    if (!state.long_active) {
        if (eof) return true;
        const search_end = lastComplete(buf.*[0..filled.*], config);
        if (filled.* - search_end <= config.max_line_len) return true;
        return transitionToLong(S, allocator, sink, matcher, buf, filled, search_end, hold, seen, state, config);
    }
    const sep = recordSep(config);
    if (std.mem.findScalar(u8, buf.*[0..filled.*], sep)) |nl| {
        var content_len = nl;
        if (!config.null_data and nl > 0 and buf.*[nl - 1] == '\r') content_len = nl - 1;
        try noteLong(allocator, matcher, buf.*[0..content_len], hold, seen, state, config, true);
        return finishLong(S, sink, buf, filled, hold.*, seen.*, state, config, content_len, nl + 1);
    }
    if (eof) {
        try noteLong(allocator, matcher, buf.*[0..filled.*], hold, seen, state, config, true);
        return finishLong(S, sink, buf, filled, hold.*, seen.*, state, config, filled.*, filled.*);
    }
    try noteLong(allocator, matcher, buf.*[0..filled.*], hold, seen, state, config, false);
    if (filled.* > config.max_line_len) slideLong(buf, filled, matcher, state, config);
    return !state.stopped;
}

