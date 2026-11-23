//! [Module] search/line_matcher.zig
//! [Layer] Layer 4 — Core Line Matching, Whole-Word/Line Verification, & Secondary Filtering
//! [Role] Scans complete lines in a buffer (`matchBuffer`, `findLine`), fuses NUL binary detection when eligible,
//!        verifies whole-word/whole-line boundaries, applies `contains`/`excludes` filters, and drives context emission.
//! [Invariants]
//!   1. `buf` passed to `matchBuffer` contains only complete lines (or the final line at EOF).
//!   2. Word-boundary and whole-line checks are evaluated before `invert_match` and secondary `contains`/`excludes` filters.
//! [HotPath] `matchBuffer` -> `findLine` -> `nextMatch` -> `linePassesFilters`.

const std = @import("std");
const matcher_mod = @import("../matcher.zig");
const memchr = @import("../finder/memchr.zig");
const unicode_fold = @import("../finder/unicode_fold.zig");
const cfg_mod = @import("config.zig");
const state_mod = @import("state.zig");
const ring_mod = @import("context_ring.zig");
const format_mod = @import("format.zig");

const SearchConfig = cfg_mod.SearchConfig;
const SliceError = cfg_mod.SliceError;
const beforeCount = cfg_mod.beforeCount;
const afterCount = cfg_mod.afterCount;
const Range = state_mod.Range;
const BufMatch = state_mod.BufMatch;
const State = state_mod.State;
const stopInMatch = state_mod.stopInMatch;
const canFuse = state_mod.canFuse;
const noteBinary = state_mod.noteBinary;
const callOpt = state_mod.callOpt;
const maybeProgress = state_mod.maybeProgress;
const lineStart = state_mod.lineStart;
const lineEnd = state_mod.lineEnd;
const nextLine = state_mod.nextLine;
const contentEnd = state_mod.contentEnd;
const isMultilineMatcher = state_mod.isMultilineMatcher;
const effectiveMultiline = state_mod.effectiveMultiline;
const effectiveMultilineWindow = state_mod.effectiveMultilineWindow;
const isStartAnchoredMatcher = state_mod.isStartAnchoredMatcher;
const multilineWindow = state_mod.multilineWindow;
const rememberBefore = ring_mod.rememberBefore;
const emitRing = ring_mod.emitRing;
const emitRingFrom = ring_mod.emitRingFrom;
const sinkMatched = format_mod.sinkMatched;
const sinkContext = format_mod.sinkContext;

pub fn needLineStart(comptime S: type, state: *const State, config: SearchConfig) bool {
    if (comptime @hasDecl(S, "matched") or @hasDecl(S, "context") or @hasDecl(S, "context_break")) return true;
    return state.line_number != null or
        config.max_output_bytes != null or
        config.max_queued_event_bytes != null or
        config.resume_from > 0 or
        config.stop_on_nonmatch or
        config.whole_line or
        config.passthru or
        beforeCount(config) > 0 or
        afterCount(config) > 0 or
        config.contains.len > 0 or
        config.excludes.len > 0 or
        config.contains_regexes.len > 0 or
        config.excludes_regexes.len > 0 or
        config.line_filter != null;
}

pub fn applyInBufferSkip(buf: []const u8, limit: usize, state: *State, config: SearchConfig) bool {
    const target = state.pending_skip_to orelse return true;
    const cur_abs = state.abs_base + @as(u64, state.pos);
    if (target <= cur_abs) {
        state.pending_skip_to = null;
        return true;
    }
    state.after_left = 0;
    state.ring.clear();
    if (!state.from_reader) {
        const buf_end_abs = state.abs_base + @as(u64, buf.len);
        if (target <= buf_end_abs) {
            const new_pos: usize = @intCast(target - state.abs_base);
            state_mod.countLines(buf, new_pos, state, config);
            state.pos = new_pos;
            state.last_line_visited = new_pos;
            state.remembered_until = new_pos;
            state.pending_skip_to = null;
            return new_pos < limit;
        }
        state_mod.countLines(buf, buf.len, state, config);
        state.pos = buf.len;
        state.last_line_visited = buf.len;
        state.remembered_until = buf.len;
        return false;
    }
    const lim_abs = state.abs_base + @as(u64, limit);
    if (target <= lim_abs) {
        const new_pos: usize = @intCast(target - state.abs_base);
        state_mod.countLines(buf, new_pos, state, config);
        state.pos = new_pos;
        state.last_line_visited = new_pos;
        state.remembered_until = new_pos;
        state.pending_skip_to = null;
        return new_pos < limit;
    }
    state_mod.countLines(buf, limit, state, config);
    state.pos = limit;
    state.last_line_visited = limit;
    state.remembered_until = limit;
    return false;
}

pub fn matchBuffer(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    return matchBufferWithLimit(S, sink, matcher, buf, buf.len, false, state, config);
}

fn canBulkInvertCount(
    comptime S: type,
    matcher: anytype,
    state: *const State,
    config: SearchConfig,
    limit: usize,
    buf_len: usize,
) bool {
    if (comptime @hasDecl(S, "matched") or @hasDecl(S, "context") or @hasDecl(S, "contextBreak") or @hasDecl(S, "context_break")) {
        return false;
    }
    return config.invert and
        limit >= buf_len and
        !config.null_data and
        !effectiveMultiline(matcher, config) and
        config.max_count == null and
        config.max_results == null and
        !config.exists and
        !config.files_without_match and
        !config.passthru and
        !config.stop_on_nonmatch and
        !config.whole_line and
        beforeCount(config) == 0 and
        afterCount(config) == 0 and
        state.after_left == 0 and
        config.contains.len == 0 and
        config.excludes.len == 0 and
        config.contains_regexes.len == 0 and
        config.excludes_regexes.len == 0 and
        config.line_filter == null and
        config.resume_from == 0 and
        config.max_output_bytes == null and
        config.max_queued_event_bytes == null and
        (config.progress_interval == null or config.progress_interval.? == 0);
}

fn bulkInvertCount(
    matcher: anytype,
    buf: []const u8,
    effective_limit: usize,
    state: *State,
    config: SearchConfig,
) bool {
    const start_pos = state.pos;
    if (start_pos >= effective_limit) return !state.stopped;

    const has_abort = config.stop != null or config.cancel != null or state.deadline_armed;
    var pos = start_pos;
    var matched: u64 = 0;
    var aborted = false;

    if (config.whole_word) {
        while (pos < effective_limit) {
            if (has_abort) {
                if (state_mod.flagIsSet(config)) {
                    state.stopped = true;
                    aborted = true;
                    break;
                }
                if (stopInMatch(state, config)) {
                    aborted = true;
                    break;
                }
            }
            const hit = nextMatch(matcher, buf, pos, config) orelse break;
            if (hit.start >= effective_limit or hit.start < pos) break;
            matched += 1;
            const probe = if (hit.end > hit.start and hit.end <= effective_limit and buf[hit.end - 1] == '\n')
                hit.end - 1
            else
                @max(hit.end, pos);
            pos = if (probe < effective_limit)
                (if (std.mem.findScalarPos(u8, buf[0..effective_limit], probe, '\n')) |nl| nl + 1 else effective_limit)
            else
                effective_limit;
        }
    } else if (comptime @hasDecl(state_mod.MatcherType(@TypeOf(matcher)), "findEnd")) {
        while (pos < effective_limit) {
            if (has_abort) {
                if (state_mod.flagIsSet(config)) {
                    state.stopped = true;
                    aborted = true;
                    break;
                }
                if (stopInMatch(state, config)) {
                    aborted = true;
                    break;
                }
            }
            const end_pos = matcher.findEnd(buf, pos, .earliest) orelse break;
            if (end_pos < pos or end_pos > buf.len) break;
            const probe = if (end_pos > pos and buf[end_pos - 1] != '\n') end_pos - 1 else end_pos;
            if (probe >= effective_limit) break;
            matched += 1;
            pos = if (probe < effective_limit)
                (if (std.mem.findScalarPos(u8, buf[0..effective_limit], probe, '\n')) |nl| nl + 1 else effective_limit)
            else
                effective_limit;
        }
    } else {
        while (pos < effective_limit) {
            if (has_abort) {
                if (state_mod.flagIsSet(config)) {
                    state.stopped = true;
                    aborted = true;
                    break;
                }
                if (stopInMatch(state, config)) {
                    aborted = true;
                    break;
                }
            }
            const hit = matcher.find(buf, pos, config.match_mode) orelse break;
            if (hit.start >= effective_limit or hit.start < pos) break;
            matched += 1;
            const probe = if (hit.end > hit.start and hit.end <= effective_limit and buf[hit.end - 1] == '\n')
                hit.end - 1
            else
                @max(hit.end, pos);
            pos = if (probe < effective_limit)
                (if (std.mem.findScalarPos(u8, buf[0..effective_limit], probe, '\n')) |nl| nl + 1 else effective_limit)
            else
                effective_limit;
        }
    }

    const scan_end = if (aborted) pos else effective_limit;
    const total_seps: u64 = memchr.count(cfg_mod.width, buf, start_pos, scan_end, '\n');
    const trailing_line: u64 = @intFromBool(scan_end > start_pos and buf[scan_end - 1] != '\n');
    const total_lines = total_seps + trailing_line;
    const non_matching = total_lines -| matched;

    if (state.line_number != null) {
        state_mod.countLines(buf, start_pos, state, config);
        state.line_number = state.line_number.? + total_seps;
        state.last_line_counted = scan_end;
    }
    if (non_matching > 0) {
        state.matched_lines += non_matching;
        state.matches += non_matching;
        state.limit_count += non_matching;
        state.results_out += non_matching;
        state.has_sunk = true;
        state.last_abs_end = state.abs_base + @as(u64, scan_end);
    }
    state.pos = scan_end;
    state.last_line_visited = scan_end;
    state.remembered_until = @max(state.remembered_until, scan_end);
    return !state.stopped;
}

fn canUseFindEnd(comptime S: type, matcher: anytype, config: SearchConfig, need_ls: bool) bool {
    const T = state_mod.MatcherType(@TypeOf(matcher));
    if (comptime !@hasDecl(T, "findEnd")) return false;
    if (comptime @hasDecl(S, "matched")) {
        if (comptime !(@hasDecl(S, "matched_fast_line") and S.matched_fast_line)) return false;
        if (config.replacement != null or config.binary == .report) return false;
    } else if (need_ls) {
        // CountSink with need_ls still doesn't inspect match start/end spans
    }
    return !effectiveMultiline(matcher, config) and
        !config.whole_word and
        !config.whole_line and
        !config.null_data and
        config.line_filter == null and
        config.contains.len == 0 and
        config.excludes.len == 0 and
        config.contains_regexes.len == 0 and
        config.excludes_regexes.len == 0;
}

pub fn matchBufferWithLimit(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    limit: usize,
    can_hold_zero: bool,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    const need_ls = needLineStart(S, state, config);
    const allow_find_end = canUseFindEnd(S, matcher, config, need_ls);
    var effective_limit = @min(limit, buf.len);
    if (config.invert and canBulkInvertCount(S, matcher, state, config, limit, buf.len)) {
        if (state.stopped) return false;
        if (state_mod.flagIsSet(config)) {
            state.stopped = true;
            return false;
        }
        if (stopInMatch(state, config)) return false;
        if (state.pending_skip_to != null) {
            if (!applyInBufferSkip(buf, effective_limit, state, config)) return false;
        }
        return bulkInvertCount(matcher, buf, effective_limit, state, config);
    }
    while (state.pos < effective_limit) {
        if (state.stopped) return false;
        if (state_mod.flagIsSet(config)) {
            state.stopped = true;
            return false;
        }
        if (stopInMatch(state, config)) return false;
        if (!maybeProgress(S, sink, state, config)) return false;
        if (state.pending_skip_to != null) {
            if (!applyInBufferSkip(buf, effective_limit, state, config)) return false;
            continue;
        }
        if (config.invert) {
            if (!try matchInvert(S, sink, matcher, buf, &effective_limit, can_hold_zero, state, config)) {
                if (state.pending_skip_to != null) return false;
                break;
            }
            if (state.pending_skip_to != null) {
                if (!applyInBufferSkip(buf, effective_limit, state, config)) return false;
                continue;
            }
        } else if (try findLineLimitInternal(matcher, buf, state, effective_limit, config, need_ls, allow_find_end)) |line| {
            if (effective_limit < buf.len and line.end > effective_limit and (line.start > 0 or can_hold_zero)) {
                effective_limit = line.start;
                break;
            }
            if (state.abs_base + @as(u64, line.start) < config.resume_from) {
                state.pos = line.end;
                continue;
            }
            if (config.stop_on_nonmatch and state.matched_lines > 0 and line.start > state.pos) {
                state.pos = lineEnd(buf, state.pos, config);
                state.stopped = true;
                state.need_close = true;
                return false;
            }
            if (config.files_without_match) {
                state.limit_count += 1;
                state.matched_lines += 1;
                state.matches += 1;
                state.results_out += 1;
                state.pos = line.end;
                state.stopped = true;
                state.need_close = true;
                return false;
            }
            if (config.passthru) {
                if (!try passthruTo(S, sink, matcher, buf, line.start, state, config)) {
                    if (state.pending_skip_to != null) {
                        state.pos = state.last_line_visited;
                        if (!applyInBufferSkip(buf, effective_limit, state, config)) return false;
                        continue;
                    }
                    return false;
                }
            } else if (beforeCount(config) > 0 or afterCount(config) > 0) {
                if (!try afterContext(S, sink, matcher, buf, line.start, state, config)) {
                    if (state.pending_skip_to != null) {
                        state.pos = state.last_line_visited;
                        if (!applyInBufferSkip(buf, effective_limit, state, config)) return false;
                        continue;
                    }
                    return false;
                }
                if (!try beforeContext(S, sink, matcher, buf, line.start, state, config)) {
                    if (state.pending_skip_to != null) {
                        state.pos = @intCast(@min(@as(u64, buf.len), state.last_abs_end -| state.abs_base));
                        if (!applyInBufferSkip(buf, effective_limit, state, config)) return false;
                        continue;
                    }
                    return false;
                }
            }
            state.limit_count += 1;
            state.pos = line.end;
            const known = BufMatch{ .start = line.mstart, .end = line.mend, .pattern_id = line.mpid, .single_match = line.single_match };
            if (!try sinkMatched(S, sink, matcher, buf, line.range(), known, state, config)) return false;
            if (state.pending_skip_to != null) {
                if (!applyInBufferSkip(buf, effective_limit, state, config)) return false;
                continue;
            }
        } else {
            if (config.stop_on_nonmatch and state.matched_lines > 0) {
                state.pos = lineEnd(buf, state.pos, config);
                state.stopped = true;
                state.need_close = true;
                return false;
            }
            break;
        }
    }
    if (state.stopped) return false;
    if (!maybeProgress(S, sink, state, config)) return false;
    if (state.pending_skip_to != null) {
        _ = applyInBufferSkip(buf, effective_limit, state, config);
        if (state.pending_skip_to != null) return false;
    }
    const end_pos = if (state.exceeded(config)) buf.len else @max(effective_limit, state.pos);
    if (config.passthru and !state.exceeded(config)) {
        if (!try passthruTo(S, sink, matcher, buf, end_pos, state, config)) {
            if (state.pending_skip_to != null) {
                state.pos = state.last_line_visited;
                _ = applyInBufferSkip(buf, end_pos, state, config);
            }
            return false;
        }
    } else {
        if (!try afterContext(S, sink, matcher, buf, end_pos, state, config)) {
            if (state.pending_skip_to != null) {
                state.pos = state.last_line_visited;
                _ = applyInBufferSkip(buf, end_pos, state, config);
            }
            return false;
        }
    }
    // Once the limit is reached, buffered after-context lines have just been emitted; do not read further chunks for subsequent lines.
    if (state.exceeded(config)) return false;
    state.pos = end_pos;
    return !state.stopped;
}

pub const FoundLine = struct {
    start: usize,
    end: usize,
    mstart: usize,
    mend: usize,
    mpid: ?u32 = null,
    single_match: bool = false,

    pub fn range(self: FoundLine) Range {
        return .{ .start = self.start, .end = self.end };
    }
};

pub inline fn bridgingProbeLimit(matcher: anytype, buf: []const u8, end: usize, config: SearchConfig) usize {
    if (end >= buf.len) return buf.len;
    if (!config.null_data) {
        if (state_mod.effectiveMaxNewlines(matcher, config)) |max_nl| {
            if (max_nl <= 8) {
                var pe = end;
                var rem: u32 = max_nl;
                while (rem > 0 and pe < buf.len) : (rem -= 1) {
                    pe = lineEnd(buf, pe, config);
                }
                return pe;
            }
        }
    }
    const ml_win = effectiveMultilineWindow(matcher, config);
    if (ml_win > 0) {
        const T = state_mod.MatcherType(@TypeOf(matcher));
        const m_win: usize = if (@hasDecl(T, "multilineWindow")) matcher.multilineWindow() else ml_win;
        return @min(buf.len, end +| @max(ml_win, m_win) +| 1);
    }
    return buf.len;
}

pub fn matchLineEnd(buf: []const u8, start: usize, hit: matcher_mod.Match, config: SearchConfig) usize {
    const sep = cfg_mod.recordSep(config);
    const probe = if (hit.end > hit.start and hit.end <= buf.len and buf[hit.end - 1] == sep)
        hit.end - 1
    else
        @max(hit.end, start);
    return lineEnd(buf, probe, config);
}

pub fn findLine(matcher: anytype, buf: []const u8, state: *State, config: SearchConfig) SliceError!?FoundLine {
    return findLineLimitOpts(matcher, buf, state, buf.len, config, true);
}

pub fn findLineOpts(matcher: anytype, buf: []const u8, state: *State, config: SearchConfig, need_ls: bool) SliceError!?FoundLine {
    return findLineLimitOpts(matcher, buf, state, buf.len, config, need_ls);
}

pub fn findLineLimitOpts(matcher: anytype, buf: []const u8, state: *State, limit: usize, config: SearchConfig, need_ls: bool) SliceError!?FoundLine {
    const allow_find_end = !need_ls and
        !effectiveMultiline(matcher, config) and
        !config.whole_word and
        !config.whole_line and
        !config.null_data and
        config.line_filter == null and
        config.contains.len == 0 and
        config.excludes.len == 0 and
        config.contains_regexes.len == 0 and
        config.excludes_regexes.len == 0;
    return findLineLimitInternal(matcher, buf, state, limit, config, need_ls, allow_find_end);
}

fn findLineLimitInternal(matcher: anytype, buf: []const u8, state: *State, limit: usize, config: SearchConfig, need_ls: bool, allow_find_end: bool) SliceError!?FoundLine {
    if (state.exceeded(config)) return null;
    const is_ml = effectiveMultiline(matcher, config);
    const max_start = @min(limit, buf.len);
    var pos = state.pos;
    while (pos < max_start) {
        if (allow_find_end) {
            const T = state_mod.MatcherType(@TypeOf(matcher));
            if (comptime @hasDecl(T, "findEnd")) {
                if (state.getCachedMatch(buf, pos) == null) {
                    const end_pos = matcher.findEnd(buf, pos, .earliest) orelse return null;
                    if (end_pos > buf.len or end_pos < pos) return null;
                    const probe = if (end_pos > pos and buf[end_pos - 1] != '\n') end_pos - 1 else end_pos;
                    if (!need_ls and limit >= buf.len) {
                        if (probe >= max_start) return null;
                        const end = lineEnd(buf, probe, config);
                        return .{
                            .start = pos,
                            .end = end,
                            .mstart = probe,
                            .mend = end_pos,
                            .mpid = null,
                            .single_match = false,
                        };
                    }
                    const start = lineStart(buf, probe, config);
                    if (start >= max_start or start == buf.len) return null;
                    const end = lineEnd(buf, probe, config);
                    if (end == start) {
                        pos = @min(buf.len, start + 1);
                        continue;
                    }
                    var mstart = probe;
                    var mend = end_pos;
                    var mpid: ?u32 = null;
                    if (config.max_line_len > 0) {
                        const ce = contentEnd(buf, .{ .start = start, .end = end }, config);
                        if (ce - start > config.max_line_len) {
                            if (matcher.find(buf[0..ce], start, config.match_mode)) |exact_m| {
                                mstart = exact_m.start;
                                mend = exact_m.end;
                                mpid = exact_m.pattern_id;
                            }
                        }
                    }
                    return .{
                        .start = start,
                        .end = end,
                        .mstart = mstart,
                        .mend = mend,
                        .mpid = mpid,
                        .single_match = false,
                    };
                }
            }
        }
        const found = if (config.whole_line)
            matcher.find(buf, pos, config.match_mode)
        else
            nextMatchCached(matcher, buf, pos, state, config);
        const hit = found orelse return null;
        if (hit.start > buf.len or hit.start < pos) return null;
        if (!need_ls and (!is_ml or limit >= buf.len) and hit.start < max_start) {
            var end = matchLineEnd(buf, pos, hit, config);
            var single_match = false;
            if (is_ml and !config.whole_line) {
                single_match = true;
                var cur = hit;
                while (true) {
                    const next_from = if (cur.end == cur.start) cur.end + 1 else cur.end;
                    if (next_from >= end or next_from > buf.len) break;
                    const probe_lim = bridgingProbeLimit(matcher, buf, end, config);
                    const m2 = nextMatch(matcher, buf[0..probe_lim], next_from, config) orelse break;
                    if (m2.start >= end) break;
                    single_match = false;
                    const end2 = matchLineEnd(buf, pos, m2, config);
                    if (end2 > end) end = end2;
                    cur = m2;
                }
            }
            return .{
                .start = pos,
                .end = end,
                .mstart = hit.start,
                .mend = hit.end,
                .mpid = hit.pattern_id,
                .single_match = single_match,
            };
        }
        const start = lineStart(buf, hit.start, config);
        if (start >= max_start or start == buf.len) {
            return null;
        }
        var end = matchLineEnd(buf, start, hit, config);
        if (end == start) {
            pos = @min(buf.len, start + 1);
            continue;
        }
        if (config.whole_line and is_ml) {
            const ml_win = effectiveMultilineWindow(matcher, config);
            const win_cap = if (ml_win > 0) @min(buf.len, start +| ml_win +| 2) else buf.len;
            const max_lines: usize = if (!config.null_data)
                (if (state_mod.effectiveMaxNewlines(matcher, config)) |mn| @as(usize, mn) + 1 else std.math.maxInt(usize))
            else
                std.math.maxInt(usize);
            var cand_pos = start;
            var lines_checked: usize = 0;
            var matched_wl: ?FoundLine = null;
            while (cand_pos < win_cap and lines_checked < max_lines) {
                const cand_le = lineEnd(buf, cand_pos, config);
                if (cand_le <= cand_pos) break;
                lines_checked += 1;
                const cand_ce = contentEnd(buf, .{ .start = start, .end = cand_le }, config);
                if (ml_win > 0 and cand_ce - start > ml_win) break;
                if (matchWholeLine(matcher, buf, start, cand_ce, config)) |wl| {
                    if (linePassesFilters(buf, start, cand_ce, config)) {
                        const first_sp = cfg_mod.Span{
                            .start = 0,
                            .end = cand_ce - start,
                            .pattern_id = wl.pattern_id,
                        };
                        if (config.invert or linePassesUserFilter(buf, start, cand_ce, cand_le, first_sp, false, state, config)) {
                            matched_wl = .{
                                .start = start,
                                .end = cand_le,
                                .mstart = start,
                                .mend = cand_ce,
                                .mpid = wl.pattern_id,
                            };
                            if (config.match_mode == .earliest) break;
                        }
                    }
                }
                cand_pos = cand_le;
            }
            if (matched_wl) |found_wl| return found_wl;
            pos = lineEnd(buf, start, config);
            continue;
        }
        var single_match = false;
        if (is_ml and !config.whole_line) {
            single_match = true;
            var cur = hit;
            while (true) {
                const next_from = if (cur.end == cur.start) cur.end + 1 else cur.end;
                if (next_from >= end or next_from > buf.len) break;
                const probe_lim = bridgingProbeLimit(matcher, buf, end, config);
                const m2 = nextMatch(matcher, buf[0..probe_lim], next_from, config) orelse break;
                if (m2.start >= end) break;
                single_match = false;
                const end2 = matchLineEnd(buf, start, m2, config);
                if (end2 > end) end = end2;
                cur = m2;
            }
        }
        const content_end = contentEnd(buf, .{ .start = start, .end = end }, config);
        var wl_pid: ?u32 = hit.pattern_id;
        if (config.whole_line) {
            const wl = matchWholeLine(matcher, buf, start, content_end, config) orelse {
                pos = end;
                continue;
            };
            wl_pid = wl.pattern_id;
        }
        if (!linePassesFilters(buf, start, content_end, config)) {
            pos = end;
            continue;
        }
        if (!config.invert and config.line_filter != null) {
            const raw_ms = if (config.whole_line) start else hit.start;
            const raw_me = if (config.whole_line) content_end else hit.end;
            const rel_s = @min(@max(raw_ms, start), content_end) - start;
            const rel_e = @max(rel_s, @min(@max(raw_me, start), content_end) - start);
            const first_sp = cfg_mod.Span{
                .start = rel_s,
                .end = rel_e,
                .pattern_id = if (config.whole_line) wl_pid else hit.pattern_id,
            };
            if (!linePassesUserFilter(buf, start, content_end, end, first_sp, false, state, config)) {
                pos = end;
                continue;
            }
        }
        return .{
            .start = start,
            .end = end,
            .mstart = if (config.whole_line) start else hit.start,
            .mend = if (config.whole_line) content_end else hit.end,
            .mpid = if (config.whole_line) wl_pid else hit.pattern_id,
            .single_match = single_match,
        };
    }
    return null;
}

const WordBoundedCtx = struct {
    pub inline fn allow(_: WordBoundedCtx, haystack: []const u8, start: usize, end: usize) bool {
        return wordBounded(haystack, start, end);
    }
};

pub inline fn nextMatchCached(matcher: anytype, buf: []const u8, pos: usize, state: *State, config: SearchConfig) ?matcher_mod.Match {
    if (state.getCachedMatch(buf, pos)) |cached| {
        return cached;
    }
    const m = nextMatch(matcher, buf, pos, config);
    state.setCachedMatch(buf, pos, m);
    return m;
}

pub fn nextMatch(matcher: anytype, buf: []const u8, pos: usize, config: SearchConfig) ?matcher_mod.Match {
    const T = state_mod.MatcherType(@TypeOf(matcher));
    if (config.whole_word and @hasDecl(T, "findAllowed")) {
        if (T == matcher_mod.AnyMatcher) {
            return matcher.findAllowed(buf, pos, config.match_mode, WordBoundedCtx{});
        }
        return matcher.findAllowed(buf, pos, config.match_mode, wordBounded);
    }
    if (config.whole_word) {
        var cur = pos;
        while (cur <= buf.len) {
            const m = matcher.find(buf, cur, config.match_mode) orelse return null;
            if (wordBounded(buf, m.start, m.end)) return m;
            if (m.start >= buf.len) return null;
            cur = m.start + 1;
        }
        return null;
    }
    return matcher.find(buf, pos, config.match_mode);
}

pub fn matchWholeLine(matcher: anytype, buf: []const u8, start: usize, end: usize, config: SearchConfig) ?matcher_mod.Match {
    if (end < start or end > buf.len) return null;
    const T = state_mod.MatcherType(@TypeOf(matcher));
    if (@hasDecl(T, "matchSpan")) {
        const hit = matcher.matchSpan(buf[start..end], config.match_mode) orelse return null;
        return .{ .start = start, .end = end, .pattern_id = hit.pattern_id };
    }
    if (@hasDecl(T, "acceptsSpan")) {
        const FnInfo = @typeInfo(@TypeOf(@field(T, "acceptsSpan"))).@"fn";
        const ok = if (FnInfo.param_types.len == 3)
            matcher.acceptsSpan(buf[start..end], config.match_mode)
        else
            matcher.acceptsSpan(buf, start, end);
        if (!ok) return null;
        if (matcher.find(buf[start..end], 0, config.match_mode)) |m| {
            if (m.start == 0 and m.end == end - start) {
                return .{ .start = start, .end = end, .pattern_id = m.pattern_id };
            }
        }
        return .{ .start = start, .end = end, .pattern_id = null };
    }
    const found = matcher.find(buf[start..end], 0, .leftmost_first) orelse return null;
    if (found.start == 0 and found.end == end - start) {
        return .{ .start = start, .end = end, .pattern_id = found.pattern_id };
    }
    return null;
}

pub fn acceptsWholeLine(matcher: anytype, buf: []const u8, start: usize, end: usize) bool {
    if (end < start or end > buf.len) return false;
    const T = state_mod.MatcherType(@TypeOf(matcher));
    if (@hasDecl(T, "acceptsSpan")) {
        const FnInfo = @typeInfo(@TypeOf(@field(T, "acceptsSpan"))).@"fn";
        return if (FnInfo.param_types.len == 3)
            matcher.acceptsSpan(buf[start..end], .leftmost_first)
        else
            matcher.acceptsSpan(buf, start, end);
    }
    const found = matcher.find(buf[start..end], 0, .leftmost_first) orelse return false;
    return found.start == 0 and found.end == end - start;
}

pub inline fn hasFilterUpper(s: []const u8) bool {
    for (s) |c| {
        if (std.ascii.isUpper(c)) return true;
    }
    return unicode_fold.patternHasUnicodeUpper(s);
}

pub inline fn sliceContainsFilter(haystack: []const u8, needle: []const u8, case_insensitive: bool, smart_case: bool) bool {
    if (needle.len == 0) return true;
    const effective_ci = if (smart_case) !hasFilterUpper(needle) else case_insensitive;
    if (effective_ci and unicode_fold.needsUnicodeExpansion(needle)) {
        return unicode_fold.findFolded(haystack, needle, 0) != null;
    }
    if (haystack.len < needle.len) return false;
    const limit = haystack.len - needle.len;
    const head_haystack = haystack[0 .. limit + 1];
    if (effective_ci) {
        const b0_lo = std.ascii.toLower(needle[0]);
        const b0_hi = std.ascii.toUpper(needle[0]);
        if (needle.len == 1) {
            return if (b0_lo == b0_hi)
                std.mem.findScalar(u8, haystack, b0_lo) != null
            else
                memchr.findEither(memchr.native_width, haystack, 0, b0_lo, b0_hi) != null;
        }
        const blast_lo = std.ascii.toLower(needle[needle.len - 1]);
        const mid_needle = needle[1 .. needle.len - 1];
        var pos: usize = 0;
        while (pos <= limit) {
            const at = (if (b0_lo == b0_hi)
                std.mem.findScalarPos(u8, head_haystack, pos, b0_lo)
            else
                memchr.findEither(memchr.native_width, head_haystack, pos, b0_lo, b0_hi)) orelse return false;
            if (std.ascii.toLower(haystack[at + needle.len - 1]) == blast_lo and
                std.ascii.eqlIgnoreCase(haystack[at + 1 .. at + needle.len - 1], mid_needle))
            {
                return true;
            }
            pos = at + 1;
        }
        return false;
    }
    const b0 = needle[0];
    if (needle.len == 1) {
        return std.mem.findScalar(u8, haystack, b0) != null;
    }
    const blast = needle[needle.len - 1];
    const mid_needle = needle[1 .. needle.len - 1];
    var pos: usize = 0;
    while (pos <= limit) {
        const at = std.mem.findScalarPos(u8, head_haystack, pos, b0) orelse return false;
        if (haystack[at + needle.len - 1] == blast and
            std.mem.eql(u8, haystack[at + 1 .. at + needle.len - 1], mid_needle))
        {
            return true;
        }
        pos = at + 1;
    }
    return false;
}

pub fn linePassesFilters(buf: []const u8, start: usize, end: usize, config: SearchConfig) bool {
    if (config.contains.len == 0 and config.excludes.len == 0 and config.contains_regexes.len == 0 and config.excludes_regexes.len == 0) return true;
    if (end < start or end > buf.len) return false;
    const text = buf[start..end];
    for (config.contains) |pat| {
        if (!sliceContainsFilter(text, pat, config.filter_case_insensitive, config.filter_smart_case)) return false;
    }
    for (config.excludes) |pat| {
        if (sliceContainsFilter(text, pat, config.filter_case_insensitive, config.filter_smart_case)) return false;
    }
    for (config.contains_regexes) |*re| {
        if (re.findReadOnly(text, 0, .earliest) == null) return false;
    }
    for (config.excludes_regexes) |*re| {
        if (re.findReadOnly(text, 0, .earliest) != null) return false;
    }
    return true;
}

pub fn linePassesUserFilter(
    buf: []const u8,
    start: usize,
    content_end: usize,
    raw_end: usize,
    first_match: cfg_mod.Span,
    is_inverted: bool,
    state: *const State,
    config: SearchConfig,
) bool {
    const cb = config.line_filter orelse return true;
    if (content_end < start or content_end > buf.len) return false;
    const clamped_raw = @min(@max(raw_end, content_end), buf.len);
    return cb(config.line_filter_ctx, .{
        .bytes = buf[start..content_end],
        .raw_bytes = buf[start..clamped_raw],
        .absolute_offset = state.abs_base + @as(u64, start),
        .first_match = first_sp: {
            break :first_sp first_match;
        },
        .is_inverted = is_inverted,
    });
}

/// Half-boundary check: inspects only the codepoints immediately outside the match, without requiring the match endpoints themselves to be word characters.
pub fn wordBounded(haystack: []const u8, start: usize, end: usize) bool {
    if (start > haystack.len or end > haystack.len or start > end) return false;
    if (unicode_fold.isWordBefore(haystack, start)) return false;
    if (unicode_fold.isWordAt(haystack, end)) return false;
    return true;
}

pub fn matchInvert(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    effective_limit: *usize,
    can_hold_zero: bool,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    var found_nonmatch = false;
    var nonmatch_range: Range = .{ .start = 0, .end = 0 };
    const gap: Range = if (try findLineLimitOpts(matcher, buf, state, effective_limit.*, config, true)) |line| blk: {
        if (effective_limit.* < buf.len and line.end > effective_limit.* and (line.start > 0 or can_hold_zero)) {
            effective_limit.* = line.start;
            const g = Range{ .start = state.pos, .end = line.start };
            state.pos = line.start;
            break :blk g;
        }
        const g = Range{ .start = state.pos, .end = line.start };
        state.pos = line.end;
        found_nonmatch = true;
        nonmatch_range = line.range();
        break :blk g;
    } else blk: {
        const g = Range{ .start = state.pos, .end = effective_limit.* };
        state.pos = effective_limit.*;
        break :blk g;
    };
    if (gap.start < gap.end) {
        if (config.passthru) {
            if (!try passthruTo(S, sink, matcher, buf, gap.start, state, config)) {
                if (state.pending_skip_to != null) {
                    state.pos = state.last_line_visited;
                    return applyInBufferSkip(buf, effective_limit.*, state, config);
                }
                return false;
            }
        } else if (beforeCount(config) > 0 or afterCount(config) > 0) {
            if (!try afterContext(S, sink, matcher, buf, gap.start, state, config)) {
                if (state.pending_skip_to != null) {
                    state.pos = state.last_line_visited;
                    return applyInBufferSkip(buf, effective_limit.*, state, config);
                }
                return false;
            }
            if (!try beforeContext(S, sink, matcher, buf, gap.start, state, config)) {
                if (state.pending_skip_to != null) {
                    state.pos = @intCast(@min(@as(u64, buf.len), state.last_abs_end -| state.abs_base));
                    return applyInBufferSkip(buf, effective_limit.*, state, config);
                }
                return false;
            }
        }
        var cursor = gap.start;
        while (nextLine(buf, cursor, gap.end, config)) |line| {
            cursor = line.end;
            const content_end = contentEnd(buf, line, config);
            if (!linePassesFilters(buf, line.start, content_end, config) or
                !linePassesUserFilter(buf, line.start, content_end, line.end, .{ .start = 0, .end = 0 }, true, state, config))
            {
                if (config.stop_on_nonmatch and state.matched_lines > 0) {
                    state.pos = line.end;
                    state.stopped = true;
                    state.need_close = true;
                    return false;
                }
                if (config.passthru) {
                    if (!try sinkContext(S, sink, matcher, buf, line, .after, state, config)) return false;
                    if (state.pending_skip_to != null) {
                        state.pos = cursor;
                        return applyInBufferSkip(buf, effective_limit.*, state, config);
                    }
                }
                continue;
            }
            state.limit_count += 1;
            if (!try sinkMatched(S, sink, matcher, buf, line, null, state, config)) return false;
            if (state.pending_skip_to != null) {
                state.pos = cursor;
                return applyInBufferSkip(buf, effective_limit.*, state, config);
            }
            if (state.exceeded(config)) return false;
        }
    }
    if (found_nonmatch) {
        if (config.stop_on_nonmatch and state.matched_lines > 0) {
            state.stopped = true;
            state.need_close = true;
            return false;
        }
        if (config.passthru) {
            if (!try sinkContext(S, sink, matcher, buf, nonmatch_range, .after, state, config)) return false;
            if (state.pending_skip_to != null) {
                state.pos = nonmatch_range.end;
                return applyInBufferSkip(buf, effective_limit.*, state, config);
            }
        }
    }
    return true;
}

pub fn passthruTo(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    upto: usize,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    var cursor = state.last_line_visited;
    if (cursor > upto) return true;
    while (nextLine(buf, cursor, upto, config)) |line| {
        cursor = line.end;
        if (!try sinkContext(S, sink, matcher, buf, line, .after, state, config)) return false;
        if (state.pending_skip_to != null) return false;
    }
    return true;
}

pub fn afterContext(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    upto: usize,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    if (state.after_left == 0) return true;
    const exceeded = state.exceeded(config);
    const is_ml = effectiveMultiline(matcher, config);
    var cursor = state.last_line_visited;
    if (cursor > upto) return true;
    var excluded_until: usize = 0;
    while (nextLine(buf, cursor, upto, config)) |line| {
        cursor = line.end;
        if (exceeded and is_ml) {
            if (config.invert) {
                if (line.start >= excluded_until) {
                    var probe_state = state.*;
                    probe_state.pos = line.start;
                    probe_state.limit_count = 0;
                    var probe_cfg = config;
                    probe_cfg.max_count = null;
                    probe_cfg.line_filter = null;
                    if (try findLineLimitOpts(matcher, buf, &probe_state, line.end, probe_cfg, true)) |ml_line| {
                        if (ml_line.start == line.start) excluded_until = @max(excluded_until, ml_line.end);
                    }
                }
                const content_end = contentEnd(buf, line, config);
                if (line.start >= excluded_until and
                    linePassesFilters(buf, line.start, content_end, config) and
                    linePassesUserFilter(buf, line.start, content_end, line.end, .{ .start = 0, .end = 0 }, true, state, config))
                {
                    const saved = state.after_left;
                    state.pos = line.end;
                    if (!try sinkMatched(S, sink, matcher, buf, line, null, state, config)) return false;
                    if (state.pending_skip_to != null) return false;
                    state.after_left = saved - 1;
                } else {
                    if (!try sinkContext(S, sink, matcher, buf, line, .after, state, config)) return false;
                    if (state.pending_skip_to != null) return false;
                }
            } else {
                var probe_state = state.*;
                probe_state.pos = line.start;
                probe_state.limit_count = 0;
                var probe_cfg = config;
                probe_cfg.max_count = null;
                if (try findLineLimitOpts(matcher, buf, &probe_state, line.end, probe_cfg, true)) |ml_line| {
                    if (ml_line.start == line.start and ml_line.end <= upto) {
                        const saved = state.after_left;
                        const spanned_raw = memchr.count(cfg_mod.width, buf, ml_line.start, ml_line.end, cfg_mod.recordSep(config));
                        const dec: u32 = @intCast(@min(@as(u64, saved), @max(@as(u64, 1), spanned_raw)));
                        cursor = ml_line.end;
                        state.pos = ml_line.end;
                        const known = BufMatch{ .start = ml_line.mstart, .end = ml_line.mend, .pattern_id = ml_line.mpid, .single_match = ml_line.single_match };
                        if (!try sinkMatched(S, sink, matcher, buf, ml_line.range(), known, state, config)) return false;
                        if (state.pending_skip_to != null) return false;
                        state.after_left = saved - dec;
                        if (state.after_left == 0) break;
                        continue;
                    }
                }
                if (!try sinkContext(S, sink, matcher, buf, line, .after, state, config)) return false;
                if (state.pending_skip_to != null) return false;
            }
        } else if (exceeded and lineIsReportedHit(matcher, buf, line, state, config)) {
            const saved = state.after_left;
            state.pos = line.end;
            const known = if (config.invert) null else matchInLine(matcher, buf, line, config);
            if (!try sinkMatched(S, sink, matcher, buf, line, known, state, config)) return false;
            if (state.pending_skip_to != null) return false;
            state.after_left = saved - 1;
        } else {
            if (!try sinkContext(S, sink, matcher, buf, line, .after, state, config)) return false;
            if (state.pending_skip_to != null) return false;
        }
        if (state.after_left == 0) break;
    }
    return true;
}

pub fn beforeContext(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    upto: usize,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    const before_n = beforeCount(config);
    if (before_n == 0) return true;
    if (!config.passthru and !config.invert and !config.stop_on_nonmatch) {
        const limit_end = @min(upto, buf.len);
        const floor = @max(state.remembered_until, state.last_line_visited);
        if (floor >= limit_end) {
            return emitRing(S, sink, buf, state, config);
        }
        const sep = cfg_mod.recordSep(config);
        var start_pos = limit_end;
        var found: u32 = 0;
        while (found < before_n and start_pos > floor) {
            const ls = if (memchr.findLast(cfg_mod.width, buf, floor, start_pos - 1, sep)) |at| at + 1 else floor;
            start_pos = ls;
            found += 1;
        }
        if (found == before_n) {
            state.ring.clear();
        } else if (state.ring.count > 0) {
            const keep = @min(state.ring.count, before_n - found);
            const skip = state.ring.count - keep;
            if (!try emitRingFrom(S, sink, buf, state, config, skip)) return false;
        }
        state_mod.countLines(buf, start_pos, state, config);
        var cursor = start_pos;
        while (nextLine(buf, cursor, limit_end, config)) |line| {
            cursor = line.end;
            if (!try sinkContext(S, sink, matcher, buf, line, .before, state, config)) return false;
            if (state.pending_skip_to != null) return false;
        }
        state.remembered_until = @max(state.remembered_until, limit_end);
        return true;
    }
    // The match may fall at the start of the current chunk with its before-context lines already pushed into the ring during the previous chunk.
    // In that case `last_line_visited == upto`, and the ring must still be emitted.
    if (state.last_line_visited < upto) {
        rememberBefore(matcher, buf, state, config, upto);
    }
    return emitRing(S, sink, buf, state, config);
}


pub fn lineIsReportedHit(matcher: anytype, buf: []const u8, line: Range, state: *const State, config: SearchConfig) bool {
    const content_end = contentEnd(buf, line, config);
    if (!linePassesFilters(buf, line.start, content_end, config)) return false;
    const m_opt = matchInLine(matcher, buf, line, config);
    const hit = m_opt != null;
    const is_hit = if (config.invert) !hit else hit;
    if (!is_hit) return false;
    if (config.line_filter != null) {
        const first_sp: cfg_mod.Span = if (!config.invert) blk: {
            const m = m_opt.?;
            const rel_s = @min(@max(m.start, line.start), content_end) - line.start;
            const rel_e = @max(rel_s, @min(@max(m.end, line.start), content_end) - line.start);
            break :blk .{ .start = rel_s, .end = rel_e, .pattern_id = m.pattern_id };
        } else .{ .start = 0, .end = 0 };
        if (!linePassesUserFilter(buf, line.start, content_end, line.end, first_sp, config.invert, state, config)) return false;
    }
    return true;
}

pub fn matchInLine(matcher: anytype, buf: []const u8, line: Range, config: SearchConfig) ?BufMatch {
    const end = contentEnd(buf, line, config);
    if (config.whole_line) {
        const wl = matchWholeLine(matcher, buf, line.start, end, config) orelse return null;
        return .{ .start = line.start, .end = end, .pattern_id = wl.pattern_id };
    }
    const line_buf = if (effectiveMultiline(matcher, config)) buf else buf[0..@min(end, buf.len)];
    const found = nextMatch(matcher, line_buf, line.start, config) orelse return null;
    // An empty line's content end equals its start; an empty pattern still counts as a match here.
    if (found.start < line.start or found.start > end or found.end > line.end) return null;
    if (found.start == end and found.end > end) return null;
    if (found.start >= line.end) return null;
    return .{ .start = found.start, .end = @min(found.end, end), .pattern_id = found.pattern_id };
}

