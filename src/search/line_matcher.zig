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
const isStartAnchoredMatcher = state_mod.isStartAnchoredMatcher;
const multilineWindow = state_mod.multilineWindow;
const rememberBefore = ring_mod.rememberBefore;
const emitRing = ring_mod.emitRing;
const sinkMatched = format_mod.sinkMatched;
const sinkContext = format_mod.sinkContext;

pub fn matchBuffer(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    while (state.pos < buf.len) {
        if (state.stopped) return false;
        if (stopInMatch(state, config)) return false;
        if (!maybeProgress(S, sink, state, config)) return false;
        if (config.invert) {
            if (!try matchInvert(S, sink, matcher, buf, state, config)) break;
        } else if (try findLine(matcher, buf, state, config)) |line| {
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
            state.limit_count += 1;
            if (config.passthru) {
                if (!try passthruTo(S, sink, matcher, buf, line.start, state, config)) return false;
            } else if (beforeCount(config) > 0 or afterCount(config) > 0) {
                if (!try afterContext(S, sink, matcher, buf, line.start, state, config)) return false;
                if (!try beforeContext(S, sink, matcher, buf, line.start, state, config)) return false;
            }
            state.pos = line.end;
            const known = BufMatch{ .start = line.mstart, .end = line.mend };
            if (!try sinkMatched(S, sink, matcher, buf, line.range(), known, state, config)) return false;
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
    if (config.passthru and !state.exceeded(config)) {
        if (!try passthruTo(S, sink, matcher, buf, buf.len, state, config)) return false;
    } else {
        if (!try afterContext(S, sink, matcher, buf, buf.len, state, config)) return false;
    }
    // Once the limit is reached, buffered after-context lines have just been emitted; do not read further chunks for subsequent lines.
    if (state.exceeded(config)) return false;
    state.pos = buf.len;
    return !state.stopped;
}

pub const FoundLine = struct {
    start: usize,
    end: usize,
    mstart: usize,
    mend: usize,

    pub fn range(self: FoundLine) Range {
        return .{ .start = self.start, .end = self.end };
    }
};

pub fn findLine(matcher: anytype, buf: []const u8, state: *State, config: SearchConfig) SliceError!?FoundLine {
    if (state.exceeded(config)) return null;
    var pos = state.pos;
    while (pos < buf.len) {
        const found = if (config.whole_line)
            matcher.find(buf, pos, config.match_mode)
        else
            nextMatch(matcher, buf, pos, config);
        const hit = found orelse return null;
        if (hit.start > buf.len or hit.start < pos) return null;
        const start = lineStart(buf, hit.start, config);
        if (start == buf.len) {
            pos = buf.len;
            continue;
        }
        const end = lineEnd(buf, @max(hit.end, start), config);
        if (end == start) {
            pos = @min(buf.len, start + 1);
            continue;
        }
        const content_end = contentEnd(buf, .{ .start = start, .end = end }, config);
        if (config.whole_line and !acceptsWholeLine(matcher, buf, start, content_end)) {
            pos = end;
            continue;
        }
        if (!linePassesFilters(buf, start, content_end, config)) {
            pos = end;
            continue;
        }
        return .{
            .start = start,
            .end = end,
            .mstart = if (config.whole_line) start else hit.start,
            .mend = if (config.whole_line) content_end else hit.end,
        };
    }
    return null;
}

pub fn nextMatch(matcher: anytype, buf: []const u8, pos: usize, config: SearchConfig) ?matcher_mod.Match {
    if (config.whole_word and @hasDecl(@TypeOf(matcher.*), "findAllowed")) {
        return matcher.findAllowed(buf, pos, config.match_mode, wordBounded);
    }
    return matcher.find(buf, pos, config.match_mode);
}

pub fn acceptsWholeLine(matcher: anytype, buf: []const u8, start: usize, end: usize) bool {
    if (end < start or end > buf.len) return false;
    const T = @TypeOf(matcher.*);
    if (@hasDecl(T, "acceptsSpan")) return matcher.acceptsSpan(buf, start, end);
    const found = matcher.find(buf[start..end], 0, .leftmost_first) orelse return false;
    return found.start == 0 and found.end == end - start;
}

pub inline fn hasFilterUpper(s: []const u8) bool {
    for (s) |c| {
        if (c >= 'A' and c <= 'Z') return true;
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
                memchr.find(memchr.native_width, haystack, 0, b0_lo) != null
            else
                memchr.findEither(memchr.native_width, haystack, 0, b0_lo, b0_hi) != null;
        }
        const blast_lo = std.ascii.toLower(needle[needle.len - 1]);
        const mid_needle = needle[1 .. needle.len - 1];
        var pos: usize = 0;
        while (pos <= limit) {
            const at = (if (b0_lo == b0_hi)
                memchr.find(memchr.native_width, head_haystack, pos, b0_lo)
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
        return memchr.find(memchr.native_width, haystack, 0, b0) != null;
    }
    const blast = needle[needle.len - 1];
    const mid_needle = needle[1 .. needle.len - 1];
    var pos: usize = 0;
    while (pos <= limit) {
        const at = memchr.find(memchr.native_width, head_haystack, pos, b0) orelse return false;
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
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    var found_nonmatch = false;
    var nonmatch_range: Range = .{ .start = 0, .end = 0 };
    const gap: Range = if (try findLine(matcher, buf, state, config)) |line| blk: {
        const g = Range{ .start = state.pos, .end = line.start };
        state.pos = line.end;
        found_nonmatch = true;
        nonmatch_range = line.range();
        break :blk g;
    } else blk: {
        const g = Range{ .start = state.pos, .end = buf.len };
        state.pos = buf.len;
        break :blk g;
    };
    if (gap.start < gap.end) {
        if (config.passthru) {
            if (!try passthruTo(S, sink, matcher, buf, gap.start, state, config)) return false;
        } else if (beforeCount(config) > 0 or afterCount(config) > 0) {
            if (!try afterContext(S, sink, matcher, buf, gap.start, state, config)) return false;
            if (!try beforeContext(S, sink, matcher, buf, gap.start, state, config)) return false;
        }
        var cursor = gap.start;
        while (nextLine(buf, cursor, gap.end, config)) |line| {
            cursor = line.end;
            const content_end = contentEnd(buf, line, config);
            if (!linePassesFilters(buf, line.start, content_end, config)) {
                if (config.stop_on_nonmatch and state.matched_lines > 0) {
                    state.pos = line.end;
                    state.stopped = true;
                    state.need_close = true;
                    return false;
                }
                if (config.passthru) {
                    if (!try sinkContext(S, sink, matcher, buf, line, .after, state, config)) return false;
                }
                continue;
            }
            state.limit_count += 1;
            if (!try sinkMatched(S, sink, matcher, buf, line, null, state, config)) return false;
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
    var cursor = state.last_line_visited;
    if (cursor > upto) return true;
    while (nextLine(buf, cursor, upto, config)) |line| {
        cursor = line.end;
        if (exceeded and lineIsReportedHit(matcher, buf, line, config)) {
            const saved = state.after_left;
            state.pos = line.end;
            const known = matchInLine(matcher, buf, line, config);
            if (!try sinkMatched(S, sink, matcher, buf, line, known, state, config)) return false;
            state.after_left = saved - 1;
        } else if (!try sinkContext(S, sink, matcher, buf, line, .after, state, config)) return false;
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
    if (beforeCount(config) == 0) return true;
    // The match may fall at the start of the current chunk with its before-context lines already pushed into the ring during the previous chunk.
    // In that case `last_line_visited == upto`, and the ring must still be emitted.
    if (state.last_line_visited < upto) {
        rememberBefore(matcher, buf, state, config, upto);
    }
    return emitRing(S, sink, buf, state, config);
}


pub fn lineIsReportedHit(matcher: anytype, buf: []const u8, line: Range, config: SearchConfig) bool {
    const content_end = contentEnd(buf, line, config);
    if (!linePassesFilters(buf, line.start, content_end, config)) return false;
    const hit = matchInLine(matcher, buf, line, config) != null;
    return if (config.invert) !hit else hit;
}

pub fn matchInLine(matcher: anytype, buf: []const u8, line: Range, config: SearchConfig) ?BufMatch {
    const end = contentEnd(buf, line, config);
    if (config.whole_line) {
        if (!acceptsWholeLine(matcher, buf, line.start, end)) return null;
        return .{ .start = line.start, .end = end };
    }
    const line_buf = if (isMultilineMatcher(matcher)) buf else buf[0..@min(end, buf.len)];
    const found = nextMatch(matcher, line_buf, line.start, config) orelse return null;
    // An empty line's content end equals its start; an empty pattern still counts as a match here.
    if (found.start < line.start or found.start > end or found.end > line.end) return null;
    if (found.start == end and found.end > end) return null;
    if (found.start >= line.end) return null;
    return .{ .start = found.start, .end = @min(found.end, end) };
}

