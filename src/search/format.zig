//! [Module] search/format.zig
//! [Layer] Layer 4 — Match Span Collection, UTF-16 Columns, Lossy Sanitization, & Template Replacement
//! [Role] Constructs `Line` payloads for matched/context lines, computes UTF-16 code-unit columns/spans,
//!        sanitizes invalid UTF-8 to U+FFFD on demand, and expands `$0`/`$1`..`$9`/`${name}` replacement templates.
//! [Invariants]
//!   1. Only executed on matched or emitted context lines (never on non-matching lines).
//!   2. Uses stack scratch buffers first (`stack_spans`, `text_scratch`, `replace_scratch`), falling back to `text_alloc` only for huge lines.
//! [HotPath] `sinkMatched` -> `buildLine` -> `gatherSpans`.

const std = @import("std");
const encoding = @import("../codec/encoding.zig");
const matcher_mod = @import("../matcher.zig");
const sink_mod = @import("../sink.zig");
const cfg_mod = @import("config.zig");
const state_mod = @import("state.zig");
const ring_mod = @import("context_ring.zig");
const line_matcher_mod = @import("line_matcher.zig");

const SearchConfig = cfg_mod.SearchConfig;
const SliceError = cfg_mod.SliceError;
const Span = cfg_mod.Span;
const Line = cfg_mod.Line;
const beforeCount = cfg_mod.beforeCount;
const afterCount = cfg_mod.afterCount;
const binaryStatus = cfg_mod.binaryStatus;
const Range = state_mod.Range;
const BufMatch = state_mod.BufMatch;
const State = state_mod.State;
const isMultilineMatcher = state_mod.isMultilineMatcher;
const guardLine = state_mod.guardLine;
const releaseQueue = state_mod.releaseQueue;
const noteRejected = state_mod.noteRejected;
const noteHitLimit = state_mod.noteHitLimit;
const nextLineNumber = state_mod.nextLineNumber;
const contentEnd = state_mod.contentEnd;
const countLines = state_mod.countLines;
const stopInMatch = state_mod.stopInMatch;
const maybeProgress = state_mod.maybeProgress;
const callOpt = state_mod.callOpt;
const regex_mod = @import("../regex.zig");
const Preview = ring_mod.Preview;
const previewLine = ring_mod.previewLine;
const isPause = state_mod.isPause;
const nextMatch = line_matcher_mod.nextMatch;
const matchInLine = line_matcher_mod.matchInLine;

pub const ContextKind = enum { before, after };

pub fn spanBefore(_: void, a: Span, b: Span) bool {
    if (a.start == b.start) return a.end < b.end;
    return a.start < b.start;
}

pub fn growSpans(alloc: ?std.mem.Allocator, store: []Span, heap: *[]Span, n: usize) SliceError![]Span {
    const a = alloc orelse return error.OutOfMemory;
    const bigger_n = @max(store.len * 2, @max(heap.len * 2, n + 1));
    if (heap.len == 0) {
        const bigger = try a.alloc(Span, bigger_n);
        @memcpy(bigger[0..n], store[0..n]);
        heap.* = bigger;
        return bigger;
    }
    const from_inline = (store.ptr != heap.*.ptr);
    if (heap.len < bigger_n) {
        heap.* = try a.realloc(heap.*, bigger_n);
    }
    if (from_inline and n > 0) {
        @memcpy(heap.*[0..n], store[0..n]);
    }
    return heap.*;
}

/// Non-overlapping matches on this line, relative to the preview window and sorted by start offset.
/// An empty pattern records only a single zero-width span to avoid spinning at every byte.
pub fn gatherSpans(
    alloc: ?std.mem.Allocator,
    inline_buf: []Span,
    heap: *[]Span,
    matcher: anytype,
    buf: []const u8,
    line: Range,
    preview: Preview,
    known: ?BufMatch,
    state: *State,
    config: SearchConfig,
) SliceError![]Span {
    if (known == null) return inline_buf[0..0];
    var store = if (heap.len > inline_buf.len) heap.* else inline_buf;
    var n: usize = 0;
    if (config.whole_line) {
        if (preview.span) |span| {
            store[0] = span;
            n = 1;
        }
        return store[0..n];
    }
    const content_end = contentEnd(buf, line, config);
    const line_buf = if (isMultilineMatcher(matcher)) buf else buf[0..@min(content_end, buf.len)];
    const win_lo = preview.start;
    const win_hi = preview.end;
    var pos = line.start;
    if (known) |k| {
        const kmend = @min(k.end, content_end);
        const kempty = k.start == kmend;
        const kin_win = k.start >= win_lo and k.start < win_hi;
        const kempty_at_pt = kempty and k.start == win_lo and win_lo == win_hi;
        if (kin_win or kempty_at_pt) {
            if (kempty_at_pt) {
                store[0] = .{ .start = 0, .end = 0, .pattern_id = k.pattern_id };
            } else {
                store[0] = .{
                    .start = k.start - win_lo,
                    .end = @min(kmend, win_hi) - win_lo,
                    .pattern_id = k.pattern_id,
                };
            }
            n = 1;
        }
        pos = if (k.end > k.start) k.end else k.start + 1;
    }
    while (pos <= content_end and pos <= line_buf.len) {
        if (stopInMatch(state, config)) break;
        const found = nextMatch(matcher, line_buf, pos, config) orelse break;
        if (found.start < pos or found.start > buf.len or found.start > content_end) break;
        if (found.start == content_end and found.end > content_end) break;
        const mend = @min(found.end, content_end);
        const empty = found.start == mend;
        const in_window = found.start >= win_lo and found.start < win_hi;
        const empty_at_point = empty and found.start == win_lo and win_lo == win_hi;
        if (in_window or empty_at_point) {
            if (n == store.len) store = try growSpans(alloc, store, heap, n);
            if (empty_at_point) {
                store[n] = .{ .start = 0, .end = 0, .pattern_id = found.pattern_id };
            } else {
                store[n] = .{
                    .start = found.start - win_lo,
                    .end = @min(mend, win_hi) - win_lo,
                    .pattern_id = found.pattern_id,
                };
            }
            n += 1;
        }
        if (empty or found.end <= pos) break;
        pos = found.end;
    }
    if (n == 0) {
        if (preview.span) |span| {
            if (store.len == 0) store = try growSpans(alloc, store, heap, 0);
            store[0] = span;
            n = 1;
        }
    }
    std.mem.sort(Span, store[0..n], {}, spanBefore);
    return store[0..n];
}

pub fn sinkLine(
    comptime S: type,
    comptime name: []const u8,
    sink: *S,
    state: *State,
    bytes: []const u8,
    span: ?Span,
    matches: []Span,
    offset: u64,
    number: ?u64,
    truncated: bool,
    line_len: u64,
    window_start: u64,
    replacement: ?[]const u8,
) bool {
    if (comptime !@hasDecl(S, name)) return true;
    var one: [1]Span = undefined;
    var multi = matches;
    if (multi.len == 0) {
        if (span) |found| {
            one[0] = .{ .start = found.start, .end = found.end, .pattern_id = found.pattern_id };
            multi = &one;
        }
    }
    var scratch: [1024]u8 = undefined;
    var replace_scratch: [4096]u8 = undefined;
    const line = buildLine(state, &scratch, &replace_scratch, bytes, span, multi, offset, number, truncated, line_len, window_start, replacement);
    return callOpt(S, name, sink, .{line});
}

pub fn buildLine(
    state: *State,
    scratch: []u8,
    replace_scratch: []u8,
    bytes: []const u8,
    span: ?Span,
    matches: []Span,
    offset: u64,
    number: ?u64,
    truncated: bool,
    line_len: u64,
    window_start: u64,
    replacement: ?[]const u8,
) Line {
    const is_ascii = encoding.isAsciiSlice(bytes);
    const text = if (is_ascii) bytes else lossyText(state, scratch, bytes);
    if (is_ascii) {
        for (matches) |*item| {
            item.u16_start = item.start;
            item.u16_end = item.end;
            item.replacement = replacement;
        }
    } else {
        var cursor_byte: usize = 0;
        var cursor_units: usize = 0;
        for (matches) |*item| {
            const from = @min(item.start, bytes.len);
            const to = @min(@max(item.end, from), bytes.len);
            const units = advanceUtf16Span(bytes, &cursor_byte, &cursor_units, from, to);
            item.u16_start = units.start;
            item.u16_end = units.end;
            item.replacement = replacement;
        }
    }
    var match = span;
    var u16_column: ?u64 = null;
    if (span) |found| {
        const from = @min(found.start, bytes.len);
        const to = @min(@max(found.end, from), bytes.len);
        const units: encoding.Utf16Span = if (is_ascii)
            .{ .start = from, .end = to }
        else if (matches.len > 0 and matches[0].start == found.start and matches[0].end == found.end)
            .{ .start = matches[0].u16_start, .end = matches[0].u16_end }
        else
            encoding.utf16Span(bytes, from, to);
        match = .{
            .start = found.start,
            .end = found.end,
            .u16_start = units.start,
            .u16_end = units.end,
            .replacement = replacement,
            .pattern_id = found.pattern_id,
        };
        u16_column = units.start + 1;
    }
    const replaced: ?[]const u8 = if (replacement) |repl|
        if (matches.len > 0) buildReplaced(state, replace_scratch, bytes, matches, &match, repl) else null
    else
        null;
    const column: ?u64 = if (matches.len > 0) @as(u64, matches[0].start) + 1 else null;
    const mid_offset: u64 = if (state.offset_map) |m| m.map(offset -| state.offset_map_base) else offset;
    const raw_offset: u64 = if (state.decompress_map) |dm| dm.map(mid_offset) else mid_offset;
    return .{
        .bytes = bytes,
        .text = text,
        .raw = bytes,
        .replaced = replaced,
        .offset = offset,
        .raw_offset = raw_offset,
        .number = number,
        .match = match,
        .matches = matches,
        .column = column,
        .u16_column = u16_column,
        .binary_status = state.binary_status,
        .truncated = truncated,
        .line_len = line_len,
        .window_start = window_start,
    };
}

pub fn advanceUtf16Span(
    bytes: []const u8,
    cursor_byte: *usize,
    cursor_units: *usize,
    from: usize,
    to: usize,
) encoding.Utf16Span {
    if (from < cursor_byte.*) {
        cursor_byte.* = 0;
        cursor_units.* = 0;
    }
    const delta_start = encoding.utf16Span(bytes[cursor_byte.*..], 0, from - cursor_byte.*).end;
    const u16_start = cursor_units.* + delta_start;
    cursor_byte.* = from;
    cursor_units.* = u16_start;

    const delta_end = encoding.utf16Span(bytes[from..], 0, to - from).end;
    const u16_end = u16_start + delta_end;
    cursor_byte.* = to;
    cursor_units.* = u16_end;
    return .{ .start = u16_start, .end = u16_end };
}

pub fn expandReplacementTemplate(
    repl: []const u8,
    bytes: []const u8,
    from: usize,
    to: usize,
    caps: ?regex_mod.Captures,
    dest: ?[]u8,
) usize {
    var written: usize = 0;
    var i: usize = 0;
    while (i < repl.len) {
        if (repl[i] != '$' or i + 1 >= repl.len) {
            if (dest) |d| d[written] = repl[i];
            written += 1;
            i += 1;
            continue;
        }
        const next = repl[i + 1];
        if (next == '$') {
            if (dest) |d| d[written] = '$';
            written += 1;
            i += 2;
        } else if (next == '&' or next == '0') {
            const seg = bytes[from..to];
            if (dest) |d| if (seg.len > 0) @memcpy(d[written .. written + seg.len], seg);
            written += seg.len;
            i += 2;
        } else if (next >= '1' and next <= '9') {
            const g: usize = next - '0';
            if (caps) |c| {
                if (c.group(g)) |sp| {
                    const gfrom = @min(sp.start, bytes.len);
                    const gto = @min(@max(sp.end, gfrom), bytes.len);
                    const seg = bytes[gfrom..gto];
                    if (dest) |d| if (seg.len > 0) @memcpy(d[written .. written + seg.len], seg);
                    written += seg.len;
                }
            }
            i += 2;
        } else if (next == '{' and i + 3 < repl.len and repl[i + 3] == '}' and repl[i + 2] >= '0' and repl[i + 2] <= '9') {
            const g: usize = repl[i + 2] - '0';
            if (g == 0) {
                const seg = bytes[from..to];
                if (dest) |d| if (seg.len > 0) @memcpy(d[written .. written + seg.len], seg);
                written += seg.len;
            } else if (caps) |c| {
                if (c.group(g)) |sp| {
                    const gfrom = @min(sp.start, bytes.len);
                    const gto = @min(@max(sp.end, gfrom), bytes.len);
                    const seg = bytes[gfrom..gto];
                    if (dest) |d| if (seg.len > 0) @memcpy(d[written .. written + seg.len], seg);
                    written += seg.len;
                }
            }
            i += 4;
        } else {
            if (dest) |d| d[written] = '$';
            written += 1;
            i += 1;
        }
    }
    return written;
}

pub fn buildReplaced(
    state: *State,
    scratch: []u8,
    bytes: []const u8,
    matches: []Span,
    match_out: *?Span,
    repl: []const u8,
) ?[]const u8 {
    if (std.mem.indexOfScalar(u8, repl, '$') == null) {
        var need: usize = 0;
        var cursor: usize = 0;
        for (matches) |item| {
            const from = @min(item.start, bytes.len);
            const to = @min(@max(item.end, from), bytes.len);
            if (from > cursor) need += from - cursor;
            need += repl.len;
            cursor = @max(cursor, to);
        }
        if (cursor < bytes.len) need += bytes.len - cursor;
        const dest = replaceDest(state, scratch, need) orelse return null;
        cursor = 0;
        var out: usize = 0;
        for (matches) |item| {
            const from = @min(item.start, bytes.len);
            const to = @min(@max(item.end, from), bytes.len);
            if (from > cursor) {
                const seg = bytes[cursor..from];
                @memcpy(dest[out .. out + seg.len], seg);
                out += seg.len;
            }
            if (repl.len > 0) {
                @memcpy(dest[out .. out + repl.len], repl);
                out += repl.len;
            }
            cursor = @max(cursor, to);
        }
        if (cursor < bytes.len) {
            const tail = bytes[cursor..];
            @memcpy(dest[out .. out + tail.len], tail);
            out += tail.len;
        }
        return dest[0..out];
    }

    var caps_cache: [32]?regex_mod.Captures = undefined;
    var need: usize = 0;
    var cursor: usize = 0;
    for (matches, 0..) |item, idx| {
        const from = @min(item.start, bytes.len);
        const to = @min(@max(item.end, from), bytes.len);
        if (from > cursor) need += from - cursor;
        const caps: ?regex_mod.Captures = if (state.capture_regex) |re|
            re.extractCaptures(bytes, .{ .start = from, .end = to })
        else
            null;
        if (idx < caps_cache.len) caps_cache[idx] = caps;
        need += expandReplacementTemplate(repl, bytes, from, to, caps, null);
        cursor = @max(cursor, to);
    }
    if (cursor < bytes.len) need += bytes.len - cursor;
    const dest = replaceDest(state, scratch, need) orelse return null;
    cursor = 0;
    var out: usize = 0;
    for (matches, 0..) |*item, idx| {
        const from = @min(item.start, bytes.len);
        const to = @min(@max(item.end, from), bytes.len);
        if (from > cursor) {
            const seg = bytes[cursor..from];
            @memcpy(dest[out .. out + seg.len], seg);
            out += seg.len;
        }
        const caps: ?regex_mod.Captures = if (idx < caps_cache.len)
            caps_cache[idx]
        else if (state.capture_regex) |re|
            re.extractCaptures(bytes, .{ .start = from, .end = to })
        else
            null;
        const exp_start = out;
        out += expandReplacementTemplate(repl, bytes, from, to, caps, dest[exp_start..]);
        item.replacement = dest[exp_start..out];
        cursor = @max(cursor, to);
    }
    if (match_out.*) |*m| {
        if (matches.len > 0 and m.start == matches[0].start and m.end == matches[0].end) {
            m.replacement = matches[0].replacement;
        }
    }
    if (cursor < bytes.len) {
        const tail = bytes[cursor..];
        @memcpy(dest[out .. out + tail.len], tail);
        out += tail.len;
    }
    return dest[0..out];
}

pub fn replaceDest(state: *State, scratch: []u8, need: usize) ?[]u8 {
    if (need <= scratch.len) return scratch[0..need];
    const alloc = state.text_alloc orelse return null;
    if (state.replace_buf.len < need) {
        if (state.replace_buf.len == 0) {
            state.replace_buf = alloc.alloc(u8, need) catch return null;
        } else {
            state.replace_buf = alloc.realloc(state.replace_buf, need) catch return null;
        }
    }
    if (state.replace_buf.len < need) return null;
    return state.replace_buf[0..need];
}

pub fn lossyText(state: *State, scratch: []u8, bytes: []const u8) []const u8 {
    if (encoding.validUtf8(bytes)) return bytes;
    const need = encoding.lossyLen(bytes);
    const dest = lossyDest(state, scratch, need) orelse return bytes;
    return dest[0..encoding.writeLossy(bytes, dest)];
}

pub fn lossyDest(state: *State, scratch: []u8, need: usize) ?[]u8 {
    if (need <= scratch.len) return scratch[0..need];
    const alloc = state.text_alloc orelse return null;
    if (state.text_buf.len < need) {
        if (state.text_buf.len == 0) {
            state.text_buf = alloc.alloc(u8, need) catch return null;
        } else {
            state.text_buf = alloc.realloc(state.text_buf, need) catch return null;
        }
    }
    if (state.text_buf.len < need) return null;
    return state.text_buf[0..need];
}


pub fn sinkMatched(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    line: Range,
    known: ?BufMatch,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    if (comptime !@hasDecl(S, "matched")) {
        const line_abs = state.abs_base + line.start;
        if (!try sinkBreakAt(S, sink, line_abs, state, config)) return false;
        countLines(buf, line.start, state, config);
        const withheld = config.binary == .report and state.nul_offset != null;
        if (!withheld) {
            const content_end = contentEnd(buf, line, config);
            const raw_len = content_end - line.start;
            const capped_len = if (config.max_line_len == 0 or raw_len <= config.max_line_len) raw_len else config.max_line_len;
            if (!try guardLine(state, config, capped_len)) return false;
        }
        releaseQueue(state);
        state.last_line_visited = line.end;
        state.last_abs_end = state.abs_base + line.end;
        state.remembered_until = @max(state.remembered_until, line.end);
        state.after_left = afterCount(config);
        state.has_sunk = true;
        state.matched_lines += 1;
        state.matches += 1;
        state.results_out += 1;
        return true;
    }
    const preview = previewLine(buf, line, known, config);
    const line_abs = state.abs_base + line.start;
    if (!try sinkBreakAt(S, sink, line_abs, state, config)) return false;
    countLines(buf, line.start, state, config);
    const withheld = config.binary == .report and state.nul_offset != null;
    const bytes = if (withheld) buf[line.start..line.start] else buf[preview.start..preview.end];
    var inline_spans: [32]Span = undefined;
    const matches = if (withheld) inline_spans[0..0] else try gatherSpans(
        state.text_alloc,
        &inline_spans,
        &state.span_buf,
        matcher,
        buf,
        line,
        preview,
        known,
        state,
        config,
    );
    if (!try guardLine(state, config, bytes.len)) return false;
    const keep = sinkLine(
        S,
        "matched",
        sink,
        state,
        bytes,
        if (withheld) null else preview.span,
        matches,
        line_abs,
        state.line_number,
        preview.truncated and !withheld,
        preview.line_len,
        if (withheld) 0 else preview.window_start,
        if (withheld) null else config.replacement,
    );
    releaseQueue(state);
    state.last_line_visited = line.end;
    state.last_abs_end = state.abs_base + line.end;
    state.remembered_until = @max(state.remembered_until, line.end);
    state.after_left = afterCount(config);
    state.has_sunk = true;
    state.matched_lines += 1;
    state.matches += if (matches.len > 0) @as(u64, @intCast(matches.len)) else 1;
    state.results_out += 1;
    if (!keep) {
        if (isPause(S, sink)) {
            state.resume_at = state.abs_base + @as(u64, line.end);
            state.resume_line = nextLineNumber(state, buf, line, config);
        }
        noteRejected(S, state, sink);
    }
    if (state.paused) return false;
    if (!maybeProgress(S, sink, state, config)) return false;
    if (!noteHitLimit(state, config, state.abs_base + line.end)) return false;
    return keep and !state.paused;
}

pub fn sinkContext(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    line: Range,
    kind: ContextKind,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    const known = if (config.invert) matchInLine(matcher, buf, line, config) else null;
    const preview = previewLine(buf, line, known, config);
    const line_abs = state.abs_base + line.start;
    if (!try sinkBreakAt(S, sink, line_abs, state, config)) return false;
    countLines(buf, line.start, state, config);
    const withheld = config.binary == .report and state.nul_offset != null;
    const bytes = if (withheld) buf[line.start..line.start] else buf[preview.start..preview.end];
    var inline_spans: [32]Span = undefined;
    const matches = if (withheld) inline_spans[0..0] else try gatherSpans(
        state.text_alloc,
        &inline_spans,
        &state.span_buf,
        matcher,
        buf,
        line,
        preview,
        known,
        state,
        config,
    );
    if (!try guardLine(state, config, bytes.len)) return false;
    const keep = sinkLine(
        S,
        "context",
        sink,
        state,
        bytes,
        if (withheld) null else preview.span,
        matches,
        line_abs,
        state.line_number,
        preview.truncated and !withheld,
        preview.line_len,
        if (withheld) 0 else preview.window_start,
        if (withheld) null else config.replacement,
    );
    releaseQueue(state);
    state.last_line_visited = line.end;
    state.last_abs_end = state.abs_base + line.end;
    state.remembered_until = @max(state.remembered_until, line.end);
    if (kind == .after and state.after_left > 0) state.after_left -= 1;
    state.has_sunk = true;
    if (!keep) noteRejected(S, state, sink);
    return keep and !state.paused;
}

pub fn sinkBreakAt(
    comptime S: type,
    sink: *S,
    line_abs: u64,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    if (config.passthru) return true;
    const any_context = beforeCount(config) > 0 or afterCount(config) > 0;
    if (!any_context or !state.has_sunk or line_abs <= state.last_abs_end) return true;
    const keep = callOpt(S, "contextBreak", sink, .{});
    if (!keep) noteRejected(S, state, sink);
    return keep and !state.paused;
}


pub fn spanFrom(buf: []const u8, line: Range, content_end: usize, known: ?BufMatch) ?Span {
    const m = known orelse return null;
    _ = buf;
    if (m.start < line.start or m.start > content_end) return null;
    return .{
        .start = m.start - line.start,
        .end = @min(m.end, content_end) - line.start,
        .pattern_id = m.pattern_id,
    };
}

