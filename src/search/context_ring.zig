//! [Module] search/context_ring.zig
//! [Layer] Layer 4 — Bounded Before-Context Circular Ring & Line Window Preview
//! [Role] Implements `BeforeRing` for seek-free `before` context buffering and `previewLine` / `windowOrigin`
//!        for centering truncated line previews around matches.
//! [Invariants]
//!   1. `BeforeRing` capacity is strictly bounded by `SearchConfig.context_lines_hard_cap` and `max_before_bytes`.
//!   2. When searching an in-memory slice, `BeforeRing` borrows slice ranges with zero copying (`owned = false`).
//! [HotPath] `rememberBefore`, `previewLine`, `emitRing`.

const std = @import("std");
const cfg_mod = @import("config.zig");
const state_mod = @import("state.zig");
const format_mod = @import("format.zig");
const line_matcher_mod = @import("line_matcher.zig");

const SearchConfig = cfg_mod.SearchConfig;
const SliceError = cfg_mod.SliceError;
const Span = cfg_mod.Span;
const Range = state_mod.Range;
const BufMatch = state_mod.BufMatch;
const State = state_mod.State;
const contentEnd = state_mod.contentEnd;
const nextLine = state_mod.nextLine;
const countLines = state_mod.countLines;
const guardLine = state_mod.guardLine;
const releaseQueue = state_mod.releaseQueue;
const noteRejected = state_mod.noteRejected;
const spanFrom = format_mod.spanFrom;
const sinkBreakAt = format_mod.sinkBreakAt;
const sinkLine = format_mod.sinkLine;
const matchInLine = line_matcher_mod.matchInLine;

pub const Preview = struct {
    start: usize,
    end: usize,
    truncated: bool,
    line_len: u64,
    window_start: u64,
    span: ?Span,
};

/// Center the window around the match when possible; if the match exceeds the limit, start at the match start.
pub fn windowOrigin(raw: usize, limit: usize, match_at: usize, match_end: usize) usize {
    if (limit == 0 or raw <= limit) return 0;
    const mend = @min(match_end, raw);
    const mstart = @min(match_at, mend);
    const mlen = mend - mstart;
    if (mlen >= limit) {
        if (mstart + limit > raw) return raw - limit;
        return mstart;
    }
    const mid = mstart + mlen / 2;
    var rel: usize = if (mid > limit / 2) mid - limit / 2 else 0;
    if (rel + limit > raw) rel = raw - limit;
    if (mstart < rel) rel = mstart;
    const tail = mstart + mlen;
    if (tail > rel + limit) rel = tail - limit;
    if (rel + limit > raw) rel = raw - limit;
    return rel;
}

pub fn previewLine(buf: []const u8, line: Range, known: ?BufMatch, config: SearchConfig) Preview {
    const content_end = contentEnd(buf, line, config);
    const raw = content_end - line.start;
    const limit = config.max_line_len;
    if (limit == 0 or raw <= limit) {
        return .{
            .start = line.start,
            .end = content_end,
            .truncated = false,
            .line_len = raw,
            .window_start = 0,
            .span = spanFrom(buf, line, content_end, known),
        };
    }
    var rel: usize = 0;
    if (known) |m| {
        const at = if (m.start > line.start) m.start - line.start else 0;
        const mend = if (m.end > line.start) @min(m.end - line.start, raw) else at;
        rel = windowOrigin(raw, limit, at, mend);
    }
    const win_end = rel + limit;
    var span: ?Span = null;
    if (known) |m| {
        const abs_s = line.start + rel;
        const abs_e = line.start + win_end;
        if (m.start >= abs_s and m.start < abs_e) {
            span = .{
                .start = m.start - abs_s,
                .end = @min(m.end, abs_e) - abs_s,
                .pattern_id = m.pattern_id,
            };
        }
    }
    return .{
        .start = line.start + rel,
        .end = line.start + win_end,
        .truncated = true,
        .line_len = raw,
        .window_start = rel,
        .span = span,
    };
}

pub const RingSlot = struct {
    len: u32 = 0,
    abs: u64 = 0,
    end_abs: u64 = 0,
    number: ?u64 = null,
    truncated: bool = false,
    line_len: u64 = 0,
    window_start: u64 = 0,
    mstart: u32 = 0,
    mend: u32 = 0,
    mpid: ?u32 = null,
    has_match: bool = false,
    src_start: usize = 0,
    src_end: usize = 0,
};

pub const BeforeRing = struct {
    slots: [SearchConfig.context_lines_hard_cap]RingSlot = undefined,
    storage: []u8 = &.{},
    stride: usize = 0,
    cap: u32 = 0,
    count: u32 = 0,
    head: u32 = 0,
    owned: bool = false,

    pub fn clear(self: *BeforeRing) void {
        self.count = 0;
        self.head = 0;
    }

    pub fn index(self: *const BeforeRing, oldest_i: u32) u32 {
        return (self.head + self.cap - self.count + oldest_i) % self.cap;
    }

    pub fn push(self: *BeforeRing, buf: []const u8, preview: Preview, abs: u64, end_abs: u64, number: ?u64) void {
        const slice = if (preview.end >= preview.start) buf[preview.start..preview.end] else buf[0..0];
        self.pushBytes(slice, preview, abs, end_abs, number);
    }

    pub fn pushBytes(self: *BeforeRing, slice: []const u8, preview: Preview, abs: u64, end_abs: u64, number: ?u64) void {
        if (self.cap == 0) return;
        const idx = self.head;
        if (self.count < self.cap) self.count += 1;
        const len = slice.len;
        self.slots[idx] = .{
            .len = std.math.cast(u32, len) orelse std.math.maxInt(u32),
            .abs = abs,
            .end_abs = end_abs,
            .number = number,
            .truncated = preview.truncated,
            .line_len = preview.line_len,
            .window_start = preview.window_start,
            .has_match = preview.span != null,
            .mstart = if (preview.span) |s| std.math.cast(u32, s.start) orelse 0 else 0,
            .mend = if (preview.span) |s| std.math.cast(u32, s.end) orelse 0 else 0,
            .mpid = if (preview.span) |s| s.pattern_id else null,
            .src_start = preview.start,
            .src_end = preview.end,
        };
        if (self.owned and self.stride > 0 and len > 0) {
            const at = @as(usize, idx) * self.stride;
            const n = @min(len, self.stride);
            @memcpy(self.storage[at..][0..n], slice[0..n]);
            self.slots[idx].len = std.math.cast(u32, n) orelse 0;
        }
        self.head = (self.head + 1) % self.cap;
    }

    pub fn bytes(self: *const BeforeRing, idx: u32, buf: []const u8) []const u8 {
        const slot = self.slots[idx];
        if (self.owned) {
            if (self.stride == 0 or slot.len == 0) return &.{};
            const at = @as(usize, idx) * self.stride;
            return self.storage[at..][0..slot.len];
        }
        if (slot.src_end < slot.src_start or slot.src_end > buf.len) return &.{};
        return buf[slot.src_start..slot.src_end];
    }
};

pub fn rememberBefore(matcher: anytype, buf: []const u8, state: *State, config: SearchConfig, upto: usize) void {
    const limit_end = @min(upto, buf.len);
    if (state.ring.cap == 0) {
        state.remembered_until = @max(state.remembered_until, limit_end);
        return;
    }
    var cursor = @max(state.remembered_until, state.last_line_visited);
    if (cursor > limit_end) cursor = limit_end;
    while (nextLine(buf, cursor, limit_end, config)) |line| {
        if (line.end <= state.last_line_visited) {
            cursor = line.end;
            continue;
        }
        const known = if (config.invert) matchInLine(matcher, buf, line, config) else null;
        const preview = previewLine(buf, line, known, config);
        countLines(buf, line.start, state, config);
        state.ring.push(buf, preview, state.abs_base + line.start, state.abs_base + line.end, state.line_number);
        cursor = line.end;
    }
    state.remembered_until = limit_end;
}

pub fn emitRing(
    comptime S: type,
    sink: *S,
    buf: []const u8,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    var i: u32 = 0;
    while (i < state.ring.count) : (i += 1) {
        const idx = state.ring.index(i);
        const slot = state.ring.slots[idx];
        if (!try sinkBreakAt(S, sink, slot.abs, state, config)) {
            state.ring.clear();
            return false;
        }
        const raw = state.ring.bytes(idx, buf);
        const withheld = config.binary == .report and state.nul_offset != null;
        const span: ?Span = if (withheld or !slot.has_match) null else .{
            .start = slot.mstart,
            .end = slot.mend,
            .pattern_id = slot.mpid,
        };
        var none: [0]Span = .{};
        const shown = if (withheld) raw[0..0] else raw;
        if (!try guardLine(state, config, shown.len)) {
            state.ring.clear();
            return false;
        }
        const keep = sinkLine(
            S,
            "context",
            sink,
            state,
            shown,
            span,
            &none,
            slot.abs,
            slot.number,
            slot.truncated and !withheld,
            slot.line_len,
            if (withheld) 0 else slot.window_start,
            if (withheld) null else config.replacement,
        );
        releaseQueue(state);
        state.last_abs_end = slot.end_abs;
        state.has_sunk = true;
        if (!keep) {
            noteRejected(S, state, sink);
            state.ring.clear();
            return false;
        }
    }
    state.ring.clear();
    return true;
}

