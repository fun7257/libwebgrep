//! Vectorized prefilter over adjacent byte pairs.
//!
//! For each pattern of length at least 2, selects the rarest byte and its rarer immediate neighbor.
//! When the total number of distinct `(offset_direction, anchor, partner)` rules is at most 16,
//! `@Vector` compares both bytes simultaneously.
//! Single-byte anchors would stop on common letters; a byte pair defers verification until a likely hit.
//! Because per-pair vector arithmetic can grow large, adjacent byte pairs are hashed into a single byte
//! and compared against a small set of buckets when more than 2 rules exist, followed by exact verification on a hit.
//! False positives are acceptable; false negatives are not.
//! Allocates a small pattern-indexed table at construction time; searches do not allocate.
//! When rules exceed capacity, or when any pattern is empty or single-byte, the caller falls back to Teddy or Aho-Corasick.

const std = @import("std");
const ascii = @import("ascii.zig");
const frequency = @import("frequency.zig");
const matcher = @import("../matcher.zig");
const memchr = @import("memchr.zig");

const width = memchr.native_width;
const max_rules: u8 = 16;
const windows: usize = 4;
const fp_windows: usize = 8;

const Rule = struct {
    anchor: u8,
    partner: u8,
};

const Item = struct {
    offset: u32,
    id: u32,
};

const Span = struct {
    begin: u32 = 0,
    count: u32 = 0,
};

const Cand = struct {
    start: usize,
    end: usize,
    id: u32,
};

pub const Engine = struct {
    patterns: []const []const u8,
    ignore_case: bool,
    min_len: u32,
    max_off: u32,
    npos: u8,
    nneg: u8,
    pos_rules: [max_rules]Rule,
    neg_rules: [max_rules]Rule,
    spans: [256]Span,
    items: []Item,
    allocator: std.mem.Allocator,

    /// Returns an engine when all patterns can be covered by at most 16 adjacent-pair rules, or null otherwise.
    pub fn create(
        allocator: std.mem.Allocator,
        patterns: []const []const u8,
        ignore: bool,
    ) error{OutOfMemory}!?Engine {
        if (patterns.len == 0) return null;
        if (ignore) return build(allocator, patterns, true);
        return build(allocator, patterns, false);
    }

    fn build(
        allocator: std.mem.Allocator,
        patterns: []const []const u8,
        comptime ignore: bool,
    ) error{OutOfMemory}!?Engine {
        var pos_rules: [max_rules]Rule = undefined;
        var neg_rules: [max_rules]Rule = undefined;
        var npos: u8 = 0;
        var nneg: u8 = 0;
        var min_len: u32 = std.math.maxInt(u32);
        var max_off: u32 = 0;
        var counts: [256]u32 = @splat(0);
        for (patterns) |pat| {
            if (pat.len < 2) return null;
            const pick = rarest(ignore, pat);
            const side = neighbor(pat, pick.offset);
            if (!addForms(ignore, &pos_rules, &npos, &neg_rules, &nneg, pat[pick.offset], side.byte, side.delta)) return null;
            counts[pick.byte] += 1;
            min_len = @min(min_len, @as(u32, @intCast(pat.len)));
            max_off = @max(max_off, pick.offset);
        }

        var spans: [256]Span = @splat(.{});
        var cursor: u32 = 0;
        for (counts, 0..) |count, byte| {
            spans[byte] = .{ .begin = cursor, .count = count };
            cursor += count;
        }
        const items = try allocator.alloc(Item, patterns.len);
        errdefer allocator.free(items);
        var placed: [256]u32 = @splat(0);
        for (patterns, 0..) |pat, id_usize| {
            const pick = rarest(ignore, pat);
            const index = spans[pick.byte].begin + placed[pick.byte];
            items[index] = .{ .offset = pick.offset, .id = @intCast(id_usize) };
            placed[pick.byte] += 1;
        }
        return .{
            .patterns = patterns,
            .ignore_case = ignore,
            .min_len = min_len,
            .max_off = max_off,
            .npos = npos,
            .nneg = nneg,
            .pos_rules = pos_rules,
            .neg_rules = neg_rules,
            .spans = spans,
            .items = items,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Engine) void {
        self.allocator.free(self.items);
        self.* = undefined;
    }

    pub fn find(self: *const Engine, haystack: []const u8, start: usize, mode: matcher.MatchMode) ?matcher.Match {
        return self.findInner(haystack, start, mode, false, undefined);
    }

    pub fn findWatchingNul(
        self: *const Engine,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        nul_out: *?usize,
    ) ?matcher.Match {
        return self.findInner(haystack, start, mode, true, nul_out);
    }

    fn findInner(
        self: *const Engine,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        comptime watch_nul: bool,
        nul_out: *?usize,
    ) ?matcher.Match {
        if (start > haystack.len) return null;
        var best: ?Cand = null;
        var pos = start;
        var nul_checked: usize = start;
        while (pos < haystack.len) {
            // Adjacent pairs are rare. Bound the scan once a match is confirmed so line-by-line callers do not rescan the rest of the buffer.
            const limit = anchorLimit(haystack.len, pos, start, self.max_off, self.min_len, mode, best) orelse break;
            const at = self.findCandidate(haystack, pos, limit, watch_nul, &nul_checked, nul_out) orelse break;
            if (watch_nul and nul_out.* != null) break;
            self.note(haystack, at, start, mode, &best);
            pos = at + 1;
        }
        if (watch_nul) {
            if (nul_out.*) |nul_at| {
                if (best) |chosen| {
                    if (chosen.start <= nul_at) {
                        nul_out.* = null;
                        return .{ .start = chosen.start, .end = chosen.end };
                    }
                }
                return null;
            }
        }
        const chosen = best orelse {
            if (watch_nul and nul_checked < haystack.len) {
                if (memchr.find(width, haystack, nul_checked, 0)) |at| nul_out.* = at;
            }
            return null;
        };
        if (watch_nul and nul_checked < chosen.start) {
            if (memchr.find(width, haystack[0..chosen.start], nul_checked, 0)) |at| {
                nul_out.* = at;
                return null;
            }
        }
        return .{ .start = chosen.start, .end = chosen.end };
    }

    /// Scans to the end of the text before any hit is found; once a match exists, bounds how far right an anchor can still improve the result.
    fn anchorLimit(
        hay_len: usize,
        pos: usize,
        start: usize,
        max_off: u32,
        min_len: u32,
        mode: matcher.MatchMode,
        best: ?Cand,
    ) ?usize {
        const chosen = best orelse return hay_len;
        const back: usize = max_off;
        switch (mode) {
            .leftmost_first => {
                const last = chosen.start + back;
                if (pos > last) return null;
                return @min(hay_len, last + 1);
            },
            .earliest => {
                const earliest_start = if (pos > back) pos - back else 0;
                if (@max(earliest_start, start) + @as(usize, min_len) > chosen.end) return null;
                const last = (chosen.end - @as(usize, min_len)) + back;
                if (pos > last) return null;
                return @min(hay_len, last + 1);
            },
        }
    }

    fn findCandidate(
        self: *const Engine,
        hay: []const u8,
        pos: usize,
        limit: usize,
        comptime watch_nul: bool,
        nul_checked: *usize,
        nul_out: *?usize,
    ) ?usize {
        const end = @min(limit, hay.len);
        if (pos >= end) return null;
        const back: usize = if (self.nneg != 0) 1 else 0;
        const fwd: usize = if (self.npos != 0) 1 else 0;
        var i = pos;
        while (i < back and i < end) : (i += 1) {
            if (watch_nul and hay[i] == 0) {
                nul_out.* = i;
                return null;
            }
            if (self.hitScalar(hay, i)) {
                if (watch_nul and i + 1 > nul_checked.*) nul_checked.* = i + 1;
                return i;
            }
        }
        if (self.scan(hay, &i, end, fwd, watch_nul, nul_checked, nul_out)) |at| return at;
        if (watch_nul and nul_out.* != null) return null;
        while (i < end) : (i += 1) {
            if (watch_nul and hay[i] == 0) {
                nul_out.* = i;
                return null;
            }
            if (self.hitScalar(hay, i)) {
                if (watch_nul and i + 1 > nul_checked.*) nul_checked.* = i + 1;
                return i;
            }
        }
        if (watch_nul and end > nul_checked.*) nul_checked.* = end;
        return null;
    }

    /// Compares vectors directly when there are at most 2 forward byte pairs, avoiding shift-add hashing;
    /// uses hash buckets for up to 8 buckets, and falls back to per-pair comparisons beyond that.
    noinline fn scan(
        self: *const Engine,
        hay: []const u8,
        i: *usize,
        end: usize,
        fwd: usize,
        comptime watch_nul: bool,
        nul_checked: *usize,
        nul_out: *?usize,
    ) ?usize {
        if (self.collectDirect()) |direct| {
            switch (direct.n) {
                inline 1...2 => |n| return self.scanDirect(hay, i, end, &direct.rules, n, watch_nul, nul_checked, nul_out),
                else => {},
            }
        }
        if (self.collectBuckets()) |pack| {
            switch (pack.n) {
                inline 1...8 => |n| return self.scanBuckets(hay, i, end, &pack.bytes, n, watch_nul, nul_checked, nul_out),
                else => {},
            }
        }
        @setEvalBranchQuota(4000);
        switch (self.npos) {
            inline 0...8 => |npos| switch (self.nneg) {
                inline 0...4 => |nneg| return scanFixed(self, hay, i, end, fwd, npos, nneg),
                else => return scanSlow(self, hay, i, end, fwd),
            },
            else => return scanSlow(self, hay, i, end, fwd),
        }
    }

    noinline fn scanDirect(
        self: *const Engine,
        hay: []const u8,
        i: *usize,
        end: usize,
        rules: *const [2]Rule,
        comptime n: u8,
        comptime watch_nul: bool,
        nul_checked: *usize,
        nul_out: *?usize,
    ) ?usize {
        const V = @Vector(width, u8);
        const zero: V = @splat(0);
        var f_splat: [n]V = undefined;
        var s_splat: [n]V = undefined;
        inline for (0..n) |k| {
            f_splat[k] = @splat(rules[k].anchor);
            s_splat[k] = @splat(rules[k].partner);
        }
        var at = i.*;
        const stride = width * fp_windows;
        while (at + stride + 1 <= hay.len and at + stride <= end) {
            var m0: [fp_windows]@Vector(width, bool) = undefined;
            inline for (0..fp_windows) |w| {
                const base = at + w * width;
                const v0: V = hay[base..][0..width].*;
                var m: @Vector(width, bool) = (v0 == f_splat[0]);
                if (comptime n > 1) m = m | (v0 == f_splat[1]);
                if (watch_nul) m = m | (v0 == zero);
                m0[w] = m;
            }
            const lo4 = (m0[0] | m0[1]) | (m0[2] | m0[3]);
            const hi4 = (m0[4] | m0[5]) | (m0[6] | m0[7]);
            if (!@reduce(.Or, lo4 | hi4)) {
                at += stride;
                if (watch_nul and at > nul_checked.*) nul_checked.* = at;
                continue;
            }
            inline for (0..fp_windows) |w| {
                if (@reduce(.Or, m0[w])) {
                    const base = at + w * width;
                    const v0: V = hay[base..][0..width].*;
                    const v1: V = hay[base + 1 ..][0..width].*;
                    var m: @Vector(width, bool) = (v0 == f_splat[0]) & (v1 == s_splat[0]);
                    if (comptime n > 1) m = m | ((v0 == f_splat[1]) & (v1 == s_splat[1]));
                    const z = if (watch_nul) (v0 == zero) else @as(@Vector(width, bool), @splat(false));
                    if (@reduce(.Or, m | z)) {
                        if (self.verifySpan(hay, base, end)) |found| {
                            if (watch_nul) {
                                if (memchr.find(width, hay[0 .. found + 1], nul_checked.*, 0)) |nul_at| {
                                    nul_out.* = nul_at;
                                    return null;
                                }
                                if (found + 1 > nul_checked.*) nul_checked.* = found + 1;
                            }
                            i.* = found;
                            return found;
                        }
                        if (watch_nul and @reduce(.Or, z)) {
                            nul_out.* = base + @as(usize, std.simd.firstTrue(z).?);
                            return null;
                        }
                    }
                }
                if (watch_nul and at + (w + 1) * width > nul_checked.*) nul_checked.* = at + (w + 1) * width;
            }
            at += stride;
        }
        while (at + width + 1 <= hay.len and at + width <= end) {
            const v0: V = hay[at..][0..width].*;
            const v1: V = hay[at + 1 ..][0..width].*;
            var m: @Vector(width, bool) = @splat(false);
            inline for (0..n) |k| m = m | ((v0 == f_splat[k]) & (v1 == s_splat[k]));
            const z = if (watch_nul) (v0 == zero) else @as(@Vector(width, bool), @splat(false));
            if (@reduce(.Or, m | z)) {
                if (self.verifySpan(hay, at, end)) |found| {
                    if (watch_nul) {
                        if (memchr.find(width, hay[0 .. found + 1], nul_checked.*, 0)) |nul_at| {
                            nul_out.* = nul_at;
                            return null;
                        }
                        if (found + 1 > nul_checked.*) nul_checked.* = found + 1;
                    }
                    i.* = found;
                    return found;
                }
                if (watch_nul and @reduce(.Or, z)) {
                    nul_out.* = at + @as(usize, std.simd.firstTrue(z).?);
                    return null;
                }
            }
            at += width;
            if (watch_nul and at > nul_checked.*) nul_checked.* = at;
        }
        i.* = at;
        return null;
    }

    /// `h = first + (second << 7)`. Every rule's hash is placed in a bucket, so no match can be missed.
    /// Negative-offset rules hash the forward byte pair formed by the preceding byte and the anchor.
    noinline fn scanBuckets(
        self: *const Engine,
        hay: []const u8,
        i: *usize,
        end: usize,
        buckets: *const [8]u8,
        comptime n: u8,
        comptime watch_nul: bool,
        nul_checked: *usize,
        nul_out: *?usize,
    ) ?usize {
        const V = @Vector(width, u8);
        var splats: [n]V = undefined;
        inline for (0..n) |k| splats[k] = @splat(buckets[k]);
        var at = i.*;
        const stride = width * fp_windows;
        while (at + stride + 1 <= hay.len and at + stride <= end) {
            var acc: @Vector(width, bool) = @splat(false);
            inline for (0..fp_windows) |w| {
                acc = acc | fpWindow(n, hay, at + w * width, &splats, watch_nul);
            }
            if (!@reduce(.Or, acc)) {
                at += stride;
                if (watch_nul and at > nul_checked.*) nul_checked.* = at;
                continue;
            }
            inline for (0..fp_windows) |w| {
                const base = at + w * width;
                if (@reduce(.Or, fpWindow(n, hay, base, &splats, watch_nul))) {
                    if (self.verifySpan(hay, base, end)) |found| {
                        if (watch_nul) {
                            if (memchr.find(width, hay[0 .. found + 1], nul_checked.*, 0)) |nul_at| {
                                nul_out.* = nul_at;
                                return null;
                            }
                            if (found + 1 > nul_checked.*) nul_checked.* = found + 1;
                        }
                        i.* = found;
                        return found;
                    }
                    if (watch_nul) {
                        const v0: V = hay[base..][0..width].*;
                        const z = v0 == @as(V, @splat(0));
                        if (@reduce(.Or, z)) {
                            nul_out.* = base + @as(usize, std.simd.firstTrue(z).?);
                            return null;
                        }
                    }
                }
                if (watch_nul and base + width > nul_checked.*) nul_checked.* = base + width;
            }
            at += stride;
        }
        while (at + width + 1 <= hay.len and at + width <= end) {
            if (@reduce(.Or, fpWindow(n, hay, at, &splats, watch_nul))) {
                if (self.verifySpan(hay, at, end)) |found| {
                    if (watch_nul) {
                        if (memchr.find(width, hay[0 .. found + 1], nul_checked.*, 0)) |nul_at| {
                            nul_out.* = nul_at;
                            return null;
                        }
                        if (found + 1 > nul_checked.*) nul_checked.* = found + 1;
                    }
                    i.* = found;
                    return found;
                }
                if (watch_nul) {
                    const v0: V = hay[at..][0..width].*;
                    const z = v0 == @as(V, @splat(0));
                    if (@reduce(.Or, z)) {
                        nul_out.* = at + @as(usize, std.simd.firstTrue(z).?);
                        return null;
                    }
                }
            }
            at += width;
            if (watch_nul and at > nul_checked.*) nul_checked.* = at;
        }
        i.* = at;
        return null;
    }

    fn verifySpan(self: *const Engine, hay: []const u8, at: usize, end: usize) ?usize {
        const stop = @min(at + width, end);
        var j = at;
        while (j < stop) : (j += 1) {
            if (self.hitScalar(hay, j)) return j;
        }
        // A negative-offset anchor may land on the first byte past the window while its forward digram hash was in the current window.
        if (self.nneg != 0) {
            const edge = at + width;
            if (edge < end and edge < hay.len and self.hitScalar(hay, edge)) return edge;
        }
        return null;
    }

    fn collectDirect(self: *const Engine) ?struct { n: u8, rules: [2]Rule } {
        var rules: [2]Rule = undefined;
        var n: u8 = 0;
        for (self.pos_rules[0..self.npos]) |rule| {
            if (!noteDirect(&rules, &n, rule.anchor, rule.partner)) return null;
        }
        for (self.neg_rules[0..self.nneg]) |rule| {
            if (!noteDirect(&rules, &n, rule.partner, rule.anchor)) return null;
        }
        if (n == 0) return null;
        return .{ .n = n, .rules = rules };
    }

    fn collectBuckets(self: *const Engine) ?struct { n: u8, bytes: [8]u8 } {
        var bytes: [8]u8 = undefined;
        var n: u8 = 0;
        for (self.pos_rules[0..self.npos]) |rule| {
            if (!noteBucket(&bytes, &n, digramHash(rule.anchor, rule.partner))) return null;
        }
        for (self.neg_rules[0..self.nneg]) |rule| {
            if (!noteBucket(&bytes, &n, digramHash(rule.partner, rule.anchor))) return null;
        }
        if (n == 0) return null;
        return .{ .n = n, .bytes = bytes };
    }

    noinline fn scanFixed(
        self: *const Engine,
        hay: []const u8,
        i: *usize,
        end: usize,
        fwd: usize,
        comptime npos: u8,
        comptime nneg: u8,
    ) ?usize {
        const V = @Vector(width, u8);
        const Pos = struct { anchor: V, partner: V };
        var pos_rules: [if (npos == 0) 1 else npos]Pos = undefined;
        if (comptime npos != 0) {
            inline for (0..npos) |k| {
                const rule = self.pos_rules[k];
                pos_rules[k] = .{ .anchor = @splat(rule.anchor), .partner = @splat(rule.partner) };
            }
        }
        var neg_rules: [if (nneg == 0) 1 else nneg]Pos = undefined;
        if (comptime nneg != 0) {
            inline for (0..nneg) |k| {
                const rule = self.neg_rules[k];
                neg_rules[k] = .{ .anchor = @splat(rule.anchor), .partner = @splat(rule.partner) };
            }
        }
        const need = width + fwd;
        if (hay.len < need or end < width) return null;
        const max_i = @min(hay.len - need, end - width);
        var at = i.*;
        if (at > max_i) return null;
        const group = width * (windows - 1);
        if (at <= max_i and max_i - at >= group) {
            const fence = max_i - group;
            while (at <= fence) {
                var acc: @Vector(width, bool) = @splat(false);
                inline for (0..windows) |w| {
                    acc = acc | windowHits(hay, at + w * width, &pos_rules, &neg_rules, npos, nneg);
                }
                if (!@reduce(.Or, acc)) {
                    at += width * windows;
                    continue;
                }
                inline for (0..windows) |w| {
                    const base = at + w * width;
                    if (firstTrue(windowHits(hay, base, &pos_rules, &neg_rules, npos, nneg))) |rel| {
                        const found = base + rel;
                        i.* = found;
                        return found;
                    }
                }
                at += width * windows;
            }
        }
        while (at <= max_i) {
            if (firstTrue(windowHits(hay, at, &pos_rules, &neg_rules, npos, nneg))) |rel| {
                @branchHint(.unlikely);
                const found = at + rel;
                i.* = found;
                return found;
            }
            at += width;
        }
        i.* = at;
        return null;
    }

    noinline fn scanSlow(self: *const Engine, hay: []const u8, i: *usize, end: usize, fwd: usize) ?usize {
        const V = @Vector(width, u8);
        const need = width + fwd;
        if (hay.len < need or end < width) return null;
        const max_i = @min(hay.len - need, end - width);
        var at = i.*;
        if (at > max_i) return null;
        while (at <= max_i) {
            const v0: V = hay[at..][0..width].*;
            var hits: @Vector(width, bool) = @splat(false);
            if (self.npos != 0) {
                const plus: V = hay[at + 1 ..][0..width].*;
                var k: usize = 0;
                while (k < self.npos) : (k += 1) {
                    const rule = self.pos_rules[k];
                    hits = hits | ((v0 == @as(V, @splat(rule.anchor))) & (plus == @as(V, @splat(rule.partner))));
                }
            }
            if (self.nneg != 0) {
                const minus: V = hay[at - 1 ..][0..width].*;
                var k: usize = 0;
                while (k < self.nneg) : (k += 1) {
                    const rule = self.neg_rules[k];
                    hits = hits | ((v0 == @as(V, @splat(rule.anchor))) & (minus == @as(V, @splat(rule.partner))));
                }
            }
            if (firstTrue(hits)) |rel| {
                @branchHint(.unlikely);
                const found = at + rel;
                i.* = found;
                return found;
            }
            at += width;
        }
        i.* = at;
        return null;
    }

    fn hitScalar(self: *const Engine, hay: []const u8, i: usize) bool {
        const anchor = hay[i];
        if (sideHit(self.pos_rules[0..self.npos], hay, i, anchor, 1)) return true;
        if (sideHit(self.neg_rules[0..self.nneg], hay, i, anchor, -1)) return true;
        return false;
    }

    fn note(
        self: *const Engine,
        hay: []const u8,
        at: usize,
        start: usize,
        mode: matcher.MatchMode,
        best: *?Cand,
    ) void {
        if (self.ignore_case) {
            confirm(self, hay, at, start, mode, best, true);
        } else {
            confirm(self, hay, at, start, mode, best, false);
        }
    }
};

fn confirm(
    self: *const Engine,
    hay: []const u8,
    at: usize,
    start: usize,
    mode: matcher.MatchMode,
    best: *?Cand,
    comptime ignore: bool,
) void {
    const key = if (ignore) ascii.fold(hay[at]) else hay[at];
    const span = self.spans[key];
    const list = self.items[span.begin..][0..span.count];
    for (list) |item| {
        if (at < item.offset) continue;
        const begin = at - @as(usize, item.offset);
        if (begin < start) continue;
        const pat = self.patterns[item.id];
        if (begin > hay.len or pat.len > hay.len - begin) continue;
        if (!equalAt(pat, hay[begin..][0..pat.len], ignore)) continue;
        consider(best, begin, begin + pat.len, item.id, mode);
    }
}

fn digramHash(first: u8, second: u8) u8 {
    return first +% @as(u8, @truncate(@as(u16, second) << 7));
}

fn noteBucket(bytes: *[8]u8, n: *u8, hash: u8) bool {
    for (bytes[0..n.*]) |have| if (have == hash) return true;
    if (n.* == 8) return false;
    bytes[n.*] = hash;
    n.* += 1;
    return true;
}

fn noteDirect(rules: *[2]Rule, n: *u8, first: u8, second: u8) bool {
    for (rules[0..n.*]) |have| if (have.anchor == first and have.partner == second) return true;
    if (n.* == 2) return false;
    rules[n.*] = .{ .anchor = first, .partner = second };
    n.* += 1;
    return true;
}

fn fpWindow(comptime n: u8, hay: []const u8, at: usize, splats: *const [n]@Vector(width, u8), comptime watch_nul: bool) @Vector(width, bool) {
    const V = @Vector(width, u8);
    const v0: V = hay[at..][0..width].*;
    const v1: V = hay[at + 1 ..][0..width].*;
    const h = v0 +% (v1 << @as(V, @splat(@as(u8, 7))));
    var hits: @Vector(width, bool) = @splat(false);
    inline for (0..n) |k| hits = hits | (h == splats[k]);
    if (watch_nul) hits = hits | (v0 == @as(V, @splat(@as(u8, 0))));
    return hits;
}

fn addForms(
    comptime ignore: bool,
    pos_rules: *[max_rules]Rule,
    npos: *u8,
    neg_rules: *[max_rules]Rule,
    nneg: *u8,
    anchor: u8,
    partner: u8,
    delta: i8,
) bool {
    const rules = if (delta == 1) pos_rules else neg_rules;
    const n = if (delta == 1) npos else nneg;
    if (ignore) {
        const anchors = ascii.caseVariants(anchor);
        const partners = ascii.caseVariants(partner);
        for (anchors) |a| {
            for (partners) |b| {
                if (!pushRule(rules, n, npos, nneg, a, b)) return false;
            }
        }
        return true;
    }
    return pushRule(rules, n, npos, nneg, anchor, partner);
}

fn pushRule(
    rules: *[max_rules]Rule,
    n: *u8,
    npos: *u8,
    nneg: *u8,
    anchor: u8,
    partner: u8,
) bool {
    for (rules[0..n.*]) |have| {
        if (have.anchor == anchor and have.partner == partner) return true;
    }
    if (npos.* + nneg.* == max_rules) return false;
    rules[n.*] = .{ .anchor = anchor, .partner = partner };
    n.* += 1;
    return true;
}

fn sideHit(rules: []const Rule, hay: []const u8, i: usize, anchor: u8, delta: i8) bool {
    for (rules) |rule| {
        if (rule.anchor != anchor) continue;
        const j = @as(isize, @intCast(i)) + delta;
        if (j < 0 or j >= @as(isize, @intCast(hay.len))) continue;
        if (hay[@intCast(j)] == rule.partner) return true;
    }
    return false;
}

const Pick = struct { byte: u8, offset: u32 };

fn rarest(comptime ignore: bool, pat: []const u8) Pick {
    var best_i: usize = 0;
    var best_byte: u8 = if (ignore) ascii.fold(pat[0]) else pat[0];
    var best_rank: u8 = frequency.default_rank[best_byte];
    for (pat[1..], 1..) |raw, i| {
        const byte = if (ignore) ascii.fold(raw) else raw;
        const rank = frequency.default_rank[byte];
        if (rank < best_rank) {
            best_rank = rank;
            best_byte = byte;
            best_i = i;
        }
    }
    return .{ .byte = best_byte, .offset = @intCast(best_i) };
}

fn neighbor(pat: []const u8, off: u32) struct { byte: u8, delta: i8 } {
    const i: usize = off;
    const right = i + 1 < pat.len;
    const left = i > 0;
    if (right and left) {
        const rb = pat[i + 1];
        const lb = pat[i - 1];
        if (frequency.default_rank[rb] <= frequency.default_rank[lb]) {
            return .{ .byte = rb, .delta = 1 };
        }
        return .{ .byte = lb, .delta = -1 };
    }
    if (right) return .{ .byte = pat[i + 1], .delta = 1 };
    return .{ .byte = pat[i - 1], .delta = -1 };
}

inline fn windowHits(
    hay: []const u8,
    at: usize,
    pos_rules: anytype,
    neg_rules: anytype,
    comptime npos: u8,
    comptime nneg: u8,
) @Vector(width, bool) {
    const V = @Vector(width, u8);
    const v0: V = hay[at..][0..width].*;
    const plus: V = if (comptime npos != 0) hay[at + 1 ..][0..width].* else @splat(0);
    const minus: V = if (comptime nneg != 0) hay[at - 1 ..][0..width].* else @splat(0);
    var hits: @Vector(width, bool) = @splat(false);
    if (comptime npos != 0) {
        inline for (0..npos) |k| {
            const rule = pos_rules[k];
            hits = hits | ((v0 == rule.anchor) & (plus == rule.partner));
        }
    }
    if (comptime nneg != 0) {
        inline for (0..nneg) |k| {
            const rule = neg_rules[k];
            hits = hits | ((v0 == rule.anchor) & (minus == rule.partner));
        }
    }
    return hits;
}

inline fn firstTrue(hits: @Vector(width, bool)) ?usize {
    const V = @Vector(width, u8);
    const flags: V = @select(u8, hits, @as(V, @splat(@as(u8, 0xFF))), @as(V, @splat(@as(u8, 0))));
    return memchr.indexWidth(flags);
}

fn equalAt(pat: []const u8, hay: []const u8, comptime ignore: bool) bool {
    for (pat, hay) |p, h| {
        if (ignore) {
            if (ascii.fold(p) != ascii.fold(h)) return false;
        } else if (p != h) return false;
    }
    return true;
}

fn consider(best: *?Cand, start: usize, end: usize, id: u32, mode: matcher.MatchMode) void {
    const cand = Cand{ .start = start, .end = end, .id = id };
    if (best.*) |cur| {
        if (prefer(cand, cur, mode)) best.* = cand;
    } else best.* = cand;
}

fn prefer(a: Cand, b: Cand, mode: matcher.MatchMode) bool {
    switch (mode) {
        .earliest => {
            if (a.end != b.end) return a.end < b.end;
            if (a.start != b.start) return a.start < b.start;
            return a.id < b.id;
        },
        .leftmost_first => {
            if (a.start != b.start) return a.start < b.start;
            return a.id < b.id;
        },
    }
}

test "adjacent pairs match automaton at the same position" {
    const alloc = std.testing.allocator;
    const pats = [_][]const u8{ "abcdef", "de", "xxqz", "alpha" };
    var engine = (try Engine.create(alloc, &pats, false)).?;
    defer engine.deinit();
    const hay = "....abcdef....de..xxqz..alpha";
    const left = engine.find(hay, 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 4), left.start);
    try std.testing.expectEqual(@as(usize, 10), left.end);
    const early = engine.find(hay, 0, .earliest).?;
    try std.testing.expectEqual(@as(usize, 7), early.start);
    try std.testing.expectEqual(@as(usize, 9), early.end);

    var folded = (try Engine.create(alloc, &.{ "AbC", "zzz" }, true)).?;
    defer folded.deinit();
    const hit = folded.find("xxabcYY", 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 2), hit.start);
    try std.testing.expectEqual(@as(usize, 5), hit.end);

    var wide_buf: [17][2]u8 = undefined;
    var wide: [17][]const u8 = undefined;
    for (&wide_buf, 0..) |*slot, i| {
        slot[0] = @intCast(32 + i);
        slot[1] = @intCast(160 + i);
        wide[i] = slot;
    }
    try std.testing.expect(try Engine.create(alloc, &wide, false) == null);
}

test "adjacent pairs in long text, including window boundaries" {
    const alloc = std.testing.allocator;
    var buf: [200]u8 = undefined;
    @memset(&buf, 'x');
    // For "lp", the rarer byte is 'p', placing the anchor on the first byte after the window boundary.
    buf[16] = 'l';
    buf[17] = 'p';
    buf[100] = 'b';
    buf[101] = 'e';
    var engine = (try Engine.create(alloc, &.{ "lp", "be" }, false)).?;
    defer engine.deinit();
    const first = engine.find(&buf, 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 16), first.start);
    try std.testing.expectEqual(@as(usize, 18), first.end);
    const second = engine.find(&buf, first.end, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 100), second.start);
    try std.testing.expectEqual(@as(usize, 102), second.end);
}
