//! Prefilters using two rare bytes, then verifies candidate spans in full.
//! Patterns must be at least two bytes; single-byte patterns use memchr and are not handled here.
//!
//! The hot path uses generic SIMD (Wojciech Muła's generic SIMD algorithm, also used by
//! memchr's packed pair): each vector compares bytes at two offsets simultaneously and ANDs their masks.
//! The loop exits SIMD only when both bytes hit together. Even if individual bytes are common,
//! as long as their relative offset does not match, execution stays entirely within vector instructions.

const builtin = @import("builtin");
const std = @import("std");
const ascii = @import("ascii.zig");

/// Up to this length, packed pair completes the search itself without handing the remaining input to Two-Way.
/// False positives multiplied by at most a 32-byte comparison still run in constant-factor linear time.
/// Matches memchr's `do_packed_search` upper bound.
pub const owns_search_max_len: usize = 32;

/// Prefilter accounting for long patterns. When failed verifications skip too few bytes on average,
/// the caller should switch to Two-Way.
/// Thresholds match memchr's PrefilterState: at least 50 candidates and fewer than 8 bytes skipped per candidate on average.
pub const Guard = struct {
    candidates: u32 = 0,
    skipped: u64 = 0,
    /// Offset where Two-Way should resume after the prefilter gives up (`resume` is a reserved keyword).
    restart: usize = 0,
    gave_up: bool = false,

    const min_candidates: u32 = 50;
    const min_skip_bytes: u64 = 8;

    fn noteMiss(self: *Guard, origin: usize, previous: usize) void {
        const stride = origin - previous;
        self.candidates +|= 1;
        self.skipped +|= stride;
        if (self.candidates < min_candidates) return;
        if (self.skipped >= min_skip_bytes * @as(u64, self.candidates)) return;
        self.gave_up = true;
        self.restart = origin + 1;
    }
};

pub const PackedPair = struct {
    pattern: []const u8,
    anchor_index: usize,
    other_index: usize,
    third_index: usize,
    fourth_index: usize,
    anchor: u8,
    other: u8,
    third: u8,
    fourth: u8,
    ignore_case: bool,

    /// Smaller `rank` values indicate rarer bytes. `pattern` is owned by the caller.
    pub fn init(pattern: []const u8, rank: *const [256]u8, ignore_case: bool) PackedPair {
        std.debug.assert(pattern.len >= 2);
        var best: usize = 0;
        var second: usize = 1;
        if (rank[pattern[second]] < rank[pattern[best]]) {
            best = 1;
            second = 0;
        }
        var i: usize = 2;
        while (i < pattern.len) : (i += 1) {
            const r = rank[pattern[i]];
            if (r < rank[pattern[best]]) {
                second = best;
                best = i;
            } else if (r < rank[pattern[second]]) {
                second = i;
            } else if (r == rank[pattern[second]]) {
                const cur_dist = if (second > best) second - best else best - second;
                const new_dist = if (i > best) i - best else best - i;
                if (new_dist > cur_dist) {
                    second = i;
                }
            }
        }
        var third_idx: usize = second;
        var third_rank: u16 = 256;
        for (pattern, 0..) |b, idx| {
            if (idx == best or idx == second) continue;
            if (rank[b] < third_rank) {
                third_rank = rank[b];
                third_idx = idx;
            }
        }
        var fourth_idx: usize = third_idx;
        var fourth_rank: u16 = 256;
        for (pattern, 0..) |b, idx| {
            if (idx == best or idx == second or idx == third_idx) continue;
            if (rank[b] < fourth_rank) {
                fourth_rank = rank[b];
                fourth_idx = idx;
            }
        }
        return .{
            .pattern = pattern,
            .anchor_index = best,
            .other_index = second,
            .third_index = third_idx,
            .fourth_index = fourth_idx,
            .anchor = pattern[best],
            .other = pattern[second],
            .third = pattern[third_idx],
            .fourth = pattern[fourth_idx],
            .ignore_case = ignore_case,
        };
    }

    /// Finds the start of the next full match in `haystack[start..]`.
    /// When `guard` is non-null and the pattern is longer than `owns_search_max_len`, stops if the prefilter
    /// advances too slowly and records the resume offset for Two-Way in `guard`.
    pub fn find(
        self: PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        guard: ?*Guard,
    ) ?usize {
        return self.findInner(width, haystack, start, guard, false, undefined);
    }

    pub fn findWithWidth(
        self: PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        guard: ?*Guard,
    ) ?usize {
        return self.find(width, haystack, start, guard);
    }

    /// Same as `find`, while also checking already-loaded vectors for NUL bytes.
    /// If a NUL is seen before a match completes, writes its offset to `nul_out` and returns null so the caller can apply its binary policy.
    /// When returning a match, guarantees no NUL precedes or lies within the matched span; bytes after the match are checked by the caller.
    pub fn findWatchingNul(
        self: PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        guard: ?*Guard,
        nul_out: *?usize,
    ) ?usize {
        return self.findInner(width, haystack, start, guard, true, nul_out);
    }

    pub fn findWatchingNulWithWidth(
        self: PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        guard: ?*Guard,
        nul_out: *?usize,
    ) ?usize {
        return self.findWatchingNul(width, haystack, start, guard, nul_out);
    }

    fn findInner(
        self: PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        guard: ?*Guard,
        comptime watch_nul: bool,
        nul_out: *?usize,
    ) ?usize {
        comptime if (width != 16 and width != 32 and width != 64) @compileError("packed pair width must be 16, 32, or 64");
        const m = self.pattern.len;
        if (m > haystack.len or start > haystack.len - m) {
            if (watch_nul and start <= haystack.len) {
                _ = noteNul(haystack[start..], start, nul_out);
            }
            return null;
        }
        const last = haystack.len - m;
        // Case folding, guard accounting, and NUL watching are specialized outside the loop so the miss loop contains only loads, comparisons, and reductions.
        if (self.ignore_case) {
            if (guard) |g| return self.findLoop(width, haystack, start, last, true, true, watch_nul, g, nul_out);
            return self.findLoop(width, haystack, start, last, true, false, watch_nul, undefined, nul_out);
        }
        if (guard) |g| return self.findLoop(width, haystack, start, last, false, true, watch_nul, g, nul_out);
        return self.findLoop(width, haystack, start, last, false, false, watch_nul, undefined, nul_out);
    }

    fn findLoop(
        self: PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        last: usize,
        comptime fold: bool,
        comptime watched: bool,
        comptime watch_nul: bool,
        guard: *Guard,
        nul_out: *?usize,
    ) ?usize {
        const max_index = @max(@max(self.anchor_index, self.other_index), @max(self.third_index, self.fourth_index));
        const cover_index = @min(self.anchor_index, self.other_index);
        // When the minimum anchor offset is non-zero, SIMD loads do not cover the leading bytes after `start`.
        if (watch_nul and cover_index > 0) {
            const prefix_end = @min(haystack.len, start + cover_index);
            if (noteNul(haystack[start..prefix_end], start, nul_out)) return null;
        }
        var origin = start;
        var previous = start;
        // Advance 4 vectors per iteration and OR their masks into a single reduction, cutting reduction and branch instructions by 75%.
        const stride = width * 4;
        while (origin <= last and origin + max_index + stride <= haystack.len) {
            var masks: [4]@Vector(width, bool) = undefined;
            inline for (0..4) |k| {
                masks[k] = hotMask(self, width, haystack, origin + k * width, fold, watch_nul);
            }
            if (@reduce(.Or, (masks[0] | masks[1]) | (masks[2] | masks[3]))) {
                @branchHint(.unlikely);
                inline for (0..4) |k| {
                    if (@reduce(.Or, masks[k])) {
                        const at = origin + k * width;
                        const rel = @call(
                            .never_inline,
                            takeHit,
                            .{ self, width, haystack, at, last, &previous, fold, watched, watch_nul, guard, nul_out },
                        );
                        if (watch_nul and nul_out.* != null) return null;
                        if (rel) |found| return at + found;
                        if (watched and guard.gave_up) return null;
                    }
                }
            }
            origin += stride;
        }
        while (origin <= last and origin + max_index + width <= haystack.len) {
            if (@reduce(.Or, hotMask(self, width, haystack, origin, fold, watch_nul))) {
                @branchHint(.unlikely);
                const rel = @call(
                    .never_inline,
                    takeHit,
                    .{ self, width, haystack, origin, last, &previous, fold, watched, watch_nul, guard, nul_out },
                );
                if (watch_nul and nul_out.* != null) return null;
                if (rel) |found| return origin + found;
                if (watched and guard.gave_up) return null;
            }
            origin += width;
        }
        const tail_hit = scalarFrom(self, haystack, origin, last, &previous, fold, watched, guard);
        if (watch_nul) {
            const from = @min(haystack.len, origin + cover_index);
            const nul_limit = if (tail_hit) |pos| @min(haystack.len, @max(from, pos + self.pattern.len)) else haystack.len;
            if (noteNul(haystack[from..nul_limit], from, nul_out)) return null;
        }
        return tail_hit;
    }
};

fn confirm(self: PackedPair, haystack: []const u8, origin: usize) bool {
    const pat = self.pattern;
    const window = haystack[origin..][0..pat.len];
    if (!self.ignore_case) return std.mem.eql(u8, pat, window);
    for (pat, window) |p, h| {
        if (!ascii.eq(p, h, true)) return false;
    }
    return true;
}

inline fn byteMask(comptime width: comptime_int, block: @Vector(width, u8), byte: u8, comptime fold: bool) @Vector(width, bool) {
    if (!fold) return block == @as(@Vector(width, u8), @splat(byte));
    const forms = ascii.caseVariants(byte);
    if (forms[0] == forms[1]) return block == @as(@Vector(width, u8), @splat(forms[0]));
    // Uppercase and lowercase ASCII letters differ only by bit 0x20; setting that bit matches the lowercase form without false positives and saves a comparison and OR.
    return (block | @as(@Vector(width, u8), @splat(0x20))) == @as(@Vector(width, u8), @splat(forms[0]));
}

/// Hit mask for both anchor bytes in this window. When `watch_nul` is enabled, ORs in the NUL mask from the covering vector.
/// The covering vector is the anchor at the smaller offset, which is already in a register and requires no extra load.
inline fn hotMask(
    self: PackedPair,
    comptime width: comptime_int,
    haystack: []const u8,
    origin: usize,
    comptime fold: bool,
    comptime watch_nul: bool,
) @Vector(width, bool) {
    const left: @Vector(width, u8) = haystack[origin + self.anchor_index ..][0..width].*;
    const right: @Vector(width, u8) = haystack[origin + self.other_index ..][0..width].*;
    const hits = byteMask(width, left, self.anchor, fold) & byteMask(width, right, self.other, fold);
    if (!watch_nul) return hits;
    const cover = if (self.anchor_index <= self.other_index) left else right;
    return hits | (cover == @as(@Vector(width, u8), @splat(0)));
}

fn noteNul(haystack: []const u8, base: usize, nul_out: *?usize) bool {
    const rel = std.mem.findScalarPos(u8, haystack, 0, 0) orelse return false;
    nul_out.* = base + rel;
    return true;
}

/// Returns the match start relative to `origin`. Outlined so verification logic stays out of the hot loop.
fn takeHit(
    self: PackedPair,
    comptime width: comptime_int,
    haystack: []const u8,
    origin: usize,
    last: usize,
    previous: *usize,
    comptime fold: bool,
    comptime watched: bool,
    comptime watch_nul: bool,
    guard: *Guard,
    nul_out: *?usize,
) ?usize {
    const cover_index = @min(self.anchor_index, self.other_index);
    const left: @Vector(width, u8) = haystack[origin + self.anchor_index ..][0..width].*;
    const right: @Vector(width, u8) = haystack[origin + self.other_index ..][0..width].*;
    var hits = byteMask(width, left, self.anchor, fold) & byteMask(width, right, self.other, fold);
    if (self.pattern.len >= 4) {
        const b3: @Vector(width, u8) = haystack[origin + self.third_index ..][0..width].*;
        const b4: @Vector(width, u8) = haystack[origin + self.fourth_index ..][0..width].*;
        hits = hits & byteMask(width, b3, self.third, fold) & byteMask(width, b4, self.fourth, fold);
    }

    if (comptime builtin.cpu.arch.endian() == .little) {
        // Little-endian bitmask extraction (`vpmovmskb` + `tzcnt` + `blsr` on x86_64 AVX2, optimal bit-scan on aarch64).
        const MaskInt = @Int(.unsigned, width);
        var mask: MaskInt = @bitCast(hits);
        while (mask != 0) : (mask &= mask - 1) {
            const rel: usize = @ctz(mask);
            const at = origin + rel;
            if (at > last) continue;
            if (confirm(self, haystack, at)) {
                if (watch_nul) {
                    const check_start = @min(haystack.len, origin + cover_index);
                    const check_end = @min(haystack.len, @max(check_start, at + self.pattern.len));
                    if (noteNul(haystack[check_start..check_end], check_start, nul_out)) return null;
                }
                return rel;
            }
            if (!watched) continue;
            guard.noteMiss(at, previous.*);
            previous.* = at + 1;
            if (guard.gave_up) {
                if (watch_nul) {
                    const block: @Vector(width, u8) = haystack[origin + cover_index ..][0..width].*;
                    const zeros = block == @as(@Vector(width, u8), @splat(0));
                    const zmask: MaskInt = @bitCast(zeros);
                    if (zmask != 0) {
                        nul_out.* = origin + cover_index + @as(usize, @ctz(zmask));
                    }
                }
                return null;
            }
        }
    } else {
        const Index = std.simd.VectorIndex(@TypeOf(hits));
        const indices = comptime std.simd.iota(Index, width);
        while (std.simd.firstTrue(hits)) |rel| {
            hits = @select(
                bool,
                indices == @as(@Vector(width, Index), @splat(rel)),
                @as(@Vector(width, bool), @splat(false)),
                hits,
            );
            const at = origin + @as(usize, rel);
            if (at > last) continue;
            if (confirm(self, haystack, at)) {
                if (watch_nul) {
                    const check_start = @min(haystack.len, origin + cover_index);
                    const check_end = @min(haystack.len, @max(check_start, at + self.pattern.len));
                    if (noteNul(haystack[check_start..check_end], check_start, nul_out)) return null;
                }
                return @as(usize, rel);
            }
            if (!watched) continue;
            guard.noteMiss(at, previous.*);
            previous.* = at + 1;
            if (guard.gave_up) {
                if (watch_nul) {
                    const block: @Vector(width, u8) = haystack[origin + cover_index ..][0..width].*;
                    const zeros = block == @as(@Vector(width, u8), @splat(0));
                    if (@reduce(.Or, zeros)) {
                        const zrel = std.simd.firstTrue(zeros).?;
                        nul_out.* = origin + cover_index + @as(usize, zrel);
                    }
                }
                return null;
            }
        }
    }

    if (watch_nul) {
        const block: @Vector(width, u8) = haystack[origin + cover_index ..][0..width].*;
        const zeros = block == @as(@Vector(width, u8), @splat(0));
        if (comptime builtin.cpu.arch.endian() == .little) {
            const MaskInt = @Int(.unsigned, width);
            const zmask: MaskInt = @bitCast(zeros);
            if (zmask != 0) {
                nul_out.* = origin + cover_index + @as(usize, @ctz(zmask));
                return null;
            }
        } else if (@reduce(.Or, zeros)) {
            const zrel = std.simd.firstTrue(zeros).?;
            nul_out.* = origin + cover_index + @as(usize, zrel);
            return null;
        }
    }
    return null;
}

inline fn scalarFrom(
    self: PackedPair,
    haystack: []const u8,
    origin: usize,
    last: usize,
    previous: *usize,
    comptime fold: bool,
    comptime watched: bool,
    guard: *Guard,
) ?usize {
    var i = origin;
    while (i <= last) : (i += 1) {
        const anchor_byte = haystack[i + self.anchor_index];
        const other_byte = haystack[i + self.other_index];
        if (!ascii.eq(anchor_byte, self.anchor, fold)) continue;
        if (!ascii.eq(other_byte, self.other, fold)) continue;
        if (confirm(self, haystack, i)) return i;
        if (!watched) continue;
        guard.noteMiss(i, previous.*);
        previous.* = i + 1;
        if (guard.gave_up) return null;
    }
    return null;
}

fn scalarFind(haystack: []const u8, pattern: []const u8, start: usize, ignore_case: bool) ?usize {
    if (pattern.len > haystack.len or start > haystack.len - pattern.len) return null;
    var i = start;
    while (i + pattern.len <= haystack.len) : (i += 1) {
        var ok = true;
        for (pattern, haystack[i..][0..pattern.len]) |p, h| {
            if (!ascii.eq(p, h, ignore_case)) {
                ok = false;
                break;
            }
        }
        if (ok) return i;
    }
    return null;
}

fn findAll(pair: PackedPair, comptime width: comptime_int, haystack: []const u8, start: usize) ?usize {
    return pair.find(width, haystack, start, null);
}

test "selects the two rarest bytes by rank" {
    var rank: [256]u8 = @splat(200);
    rank['z'] = 0;
    rank['q'] = 1;
    rank['a'] = 50;
    const pair = PackedPair.init("aqz", &rank, false);
    try std.testing.expectEqual(@as(usize, 2), pair.anchor_index);
    try std.testing.expectEqual(@as(u8, 'z'), pair.anchor);
    try std.testing.expectEqual(@as(usize, 1), pair.other_index);
    try std.testing.expectEqual(@as(u8, 'q'), pair.other);
}

test "detects NUL during scan, including prefix before minimum anchor offset and NUL after match in same block" {
    const mid = PackedPair.init("QX", &frequency.default_rank, false);
    var buf: [200]u8 = undefined;
    @memset(&buf, 'a');
    buf[80] = 0;
    @memcpy(buf[120..][0..2], "QX");
    inline for (.{ 16, 32, 64 }) |w| {
        var nul: ?usize = null;
        try std.testing.expect(mid.findWatchingNul(w, &buf, 0, null, &nul) == null);
        try std.testing.expectEqual(@as(?usize, 80), nul);
    }

    @memset(&buf, 'a');
    @memcpy(buf[30..][0..2], "QX");
    buf[150] = 0;
    inline for (.{ 16, 32, 64 }) |w| {
        var nul: ?usize = null;
        try std.testing.expectEqual(@as(?usize, 30), mid.findWatchingNul(w, &buf, 0, null, &nul));
        try std.testing.expect(nul == null);
    }

    // NUL immediately after match in the same SIMD block must still return the match!
    @memset(&buf, 'a');
    @memcpy(buf[2..][0..2], "QX");
    buf[5] = 0;
    inline for (.{ 16, 32, 64 }) |w| {
        var nul: ?usize = null;
        try std.testing.expectEqual(@as(?usize, 2), mid.findWatchingNul(w, &buf, 0, null, &nul));
        try std.testing.expect(nul == null);
    }

    const shifted = PackedPair.init("aQX", &frequency.default_rank, false);
    try std.testing.expect(shifted.anchor_index != 0 and shifted.other_index != 0);
    @memset(&buf, 'b');
    buf[0] = 0;
    @memcpy(buf[40..][0..3], "aQX");
    inline for (.{ 16, 32, 64 }) |w| {
        var nul: ?usize = null;
        try std.testing.expect(shifted.findWatchingNul(w, &buf, 0, null, &nul) == null);
        try std.testing.expectEqual(@as(?usize, 0), nul);
    }
}

test "verifies candidates and continues past false positives" {
    const pair = PackedPair.init("qx", &frequency.default_rank, false);
    inline for (.{ 16, 32, 64 }) |w| {
        try std.testing.expectEqual(@as(?usize, 3), findAll(pair, w, "qqqqxqx", 0));
        try std.testing.expectEqual(@as(?usize, null), findAll(pair, w, "qqqqqq", 0));
        try std.testing.expectEqual(@as(?usize, null), findAll(pair, w, "qx", 1));
    }
}

test "case-insensitive matching" {
    const pair = PackedPair.init("Ab", &frequency.default_rank, true);
    inline for (.{ 16, 32, 64 }) |w| {
        try std.testing.expectEqual(@as(?usize, 1), findAll(pair, w, "xabXAB", 0));
        try std.testing.expectEqual(@as(?usize, 4), findAll(pair, w, "xabXAB", 2));
        try std.testing.expectEqual(@as(?usize, null), findAll(pair, w, "axb", 0));
    }
}

const frequency = @import("frequency.zig");

test "random differential against naive search" {
    var prng = std.Random.DefaultPrng.init(0x9A11);
    const random = prng.random();
    var hay: [200]u8 = undefined;
    var pat: [8]u8 = undefined;
    const rank = frequency.default_rank;
    for (0..60) |_| {
        const hlen = random.intRangeAtMost(usize, 0, hay.len);
        const plen = random.intRangeAtMost(usize, 2, pat.len);
        random.bytes(hay[0..hlen]);
        random.bytes(pat[0..plen]);
        const start = if (hlen == 0) 0 else random.intRangeAtMost(usize, 0, hlen);
        inline for (.{ false, true }) |fold| {
            const pair = PackedPair.init(pat[0..plen], &rank, fold);
            inline for (.{ 16, 32, 64 }) |w| {
                try std.testing.expectEqual(
                    scalarFind(hay[0..hlen], pat[0..plen], start, fold),
                    findAll(pair, w, hay[0..hlen], start),
                );
            }
        }
    }
}

test "packed pair fuzz differential" {
    try std.testing.fuzz({}, fuzzPair, .{});
}

fn fuzzPair(_: void, smith: *std.testing.Smith) !void {
    var hay_buf: [80]u8 = undefined;
    var pat_buf: [10]u8 = undefined;
    const hlen: usize = smith.slice(&hay_buf);
    var plen: usize = smith.slice(&pat_buf);
    if (plen < 2) plen = 0;
    if (plen < 2) return;
    const fold = smith.value(bool);
    const start: usize = if (hlen == 0) 0 else smith.valueRangeAtMost(u32, 0, @intCast(hlen));
    const pair = PackedPair.init(pat_buf[0..plen], &frequency.default_rank, fold);
    inline for (.{ 16, 32, 64 }) |w| {
        try std.testing.expectEqual(
            scalarFind(hay_buf[0..hlen], pat_buf[0..plen], start, fold),
            findAll(pair, w, hay_buf[0..hlen], start),
        );
    }
}
