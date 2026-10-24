//! Two-Way literal search (Crochemore-Perrin).
//! O(m) preprocessing in constant extra space and O(n) worst-case search time. Pattern bytes are owned by the caller.
//!
//! Critical factorization picks the rightmost maximal suffix under both ordering directions.
//! The right half is compared left-to-right first; once matched, the left half is compared right-to-left.
//! For periodic patterns, the matched prefix length is remembered to avoid redundant comparisons.

const std = @import("std");
const ascii = @import("ascii.zig");
const memchr = @import("memchr.zig");

pub const Fold = enum {
    sensitive,
    ascii,
};

pub const TwoWay = struct {
    pattern: []const u8,
    /// Start index of the right half. 0 means the left half is empty.
    crit: usize,
    period: usize,
    /// True when the left half repeats at distance `period`, allowing prefix memory during search.
    periodic: bool,
    fold: Fold,

    pub fn init(pattern: []const u8, fold: Fold) TwoWay {
        if (pattern.len == 0) {
            return .{
                .pattern = pattern,
                .crit = 0,
                .period = 1,
                .periodic = true,
                .fold = fold,
            };
        }

        const forward = maximalSuffix(pattern, fold, false);
        const reverse = maximalSuffix(pattern, fold, true);
        const chosen = if (forward.pos > reverse.pos) forward else reverse;
        const crit: usize = @intCast(chosen.pos + 1);
        const period = chosen.period;
        const periodic = period + crit <= pattern.len and bytesEqual(pattern[0..crit], pattern[period..][0..crit], fold);

        return .{
            .pattern = pattern,
            .crit = crit,
            .period = period,
            .periodic = periodic,
            .fold = fold,
        };
    }

    /// Returns the start of the next match. An empty pattern matches at `start` when `start <= haystack.len`.
    pub fn find(self: TwoWay, haystack: []const u8, start: usize) ?usize {
        const m = self.pattern.len;
        if (m == 0) {
            if (start <= haystack.len) return start;
            return null;
        }
        if (start > haystack.len or m > haystack.len - start) return null;
        if (self.periodic) return findPeriodic(self, haystack, start);
        return findNonPeriodic(self, haystack, start);
    }

    fn eq(self: TwoWay, a: u8, b: u8) bool {
        return ascii.eq(a, b, self.fold == .ascii);
    }
};

const Suffix = struct {
    /// Start index of the maximal suffix minus one (-1 when the entire string is the maximal suffix).
    pos: isize,
    period: usize,
};

fn maximalSuffix(pattern: []const u8, fold: Fold, reverse_order: bool) Suffix {
    const m: isize = @intCast(pattern.len);
    var ms: isize = -1;
    var j: isize = 0;
    var k: isize = 1;
    var p: isize = 1;
    while (j + k < m) {
        const a = pattern[@intCast(j + k)];
        const b = pattern[@intCast(ms + k)];
        const ord = cmpByte(a, b, fold);
        const a_smaller = if (reverse_order) ord == .gt else ord == .lt;
        const a_greater = if (reverse_order) ord == .lt else ord == .gt;
        if (a_smaller) {
            j += k;
            k = 1;
            p = j - ms;
        } else if (!a_greater) {
            if (k != p) {
                k += 1;
            } else {
                j += p;
                k = 1;
            }
        } else {
            ms = j;
            j = ms + 1;
            k = 1;
            p = 1;
        }
    }
    return .{ .pos = ms, .period = @intCast(p) };
}

fn findPeriodic(self: TwoWay, haystack: []const u8, start: usize) ?usize {
    const pat = self.pattern;
    const m: isize = @intCast(pat.len);
    const n = haystack.len;
    const ell: isize = @as(isize, @intCast(self.crit)) - 1;
    const per = self.period;
    var window = start;
    var memory: isize = -1;
    while (window <= n - pat.len) {
        var i: isize = @max(ell, memory) + 1;
        while (i < m and self.eq(pat[@intCast(i)], haystack[window + @as(usize, @intCast(i))])) {
            i += 1;
        }
        if (i >= m) {
            i = ell;
            while (i > memory and self.eq(pat[@intCast(i)], haystack[window + @as(usize, @intCast(i))])) {
                i -= 1;
            }
            if (i <= memory) return window;
            window += per;
            memory = m - @as(isize, @intCast(per)) - 1;
        } else {
            window += @intCast(i - ell);
            memory = -1;
        }
    }
    return null;
}

fn findNonPeriodic(self: TwoWay, haystack: []const u8, start: usize) ?usize {
    const pat = self.pattern;
    const m: isize = @intCast(pat.len);
    const n = haystack.len;
    const ell: isize = @as(isize, @intCast(self.crit)) - 1;
    const per = @max(self.crit, pat.len - self.crit) + 1;
    const crit = self.crit;
    const fold = self.fold == .ascii;
    // When the right half is non-empty, use vectorized memchr to skip to the first required byte.
    // Mismatch shifts still follow Two-Way, preserving linear worst-case time.
    const forms: [2]u8 = if (crit < pat.len and fold)
        ascii.caseVariants(pat[crit])
    else if (crit < pat.len)
        .{ pat[crit], pat[crit] }
    else
        .{ 0, 0 };
    var window: usize = start;
    while (window <= n - pat.len) {
        var i: isize = ell + 1;
        if (crit < pat.len) {
            const at = memchr.findEither(memchr.native_width, haystack, window + crit, forms[0], forms[1]) orelse return null;
            if (at < crit) return null;
            const aligned = at - crit;
            if (aligned > n - pat.len) return null;
            window = aligned;
            i = ell + 2;
        }
        while (i < m and self.eq(pat[@intCast(i)], haystack[window + @as(usize, @intCast(i))])) {
            i += 1;
        }
        if (i >= m) {
            i = ell;
            while (i >= 0 and self.eq(pat[@intCast(i)], haystack[window + @as(usize, @intCast(i))])) {
                i -= 1;
            }
            if (i < 0) return window;
            window += per;
        } else {
            const shift: usize = @intCast(i - ell);
            window += if (shift == 0) 1 else shift;
        }
    }
    return null;
}

fn cmpByte(a: u8, b: u8, fold: Fold) std.math.Order {
    const x = if (fold == .ascii) ascii.fold(a) else a;
    const y = if (fold == .ascii) ascii.fold(b) else b;
    return std.math.order(x, y);
}

fn bytesEqual(a: []const u8, b: []const u8, fold: Fold) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (cmpByte(x, y, fold) != .eq) return false;
    }
    return true;
}

fn scalarFind(haystack: []const u8, needle: []const u8, start: usize, fold: Fold) ?usize {
    if (needle.len == 0) {
        if (start <= haystack.len) return start;
        return null;
    }
    if (start > haystack.len or needle.len > haystack.len - start) return null;
    var i = start;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (bytesEqual(haystack[i..][0..needle.len], needle, fold)) return i;
    }
    return null;
}

test "empty pattern, not found, and pattern longer than remaining input" {
    const empty = TwoWay.init("", .sensitive);
    try std.testing.expectEqual(@as(?usize, 0), empty.find("", 0));
    try std.testing.expectEqual(@as(?usize, 2), empty.find("ab", 2));
    try std.testing.expectEqual(@as(?usize, null), empty.find("ab", 3));

    const abc = TwoWay.init("abc", .sensitive);
    try std.testing.expectEqual(@as(?usize, null), abc.find("", 0));
    try std.testing.expectEqual(@as(?usize, null), abc.find("ab", 0));
    try std.testing.expectEqual(@as(?usize, null), abc.find("zz", 0));
    try std.testing.expectEqual(@as(?usize, 2), abc.find("xxabcxx", 0));
    try std.testing.expectEqual(@as(?usize, null), abc.find("xxabcxx", 3));
}

test "overlapping matches in periodic patterns" {
    const aaa = TwoWay.init("aaa", .sensitive);
    try std.testing.expectEqual(@as(?usize, 0), aaa.find("aaaa", 0));
    try std.testing.expectEqual(@as(?usize, 1), aaa.find("aaaa", 1));
    const abab = TwoWay.init("abab", .sensitive);
    try std.testing.expectEqual(@as(?usize, 0), abab.find("ababab", 0));
    try std.testing.expectEqual(@as(?usize, 2), abab.find("ababab", 1));
    const aabaab = TwoWay.init("aabaab", .sensitive);
    try std.testing.expectEqual(@as(?usize, 3), aabaab.find("xxxaabaabaab", 0));
}

test "ASCII case-insensitive matching" {
    const pat = TwoWay.init("AbC", .ascii);
    try std.testing.expectEqual(@as(?usize, 2), pat.find("xxabcXX", 0));
    try std.testing.expectEqual(@as(?usize, 2), pat.find("xxABCxx", 0));
    try std.testing.expectEqual(@as(?usize, null), pat.find("xxabxx", 0));
    const sensitive = TwoWay.init("AbC", .sensitive);
    try std.testing.expectEqual(@as(?usize, null), sensitive.find("xxabcXX", 0));
}

test "matches naive search over a binary alphabet" {
    const alphabet = "ab";
    var hay: [10]u8 = undefined;
    var pat: [5]u8 = undefined;
    var hlen: usize = 0;
    while (hlen <= hay.len) : (hlen += 1) {
        var hmask: usize = 0;
        const hlimit: usize = @as(usize, 1) << @intCast(hlen);
        while (hmask < hlimit) : (hmask += 1) {
            for (0..hlen) |i| {
                hay[i] = alphabet[(hmask >> @intCast(i)) & 1];
            }
            var plen: usize = 0;
            while (plen <= pat.len) : (plen += 1) {
                var pmask: usize = 0;
                const plimit: usize = @as(usize, 1) << @intCast(plen);
                while (pmask < plimit) : (pmask += 1) {
                    for (0..plen) |i| {
                        pat[i] = alphabet[(pmask >> @intCast(i)) & 1];
                    }
                    const tw = TwoWay.init(pat[0..plen], .sensitive);
                    const got = tw.find(hay[0..hlen], 0);
                    const expect = scalarFind(hay[0..hlen], pat[0..plen], 0, .sensitive);
                    try std.testing.expectEqual(expect, got);
                    if (hlen > 0) {
                        const from = hlen / 2;
                        try std.testing.expectEqual(
                            scalarFind(hay[0..hlen], pat[0..plen], from, .sensitive),
                            tw.find(hay[0..hlen], from),
                        );
                    }
                }
            }
        }
    }
}

test "random inputs against std.mem.findPos" {
    var prng = std.Random.DefaultPrng.init(0x7A0);
    const random = prng.random();
    var hay: [80]u8 = undefined;
    var pat: [12]u8 = undefined;
    for (0..80) |_| {
        const hlen = random.intRangeAtMost(usize, 0, hay.len);
        const plen = random.intRangeAtMost(usize, 0, pat.len);
        random.bytes(hay[0..hlen]);
        random.bytes(pat[0..plen]);
        const start = if (hlen == 0) 0 else random.intRangeAtMost(usize, 0, hlen);
        const tw = TwoWay.init(pat[0..plen], .sensitive);
        try std.testing.expectEqual(std.mem.findPos(u8, hay[0..hlen], start, pat[0..plen]), tw.find(hay[0..hlen], start));

        for (pat[0..plen]) |*b| b.* = random.intRangeAtMost(u8, 'A', 'z');
        for (hay[0..hlen]) |*b| b.* = random.intRangeAtMost(u8, 'A', 'z');
        const folded = TwoWay.init(pat[0..plen], .ascii);
        try std.testing.expectEqual(
            scalarFind(hay[0..hlen], pat[0..plen], start, .ascii),
            folded.find(hay[0..hlen], start),
        );
    }
}

test "Two-Way fuzz differential" {
    try std.testing.fuzz({}, fuzzTwoWay, .{});
}

fn fuzzTwoWay(_: void, smith: *std.testing.Smith) !void {
    var hay_buf: [96]u8 = undefined;
    var pat_buf: [16]u8 = undefined;
    const hlen: usize = smith.slice(&hay_buf);
    const plen: usize = smith.slice(&pat_buf);
    const hay = hay_buf[0..hlen];
    const pat = pat_buf[0..plen];
    const start: usize = if (hlen == 0) 0 else smith.valueRangeAtMost(u32, 0, @intCast(hlen));
    const sensitive = TwoWay.init(pat, .sensitive);
    try std.testing.expectEqual(std.mem.findPos(u8, hay, start, pat), sensitive.find(hay, start));
    const folded = TwoWay.init(pat, .ascii);
    try std.testing.expectEqual(scalarFind(hay, pat, start, .ascii), folded.find(hay, start));
}
