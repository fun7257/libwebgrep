//! 用两个稀有字节做预过滤，再对候选做整段确认。
//! 模式至少两个字节。单字节走 memchr，本模块不处理。

const std = @import("std");
const ascii = @import("ascii.zig");
const memchr = @import("memchr.zig");

pub const PackedPair = struct {
    pattern: []const u8,
    anchor_index: usize,
    other_index: usize,
    anchor: u8,
    other: u8,
    ignore_case: bool,

    /// `rank` 的值越小越稀有。`pattern` 由调用方持有。
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
            }
        }
        return .{
            .pattern = pattern,
            .anchor_index = best,
            .other_index = second,
            .anchor = pattern[best],
            .other = pattern[second],
            .ignore_case = ignore_case,
        };
    }

    pub const Candidate = struct {
        /// 锚点在 haystack 中的下标。
        anchor_at: usize,
        /// 整段确认是否通过。
        confirmed: bool,
        /// 若模式放得下，这是模式起点。确认失败时仍给出，方便调用方决定从哪里继续。
        origin: usize,
    };

    /// 从 `anchor_from`（含）起找下一个锚点。没有则返回 null。
    /// 锚点必须让整个模式落在 haystack 内，并且起点不早于 `start`。
    pub fn next(
        self: PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        anchor_from: usize,
    ) ?Candidate {
        const m = self.pattern.len;
        if (m > haystack.len or start > haystack.len - m) return null;
        const last_anchor = haystack.len - m + self.anchor_index;
        if (anchor_from > last_anchor) return null;

        const forms = if (self.ignore_case) ascii.caseVariants(self.anchor) else .{ self.anchor, self.anchor };
        const found = memchr.findEither(width, haystack[0 .. last_anchor + 1], anchor_from, forms[0], forms[1]) orelse return null;
        const origin = found - self.anchor_index;
        return .{
            .anchor_at = found,
            .origin = origin,
            .confirmed = confirm(self, haystack, origin),
        };
    }
};

fn confirm(self: PackedPair, haystack: []const u8, origin: usize) bool {
    const window = haystack[origin..][0..self.pattern.len];
    const other = window[self.other_index];
    if (!ascii.eq(other, self.other, self.ignore_case)) return false;
    for (self.pattern, window) |p, h| {
        if (!ascii.eq(p, h, self.ignore_case)) return false;
    }
    return true;
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
    const m = pair.pattern.len;
    if (m > haystack.len or start > haystack.len - m) return null;
    var anchor_from = start + pair.anchor_index;
    while (pair.next(width, haystack, start, anchor_from)) |cand| {
        if (cand.confirmed) return cand.origin;
        anchor_from = cand.anchor_at + 1;
    }
    return null;
}

test "按秩选择最稀有的两个字节" {
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

test "确认候选，假阳性继续往后" {
    const pair = PackedPair.init("qx", &frequency.default_rank, false);
    inline for (.{ 16, 32 }) |w| {
        try std.testing.expectEqual(@as(?usize, 3), findAll(pair, w, "qqqqxqx", 0));
        try std.testing.expectEqual(@as(?usize, null), findAll(pair, w, "qqqqqq", 0));
        try std.testing.expectEqual(@as(?usize, null), findAll(pair, w, "qx", 1));
    }
}

test "忽略大小写" {
    const pair = PackedPair.init("Ab", &frequency.default_rank, true);
    inline for (.{ 16, 32 }) |w| {
        try std.testing.expectEqual(@as(?usize, 1), findAll(pair, w, "xabXAB", 0));
        try std.testing.expectEqual(@as(?usize, 4), findAll(pair, w, "xabXAB", 2));
        try std.testing.expectEqual(@as(?usize, null), findAll(pair, w, "axb", 0));
    }
}

const frequency = @import("frequency.zig");

test "随机对照朴素查找" {
    var prng = std.Random.DefaultPrng.init(0x9A11);
    const random = prng.random();
    var hay: [100]u8 = undefined;
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
            inline for (.{ 16, 32 }) |w| {
                try std.testing.expectEqual(
                    scalarFind(hay[0..hlen], pat[0..plen], start, fold),
                    findAll(pair, w, hay[0..hlen], start),
                );
            }
        }
    }
}

test "packed pair 模糊对照" {
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
    inline for (.{ 16, 32 }) |w| {
        try std.testing.expectEqual(
            scalarFind(hay_buf[0..hlen], pat_buf[0..plen], start, fold),
            findAll(pair, w, hay_buf[0..hlen], start),
        );
    }
}
