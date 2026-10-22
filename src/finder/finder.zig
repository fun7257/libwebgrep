//! 单模式字面量查找器。
//! 一个字节走 memchr。长度不超过 32 的模式走向量 packed pair，自己完成确认。
//! 更长的模式仍用 packed pair，但两个稀有字节挤在一起、确认又总是失败时改走 Two-Way。
//! 不分配内存。模式字节由调用方持有，并且不能含有换行。

const std = @import("std");
const ascii = @import("ascii.zig");
const frequency = @import("frequency.zig");
const matcher = @import("../matcher.zig");
const memchr = @import("memchr.zig");
const packed_pair = @import("packed_pair.zig");
const two_way = @import("two_way.zig");

pub const Finder = struct {
    pattern: []const u8,
    ignore_case: bool,
    kind: Kind,
    fp_threshold: f32,
    /// 本次生命周期里 packed pair 看到的候选数。可用 `resetStats` 清零。
    candidates: u32 = 0,
    confirms: u32 = 0,
    /// 为真之后，后续查找都走 Two-Way。
    use_two_way: bool = false,
    two_way: two_way.TwoWay,

    const Kind = union(enum) {
        empty,
        byte: u8,
        pair: packed_pair.PackedPair,
    };

    pub fn init(pattern: []const u8, options: matcher.FindOptions) error{PatternHasNewline}!Finder {
        if (std.mem.findScalar(u8, pattern, '\n') != null) return error.PatternHasNewline;

        const ignore_case = switch (options.case) {
            .sensitive => false,
            .insensitive => true,
            .smart => !ascii.patternHasUpper(pattern),
        };
        const fold: two_way.Fold = if (ignore_case) .ascii else .sensitive;
        const rank: *const [256]u8 = if (options.frequency) |*table| table else &frequency.default_rank;

        const kind: Kind = switch (pattern.len) {
            0 => .empty,
            1 => .{ .byte = pattern[0] },
            else => .{ .pair = packed_pair.PackedPair.init(pattern, rank, ignore_case) },
        };

        return .{
            .pattern = pattern,
            .ignore_case = ignore_case,
            .kind = kind,
            .fp_threshold = options.prefilter_fp_threshold,
            .two_way = two_way.TwoWay.init(pattern, fold),
        };
    }

    /// 单个字面量下 `earliest` 和 `leftmost_first` 是同一次匹配。
    /// 这条路径单独写，不经过 NUL 监视。密集命中时它会被内联进搜索循环。
    pub fn find(self: *Finder, haystack: []const u8, start: usize, mode: matcher.MatchMode) ?matcher.Match {
        _ = mode;
        switch (self.kind) {
            .empty => {
                if (start <= haystack.len) return .{ .start = start, .end = start };
                return null;
            },
            .byte => |needle| {
                const at = if (self.ignore_case) blk: {
                    const forms = ascii.caseVariants(needle);
                    break :blk memchr.findEither(memchr.native_width, haystack, start, forms[0], forms[1]);
                } else memchr.find(memchr.native_width, haystack, start, needle);
                const i = at orelse return null;
                return .{ .start = i, .end = i + 1 };
            },
            .pair => return self.findPair(haystack, start),
        }
    }

    /// 和 `find` 一样，另外把扫描过的区间里第一个 NUL 写到 `nul`。
    /// 返回匹配时，只保证这个匹配起点之前没有 NUL。
    pub fn findWatched(self: *Finder, haystack: []const u8, start: usize, nul: *?usize) ?matcher.Match {
        switch (self.kind) {
            .empty => {
                if (start < haystack.len) {
                    if (memchr.find(memchr.native_width, haystack, start, 0)) |at| nul.* = at;
                }
                if (start <= haystack.len) return .{ .start = start, .end = start };
                return null;
            },
            .byte => |needle| {
                const hit = if (self.ignore_case) blk: {
                    const forms = ascii.caseVariants(needle);
                    break :blk memchr.findAny(memchr.native_width, haystack, start, forms[0], forms[1], 0);
                } else memchr.findAny(memchr.native_width, haystack, start, needle, 0, 0);
                const found = hit orelse return null;
                if (found.byte == 0) {
                    nul.* = found.index;
                    return null;
                }
                return .{ .start = found.index, .end = found.index + 1 };
            },
            .pair => return self.findPairWatched(haystack, start, nul),
        }
    }

    /// 供将来的正则预过滤使用。忽略大小写时字节仍是原模式，不能当成大小写敏感的必要子串。
    pub fn requiredLiteral(self: *const Finder) ?matcher.RequiredLiteral {
        if (self.pattern.len == 0) return null;
        return .{ .bytes = self.pattern, .offset_in_match = 0 };
    }

    /// 每个新输入开始时调用，避免上一个输入的假阳性把这个输入锁进 Two-Way。
    pub fn resetStats(self: *Finder) void {
        self.candidates = 0;
        self.confirms = 0;
        self.use_two_way = false;
    }

    fn findPair(self: *Finder, haystack: []const u8, start: usize) ?matcher.Match {
        const pair = self.kind.pair;
        const m = pair.pattern.len;
        if (self.use_two_way) return self.findLinear(haystack, start, m);
        if (m > haystack.len or start > haystack.len - m) return null;

        // 短模式的最坏情况是常数倍的线性时间，不切到标量 Two-Way。
        // 长模式只在调用方把阈值设到 1 以下、并且预过滤跳不动时才切。
        var guard: packed_pair.Guard = .{};
        const watch = m > packed_pair.owns_search_max_len and self.fp_threshold < 1;
        const at = pair.find(memchr.native_width, haystack, start, if (watch) &guard else null);
        if (at) |pos| {
            self.confirms +|= 1;
            return .{ .start = pos, .end = pos + m };
        }
        if (guard.gave_up) {
            self.use_two_way = true;
            self.candidates = guard.candidates;
            return self.findLinear(haystack, guard.restart, m);
        }
        return null;
    }

    fn findPairWatched(self: *Finder, haystack: []const u8, start: usize, nul: *?usize) ?matcher.Match {
        const pair = self.kind.pair;
        const m = pair.pattern.len;
        if (self.use_two_way) {
            if (memchr.find(memchr.native_width, haystack, start, 0)) |at| {
                nul.* = at;
                return null;
            }
            return self.findLinear(haystack, start, m);
        }
        if (m > haystack.len or start > haystack.len - m) {
            if (start <= haystack.len) {
                if (memchr.find(memchr.native_width, haystack, start, 0)) |at| nul.* = at;
            }
            return null;
        }

        var guard: packed_pair.Guard = .{};
        const watch = m > packed_pair.owns_search_max_len and self.fp_threshold < 1;
        const at = pair.findWatchingNul(memchr.native_width, haystack, start, if (watch) &guard else null, nul);
        if (nul.* != null) return null;
        if (at) |pos| {
            self.confirms +|= 1;
            return .{ .start = pos, .end = pos + m };
        }
        if (guard.gave_up) {
            self.use_two_way = true;
            self.candidates = guard.candidates;
            if (memchr.find(memchr.native_width, haystack, guard.restart, 0)) |z| {
                nul.* = z;
                return null;
            }
            return self.findLinear(haystack, guard.restart, m);
        }
        return null;
    }

    fn findLinear(self: *Finder, haystack: []const u8, start: usize, m: usize) ?matcher.Match {
        const at = self.two_way.find(haystack, start) orelse return null;
        return .{ .start = at, .end = at + m };
    }
};

fn scalarFind(haystack: []const u8, pattern: []const u8, start: usize, ignore_case: bool) ?usize {
    if (pattern.len == 0) {
        if (start <= haystack.len) return start;
        return null;
    }
    if (start > haystack.len or pattern.len > haystack.len - start) return null;
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

test "换行、空模式、单字节、smart case" {
    try std.testing.expectError(error.PatternHasNewline, Finder.init("a\nb", .{}));

    var empty = try Finder.init("", .{});
    const empty_match = empty.find("ab", 1, .earliest).?;
    try std.testing.expectEqual(@as(usize, 1), empty_match.start);
    try std.testing.expectEqual(@as(usize, 1), empty_match.end);

    var byte = try Finder.init("A", .{ .case = .insensitive });
    try std.testing.expectEqual(@as(usize, 2), byte.find("xxaXX", 0, .leftmost_first).?.start);

    var smart_upper = try Finder.init("Foo", .{ .case = .smart });
    try std.testing.expect(!smart_upper.ignore_case);
    try std.testing.expect(smart_upper.find("foo", 0, .earliest) == null);

    var smart_lower = try Finder.init("foo", .{ .case = .smart });
    try std.testing.expect(smart_lower.ignore_case);
    try std.testing.expectEqual(@as(usize, 0), smart_lower.find("FOO", 0, .earliest).?.start);
}

test "多字节命中，短模式不因常见字节切到 Two-Way" {
    var finder = try Finder.init("qx", .{});
    try std.testing.expectEqual(@as(usize, 4), finder.find("qqq qx", 0, .earliest).?.start);
    try std.testing.expect(!finder.use_two_way);

    var rank: [256]u8 = @splat(100);
    rank['a'] = 0;
    rank['b'] = 1;
    var noisy = try Finder.init("ab", .{
        .frequency = rank,
        .prefilter_fp_threshold = 0.5,
    });
    var hay: [48]u8 = @splat('a');
    hay[46] = 'a';
    hay[47] = 'b';
    try std.testing.expectEqual(@as(usize, 46), noisy.find(&hay, 0, .earliest).?.start);
    try std.testing.expect(!noisy.use_two_way);
}

test "长模式在两个稀有字节挤在一起时改走 Two-Way，并且仍能找到" {
    var rank: [256]u8 = @splat(100);
    rank['a'] = 0;
    rank['b'] = 1;
    var pat: [33]u8 = @splat('c');
    pat[0] = 'a';
    pat[1] = 'b';
    var noisy = try Finder.init(&pat, .{
        .frequency = rank,
        .prefilter_fp_threshold = 0.5,
    });
    var hay: [200]u8 = @splat('a');
    for (0..80) |i| {
        hay[i * 2] = 'a';
        hay[i * 2 + 1] = 'b';
    }
    @memcpy(hay[hay.len - pat.len ..], pat[0..]);
    try std.testing.expectEqual(hay.len - pat.len, noisy.find(&hay, 0, .earliest).?.start);
    try std.testing.expect(noisy.use_two_way);

    noisy.resetStats();
    try std.testing.expect(!noisy.use_two_way);
    try std.testing.expectEqual(@as(u32, 0), noisy.candidates);
}

test "Finder 与朴素查找一致" {
    var prng = std.Random.DefaultPrng.init(0xF1A0);
    const random = prng.random();
    var hay: [120]u8 = undefined;
    var pat: [8]u8 = undefined;
    const cases = [_]matcher.CaseMode{ .sensitive, .insensitive, .smart };
    for (0..40) |_| {
        const hlen = random.intRangeAtMost(usize, 0, hay.len);
        const plen = random.intRangeAtMost(usize, 0, pat.len);
        random.bytes(hay[0..hlen]);
        random.bytes(pat[0..plen]);
        if (std.mem.findScalar(u8, pat[0..plen], '\n') != null) continue;
        for (cases) |case| {
            var finder = try Finder.init(pat[0..plen], .{ .case = case });
            const start = if (hlen == 0) 0 else random.intRangeAtMost(usize, 0, hlen);
            const expect = scalarFind(hay[0..hlen], pat[0..plen], start, finder.ignore_case);
            const got = finder.find(hay[0..hlen], start, .earliest);
            if (expect) |at| {
                try std.testing.expectEqual(at, got.?.start);
                try std.testing.expectEqual(at + plen, got.?.end);
            } else {
                try std.testing.expect(got == null);
            }
        }
    }
}

test "必需字面量" {
    var finder = try Finder.init("abc", .{});
    const lit = finder.requiredLiteral().?;
    try std.testing.expectEqualStrings("abc", lit.bytes);
    try std.testing.expectEqual(@as(usize, 0), lit.offset_in_match);
    var empty = try Finder.init("", .{});
    try std.testing.expect(empty.requiredLiteral() == null);
}
