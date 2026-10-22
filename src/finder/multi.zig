//! 多模式字面量。
//!
//! 全部是单字节时走字节集。其余走 Aho-Corasick 稠密 DFA。
//! Teddy 由 `-Dteddy` 选择。aarch64 默认是 neon，其他架构默认关闭。
//! 打开时，不超过 32 个、并且都非空的模式走 Teddy。空模式和更长的集合仍走自动机。
//!
//! 模式字节由调用方持有，并且不能含有换行。复制本结构只复制指针，表在
//! `deinit` 之前只读，工人可以共享。只有创建者调用 `deinit`。

const std = @import("std");
const aho = @import("aho.zig");
const ascii = @import("ascii.zig");
const build_options = @import("build_options");
const byteset = @import("byteset.zig");
const matcher = @import("../matcher.zig");
const memchr = @import("memchr.zig");

const teddy_on = build_options.teddy != .off;
const teddy_mod = if (teddy_on) @import("teddy.zig") else struct {
    pub const Engine = struct {};
};

pub const Multi = struct {
    kind: Kind,
    ignore_case: bool,
    empty_only: bool,

    const Kind = union(enum) {
        bytes: byteset.Set,
        ac: aho.Ac,
        teddy: if (teddy_on) teddy_mod.Engine else void,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        patterns: []const []const u8,
        options: matcher.FindOptions,
    ) error{ PatternHasNewline, OutOfMemory }!Multi {
        for (patterns) |pat| {
            if (std.mem.findScalar(u8, pat, '\n') != null) return error.PatternHasNewline;
        }
        const ignore = ignoreCase(patterns, options.case);
        if (allSingleByte(patterns)) {
            return .{
                .kind = .{ .bytes = byteset.Set.init(patterns, ignore) },
                .ignore_case = ignore,
                .empty_only = false,
            };
        }
        if (comptime teddy_on) {
            if (teddyEligible(patterns)) {
                return .{
                    .kind = .{ .teddy = teddy_mod.Engine.init(patterns, ignore) },
                    .ignore_case = ignore,
                    .empty_only = false,
                };
            }
        }
        return .{
            .kind = .{ .ac = try aho.build(allocator, patterns, ignore) },
            .ignore_case = ignore,
            .empty_only = onlyEmpty(patterns),
        };
    }

    pub fn deinit(self: *Multi) void {
        switch (self.kind) {
            .bytes => {},
            .ac => |*ac| ac.deinit(),
            .teddy => |*engine| {
                if (comptime teddy_on) engine.deinit();
            },
        }
        self.* = undefined;
    }

    pub fn isEmpty(self: *const Multi) bool {
        return self.empty_only;
    }

    pub fn resetStats(self: *Multi) void {
        _ = self;
    }

    pub fn find(self: *Multi, haystack: []const u8, start: usize, mode: matcher.MatchMode) ?matcher.Match {
        switch (self.kind) {
            .bytes => |*set| {
                const at = set.find(haystack, start) orelse return null;
                return .{ .start = at, .end = at + 1 };
            },
            .ac => |*ac| return ac.find(haystack, start, mode),
            .teddy => |*engine| {
                if (comptime teddy_on) return engine.find(haystack, start, mode);
                unreachable;
            },
        }
    }

    pub fn findWatched(self: *Multi, haystack: []const u8, start: usize, nul: *?usize) ?matcher.Match {
        const hit = self.find(haystack, start, .earliest);
        const limit = if (hit) |item| item.start else haystack.len;
        if (start < limit) {
            if (memchr.find(memchr.native_width, haystack, start, 0)) |at| {
                if (at < limit) {
                    nul.* = at;
                    return null;
                }
            }
        }
        return hit;
    }
};

pub fn ignoreCase(patterns: []const []const u8, mode: matcher.CaseMode) bool {
    switch (mode) {
        .sensitive => return false,
        .insensitive => return true,
        .smart => {
            for (patterns) |pat| {
                if (ascii.patternHasUpper(pat)) return false;
            }
            return true;
        },
    }
}

fn allSingleByte(patterns: []const []const u8) bool {
    if (patterns.len == 0) return false;
    for (patterns) |pat| if (pat.len != 1) return false;
    return true;
}

fn teddyEligible(patterns: []const []const u8) bool {
    if (patterns.len == 0 or patterns.len > 32) return false;
    for (patterns) |pat| if (pat.len == 0) return false;
    return true;
}

fn onlyEmpty(patterns: []const []const u8) bool {
    if (patterns.len == 0) return false;
    for (patterns) |pat| if (pat.len != 0) return false;
    return true;
}

const Naive = struct { start: usize, end: usize, id: u32 };

fn naive(
    haystack: []const u8,
    start: usize,
    patterns: []const []const u8,
    ignore: bool,
    mode: matcher.MatchMode,
) ?matcher.Match {
    if (start > haystack.len) return null;
    var best: ?Naive = null;
    var i = start;
    while (i <= haystack.len) : (i += 1) {
        for (patterns, 0..) |pat, id_usize| {
            if (i + pat.len > haystack.len) continue;
            var ok = true;
            for (pat, haystack[i..][0..pat.len]) |p, h| {
                if (!ascii.eq(p, h, ignore)) {
                    ok = false;
                    break;
                }
            }
            if (!ok) continue;
            const cand = Naive{ .start = i, .end = i + pat.len, .id = @intCast(id_usize) };
            if (best) |cur| {
                if (better(cand, cur, mode)) best = cand;
            } else best = cand;
        }
    }
    const found = best orelse return null;
    return .{ .start = found.start, .end = found.end };
}

fn better(a: Naive, b: Naive, mode: matcher.MatchMode) bool {
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

test "换行、空集、单字节和模式顺序" {
    const alloc = std.testing.allocator;
    try std.testing.expectError(error.PatternHasNewline, Multi.init(alloc, &.{ "a", "b\nc" }, .{}));

    var none = try Multi.init(alloc, &.{}, .{});
    defer none.deinit();
    try std.testing.expect(none.find("abc", 0, .leftmost_first) == null);

    var bytes = try Multi.init(alloc, &.{ "b", "a", "c" }, .{});
    defer bytes.deinit();
    const at = bytes.find("xxcya", 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 2), at.start);
    try std.testing.expectEqual(@as(usize, 3), at.end);

    var order = try Multi.init(alloc, &.{ "foo", "foobar" }, .{});
    defer order.deinit();
    const short = order.find("foobar", 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 0), short.start);
    try std.testing.expectEqual(@as(usize, 3), short.end);
    const early = order.find("foobar", 0, .earliest).?;
    try std.testing.expectEqual(@as(usize, 3), early.end);

    var flipped = try Multi.init(alloc, &.{ "foobar", "foo" }, .{});
    defer flipped.deinit();
    const long = flipped.find("foobar", 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 6), long.end);
    const still_early = flipped.find("foobar", 0, .earliest).?;
    try std.testing.expectEqual(@as(usize, 3), still_early.end);
}

test "同一行上的非重叠命中和空模式" {
    var many = try Multi.init(std.testing.allocator, &.{ "aa", "a" }, .{});
    defer many.deinit();
    const first = many.find("aaa", 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 0), first.start);
    try std.testing.expectEqual(@as(usize, 2), first.end);
    const second = many.find("aaa", first.end, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 2), second.start);
    try std.testing.expectEqual(@as(usize, 3), second.end);

    var empty = try Multi.init(std.testing.allocator, &.{ "", "foo" }, .{});
    defer empty.deinit();
    const blank = empty.find("foo", 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 0), blank.end);
    var foo_first = try Multi.init(std.testing.allocator, &.{ "foo", "" }, .{});
    defer foo_first.deinit();
    const word = foo_first.find("foo", 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 3), word.end);
    const miss = foo_first.find("bar", 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 0), miss.end);
}

test "ASCII 忽略大小写，smart 看全部模式" {
    var folded = try Multi.init(std.testing.allocator, &.{ "Ab", "zz" }, .{ .case = .insensitive });
    defer folded.deinit();
    try std.testing.expectEqual(@as(usize, 2), folded.find("xxaby", 0, .leftmost_first).?.start);

    try std.testing.expect(!ignoreCase(&.{ "Foo", "bar" }, .smart));
    try std.testing.expect(ignoreCase(&.{ "foo", "bar" }, .smart));
    var smart = try Multi.init(std.testing.allocator, &.{ "Foo", "bar" }, .{ .case = .smart });
    defer smart.deinit();
    try std.testing.expect(smart.find("foo", 0, .leftmost_first) == null);
    try std.testing.expect(smart.find("BAR", 0, .leftmost_first) == null);
    try std.testing.expectEqual(@as(usize, 0), smart.find("Foo", 0, .leftmost_first).?.start);
}

test "经典失败链和随机对照" {
    var classic = try Multi.init(std.testing.allocator, &.{ "he", "she", "his", "hers" }, .{});
    defer classic.deinit();
    const hit = classic.find("ushers", 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 1), hit.start);
    try std.testing.expectEqual(@as(usize, 4), hit.end);

    var prng = std.Random.DefaultPrng.init(0xA10C);
    const random = prng.random();
    var hay_buf: [48]u8 = undefined;
    var pat_buf: [4][6]u8 = undefined;
    for (0..40) |_| {
        const hlen = random.intRangeAtMost(usize, 0, hay_buf.len);
        random.bytes(hay_buf[0..hlen]);
        var pats: [4][]const u8 = undefined;
        const n = random.intRangeAtMost(usize, 1, 4);
        for (0..n) |k| {
            var plen = random.intRangeAtMost(usize, 0, pat_buf[k].len);
            random.bytes(pat_buf[k][0..plen]);
            for (pat_buf[k][0..plen]) |*byte| {
                if (byte.* == '\n') byte.* = 'x';
            }
            if (plen == 0 and random.boolean()) plen = 1;
            pats[k] = pat_buf[k][0..plen];
        }
        const ignore = random.boolean();
        const start: usize = if (hlen == 0) 0 else random.intRangeAtMost(usize, 0, hlen);
        var multi = try Multi.init(std.testing.allocator, pats[0..n], .{
            .case = if (ignore) .insensitive else .sensitive,
        });
        defer multi.deinit();
        inline for (.{ .earliest, .leftmost_first }) |mode| {
            const got = multi.find(hay_buf[0..hlen], start, mode);
            const expect = naive(hay_buf[0..hlen], start, pats[0..n], ignore, mode);
            if (expect) |want| {
                const have = got orelse return error.TestExpectedEqual;
                try std.testing.expectEqual(want.start, have.start);
                try std.testing.expectEqual(want.end, have.end);
            } else {
                try std.testing.expect(got == null);
            }
        }
    }
}

test "窗口边界、两组桶，以及更晚但更早结束" {
    const pats = [_][]const u8{
        "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota",
    };
    var multi = try Multi.init(std.testing.allocator, &pats, .{});
    defer multi.deinit();
    if (teddy_on) {
        try std.testing.expect(multi.kind == .teddy);
    } else {
        try std.testing.expect(multi.kind == .ac);
    }

    var hay: [48]u8 = @splat('x');
    @memcpy(hay[0..4], "iota");
    @memcpy(hay[15..20], "theta");
    @memcpy(hay[30..35], "alpha");
    inline for (.{ .earliest, .leftmost_first }) |mode| {
        const got = multi.find(&hay, 0, mode).?;
        const expect = naive(&hay, 0, &pats, false, mode).?;
        try std.testing.expectEqual(expect.start, got.start);
        try std.testing.expectEqual(expect.end, got.end);
    }
    const late = multi.find(&hay, 16, .leftmost_first).?;
    const late_want = naive(&hay, 16, &pats, false, .leftmost_first).?;
    try std.testing.expectEqual(late_want.start, late.start);
    try std.testing.expectEqual(@as(usize, 17), late.start);

    var ends = try Multi.init(std.testing.allocator, &.{ "abcdef", "de" }, .{});
    defer ends.deinit();
    const left = ends.find("abcdef", 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 0), left.start);
    try std.testing.expectEqual(@as(usize, 6), left.end);
    const early = ends.find("abcdef", 0, .earliest).?;
    try std.testing.expectEqual(@as(usize, 3), early.start);
    try std.testing.expectEqual(@as(usize, 5), early.end);
}

test "多模式模糊对照" {
    try std.testing.fuzz({}, fuzzMulti, .{});
}

fn fuzzMulti(_: void, smith: *std.testing.Smith) !void {
    var hay_buf: [40]u8 = undefined;
    var storage: [3][5]u8 = undefined;
    const hlen: usize = smith.slice(&hay_buf);
    var pats: [3][]const u8 = undefined;
    const n = smith.valueRangeAtMost(u32, 1, 3);
    for (0..n) |k| {
        var plen: usize = smith.slice(&storage[k]);
        if (plen > storage[k].len) plen = storage[k].len;
        for (storage[k][0..plen]) |*byte| {
            if (byte.* == '\n') byte.* = 'q';
        }
        pats[k] = storage[k][0..plen];
    }
    const ignore = smith.value(bool);
    const start: usize = if (hlen == 0) 0 else smith.valueRangeAtMost(u32, 0, @intCast(hlen));
    var multi = try Multi.init(std.testing.allocator, pats[0..n], .{
        .case = if (ignore) .insensitive else .sensitive,
    });
    defer multi.deinit();
    inline for (.{ .earliest, .leftmost_first }) |mode| {
        const got = multi.find(hay_buf[0..hlen], start, mode);
        const expect = naive(hay_buf[0..hlen], start, pats[0..n], ignore, mode);
        if (expect) |want| {
            const have = got orelse return error.TestExpectedEqual;
            try std.testing.expectEqual(want.start, have.start);
            try std.testing.expectEqual(want.end, have.end);
        } else {
            try std.testing.expect(got == null);
        }
    }
}
