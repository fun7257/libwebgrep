//! 多模式字面量。
//!
//! 全部是单字节时走字节集。邻接对不超过 16 种时走向量过滤，不建自动机。
//! 否则在 Teddy 打得开、不超过 32 个且没有空模式时走 Teddy。剩下走 Aho-Corasick，
//! 锚点字节不超过 16 种时自动机仍先做单字节向量预过滤。
//! Teddy 由 `-Dteddy` 选择。aarch64 默认是 neon，其他架构默认关闭。
//!
//! 智能大小写按每条模式判断：全是小写才忽略大小写。判断不一致时走标量扫描，
//! 一致时仍走上面的引擎。这和 rg 整组判断不同，说明写在 `matcher.zig`。
//!
//! 模式字节由调用方持有，并且不能含有换行。复制本结构只复制指针，表在
//! `deinit` 之前只读，工人可以共享。只有创建者调用 `deinit`。
//! 条数和字节总长在分配这些表之前检查。

const std = @import("std");
const aho = @import("aho.zig");
const ascii = @import("ascii.zig");
const build_options = @import("build_options");
const byteset = @import("byteset.zig");
const matcher = @import("../matcher.zig");
const memchr = @import("memchr.zig");
const pairs = @import("pairs.zig");

const teddy_on = build_options.teddy != .off;
const teddy_mod = if (teddy_on) @import("teddy.zig") else struct {
    pub const Engine = struct {};
};

pub const Multi = struct {
    kind: Kind,
    ignore_case: bool,
    empty_only: bool,
    /// 调用方持有。整行比较和整词的逐条确认用它，不另外复制模式字节。
    patterns: []const []const u8,

    const Mixed = struct {
        ignore: []bool,
        allocator: std.mem.Allocator,
    };

    const Kind = union(enum) {
        bytes: byteset.Set,
        pairs: pairs.Engine,
        ac: aho.Ac,
        teddy: if (teddy_on) teddy_mod.Engine else void,
        mixed: Mixed,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        patterns: []const []const u8,
        options: matcher.FindOptions,
    ) (matcher.LimitError || error{ PatternHasNewline, OutOfMemory })!Multi {
        // 超限在分配邻接对表、Teddy 或自动机之前返回，调用方还没开始扫描。
        try matcher.checkPatternLimits(patterns, options);
        for (patterns) |pat| {
            if (std.mem.findScalar(u8, pat, '\n') != null) return error.PatternHasNewline;
        }
        if (uniformIgnore(patterns, options.case)) |ignore| {
            if (allSingleByte(patterns)) {
                return .{
                    .kind = .{ .bytes = byteset.Set.init(patterns, ignore) },
                    .ignore_case = ignore,
                    .empty_only = false,
                    .patterns = patterns,
                };
            }
            if (try pairs.Engine.create(allocator, patterns, ignore)) |engine| {
                return .{
                    .kind = .{ .pairs = engine },
                    .ignore_case = ignore,
                    .empty_only = false,
                    .patterns = patterns,
                };
            }
            if (comptime teddy_on) {
                if (teddyEligible(patterns)) {
                    return .{
                        .kind = .{ .teddy = teddy_mod.Engine.init(patterns, ignore) },
                        .ignore_case = ignore,
                        .empty_only = false,
                        .patterns = patterns,
                    };
                }
            }
            return .{
                .kind = .{ .ac = try aho.build(allocator, patterns, ignore) },
                .ignore_case = ignore,
                .empty_only = onlyEmpty(patterns),
                .patterns = patterns,
            };
        }

        const flags = try allocator.alloc(bool, patterns.len);
        errdefer allocator.free(flags);
        for (patterns, flags) |pat, *flag| flag.* = patternIgnoresCase(pat, .smart);
        return .{
            .kind = .{ .mixed = .{
                .ignore = flags,
                .allocator = allocator,
            } },
            .ignore_case = false,
            .empty_only = false,
            .patterns = patterns,
        };
    }

    pub fn deinit(self: *Multi) void {
        switch (self.kind) {
            .bytes => {},
            .pairs => |*engine| engine.deinit(),
            .ac => |*ac| ac.deinit(),
            .teddy => |*engine| {
                if (comptime teddy_on) engine.deinit();
            },
            .mixed => |*mixed| mixed.allocator.free(mixed.ignore),
        }
        self.* = undefined;
    }

    pub fn isEmpty(self: *const Multi) bool {
        return self.empty_only;
    }

    /// 微基准用来核对这次落到哪条引擎。改分派时基准场景测试会失败。
    pub fn engineName(self: *const Multi) []const u8 {
        return switch (self.kind) {
            .bytes => "bytes",
            .pairs => "pairs",
            .ac => "ac",
            .teddy => "teddy",
            .mixed => "mixed",
        };
    }

    pub fn resetStats(self: *Multi) void {
        _ = self;
    }

    pub fn find(self: *Multi, haystack: []const u8, start: usize, mode: matcher.MatchMode) ?matcher.Match {
        if (self.kind == .mixed) return self.scan(haystack, start, mode, allowAll);
        switch (self.kind) {
            .bytes => |*set| {
                const at = set.find(haystack, start) orelse return null;
                return .{ .start = at, .end = at + 1 };
            },
            .pairs => |*engine| return engine.find(haystack, start, mode),
            .ac => |*ac| return ac.find(haystack, start, mode),
            .teddy => |*engine| {
                if (comptime teddy_on) return engine.find(haystack, start, mode);
                unreachable;
            },
            .mixed => unreachable,
        }
    }

    /// 行内容是否和其中某一条模式相同。大小写按那一条自己的规则。
    pub fn acceptsSpan(self: *const Multi, haystack: []const u8, start: usize, end: usize) bool {
        if (start > end or end > haystack.len) return false;
        const span = haystack[start..end];
        for (self.patterns, 0..) |pat, i| {
            if (ascii.eql(pat, span, self.foldOf(i))) return true;
        }
        return false;
    }

    /// 逐条确认，让同一起点上没被选中的另一条模式仍能通过 `allow`。
    /// 整词要用这个：引擎只返回一条，短的那条被词边界拒绝时，长的那条可能成立。
    pub fn findAllowed(
        self: *Multi,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        comptime allow: fn ([]const u8, usize, usize) bool,
    ) ?matcher.Match {
        return self.scan(haystack, start, mode, allow);
    }

    fn foldOf(self: *const Multi, index: usize) bool {
        switch (self.kind) {
            .mixed => |*mixed| return mixed.ignore[index],
            else => return self.ignore_case,
        }
    }

    fn scan(
        self: *const Multi,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        comptime allow: fn ([]const u8, usize, usize) bool,
    ) ?matcher.Match {
        if (start > haystack.len) return null;
        const flags: ?[]const bool = switch (self.kind) {
            .mixed => |*mixed| mixed.ignore,
            else => null,
        };
        var best: ?Naive = null;
        var i = start;
        while (i <= haystack.len) : (i += 1) {
            for (self.patterns, 0..) |pat, id_usize| {
                if (i + pat.len > haystack.len) continue;
                const fold = if (flags) |list| list[id_usize] else self.ignore_case;
                if (!ascii.eql(pat, haystack[i..][0..pat.len], fold)) continue;
                if (!allow(haystack, i, i + pat.len)) continue;
                const cand = Naive{ .start = i, .end = i + pat.len, .id = @intCast(id_usize) };
                if (best) |cur| {
                    if (better(cand, cur, mode)) best = cand;
                } else best = cand;
            }
            if (mode == .leftmost_first) {
                if (best) |cand| return .{ .start = cand.start, .end = cand.end };
            } else if (best) |cand| {
                if (i >= cand.end) return .{ .start = cand.start, .end = cand.end };
            }
        }
        const found = best orelse return null;
        return .{ .start = found.start, .end = found.end };
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

fn allowAll(haystack: []const u8, start: usize, end: usize) bool {
    _ = haystack;
    _ = start;
    _ = end;
    return true;
}

/// 这一条模式在 `mode` 下是否忽略 ASCII 大小写。
/// `smart` 只看这一条：全是小写才折叠。旁边有大写的模式不会把这一条改成区分大小写。
pub fn patternIgnoresCase(pattern: []const u8, mode: matcher.CaseMode) bool {
    return switch (mode) {
        .sensitive => false,
        .insensitive => true,
        .smart => !ascii.patternHasUpper(pattern),
    };
}

/// 全部模式的大小写判断一致时返回那个值。`smart` 下不一致则返回 null。
fn uniformIgnore(patterns: []const []const u8, mode: matcher.CaseMode) ?bool {
    switch (mode) {
        .sensitive => return false,
        .insensitive => return true,
        .smart => {
            if (patterns.len == 0) return true;
            const first = patternIgnoresCase(patterns[0], .smart);
            for (patterns[1..]) |pat| {
                if (patternIgnoresCase(pat, .smart) != first) return null;
            }
            return first;
        },
    }
}

fn allSingleByte(patterns: []const []const u8) bool {
    if (patterns.len == 0) return false;
    for (patterns) |pat| if (pat.len != 1) return false;
    return true;
}

const digram_store = blk: {
    const n = 33;
    var storage: [n][2]u8 = undefined;
    for (0..n) |i| {
        storage[i] = .{ 0x80 + @as(u8, @intCast(i)), 0xC0 + @as(u8, @intCast(i)) };
    }
    break :blk storage;
};

const digram_pats = blk: {
    var pats: [digram_store.len][]const u8 = undefined;
    for (0..digram_store.len) |i| pats[i] = &digram_store[i];
    break :blk pats;
};

/// 微基准和场景测试共用这些模式。文本形状见 `fillScenarioText`。
/// 字节集是两个不会出现的单字节。邻接对里有末尾那个 `NEEDLE`。
/// 17 条双字节超过邻接对的 16 条上限，Teddy 开着时走 Teddy，否则走自动机。
/// 33 条超过 Teddy 的 32 条上限，只能走自动机。这些字节都不在样例文本里。
pub const scenario_bytes: []const []const u8 = &.{ "Q", "Z" };
pub const scenario_pairs: []const []const u8 = &.{ "NEEDLE", "ZXZQ" };
pub const scenario_teddy: []const []const u8 = digram_pats[0..17];
pub const scenario_ac: []const []const u8 = &digram_pats;

/// 基准文本：全是 `a`，每 64 字节一个换行，末尾盖上 `NEEDLE\n`。
/// `bench/micro.zig` 和场景测试用同一形状。缓冲至少要容得下末尾那 7 个字节。
pub fn fillScenarioText(buf: []u8) void {
    const needle = "NEEDLE\n";
    std.debug.assert(buf.len >= needle.len);
    @memset(buf, 'a');
    var i: usize = 63;
    while (i < buf.len) : (i += 64) buf[i] = '\n';
    @memcpy(buf[buf.len - needle.len ..], needle);
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

test "智能大小写按每个模式判断" {
    var folded = try Multi.init(std.testing.allocator, &.{ "Ab", "zz" }, .{ .case = .insensitive });
    defer folded.deinit();
    try std.testing.expect(folded.kind != .mixed);
    try std.testing.expectEqual(@as(usize, 2), folded.find("xxaby", 0, .leftmost_first).?.start);

    try std.testing.expect(!patternIgnoresCase("Foo", .smart));
    try std.testing.expect(patternIgnoresCase("bar", .smart));
    try std.testing.expect(patternIgnoresCase("foo", .smart));

    // Foo 含大写，仍区分大小写。bar 全是小写，单独忽略大小写。
    // rg 会因为整组里有 Foo 而让 bar 也区分大小写。
    var smart = try Multi.init(std.testing.allocator, &.{ "Foo", "bar" }, .{ .case = .smart });
    defer smart.deinit();
    try std.testing.expect(smart.kind == .mixed);
    try std.testing.expect(smart.find("foo", 0, .leftmost_first) == null);
    try std.testing.expectEqual(@as(usize, 0), smart.find("BAR", 0, .leftmost_first).?.start);
    try std.testing.expectEqual(@as(usize, 0), smart.find("Foo", 0, .leftmost_first).?.start);
    try std.testing.expectEqual(@as(usize, 0), smart.find("Bar", 0, .leftmost_first).?.start);
    try std.testing.expectEqual(@as(usize, 0), smart.find("FooBAR", 0, .earliest).?.start);
    try std.testing.expectEqual(@as(usize, 3), smart.find("FooBAR", 0, .earliest).?.end);

    var lower = try Multi.init(std.testing.allocator, &.{ "foo", "bar" }, .{ .case = .smart });
    defer lower.deinit();
    try std.testing.expect(lower.kind != .mixed);
    try std.testing.expectEqual(@as(usize, 0), lower.find("FOO", 0, .leftmost_first).?.start);
    try std.testing.expectEqual(@as(usize, 0), lower.find("BAR", 0, .leftmost_first).?.start);

    var mixed_case = try Multi.init(std.testing.allocator, &.{ "Ab", "zz" }, .{ .case = .smart });
    defer mixed_case.deinit();
    try std.testing.expect(mixed_case.find("ab", 0, .leftmost_first) == null);
    try std.testing.expectEqual(@as(usize, 0), mixed_case.find("Ab", 0, .leftmost_first).?.start);
    try std.testing.expectEqual(@as(usize, 0), mixed_case.find("ZZ", 0, .leftmost_first).?.start);
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

test "邻接对放不下时走 Teddy 或自动机" {
    var buf: [17][2]u8 = undefined;
    var pats: [17][]const u8 = undefined;
    for (&buf, 0..) |*slot, i| {
        slot[0] = @intCast(32 + i);
        slot[1] = @intCast(160 + i);
        pats[i] = slot;
    }
    var multi = try Multi.init(std.testing.allocator, &pats, .{});
    defer multi.deinit();
    if (teddy_on) {
        try std.testing.expect(multi.kind == .teddy);
    } else {
        try std.testing.expect(multi.kind == .ac);
    }
    var hay: [4]u8 = .{ 0, 0, 0, 0 };
    @memcpy(hay[1..3], pats[3]);
    const got = multi.find(&hay, 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 1), got.start);
    try std.testing.expectEqual(@as(usize, 3), got.end);
}

test "窗口边界、邻接对，以及更晚但更早结束" {
    const pats = [_][]const u8{
        "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta", "theta", "iota",
    };
    var multi = try Multi.init(std.testing.allocator, &pats, .{});
    defer multi.deinit();
    try std.testing.expect(multi.kind == .pairs);

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

const vec_width = memchr.native_width;

fn expectNaive(multi: *Multi, hay: []const u8, pats: []const []const u8) !void {
    inline for (.{ .earliest, .leftmost_first }) |mode| {
        var pos: usize = 0;
        while (pos <= hay.len) {
            const got = multi.find(hay, pos, mode);
            const want = naive(hay, pos, pats, false, mode);
            if (want) |match| {
                const have = got orelse return error.TestExpectedEqual;
                try std.testing.expectEqual(match.start, have.start);
                try std.testing.expectEqual(match.end, have.end);
                pos = have.end;
            } else {
                try std.testing.expect(got == null);
                break;
            }
        }
    }
}

test "第二跨：邻接对先整窗未命中，再命中" {
    const stride = vec_width * 8;
    const pats = [_][]const u8{ "lp", "be" };
    var multi = try Multi.init(std.testing.allocator, &pats, .{});
    defer multi.deinit();
    try std.testing.expect(multi.kind == .pairs);

    var missed: [stride * 2 + vec_width]u8 = @splat('x');
    const deep = stride + 4;
    missed[deep] = 'l';
    missed[deep + 1] = 'p';
    try std.testing.expectEqual(deep, multi.find(&missed, 0, .leftmost_first).?.start);
    try expectNaive(&multi, &missed, &pats);

    var edge: [stride * 2 + vec_width]u8 = @splat('x');
    edge[stride - 1] = 'l';
    edge[stride] = 'p';
    edge[stride + vec_width] = 'b';
    edge[stride + vec_width + 1] = 'e';
    try std.testing.expectEqual(stride - 1, multi.find(&edge, 0, .leftmost_first).?.start);
    try expectNaive(&multi, &edge, &pats);
}

test "第二跨：Teddy 四窗或自动机，和朴素查找一致" {
    var buf: [17][2]u8 = undefined;
    var pats: [17][]const u8 = undefined;
    for (&buf, 0..) |*slot, i| {
        slot[0] = @intCast(32 + i);
        slot[1] = @intCast(160 + i);
        pats[i] = slot;
    }
    var multi = try Multi.init(std.testing.allocator, &pats, .{});
    defer multi.deinit();
    if (teddy_on) {
        try std.testing.expect(multi.kind == .teddy);
    } else {
        try std.testing.expect(multi.kind == .ac);
    }

    var inside: [96]u8 = @splat('x');
    @memcpy(inside[50..][0..2], pats[3]);
    try std.testing.expectEqual(@as(usize, 50), multi.find(&inside, 0, .leftmost_first).?.start);
    try expectNaive(&multi, &inside, &pats);

    var skipped: [160]u8 = @splat('x');
    @memcpy(skipped[96..][0..2], pats[5]);
    try std.testing.expectEqual(@as(usize, 96), multi.find(&skipped, 0, .leftmost_first).?.start);
    try expectNaive(&multi, &skipped, &pats);
}

test "全是单字节时走字节集，第二跨和朴素查找一致" {
    const stride = vec_width * 4;
    var one_buf: [1]u8 = .{'q'};
    const one_pats = [_][]const u8{&one_buf};
    var one = try Multi.init(std.testing.allocator, &one_pats, .{});
    defer one.deinit();
    try std.testing.expect(one.kind == .bytes);

    var many_buf: [17][1]u8 = undefined;
    var many_pats: [17][]const u8 = undefined;
    for (&many_buf, 0..) |*slot, i| {
        slot[0] = @intCast(32 + i);
        many_pats[i] = slot;
    }
    var many = try Multi.init(std.testing.allocator, &many_pats, .{});
    defer many.deinit();
    try std.testing.expect(many.kind == .bytes);

    var hay: [stride * 2 + 4]u8 = @splat(0);
    hay[stride + 1] = 48;
    try std.testing.expectEqual(stride + 1, many.find(&hay, 0, .leftmost_first).?.start);
    try expectNaive(&many, &hay, &many_pats);
    try std.testing.expect(many.find(&hay, stride + 2, .leftmost_first) == null);
}

test "基准场景的模式落到各自的引擎" {
    try std.testing.expectEqual(@as(usize, 17), scenario_teddy.len);
    try std.testing.expectEqual(@as(usize, 33), scenario_ac.len);

    var bytes = try Multi.init(std.testing.allocator, scenario_bytes, .{});
    defer bytes.deinit();
    try std.testing.expectEqualStrings("bytes", bytes.engineName());

    var pairs_engine = try Multi.init(std.testing.allocator, scenario_pairs, .{});
    defer pairs_engine.deinit();
    try std.testing.expectEqualStrings("pairs", pairs_engine.engineName());

    var teddy = try Multi.init(std.testing.allocator, scenario_teddy, .{});
    defer teddy.deinit();
    const teddy_name = if (teddy_on) "teddy" else "ac";
    try std.testing.expectEqualStrings(teddy_name, teddy.engineName());

    var ac = try Multi.init(std.testing.allocator, scenario_ac, .{});
    defer ac.deinit();
    try std.testing.expectEqualStrings("ac", ac.engineName());

    var hay: [256]u8 = undefined;
    fillScenarioText(&hay);
    const needle_at = hay.len - "NEEDLE\n".len;
    try std.testing.expect(bytes.find(&hay, 0, .earliest) == null);
    const pair_hit = pairs_engine.find(&hay, 0, .earliest).?;
    try std.testing.expectEqual(needle_at, pair_hit.start);
    try std.testing.expectEqual(needle_at + "NEEDLE".len, pair_hit.end);
    try std.testing.expect(teddy.find(&hay, 0, .earliest) == null);
    try std.testing.expect(ac.find(&hay, 0, .earliest) == null);

    // 样例文本本身命中不了这三组。种进一个模式字节，确认不是空转。
    hay[80] = scenario_bytes[0][0];
    try std.testing.expectEqual(@as(usize, 80), bytes.find(&hay, 0, .earliest).?.start);

    hay[80] = 'a';
    @memcpy(hay[90..][0..2], scenario_teddy[0]);
    try std.testing.expectEqual(@as(usize, 90), teddy.find(&hay, 0, .earliest).?.start);

    @memset(hay[90..][0..2], 'a');
    @memcpy(hay[120..][0..2], scenario_ac[32]);
    try std.testing.expectEqual(@as(usize, 120), ac.find(&hay, 0, .earliest).?.start);
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
