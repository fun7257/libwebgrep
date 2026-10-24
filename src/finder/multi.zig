//! Multi-pattern literal search.
//!
//! When all patterns are single bytes, dispatches to `byteset`. When adjacent byte pairs fit within
//! 16 distinct rules, uses vectorized pair prefiltering without building an automaton.
//! Otherwise, when Teddy is enabled, there are at most 32 patterns, and none are empty, uses Teddy.
//! All remaining cases use Aho-Corasick, which still applies a single-byte SIMD prefilter when
//! anchor bytes fit within 16 distinct values.
//! Teddy is selected via `-Dteddy` (defaults to `neon` on aarch64 and `off` on other architectures).
//!
//! Smart case is evaluated per pattern: a pattern ignores case only if it contains no uppercase letters.
//! When patterns disagree on case sensitivity, search falls back to a scalar scan; when they agree,
//! the SIMD engines above are used. This differs from ripgrep's whole-set smart case; see `matcher.zig`.
//!
//! Pattern bytes are owned by the caller and must not contain newlines. Copying this struct copies only
//! pointers; internal tables are read-only until `deinit` and can be shared across worker threads.
//! Only the creator calls `deinit`. Pattern count and total byte limits are checked before allocating tables.

const std = @import("std");
const aho = @import("aho.zig");
const ascii = @import("ascii.zig");
const build_options = @import("build_options");
const byteset = @import("byteset.zig");
const matcher = @import("../matcher.zig");
const memchr = @import("memchr.zig");
const pairs = @import("pairs.zig");
const unicode_fold = @import("unicode_fold.zig");

const teddy_on = build_options.teddy != .off;
const teddy_mod = if (teddy_on) @import("teddy.zig") else struct {
    pub const Engine = struct {};
};

pub const Multi = struct {
    kind: Kind,
    ignore_case: bool,
    empty_only: bool,
    /// Owned by the caller. Used for whole-line comparison and whole-word per-pattern verification without copying pattern bytes.
    patterns: []const []const u8,
    owned_patterns: ?[][]const u8 = null,
    owned_variant_bytes: ?[][]u8 = null,
    patterns_alloc: ?std.mem.Allocator = null,

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
        // Reject limit violations before allocating pair tables, Teddy, or the automaton.
        try matcher.checkPatternLimits(patterns, options);
        for (patterns) |pat| {
            if (std.mem.findScalar(u8, pat, '\n') != null) return error.PatternHasNewline;
        }
        if (options.unicode_case and options.case != .sensitive and anyNeedsUnicodeFold(patterns, options)) {
            return initUnicodeFolded(allocator, patterns, options);
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

    /// Builds a multi-pattern finder from newline-separated pattern text. Each line is one pattern,
    /// stripping a single trailing CR before LF. Empty lines represent empty patterns that match every line.
    /// Accepts in-memory text only and never reads filesystem paths.
    /// Pattern count and total byte limits are checked before allocating pattern slices or internal tables.
    /// The `text` bytes remain owned by the caller.
    pub fn initFromText(
        allocator: std.mem.Allocator,
        text: []const u8,
        options: matcher.FindOptions,
    ) (matcher.LimitError || error{ PatternHasNewline, OutOfMemory })!Multi {
        const count_limit = matcher.patternCountLimit(options);
        const byte_limit = matcher.patternBytesLimit(options);
        var count: usize = 0;
        var total_bytes: usize = 0;
        var pos: usize = 0;
        while (pos < text.len) {
            count += 1;
            if (count > count_limit) return error.PatternCountExceeded;
            const nl = memchr.find(memchr.native_width, text, pos, '\n') orelse text.len;
            var end = nl;
            if (end > pos and text[end - 1] == '\r') end -= 1;
            const len = end - pos;
            total_bytes = std.math.add(usize, total_bytes, len) catch return error.PatternBytesExceeded;
            if (total_bytes > byte_limit) return error.PatternBytesExceeded;
            pos = if (nl < text.len) nl + 1 else text.len;
        }
        const list = try allocator.alloc([]const u8, count);
        errdefer allocator.free(list);
        pos = 0;
        var idx: usize = 0;
        while (pos < text.len) : (idx += 1) {
            const nl = memchr.find(memchr.native_width, text, pos, '\n') orelse text.len;
            var end = nl;
            if (end > pos and text[end - 1] == '\r') end -= 1;
            list[idx] = text[pos..end];
            pos = if (nl < text.len) nl + 1 else text.len;
        }
        var self = try init(allocator, list, options);
        if (self.owned_patterns != null) {
            allocator.free(list);
        } else {
            self.owned_patterns = list;
            self.patterns_alloc = allocator;
        }
        return self;
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
        if (self.owned_variant_bytes) |variants| {
            if (self.patterns_alloc) |alloc| {
                for (variants) |v| alloc.free(v);
                alloc.free(variants);
            }
        }
        if (self.owned_patterns) |list| {
            if (self.patterns_alloc) |alloc| alloc.free(list);
        }
        self.* = undefined;
    }

    pub fn isEmpty(self: *const Multi) bool {
        return self.empty_only;
    }

    /// Used by microbenchmarks to verify which engine was selected. Changing dispatch rules will fail scenario tests.
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

    /// Whether the line span equals any pattern, using each pattern's own case-folding rule.
    pub fn acceptsSpan(self: *const Multi, haystack: []const u8, start: usize, end: usize) bool {
        if (start > end or end > haystack.len) return false;
        const span = haystack[start..end];
        for (self.patterns, 0..) |pat, i| {
            if (ascii.eql(pat, span, self.foldOf(i))) return true;
        }
        return false;
    }

    /// Verifies each pattern individually so another pattern at the same start position can still pass `allow`.
    /// Required for whole-word matching: an engine returns only one match per position, so if a shorter
    /// pattern is rejected by a word boundary, a longer pattern at the same start may still succeed.
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
        switch (self.kind) {
            .bytes => |*set| {
                const at = set.findWatchingNul(haystack, start, nul) orelse return null;
                return .{ .start = at, .end = at + 1 };
            },
            .pairs => |*engine| return engine.findWatchingNul(haystack, start, .earliest, nul),
            .ac => |*ac| return ac.findWatchingNul(haystack, start, .earliest, nul),
            .teddy => |*engine| {
                if (comptime teddy_on) return engine.findWatchingNul(haystack, start, .earliest, nul);
                unreachable;
            },
            .mixed => {
                const hit = self.scan(haystack, start, .earliest, allowAll);
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
            },
        }
    }
};

fn allowAll(haystack: []const u8, start: usize, end: usize) bool {
    _ = haystack;
    _ = start;
    _ = end;
    return true;
}

/// Returns whether this single pattern ignores ASCII case under `mode`.
/// In `smart` mode, only this pattern is inspected: it folds case iff it has no uppercase letters.
/// Another pattern containing uppercase letters does not force this pattern to be case-sensitive.
pub fn patternIgnoresCase(pattern: []const u8, mode: matcher.CaseMode) bool {
    return switch (mode) {
        .sensitive => false,
        .insensitive => true,
        .smart => !ascii.patternHasUpper(pattern),
    };
}

pub fn patternIgnoresCaseUnicode(pattern: []const u8, mode: matcher.CaseMode) bool {
    return switch (mode) {
        .sensitive => false,
        .insensitive => true,
        .smart => !unicode_fold.patternHasUnicodeUpper(pattern),
    };
}

fn anyNeedsUnicodeFold(patterns: []const []const u8, options: matcher.FindOptions) bool {
    for (patterns) |pat| {
        if (unicode_fold.needsUnicodeExpansion(pat) or unicode_fold.patternHasUnicodeUpper(pat)) return true;
    }
    _ = options;
    return false;
}

fn initUnicodeFolded(
    allocator: std.mem.Allocator,
    patterns: []const []const u8,
    options: matcher.FindOptions,
) (matcher.LimitError || error{ PatternHasNewline, OutOfMemory })!Multi {
    var variant_bytes = std.ArrayList([]u8).empty;
    errdefer {
        for (variant_bytes.items) |v| allocator.free(v);
        variant_bytes.deinit(allocator);
    }
    var variant_flags = std.ArrayList(bool).empty;
    defer variant_flags.deinit(allocator);

    for (patterns) |pat| {
        const ig = patternIgnoresCaseUnicode(pat, options.case);
        if (ig and unicode_fold.needsUnicodeExpansion(pat)) {
            const before = variant_bytes.items.len;
            try unicode_fold.expandPatternVariants(allocator, pat, &variant_bytes, 32);
            const added = variant_bytes.items.len - before;
            try variant_flags.appendNTimes(allocator, true, added);
        } else {
            const copy = try allocator.dupe(u8, pat);
            errdefer allocator.free(copy);
            try variant_bytes.append(allocator, copy);
            try variant_flags.append(allocator, ig);
        }
    }

    const owned_slices = try allocator.alloc([]const u8, variant_bytes.items.len);
    errdefer allocator.free(owned_slices);
    for (variant_bytes.items, 0..) |v, i| owned_slices[i] = v;

    try matcher.checkPatternLimits(owned_slices, options);

    const owned_variants = try variant_bytes.toOwnedSlice(allocator);
    errdefer {
        for (owned_variants) |v| allocator.free(v);
        allocator.free(owned_variants);
    }

    var all_same = true;
    const first_flag = if (variant_flags.items.len > 0) variant_flags.items[0] else true;
    for (variant_flags.items) |fl| {
        if (fl != first_flag) {
            all_same = false;
            break;
        }
    }

    if (all_same) {
        var plain_opts = options;
        plain_opts.unicode_case = false;
        plain_opts.case = if (first_flag) .insensitive else .sensitive;
        var res = try Multi.init(allocator, owned_slices, plain_opts);
        res.owned_patterns = owned_slices;
        res.owned_variant_bytes = owned_variants;
        res.patterns_alloc = allocator;
        return res;
    }

    const flags = try allocator.dupe(bool, variant_flags.items);
    return .{
        .kind = .{ .mixed = .{
            .ignore = flags,
            .allocator = allocator,
        } },
        .ignore_case = false,
        .empty_only = false,
        .patterns = owned_slices,
        .owned_patterns = owned_slices,
        .owned_variant_bytes = owned_variants,
        .patterns_alloc = allocator,
    };
}

/// Returns the shared case-insensitivity flag when all patterns agree, or null when `smart` mode produces mixed sensitivity.
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

/// Patterns shared between microbenchmarks and scenario tests; see `fillScenarioText` for the input shape.
/// `scenario_bytes` uses two single bytes absent from the sample text. `scenario_pairs` includes the trailing `NEEDLE`.
/// 17 two-byte patterns exceed the 16-rule limit of `pairs`, routing to Teddy when enabled or Aho-Corasick otherwise.
/// 33 patterns exceed Teddy's 32-pattern limit, routing to Aho-Corasick. None of those digram bytes appear in the sample text.
pub const scenario_bytes: []const []const u8 = &.{ "Q", "Z" };
pub const scenario_pairs: []const []const u8 = &.{ "NEEDLE", "ZXZQ" };
pub const scenario_teddy: []const []const u8 = digram_pats[0..17];
pub const scenario_ac: []const []const u8 = &digram_pats;

/// Benchmark text: filled with `'a'`, a newline every 64 bytes, and `NEEDLE\n` overwritten at the end.
/// `bench/micro.zig` and scenario tests share this shape. The buffer must hold at least the trailing 7 bytes.
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

test "newline error, empty set, single bytes, and pattern priority order" {
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

test "non-overlapping matches on the same line and empty patterns" {
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

test "smart case is evaluated per pattern" {
    var folded = try Multi.init(std.testing.allocator, &.{ "Ab", "zz" }, .{ .case = .insensitive });
    defer folded.deinit();
    try std.testing.expect(folded.kind != .mixed);
    try std.testing.expectEqual(@as(usize, 2), folded.find("xxaby", 0, .leftmost_first).?.start);

    try std.testing.expect(!patternIgnoresCase("Foo", .smart));
    try std.testing.expect(patternIgnoresCase("bar", .smart));
    try std.testing.expect(patternIgnoresCase("foo", .smart));

    // "Foo" contains uppercase and stays case-sensitive; "bar" is all lowercase and folds case independently.
    // By contrast, ripgrep would make "bar" case-sensitive because "Foo" is in the same pattern set.
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

test "classic failure links and random differential" {
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

test "falls back to Teddy or automaton when adjacent pairs exceed capacity" {
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

test "window boundaries, adjacent pairs, and later-starting match ending earlier" {
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

test "second stride: adjacent pairs miss full window before hitting" {
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

test "second stride: Teddy 4-window or automaton matches naive search" {
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

test "all single-byte patterns use byteset and match naive search on second stride" {
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

test "benchmark scenario patterns dispatch to their expected engines" {
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

    // The sample text does not contain patterns from these three sets; plant a pattern byte to verify they match.
    hay[80] = scenario_bytes[0][0];
    try std.testing.expectEqual(@as(usize, 80), bytes.find(&hay, 0, .earliest).?.start);

    hay[80] = 'a';
    @memcpy(hay[90..][0..2], scenario_teddy[0]);
    try std.testing.expectEqual(@as(usize, 90), teddy.find(&hay, 0, .earliest).?.start);

    @memset(hay[90..][0..2], 'a');
    @memcpy(hay[120..][0..2], scenario_ac[32]);
    try std.testing.expectEqual(@as(usize, 120), ac.find(&hay, 0, .earliest).?.start);
}

test "multi-pattern fuzz differential" {
    try std.testing.fuzz({}, fuzzMulti, .{});
}

test "empty line pattern matches all lines and limit violations are rejected before allocation" {
    var empty_multi = try Multi.initFromText(std.testing.allocator, "foo\r\n\r\nbar\n", .{});
    defer empty_multi.deinit();
    try std.testing.expectEqual(@as(usize, 3), empty_multi.patterns.len);
    try std.testing.expectEqualStrings("foo", empty_multi.patterns[0]);
    try std.testing.expectEqualStrings("", empty_multi.patterns[1]);
    try std.testing.expectEqualStrings("bar", empty_multi.patterns[2]);
    const hit = empty_multi.find("anything", 0, .earliest).?;
    try std.testing.expectEqual(@as(usize, 0), hit.start);
    try std.testing.expectEqual(@as(usize, 0), hit.end);

    var fail_alloc = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(
        error.PatternCountExceeded,
        Multi.initFromText(fail_alloc.allocator(), "a\nb\nc\n", .{ .max_pattern_count = 2 }),
    );
    try std.testing.expectError(
        error.PatternBytesExceeded,
        Multi.initFromText(fail_alloc.allocator(), "abcd\nefgh\n", .{ .max_pattern_bytes = 6 }),
    );
    try std.testing.expectEqual(@as(usize, 0), fail_alloc.allocations);
}

test "Unicode case folding applies smart case per pattern" {
    // 1. Within the same Multi set: "Δelta" contains uppercase Greek Δ and stays case-sensitive under smart case;
    //    "σigma" is all lowercase and folds under smart case to match Σigma / σigma / ςigma.
    var smart_uni = try Multi.init(std.testing.allocator, &.{ "Δelta", "σigma" }, .{
        .case = .smart,
        .unicode_case = true,
    });
    defer smart_uni.deinit();

    try std.testing.expect(smart_uni.find("δelta", 0, .earliest) == null);
    try std.testing.expectEqual(@as(usize, 0), smart_uni.find("Δelta", 0, .earliest).?.start);
    try std.testing.expectEqual(@as(usize, 0), smart_uni.find("ΣIGMA", 0, .earliest).?.start);
    try std.testing.expectEqual(@as(usize, 0), smart_uni.find("ςigma", 0, .earliest).?.start);

    // 2. All-lowercase Unicode pattern sets dispatch directly to a SIMD engine (not `mixed`) and support cross-ASCII folding (e.g., Kelvin K U+212A <-> k).
    var all_lower = try Multi.init(std.testing.allocator, &.{ "δelta", "kelvin" }, .{
        .case = .smart,
        .unicode_case = true,
    });
    defer all_lower.deinit();
    try std.testing.expect(!std.mem.eql(u8, "mixed", all_lower.engineName()));
    try std.testing.expectEqual(@as(usize, 0), all_lower.find("ΔELTA", 0, .earliest).?.start);
    try std.testing.expectEqual(@as(usize, 0), all_lower.find("\u{212A}ELVIN", 0, .earliest).?.start);
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
