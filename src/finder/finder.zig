//! Single-pattern literal finder.
//! Single-byte patterns use memchr. Patterns up to 32 bytes use SIMD packed pair and complete verification directly.
//! Longer patterns still use packed pair, falling back to Two-Way when the two rare bytes are close together and verification repeatedly fails.
//! Does not allocate memory. Pattern bytes are owned by the caller and must not contain newlines.

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
    /// Number of candidates seen by packed pair during this lifetime. Can be cleared with `resetStats`.
    candidates: u32 = 0,
    confirms: u32 = 0,
    /// Once true, subsequent searches use Two-Way.
    use_two_way: bool = false,
    two_way: two_way.TwoWay,

    const Kind = union(enum) {
        empty,
        byte: u8,
        pair: packed_pair.PackedPair,
    };

    pub fn init(pattern: []const u8, options: matcher.FindOptions) (matcher.LimitError || error{PatternHasNewline})!Finder {
        try matcher.checkPatternLimits(&.{pattern}, options);
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

    /// For a single literal, `earliest` and `leftmost_first` produce the same match.
    /// Kept separate from NUL watching so it can be inlined into tight search loops on dense hits.
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

    /// Same as `find`, additionally writing the first NUL within the scanned span to `nul`.
    /// When returning a match, only guarantees no NUL precedes the match start.
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

    /// For future regex prefiltering. When case-insensitive, bytes remain the raw pattern and must not be treated as a case-sensitive required substring.
    pub fn requiredLiteral(self: *const Finder) ?matcher.RequiredLiteral {
        if (self.pattern.len == 0) return null;
        return .{ .bytes = self.pattern, .offset_in_match = 0 };
    }

    /// Called at the start of each new input so false positives from a previous input do not lock this input into Two-Way.
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

        // Short patterns have a constant-factor linear worst case, so they never switch to scalar Two-Way.
        // Long patterns switch only when the caller lowers the threshold below 1 and the prefilter fails to make progress.
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

    /// Whether the line content (excluding newline and a trailing CR) equals this pattern.
    pub fn acceptsSpan(self: *const Finder, haystack: []const u8, start: usize, end: usize) bool {
        if (start > end or end > haystack.len) return false;
        return ascii.eql(self.pattern, haystack[start..end], self.ignore_case);
    }

    /// Same as `find`, advancing one byte past the match start when `allow` rejects a candidate.
    /// A single pattern has only one possible length at any given start position.
    pub fn findAllowed(
        self: *Finder,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        comptime allow: fn ([]const u8, usize, usize) bool,
    ) ?matcher.Match {
        var pos = start;
        while (pos <= haystack.len) {
            const found = self.find(haystack, pos, mode) orelse return null;
            if (found.start < pos) return null;
            if (allow(haystack, found.start, found.end)) return found;
            if (found.start >= haystack.len) return null;
            pos = found.start + 1;
        }
        return null;
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

test "newline error, empty pattern, single byte, and smart case" {
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

test "multi-byte match: short patterns do not switch to Two-Way on frequent bytes" {
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

test "long pattern switches to Two-Way when rare bytes cluster and still finds match" {
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

test "Finder matches naive search" {
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

test "required literal" {
    var finder = try Finder.init("abc", .{});
    const lit = finder.requiredLiteral().?;
    try std.testing.expectEqualStrings("abc", lit.bytes);
    try std.testing.expectEqual(@as(usize, 0), lit.offset_in_match);
    var empty = try Finder.init("", .{});
    try std.testing.expect(empty.requiredLiteral() == null);
}
