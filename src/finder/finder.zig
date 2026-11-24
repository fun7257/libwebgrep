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
const unicode_fold = @import("unicode_fold.zig");

pub const Finder = struct {
    pattern: []const u8,
    ignore_case: bool,
    unicode_folded: bool = false,
    /// Longest contiguous safe ASCII substring (`< 0x80` and not cross-ASCII `k`/`s`) inside a
    /// `unicode_folded` pattern, used as an AVX2/NEON `PackedPair` SIMD prefilter when len >= 2.
    unicode_ascii_off: usize = 0,
    unicode_ascii_len: usize = 0,
    unicode_ascii_cp_before: usize = 0,
    multiline: bool = false,
    max_multiline_window: usize = 64 * 1024,
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
        masked_pair: packed_pair.MaskedPair,
    };

    pub fn init(pattern: []const u8, options: matcher.FindOptions) (matcher.LimitError || error{PatternHasNewline})!Finder {
        try matcher.checkPatternLimits(&.{pattern}, options);
        if (!options.multiline and std.mem.findScalar(u8, pattern, '\n') != null) return error.PatternHasNewline;

        const ignore_case = switch (options.case) {
            .sensitive => false,
            .insensitive => true,
            .smart => if (options.unicode_case) !unicode_fold.patternHasUnicodeUpper(pattern) else !ascii.patternHasUpper(pattern),
        };
        const unicode_folded = ignore_case and options.unicode_case and unicode_fold.needsUnicodeExpansion(pattern);
        const fold: two_way.Fold = if (ignore_case) .ascii else .sensitive;
        const rank: *const [256]u8 = if (options.frequency) |*table| table else &frequency.default_rank;

        var uni_off: usize = 0;
        var uni_len: usize = 0;
        var uni_cp_before: usize = 0;
        var masked_opt: ?packed_pair.MaskedPair = null;
        if (unicode_folded) {
            masked_opt = tryBuildMaskedPair(pattern, rank);
            if (masked_opt == null) {
                const best = findSafeAsciiRun(pattern);
                uni_off = best.off;
                uni_len = best.len;
                uni_cp_before = best.cp_before;
            }
        }

        const kind: Kind = if (masked_opt) |mp|
            .{ .masked_pair = mp }
        else if (unicode_folded and uni_len >= 2)
            .{ .pair = packed_pair.PackedPair.init(pattern[uni_off .. uni_off + uni_len], rank, true) }
        else switch (pattern.len) {
            0 => .empty,
            1 => .{ .byte = pattern[0] },
            else => .{ .pair = packed_pair.PackedPair.init(pattern, rank, ignore_case) },
        };

        const min_win = if (unicode_folded and masked_opt == null) pattern.len *| 3 else pattern.len;

        return .{
            .pattern = pattern,
            .ignore_case = ignore_case,
            .unicode_folded = unicode_folded,
            .unicode_ascii_off = uni_off,
            .unicode_ascii_len = uni_len,
            .unicode_ascii_cp_before = uni_cp_before,
            .multiline = options.multiline,
            .max_multiline_window = @max(options.max_multiline_window, min_win),
            .kind = kind,
            .fp_threshold = options.prefilter_fp_threshold,
            .two_way = two_way.TwoWay.init(pattern, fold),
        };
    }

    fn tryBuildMaskedPair(pattern: []const u8, rank: *const [256]u8) ?packed_pair.MaskedPair {
        if (pattern.len < 2 or pattern.len > 64) return null;
        var values: [64]u8 = undefined;
        var masks: [64]u8 = undefined;
        var out_len: usize = 0;
        var i: usize = 0;
        while (i < pattern.len) {
            const b = pattern[i];
            const slen: usize = if (b < 0x80) 1 else (std.unicode.utf8ByteSequenceLength(b) catch return null);
            if (i + slen > pattern.len) return null;
            const cp: u21 = switch (slen) {
                1 => b,
                2 => std.unicode.utf8Decode2(pattern[i..][0..2].*) catch return null,
                3 => std.unicode.utf8Decode3(pattern[i..][0..3].*) catch return null,
                4 => std.unicode.utf8Decode4(pattern[i..][0..4].*) catch return null,
                else => unreachable,
            };
            var eq: [4]u21 = undefined;
            const n_eq = unicode_fold.foldEquivalents(cp, &eq);
            if (n_eq == 1) {
                if (out_len + slen > 64) return null;
                for (pattern[i .. i + slen]) |raw_b| {
                    values[out_len] = raw_b;
                    masks[out_len] = 0;
                    out_len += 1;
                }
            } else if (n_eq == 2) {
                var enc0: [4]u8 = undefined;
                var enc1: [4]u8 = undefined;
                const l0 = std.unicode.utf8Encode(eq[0], &enc0) catch return null;
                const l1 = std.unicode.utf8Encode(eq[1], &enc1) catch return null;
                if (l0 != l1 or l0 != slen or out_len + l0 > 64) return null;
                var diff_count: usize = 0;
                var diff_idx: usize = 0;
                for (0..l0) |k| {
                    if (enc0[k] != enc1[k]) {
                        diff_count += 1;
                        diff_idx = k;
                    }
                }
                if (diff_count != 1) return null;
                const diff_bit = enc0[diff_idx] ^ enc1[diff_idx];
                if (@popCount(diff_bit) != 1) return null;
                for (0..l0) |k| {
                    if (k == diff_idx) {
                        values[out_len] = enc0[k] | diff_bit;
                        masks[out_len] = diff_bit;
                    } else {
                        values[out_len] = enc0[k];
                        masks[out_len] = 0;
                    }
                    out_len += 1;
                }
            } else {
                return null;
            }
            i += slen;
        }
        if (out_len != pattern.len) return null;
        return packed_pair.MaskedPair.init(values[0..out_len], masks[0..out_len], rank);
    }

    fn findSafeAsciiRun(pattern: []const u8) struct { off: usize, len: usize, cp_before: usize } {
        var best_off: usize = 0;
        var best_len: usize = 0;
        var best_cp_before: usize = 0;
        var cur_off: usize = 0;
        var cur_len: usize = 0;
        var cur_cp_before: usize = 0;
        var cp_count: usize = 0;
        var i: usize = 0;
        while (i < pattern.len) {
            const b = pattern[i];
            if (b < 0x80 and b != 'k' and b != 'K' and b != 's' and b != 'S') {
                if (cur_len == 0) {
                    cur_off = i;
                    cur_cp_before = cp_count;
                }
                cur_len += 1;
                if (cur_len > best_len) {
                    best_off = cur_off;
                    best_len = cur_len;
                    best_cp_before = cur_cp_before;
                }
                i += 1;
                cp_count += 1;
            } else {
                cur_len = 0;
                const slen = if (b < 0x80) @as(usize, 1) else (std.unicode.utf8ByteSequenceLength(b) catch 1);
                i = @min(pattern.len, i + slen);
                cp_count += 1;
            }
        }
        return .{ .off = best_off, .len = best_len, .cp_before = best_cp_before };
    }

    pub fn isMultiline(self: *const Finder) bool {
        return self.multiline;
    }

    pub fn multilineWindow(self: *const Finder) usize {
        return self.max_multiline_window;
    }

    pub fn maxNewlines(self: *const Finder) ?u32 {
        return @intCast(std.mem.count(u8, self.pattern, "\n"));
    }

    pub inline fn watchedIsExact(_: *const Finder) bool {
        return true;
    }

    pub inline fn watchedHasExactStart(_: *const Finder) bool {
        return true;
    }

    /// For a single literal, `earliest` and `leftmost_first` produce the same match.
    /// Kept separate from NUL watching so it can be inlined into tight search loops on dense hits.
    pub fn find(self: *const Finder, haystack: []const u8, start: usize, mode: matcher.MatchMode) ?matcher.Match {
        _ = mode;
        if (self.kind == .masked_pair) {
            const mp = &self.kind.masked_pair;
            const pos = mp.find(memchr.native_width, haystack, start) orelse return null;
            return .{ .start = pos, .end = pos + mp.len, .pattern_id = null };
        }
        if (self.unicode_folded) {
            if (self.unicode_ascii_len >= 2) {
                return self.findUnicodePrefiltered(haystack, start, null);
            }
            const hit = unicode_fold.findFolded(haystack, self.pattern, start) orelse return null;
            return .{ .start = hit.start, .end = hit.end, .pattern_id = null };
        }
        switch (self.kind) {
            .empty => {
                if (start <= haystack.len) return .{ .start = start, .end = start, .pattern_id = null };
                return null;
            },
            .byte => |needle| {
                const at = if (self.ignore_case) blk: {
                    const forms = ascii.caseVariants(needle);
                    break :blk memchr.findEither(memchr.native_width, haystack, start, forms[0], forms[1]);
                } else memchr.find(memchr.native_width, haystack, start, needle);
                const i = at orelse return null;
                return .{ .start = i, .end = i + 1, .pattern_id = null };
            },
            .pair => return self.findPair(haystack, start),
            .masked_pair => unreachable,
        }
    }

    /// Read-only variant of `find` that accepts `*const Finder` without mutating telemetry fields.
    pub fn findReadOnly(self: *const Finder, haystack: []const u8, start: usize, mode: matcher.MatchMode) ?matcher.Match {
        return self.find(haystack, start, mode);
    }

    /// Same as `find`, additionally writing the first NUL preceding or inside the match (or in the scanned span when no match is found) to `nul`.
    pub fn findWatched(self: *const Finder, haystack: []const u8, start: usize, nul: *?usize) ?matcher.Match {
        if (self.kind == .masked_pair) {
            const mp = &self.kind.masked_pair;
            const pos = mp.findWatchingNul(memchr.native_width, haystack, start, nul) orelse return null;
            return .{ .start = pos, .end = pos + mp.len, .pattern_id = null };
        }
        if (self.unicode_folded) {
            if (self.unicode_ascii_len >= 2) {
                return self.findUnicodePrefiltered(haystack, start, nul);
            }
            const hit = unicode_fold.findFolded(haystack, self.pattern, start);
            const limit = if (hit) |item| @min(haystack.len, @max(start, item.end)) else haystack.len;
            if (start < limit) {
                if (memchr.find(memchr.native_width, haystack[0..limit], start, 0)) |at| {
                    nul.* = at;
                    return null;
                }
            }
            const found = hit orelse return null;
            return .{ .start = found.start, .end = found.end, .pattern_id = null };
        }
        switch (self.kind) {
            .empty => {
                if (start <= haystack.len) return .{ .start = start, .end = start, .pattern_id = null };
                return null;
            },
            .byte => |needle| {
                if (needle == 0 and !self.ignore_case) {
                    const i = memchr.find(memchr.native_width, haystack, start, 0) orelse return null;
                    nul.* = i;
                    return null;
                }
                const hit = if (self.ignore_case) blk: {
                    const forms = ascii.caseVariants(needle);
                    break :blk memchr.findAny(memchr.native_width, haystack, start, forms[0], forms[1], 0);
                } else memchr.findAny(memchr.native_width, haystack, start, needle, 0, 0);
                const found = hit orelse return null;
                if (found.byte == 0) {
                    @branchHint(.cold);
                    nul.* = found.index;
                    return null;
                }
                return .{ .start = found.index, .end = found.index + 1, .pattern_id = null };
            },
            .pair => return self.findPairWatched(haystack, start, nul),
            .masked_pair => unreachable,
        }
    }

    /// For future regex prefiltering. When case-insensitive, bytes remain the raw pattern and must not be treated as a case-sensitive required substring.
    pub fn requiredLiteral(self: *const Finder) ?matcher.RequiredLiteral {
        if (self.pattern.len == 0) return null;
        return .{ .bytes = self.pattern, .offset_in_match = 0 };
    }

    /// Resets any per-input state. Retained as a no-op since `Finder` uses stack-local adaptive guards per search call.
    pub fn resetStats(self: *const Finder) void {
        _ = self;
    }

    noinline fn findUnicodePrefiltered(self: *const Finder, haystack: []const u8, start: usize, nul_opt: ?*?usize) ?matcher.Match {
        const pair = &self.kind.pair;
        const sub_len = self.unicode_ascii_len;
        if (self.unicode_ascii_off == 0) {
            const tail_pat = self.pattern[sub_len..];
            var pos = start;
            while (pos <= haystack.len) {
                const hit_pos = if (nul_opt) |nul| blk: {
                    const at = pair.findWatchingNul(memchr.native_width, haystack, pos, null, nul);
                    if (nul.* != null) return null;
                    break :blk at orelse return null;
                } else (pair.find(memchr.native_width, haystack, pos, null) orelse return null);
                if (unicode_fold.matchFoldedPrefix(tail_pat, haystack[hit_pos + sub_len ..])) |tail_len| {
                    const end = hit_pos + sub_len + tail_len;
                    if (nul_opt) |nul| {
                        if (hit_pos + sub_len < end) {
                            if (memchr.find(memchr.native_width, haystack[0..end], hit_pos + sub_len, 0)) |z| {
                                nul.* = z;
                                return null;
                            }
                        }
                    }
                    return .{ .start = hit_pos, .end = end, .pattern_id = null };
                }
                pos = hit_pos + 1;
            }
            return null;
        }

        const cp_before = self.unicode_ascii_cp_before;
        var search_pos = start +| cp_before;
        var checked_up_to = start;
        var nul_checked_up_to = start;
        while (search_pos <= haystack.len) {
            const hit_pos = if (nul_opt) |nul| blk: {
                const at = pair.findWatchingNul(memchr.native_width, haystack, search_pos, null, nul);
                if (nul.* != null) {
                    if (nul_checked_up_to < search_pos) {
                        if (memchr.find(memchr.native_width, haystack[0..search_pos], nul_checked_up_to, 0)) |z| {
                            nul.* = z;
                        }
                    }
                    return null;
                }
                break :blk at orelse {
                    if (nul_checked_up_to < search_pos and search_pos <= haystack.len) {
                        if (memchr.find(memchr.native_width, haystack[0..search_pos], nul_checked_up_to, 0)) |z| {
                            nul.* = z;
                        }
                    }
                    return null;
                };
            } else (pair.find(memchr.native_width, haystack, search_pos, null) orelse return null);

            const win_start = @max(checked_up_to, hit_pos -| (4 * cp_before));
            const win_end = hit_pos -| cp_before;
            var cand = win_start;
            while (cand <= win_end and cand < haystack.len) : (cand += 1) {
                if ((haystack[cand] & 0xC0) == 0x80) continue;
                if (unicode_fold.matchFoldedPrefix(self.pattern, haystack[cand..])) |match_len| {
                    const end = cand + match_len;
                    if (nul_opt) |nul| {
                        if (nul_checked_up_to < end) {
                            if (memchr.find(memchr.native_width, haystack[0..end], nul_checked_up_to, 0)) |z| {
                                nul.* = z;
                                return null;
                            }
                        }
                    }
                    return .{ .start = cand, .end = end, .pattern_id = null };
                }
            }
            checked_up_to = win_end + 1;
            if (nul_opt != null and hit_pos > nul_checked_up_to) {
                if (memchr.find(memchr.native_width, haystack[0..hit_pos], nul_checked_up_to, 0)) |z| {
                    nul_opt.?.* = z;
                    return null;
                }
                nul_checked_up_to = hit_pos + sub_len;
            }
            search_pos = hit_pos + 1;
        }
        if (nul_opt) |nul| {
            if (nul_checked_up_to < haystack.len) {
                if (memchr.find(memchr.native_width, haystack, nul_checked_up_to, 0)) |z| {
                    nul.* = z;
                }
            }
        }
        return null;
    }

    inline fn findPair(self: *const Finder, haystack: []const u8, start: usize) ?matcher.Match {
        const pair = &self.kind.pair;
        const m = pair.pattern.len;
        if (m > haystack.len or start > haystack.len - m) return null;

        // Short patterns have a constant-factor linear worst case, so they never switch to scalar Two-Way.
        // Long patterns switch only when the caller lowers the threshold below 1 and the prefilter fails to make progress.
        if (m <= packed_pair.owns_search_max_len or self.fp_threshold >= 1) {
            const at = pair.find(memchr.native_width, haystack, start, null) orelse return null;
            return .{ .start = at, .end = at + m, .pattern_id = null };
        }
        return self.findPairGuarded(haystack, start, m);
    }

    noinline fn findPairGuarded(self: *const Finder, haystack: []const u8, start: usize, m: usize) ?matcher.Match {
        const pair = &self.kind.pair;
        var guard: packed_pair.Guard = .{};
        const at = pair.find(memchr.native_width, haystack, start, &guard);
        if (at) |pos| {
            return .{ .start = pos, .end = pos + m, .pattern_id = null };
        }
        if (guard.gave_up) {
            @branchHint(.cold);
            return self.findLinear(haystack, guard.restart, m);
        }
        return null;
    }

    inline fn findPairWatched(self: *const Finder, haystack: []const u8, start: usize, nul: *?usize) ?matcher.Match {
        const pair = &self.kind.pair;
        const m = pair.pattern.len;
        if (m > haystack.len or start > haystack.len - m) {
            if (start <= haystack.len) {
                if (memchr.find(memchr.native_width, haystack, start, 0)) |at| nul.* = at;
            }
            return null;
        }

        if (m <= packed_pair.owns_search_max_len or self.fp_threshold >= 1) {
            const at = pair.findWatchingNul(memchr.native_width, haystack, start, null, nul);
            if (nul.* != null) {
                @branchHint(.cold);
                return null;
            }
            const pos = at orelse return null;
            return .{ .start = pos, .end = pos + m, .pattern_id = null };
        }
        return self.findPairWatchedGuarded(haystack, start, m, nul);
    }

    noinline fn findPairWatchedGuarded(self: *const Finder, haystack: []const u8, start: usize, m: usize, nul: *?usize) ?matcher.Match {
        const pair = &self.kind.pair;
        var guard: packed_pair.Guard = .{};
        const at = pair.findWatchingNul(memchr.native_width, haystack, start, &guard, nul);
        if (nul.* != null) {
            @branchHint(.cold);
            return null;
        }
        if (at) |pos| {
            return .{ .start = pos, .end = pos + m, .pattern_id = null };
        }
        if (guard.gave_up) {
            @branchHint(.cold);
            const lin = self.findLinear(haystack, guard.restart, m);
            const limit = if (lin) |hit| @min(haystack.len, @max(guard.restart, hit.end)) else haystack.len;
            if (guard.restart < limit) {
                if (memchr.find(memchr.native_width, haystack[0..limit], guard.restart, 0)) |z| {
                    nul.* = z;
                    return null;
                }
            }
            return lin;
        }
        return null;
    }

    noinline fn findLinear(self: *const Finder, haystack: []const u8, start: usize, m: usize) ?matcher.Match {
        const at = self.two_way.find(haystack, start) orelse return null;
        return .{ .start = at, .end = at + m, .pattern_id = null };
    }

    /// Whether `span` equals this pattern (`mode` is accepted for `Matcher` contract uniformity).
    pub fn acceptsSpan(self: *const Finder, span: []const u8, mode: matcher.MatchMode) bool {
        _ = mode;
        if (self.kind == .masked_pair) {
            const mp = &self.kind.masked_pair;
            return span.len == mp.len and mp.confirmAt(span, 0);
        }
        if (self.unicode_folded) {
            return unicode_fold.eqlFolded(self.pattern, span);
        }
        return ascii.eql(self.pattern, span, self.ignore_case);
    }

    /// Same as `find`, advancing one byte past the match start when `allow` rejects a candidate.
    /// `allow` may be a function `fn ([]const u8, usize, usize) bool` or a context with `.allow(haystack, start, end) bool`.
    pub fn findAllowed(
        self: *const Finder,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        allow: anytype,
    ) ?matcher.Match {
        var pos = start;
        while (pos <= haystack.len) {
            const found = self.find(haystack, pos, mode) orelse return null;
            if (found.start < pos) return null;
            const accepted = if (@typeInfo(@TypeOf(allow)) == .@"fn" or
                (@typeInfo(@TypeOf(allow)) == .pointer and @typeInfo(@typeInfo(@TypeOf(allow)).pointer.child) == .@"fn"))
                allow(haystack, found.start, found.end)
            else
                matcher.callAllow(allow, haystack, found.start, found.end);
            if (accepted) return found;
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
    const noisy = try Finder.init(&pat, .{
        .frequency = rank,
        .prefilter_fp_threshold = 0.5,
    });
    var hay: [200]u8 = @splat('a');
    for (0..80) |i| {
        hay[i * 2] = 'a';
        hay[i * 2 + 1] = 'b';
    }
    @memcpy(hay[hay.len - pat.len ..], pat[0..]);
    const hit = noisy.find(&hay, 0, .earliest).?;
    try std.testing.expectEqual(hay.len - pat.len, hit.start);
    try std.testing.expectEqual(@as(?u32, null), hit.pattern_id);

    noisy.resetStats();
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
            const finder = try Finder.init(pat[0..plen], .{ .case = case });
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
    const finder = try Finder.init("abc", .{});
    const lit = finder.requiredLiteral().?;
    try std.testing.expectEqualStrings("abc", lit.bytes);
    try std.testing.expectEqual(@as(usize, 0), lit.offset_in_match);
    const empty = try Finder.init("", .{});
    try std.testing.expect(empty.requiredLiteral() == null);
}

test "Finder unicode_case supports Greek, Cyrillic, cross-byte-length ẞ/ß, and smart case" {
    const f_greek = try Finder.init("σigma", .{ .case = .smart, .unicode_case = true });
    const hit_g = f_greek.find("xxΣIGMAyy", 0, .earliest).?;
    try std.testing.expectEqual(@as(usize, 2), hit_g.start);
    try std.testing.expectEqual(@as(usize, 2 + "ΣIGMA".len), hit_g.end);
    try std.testing.expect(f_greek.acceptsSpan("ςigma", .earliest));

    const f_upper = try Finder.init("Δelta", .{ .case = .smart, .unicode_case = true });
    try std.testing.expect(f_upper.find("δelta", 0, .earliest) == null);
    try std.testing.expect(f_upper.find("Δelta", 0, .earliest) != null);

    const f_sharp = try Finder.init("straße", .{ .case = .insensitive, .unicode_case = true });
    var nul_at: ?usize = null;
    const hit_s = f_sharp.findWatched("aSTRA\u{1E9E}Eb", 0, &nul_at).?;
    try std.testing.expect(nul_at == null);
    try std.testing.expectEqualStrings("STRA\u{1E9E}E", "aSTRA\u{1E9E}Eb"[hit_s.start..hit_s.end]);
}

test "Finder MaskedPair exact SIMD fast path for single-bit-maskable Unicode case folding" {
    const f_cafe = try Finder.init("café", .{ .case = .insensitive, .unicode_case = true });
    try std.testing.expect(f_cafe.kind == .masked_pair);
    try std.testing.expect(f_cafe.acceptsSpan("CAFÉ", .earliest));
    try std.testing.expect(f_cafe.acceptsSpan("Café", .earliest));
    try std.testing.expect(!f_cafe.acceptsSpan("cafe", .earliest));

    // Span across > 128 bytes to exercise AVX2 4-vector unrolled loop + NUL detection
    var buf: [200]u8 = @splat('x');
    @memcpy(buf[140..][0.."CAFÉ".len], "CAFÉ");
    const hit = f_cafe.find(&buf, 0, .earliest).?;
    try std.testing.expectEqual(@as(usize, 140), hit.start);
    try std.testing.expectEqual(@as(usize, 140 + "CAFÉ".len), hit.end);

    var nul_at: ?usize = null;
    buf[70] = 0;
    try std.testing.expect(f_cafe.findWatched(&buf, 0, &nul_at) == null);
    try std.testing.expectEqual(@as(?usize, 70), nul_at);

    // NUL after match in same SIMD block still returns the match
    buf[70] = 'x';
    buf[140 + "CAFÉ".len + 1] = 0;
    nul_at = null;
    const hit2 = f_cafe.findWatched(&buf, 0, &nul_at).?;
    try std.testing.expectEqual(@as(usize, 140), hit2.start);
    try std.testing.expect(nul_at == null);
}

test "Finder ignore_case with non-letter anchor and findWatched NUL handling" {
    const f = try Finder.init("[ERROR]", .{ .case = .insensitive, .unicode_case = false });
    var buf: [200]u8 = @splat(' ');
    @memcpy(buf[15..22], "{ERROR]");
    @memcpy(buf[140..147], "[eRrOr]");

    var nul: ?usize = null;
    const hit = f.findWatched(&buf, 0, &nul).?;
    try std.testing.expectEqual(@as(usize, 140), hit.start);
    try std.testing.expectEqual(@as(usize, 147), hit.end);
    try std.testing.expect(nul == null);

    buf[135] = 0;
    nul = null;
    try std.testing.expect(f.findWatched(&buf, 0, &nul) == null);
    try std.testing.expectEqual(@as(?usize, 135), nul);
}
