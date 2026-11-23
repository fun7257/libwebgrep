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
const builtin = @import("builtin");
const aho = @import("aho.zig");
const ascii = @import("ascii.zig");
const build_options = @import("build_options");
const byteset = @import("byteset.zig");
const cpuid = @import("../io/cpuid.zig");
const matcher = @import("../matcher.zig");
const memchr = @import("memchr.zig");
const pairs = @import("pairs.zig");
const unicode_fold = @import("unicode_fold.zig");

const teddy_runtime = (builtin.cpu.arch == .x86_64 and build_options.teddy == .runtime);
const teddy_static = (build_options.teddy != .off and build_options.teddy != .runtime);
const teddy_on = teddy_static or teddy_runtime;
const teddy_mod = if (teddy_on) @import("teddy.zig") else struct {
    const Stub = @This();
    pub const Engine = struct {};
    pub const Ssse3Engine = struct {};
    pub const RuntimeAvx2Engine = struct {};
    pub const VerifyResult = union(enum) {
        accept: usize,
        reject,
        abort,
    };
    pub const VerifiedMatch = struct {
        start: usize,
        end: usize,
        id: usize,
    };
    pub const VerifiedStep = union(enum) {
        match: Stub.VerifiedMatch,
        none,
        aborted: usize,
    };
};

pub const VerifyResult = teddy_mod.VerifyResult;
pub const VerifiedMatch = teddy_mod.VerifiedMatch;
pub const VerifiedStep = teddy_mod.VerifiedStep;

pub const Multi = struct {
    kind: Kind,
    ignore_case: bool,
    unicode_case: bool = false,
    multiline: bool = false,
    max_multiline_window: usize = 64 * 1024,
    empty_only: bool,
    /// Owned by the caller. Used for whole-line comparison and whole-word per-pattern verification without copying pattern bytes.
    patterns: []const []const u8,
    owned_patterns: ?[][]const u8 = null,
    owned_variant_bytes: ?[][]u8 = null,
    owned_pattern_ids: ?[]u32 = null,
    patterns_alloc: ?std.mem.Allocator = null,

    const Mixed = struct {
        ignore: []bool,
        allocator: std.mem.Allocator,
    };

    const Kind = union(enum) {
        bytes: byteset.Set,
        pairs: pairs.Engine,
        ac: aho.Ac,
        teddy: if (teddy_static) teddy_mod.Engine else void,
        teddy_ssse3: if (teddy_runtime) teddy_mod.Ssse3Engine else void,
        teddy_avx2_rt: if (teddy_runtime) teddy_mod.RuntimeAvx2Engine else void,
        mixed: Mixed,
    };

    pub const scenario_bytes: []const []const u8 = &.{ "Q", "Z" };
    pub const scenario_pairs: []const []const u8 = &.{ "NEEDLE", "ZXZQ" };
    pub const scenario_teddy: []const []const u8 = digram_pats[0..17];
    pub const scenario_ac: []const []const u8 = &digram_pats;
    pub const fillScenarioText = @import("multi.zig").fillScenarioText;

    pub fn init(
        allocator: std.mem.Allocator,
        patterns: []const []const u8,
        options: matcher.FindOptions,
    ) (matcher.LimitError || error{ PatternHasNewline, OutOfMemory })!Multi {
        // Reject limit violations before allocating pair tables, Teddy, or the automaton.
        try matcher.checkPatternLimits(patterns, options);
        var max_pat_len: usize = 0;
        for (patterns) |pat| {
            if (!options.multiline and std.mem.findScalar(u8, pat, '\n') != null) return error.PatternHasNewline;
            if (pat.len > max_pat_len) max_pat_len = pat.len;
        }
        const ml_win = @max(options.max_multiline_window, max_pat_len);
        if (options.unicode_case and options.case != .sensitive and anyNeedsUnicodeFold(patterns, options)) {
            return initUnicodeFolded(allocator, patterns, options);
        }
        if (uniformIgnore(patterns, options.case)) |ignore| {
            if (allSingleByte(patterns)) {
                return .{
                    .kind = .{ .bytes = byteset.Set.init(patterns, ignore) },
                    .ignore_case = ignore,
                    .unicode_case = options.unicode_case,
                    .multiline = options.multiline,
                    .max_multiline_window = ml_win,
                    .empty_only = false,
                    .patterns = patterns,
                };
            }
            if (comptime teddy_static) {
                if (preferTeddyOverPairs(patterns)) {
                    return .{
                        .kind = .{ .teddy = teddy_mod.Engine.init(patterns, ignore) },
                        .ignore_case = ignore,
                        .unicode_case = options.unicode_case,
                        .multiline = options.multiline,
                        .max_multiline_window = ml_win,
                        .empty_only = false,
                        .patterns = patterns,
                    };
                }
            } else if (comptime teddy_runtime) {
                if (preferTeddyOverPairs(patterns)) {
                    const feats = cpuid.detectX86();
                    if (feats.avx2) {
                        return .{
                            .kind = .{ .teddy_avx2_rt = teddy_mod.RuntimeAvx2Engine.init(patterns, ignore) },
                            .ignore_case = ignore,
                            .unicode_case = options.unicode_case,
                            .multiline = options.multiline,
                            .max_multiline_window = ml_win,
                            .empty_only = false,
                            .patterns = patterns,
                        };
                    } else if (feats.ssse3) {
                        return .{
                            .kind = .{ .teddy_ssse3 = teddy_mod.Ssse3Engine.init(patterns, ignore) },
                            .ignore_case = ignore,
                            .unicode_case = options.unicode_case,
                            .multiline = options.multiline,
                            .max_multiline_window = ml_win,
                            .empty_only = false,
                            .patterns = patterns,
                        };
                    }
                }
            }
            if (try pairs.Engine.create(allocator, patterns, ignore)) |engine| {
                return .{
                    .kind = .{ .pairs = engine },
                    .ignore_case = ignore,
                    .unicode_case = options.unicode_case,
                    .multiline = options.multiline,
                    .max_multiline_window = ml_win,
                    .empty_only = false,
                    .patterns = patterns,
                };
            }
            if (comptime teddy_static) {
                if (teddyEligible(patterns)) {
                    return .{
                        .kind = .{ .teddy = teddy_mod.Engine.init(patterns, ignore) },
                        .ignore_case = ignore,
                        .unicode_case = options.unicode_case,
                        .multiline = options.multiline,
                        .max_multiline_window = ml_win,
                        .empty_only = false,
                        .patterns = patterns,
                    };
                }
            } else if (comptime teddy_runtime) {
                if (teddyEligible(patterns)) {
                    const feats = cpuid.detectX86();
                    if (feats.avx2) {
                        return .{
                            .kind = .{ .teddy_avx2_rt = teddy_mod.RuntimeAvx2Engine.init(patterns, ignore) },
                            .ignore_case = ignore,
                            .unicode_case = options.unicode_case,
                            .multiline = options.multiline,
                            .max_multiline_window = ml_win,
                            .empty_only = false,
                            .patterns = patterns,
                        };
                    } else if (feats.ssse3) {
                        return .{
                            .kind = .{ .teddy_ssse3 = teddy_mod.Ssse3Engine.init(patterns, ignore) },
                            .ignore_case = ignore,
                            .unicode_case = options.unicode_case,
                            .multiline = options.multiline,
                            .max_multiline_window = ml_win,
                            .empty_only = false,
                            .patterns = patterns,
                        };
                    }
                }
            }
            return .{
                .kind = .{ .ac = try aho.build(allocator, patterns, ignore) },
                .ignore_case = ignore,
                .unicode_case = options.unicode_case,
                .multiline = options.multiline,
                .max_multiline_window = ml_win,
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
            .unicode_case = options.unicode_case,
            .multiline = options.multiline,
            .max_multiline_window = ml_win,
            .empty_only = false,
            .patterns = patterns,
        };
    }

    pub fn isMultiline(self: *const Multi) bool {
        return self.multiline;
    }

    pub fn multilineWindow(self: *const Multi) usize {
        return self.max_multiline_window;
    }

    pub fn maxNewlines(self: *const Multi) ?u32 {
        var max_nl: usize = 0;
        for (self.patterns) |pat| {
            const c = std.mem.count(u8, pat, "\n");
            if (c > max_nl) max_nl = c;
        }
        return @intCast(max_nl);
    }

    pub inline fn watchedIsExact(self: *const Multi) bool {
        return self.patterns.len <= 1;
    }

    pub inline fn watchedHasExactStart(self: *const Multi) bool {
        return self.patterns.len <= 1;
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
                if (comptime teddy_static) engine.deinit();
            },
            .teddy_ssse3 => |*engine| {
                if (comptime teddy_runtime) engine.deinit();
            },
            .teddy_avx2_rt => |*engine| {
                if (comptime teddy_runtime) engine.deinit();
            },
            .mixed => |*mixed| mixed.allocator.free(mixed.ignore),
        }
        if (self.owned_variant_bytes) |variants| {
            if (self.patterns_alloc) |alloc| {
                for (variants) |v| alloc.free(v);
                alloc.free(variants);
            }
        }
        if (self.owned_pattern_ids) |ids| {
            if (self.patterns_alloc) |alloc| alloc.free(ids);
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
            .teddy, .teddy_ssse3, .teddy_avx2_rt => "teddy",
            .mixed => "mixed",
        };
    }

    pub fn resetStats(self: *const Multi) void {
        _ = self;
    }

    inline fn mapPatternId(self: *const Multi, raw_id: ?u32) ?u32 {
        const id = raw_id orelse return null;
        if (self.owned_pattern_ids) |ids| {
            if (id < ids.len) return ids[id];
        }
        return id;
    }

    inline fn withMappedId(self: *const Multi, hit: ?matcher.Match) ?matcher.Match {
        var m = hit orelse return null;
        m.pattern_id = self.mapPatternId(m.pattern_id);
        return m;
    }

    inline fn bytePatternId(self: *const Multi, set: *const byteset.Set, byte: u8) ?u32 {
        const raw = if (self.ignore_case) set.id_of[ascii.fold(byte)] else set.id_of[byte];
        return self.mapPatternId(raw);
    }

    pub fn find(self: *const Multi, haystack: []const u8, start: usize, mode: matcher.MatchMode) ?matcher.Match {
        if (self.kind == .mixed) return self.scan(haystack, start, mode, allowAll);
        switch (self.kind) {
            .bytes => |*set| {
                const at = set.find(haystack, start) orelse return null;
                return .{ .start = at, .end = at + 1, .pattern_id = self.bytePatternId(set, haystack[at]) };
            },
            .pairs => |*engine| return self.withMappedId(engine.find(haystack, start, mode)),
            .ac => |*ac| return self.withMappedId(ac.find(haystack, start, mode)),
            .teddy => |*engine| {
                if (comptime teddy_static) return self.withMappedId(engine.find(haystack, start, mode));
                unreachable;
            },
            .teddy_ssse3 => |*engine| {
                if (comptime teddy_runtime) return self.withMappedId(engine.find(haystack, start, mode));
                unreachable;
            },
            .teddy_avx2_rt => |*engine| {
                if (comptime teddy_runtime) return self.withMappedId(engine.find(haystack, start, mode));
                unreachable;
            },
            .mixed => unreachable,
        }
    }

    pub fn findReadOnly(self: *const Multi, haystack: []const u8, start: usize, mode: matcher.MatchMode) ?matcher.Match {
        return self.find(haystack, start, mode);
    }

    /// Returns the full-span match (including `pattern_id`) if `span` equals any pattern.
    pub fn matchSpan(self: *const Multi, span: []const u8, mode: matcher.MatchMode) ?matcher.Match {
        var best: ?Naive = null;
        for (self.patterns, 0..) |pat, i| {
            const fold = self.foldOf(i);
            const matched = if (self.unicode_case and fold)
                unicode_fold.eqlFolded(pat, span)
            else
                ascii.eql(pat, span, fold);
            if (!matched) continue;
            const pid = self.mapPatternId(@intCast(i)) orelse @as(u32, @intCast(i));
            const cand = Naive{ .start = 0, .end = span.len, .id = pid };
            if (best) |cur| {
                if (better(cand, cur, mode)) best = cand;
            } else best = cand;
        }
        const found = best orelse return null;
        return .{ .start = 0, .end = span.len, .pattern_id = found.id };
    }

    /// Whether the line span equals any pattern, using each pattern's own case-folding rule.
    pub fn acceptsSpan(self: *const Multi, span: []const u8, mode: matcher.MatchMode) bool {
        return self.matchSpan(span, mode) != null;
    }

    /// Verifies each pattern individually so another pattern at the same start position (or an overlapping
    /// earlier-ending pattern in `.earliest` mode) can still pass `allow`.
    pub fn findAllowed(
        self: *const Multi,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        allow: anytype,
    ) ?matcher.Match {
        if (self.kind == .mixed) return self.scan(haystack, start, mode, allow);
        if (start > haystack.len) return null;

        // Fast path: if the primary engine match is allowed, it is already optimal for `mode`.
        const first = self.find(haystack, start, mode) orelse return null;
        if (callAllowAny(allow, haystack, first.start, first.end)) return first;

        if (mode == .leftmost_first) {
            if (self.checkAllowedAt(haystack, first.start, .leftmost_first, allow)) |alt| return alt;
            if (first.start >= haystack.len) return null;
            var pos = first.start + 1;
            while (pos <= haystack.len) {
                const hit = self.find(haystack, pos, .leftmost_first) orelse return null;
                if (callAllowAny(allow, haystack, hit.start, hit.end)) return hit;
                if (self.checkAllowedAt(haystack, hit.start, .leftmost_first, allow)) |alt| return alt;
                if (hit.start >= haystack.len) return null;
                pos = hit.start + 1;
            }
            return null;
        }

        // In `.earliest` mode, `first` may have started > `start` because a shorter pattern at `first.start`
        // ended earlier than a longer (but allowed) pattern starting in `start .. first.start`.
        // Step through leftmost candidate start positions until no future start can beat `best.end`.
        var best: ?Naive = null;
        var pos = start;
        while (pos <= haystack.len) {
            if (best) |cur| {
                if (pos > cur.end) break;
            }
            const l_hit = self.find(haystack, pos, .leftmost_first) orelse break;
            if (best) |cur| {
                if (l_hit.start > cur.end) break;
            }
            if (self.checkAllowedAt(haystack, l_hit.start, .earliest, allow)) |alt| {
                const cand = Naive{
                    .start = alt.start,
                    .end = alt.end,
                    .id = alt.pattern_id orelse 0,
                };
                if (best) |cur| {
                    if (better(cand, cur, .earliest)) best = cand;
                } else best = cand;
            }
            if (l_hit.start >= haystack.len) break;
            pos = l_hit.start + 1;
        }
        if (best) |found| return .{ .start = found.start, .end = found.end, .pattern_id = found.id };
        return null;
    }

    fn checkAllowedAt(
        self: *const Multi,
        haystack: []const u8,
        at: usize,
        mode: matcher.MatchMode,
        allow: anytype,
    ) ?matcher.Match {
        var best: ?Naive = null;
        for (self.patterns, 0..) |pat, id_usize| {
            const pid = self.mapPatternId(@intCast(id_usize)) orelse @as(u32, @intCast(id_usize));
            const fold = self.foldOf(id_usize);
            if (self.unicode_case and fold) {
                if (unicode_fold.matchFoldedPrefix(pat, haystack[at..])) |match_len| {
                    if (callAllowAny(allow, haystack, at, at + match_len)) {
                        const cand = Naive{ .start = at, .end = at + match_len, .id = pid };
                        if (best) |cur| {
                            if (better(cand, cur, mode)) best = cand;
                        } else best = cand;
                    }
                }
                continue;
            }
            if (at + pat.len > haystack.len) continue;
            if (!ascii.eql(pat, haystack[at..][0..pat.len], fold)) continue;
            if (!callAllowAny(allow, haystack, at, at + pat.len)) continue;
            const cand = Naive{ .start = at, .end = at + pat.len, .id = pid };
            if (best) |cur| {
                if (better(cand, cur, mode)) best = cand;
            } else best = cand;
        }
        if (best) |found| return .{ .start = found.start, .end = found.end, .pattern_id = found.id };
        return null;
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
        allow: anytype,
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
                const pid = self.mapPatternId(@intCast(id_usize)) orelse @as(u32, @intCast(id_usize));
                const fold = if (flags) |list| list[id_usize] else self.ignore_case;
                if (self.unicode_case and fold) {
                    if (unicode_fold.matchFoldedPrefix(pat, haystack[i..])) |match_len| {
                        if (callAllowAny(allow, haystack, i, i + match_len)) {
                            const cand = Naive{ .start = i, .end = i + match_len, .id = pid };
                            if (best) |cur| {
                                if (better(cand, cur, mode)) best = cand;
                            } else best = cand;
                        }
                    }
                    continue;
                }
                if (i + pat.len > haystack.len) continue;
                if (!ascii.eql(pat, haystack[i..][0..pat.len], fold)) continue;
                if (!callAllowAny(allow, haystack, i, i + pat.len)) continue;
                const cand = Naive{ .start = i, .end = i + pat.len, .id = pid };
                if (best) |cur| {
                    if (better(cand, cur, mode)) best = cand;
                } else best = cand;
            }
            if (mode == .leftmost_first) {
                if (best) |cand| return .{ .start = cand.start, .end = cand.end, .pattern_id = cand.id };
            } else if (best) |cand| {
                if (i >= cand.end) return .{ .start = cand.start, .end = cand.end, .pattern_id = cand.id };
            }
        }
        const found = best orelse return null;
        return .{ .start = found.start, .end = found.end, .pattern_id = found.id };
    }

    pub fn findWatched(self: *const Multi, haystack: []const u8, start: usize, nul: *?usize) ?matcher.Match {
        switch (self.kind) {
            .bytes => |*set| {
                const at = set.findWatchingNul(haystack, start, nul) orelse return null;
                return .{ .start = at, .end = at + 1, .pattern_id = self.bytePatternId(set, haystack[at]) };
            },
            .pairs => |*engine| return self.withMappedId(engine.findWatchingNul(haystack, start, .earliest, nul)),
            .ac => |*ac| return self.withMappedId(ac.findWatchingNul(haystack, start, .earliest, nul)),
            .teddy => |*engine| {
                if (comptime teddy_static) return self.withMappedId(engine.findWatchingNul(haystack, start, .earliest, nul));
                unreachable;
            },
            .teddy_ssse3 => |*engine| {
                if (comptime teddy_runtime) return self.withMappedId(engine.findWatchingNul(haystack, start, .earliest, nul));
                unreachable;
            },
            .teddy_avx2_rt => |*engine| {
                if (comptime teddy_runtime) return self.withMappedId(engine.findWatchingNul(haystack, start, .earliest, nul));
                unreachable;
            },
            .mixed => {
                const hit = self.scan(haystack, start, .earliest, allowAll);
                const limit = if (hit) |item| @min(haystack.len, @max(start, item.end)) else haystack.len;
                if (start < limit) {
                    if (memchr.find(memchr.native_width, haystack[0..limit], start, 0)) |at| {
                        nul.* = at;
                        return null;
                    }
                }
                return hit;
            },
        }
    }

    pub fn findVerified(
        self: *const Multi,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        verifier: anytype,
    ) VerifiedStep {
        if (start > haystack.len) return .none;
        switch (self.kind) {
            .teddy => |*engine| {
                if (comptime teddy_static) return self.teddyFindVerified(engine, haystack, start, mode, verifier);
                unreachable;
            },
            .teddy_ssse3 => |*engine| {
                if (comptime teddy_runtime) return self.teddyFindVerified(engine, haystack, start, mode, verifier);
                unreachable;
            },
            .teddy_avx2_rt => |*engine| {
                if (comptime teddy_runtime) return self.teddyFindVerified(engine, haystack, start, mode, verifier);
                unreachable;
            },
            else => return self.findVerifiedFallback(haystack, start, mode, verifier),
        }
    }

    pub fn findVerifiedWatched(
        self: *const Multi,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        nul_pos: *?usize,
        verifier: anytype,
    ) VerifiedStep {
        if (start > haystack.len) return .none;
        switch (self.kind) {
            .teddy => |*engine| {
                if (comptime teddy_static) return self.teddyFindVerifiedWatched(engine, haystack, start, mode, nul_pos, verifier);
                unreachable;
            },
            .teddy_ssse3 => |*engine| {
                if (comptime teddy_runtime) return self.teddyFindVerifiedWatched(engine, haystack, start, mode, nul_pos, verifier);
                unreachable;
            },
            .teddy_avx2_rt => |*engine| {
                if (comptime teddy_runtime) return self.teddyFindVerifiedWatched(engine, haystack, start, mode, nul_pos, verifier);
                unreachable;
            },
            else => return self.findVerifiedWatchedFallback(haystack, start, mode, nul_pos, verifier),
        }
    }

    fn MappedVerifier(comptime V: type) type {
        return struct {
            multi: *const Multi,
            inner: V,

            pub fn verify(self: @This(), haystack: []const u8, pat_start: usize, pat_end: usize, pat_id: usize) VerifyResult {
                const mapped = self.multi.mapPatternId(@intCast(pat_id)) orelse @as(u32, @intCast(pat_id));
                return self.inner.verify(haystack, pat_start, pat_end, @as(usize, mapped));
            }
        };
    }

    inline fn mapVerifiedStep(self: *const Multi, step: VerifiedStep) VerifiedStep {
        return switch (step) {
            .match => |m| .{ .match = .{
                .start = m.start,
                .end = m.end,
                .id = @as(usize, self.mapPatternId(@intCast(m.id)) orelse @as(u32, @intCast(m.id))),
            } },
            .none => .none,
            .aborted => |pos| .{ .aborted = pos },
        };
    }

    inline fn teddyFindVerified(
        self: *const Multi,
        engine: anytype,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        verifier: anytype,
    ) VerifiedStep {
        if (self.owned_pattern_ids == null) {
            return engine.findVerified(haystack, start, mode, verifier);
        }
        const wrapped = MappedVerifier(@TypeOf(verifier)){ .multi = self, .inner = verifier };
        return self.mapVerifiedStep(engine.findVerified(haystack, start, mode, wrapped));
    }

    inline fn teddyFindVerifiedWatched(
        self: *const Multi,
        engine: anytype,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        nul_pos: *?usize,
        verifier: anytype,
    ) VerifiedStep {
        if (self.owned_pattern_ids == null) {
            return engine.findVerifiedWatchingNul(haystack, start, mode, nul_pos, verifier);
        }
        const wrapped = MappedVerifier(@TypeOf(verifier)){ .multi = self, .inner = verifier };
        return self.mapVerifiedStep(engine.findVerifiedWatchingNul(haystack, start, mode, nul_pos, wrapped));
    }

    fn maxPatternLen(self: *const Multi) usize {
        var max_len: usize = 0;
        for (self.patterns) |pat| {
            if (pat.len > max_len) max_len = pat.len;
        }
        if (self.unicode_case) max_len *|= 3;
        return max_len;
    }

    fn verifyLeftmostAllAt(
        self: *const Multi,
        haystack: []const u8,
        at: usize,
        verifier: anytype,
    ) VerifiedStep {
        for (self.patterns, 0..) |pat, id_usize| {
            const pid: usize = self.mapPatternId(@intCast(id_usize)) orelse @as(u32, @intCast(id_usize));
            const fold = self.foldOf(id_usize);
            const match_len: usize = if (self.unicode_case and fold)
                unicode_fold.matchFoldedPrefix(pat, haystack[at..]) orelse continue
            else blk: {
                if (at + pat.len > haystack.len) continue;
                if (!ascii.eql(pat, haystack[at..][0..pat.len], fold)) continue;
                break :blk pat.len;
            };
            const pat_end = at + match_len;
            switch (verifier.verify(haystack, at, pat_end, pid)) {
                .accept => |end| return .{ .match = .{ .start = at, .end = end, .id = pid } },
                .abort => return .{ .aborted = at },
                .reject => {},
            }
        }
        return .none;
    }

    fn verifyLeftmostAt(
        self: *const Multi,
        haystack: []const u8,
        hit: matcher.Match,
        verifier: anytype,
    ) VerifiedStep {
        const hit_id: usize = hit.pattern_id orelse 0;
        switch (verifier.verify(haystack, hit.start, hit.end, hit_id)) {
            .accept => |end| return .{ .match = .{ .start = hit.start, .end = end, .id = hit_id } },
            .abort => return .{ .aborted = hit.start },
            .reject => {},
        }
        if (self.patterns.len <= 1) return .none;
        const at = hit.start;
        for (self.patterns, 0..) |pat, id_usize| {
            const pid: usize = self.mapPatternId(@intCast(id_usize)) orelse @as(u32, @intCast(id_usize));
            const fold = self.foldOf(id_usize);
            const match_len: usize = if (self.unicode_case and fold)
                unicode_fold.matchFoldedPrefix(pat, haystack[at..]) orelse continue
            else blk: {
                if (at + pat.len > haystack.len) continue;
                if (!ascii.eql(pat, haystack[at..][0..pat.len], fold)) continue;
                break :blk pat.len;
            };
            const pat_end = at + match_len;
            if (pid == hit_id and pat_end == hit.end) continue;
            switch (verifier.verify(haystack, at, pat_end, pid)) {
                .accept => |end| return .{ .match = .{ .start = at, .end = end, .id = pid } },
                .abort => return .{ .aborted = at },
                .reject => {},
            }
        }
        return .none;
    }

    fn verifyEarliestAt(
        self: *const Multi,
        haystack: []const u8,
        hit: matcher.Match,
        best: *?VerifiedMatch,
        verifier: anytype,
    ) ?usize {
        if (self.patterns.len <= 1) {
            const hit_id: usize = hit.pattern_id orelse 0;
            switch (verifier.verify(haystack, hit.start, hit.end, hit_id)) {
                .accept => |end| {
                    const cand = VerifiedMatch{ .start = hit.start, .end = end, .id = hit_id };
                    if (best.*) |cur| {
                        if (preferVerifiedEarliest(cand, cur)) best.* = cand;
                    } else best.* = cand;
                },
                .abort => {
                    if (best.* == null) return hit.start;
                },
                .reject => {},
            }
            return null;
        }
        const at = hit.start;
        for (self.patterns, 0..) |pat, id_usize| {
            const pid: usize = self.mapPatternId(@intCast(id_usize)) orelse @as(u32, @intCast(id_usize));
            const fold = self.foldOf(id_usize);
            const match_len: usize = if (self.unicode_case and fold)
                unicode_fold.matchFoldedPrefix(pat, haystack[at..]) orelse continue
            else blk: {
                if (at + pat.len > haystack.len) continue;
                if (!ascii.eql(pat, haystack[at..][0..pat.len], fold)) continue;
                break :blk pat.len;
            };
            const pat_end = at + match_len;
            switch (verifier.verify(haystack, at, pat_end, pid)) {
                .accept => |end| {
                    const cand = VerifiedMatch{ .start = at, .end = end, .id = pid };
                    if (best.*) |cur| {
                        if (preferVerifiedEarliest(cand, cur)) best.* = cand;
                    } else best.* = cand;
                },
                .abort => {
                    if (best.* == null) return at;
                },
                .reject => {},
            }
        }
        return null;
    }

    fn findVerifiedFallback(
        self: *const Multi,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        verifier: anytype,
    ) VerifiedStep {
        if (mode == .leftmost_first) {
            var pos = start;
            while (pos <= haystack.len) {
                const hit = self.find(haystack, pos, .leftmost_first) orelse return .none;
                switch (self.verifyLeftmostAt(haystack, hit, verifier)) {
                    .match => |m| return .{ .match = m },
                    .aborted => |resume_pos| return .{ .aborted = resume_pos },
                    .none => {},
                }
                if (hit.start >= haystack.len) return .none;
                pos = hit.start + 1;
            }
            return .none;
        }

        var best: ?VerifiedMatch = null;
        var pos = start;
        while (pos <= haystack.len) {
            if (best) |cur| {
                if (pos > cur.end) break;
            }
            const hit = self.find(haystack, pos, .leftmost_first) orelse break;
            if (best) |cur| {
                if (hit.start > cur.end) break;
            }
            if (self.verifyEarliestAt(haystack, hit, &best, verifier)) |abort_pos| {
                return .{ .aborted = abort_pos };
            }
            if (hit.start >= haystack.len) break;
            pos = hit.start + 1;
        }
        if (best) |m| return .{ .match = m };
        return .none;
    }

    fn findVerifiedWatchedFallback(
        self: *const Multi,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        nul_pos: *?usize,
        verifier: anytype,
    ) VerifiedStep {
        const max_pat_len = self.maxPatternLen();
        var nul_checked = start;

        if (mode == .leftmost_first) {
            var pos = start;
            while (pos <= haystack.len) {
                const raw_hit = self.findWatched(haystack, pos, nul_pos) orelse return .none;
                const lo = @max(pos, raw_hit.end -| max_pat_len);
                const hi_slice = @min(haystack.len, raw_hit.start +| max_pat_len);
                const used_leftmost = lo < raw_hit.start;
                const hit = if (used_leftmost)
                    (self.find(haystack[0..hi_slice], lo, .leftmost_first) orelse raw_hit)
                else
                    raw_hit;
                if (hit.start > nul_checked) nul_checked = hit.start;
                const step = if (used_leftmost or self.patterns.len <= 1)
                    self.verifyLeftmostAt(haystack, hit, verifier)
                else
                    self.verifyLeftmostAllAt(haystack, hit.start, verifier);
                switch (step) {
                    .match => |m| {
                        const check_end = @min(haystack.len, m.end);
                        if (nul_checked < check_end) {
                            if (memchr.find(memchr.native_width, haystack[0..check_end], nul_checked, 0)) |z| {
                                nul_pos.* = z;
                                return .none;
                            }
                        }
                        return .{ .match = m };
                    },
                    .aborted => |resume_pos| {
                        if (nul_checked < resume_pos) {
                            if (memchr.find(memchr.native_width, haystack[0..resume_pos], nul_checked, 0)) |z| {
                                nul_pos.* = z;
                                return .none;
                            }
                        }
                        return .{ .aborted = resume_pos };
                    },
                    .none => {},
                }
                if (hit.start < haystack.len and haystack[hit.start] == 0) {
                    nul_pos.* = hit.start;
                    return .none;
                }
                if (hit.start >= haystack.len) return .none;
                pos = hit.start + 1;
                if (pos > nul_checked) nul_checked = pos;
            }
            return .none;
        }

        var best: ?VerifiedMatch = null;
        var pos = start;
        outer: while (pos <= haystack.len) {
            if (best) |cur| {
                if (pos > cur.end) break;
            }
            const hit = if (best == null) blk: {
                const raw_hit = self.findWatched(haystack, pos, nul_pos) orelse return .none;
                const lo = @max(pos, raw_hit.end -| max_pat_len);
                const hi_slice = @min(haystack.len, raw_hit.start +| max_pat_len);
                const left_hit = if (lo < raw_hit.start)
                    (self.find(haystack[0..hi_slice], lo, .leftmost_first) orelse raw_hit)
                else
                    raw_hit;
                if (left_hit.start > nul_checked) nul_checked = left_hit.start;
                break :blk left_hit;
            } else blk: {
                const left_hit = self.find(haystack, pos, .leftmost_first) orelse break :outer;
                if (left_hit.start > best.?.end) break :outer;
                break :blk left_hit;
            };
            if (self.verifyEarliestAt(haystack, hit, &best, verifier)) |abort_pos| {
                if (nul_checked < abort_pos) {
                    if (memchr.find(memchr.native_width, haystack[0..abort_pos], nul_checked, 0)) |z| {
                        nul_pos.* = z;
                        return .none;
                    }
                }
                return .{ .aborted = abort_pos };
            }
            if (best == null) {
                if (hit.start < haystack.len and haystack[hit.start] == 0) {
                    nul_pos.* = hit.start;
                    return .none;
                }
            }
            if (hit.start >= haystack.len) break;
            pos = hit.start + 1;
            if (best == null and pos > nul_checked) nul_checked = pos;
        }
        const chosen = best orelse return .none;
        const check_end = @min(haystack.len, chosen.end);
        if (nul_checked < check_end) {
            if (memchr.find(memchr.native_width, haystack[0..check_end], nul_checked, 0)) |z| {
                nul_pos.* = z;
                return .none;
            }
        }
        return .{ .match = chosen };
    }
};

fn preferVerifiedEarliest(a: VerifiedMatch, b: VerifiedMatch) bool {
    if (a.end != b.end) return a.end < b.end;
    if (a.start != b.start) return a.start < b.start;
    return a.id < b.id;
}

inline fn callAllowAny(allow: anytype, haystack: []const u8, start: usize, end: usize) bool {
    const T = @TypeOf(allow);
    if (@typeInfo(T) == .@"fn" or (@typeInfo(T) == .pointer and @typeInfo(@typeInfo(T).pointer.child) == .@"fn")) {
        return allow(haystack, start, end);
    }
    return matcher.callAllow(allow, haystack, start, end);
}

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
    const max_variants_per_pattern: usize = @max(options.max_unicode_variants, 1);
    for (patterns) |pat| {
        const ig = patternIgnoresCaseUnicode(pat, options.case);
        if (ig and unicode_fold.needsUnicodeExpansion(pat)) {
            if (unicode_fold.countBranches(pat, true) > max_variants_per_pattern) {
                return initUnicodeFallback(allocator, patterns, options);
            }
        }
    }

    var variant_bytes = std.ArrayList([]u8).empty;
    errdefer {
        for (variant_bytes.items) |v| allocator.free(v);
        variant_bytes.deinit(allocator);
    }
    var variant_flags = std.ArrayList(bool).empty;
    defer variant_flags.deinit(allocator);
    var variant_ids = std.ArrayList(u32).empty;
    errdefer variant_ids.deinit(allocator);

    for (patterns, 0..) |pat, orig_idx| {
        const orig_id: u32 = @intCast(orig_idx);
        const ig = patternIgnoresCaseUnicode(pat, options.case);
        if (ig and unicode_fold.needsUnicodeExpansion(pat)) {
            const before = variant_bytes.items.len;
            try unicode_fold.expandPatternVariants(allocator, pat, &variant_bytes, max_variants_per_pattern);
            const added = variant_bytes.items.len - before;
            try variant_flags.appendNTimes(allocator, true, added);
            try variant_ids.appendNTimes(allocator, orig_id, added);
        } else {
            const copy = try allocator.dupe(u8, pat);
            errdefer allocator.free(copy);
            try variant_bytes.append(allocator, copy);
            try variant_flags.append(allocator, ig);
            try variant_ids.append(allocator, orig_id);
        }
    }

    // Check pattern count and byte limits on the expanded variants BEFORE allocating owned slices.
    var within_limits = variant_bytes.items.len <= matcher.patternCountLimit(options);
    if (within_limits) {
        const byte_limit = matcher.patternBytesLimit(options);
        var total: usize = 0;
        for (variant_bytes.items) |v| {
            total = std.math.add(usize, total, v.len) catch {
                within_limits = false;
                break;
            };
            if (total > byte_limit) {
                within_limits = false;
                break;
            }
        }
    }
    if (!within_limits) {
        for (variant_bytes.items) |v| allocator.free(v);
        variant_bytes.deinit(allocator);
        variant_bytes = .empty;
        variant_ids.deinit(allocator);
        variant_ids = .empty;
        return initUnicodeFallback(allocator, patterns, options);
    }

    const owned_slices = try allocator.alloc([]const u8, variant_bytes.items.len);
    errdefer allocator.free(owned_slices);
    for (variant_bytes.items, 0..) |v, i| owned_slices[i] = v;

    const owned_variants = try variant_bytes.toOwnedSlice(allocator);
    errdefer {
        for (owned_variants) |v| allocator.free(v);
        allocator.free(owned_variants);
    }
    const owned_ids = try variant_ids.toOwnedSlice(allocator);
    errdefer allocator.free(owned_ids);

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
        res.unicode_case = true;
        res.owned_patterns = owned_slices;
        res.owned_variant_bytes = owned_variants;
        res.owned_pattern_ids = owned_ids;
        res.patterns_alloc = allocator;
        return res;
    }

    var max_v_len: usize = 0;
    for (owned_slices) |s| {
        if (s.len > max_v_len) max_v_len = s.len;
    }
    const ml_win = @max(options.max_multiline_window, max_v_len);

    const flags = try allocator.dupe(bool, variant_flags.items);
    return .{
        .kind = .{ .mixed = .{
            .ignore = flags,
            .allocator = allocator,
        } },
        .ignore_case = false,
        .unicode_case = true,
        .multiline = options.multiline,
        .max_multiline_window = ml_win,
        .empty_only = false,
        .patterns = owned_slices,
        .owned_patterns = owned_slices,
        .owned_variant_bytes = owned_variants,
        .owned_pattern_ids = owned_ids,
        .patterns_alloc = allocator,
    };
}

fn initUnicodeFallback(
    allocator: std.mem.Allocator,
    patterns: []const []const u8,
    options: matcher.FindOptions,
) error{OutOfMemory}!Multi {
    var max_pat_len: usize = 0;
    for (patterns) |pat| {
        if (pat.len > max_pat_len) max_pat_len = pat.len;
    }
    const ml_win = @max(options.max_multiline_window, max_pat_len *| 3);
    const flags = try allocator.alloc(bool, patterns.len);
    errdefer allocator.free(flags);
    for (patterns, flags) |pat, *flag| {
        flag.* = patternIgnoresCaseUnicode(pat, options.case);
    }
    return .{
        .kind = .{ .mixed = .{
            .ignore = flags,
            .allocator = allocator,
        } },
        .ignore_case = false,
        .unicode_case = true,
        .multiline = options.multiline,
        .max_multiline_window = ml_win,
        .empty_only = false,
        .patterns = patterns,
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

fn preferTeddyOverPairs(patterns: []const []const u8) bool {
    if (!teddyEligible(patterns)) return false;
    if (patterns.len > 4) return true;
    if (patterns.len >= 3) {
        for (patterns) |pat| {
            if (pat.len >= 8) return true;
        }
    }
    return false;
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
    return .{ .start = found.start, .end = found.end, .pattern_id = found.id };
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
    const expect_teddy = teddy_static or (teddy_runtime and cpuid.detectX86().ssse3);
    if (expect_teddy) {
        try std.testing.expect(multi.kind == .teddy or multi.kind == .teddy_ssse3 or multi.kind == .teddy_avx2_rt);
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
    const expect_teddy = teddy_static or (teddy_runtime and cpuid.detectX86().ssse3);
    if (expect_teddy) {
        try std.testing.expect(multi.kind == .teddy or multi.kind == .teddy_ssse3 or multi.kind == .teddy_avx2_rt);
    } else {
        try std.testing.expect(multi.kind == .pairs);
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
    const expect_teddy = teddy_static or (teddy_runtime and cpuid.detectX86().ssse3);
    if (expect_teddy) {
        try std.testing.expect(multi.kind == .teddy or multi.kind == .teddy_ssse3 or multi.kind == .teddy_avx2_rt);
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
    const expect_teddy = teddy_static or (teddy_runtime and cpuid.detectX86().ssse3);
    const teddy_name = if (expect_teddy) "teddy" else "ac";
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

    // 3. Per-pattern variant expansion limit does not drop Unicode patterns placed after >32 preceding patterns.
    var many_pats: [40][]const u8 = undefined;
    for (0..39) |i| many_pats[i] = if (i % 2 == 0) "alpha" else "bravo";
    many_pats[39] = "straße";
    var many_uni = try Multi.init(std.testing.allocator, &many_pats, .{
        .case = .insensitive,
        .unicode_case = true,
    });
    defer many_uni.deinit();
    try std.testing.expectEqual(@as(usize, 0), many_uni.find("STRA\u{1E9E}E", 0, .earliest).?.start);

    // 4. Patterns with >64 fold variants (e.g., 7 Greek letters = 2^7 = 128 variants) fall back to direct folded scan without losing matches.
    var deep_uni = try Multi.init(std.testing.allocator, &.{"αβγδεζη"}, .{
        .case = .insensitive,
        .unicode_case = true,
    });
    defer deep_uni.deinit();
    try std.testing.expectEqual(@as(usize, 2), deep_uni.find("xxΑΒΓΔΕΖΗyy", 0, .earliest).?.start);
    try std.testing.expect(deep_uni.acceptsSpan("ΑβΓδΕζΗ", .earliest));
}

test "Multi pattern_id attribution and Challenger bug regressions" {
    // 1. Challenger Bug 1: findAllowed in .earliest mode with overlapping/co-starting patterns
    var allow_multi = try Multi.init(std.testing.allocator, &.{ "foobar", "foo" }, .{});
    defer allow_multi.deinit();
    const RejectLong = struct {
        pub fn allow(_: @This(), _: []const u8, s: usize, e: usize) bool {
            return (e - s) == 3;
        }
    };
    const allowed_hit = allow_multi.findAllowed("foobar", 0, .earliest, RejectLong{}).?;
    try std.testing.expectEqual(@as(usize, 0), allowed_hit.start);
    try std.testing.expectEqual(@as(usize, 3), allowed_hit.end);
    try std.testing.expectEqual(@as(?u32, 1), allowed_hit.pattern_id);

    // 2. Challenger Bug 2: pairs >8 digram hash buckets NUL watching before vs after match
    const nine_pats = [_][]const u8{
        "p0_aa", "p1_bb", "p2_cc", "p3_dd", "p4_ee",
        "p5_ff", "p6_gg", "p7_hh", "p8_ii",
    };
    var nine_multi = try Multi.init(std.testing.allocator, &nine_pats, .{});
    defer nine_multi.deinit();
    var nul_before: ?usize = null;
    try std.testing.expect(nine_multi.findWatched("xx\x00yy p8_ii", 0, &nul_before) == null);
    try std.testing.expectEqual(@as(?usize, 2), nul_before);

    var nul_after: ?usize = null;
    const hit_after = nine_multi.findWatched("p8_ii\x00zz", 0, &nul_after).?;
    try std.testing.expectEqual(@as(usize, 0), hit_after.start);
    try std.testing.expectEqual(@as(usize, 5), hit_after.end);
    try std.testing.expectEqual(@as(?u32, 8), hit_after.pattern_id);

    // 3. Challenger Bug 3: Aho-Corasick NUL inside 16-byte scalar step window before 64-byte SIMD skip
    var ac_pats: [35][]const u8 = undefined;
    var ac_bufs: [35][6]u8 = undefined;
    for (0..35) |i| {
        _ = try std.fmt.bufPrint(&ac_bufs[i], "pat{d:0>2}x", .{i});
        ac_pats[i] = &ac_bufs[i];
    }
    var ac_multi = try Multi.init(std.testing.allocator, &ac_pats, .{});
    defer ac_multi.deinit();
    var ac_hay: [96]u8 = @splat('p');
    ac_hay[5] = 0; // NUL inside the 16-byte scalar window triggered by 'p' prefix
    var ac_nul: ?usize = null;
    try std.testing.expect(ac_multi.findWatched(&ac_hay, 0, &ac_nul) == null);
    try std.testing.expectEqual(@as(?usize, 5), ac_nul);

    // 4. Challenger Bug 4: initUnicodeFolded OOM safety without double-free
    var fail_idx: usize = 0;
    while (fail_idx < 16) : (fail_idx += 1) {
        var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_idx });
        if (Multi.init(fa.allocator(), &.{ "δelta", "σigma", "αβγδεζη" }, .{
            .case = .insensitive,
            .unicode_case = true,
        })) |*m| {
            var mut_m = m.*;
            mut_m.deinit();
            break;
        } else |_| {}
    }
}

test "Multi findVerified and findVerifiedWatched across Teddy and fallback engines" {
    const alloc = std.testing.allocator;

    // 1. Teddy (5+ patterns): reject decoys, accept extended match, watch NUL inside verified match
    {
        var m = try Multi.init(alloc, &.{ "err_", "warn_", "fail_", "crit_", "fatal_" }, .{});
        defer m.deinit();
        var hay: [256]u8 = @splat(' ');
        @memcpy(hay[10..18], "err_nope");
        @memcpy(hay[60..71], "fatal_OK999");

        const V = struct {
            pub fn verify(_: @This(), h: []const u8, _: usize, pat_end: usize, _: usize) VerifyResult {
                if (pat_end + 5 <= h.len and std.mem.eql(u8, h[pat_end .. pat_end + 2], "OK")) {
                    return .{ .accept = pat_end + 5 };
                }
                return .reject;
            }
        };
        switch (m.findVerified(&hay, 0, .leftmost_first, V{})) {
            .match => |hit| {
                try std.testing.expectEqual(@as(usize, 60), hit.start);
                try std.testing.expectEqual(@as(usize, 71), hit.end);
                try std.testing.expectEqual(@as(usize, 4), hit.id);
            },
            else => return error.TestExpectedEqual,
        }

        hay[68] = 0; // NUL inside verified suffix
        var nul_in: ?usize = null;
        try std.testing.expect(m.findVerifiedWatched(&hay, 0, .leftmost_first, &nul_in, V{}) == .none);
        try std.testing.expectEqual(@as(?usize, 68), nul_in);
    }

    // 2. Pairs fallback: co-starting overlapping patterns ("foobar", "foo") priority & rejection
    {
        var m = try Multi.init(alloc, &.{ "foobar", "foo" }, .{});
        defer m.deinit();
        try std.testing.expectEqualStrings("pairs", m.engineName());

        const AcceptAll = struct {
            pub fn verify(_: @This(), _: []const u8, _: usize, pat_end: usize, _: usize) VerifyResult {
                return .{ .accept = pat_end };
            }
        };
        var nul_a: ?usize = null;
        switch (m.findVerifiedWatched("foobar", 0, .leftmost_first, &nul_a, AcceptAll{})) {
            .match => |hit| {
                try std.testing.expectEqual(@as(usize, 0), hit.start);
                try std.testing.expectEqual(@as(usize, 6), hit.end);
                try std.testing.expectEqual(@as(usize, 0), hit.id);
            },
            else => return error.TestExpectedEqual,
        }
        try std.testing.expectEqual(@as(?usize, null), nul_a);

        const OnlyId1 = struct {
            pub fn verify(_: @This(), _: []const u8, _: usize, pat_end: usize, pat_id: usize) VerifyResult {
                return if (pat_id == 1) .{ .accept = pat_end + 2 } else .reject;
            }
        };
        switch (m.findVerified("foobar", 0, .leftmost_first, OnlyId1{})) {
            .match => |hit| {
                try std.testing.expectEqual(@as(usize, 0), hit.start);
                try std.testing.expectEqual(@as(usize, 5), hit.end);
                try std.testing.expectEqual(@as(usize, 1), hit.id);
            },
            else => return error.TestExpectedEqual,
        }

        // NUL inside verified suffix on pairs fallback
        var nul_b: ?usize = null;
        try std.testing.expect(m.findVerifiedWatched("foo\x00ar", 0, .leftmost_first, &nul_b, OnlyId1{}) == .none);
        try std.testing.expectEqual(@as(?usize, 3), nul_b);
    }

    // 3. Byteset fallback: abort + resume
    {
        var m = try Multi.init(alloc, &.{ "q", "z" }, .{});
        defer m.deinit();
        try std.testing.expectEqualStrings("bytes", m.engineName());

        const AbortOnQ = struct {
            pub fn verify(_: @This(), _: []const u8, _: usize, pat_end: usize, pat_id: usize) VerifyResult {
                if (pat_id == 0) return .abort;
                return .{ .accept = pat_end };
            }
        };
        var nul_c: ?usize = null;
        const step = m.findVerifiedWatched("aaqbbz", 0, .leftmost_first, &nul_c, AbortOnQ{});
        switch (step) {
            .aborted => |pos| try std.testing.expectEqual(@as(usize, 2), pos),
            else => return error.TestExpectedEqual,
        }
        try std.testing.expectEqual(@as(?usize, null), nul_c);
    }
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
