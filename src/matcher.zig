//! [Module] matcher.zig
//! [Layer] Layer 2 — Pattern Matcher Contract & Compile-Time Trait Introspection
//! [Role] Defines the zero-cost `Matcher` protocol (`Match`, `MatchMode`, `CaseMode`, `RequiredLiteral`, `FindOptions`)
//!        and `MatcherTraits(M)` compile-time introspection for plug-and-play matcher extensibility.
//! [Invariants]
//!   1. Searcher never depends on a concrete matcher implementation; any type implementing `find` satisfies the contract.
//!   2. Optional capabilities (`requiredLiteral`, `findCaptures`, `acceptsSpan`, `resetStats`, multiline window bounds)
//!      are resolved at `comptime` with zero virtual-dispatch overhead.
//! [HotPath] `MatcherTraits(M)` resolves entirely at compile time.

const std = @import("std");

/// Matching semantics.
/// With a single literal, both modes produce the same result: the leftmost match is also the earliest match.
/// They only diverge with multiple patterns. `leftmost_first` matches the alternation order of `rg -F` and is used for column numbers and highlighting.
pub const MatchMode = enum {
    /// The match with the earliest end position. On ties, the leftmost start position wins; further ties prefer the pattern added earlier.
    earliest,
    /// The match with the leftmost start position. At the same start position, the pattern added earlier wins rather than the longer one.
    leftmost_first,
};

/// A single match. Offsets are relative to the `haystack` passed to `find`, not absolute file offsets.
pub const Match = struct {
    start: usize,
    end: usize,
    pattern_id: ?u32 = null,
};

/// Invokes `allow_arg.allow(haystack, start, end)` whether `allow_arg` is passed by value or pointer.
pub inline fn callAllow(allow_arg: anytype, haystack: []const u8, start: usize, end: usize) bool {
    return switch (@typeInfo(@TypeOf(allow_arg))) {
        .pointer => allow_arg.allow(haystack, start, end),
        else => allow_arg.allow(haystack, start, end),
    };
}

/// Type-erased `allow_ctx` wrapper for `AnyMatcher.findAllowed`.
pub const ErasedAllow = struct {
    ptr: *const anyopaque,
    allow_fn: *const fn (*const anyopaque, []const u8, usize, usize) bool,

    pub inline fn allow(self: ErasedAllow, haystack: []const u8, start: usize, end: usize) bool {
        return self.allow_fn(self.ptr, haystack, start, end);
    }
};

/// Required literal extracted for regex prefiltering. When provided by the matcher, Searcher uses it for prefiltering first
/// and then verifies with the full matcher. Literal matchers return the pattern itself with offset 0.
pub const RequiredLiteral = struct {
    bytes: []const u8,
    /// Starting offset of this literal within the full match.
    offset_in_match: usize,
};

/// Case sensitivity mode.
/// `smart` evaluates each pattern individually: case-insensitive only if all lowercase, and case-sensitive if uppercase appears.
/// This differs from `rg -S`, which evaluates the entire pattern set together.
pub const CaseMode = enum {
    sensitive,
    insensitive,
    smart,
};

/// Hard cap on pattern count. Callers may lower the limit, but cannot exceed this value.
pub const pattern_count_hard_cap: usize = 1024;
/// Hard cap on total byte length across all patterns, summed over each pattern's length.
pub const pattern_bytes_hard_cap: usize = 256 * 1024;

pub const LimitError = error{
    PatternCountExceeded,
    PatternBytesExceeded,
};

/// Options for constructing a finder. Lower values in the frequency table indicate bytes better suited as prefilter anchors.
pub const FindOptions = struct {
    case: CaseMode = .sensitive,
    /// Enable Unicode Simple Case Folding. Defaults to false (ASCII case folding only).
    unicode_case: bool = false,
    /// Null uses the built-in frequency table.
    frequency: ?[256]u8 = null,
    /// For patterns longer than 32 bytes, when the distance between the two rarest bytes is less than 8 and verification fails,
    /// subsequent searches switch to Two-Way. Set to 1 or greater to stay in packed pair.
    /// Patterns of 32 bytes or fewer do not use this threshold.
    prefilter_fp_threshold: f32 = 0.80,
    /// Maximum number of patterns. Null uses the hard cap; values above the hard cap are still rejected at the hard cap.
    max_pattern_count: ?usize = null,
    /// Maximum total pattern bytes. Null uses the hard cap; values above the hard cap are still rejected at the hard cap.
    max_pattern_bytes: ?usize = null,
};

pub fn patternCountLimit(options: FindOptions) usize {
    return @min(options.max_pattern_count orelse pattern_count_hard_cap, pattern_count_hard_cap);
}

pub fn patternBytesLimit(options: FindOptions) usize {
    return @min(options.max_pattern_bytes orelse pattern_bytes_hard_cap, pattern_bytes_hard_cap);
}

/// Called before allocating automata, Teddy tables, or pair tables. Rejects before searching begins if limits are exceeded.
pub fn checkPatternLimits(patterns: []const []const u8, options: FindOptions) LimitError!void {
    if (patterns.len > patternCountLimit(options)) return error.PatternCountExceeded;
    const byte_limit = patternBytesLimit(options);
    var total: usize = 0;
    for (patterns) |pat| {
        total = std.math.add(usize, total, pat.len) catch return error.PatternBytesExceeded;
        if (total > byte_limit) return error.PatternBytesExceeded;
    }
}

/// Expected method shape for a Matcher. Documented here for reference; produces no runtime object.
///
/// Required:
/// ```zig
/// pub fn find(self: *const Self, haystack: []const u8, start: usize, mode: MatchMode) ?Match
/// ```
///
/// Optional extension hooks (auto-discovered at `comptime` by `MatcherTraits`):
/// ```zig
/// pub fn requiredLiteral(self: *const Self) ?RequiredLiteral
/// pub fn acceptsSpan(self: *const Self, span: []const u8, mode: MatchMode) bool
/// pub fn findCaptures(self: *const Self, haystack: []const u8, start: usize) ?Captures
/// pub fn resetStats(self: *const Self) void
/// ```
pub const matcher_shape_docs = {};

/// Unwraps a pointer type `*M` or `*const M` to its underlying struct/union type `M`.
pub fn BaseMatcherType(comptime M: type) type {
    return switch (@typeInfo(M)) {
        .pointer => |p| p.child,
        else => M,
    };
}

/// Compile-time capability descriptor for any matcher type `M` (value `M`, `*M`, or `*const M`).
/// Provides a single point of truth for matcher extensibility across the search pipeline.
pub fn MatcherTraits(comptime M: type) type {
    const Base = BaseMatcherType(M);
    if (!@hasDecl(Base, "find")) {
        @compileError("Matcher type '" ++ @typeName(Base) ++ "' must declare `pub fn find(self, haystack: []const u8, start: usize, mode: MatchMode) ?Match`");
    }
    return struct {
        pub const Self = Base;
        pub const is_pointer = @typeInfo(M) == .pointer;
        pub const is_const_pointer = switch (@typeInfo(M)) {
            .pointer => |p| p.is_const,
            else => false,
        };
        pub const is_any_matcher = Base == AnyMatcher;
        pub const has_required_literal = @hasDecl(Base, "requiredLiteral");
        pub const has_accepts_span = @hasDecl(Base, "acceptsSpan");
        pub const has_match_span = @hasDecl(Base, "matchSpan");
        pub const has_find_captures = @hasDecl(Base, "findCaptures");
        pub const has_group_index = @hasDecl(Base, "groupIndexByName");
        pub const has_reset_stats = @hasDecl(Base, "resetStats");
        pub const has_multiline_field = @hasField(Base, "multiline");
        pub const has_anchored_start_field = @hasField(Base, "anchored_start");
        pub const has_needle_field = @hasField(Base, "needle");
        pub const has_max_len_field = @hasField(Base, "max_len");
        pub const has_insts_field = @hasField(Base, "insts");
        pub const has_case_mode_field = @hasField(Base, "case_mode");
        pub const has_unicode_case_field = @hasField(Base, "unicode_case");
        pub const has_is_multiline_fn = @hasDecl(Base, "isMultiline");
        pub const has_is_start_anchored_fn = @hasDecl(Base, "isStartAnchored");
        pub const has_multiline_window_fn = @hasDecl(Base, "multilineWindow");
    };
}

/// Validates at compile time that `M` conforms to the `Matcher` contract.
pub fn validateMatcher(comptime M: type) void {
    _ = MatcherTraits(M);
}

/// Runtime-polymorphic Matcher wrapper.
/// Satisfies `MatcherTraits` as `AnyMatcher`, `*AnyMatcher`, or `*const AnyMatcher` so a single compiled
/// search pipeline instantiation can dispatch across `Finder`, `Multi`, `Regex`, `RegexSet`, or custom matchers.
pub const AnyMatcher = struct {
    ctx: *const anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        find: *const fn (ctx: *const anyopaque, haystack: []const u8, start: usize, mode: MatchMode) ?Match,
        findReadOnly: *const fn (ctx: *const anyopaque, haystack: []const u8, start: usize, mode: MatchMode) ?Match,
        findWatched: *const fn (ctx: *const anyopaque, haystack: []const u8, start: usize, nul: *?usize) ?Match,
        findAllowedErased: *const fn (ctx: *const anyopaque, haystack: []const u8, start: usize, mode: MatchMode, allow_ctx: ErasedAllow) ?Match,
        acceptsSpan: *const fn (ctx: *const anyopaque, span: []const u8, mode: MatchMode) bool,
        matchSpan: *const fn (ctx: *const anyopaque, span: []const u8, mode: MatchMode) ?Match,
        isMultiline: *const fn (ctx: *const anyopaque) bool,
        isStartAnchored: *const fn (ctx: *const anyopaque) bool,
        multilineWindow: *const fn (ctx: *const anyopaque) usize,
        resetStats: *const fn (ctx: *const anyopaque) void,
        is_capture_regex: bool = false,
    };

    /// Constructs an `AnyMatcher` from a pointer `ptr` (`*M` or `*const M`).
    /// `M` may be specified either as the value type (`Finder`, `Multi`, `Regex`, `RegexSet`)
    /// or as a pointer type (`*Finder`, `*const Multi`, etc.).
    pub fn init(comptime M: type, ptr: anytype) AnyMatcher {
        const Base = BaseMatcherType(M);
        const PtrType = @TypeOf(ptr);
        comptime {
            if (@typeInfo(PtrType) != .pointer) {
                @compileError("AnyMatcher.init expects a pointer as second argument, found " ++ @typeName(PtrType));
            }
            const Child = @typeInfo(PtrType).pointer.child;
            if (Child != Base) {
                @compileError("AnyMatcher.init type mismatch: expected pointer to " ++ @typeName(Base) ++ ", found " ++ @typeName(PtrType));
            }
            validateMatcher(Base);
        }
        if (Base == AnyMatcher) {
            return ptr.*;
        }
        const gen = struct {
            fn cast(ctx: *const anyopaque) *Base {
                return @ptrCast(@alignCast(@constCast(ctx)));
            }

            fn findFn(ctx: *const anyopaque, haystack: []const u8, start: usize, mode: MatchMode) ?Match {
                return cast(ctx).find(haystack, start, mode);
            }

            fn findReadOnlyFn(ctx: *const anyopaque, haystack: []const u8, start: usize, mode: MatchMode) ?Match {
                const self = cast(ctx);
                if (@hasDecl(Base, "findReadOnly")) {
                    return self.findReadOnly(haystack, start, mode);
                }
                return self.find(haystack, start, mode);
            }

            fn findWatchedFn(ctx: *const anyopaque, haystack: []const u8, start: usize, nul: *?usize) ?Match {
                const self = cast(ctx);
                if (@hasDecl(Base, "findWatched")) {
                    return self.findWatched(haystack, start, nul);
                }
                if (start > haystack.len) return null;
                if (self.find(haystack, start, .earliest)) |hit| {
                    const check_end = @min(haystack.len, @max(start, hit.end));
                    if (std.mem.findScalarPos(u8, haystack[0..check_end], start, 0)) |at| {
                        nul.* = at;
                        return null;
                    }
                    return hit;
                }
                if (std.mem.findScalarPos(u8, haystack, start, 0)) |at| {
                    nul.* = at;
                }
                return null;
            }

            fn findAllowedErasedFn(ctx: *const anyopaque, haystack: []const u8, start: usize, mode: MatchMode, allow_ctx: ErasedAllow) ?Match {
                const self = cast(ctx);
                if (@hasDecl(Base, "findAllowed")) {
                    return self.findAllowed(haystack, start, mode, allow_ctx);
                }
                var pos = start;
                while (pos <= haystack.len) {
                    const hit = self.find(haystack, pos, mode) orelse return null;
                    if (allow_ctx.allow(haystack, hit.start, hit.end)) return hit;
                    pos = hit.start + 1;
                }
                return null;
            }

            fn matchSpanFn(ctx: *const anyopaque, span: []const u8, mode: MatchMode) ?Match {
                const self = cast(ctx);
                if (@hasDecl(Base, "matchSpan")) {
                    return self.matchSpan(span, mode);
                }
                const hit = self.find(span, 0, mode) orelse return null;
                if (hit.start == 0 and hit.end == span.len) return hit;
                return null;
            }

            fn acceptsSpanFn(ctx: *const anyopaque, span: []const u8, mode: MatchMode) bool {
                const self = cast(ctx);
                if (@hasDecl(Base, "acceptsSpan")) {
                    return self.acceptsSpan(span, mode);
                }
                return matchSpanFn(ctx, span, mode) != null;
            }

            fn isMultilineFn(ctx: *const anyopaque) bool {
                const self = cast(ctx);
                if (@hasDecl(Base, "isMultiline")) {
                    return self.isMultiline();
                }
                if (@hasField(Base, "multiline")) {
                    return self.multiline;
                }
                return false;
            }

            fn isStartAnchoredFn(ctx: *const anyopaque) bool {
                const self = cast(ctx);
                if (@hasDecl(Base, "isStartAnchored")) {
                    return self.isStartAnchored();
                }
                if (@hasField(Base, "anchored_start")) {
                    return self.anchored_start;
                }
                return false;
            }

            fn multilineWindowFn(ctx: *const anyopaque) usize {
                const self = cast(ctx);
                if (@hasDecl(Base, "multilineWindow")) {
                    return self.multilineWindow();
                }
                if (@hasField(Base, "needle")) {
                    return @max(self.needle.len * 2, 64 * 1024);
                }
                if (@hasField(Base, "max_len")) {
                    return @max(self.max_len * 2, 64 * 1024);
                }
                if (@hasField(Base, "insts")) {
                    return @max(self.insts.len * 64, 256 * 1024);
                }
                return 256 * 1024;
            }

            fn resetStatsFn(ctx: *const anyopaque) void {
                if (@hasDecl(Base, "resetStats")) {
                    cast(ctx).resetStats();
                }
            }

            const vtable = VTable{
                .find = &findFn,
                .findReadOnly = &findReadOnlyFn,
                .findWatched = &findWatchedFn,
                .findAllowedErased = &findAllowedErasedFn,
                .acceptsSpan = &acceptsSpanFn,
                .matchSpan = &matchSpanFn,
                .isMultiline = &isMultilineFn,
                .isStartAnchored = &isStartAnchoredFn,
                .multilineWindow = &multilineWindowFn,
                .resetStats = &resetStatsFn,
                .is_capture_regex = @hasDecl(Base, "findCaptures") and (@hasField(Base, "group_count") or @hasField(Base, "num_captures")),
            };
        };

        return .{
            .ctx = @ptrCast(ptr),
            .vtable = &gen.vtable,
        };
    }

    pub fn from(ptr: anytype) AnyMatcher {
        return init(@TypeOf(ptr), ptr);
    }

    pub fn find(self: *const AnyMatcher, haystack: []const u8, start: usize, mode: MatchMode) ?Match {
        return self.vtable.find(self.ctx, haystack, start, mode);
    }

    pub fn findReadOnly(self: *const AnyMatcher, haystack: []const u8, start: usize, mode: MatchMode) ?Match {
        return self.vtable.findReadOnly(self.ctx, haystack, start, mode);
    }

    pub fn findWatched(self: *const AnyMatcher, haystack: []const u8, start: usize, nul: *?usize) ?Match {
        return self.vtable.findWatched(self.ctx, haystack, start, nul);
    }

    pub fn findAllowed(self: *const AnyMatcher, haystack: []const u8, start: usize, mode: MatchMode, allow_ctx: anytype) ?Match {
        const AllowArg = @TypeOf(allow_ctx);
        if (AllowArg == ErasedAllow) {
            return self.vtable.findAllowedErased(self.ctx, haystack, start, mode, allow_ctx);
        }
        return switch (@typeInfo(AllowArg)) {
            .pointer => |p| blk: {
                const Child = p.child;
                const erased = ErasedAllow{
                    .ptr = @ptrCast(allow_ctx),
                    .allow_fn = &struct {
                        fn call(raw: *const anyopaque, h: []const u8, s: usize, e: usize) bool {
                            const typed: *const Child = @ptrCast(@alignCast(raw));
                            return typed.allow(h, s, e);
                        }
                    }.call,
                };
                break :blk self.vtable.findAllowedErased(self.ctx, haystack, start, mode, erased);
            },
            else => blk: {
                var copy = allow_ctx;
                const erased = ErasedAllow{
                    .ptr = @ptrCast(&copy),
                    .allow_fn = &struct {
                        fn call(raw: *const anyopaque, h: []const u8, s: usize, e: usize) bool {
                            const typed: *const AllowArg = @ptrCast(@alignCast(raw));
                            return typed.allow(h, s, e);
                        }
                    }.call,
                };
                break :blk self.vtable.findAllowedErased(self.ctx, haystack, start, mode, erased);
            },
        };
    }

    pub fn acceptsSpan(self: *const AnyMatcher, span: []const u8, mode: MatchMode) bool {
        return self.vtable.acceptsSpan(self.ctx, span, mode);
    }

    pub fn matchSpan(self: *const AnyMatcher, span: []const u8, mode: MatchMode) ?Match {
        return self.vtable.matchSpan(self.ctx, span, mode);
    }

    pub fn isMultiline(self: *const AnyMatcher) bool {
        return self.vtable.isMultiline(self.ctx);
    }

    pub fn isStartAnchored(self: *const AnyMatcher) bool {
        return self.vtable.isStartAnchored(self.ctx);
    }

    pub fn multilineWindow(self: *const AnyMatcher) usize {
        return self.vtable.multilineWindow(self.ctx);
    }

    pub fn resetStats(self: *const AnyMatcher) void {
        self.vtable.resetStats(self.ctx);
    }
};

test "MatcherTraits validates custom plug-and-play matcher at comptime" {
    const CustomPrefixMatcher = struct {
        prefix: []const u8,
        pub fn find(self: *const @This(), haystack: []const u8, start: usize, _: MatchMode) ?Match {
            if (start > haystack.len) return null;
            const rel = std.mem.indexOfPos(u8, haystack, start, self.prefix) orelse return null;
            return .{ .start = rel, .end = rel + self.prefix.len, .pattern_id = 7 };
        }
    };
    validateMatcher(CustomPrefixMatcher);
    validateMatcher(*CustomPrefixMatcher);
    validateMatcher(*const CustomPrefixMatcher);
    validateMatcher(AnyMatcher);
    validateMatcher(*AnyMatcher);
    validateMatcher(*const AnyMatcher);
    const T = MatcherTraits(CustomPrefixMatcher);
    try std.testing.expect(!T.has_find_captures);
    const m = CustomPrefixMatcher{ .prefix = "abc" };
    const hit = m.find("xxabcyy", 0, .earliest).?;
    try std.testing.expectEqual(@as(usize, 2), hit.start);
    try std.testing.expectEqual(@as(usize, 5), hit.end);
    try std.testing.expectEqual(@as(?u32, 7), hit.pattern_id);

    const any = AnyMatcher.init(CustomPrefixMatcher, &m);
    const any_hit = any.find("xxabcyy", 0, .earliest).?;
    try std.testing.expectEqual(@as(usize, 2), any_hit.start);
    try std.testing.expectEqual(@as(usize, 5), any_hit.end);
    try std.testing.expectEqual(@as(?u32, 7), any_hit.pattern_id);
    try std.testing.expect(any.acceptsSpan("abc", .earliest));
    try std.testing.expect(!any.acceptsSpan("abcd", .earliest));
}

test "AnyMatcher wraps Finder and Multi (value and const pointer)" {
    const finder_mod = @import("finder/finder.zig");
    const multi_mod = @import("finder/multi.zig");
    _ = @import("finder/pairs.zig");
    _ = @import("finder/aho.zig");
    if (@import("build_options").teddy != .off) {
        _ = @import("finder/teddy.zig");
    }

    const f = try finder_mod.Finder.init("match", .{});
    const any_f = AnyMatcher.init(finder_mod.Finder, &f);
    const any_f_const = AnyMatcher.init(*const finder_mod.Finder, &f);
    try std.testing.expectEqual(@as(usize, 4), any_f.find("abc match xyz", 0, .earliest).?.start);
    try std.testing.expectEqual(@as(usize, 4), any_f_const.find("abc match xyz", 0, .earliest).?.start);

    var nul_pos: ?usize = null;
    try std.testing.expect(any_f.findWatched("abc\x00def match", 0, &nul_pos) == null);
    try std.testing.expectEqual(@as(?usize, 3), nul_pos);

    var m = try multi_mod.Multi.init(std.testing.allocator, &.{ "alpha", "beta" }, .{});
    defer m.deinit();
    const any_m = AnyMatcher.init(multi_mod.Multi, &m);
    const hit = any_m.find("xx beta yy", 0, .earliest).?;
    try std.testing.expectEqual(@as(usize, 3), hit.start);
    try std.testing.expectEqual(@as(usize, 7), hit.end);
    try std.testing.expectEqual(@as(?u32, 1), hit.pattern_id);
}


