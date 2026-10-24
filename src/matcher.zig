//! Matcher contract. Both literal kernels and regex engines implement `find`.
//! Searcher does not depend on a concrete kernel; it only requires this shape.

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
};

/// Required literal extracted for regex prefiltering. When provided by the matcher, Searcher uses it for prefiltering first
/// and then verifies with the full matcher. Literal matchers return the pattern itself with offset 0.
pub const RequiredLiteral = struct {
    bytes: []const u8,
    /// Starting offset of this literal within the full match.
    offset_in_match: usize,
};

/// Case sensitivity mode.
/// `smart` evaluates each pattern individually: case-insensitive only if all lowercase, and case-sensitive if `A-Z` appears.
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
/// ```
/// pub fn find(self: *Self, haystack: []const u8, start: usize, mode: MatchMode) ?Match
/// ```
///
/// Optional:
///
/// ```
/// pub fn requiredLiteral(self: *const Self) ?RequiredLiteral
/// ```
pub const matcher_shape_docs = {};
