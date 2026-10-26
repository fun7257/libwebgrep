//! Unicode Simple Case Folding.
//!
//! Design principles:
//! 1. Pure ASCII patterns without cross-ASCII folding codepoints (such as `k`/`K` folding with U+212A `K`
//!    or `s`/`S` folding with U+017F `ſ`) stay on the existing branchless SIMD fast path.
//! 2. Patterns containing Unicode case variants are expanded at construction time per pattern under `smart`
//!    or `insensitive` mode into equivalent UTF-8 pattern variants (guarded by `checkPatternLimits`),
//!    then searched by `Multi`'s SIMD engines.

const std = @import("std");

pub const FoldGroup = struct {
    /// All codepoints in the same simple case-folding equivalence class (both uppercase and lowercase).
    cps: []const u21,
    /// Uppercase / Titlecase codepoints in this class, used for per-pattern `smart` case detection.
    uppers: []const u21,
};

/// Common multilingual Unicode Simple Case Folding equivalence classes (covering Latin Extended, Greek,
/// Cyrillic, cross-ASCII special codepoints, etc.). Regular contiguous ranges (such as Latin-1,
/// basic Cyrillic, and basic Greek) are handled via range arithmetic alongside this table.
const special_groups = [_]FoldGroup{
    // Cross-ASCII special codepoints
    .{ .cps = &.{ 'k', 'K', 0x212A }, .uppers = &.{'K', 0x212A} }, // Kelvin sign K
    .{ .cps = &.{ 's', 'S', 0x017F }, .uppers = &.{'S'} }, // Long s ſ
    // German Sharp S (U+00DF ß <-> U+1E9E ẞ)
    .{ .cps = &.{ 0x00DF, 0x1E9E }, .uppers = &.{0x1E9E} },
    // Greek Sigma (Σ U+03A3, σ U+03C3, ς U+03C2)
    .{ .cps = &.{ 0x03A3, 0x03C3, 0x03C2 }, .uppers = &.{0x03A3} },
    // Common Turkish / Latin Extended special pairs
    .{ .cps = &.{ 0x00FF, 0x0178 }, .uppers = &.{0x0178} }, // ÿ / Ÿ
    .{ .cps = &.{ 0x0152, 0x0153 }, .uppers = &.{0x0152} }, // Œ / œ
};

/// Returns whether a single Unicode codepoint is uppercase (used for per-pattern detection in `smart` mode).
pub fn isUpperCodepoint(cp: u21) bool {
    if (cp >= 'A' and cp <= 'Z') return true;
    // Latin-1 Supplement uppercase: U+00C0..U+00D6, U+00D8..U+00DE
    if ((cp >= 0x00C0 and cp <= 0x00D6) or (cp >= 0x00D8 and cp <= 0x00DE)) return true;
    // Latin Extended-A even-codepoint uppercase: U+0100..U+012E, U+0132..U+0136, U+014A..U+0176
    if (cp >= 0x0100 and cp <= 0x012E and (cp & 1) == 0) return true;
    // Basic Greek uppercase: U+0391..U+03A1, U+03A3..U+03AB, plus accented uppercase U+0386, U+0388..U+038A, U+038C, U+038E..U+038F
    if ((cp >= 0x0391 and cp <= 0x03A1) or (cp >= 0x03A3 and cp <= 0x03AB)) return true;
    if (cp == 0x0386 or (cp >= 0x0388 and cp <= 0x038A) or cp == 0x038C or cp == 0x038E or cp == 0x038F) return true;
    // Basic Cyrillic uppercase: U+0410..U+042F, Ё U+0401
    if ((cp >= 0x0410 and cp <= 0x042F) or cp == 0x0401) return true;
    for (special_groups) |g| {
        for (g.uppers) |u| if (cp == u) return true;
    }
    return false;
}

/// Returns whether `pattern` contains any ASCII or Unicode uppercase codepoints.
pub fn patternHasUnicodeUpper(pattern: []const u8) bool {
    var i: usize = 0;
    while (i < pattern.len) {
        const b = pattern[i];
        if (b < 0x80) {
            if (b >= 'A' and b <= 'Z') return true;
            i += 1;
            continue;
        }
        const len = std.unicode.utf8ByteSequenceLength(b) catch {
            i += 1;
            continue;
        };
        if (i + len > pattern.len) break;
        const cp = std.unicode.utf8Decode(pattern[i .. i + len]) catch {
            i += 1;
            continue;
        };
        if (isUpperCodepoint(cp)) return true;
        i += len;
    }
    return false;
}

/// Writes all codepoints in the same simple case-folding equivalence class as `cp` into `out` and returns the count.
pub fn foldEquivalents(cp: u21, out: *[4]u21) usize {
    for (special_groups) |g| {
        for (g.cps) |item| {
            if (item == cp) {
                for (g.cps, 0..) |c, idx| out[idx] = c;
                return g.cps.len;
            }
        }
    }
    // ASCII letters
    if (cp >= 'A' and cp <= 'Z') {
        out[0] = cp;
        out[1] = cp + 32;
        return 2;
    }
    if (cp >= 'a' and cp <= 'z') {
        out[0] = cp;
        out[1] = cp - 32;
        return 2;
    }
    // Latin-1 Supplement: U+00C0..U+00D6 <-> U+00E0..U+00F6, U+00D8..U+00DE <-> U+00F8..U+00FE
    if ((cp >= 0x00C0 and cp <= 0x00D6) or (cp >= 0x00D8 and cp <= 0x00DE)) {
        out[0] = cp;
        out[1] = cp + 0x20;
        return 2;
    }
    if ((cp >= 0x00E0 and cp <= 0x00F6) or (cp >= 0x00F8 and cp <= 0x00FE)) {
        out[0] = cp;
        out[1] = cp - 0x20;
        return 2;
    }
    // Latin Extended-A: U+0100..U+012F (even uppercase, odd lowercase)
    if (cp >= 0x0100 and cp <= 0x012F) {
        out[0] = cp & ~@as(u21, 1);
        out[1] = cp | 1;
        return 2;
    }
    // Basic Greek letters (excluding Sigma, which is handled in special_groups): U+0391..U+03A1, U+03A4..U+03AB <-> +0x20
    if ((cp >= 0x0391 and cp <= 0x03A1) or (cp >= 0x03A4 and cp <= 0x03AB)) {
        out[0] = cp;
        out[1] = cp + 0x20;
        return 2;
    }
    if ((cp >= 0x03B1 and cp <= 0x03C1) or (cp >= 0x03C4 and cp <= 0x03CB)) {
        out[0] = cp;
        out[1] = cp - 0x20;
        return 2;
    }
    // Basic Cyrillic letters: U+0410..U+042F <-> U+0430..U+044F
    if (cp >= 0x0410 and cp <= 0x042F) {
        out[0] = cp;
        out[1] = cp + 0x20;
        return 2;
    }
    if (cp >= 0x0430 and cp <= 0x044F) {
        out[0] = cp;
        out[1] = cp - 0x20;
        return 2;
    }
    if (cp == 0x0401 or cp == 0x0451) {
        out[0] = 0x0401;
        out[1] = 0x0451;
        return 2;
    }

    out[0] = cp;
    return 1;
}

/// Folds `cp` to its canonical lowercase representative (used for codepoint-by-codepoint equivalence comparison).
pub fn toFoldedLower(cp: u21) u21 {
    var eq: [4]u21 = undefined;
    const n = foldEquivalents(cp, &eq);
    if (n <= 1) return cp;
    // Return the non-uppercase representative codepoint in the equivalence class
    for (eq[0..n]) |c| {
        if (!isUpperCodepoint(c)) return c;
    }
    return eq[0];
}

/// Checks whether `pattern` contains codepoints that require folding beyond plain ASCII (such as non-ASCII letters or cross-ASCII `k`/`s`).
pub fn needsUnicodeExpansion(pattern: []const u8) bool {
    var i: usize = 0;
    while (i < pattern.len) {
        const b = pattern[i];
        if (b < 0x80) {
            if (b == 'k' or b == 'K' or b == 's' or b == 'S') return true;
            i += 1;
            continue;
        }
        const len = std.unicode.utf8ByteSequenceLength(b) catch {
            i += 1;
            continue;
        };
        if (i + len > pattern.len) break;
        const cp = std.unicode.utf8Decode(pattern[i .. i + len]) catch {
            i += 1;
            continue;
        };
        var eq: [4]u21 = undefined;
        if (foldEquivalents(cp, &eq) > 1) return true;
        i += len;
    }
    return false;
}

/// Expands a single pattern under Unicode Simple Case Folding into UTF-8 variants and appends them to `out_list`.
/// To prevent combinatorial explosion, at most `max_variants` variants are generated per pattern (falling back to expanding only non-ASCII case variants when exceeded).
pub fn expandPatternVariants(
    allocator: std.mem.Allocator,
    pattern: []const u8,
    out_list: *std.ArrayList([]u8),
    max_variants: usize,
) error{OutOfMemory}!void {
    // Check whether cross-ASCII variants fit within the branch budget
    const include_cross_ascii = countBranches(pattern, true) <= max_variants;
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(allocator);
    const limit = out_list.items.len +| max_variants;
    try expandRecursive(allocator, pattern, 0, include_cross_ascii, &buf, out_list, limit);
}

fn countBranches(pattern: []const u8, include_cross_ascii: bool) usize {
    var total: usize = 1;
    var i: usize = 0;
    while (i < pattern.len) {
        const b = pattern[i];
        if (b < 0x80) {
            if (include_cross_ascii and (b == 'k' or b == 'K' or b == 's' or b == 'S')) {
                total = std.math.mul(usize, total, 2) catch return std.math.maxInt(usize);
            }
            i += 1;
            continue;
        }
        const len = std.unicode.utf8ByteSequenceLength(b) catch {
            i += 1;
            continue;
        };
        if (i + len > pattern.len) break;
        const cp = std.unicode.utf8Decode(pattern[i .. i + len]) catch {
            i += 1;
            continue;
        };
        var eq: [4]u21 = undefined;
        const n = foldEquivalents(cp, &eq);
        if (n > 1) {
            total = std.math.mul(usize, total, n) catch return std.math.maxInt(usize);
        }
        i += len;
    }
    return total;
}

fn expandRecursive(
    allocator: std.mem.Allocator,
    pattern: []const u8,
    pos: usize,
    include_cross_ascii: bool,
    prefix: *std.ArrayList(u8),
    out_list: *std.ArrayList([]u8),
    max_variants: usize,
) error{OutOfMemory}!void {
    if (out_list.items.len >= max_variants) return;
    if (pos >= pattern.len) {
        const copy = try allocator.dupe(u8, prefix.items);
        errdefer allocator.free(copy);
        try out_list.append(allocator, copy);
        return;
    }

    const saved_len = prefix.items.len;
    const b = pattern[pos];
    if (b < 0x80) {
        if (include_cross_ascii and (b == 'k' or b == 'K')) {
            // Original ASCII byte (handled by the engine's own ASCII case-folding or case-sensitive matching) + U+212A (K)
            try prefix.append(allocator, b);
            try expandRecursive(allocator, pattern, pos + 1, include_cross_ascii, prefix, out_list, max_variants);
            prefix.shrinkRetainingCapacity(saved_len);

            var utf8_buf: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(0x212A, &utf8_buf) catch unreachable;
            try prefix.appendSlice(allocator, utf8_buf[0..n]);
            try expandRecursive(allocator, pattern, pos + 1, include_cross_ascii, prefix, out_list, max_variants);
            prefix.shrinkRetainingCapacity(saved_len);
            return;
        }
        if (include_cross_ascii and (b == 's' or b == 'S')) {
            try prefix.append(allocator, b);
            try expandRecursive(allocator, pattern, pos + 1, include_cross_ascii, prefix, out_list, max_variants);
            prefix.shrinkRetainingCapacity(saved_len);

            var utf8_buf: [4]u8 = undefined;
            const n = std.unicode.utf8Encode(0x017F, &utf8_buf) catch unreachable;
            try prefix.appendSlice(allocator, utf8_buf[0..n]);
            try expandRecursive(allocator, pattern, pos + 1, include_cross_ascii, prefix, out_list, max_variants);
            prefix.shrinkRetainingCapacity(saved_len);
            return;
        }
        try prefix.append(allocator, b);
        try expandRecursive(allocator, pattern, pos + 1, include_cross_ascii, prefix, out_list, max_variants);
        prefix.shrinkRetainingCapacity(saved_len);
        return;
    }

    const len = std.unicode.utf8ByteSequenceLength(b) catch {
        try prefix.append(allocator, b);
        try expandRecursive(allocator, pattern, pos + 1, include_cross_ascii, prefix, out_list, max_variants);
        prefix.shrinkRetainingCapacity(saved_len);
        return;
    };
    if (pos + len > pattern.len) {
        try prefix.appendSlice(allocator, pattern[pos..]);
        try expandRecursive(allocator, pattern, pattern.len, include_cross_ascii, prefix, out_list, max_variants);
        prefix.shrinkRetainingCapacity(saved_len);
        return;
    }
    const cp = std.unicode.utf8Decode(pattern[pos .. pos + len]) catch {
        try prefix.appendSlice(allocator, pattern[pos .. pos + len]);
        try expandRecursive(allocator, pattern, pos + len, include_cross_ascii, prefix, out_list, max_variants);
        prefix.shrinkRetainingCapacity(saved_len);
        return;
    };

    var eq: [4]u21 = undefined;
    const n_eq = foldEquivalents(cp, &eq);
    for (eq[0..n_eq]) |alt_cp| {
        var utf8_buf: [4]u8 = undefined;
        const enc_len = std.unicode.utf8Encode(alt_cp, &utf8_buf) catch continue;
        try prefix.appendSlice(allocator, utf8_buf[0..enc_len]);
        try expandRecursive(allocator, pattern, pos + len, include_cross_ascii, prefix, out_list, max_variants);
        prefix.shrinkRetainingCapacity(saved_len);
    }
}
