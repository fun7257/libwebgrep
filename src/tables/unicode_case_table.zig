//! [Module] tables/unicode_case_table.zig
//! [Layer] Layer 1 — Static Primitives & Lookup Tables
//! [Role] Unicode Simple Case Folding equivalence classes, uppercase detection, and word-character classification tables.
//! [Invariants]
//!   1. All mappings are pure, stateless, zero-allocation functions over Unicode scalar values (`u21`).
//!   2. Contiguous case-paired blocks (Latin-1, Latin Extended, Greek, Cyrillic, Armenian, Georgian, Fullwidth) use branch-free arithmetic.
//!   3. Cross-ASCII and irregular equivalence classes (`K`, `ſ`, `ß`/`ẞ`, `Σ`/`σ`/`ς`, `ÿ`/`Ÿ`, `Œ`/`œ`) use `special_groups`.

const std = @import("std");

pub const FoldGroup = struct {
    /// All codepoints in the same simple case-folding equivalence class (both uppercase and lowercase).
    cps: []const u21,
    /// Uppercase / Titlecase codepoints in this class, used for per-pattern `smart` case detection.
    uppers: []const u21,
};

/// Irregular and cross-ASCII Unicode Simple Case Folding equivalence classes.
/// Regular contiguous ranges (Latin-1, Cyrillic, Greek, etc.) are handled via range arithmetic below.
pub const special_groups = [_]FoldGroup{
    // Cross-ASCII special codepoints
    .{ .cps = &.{ 'k', 'K', 0x212A }, .uppers = &.{ 'K', 0x212A } }, // Kelvin sign U+212A
    .{ .cps = &.{ 's', 'S', 0x017F }, .uppers = &.{'S'} }, // Latin small letter long s U+017F
    // German Sharp S (U+00DF <-> U+1E9E)
    .{ .cps = &.{ 0x00DF, 0x1E9E }, .uppers = &.{0x1E9E} },
    // Greek Sigma (U+03A3, U+03C3, U+03C2)
    .{ .cps = &.{ 0x03A3, 0x03C3, 0x03C2 }, .uppers = &.{0x03A3} },
    // Common Latin Extended special pairs
    .{ .cps = &.{ 0x00FF, 0x0178 }, .uppers = &.{0x0178} }, // U+00FF / U+0178
    .{ .cps = &.{ 0x0152, 0x0153 }, .uppers = &.{0x0152} }, // U+0152 / U+0153
};

/// Returns whether a single Unicode codepoint is uppercase (used for per-pattern detection in `smart` mode).
pub fn isUpperCodepoint(cp: u21) bool {
    if (cp >= 'A' and cp <= 'Z') return true;
    // Latin-1 Supplement uppercase: U+00C0..U+00D6, U+00D8..U+00DE
    if ((cp >= 0x00C0 and cp <= 0x00D6) or (cp >= 0x00D8 and cp <= 0x00DE)) return true;
    // Latin Extended-A:
    // - even uppercase: U+0100..U+012E, U+0130, U+0132..U+0136, U+014A..U+0176
    // - odd uppercase: U+0139..U+0147, U+0179..U+017D
    if (cp >= 0x0100 and cp <= 0x012E and (cp & 1) == 0) return true;
    if (cp == 0x0130) return true;
    if (cp >= 0x0132 and cp <= 0x0136 and (cp & 1) == 0) return true;
    if (cp >= 0x0139 and cp <= 0x0147 and (cp & 1) == 1) return true;
    if (cp >= 0x014A and cp <= 0x0176 and (cp & 1) == 0) return true;
    if (cp >= 0x0179 and cp <= 0x017D and (cp & 1) == 1) return true;
    // Latin Extended-B contiguous pairs:
    if (cp >= 0x01CD and cp <= 0x01DB and (cp & 1) == 1) return true;
    if (cp >= 0x01DE and cp <= 0x01EE and (cp & 1) == 0) return true;
    if (cp >= 0x01F8 and cp <= 0x021E and (cp & 1) == 0) return true;
    if (cp >= 0x0222 and cp <= 0x0232 and (cp & 1) == 0) return true;
    // Basic Greek uppercase: U+0391..U+03A1, U+03A3..U+03AB, plus accented uppercase U+0386, U+0388..U+038A, U+038C, U+038E..U+038F
    if ((cp >= 0x0391 and cp <= 0x03A1) or (cp >= 0x03A3 and cp <= 0x03AB)) return true;
    if (cp == 0x0386 or (cp >= 0x0388 and cp <= 0x038A) or cp == 0x038C or cp == 0x038E or cp == 0x038F) return true;
    // Cyrillic uppercase: U+0400..U+042F, plus extended Cyrillic pairs
    if (cp >= 0x0400 and cp <= 0x042F) return true;
    if (cp >= 0x0460 and cp <= 0x0480 and (cp & 1) == 0) return true;
    if (cp >= 0x048A and cp <= 0x04BE and (cp & 1) == 0) return true;
    if (cp >= 0x04C1 and cp <= 0x04CD and (cp & 1) == 1) return true;
    if (cp >= 0x04D0 and cp <= 0x04FE and (cp & 1) == 0) return true;
    // Armenian uppercase: U+0531..U+0556
    if (cp >= 0x0531 and cp <= 0x0556) return true;
    // Georgian Asomtavruli (U+10A0..U+10C5) & Mtavruli (U+1C90..U+1CBA, U+1CBD..U+1CBF)
    if (cp >= 0x10A0 and cp <= 0x10C5) return true;
    if ((cp >= 0x1C90 and cp <= 0x1CBA) or (cp >= 0x1CBD and cp <= 0x1CBF)) return true;
    // Latin Extended Additional (even uppercase: U+1E00..U+1E94, U+1EA0..U+1EFE)
    if (cp >= 0x1E00 and cp <= 0x1E94 and (cp & 1) == 0) return true;
    if (cp >= 0x1EA0 and cp <= 0x1EFE and (cp & 1) == 0) return true;
    // Fullwidth Latin uppercase: U+FF21..U+FF3A
    if (cp >= 0xFF21 and cp <= 0xFF3A) return true;
    for (special_groups) |g| {
        for (g.uppers) |u| if (cp == u) return true;
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
    // Latin Extended-A: even/odd pairs
    if ((cp >= 0x0100 and cp <= 0x012F) or (cp >= 0x0132 and cp <= 0x0137) or (cp >= 0x014A and cp <= 0x0177)) {
        out[0] = cp & ~@as(u21, 1);
        out[1] = cp | 1;
        return 2;
    }
    // Latin Extended-A: odd uppercase / even lowercase pairs (U+0139..U+0148, U+0179..U+017E)
    if ((cp >= 0x0139 and cp <= 0x0148) or (cp >= 0x0179 and cp <= 0x017E)) {
        const base = if ((cp & 1) == 1) cp else cp - 1;
        out[0] = base;
        out[1] = base + 1;
        return 2;
    }
    // Latin Extended-B contiguous pairs
    if (cp >= 0x01CD and cp <= 0x01DC) {
        const base = if ((cp & 1) == 1) cp else cp - 1;
        out[0] = base;
        out[1] = base + 1;
        return 2;
    }
    if ((cp >= 0x01DE and cp <= 0x01EF) or (cp >= 0x01F8 and cp <= 0x021F) or (cp >= 0x0222 and cp <= 0x0233)) {
        out[0] = cp & ~@as(u21, 1);
        out[1] = cp | 1;
        return 2;
    }
    // Basic Greek letters (excluding Sigma, handled in special_groups): U+0391..U+03A1, U+03A4..U+03AB <-> +0x20
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
    // Greek accented uppercase/lowercase pairs
    if (cp == 0x0386 or cp == 0x03AC) {
        out[0] = 0x0386;
        out[1] = 0x03AC;
        return 2;
    }
    if (cp >= 0x0388 and cp <= 0x038A) {
        out[0] = cp;
        out[1] = cp + 0x25;
        return 2;
    }
    if (cp >= 0x03AD and cp <= 0x03AF) {
        out[0] = cp - 0x25;
        out[1] = cp;
        return 2;
    }
    if (cp == 0x038C or cp == 0x03CC) {
        out[0] = 0x038C;
        out[1] = 0x03CC;
        return 2;
    }
    if (cp == 0x038E or cp == 0x03CD) {
        out[0] = 0x038E;
        out[1] = 0x03CD;
        return 2;
    }
    if (cp == 0x038F or cp == 0x03CE) {
        out[0] = 0x038F;
        out[1] = 0x03CE;
        return 2;
    }
    // Cyrillic extensions: U+0400..U+040F <-> U+0450..U+045F
    if (cp >= 0x0400 and cp <= 0x040F) {
        out[0] = cp;
        out[1] = cp + 0x50;
        return 2;
    }
    if (cp >= 0x0450 and cp <= 0x045F) {
        out[0] = cp - 0x50;
        out[1] = cp;
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
    // Extended Cyrillic even/odd pairs
    if ((cp >= 0x0460 and cp <= 0x0481) or (cp >= 0x048A and cp <= 0x04BF) or (cp >= 0x04D0 and cp <= 0x04FF)) {
        out[0] = cp & ~@as(u21, 1);
        out[1] = cp | 1;
        return 2;
    }
    if (cp >= 0x04C1 and cp <= 0x04CE) {
        const base = if ((cp & 1) == 1) cp else cp - 1;
        out[0] = base;
        out[1] = base + 1;
        return 2;
    }
    // Armenian: U+0531..U+0556 <-> U+0561..U+0586
    if (cp >= 0x0531 and cp <= 0x0556) {
        out[0] = cp;
        out[1] = cp + 0x30;
        return 2;
    }
    if (cp >= 0x0561 and cp <= 0x0586) {
        out[0] = cp - 0x30;
        out[1] = cp;
        return 2;
    }
    // Georgian Asomtavruli (U+10A0..U+10C5) <-> Nuskhuri (U+2D00..U+2D25)
    if (cp >= 0x10A0 and cp <= 0x10C5) {
        out[0] = cp;
        out[1] = cp + 0x1C60;
        return 2;
    }
    if (cp >= 0x2D00 and cp <= 0x2D25) {
        out[0] = cp - 0x1C60;
        out[1] = cp;
        return 2;
    }
    // Georgian Mtavruli (U+1C90..U+1CBA, U+1CBD..U+1CBF) <-> Mkhedruli (U+10D0..U+10FA, U+10FD..U+10FF)
    if ((cp >= 0x1C90 and cp <= 0x1CBA) or (cp >= 0x1CBD and cp <= 0x1CBF)) {
        out[0] = cp;
        out[1] = cp - 0x0BC0;
        return 2;
    }
    if ((cp >= 0x10D0 and cp <= 0x10FA) or (cp >= 0x10FD and cp <= 0x10FF)) {
        out[0] = cp + 0x0BC0;
        out[1] = cp;
        return 2;
    }
    // Latin Extended Additional: U+1E00..U+1E95, U+1EA0..U+1EFF (even uppercase, odd lowercase)
    if ((cp >= 0x1E00 and cp <= 0x1E95) or (cp >= 0x1EA0 and cp <= 0x1EFF)) {
        out[0] = cp & ~@as(u21, 1);
        out[1] = cp | 1;
        return 2;
    }
    // Fullwidth Latin: U+FF21..U+FF3A <-> U+FF41..U+FF5A
    if (cp >= 0xFF21 and cp <= 0xFF3A) {
        out[0] = cp;
        out[1] = cp + 0x20;
        return 2;
    }
    if (cp >= 0xFF41 and cp <= 0xFF5A) {
        out[0] = cp - 0x20;
        out[1] = cp;
        return 2;
    }

    out[0] = cp;
    return 1;
}

/// Folds `cp` to its canonical lowercase representative for codepoint-by-codepoint equivalence comparison.
pub fn toLowerSimple(cp: u21) u21 {
    var eq: [4]u21 = undefined;
    const n = foldEquivalents(cp, &eq);
    if (n <= 1) return cp;
    for (eq[0..n]) |c| {
        if (!isUpperCodepoint(c)) return c;
    }
    return eq[0];
}

pub const toFoldedLower = toLowerSimple;

/// Returns whether a Unicode codepoint is a word character (ASCII `[0-9A-Za-z_]` plus Unicode letters, numbers, and CJK/kana/hangul scripts).
pub fn isUnicodeWordCodepoint(cp: u21) bool {
    if (cp < 0x80) {
        return (cp >= '0' and cp <= '9') or (cp >= 'A' and cp <= 'Z') or (cp >= 'a' and cp <= 'z') or cp == '_';
    }
    if (cp > 0x10FFFF) return false;
    // Exclude Latin-1 control/punctuation/multiplication/division
    if (cp < 0x00C0 or cp == 0x00D7 or cp == 0x00F7) return false;
    // Exclude General Punctuation, Spaces, Arrows, Math Operators, Box Drawing, Symbols, Dingbats (U+2000..U+2BFF)
    if (cp >= 0x2000 and cp <= 0x2BFF and cp != 0x212A) return false;
    // Exclude CJK Symbols and Punctuation (U+3000..U+303F: ideographic space, ideographic comma/full stop, brackets, etc.)
    if (cp >= 0x3000 and cp <= 0x303F) return false;
    // Exclude Fullwidth ASCII punctuation (U+FF00..U+FF0F, U+FF1A..U+FF20, U+FF3B..U+FF40, U+FF5B..U+FF65)
    if ((cp >= 0xFF00 and cp <= 0xFF0F) or
        (cp >= 0xFF1A and cp <= 0xFF20) or
        (cp >= 0xFF3B and cp <= 0xFF40) or
        (cp >= 0xFF5B and cp <= 0xFF65)) return false;
    return true;
}

test "unicode_case_table: canonical folding and word classification" {
    try std.testing.expectEqual(@as(u21, 'a'), toLowerSimple('A'));
    try std.testing.expectEqual(@as(u21, 0x00DF), toLowerSimple(0x1E9E));
    try std.testing.expectEqual(@as(u21, 0x03C3), toLowerSimple(0x03A3));
    try std.testing.expectEqual(@as(u21, 0x03C3), toLowerSimple(0x03C2));
    try std.testing.expect(isUnicodeWordCodepoint(0x4F60));
    try std.testing.expect(!isUnicodeWordCodepoint(0x3002));
}
