//! [Module] tables/unicode_prop_table.zig
//! [Layer] Layer 1 — Static Primitives & Lookup Tables
//! [Role] Unicode General Category (`\p{L}`, `\p{Lu}`, `\p{Nd}`, `\p{P}`, `\p{S}`, `\p{Z}`, `\p{M}`, `\p{C}`),
//!        Unicode Script (`\p{Han}`, `\p{Hiragana}`, `\p{Katakana}`, `\p{Hangul}`, `\p{Cyrillic}`, `\p{Greek}`,
//!        `\p{Latin}`, `\p{Arabic}`, `\p{Hebrew}`, `\p{Devanagari}`, `\p{Thai}`), special properties (`ASCII`, `Any`, `Assigned`, `Emoji`),
//!        UTS #18 property name normalization, and UAX #29 Word Boundary classification tables.
//! [Invariants]
//!   1. All codepoint range tables are sorted and non-overlapping (`start <= end`), enabling O(log K) binary search.
//!   2. Property name lookup follows UTS #18 RL1.2 / RL2.4 normalization (case, whitespace, hyphen, and underscore insensitive,
//!      with optional `gc=`, `general_category=`, `sc=`, `script=`, or `is` prefixes).
//!   3. Zero heap allocations on all lookup and membership paths.

const std = @import("std");

pub const CodepointRange = struct {
    start: u21,
    end: u21,
};

pub const PropertySpec = struct {
    ranges: []const CodepointRange,
    /// True for `Lu`, `Ll`, `Lt` so case-insensitive mode (`(?i)`) widens them to `LC` (`Cased_Letter`).
    is_cased_subcat: bool = false,
};

/// Binary search over a sorted, non-overlapping slice of `CodepointRange`.
pub inline fn inRanges(cp: u21, ranges: []const CodepointRange) bool {
    var lo: usize = 0;
    var hi: usize = ranges.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        const r = ranges[mid];
        if (cp < r.start) {
            hi = mid;
        } else if (cp > r.end) {
            lo = mid + 1;
        } else {
            return true;
        }
    }
    return false;
}

// ============================================================================
// General Category Ranges
// ============================================================================

/// Lu: Uppercase_Letter
pub const gc_Lu = [_]CodepointRange{
    .{ .start = 0x0041, .end = 0x005A },
    .{ .start = 0x00C0, .end = 0x00D6 },
    .{ .start = 0x00D8, .end = 0x00DE },
    .{ .start = 0x0100, .end = 0x0100 }, .{ .start = 0x0102, .end = 0x0102 }, .{ .start = 0x0104, .end = 0x0104 },
    .{ .start = 0x0106, .end = 0x0106 }, .{ .start = 0x0108, .end = 0x0108 }, .{ .start = 0x010A, .end = 0x010A },
    .{ .start = 0x010C, .end = 0x010C }, .{ .start = 0x010E, .end = 0x010E }, .{ .start = 0x0110, .end = 0x0110 },
    .{ .start = 0x0112, .end = 0x0112 }, .{ .start = 0x0114, .end = 0x0114 }, .{ .start = 0x0116, .end = 0x0116 },
    .{ .start = 0x0118, .end = 0x0118 }, .{ .start = 0x011A, .end = 0x011A }, .{ .start = 0x011C, .end = 0x011C },
    .{ .start = 0x011E, .end = 0x011E }, .{ .start = 0x0120, .end = 0x0120 }, .{ .start = 0x0122, .end = 0x0122 },
    .{ .start = 0x0124, .end = 0x0124 }, .{ .start = 0x0126, .end = 0x0126 }, .{ .start = 0x0128, .end = 0x0128 },
    .{ .start = 0x012A, .end = 0x012A }, .{ .start = 0x012C, .end = 0x012C }, .{ .start = 0x012E, .end = 0x012E },
    .{ .start = 0x0130, .end = 0x0130 }, .{ .start = 0x0132, .end = 0x0132 }, .{ .start = 0x0134, .end = 0x0134 },
    .{ .start = 0x0136, .end = 0x0136 }, .{ .start = 0x0139, .end = 0x0139 }, .{ .start = 0x013B, .end = 0x013B },
    .{ .start = 0x013D, .end = 0x013D }, .{ .start = 0x013F, .end = 0x013F }, .{ .start = 0x0141, .end = 0x0141 },
    .{ .start = 0x0143, .end = 0x0143 }, .{ .start = 0x0145, .end = 0x0145 }, .{ .start = 0x0147, .end = 0x0147 },
    .{ .start = 0x014A, .end = 0x014A }, .{ .start = 0x014C, .end = 0x014C }, .{ .start = 0x014E, .end = 0x014E },
    .{ .start = 0x0150, .end = 0x0150 }, .{ .start = 0x0152, .end = 0x0152 }, .{ .start = 0x0154, .end = 0x0154 },
    .{ .start = 0x0156, .end = 0x0156 }, .{ .start = 0x0158, .end = 0x0158 }, .{ .start = 0x015A, .end = 0x015A },
    .{ .start = 0x015C, .end = 0x015C }, .{ .start = 0x015E, .end = 0x015E }, .{ .start = 0x0160, .end = 0x0160 },
    .{ .start = 0x0162, .end = 0x0162 }, .{ .start = 0x0164, .end = 0x0164 }, .{ .start = 0x0166, .end = 0x0166 },
    .{ .start = 0x0168, .end = 0x0168 }, .{ .start = 0x016A, .end = 0x016A }, .{ .start = 0x016C, .end = 0x016C },
    .{ .start = 0x016E, .end = 0x016E }, .{ .start = 0x0170, .end = 0x0170 }, .{ .start = 0x0172, .end = 0x0172 },
    .{ .start = 0x0174, .end = 0x0174 }, .{ .start = 0x0176, .end = 0x0176 }, .{ .start = 0x0178, .end = 0x0179 },
    .{ .start = 0x017B, .end = 0x017B }, .{ .start = 0x017D, .end = 0x017D },
    .{ .start = 0x0181, .end = 0x0182 }, .{ .start = 0x0184, .end = 0x0184 }, .{ .start = 0x0186, .end = 0x0187 },
    .{ .start = 0x0189, .end = 0x018B }, .{ .start = 0x018E, .end = 0x0191 }, .{ .start = 0x0193, .end = 0x0194 },
    .{ .start = 0x0196, .end = 0x0198 }, .{ .start = 0x019C, .end = 0x019D }, .{ .start = 0x019F, .end = 0x01A0 },
    .{ .start = 0x01A2, .end = 0x01A2 }, .{ .start = 0x01A4, .end = 0x01A4 }, .{ .start = 0x01A6, .end = 0x01A7 },
    .{ .start = 0x01A9, .end = 0x01A9 }, .{ .start = 0x01AC, .end = 0x01AC }, .{ .start = 0x01AE, .end = 0x01AF },
    .{ .start = 0x01B1, .end = 0x01B3 }, .{ .start = 0x01B5, .end = 0x01B5 }, .{ .start = 0x01B7, .end = 0x01B8 },
    .{ .start = 0x01BC, .end = 0x01BC }, .{ .start = 0x01C4, .end = 0x01C4 }, .{ .start = 0x01C7, .end = 0x01C7 },
    .{ .start = 0x01CA, .end = 0x01CA }, .{ .start = 0x01CD, .end = 0x01CD }, .{ .start = 0x01CF, .end = 0x01CF },
    .{ .start = 0x01D1, .end = 0x01D1 }, .{ .start = 0x01D3, .end = 0x01D3 }, .{ .start = 0x01D5, .end = 0x01D5 },
    .{ .start = 0x01D7, .end = 0x01D7 }, .{ .start = 0x01D9, .end = 0x01D9 }, .{ .start = 0x01DB, .end = 0x01DB },
    .{ .start = 0x01DE, .end = 0x01DE }, .{ .start = 0x01E0, .end = 0x01E0 }, .{ .start = 0x01E2, .end = 0x01E2 },
    .{ .start = 0x01E4, .end = 0x01E4 }, .{ .start = 0x01E6, .end = 0x01E6 }, .{ .start = 0x01E8, .end = 0x01E8 },
    .{ .start = 0x01EA, .end = 0x01EA }, .{ .start = 0x01EC, .end = 0x01EC }, .{ .start = 0x01EE, .end = 0x01EE },
    .{ .start = 0x01F1, .end = 0x01F1 }, .{ .start = 0x01F4, .end = 0x01F4 }, .{ .start = 0x01F6, .end = 0x01F8 },
    .{ .start = 0x01FA, .end = 0x01FA }, .{ .start = 0x01FC, .end = 0x01FC }, .{ .start = 0x01FE, .end = 0x01FE },
    .{ .start = 0x0200, .end = 0x0200 }, .{ .start = 0x0202, .end = 0x0202 }, .{ .start = 0x0204, .end = 0x0204 },
    .{ .start = 0x0206, .end = 0x0206 }, .{ .start = 0x0208, .end = 0x0208 }, .{ .start = 0x020A, .end = 0x020A },
    .{ .start = 0x020C, .end = 0x020C }, .{ .start = 0x020E, .end = 0x020E }, .{ .start = 0x0210, .end = 0x0210 },
    .{ .start = 0x0212, .end = 0x0212 }, .{ .start = 0x0214, .end = 0x0214 }, .{ .start = 0x0216, .end = 0x0216 },
    .{ .start = 0x0218, .end = 0x0218 }, .{ .start = 0x021A, .end = 0x021A }, .{ .start = 0x021C, .end = 0x021C },
    .{ .start = 0x021E, .end = 0x021E }, .{ .start = 0x0220, .end = 0x0220 }, .{ .start = 0x0222, .end = 0x0222 },
    .{ .start = 0x0224, .end = 0x0224 }, .{ .start = 0x0226, .end = 0x0226 }, .{ .start = 0x0228, .end = 0x0228 },
    .{ .start = 0x022A, .end = 0x022A }, .{ .start = 0x022C, .end = 0x022C }, .{ .start = 0x022E, .end = 0x022E },
    .{ .start = 0x0230, .end = 0x0230 }, .{ .start = 0x0232, .end = 0x0232 }, .{ .start = 0x023A, .end = 0x023B },
    .{ .start = 0x023D, .end = 0x023E }, .{ .start = 0x0241, .end = 0x0241 }, .{ .start = 0x0243, .end = 0x0246 },
    .{ .start = 0x0248, .end = 0x0248 }, .{ .start = 0x024A, .end = 0x024A }, .{ .start = 0x024C, .end = 0x024C },
    .{ .start = 0x024E, .end = 0x024E },
    .{ .start = 0x0370, .end = 0x0370 }, .{ .start = 0x0372, .end = 0x0372 }, .{ .start = 0x0376, .end = 0x0376 },
    .{ .start = 0x037F, .end = 0x037F }, .{ .start = 0x0386, .end = 0x0386 }, .{ .start = 0x0388, .end = 0x038A },
    .{ .start = 0x038C, .end = 0x038C }, .{ .start = 0x038E, .end = 0x038F }, .{ .start = 0x0391, .end = 0x03A1 },
    .{ .start = 0x03A3, .end = 0x03AB }, .{ .start = 0x03CF, .end = 0x03CF }, .{ .start = 0x03D2, .end = 0x03D4 },
    .{ .start = 0x03D8, .end = 0x03D8 }, .{ .start = 0x03DA, .end = 0x03DA }, .{ .start = 0x03DC, .end = 0x03DC },
    .{ .start = 0x03DE, .end = 0x03DE }, .{ .start = 0x03E0, .end = 0x03E0 }, .{ .start = 0x03E2, .end = 0x03E2 },
    .{ .start = 0x03E4, .end = 0x03E4 }, .{ .start = 0x03E6, .end = 0x03E6 }, .{ .start = 0x03E8, .end = 0x03E8 },
    .{ .start = 0x03EA, .end = 0x03EA }, .{ .start = 0x03EC, .end = 0x03EC }, .{ .start = 0x03EE, .end = 0x03EE },
    .{ .start = 0x03F4, .end = 0x03F4 }, .{ .start = 0x03F7, .end = 0x03F7 }, .{ .start = 0x03F9, .end = 0x03FA },
    .{ .start = 0x03FD, .end = 0x042F },
    .{ .start = 0x0460, .end = 0x0460 }, .{ .start = 0x0462, .end = 0x0462 }, .{ .start = 0x0464, .end = 0x0464 },
    .{ .start = 0x0466, .end = 0x0466 }, .{ .start = 0x0468, .end = 0x0468 }, .{ .start = 0x046A, .end = 0x046A },
    .{ .start = 0x046C, .end = 0x046C }, .{ .start = 0x046E, .end = 0x046E }, .{ .start = 0x0470, .end = 0x0470 },
    .{ .start = 0x0472, .end = 0x0472 }, .{ .start = 0x0474, .end = 0x0474 }, .{ .start = 0x0476, .end = 0x0476 },
    .{ .start = 0x0478, .end = 0x0478 }, .{ .start = 0x047A, .end = 0x047A }, .{ .start = 0x047C, .end = 0x047C },
    .{ .start = 0x047E, .end = 0x047E }, .{ .start = 0x0480, .end = 0x0480 }, .{ .start = 0x048A, .end = 0x048A },
    .{ .start = 0x048C, .end = 0x048C }, .{ .start = 0x048E, .end = 0x048E }, .{ .start = 0x0490, .end = 0x0490 },
    .{ .start = 0x0492, .end = 0x0492 }, .{ .start = 0x0494, .end = 0x0494 }, .{ .start = 0x0496, .end = 0x0496 },
    .{ .start = 0x0498, .end = 0x0498 }, .{ .start = 0x049A, .end = 0x049A }, .{ .start = 0x049C, .end = 0x049C },
    .{ .start = 0x049E, .end = 0x049E }, .{ .start = 0x04A0, .end = 0x04A0 }, .{ .start = 0x04A2, .end = 0x04A2 },
    .{ .start = 0x04A4, .end = 0x04A4 }, .{ .start = 0x04A6, .end = 0x04A6 }, .{ .start = 0x04A8, .end = 0x04A8 },
    .{ .start = 0x04AA, .end = 0x04AA }, .{ .start = 0x04AC, .end = 0x04AC }, .{ .start = 0x04AE, .end = 0x04AE },
    .{ .start = 0x04B0, .end = 0x04B0 }, .{ .start = 0x04B2, .end = 0x04B2 }, .{ .start = 0x04B4, .end = 0x04B4 },
    .{ .start = 0x04B6, .end = 0x04B6 }, .{ .start = 0x04B8, .end = 0x04B8 }, .{ .start = 0x04BA, .end = 0x04BA },
    .{ .start = 0x04BC, .end = 0x04BC }, .{ .start = 0x04BE, .end = 0x04BE }, .{ .start = 0x04C0, .end = 0x04C1 },
    .{ .start = 0x04C3, .end = 0x04C3 }, .{ .start = 0x04C5, .end = 0x04C5 }, .{ .start = 0x04C7, .end = 0x04C7 },
    .{ .start = 0x04C9, .end = 0x04C9 }, .{ .start = 0x04CB, .end = 0x04CB }, .{ .start = 0x04CD, .end = 0x04CD },
    .{ .start = 0x04D0, .end = 0x04D0 }, .{ .start = 0x04D2, .end = 0x04D2 }, .{ .start = 0x04D4, .end = 0x04D4 },
    .{ .start = 0x04D6, .end = 0x04D6 }, .{ .start = 0x04D8, .end = 0x04D8 }, .{ .start = 0x04DA, .end = 0x04DA },
    .{ .start = 0x04DC, .end = 0x04DC }, .{ .start = 0x04DE, .end = 0x04DE }, .{ .start = 0x04E0, .end = 0x04E0 },
    .{ .start = 0x04E2, .end = 0x04E2 }, .{ .start = 0x04E4, .end = 0x04E4 }, .{ .start = 0x04E6, .end = 0x04E6 },
    .{ .start = 0x04E8, .end = 0x04E8 }, .{ .start = 0x04EA, .end = 0x04EA }, .{ .start = 0x04EC, .end = 0x04EC },
    .{ .start = 0x04EE, .end = 0x04EE }, .{ .start = 0x04F0, .end = 0x04F0 }, .{ .start = 0x04F2, .end = 0x04F2 },
    .{ .start = 0x04F4, .end = 0x04F4 }, .{ .start = 0x04F6, .end = 0x04F6 }, .{ .start = 0x04F8, .end = 0x04F8 },
    .{ .start = 0x04FA, .end = 0x04FA }, .{ .start = 0x04FC, .end = 0x04FC }, .{ .start = 0x04FE, .end = 0x04FE },
    .{ .start = 0x0531, .end = 0x0556 },
    .{ .start = 0x10A0, .end = 0x10C5 }, .{ .start = 0x10C7, .end = 0x10C7 }, .{ .start = 0x10CD, .end = 0x10CD },
    .{ .start = 0x1C90, .end = 0x1CBA }, .{ .start = 0x1CBD, .end = 0x1CBF },
    .{ .start = 0x1E00, .end = 0x1E00 }, .{ .start = 0x1E02, .end = 0x1E02 }, .{ .start = 0x1E04, .end = 0x1E04 },
    .{ .start = 0x1E06, .end = 0x1E06 }, .{ .start = 0x1E08, .end = 0x1E08 }, .{ .start = 0x1E0A, .end = 0x1E0A },
    .{ .start = 0x1E9E, .end = 0x1E9E },
    .{ .start = 0x1F08, .end = 0x1F0F }, .{ .start = 0x1F18, .end = 0x1F1D }, .{ .start = 0x1F28, .end = 0x1F2F },
    .{ .start = 0x1F38, .end = 0x1F3F }, .{ .start = 0x1F48, .end = 0x1F4D }, .{ .start = 0x1F59, .end = 0x1F5F },
    .{ .start = 0x1F68, .end = 0x1F6F }, .{ .start = 0x1FB8, .end = 0x1FBB }, .{ .start = 0x1FC8, .end = 0x1FCB },
    .{ .start = 0x1FD8, .end = 0x1FDB }, .{ .start = 0x1FE8, .end = 0x1FEC }, .{ .start = 0x1FF8, .end = 0x1FFB },
    .{ .start = 0x2102, .end = 0x2102 }, .{ .start = 0x2107, .end = 0x2107 }, .{ .start = 0x210B, .end = 0x210D },
    .{ .start = 0x2110, .end = 0x2112 }, .{ .start = 0x2115, .end = 0x2115 }, .{ .start = 0x2119, .end = 0x211D },
    .{ .start = 0x2124, .end = 0x2124 }, .{ .start = 0x2126, .end = 0x2126 }, .{ .start = 0x2128, .end = 0x2128 },
    .{ .start = 0x212A, .end = 0x212D }, .{ .start = 0x2130, .end = 0x2133 },
    .{ .start = 0xFF21, .end = 0xFF3A },
    .{ .start = 0x10400, .end = 0x10427 },
    .{ .start = 0x1D400, .end = 0x1D419 }, .{ .start = 0x1D434, .end = 0x1D44D },
};

/// Ll: Lowercase_Letter
pub const gc_Ll = [_]CodepointRange{
    .{ .start = 0x0061, .end = 0x007A },
    .{ .start = 0x00AA, .end = 0x00AA }, .{ .start = 0x00B5, .end = 0x00B5 }, .{ .start = 0x00BA, .end = 0x00BA },
    .{ .start = 0x00DF, .end = 0x00F6 }, .{ .start = 0x00F8, .end = 0x00FF },
    .{ .start = 0x0101, .end = 0x0101 }, .{ .start = 0x0103, .end = 0x0103 }, .{ .start = 0x0105, .end = 0x0105 },
    .{ .start = 0x0107, .end = 0x0107 }, .{ .start = 0x0109, .end = 0x0109 }, .{ .start = 0x010B, .end = 0x010B },
    .{ .start = 0x010D, .end = 0x010D }, .{ .start = 0x010F, .end = 0x010F }, .{ .start = 0x0111, .end = 0x0111 },
    .{ .start = 0x0113, .end = 0x0113 }, .{ .start = 0x0115, .end = 0x0115 }, .{ .start = 0x0117, .end = 0x0117 },
    .{ .start = 0x0119, .end = 0x0119 }, .{ .start = 0x011B, .end = 0x011B }, .{ .start = 0x011D, .end = 0x011D },
    .{ .start = 0x011F, .end = 0x011F }, .{ .start = 0x0121, .end = 0x0121 }, .{ .start = 0x0123, .end = 0x0123 },
    .{ .start = 0x0125, .end = 0x0125 }, .{ .start = 0x0127, .end = 0x0127 }, .{ .start = 0x0129, .end = 0x0129 },
    .{ .start = 0x012B, .end = 0x012B }, .{ .start = 0x012D, .end = 0x012D }, .{ .start = 0x012F, .end = 0x012F },
    .{ .start = 0x0131, .end = 0x0131 }, .{ .start = 0x0133, .end = 0x0133 }, .{ .start = 0x0135, .end = 0x0135 },
    .{ .start = 0x0137, .end = 0x0138 }, .{ .start = 0x013A, .end = 0x013A }, .{ .start = 0x013C, .end = 0x013C },
    .{ .start = 0x013E, .end = 0x013E }, .{ .start = 0x0140, .end = 0x0140 }, .{ .start = 0x0142, .end = 0x0142 },
    .{ .start = 0x0144, .end = 0x0144 }, .{ .start = 0x0146, .end = 0x0146 }, .{ .start = 0x0148, .end = 0x0149 },
    .{ .start = 0x014B, .end = 0x014B }, .{ .start = 0x014D, .end = 0x014D }, .{ .start = 0x014F, .end = 0x014F },
    .{ .start = 0x0151, .end = 0x0151 }, .{ .start = 0x0153, .end = 0x0153 }, .{ .start = 0x0155, .end = 0x0155 },
    .{ .start = 0x0157, .end = 0x0157 }, .{ .start = 0x0159, .end = 0x0159 }, .{ .start = 0x015B, .end = 0x015B },
    .{ .start = 0x015D, .end = 0x015D }, .{ .start = 0x015F, .end = 0x015F }, .{ .start = 0x0161, .end = 0x0161 },
    .{ .start = 0x0163, .end = 0x0163 }, .{ .start = 0x0165, .end = 0x0165 }, .{ .start = 0x0167, .end = 0x0167 },
    .{ .start = 0x0169, .end = 0x0169 }, .{ .start = 0x016B, .end = 0x016B }, .{ .start = 0x016D, .end = 0x016D },
    .{ .start = 0x016F, .end = 0x016F }, .{ .start = 0x0171, .end = 0x0171 }, .{ .start = 0x0173, .end = 0x0173 },
    .{ .start = 0x0175, .end = 0x0175 }, .{ .start = 0x0177, .end = 0x0177 }, .{ .start = 0x017A, .end = 0x017A },
    .{ .start = 0x017C, .end = 0x017C }, .{ .start = 0x017E, .end = 0x0180 },
    .{ .start = 0x0183, .end = 0x0183 }, .{ .start = 0x0185, .end = 0x0185 }, .{ .start = 0x0188, .end = 0x0188 },
    .{ .start = 0x018C, .end = 0x018D }, .{ .start = 0x0192, .end = 0x0192 }, .{ .start = 0x0195, .end = 0x0195 },
    .{ .start = 0x0199, .end = 0x019B }, .{ .start = 0x019E, .end = 0x019E }, .{ .start = 0x01A1, .end = 0x01A1 },
    .{ .start = 0x01A3, .end = 0x01A3 }, .{ .start = 0x01A5, .end = 0x01A5 }, .{ .start = 0x01A8, .end = 0x01A8 },
    .{ .start = 0x01AA, .end = 0x01AB }, .{ .start = 0x01AD, .end = 0x01AD }, .{ .start = 0x01B0, .end = 0x01B0 },
    .{ .start = 0x01B4, .end = 0x01B4 }, .{ .start = 0x01B6, .end = 0x01B6 }, .{ .start = 0x01B9, .end = 0x01BA },
    .{ .start = 0x01BD, .end = 0x01BF }, .{ .start = 0x01C6, .end = 0x01C6 }, .{ .start = 0x01C9, .end = 0x01C9 },
    .{ .start = 0x01CC, .end = 0x01CC }, .{ .start = 0x01CE, .end = 0x01CE }, .{ .start = 0x01D0, .end = 0x01D0 },
    .{ .start = 0x01D2, .end = 0x01D2 }, .{ .start = 0x01D4, .end = 0x01D4 }, .{ .start = 0x01D6, .end = 0x01D6 },
    .{ .start = 0x01D8, .end = 0x01D8 }, .{ .start = 0x01DA, .end = 0x01DA }, .{ .start = 0x01DC, .end = 0x01DD },
    .{ .start = 0x01DF, .end = 0x01DF }, .{ .start = 0x01E1, .end = 0x01E1 }, .{ .start = 0x01E3, .end = 0x01E3 },
    .{ .start = 0x01E5, .end = 0x01E5 }, .{ .start = 0x01E7, .end = 0x01E7 }, .{ .start = 0x01E9, .end = 0x01E9 },
    .{ .start = 0x01EB, .end = 0x01EB }, .{ .start = 0x01ED, .end = 0x01ED }, .{ .start = 0x01EF, .end = 0x01F0 },
    .{ .start = 0x01F3, .end = 0x01F3 }, .{ .start = 0x01F5, .end = 0x01F5 }, .{ .start = 0x01F9, .end = 0x01F9 },
    .{ .start = 0x01FB, .end = 0x01FB }, .{ .start = 0x01FD, .end = 0x01FD }, .{ .start = 0x01FF, .end = 0x01FF },
    .{ .start = 0x0201, .end = 0x0201 }, .{ .start = 0x0203, .end = 0x0203 }, .{ .start = 0x0205, .end = 0x0205 },
    .{ .start = 0x0207, .end = 0x0207 }, .{ .start = 0x0209, .end = 0x0209 }, .{ .start = 0x020B, .end = 0x020B },
    .{ .start = 0x020D, .end = 0x020D }, .{ .start = 0x020F, .end = 0x020F }, .{ .start = 0x0211, .end = 0x0211 },
    .{ .start = 0x0213, .end = 0x0213 }, .{ .start = 0x0215, .end = 0x0215 }, .{ .start = 0x0217, .end = 0x0217 },
    .{ .start = 0x0219, .end = 0x0219 }, .{ .start = 0x021B, .end = 0x021B }, .{ .start = 0x021D, .end = 0x021D },
    .{ .start = 0x021F, .end = 0x021F }, .{ .start = 0x0221, .end = 0x0221 }, .{ .start = 0x0223, .end = 0x0223 },
    .{ .start = 0x0225, .end = 0x0225 }, .{ .start = 0x0227, .end = 0x0227 }, .{ .start = 0x0229, .end = 0x0229 },
    .{ .start = 0x022B, .end = 0x022B }, .{ .start = 0x022D, .end = 0x022D }, .{ .start = 0x022F, .end = 0x022F },
    .{ .start = 0x0231, .end = 0x0231 }, .{ .start = 0x0233, .end = 0x0239 }, .{ .start = 0x023C, .end = 0x023C },
    .{ .start = 0x023F, .end = 0x0240 }, .{ .start = 0x0242, .end = 0x0242 }, .{ .start = 0x0247, .end = 0x0247 },
    .{ .start = 0x0249, .end = 0x0249 }, .{ .start = 0x024B, .end = 0x024B }, .{ .start = 0x024D, .end = 0x024D },
    .{ .start = 0x024F, .end = 0x02AF },
    .{ .start = 0x0371, .end = 0x0371 }, .{ .start = 0x0373, .end = 0x0373 }, .{ .start = 0x0377, .end = 0x0377 },
    .{ .start = 0x037B, .end = 0x037D }, .{ .start = 0x0390, .end = 0x0390 }, .{ .start = 0x03AC, .end = 0x03CE },
    .{ .start = 0x03D0, .end = 0x03D1 }, .{ .start = 0x03D5, .end = 0x03D7 }, .{ .start = 0x03D9, .end = 0x03D9 },
    .{ .start = 0x03DB, .end = 0x03DB }, .{ .start = 0x03DD, .end = 0x03DD }, .{ .start = 0x03DF, .end = 0x03DF },
    .{ .start = 0x03E1, .end = 0x03E1 }, .{ .start = 0x03E3, .end = 0x03E3 }, .{ .start = 0x03E5, .end = 0x03E5 },
    .{ .start = 0x03E7, .end = 0x03E7 }, .{ .start = 0x03E9, .end = 0x03E9 }, .{ .start = 0x03EB, .end = 0x03EB },
    .{ .start = 0x03ED, .end = 0x03ED }, .{ .start = 0x03EF, .end = 0x03F3 }, .{ .start = 0x03F5, .end = 0x03F5 },
    .{ .start = 0x03F8, .end = 0x03F8 }, .{ .start = 0x03FB, .end = 0x03FC },
    .{ .start = 0x0430, .end = 0x045F },
    .{ .start = 0x0461, .end = 0x0461 }, .{ .start = 0x0463, .end = 0x0463 }, .{ .start = 0x0465, .end = 0x0465 },
    .{ .start = 0x0467, .end = 0x0467 }, .{ .start = 0x0469, .end = 0x0469 }, .{ .start = 0x046B, .end = 0x046B },
    .{ .start = 0x046D, .end = 0x046D }, .{ .start = 0x046F, .end = 0x046F }, .{ .start = 0x0471, .end = 0x0471 },
    .{ .start = 0x0473, .end = 0x0473 }, .{ .start = 0x0475, .end = 0x0475 }, .{ .start = 0x0477, .end = 0x0477 },
    .{ .start = 0x0479, .end = 0x0479 }, .{ .start = 0x047B, .end = 0x047B }, .{ .start = 0x047D, .end = 0x047D },
    .{ .start = 0x047F, .end = 0x047F }, .{ .start = 0x0481, .end = 0x0481 }, .{ .start = 0x048B, .end = 0x048B },
    .{ .start = 0x048D, .end = 0x048D }, .{ .start = 0x048F, .end = 0x048F }, .{ .start = 0x0491, .end = 0x0491 },
    .{ .start = 0x0493, .end = 0x0493 }, .{ .start = 0x0495, .end = 0x0495 }, .{ .start = 0x0497, .end = 0x0497 },
    .{ .start = 0x0499, .end = 0x0499 }, .{ .start = 0x049B, .end = 0x049B }, .{ .start = 0x049D, .end = 0x049D },
    .{ .start = 0x049F, .end = 0x049F }, .{ .start = 0x04A1, .end = 0x04A1 }, .{ .start = 0x04A3, .end = 0x04A3 },
    .{ .start = 0x04A5, .end = 0x04A5 }, .{ .start = 0x04A7, .end = 0x04A7 }, .{ .start = 0x04A9, .end = 0x04A9 },
    .{ .start = 0x04AB, .end = 0x04AB }, .{ .start = 0x04AD, .end = 0x04AD }, .{ .start = 0x04AF, .end = 0x04AF },
    .{ .start = 0x04B1, .end = 0x04B1 }, .{ .start = 0x04B3, .end = 0x04B3 }, .{ .start = 0x04B5, .end = 0x04B5 },
    .{ .start = 0x04B7, .end = 0x04B7 }, .{ .start = 0x04B9, .end = 0x04B9 }, .{ .start = 0x04BB, .end = 0x04BB },
    .{ .start = 0x04BD, .end = 0x04BD }, .{ .start = 0x04BF, .end = 0x04BF }, .{ .start = 0x04C2, .end = 0x04C2 },
    .{ .start = 0x04C4, .end = 0x04C4 }, .{ .start = 0x04C6, .end = 0x04C6 }, .{ .start = 0x04C8, .end = 0x04C8 },
    .{ .start = 0x04CA, .end = 0x04CA }, .{ .start = 0x04CC, .end = 0x04CC }, .{ .start = 0x04CE, .end = 0x04CF },
    .{ .start = 0x04D1, .end = 0x04D1 }, .{ .start = 0x04D3, .end = 0x04D3 }, .{ .start = 0x04D5, .end = 0x04D5 },
    .{ .start = 0x04D7, .end = 0x04D7 }, .{ .start = 0x04D9, .end = 0x04D9 }, .{ .start = 0x04DB, .end = 0x04DB },
    .{ .start = 0x04DD, .end = 0x04DD }, .{ .start = 0x04DF, .end = 0x04DF }, .{ .start = 0x04E1, .end = 0x04E1 },
    .{ .start = 0x04E3, .end = 0x04E3 }, .{ .start = 0x04E5, .end = 0x04E5 }, .{ .start = 0x04E7, .end = 0x04E7 },
    .{ .start = 0x04E9, .end = 0x04E9 }, .{ .start = 0x04EB, .end = 0x04EB }, .{ .start = 0x04ED, .end = 0x04ED },
    .{ .start = 0x04EF, .end = 0x04EF }, .{ .start = 0x04F1, .end = 0x04F1 }, .{ .start = 0x04F3, .end = 0x04F3 },
    .{ .start = 0x04F5, .end = 0x04F5 }, .{ .start = 0x04F7, .end = 0x04F7 }, .{ .start = 0x04F9, .end = 0x04F9 },
    .{ .start = 0x04FB, .end = 0x04FB }, .{ .start = 0x04FD, .end = 0x04FD }, .{ .start = 0x04FF, .end = 0x04FF },
    .{ .start = 0x0560, .end = 0x0588 },
    .{ .start = 0x10D0, .end = 0x10FA }, .{ .start = 0x10FD, .end = 0x10FF },
    .{ .start = 0x1D00, .end = 0x1D2B }, .{ .start = 0x1D6B, .end = 0x1D77 }, .{ .start = 0x1D79, .end = 0x1D9A },
    .{ .start = 0x1E01, .end = 0x1E01 }, .{ .start = 0x1E03, .end = 0x1E03 }, .{ .start = 0x1E05, .end = 0x1E05 },
    .{ .start = 0x1E07, .end = 0x1E07 }, .{ .start = 0x1E09, .end = 0x1E09 }, .{ .start = 0x1E0B, .end = 0x1E0B },
    .{ .start = 0x1E96, .end = 0x1E9D }, .{ .start = 0x1E9F, .end = 0x1E9F },
    .{ .start = 0x1F00, .end = 0x1F07 }, .{ .start = 0x1F10, .end = 0x1F15 }, .{ .start = 0x1F20, .end = 0x1F27 },
    .{ .start = 0x1F30, .end = 0x1F37 }, .{ .start = 0x1F40, .end = 0x1F45 }, .{ .start = 0x1F50, .end = 0x1F57 },
    .{ .start = 0x1F60, .end = 0x1F67 }, .{ .start = 0x1F70, .end = 0x1F7D }, .{ .start = 0x1F80, .end = 0x1F87 },
    .{ .start = 0x1F90, .end = 0x1F97 }, .{ .start = 0x1FA0, .end = 0x1FA7 }, .{ .start = 0x1FB0, .end = 0x1FB4 },
    .{ .start = 0x1FB6, .end = 0x1FB7 }, .{ .start = 0x1FBE, .end = 0x1FBE }, .{ .start = 0x1FC2, .end = 0x1FC4 },
    .{ .start = 0x1FC6, .end = 0x1FC7 }, .{ .start = 0x1FD0, .end = 0x1FD3 }, .{ .start = 0x1FD6, .end = 0x1FD7 },
    .{ .start = 0x1FE0, .end = 0x1FE7 }, .{ .start = 0x1FF2, .end = 0x1FF4 }, .{ .start = 0x1FF6, .end = 0x1FF7 },
    .{ .start = 0x210A, .end = 0x210A }, .{ .start = 0x210E, .end = 0x210F }, .{ .start = 0x2113, .end = 0x2113 },
    .{ .start = 0x212F, .end = 0x212F }, .{ .start = 0x2134, .end = 0x2134 }, .{ .start = 0x2139, .end = 0x2139 },
    .{ .start = 0x2D00, .end = 0x2D25 }, .{ .start = 0x2D27, .end = 0x2D27 }, .{ .start = 0x2D2D, .end = 0x2D2D },
    .{ .start = 0xFF41, .end = 0xFF5A },
    .{ .start = 0x10428, .end = 0x1044F },
    .{ .start = 0x1D41A, .end = 0x1D433 }, .{ .start = 0x1D44E, .end = 0x1D454 }, .{ .start = 0x1D456, .end = 0x1D467 },
};

/// Lt: Titlecase_Letter
pub const gc_Lt = [_]CodepointRange{
    .{ .start = 0x01C5, .end = 0x01C5 },
    .{ .start = 0x01C8, .end = 0x01C8 },
    .{ .start = 0x01CB, .end = 0x01CB },
    .{ .start = 0x01F2, .end = 0x01F2 },
    .{ .start = 0x1F88, .end = 0x1F8F },
    .{ .start = 0x1F98, .end = 0x1F9F },
    .{ .start = 0x1FA8, .end = 0x1FAF },
    .{ .start = 0x1FBC, .end = 0x1FBC },
    .{ .start = 0x1FCC, .end = 0x1FCC },
    .{ .start = 0x1FFC, .end = 0x1FFC },
};

/// LC: Cased_Letter (Lu | Ll | Lt)
pub const gc_LC = [_]CodepointRange{
    .{ .start = 0x0041, .end = 0x005A },
    .{ .start = 0x0061, .end = 0x007A },
    .{ .start = 0x00AA, .end = 0x00AA }, .{ .start = 0x00B5, .end = 0x00B5 }, .{ .start = 0x00BA, .end = 0x00BA },
    .{ .start = 0x00C0, .end = 0x00D6 }, .{ .start = 0x00D8, .end = 0x00F6 }, .{ .start = 0x00F8, .end = 0x01BA },
    .{ .start = 0x01BC, .end = 0x01BF }, .{ .start = 0x01C4, .end = 0x02AF },
    .{ .start = 0x0370, .end = 0x0373 }, .{ .start = 0x0376, .end = 0x0377 }, .{ .start = 0x037B, .end = 0x037D },
    .{ .start = 0x037F, .end = 0x037F }, .{ .start = 0x0386, .end = 0x0386 }, .{ .start = 0x0388, .end = 0x038A },
    .{ .start = 0x038C, .end = 0x038C }, .{ .start = 0x038E, .end = 0x03A1 }, .{ .start = 0x03A3, .end = 0x03F5 },
    .{ .start = 0x03F7, .end = 0x0481 }, .{ .start = 0x048A, .end = 0x052F },
    .{ .start = 0x0531, .end = 0x0556 }, .{ .start = 0x0560, .end = 0x0588 },
    .{ .start = 0x10A0, .end = 0x10C5 }, .{ .start = 0x10C7, .end = 0x10C7 }, .{ .start = 0x10CD, .end = 0x10CD },
    .{ .start = 0x10D0, .end = 0x10FA }, .{ .start = 0x10FD, .end = 0x10FF },
    .{ .start = 0x1C90, .end = 0x1CBA }, .{ .start = 0x1CBD, .end = 0x1CBF },
    .{ .start = 0x1D00, .end = 0x1D2B }, .{ .start = 0x1D6B, .end = 0x1D77 }, .{ .start = 0x1D79, .end = 0x1D9A },
    .{ .start = 0x1E00, .end = 0x1F15 }, .{ .start = 0x1F18, .end = 0x1F1D }, .{ .start = 0x1F20, .end = 0x1F45 },
    .{ .start = 0x1F48, .end = 0x1F4D }, .{ .start = 0x1F50, .end = 0x1F57 }, .{ .start = 0x1F59, .end = 0x1F5F },
    .{ .start = 0x1F60, .end = 0x1F7D }, .{ .start = 0x1F80, .end = 0x1FB4 }, .{ .start = 0x1FB6, .end = 0x1FBC },
    .{ .start = 0x1FBE, .end = 0x1FBE }, .{ .start = 0x1FC2, .end = 0x1FC4 }, .{ .start = 0x1FC6, .end = 0x1FCC },
    .{ .start = 0x1FD0, .end = 0x1FD3 }, .{ .start = 0x1FD6, .end = 0x1FDB }, .{ .start = 0x1FE0, .end = 0x1FEC },
    .{ .start = 0x1FF2, .end = 0x1FF4 }, .{ .start = 0x1FF6, .end = 0x1FFC },
    .{ .start = 0x2102, .end = 0x2102 }, .{ .start = 0x2107, .end = 0x2107 }, .{ .start = 0x210A, .end = 0x2113 },
    .{ .start = 0x2115, .end = 0x2115 }, .{ .start = 0x2119, .end = 0x211D }, .{ .start = 0x2124, .end = 0x2124 },
    .{ .start = 0x2126, .end = 0x2126 }, .{ .start = 0x2128, .end = 0x2128 }, .{ .start = 0x212A, .end = 0x212D },
    .{ .start = 0x212F, .end = 0x2134 }, .{ .start = 0x2139, .end = 0x2139 },
    .{ .start = 0x2D00, .end = 0x2D25 }, .{ .start = 0x2D27, .end = 0x2D27 }, .{ .start = 0x2D2D, .end = 0x2D2D },
    .{ .start = 0xFF21, .end = 0xFF3A }, .{ .start = 0xFF41, .end = 0xFF5A },
    .{ .start = 0x10400, .end = 0x1044F },
    .{ .start = 0x1D400, .end = 0x1D454 }, .{ .start = 0x1D456, .end = 0x1D467 },
};

/// Lm: Modifier_Letter
pub const gc_Lm = [_]CodepointRange{
    .{ .start = 0x02B0, .end = 0x02C1 },
    .{ .start = 0x02C6, .end = 0x02D1 },
    .{ .start = 0x02E0, .end = 0x02E4 },
    .{ .start = 0x02EC, .end = 0x02EC },
    .{ .start = 0x02EE, .end = 0x02EE },
    .{ .start = 0x0374, .end = 0x0374 },
    .{ .start = 0x037A, .end = 0x037A },
    .{ .start = 0x0559, .end = 0x0559 },
    .{ .start = 0x0640, .end = 0x0640 },
    .{ .start = 0x06E5, .end = 0x06E6 },
    .{ .start = 0x3005, .end = 0x3005 },
    .{ .start = 0x3031, .end = 0x3035 },
    .{ .start = 0x303B, .end = 0x303B },
    .{ .start = 0x309D, .end = 0x309E },
    .{ .start = 0x30FC, .end = 0x30FE },
    .{ .start = 0xFF70, .end = 0xFF70 },
};

/// Lo: Other_Letter
pub const gc_Lo = [_]CodepointRange{
    .{ .start = 0x01BB, .end = 0x01BB },
    .{ .start = 0x01C0, .end = 0x01C3 },
    .{ .start = 0x05D0, .end = 0x05EA }, .{ .start = 0x05EF, .end = 0x05F2 },
    .{ .start = 0x0620, .end = 0x063F }, .{ .start = 0x0641, .end = 0x064A },
    .{ .start = 0x066E, .end = 0x066F }, .{ .start = 0x0671, .end = 0x06D3 }, .{ .start = 0x06D5, .end = 0x06D5 },
    .{ .start = 0x0904, .end = 0x0939 }, .{ .start = 0x093D, .end = 0x093D }, .{ .start = 0x0950, .end = 0x0950 },
    .{ .start = 0x0958, .end = 0x0961 }, .{ .start = 0x0972, .end = 0x097F },
    .{ .start = 0x0E01, .end = 0x0E30 }, .{ .start = 0x0E32, .end = 0x0E33 }, .{ .start = 0x0E40, .end = 0x0E45 },
    .{ .start = 0x1100, .end = 0x11FF },
    .{ .start = 0x3006, .end = 0x3006 }, .{ .start = 0x303C, .end = 0x303C },
    .{ .start = 0x3041, .end = 0x3096 }, .{ .start = 0x309F, .end = 0x309F },
    .{ .start = 0x30A1, .end = 0x30FA }, .{ .start = 0x30FF, .end = 0x30FF },
    .{ .start = 0x3131, .end = 0x318E },
    .{ .start = 0x31F0, .end = 0x31FF },
    .{ .start = 0x3400, .end = 0x4DBF },
    .{ .start = 0x4E00, .end = 0x9FFF },
    .{ .start = 0xA960, .end = 0xA97C },
    .{ .start = 0xAC00, .end = 0xD7A3 }, .{ .start = 0xD7B0, .end = 0xD7FB },
    .{ .start = 0xF900, .end = 0xFA6D }, .{ .start = 0xFA70, .end = 0xFAD9 },
    .{ .start = 0xFF66, .end = 0xFF6F }, .{ .start = 0xFF71, .end = 0xFF9D },
    .{ .start = 0x1B000, .end = 0x1B122 },
    .{ .start = 0x20000, .end = 0x2A6DF },
    .{ .start = 0x2A700, .end = 0x2B739 },
    .{ .start = 0x2B740, .end = 0x2B81D },
    .{ .start = 0x2B820, .end = 0x2CEA1 },
    .{ .start = 0x2CEB0, .end = 0x2EBE0 },
    .{ .start = 0x2F800, .end = 0x2FA1D },
    .{ .start = 0x30000, .end = 0x323AF },
};

/// L: Letter (Lu | Ll | Lt | Lm | Lo)
pub const gc_L = [_]CodepointRange{
    .{ .start = 0x0041, .end = 0x005A },
    .{ .start = 0x0061, .end = 0x007A },
    .{ .start = 0x00AA, .end = 0x00AA }, .{ .start = 0x00B5, .end = 0x00B5 }, .{ .start = 0x00BA, .end = 0x00BA },
    .{ .start = 0x00C0, .end = 0x00D6 }, .{ .start = 0x00D8, .end = 0x00F6 }, .{ .start = 0x00F8, .end = 0x02C1 },
    .{ .start = 0x02C6, .end = 0x02D1 }, .{ .start = 0x02E0, .end = 0x02E4 }, .{ .start = 0x02EC, .end = 0x02EC },
    .{ .start = 0x02EE, .end = 0x02EE },
    .{ .start = 0x0370, .end = 0x0374 }, .{ .start = 0x0376, .end = 0x0377 }, .{ .start = 0x037A, .end = 0x037D },
    .{ .start = 0x037F, .end = 0x037F }, .{ .start = 0x0386, .end = 0x0386 }, .{ .start = 0x0388, .end = 0x038A },
    .{ .start = 0x038C, .end = 0x038C }, .{ .start = 0x038E, .end = 0x03A1 }, .{ .start = 0x03A3, .end = 0x03F5 },
    .{ .start = 0x03F7, .end = 0x0481 }, .{ .start = 0x048A, .end = 0x052F },
    .{ .start = 0x0531, .end = 0x0556 }, .{ .start = 0x0559, .end = 0x0559 }, .{ .start = 0x0560, .end = 0x0588 },
    .{ .start = 0x05D0, .end = 0x05EA }, .{ .start = 0x05EF, .end = 0x05F2 },
    .{ .start = 0x0620, .end = 0x064A }, .{ .start = 0x066E, .end = 0x066F }, .{ .start = 0x0671, .end = 0x06D3 },
    .{ .start = 0x06D5, .end = 0x06D5 }, .{ .start = 0x06E5, .end = 0x06E6 },
    .{ .start = 0x0904, .end = 0x0939 }, .{ .start = 0x093D, .end = 0x093D }, .{ .start = 0x0950, .end = 0x0950 },
    .{ .start = 0x0958, .end = 0x0961 }, .{ .start = 0x0972, .end = 0x097F },
    .{ .start = 0x0E01, .end = 0x0E30 }, .{ .start = 0x0E32, .end = 0x0E33 }, .{ .start = 0x0E40, .end = 0x0E46 },
    .{ .start = 0x10A0, .end = 0x10C5 }, .{ .start = 0x10C7, .end = 0x10C7 }, .{ .start = 0x10CD, .end = 0x10CD },
    .{ .start = 0x10D0, .end = 0x10FA }, .{ .start = 0x10FC, .end = 0x1248 },
    .{ .start = 0x1C90, .end = 0x1CBA }, .{ .start = 0x1CBD, .end = 0x1CBF },
    .{ .start = 0x1D00, .end = 0x1DBF }, .{ .start = 0x1E00, .end = 0x1F15 }, .{ .start = 0x1F18, .end = 0x1F1D },
    .{ .start = 0x1F20, .end = 0x1F45 }, .{ .start = 0x1F48, .end = 0x1F4D }, .{ .start = 0x1F50, .end = 0x1F57 },
    .{ .start = 0x1F59, .end = 0x1F5F }, .{ .start = 0x1F60, .end = 0x1F7D }, .{ .start = 0x1F80, .end = 0x1FB4 },
    .{ .start = 0x1FB6, .end = 0x1FBC }, .{ .start = 0x1FBE, .end = 0x1FBE }, .{ .start = 0x1FC2, .end = 0x1FC4 },
    .{ .start = 0x1FC6, .end = 0x1FCC }, .{ .start = 0x1FD0, .end = 0x1FD3 }, .{ .start = 0x1FD6, .end = 0x1FDB },
    .{ .start = 0x1FE0, .end = 0x1FEC }, .{ .start = 0x1FF2, .end = 0x1FF4 }, .{ .start = 0x1FF6, .end = 0x1FFC },
    .{ .start = 0x2102, .end = 0x2102 }, .{ .start = 0x2107, .end = 0x2107 }, .{ .start = 0x210A, .end = 0x2113 },
    .{ .start = 0x2115, .end = 0x2115 }, .{ .start = 0x2119, .end = 0x211D }, .{ .start = 0x2124, .end = 0x2124 },
    .{ .start = 0x2126, .end = 0x2126 }, .{ .start = 0x2128, .end = 0x2128 }, .{ .start = 0x212A, .end = 0x212D },
    .{ .start = 0x212F, .end = 0x2139 },
    .{ .start = 0x2C00, .end = 0x2DFF },
    .{ .start = 0x3005, .end = 0x3006 }, .{ .start = 0x3031, .end = 0x3035 }, .{ .start = 0x303B, .end = 0x303C },
    .{ .start = 0x3041, .end = 0x3096 }, .{ .start = 0x309D, .end = 0x309F },
    .{ .start = 0x30A1, .end = 0x30FA }, .{ .start = 0x30FC, .end = 0x30FF },
    .{ .start = 0x3105, .end = 0x312F }, .{ .start = 0x3131, .end = 0x318E }, .{ .start = 0x31A0, .end = 0x31FF },
    .{ .start = 0x3400, .end = 0x4DBF },
    .{ .start = 0x4E00, .end = 0xA48C },
    .{ .start = 0xA960, .end = 0xA97C },
    .{ .start = 0xAC00, .end = 0xD7A3 }, .{ .start = 0xD7B0, .end = 0xD7FB },
    .{ .start = 0xF900, .end = 0xFA6D }, .{ .start = 0xFA70, .end = 0xFAD9 },
    .{ .start = 0xFB00, .end = 0xFB4F },
    .{ .start = 0xFE70, .end = 0xFEFC },
    .{ .start = 0xFF21, .end = 0xFF3A }, .{ .start = 0xFF41, .end = 0xFF5A }, .{ .start = 0xFF66, .end = 0xFFBE },
    .{ .start = 0x10400, .end = 0x1049D },
    .{ .start = 0x1B000, .end = 0x1B122 },
    .{ .start = 0x1D400, .end = 0x1D454 }, .{ .start = 0x1D456, .end = 0x1D467 },
    .{ .start = 0x20000, .end = 0x2A6DF },
    .{ .start = 0x2A700, .end = 0x2B739 },
    .{ .start = 0x2B740, .end = 0x2B81D },
    .{ .start = 0x2B820, .end = 0x2CEA1 },
    .{ .start = 0x2CEB0, .end = 0x2EBE0 },
    .{ .start = 0x2F800, .end = 0x2FA1D },
    .{ .start = 0x30000, .end = 0x323AF },
};

/// Mn: Nonspacing_Mark
pub const gc_Mn = [_]CodepointRange{
    .{ .start = 0x0300, .end = 0x036F },
    .{ .start = 0x0483, .end = 0x0487 },
    .{ .start = 0x0591, .end = 0x05BD }, .{ .start = 0x05BF, .end = 0x05BF }, .{ .start = 0x05C1, .end = 0x05C2 },
    .{ .start = 0x05C4, .end = 0x05C5 }, .{ .start = 0x05C7, .end = 0x05C7 },
    .{ .start = 0x0610, .end = 0x061A }, .{ .start = 0x064B, .end = 0x065F }, .{ .start = 0x0670, .end = 0x0670 },
    .{ .start = 0x06D6, .end = 0x06DC }, .{ .start = 0x06DF, .end = 0x06E4 }, .{ .start = 0x06E7, .end = 0x06E8 },
    .{ .start = 0x06EA, .end = 0x06ED },
    .{ .start = 0x0900, .end = 0x0902 }, .{ .start = 0x093A, .end = 0x093A }, .{ .start = 0x093C, .end = 0x093C },
    .{ .start = 0x0941, .end = 0x0948 }, .{ .start = 0x094D, .end = 0x094D }, .{ .start = 0x0951, .end = 0x0957 },
    .{ .start = 0x0962, .end = 0x0963 },
    .{ .start = 0x0E31, .end = 0x0E31 }, .{ .start = 0x0E34, .end = 0x0E3A }, .{ .start = 0x0E47, .end = 0x0E4E },
    .{ .start = 0x1AB0, .end = 0x1ABE },
    .{ .start = 0x1DC0, .end = 0x1DFF },
    .{ .start = 0x20D0, .end = 0x20DC }, .{ .start = 0x20E1, .end = 0x20E1 }, .{ .start = 0x20E5, .end = 0x20F0 },
    .{ .start = 0x302A, .end = 0x302D }, .{ .start = 0x3099, .end = 0x309A },
    .{ .start = 0xFE00, .end = 0xFE0F }, .{ .start = 0xFE20, .end = 0xFE2F },
    .{ .start = 0xE0100, .end = 0xE01EF },
};

/// Mc: Spacing_Mark
pub const gc_Mc = [_]CodepointRange{
    .{ .start = 0x0903, .end = 0x0903 }, .{ .start = 0x093B, .end = 0x093B }, .{ .start = 0x093E, .end = 0x0940 },
    .{ .start = 0x0949, .end = 0x094C }, .{ .start = 0x094E, .end = 0x094F },
    .{ .start = 0x302E, .end = 0x302F },
};

/// Me: Enclosing_Mark
pub const gc_Me = [_]CodepointRange{
    .{ .start = 0x0488, .end = 0x0489 },
    .{ .start = 0x1ABE, .end = 0x1ABE },
    .{ .start = 0x20DD, .end = 0x20E0 },
    .{ .start = 0x20E2, .end = 0x20E4 },
};

/// M: Mark (Mn | Mc | Me)
pub const gc_M = [_]CodepointRange{
    .{ .start = 0x0300, .end = 0x036F },
    .{ .start = 0x0483, .end = 0x0489 },
    .{ .start = 0x0591, .end = 0x05BD }, .{ .start = 0x05BF, .end = 0x05BF }, .{ .start = 0x05C1, .end = 0x05C2 },
    .{ .start = 0x05C4, .end = 0x05C5 }, .{ .start = 0x05C7, .end = 0x05C7 },
    .{ .start = 0x0610, .end = 0x061A }, .{ .start = 0x064B, .end = 0x065F }, .{ .start = 0x0670, .end = 0x0670 },
    .{ .start = 0x06D6, .end = 0x06DC }, .{ .start = 0x06DF, .end = 0x06E4 }, .{ .start = 0x06E7, .end = 0x06E8 },
    .{ .start = 0x06EA, .end = 0x06ED },
    .{ .start = 0x0900, .end = 0x0903 }, .{ .start = 0x093A, .end = 0x093C }, .{ .start = 0x093E, .end = 0x094F },
    .{ .start = 0x0951, .end = 0x0957 }, .{ .start = 0x0962, .end = 0x0963 },
    .{ .start = 0x0E31, .end = 0x0E31 }, .{ .start = 0x0E34, .end = 0x0E3A }, .{ .start = 0x0E47, .end = 0x0E4E },
    .{ .start = 0x1AB0, .end = 0x1ABE },
    .{ .start = 0x1DC0, .end = 0x1DFF },
    .{ .start = 0x20D0, .end = 0x20F0 },
    .{ .start = 0x302A, .end = 0x302F }, .{ .start = 0x3099, .end = 0x309A },
    .{ .start = 0xFE00, .end = 0xFE0F }, .{ .start = 0xFE20, .end = 0xFE2F },
    .{ .start = 0xE0100, .end = 0xE01EF },
};

/// Nd: Decimal_Number
pub const gc_Nd = [_]CodepointRange{
    .{ .start = 0x0030, .end = 0x0039 },
    .{ .start = 0x0660, .end = 0x0669 },
    .{ .start = 0x06F0, .end = 0x06F9 },
    .{ .start = 0x07C0, .end = 0x07C9 },
    .{ .start = 0x0966, .end = 0x096F },
    .{ .start = 0x09E6, .end = 0x09EF },
    .{ .start = 0x0A66, .end = 0x0A6F },
    .{ .start = 0x0AE6, .end = 0x0AEF },
    .{ .start = 0x0B66, .end = 0x0B6F },
    .{ .start = 0x0BE6, .end = 0x0BEF },
    .{ .start = 0x0C66, .end = 0x0C6F },
    .{ .start = 0x0CE6, .end = 0x0CEF },
    .{ .start = 0x0D66, .end = 0x0D6F },
    .{ .start = 0x0DE6, .end = 0x0DEF },
    .{ .start = 0x0E50, .end = 0x0E59 },
    .{ .start = 0x0ED0, .end = 0x0ED9 },
    .{ .start = 0x0F20, .end = 0x0F29 },
    .{ .start = 0x1040, .end = 0x1049 },
    .{ .start = 0x17E0, .end = 0x17E9 },
    .{ .start = 0x1810, .end = 0x1819 },
    .{ .start = 0xFF10, .end = 0xFF19 },
    .{ .start = 0x1D7CE, .end = 0x1D7FF },
};

/// Nl: Letter_Number
pub const gc_Nl = [_]CodepointRange{
    .{ .start = 0x16EE, .end = 0x16F0 },
    .{ .start = 0x2160, .end = 0x2182 },
    .{ .start = 0x2185, .end = 0x2188 },
    .{ .start = 0x3007, .end = 0x3007 },
    .{ .start = 0x3021, .end = 0x3029 },
    .{ .start = 0x3038, .end = 0x303A },
    .{ .start = 0x10140, .end = 0x10174 },
};

/// No: Other_Number
pub const gc_No = [_]CodepointRange{
    .{ .start = 0x00B2, .end = 0x00B3 },
    .{ .start = 0x00B9, .end = 0x00B9 },
    .{ .start = 0x00BC, .end = 0x00BE },
    .{ .start = 0x2070, .end = 0x2070 }, .{ .start = 0x2074, .end = 0x2079 },
    .{ .start = 0x2080, .end = 0x2089 },
    .{ .start = 0x2150, .end = 0x215F }, .{ .start = 0x2189, .end = 0x2189 },
    .{ .start = 0x2460, .end = 0x249B }, .{ .start = 0x24EA, .end = 0x24FF },
    .{ .start = 0x2776, .end = 0x2793 },
    .{ .start = 0x3220, .end = 0x3229 }, .{ .start = 0x3248, .end = 0x324F },
    .{ .start = 0x3251, .end = 0x325F }, .{ .start = 0x3280, .end = 0x3289 },
    .{ .start = 0x32B1, .end = 0x32BF },
};

/// N: Number (Nd | Nl | No)
pub const gc_N = [_]CodepointRange{
    .{ .start = 0x0030, .end = 0x0039 },
    .{ .start = 0x00B2, .end = 0x00B3 }, .{ .start = 0x00B9, .end = 0x00B9 }, .{ .start = 0x00BC, .end = 0x00BE },
    .{ .start = 0x0660, .end = 0x0669 }, .{ .start = 0x06F0, .end = 0x06F9 }, .{ .start = 0x07C0, .end = 0x07C9 },
    .{ .start = 0x0966, .end = 0x096F }, .{ .start = 0x09E6, .end = 0x09EF }, .{ .start = 0x0A66, .end = 0x0A6F },
    .{ .start = 0x0AE6, .end = 0x0AEF }, .{ .start = 0x0B66, .end = 0x0B6F }, .{ .start = 0x0BE6, .end = 0x0BEF },
    .{ .start = 0x0C66, .end = 0x0C6F }, .{ .start = 0x0CE6, .end = 0x0CEF }, .{ .start = 0x0D66, .end = 0x0D6F },
    .{ .start = 0x0DE6, .end = 0x0DEF }, .{ .start = 0x0E50, .end = 0x0E59 }, .{ .start = 0x0ED0, .end = 0x0ED9 },
    .{ .start = 0x0F20, .end = 0x0F33 }, .{ .start = 0x1040, .end = 0x1049 }, .{ .start = 0x16EE, .end = 0x16F0 },
    .{ .start = 0x17E0, .end = 0x17E9 }, .{ .start = 0x1810, .end = 0x1819 },
    .{ .start = 0x2070, .end = 0x2070 }, .{ .start = 0x2074, .end = 0x2079 }, .{ .start = 0x2080, .end = 0x2089 },
    .{ .start = 0x2150, .end = 0x2189 }, .{ .start = 0x2460, .end = 0x249B }, .{ .start = 0x24EA, .end = 0x24FF },
    .{ .start = 0x2776, .end = 0x2793 },
    .{ .start = 0x3007, .end = 0x3007 }, .{ .start = 0x3021, .end = 0x3029 }, .{ .start = 0x3038, .end = 0x303A },
    .{ .start = 0x3220, .end = 0x3229 }, .{ .start = 0x3248, .end = 0x324F }, .{ .start = 0x3251, .end = 0x325F },
    .{ .start = 0x3280, .end = 0x3289 }, .{ .start = 0x32B1, .end = 0x32BF },
    .{ .start = 0xFF10, .end = 0xFF19 },
    .{ .start = 0x10140, .end = 0x10174 },
    .{ .start = 0x1D7CE, .end = 0x1D7FF },
};

/// Pc: Connector_Punctuation
pub const gc_Pc = [_]CodepointRange{
    .{ .start = 0x005F, .end = 0x005F },
    .{ .start = 0x203F, .end = 0x2040 },
    .{ .start = 0x2054, .end = 0x2054 },
    .{ .start = 0xFE33, .end = 0xFE34 },
    .{ .start = 0xFE4D, .end = 0xFE4F },
    .{ .start = 0xFF3F, .end = 0xFF3F },
};

/// Pd: Dash_Punctuation
pub const gc_Pd = [_]CodepointRange{
    .{ .start = 0x002D, .end = 0x002D },
    .{ .start = 0x058A, .end = 0x058A }, .{ .start = 0x05BE, .end = 0x05BE },
    .{ .start = 0x2010, .end = 0x2015 },
    .{ .start = 0x2E17, .end = 0x2E17 }, .{ .start = 0x2E1A, .end = 0x2E1A }, .{ .start = 0x2E3A, .end = 0x2E3B },
    .{ .start = 0x301C, .end = 0x301C }, .{ .start = 0x3030, .end = 0x3030 }, .{ .start = 0x30A0, .end = 0x30A0 },
    .{ .start = 0xFE31, .end = 0xFE32 }, .{ .start = 0xFE58, .end = 0xFE58 }, .{ .start = 0xFE63, .end = 0xFE63 },
    .{ .start = 0xFF0D, .end = 0xFF0D },
};

/// Ps: Open_Punctuation
pub const gc_Ps = [_]CodepointRange{
    .{ .start = 0x0028, .end = 0x0028 }, .{ .start = 0x005B, .end = 0x005B }, .{ .start = 0x007B, .end = 0x007B },
    .{ .start = 0x201A, .end = 0x201A }, .{ .start = 0x201E, .end = 0x201E }, .{ .start = 0x2045, .end = 0x2045 },
    .{ .start = 0x207D, .end = 0x207D }, .{ .start = 0x208D, .end = 0x208D },
    .{ .start = 0x2308, .end = 0x2308 }, .{ .start = 0x230A, .end = 0x230A }, .{ .start = 0x2329, .end = 0x2329 },
    .{ .start = 0x2768, .end = 0x2768 }, .{ .start = 0x276A, .end = 0x276A }, .{ .start = 0x276C, .end = 0x276C },
    .{ .start = 0x276E, .end = 0x276E }, .{ .start = 0x2770, .end = 0x2770 }, .{ .start = 0x2772, .end = 0x2772 },
    .{ .start = 0x2774, .end = 0x2774 },
    .{ .start = 0x3008, .end = 0x3008 }, .{ .start = 0x300A, .end = 0x300A }, .{ .start = 0x300C, .end = 0x300C },
    .{ .start = 0x300E, .end = 0x300E }, .{ .start = 0x3010, .end = 0x3010 }, .{ .start = 0x3014, .end = 0x3014 },
    .{ .start = 0x3016, .end = 0x3016 }, .{ .start = 0x3018, .end = 0x3018 }, .{ .start = 0x301A, .end = 0x301A },
    .{ .start = 0x301D, .end = 0x301D },
    .{ .start = 0xFE59, .end = 0xFE59 }, .{ .start = 0xFE5B, .end = 0xFE5B }, .{ .start = 0xFE5D, .end = 0xFE5D },
    .{ .start = 0xFF08, .end = 0xFF08 }, .{ .start = 0xFF3B, .end = 0xFF3B }, .{ .start = 0xFF5B, .end = 0xFF5B },
    .{ .start = 0xFF5F, .end = 0xFF5F }, .{ .start = 0xFF62, .end = 0xFF62 },
};

/// Pe: Close_Punctuation
pub const gc_Pe = [_]CodepointRange{
    .{ .start = 0x0029, .end = 0x0029 }, .{ .start = 0x005D, .end = 0x005D }, .{ .start = 0x007D, .end = 0x007D },
    .{ .start = 0x2046, .end = 0x2046 }, .{ .start = 0x207E, .end = 0x207E }, .{ .start = 0x208E, .end = 0x208E },
    .{ .start = 0x2309, .end = 0x2309 }, .{ .start = 0x230B, .end = 0x230B }, .{ .start = 0x232A, .end = 0x232A },
    .{ .start = 0x2769, .end = 0x2769 }, .{ .start = 0x276B, .end = 0x276B }, .{ .start = 0x276D, .end = 0x276D },
    .{ .start = 0x276F, .end = 0x276F }, .{ .start = 0x2771, .end = 0x2771 }, .{ .start = 0x2773, .end = 0x2773 },
    .{ .start = 0x2775, .end = 0x2775 },
    .{ .start = 0x3009, .end = 0x3009 }, .{ .start = 0x300B, .end = 0x300B }, .{ .start = 0x300D, .end = 0x300D },
    .{ .start = 0x300F, .end = 0x300F }, .{ .start = 0x3011, .end = 0x3011 }, .{ .start = 0x3015, .end = 0x3015 },
    .{ .start = 0x3017, .end = 0x3017 }, .{ .start = 0x3019, .end = 0x3019 }, .{ .start = 0x301B, .end = 0x301B },
    .{ .start = 0x301E, .end = 0x301F },
    .{ .start = 0xFE5A, .end = 0xFE5A }, .{ .start = 0xFE5C, .end = 0xFE5C }, .{ .start = 0xFE5E, .end = 0xFE5E },
    .{ .start = 0xFF09, .end = 0xFF09 }, .{ .start = 0xFF3D, .end = 0xFF3D }, .{ .start = 0xFF5D, .end = 0xFF5D },
    .{ .start = 0xFF60, .end = 0xFF60 }, .{ .start = 0xFF63, .end = 0xFF63 },
};

/// Pi: Initial_Punctuation
pub const gc_Pi = [_]CodepointRange{
    .{ .start = 0x00AB, .end = 0x00AB },
    .{ .start = 0x2018, .end = 0x2018 }, .{ .start = 0x201B, .end = 0x201C }, .{ .start = 0x201F, .end = 0x201F },
    .{ .start = 0x2039, .end = 0x2039 },
};

/// Pf: Final_Punctuation
pub const gc_Pf = [_]CodepointRange{
    .{ .start = 0x00BB, .end = 0x00BB },
    .{ .start = 0x2019, .end = 0x2019 }, .{ .start = 0x201D, .end = 0x201D },
    .{ .start = 0x203A, .end = 0x203A },
};

/// Po: Other_Punctuation
pub const gc_Po = [_]CodepointRange{
    .{ .start = 0x0021, .end = 0x0023 }, .{ .start = 0x0025, .end = 0x0027 }, .{ .start = 0x002A, .end = 0x002A },
    .{ .start = 0x002C, .end = 0x002C }, .{ .start = 0x002E, .end = 0x002F }, .{ .start = 0x003A, .end = 0x003B },
    .{ .start = 0x003F, .end = 0x0040 }, .{ .start = 0x005C, .end = 0x005C },
    .{ .start = 0x00A1, .end = 0x00A1 }, .{ .start = 0x00A7, .end = 0x00A7 }, .{ .start = 0x00B6, .end = 0x00B7 },
    .{ .start = 0x00BF, .end = 0x00BF },
    .{ .start = 0x037E, .end = 0x037E }, .{ .start = 0x0387, .end = 0x0387 },
    .{ .start = 0x055A, .end = 0x055F }, .{ .start = 0x0589, .end = 0x0589 },
    .{ .start = 0x060C, .end = 0x060D }, .{ .start = 0x061B, .end = 0x061B }, .{ .start = 0x061E, .end = 0x061F },
    .{ .start = 0x066A, .end = 0x066D }, .{ .start = 0x06D4, .end = 0x06D4 },
    .{ .start = 0x0964, .end = 0x0965 }, .{ .start = 0x0970, .end = 0x0970 },
    .{ .start = 0x2016, .end = 0x2017 }, .{ .start = 0x2020, .end = 0x2027 }, .{ .start = 0x2030, .end = 0x2038 },
    .{ .start = 0x203B, .end = 0x203E }, .{ .start = 0x2041, .end = 0x2043 }, .{ .start = 0x2047, .end = 0x2051 },
    .{ .start = 0x2053, .end = 0x2053 }, .{ .start = 0x2055, .end = 0x205E },
    .{ .start = 0x3001, .end = 0x3003 }, .{ .start = 0x303D, .end = 0x303D }, .{ .start = 0x30FB, .end = 0x30FB },
    .{ .start = 0xFE10, .end = 0xFE16 }, .{ .start = 0xFE19, .end = 0xFE19 }, .{ .start = 0xFE30, .end = 0xFE30 },
    .{ .start = 0xFE45, .end = 0xFE46 }, .{ .start = 0xFE49, .end = 0xFE4C }, .{ .start = 0xFE50, .end = 0xFE52 },
    .{ .start = 0xFE54, .end = 0xFE57 }, .{ .start = 0xFE5F, .end = 0xFE61 }, .{ .start = 0xFE68, .end = 0xFE68 },
    .{ .start = 0xFE6A, .end = 0xFE6B },
    .{ .start = 0xFF01, .end = 0xFF03 }, .{ .start = 0xFF05, .end = 0xFF07 }, .{ .start = 0xFF0A, .end = 0xFF0A },
    .{ .start = 0xFF0C, .end = 0xFF0C }, .{ .start = 0xFF0E, .end = 0xFF0F }, .{ .start = 0xFF1A, .end = 0xFF1B },
    .{ .start = 0xFF1F, .end = 0xFF20 }, .{ .start = 0xFF3C, .end = 0xFF3C }, .{ .start = 0xFF61, .end = 0xFF61 },
    .{ .start = 0xFF64, .end = 0xFF65 },
};

/// P: Punctuation (Pc | Pd | Ps | Pe | Pi | Pf | Po)
pub const gc_P = [_]CodepointRange{
    .{ .start = 0x0021, .end = 0x0023 }, .{ .start = 0x0025, .end = 0x002A }, .{ .start = 0x002C, .end = 0x002F },
    .{ .start = 0x003A, .end = 0x003B }, .{ .start = 0x003F, .end = 0x0040 }, .{ .start = 0x005B, .end = 0x005D },
    .{ .start = 0x005F, .end = 0x005F }, .{ .start = 0x007B, .end = 0x007B }, .{ .start = 0x007D, .end = 0x007D },
    .{ .start = 0x00A1, .end = 0x00A1 }, .{ .start = 0x00A7, .end = 0x00A7 }, .{ .start = 0x00AB, .end = 0x00AB },
    .{ .start = 0x00B6, .end = 0x00B7 }, .{ .start = 0x00BB, .end = 0x00BB }, .{ .start = 0x00BF, .end = 0x00BF },
    .{ .start = 0x037E, .end = 0x037E }, .{ .start = 0x0387, .end = 0x0387 },
    .{ .start = 0x055A, .end = 0x055F }, .{ .start = 0x0589, .end = 0x058A }, .{ .start = 0x05BE, .end = 0x05BE },
    .{ .start = 0x060C, .end = 0x060D }, .{ .start = 0x061B, .end = 0x061F }, .{ .start = 0x066A, .end = 0x066D },
    .{ .start = 0x06D4, .end = 0x06D4 },
    .{ .start = 0x0964, .end = 0x0965 }, .{ .start = 0x0970, .end = 0x0970 },
    .{ .start = 0x2010, .end = 0x2027 }, .{ .start = 0x2030, .end = 0x2043 }, .{ .start = 0x2045, .end = 0x2051 },
    .{ .start = 0x2053, .end = 0x205E }, .{ .start = 0x207D, .end = 0x207E }, .{ .start = 0x208D, .end = 0x208E },
    .{ .start = 0x2308, .end = 0x230B }, .{ .start = 0x2329, .end = 0x232A }, .{ .start = 0x2768, .end = 0x2775 },
    .{ .start = 0x2E00, .end = 0x2E52 },
    .{ .start = 0x3001, .end = 0x3003 }, .{ .start = 0x3008, .end = 0x3011 }, .{ .start = 0x3014, .end = 0x301F },
    .{ .start = 0x3030, .end = 0x3030 }, .{ .start = 0x303D, .end = 0x303D }, .{ .start = 0x30A0, .end = 0x30A0 },
    .{ .start = 0x30FB, .end = 0x30FB },
    .{ .start = 0xFE10, .end = 0xFE19 }, .{ .start = 0xFE30, .end = 0xFE52 }, .{ .start = 0xFE54, .end = 0xFE61 },
    .{ .start = 0xFE63, .end = 0xFE63 }, .{ .start = 0xFE68, .end = 0xFE68 }, .{ .start = 0xFE6A, .end = 0xFE6B },
    .{ .start = 0xFF01, .end = 0xFF03 }, .{ .start = 0xFF05, .end = 0xFF0A }, .{ .start = 0xFF0C, .end = 0xFF0F },
    .{ .start = 0xFF1A, .end = 0xFF1B }, .{ .start = 0xFF1F, .end = 0xFF20 }, .{ .start = 0xFF3B, .end = 0xFF3D },
    .{ .start = 0xFF3F, .end = 0xFF3F }, .{ .start = 0xFF5B, .end = 0xFF5B }, .{ .start = 0xFF5D, .end = 0xFF5D },
    .{ .start = 0xFF5F, .end = 0xFF65 },
};

/// Sm: Math_Symbol
pub const gc_Sm = [_]CodepointRange{
    .{ .start = 0x002B, .end = 0x002B }, .{ .start = 0x003C, .end = 0x003E }, .{ .start = 0x007C, .end = 0x007C },
    .{ .start = 0x007E, .end = 0x007E }, .{ .start = 0x00AC, .end = 0x00AC }, .{ .start = 0x00B1, .end = 0x00B1 },
    .{ .start = 0x00D7, .end = 0x00D7 }, .{ .start = 0x00F7, .end = 0x00F7 },
    .{ .start = 0x2044, .end = 0x2044 }, .{ .start = 0x2052, .end = 0x2052 },
    .{ .start = 0x207A, .end = 0x207C }, .{ .start = 0x208A, .end = 0x208C },
    .{ .start = 0x2190, .end = 0x2194 }, .{ .start = 0x219A, .end = 0x219B },
    .{ .start = 0x2200, .end = 0x22FF },
    .{ .start = 0x27C0, .end = 0x27EF }, .{ .start = 0x2980, .end = 0x2AFF },
    .{ .start = 0xFF0B, .end = 0xFF0B }, .{ .start = 0xFF1C, .end = 0xFF1E }, .{ .start = 0xFF5C, .end = 0xFF5C },
    .{ .start = 0xFF5E, .end = 0xFF5E },
};

/// Sc: Currency_Symbol
pub const gc_Sc = [_]CodepointRange{
    .{ .start = 0x0024, .end = 0x0024 },
    .{ .start = 0x00A2, .end = 0x00A5 },
    .{ .start = 0x058F, .end = 0x058F },
    .{ .start = 0x060B, .end = 0x060B },
    .{ .start = 0x09F2, .end = 0x09F3 }, .{ .start = 0x09FB, .end = 0x09FB },
    .{ .start = 0x0E3F, .end = 0x0E3F },
    .{ .start = 0x20A0, .end = 0x20C0 },
    .{ .start = 0xFE69, .end = 0xFE69 },
    .{ .start = 0xFF04, .end = 0xFF04 }, .{ .start = 0xFFE0, .end = 0xFFE1 }, .{ .start = 0xFFE5, .end = 0xFFE6 },
};

/// Sk: Modifier_Symbol
pub const gc_Sk = [_]CodepointRange{
    .{ .start = 0x005E, .end = 0x005E }, .{ .start = 0x0060, .end = 0x0060 },
    .{ .start = 0x00A8, .end = 0x00A8 }, .{ .start = 0x00AF, .end = 0x00AF }, .{ .start = 0x00B4, .end = 0x00B4 },
    .{ .start = 0x00B8, .end = 0x00B8 },
    .{ .start = 0x02C2, .end = 0x02C5 }, .{ .start = 0x02D2, .end = 0x02DF }, .{ .start = 0x02E5, .end = 0x02EB },
    .{ .start = 0x02ED, .end = 0x02ED }, .{ .start = 0x02EF, .end = 0x02FF },
    .{ .start = 0xFF3E, .end = 0xFF3E }, .{ .start = 0xFF40, .end = 0xFF40 },
    .{ .start = 0x1F3FB, .end = 0x1F3FF },
};

/// So: Other_Symbol (including Emoji, Pictographs, Dingbats, Emoticons, Transport, Arrows, Box Drawing)
pub const gc_So = [_]CodepointRange{
    .{ .start = 0x00A6, .end = 0x00A6 }, .{ .start = 0x00A9, .end = 0x00A9 }, .{ .start = 0x00AE, .end = 0x00AE },
    .{ .start = 0x00B0, .end = 0x00B0 },
    .{ .start = 0x2100, .end = 0x2101 }, .{ .start = 0x2103, .end = 0x2106 }, .{ .start = 0x2108, .end = 0x2109 },
    .{ .start = 0x2114, .end = 0x2114 }, .{ .start = 0x2116, .end = 0x2118 }, .{ .start = 0x211E, .end = 0x2123 },
    .{ .start = 0x2125, .end = 0x2125 }, .{ .start = 0x2127, .end = 0x2127 }, .{ .start = 0x2129, .end = 0x2129 },
    .{ .start = 0x212E, .end = 0x212E }, .{ .start = 0x213A, .end = 0x213B },
    .{ .start = 0x2195, .end = 0x2199 }, .{ .start = 0x219C, .end = 0x21FF },
    .{ .start = 0x2300, .end = 0x2307 }, .{ .start = 0x230C, .end = 0x231F }, .{ .start = 0x2322, .end = 0x2328 },
    .{ .start = 0x232B, .end = 0x237B }, .{ .start = 0x237D, .end = 0x239A }, .{ .start = 0x23B4, .end = 0x23FE },
    .{ .start = 0x2400, .end = 0x2426 }, .{ .start = 0x2440, .end = 0x244A }, .{ .start = 0x249C, .end = 0x24E9 },
    .{ .start = 0x2500, .end = 0x25B6 }, .{ .start = 0x25B8, .end = 0x25C0 }, .{ .start = 0x25C2, .end = 0x25F7 },
    .{ .start = 0x2600, .end = 0x266E }, .{ .start = 0x2670, .end = 0x2767 }, .{ .start = 0x2794, .end = 0x27BF },
    .{ .start = 0x2B00, .end = 0x2BFF },
    .{ .start = 0x3004, .end = 0x3004 }, .{ .start = 0x3012, .end = 0x3013 }, .{ .start = 0x3020, .end = 0x3020 },
    .{ .start = 0x3036, .end = 0x3037 }, .{ .start = 0x303E, .end = 0x303F },
    .{ .start = 0x1F000, .end = 0x1F3FA }, .{ .start = 0x1F400, .end = 0x1FAFF },
};

/// S: Symbol (Sm | Sc | Sk | So)
pub const gc_S = [_]CodepointRange{
    .{ .start = 0x0024, .end = 0x0024 }, .{ .start = 0x002B, .end = 0x002B }, .{ .start = 0x003C, .end = 0x003E },
    .{ .start = 0x005E, .end = 0x005E }, .{ .start = 0x0060, .end = 0x0060 }, .{ .start = 0x007C, .end = 0x007C },
    .{ .start = 0x007E, .end = 0x007E }, .{ .start = 0x00A2, .end = 0x00A6 }, .{ .start = 0x00A8, .end = 0x00A9 },
    .{ .start = 0x00AC, .end = 0x00AC }, .{ .start = 0x00AE, .end = 0x00B1 }, .{ .start = 0x00B4, .end = 0x00B4 },
    .{ .start = 0x00B8, .end = 0x00B8 }, .{ .start = 0x00D7, .end = 0x00D7 }, .{ .start = 0x00F7, .end = 0x00F7 },
    .{ .start = 0x02C2, .end = 0x02C5 }, .{ .start = 0x02D2, .end = 0x02DF }, .{ .start = 0x02E5, .end = 0x02EB },
    .{ .start = 0x02ED, .end = 0x02ED }, .{ .start = 0x02EF, .end = 0x02FF },
    .{ .start = 0x058F, .end = 0x058F }, .{ .start = 0x060B, .end = 0x060B },
    .{ .start = 0x09F2, .end = 0x09F3 }, .{ .start = 0x09FB, .end = 0x09FB }, .{ .start = 0x0E3F, .end = 0x0E3F },
    .{ .start = 0x2044, .end = 0x2044 }, .{ .start = 0x2052, .end = 0x2052 },
    .{ .start = 0x207A, .end = 0x207C }, .{ .start = 0x208A, .end = 0x208C }, .{ .start = 0x20A0, .end = 0x20C0 },
    .{ .start = 0x2100, .end = 0x2101 }, .{ .start = 0x2103, .end = 0x2106 }, .{ .start = 0x2108, .end = 0x2109 },
    .{ .start = 0x2114, .end = 0x2114 }, .{ .start = 0x2116, .end = 0x2118 }, .{ .start = 0x211E, .end = 0x2123 },
    .{ .start = 0x2125, .end = 0x2125 }, .{ .start = 0x2127, .end = 0x2127 }, .{ .start = 0x2129, .end = 0x2129 },
    .{ .start = 0x212E, .end = 0x212E }, .{ .start = 0x213A, .end = 0x213B }, .{ .start = 0x2140, .end = 0x214F },
    .{ .start = 0x2190, .end = 0x2307 }, .{ .start = 0x230C, .end = 0x2328 }, .{ .start = 0x232B, .end = 0x2426 },
    .{ .start = 0x2440, .end = 0x244A }, .{ .start = 0x249C, .end = 0x24E9 }, .{ .start = 0x2500, .end = 0x2767 },
    .{ .start = 0x2794, .end = 0x2BFF },
    .{ .start = 0x3004, .end = 0x3004 }, .{ .start = 0x3012, .end = 0x3013 }, .{ .start = 0x3020, .end = 0x3020 },
    .{ .start = 0x3036, .end = 0x3037 }, .{ .start = 0x303E, .end = 0x303F },
    .{ .start = 0xFE69, .end = 0xFE69 },
    .{ .start = 0xFF04, .end = 0xFF04 }, .{ .start = 0xFF0B, .end = 0xFF0B }, .{ .start = 0xFF1C, .end = 0xFF1E },
    .{ .start = 0xFF3E, .end = 0xFF3E }, .{ .start = 0xFF40, .end = 0xFF40 }, .{ .start = 0xFF5C, .end = 0xFF5C },
    .{ .start = 0xFF5E, .end = 0xFF5E }, .{ .start = 0xFFE0, .end = 0xFFE6 },
    .{ .start = 0x1F000, .end = 0x1FAFF },
};

/// Zs: Space_Separator
pub const gc_Zs = [_]CodepointRange{
    .{ .start = 0x0020, .end = 0x0020 },
    .{ .start = 0x00A0, .end = 0x00A0 },
    .{ .start = 0x1680, .end = 0x1680 },
    .{ .start = 0x2000, .end = 0x200A },
    .{ .start = 0x202F, .end = 0x202F },
    .{ .start = 0x205F, .end = 0x205F },
    .{ .start = 0x3000, .end = 0x3000 },
};

/// Zl: Line_Separator
pub const gc_Zl = [_]CodepointRange{
    .{ .start = 0x2028, .end = 0x2028 },
};

/// Zp: Paragraph_Separator
pub const gc_Zp = [_]CodepointRange{
    .{ .start = 0x2029, .end = 0x2029 },
};

/// Z: Separator (Zs | Zl | Zp)
pub const gc_Z = [_]CodepointRange{
    .{ .start = 0x0020, .end = 0x0020 },
    .{ .start = 0x00A0, .end = 0x00A0 },
    .{ .start = 0x1680, .end = 0x1680 },
    .{ .start = 0x2000, .end = 0x200A },
    .{ .start = 0x2028, .end = 0x2029 },
    .{ .start = 0x202F, .end = 0x202F },
    .{ .start = 0x205F, .end = 0x205F },
    .{ .start = 0x3000, .end = 0x3000 },
};

/// Cc: Control
pub const gc_Cc = [_]CodepointRange{
    .{ .start = 0x0000, .end = 0x001F },
    .{ .start = 0x007F, .end = 0x009F },
};

/// Cf: Format
pub const gc_Cf = [_]CodepointRange{
    .{ .start = 0x00AD, .end = 0x00AD },
    .{ .start = 0x0600, .end = 0x0605 }, .{ .start = 0x061C, .end = 0x061C }, .{ .start = 0x06DD, .end = 0x06DD },
    .{ .start = 0x180E, .end = 0x180E },
    .{ .start = 0x200B, .end = 0x200F },
    .{ .start = 0x202A, .end = 0x202E },
    .{ .start = 0x2060, .end = 0x2064 }, .{ .start = 0x2066, .end = 0x206F },
    .{ .start = 0xFEFF, .end = 0xFEFF },
    .{ .start = 0xFFF9, .end = 0xFFFB },
    .{ .start = 0xE0001, .end = 0xE007F },
};

/// Co: Private_Use
pub const gc_Co = [_]CodepointRange{
    .{ .start = 0xE000, .end = 0xF8FF },
    .{ .start = 0xF0000, .end = 0xFFFFD },
    .{ .start = 0x100000, .end = 0x10FFFD },
};

/// Cn: Unassigned
pub const gc_Cn = [_]CodepointRange{
    .{ .start = 0x0378, .end = 0x0379 },
    .{ .start = 0x0380, .end = 0x0383 },
    .{ .start = 0xFDD0, .end = 0xFDEF },
    .{ .start = 0xFFFE, .end = 0xFFFF },
    .{ .start = 0xFFFFE, .end = 0xFFFFF },
    .{ .start = 0x10FFFE, .end = 0x10FFFF },
};

/// C: Other (Cc | Cf | Co | Cn)
pub const gc_C = [_]CodepointRange{
    .{ .start = 0x0000, .end = 0x001F },
    .{ .start = 0x007F, .end = 0x009F },
    .{ .start = 0x00AD, .end = 0x00AD },
    .{ .start = 0x0378, .end = 0x0379 }, .{ .start = 0x0380, .end = 0x0383 },
    .{ .start = 0x0600, .end = 0x0605 }, .{ .start = 0x061C, .end = 0x061C }, .{ .start = 0x06DD, .end = 0x06DD },
    .{ .start = 0x180E, .end = 0x180E },
    .{ .start = 0x200B, .end = 0x200F }, .{ .start = 0x202A, .end = 0x202E },
    .{ .start = 0x2060, .end = 0x206F },
    .{ .start = 0xE000, .end = 0xF8FF },
    .{ .start = 0xFDD0, .end = 0xFDEF },
    .{ .start = 0xFEFF, .end = 0xFEFF }, .{ .start = 0xFFF9, .end = 0xFFFB }, .{ .start = 0xFFFE, .end = 0xFFFF },
    .{ .start = 0xE0001, .end = 0xE007F },
    .{ .start = 0xF0000, .end = 0x10FFFF },
};

// ============================================================================
// Special Properties
// ============================================================================

pub const prop_ASCII = [_]CodepointRange{
    .{ .start = 0x0000, .end = 0x007F },
};

pub const prop_Any = [_]CodepointRange{
    .{ .start = 0x0000, .end = 0x10FFFF },
};

pub const prop_Emoji = [_]CodepointRange{
    .{ .start = 0x0023, .end = 0x0023 }, .{ .start = 0x002A, .end = 0x002A }, .{ .start = 0x0030, .end = 0x0039 },
    .{ .start = 0x00A9, .end = 0x00A9 }, .{ .start = 0x00AE, .end = 0x00AE },
    .{ .start = 0x203C, .end = 0x203C }, .{ .start = 0x2049, .end = 0x2049 },
    .{ .start = 0x2122, .end = 0x2122 }, .{ .start = 0x2139, .end = 0x2139 },
    .{ .start = 0x2194, .end = 0x2199 }, .{ .start = 0x21A9, .end = 0x21AA },
    .{ .start = 0x231A, .end = 0x231B }, .{ .start = 0x2328, .end = 0x2328 }, .{ .start = 0x23CF, .end = 0x23CF },
    .{ .start = 0x23E9, .end = 0x23F3 }, .{ .start = 0x23F8, .end = 0x23FA },
    .{ .start = 0x24C2, .end = 0x24C2 },
    .{ .start = 0x25AA, .end = 0x25AB }, .{ .start = 0x25B6, .end = 0x25B6 }, .{ .start = 0x25C0, .end = 0x25C0 },
    .{ .start = 0x25FB, .end = 0x25FE },
    .{ .start = 0x2600, .end = 0x27BF },
    .{ .start = 0x2934, .end = 0x2935 },
    .{ .start = 0x2B05, .end = 0x2B07 }, .{ .start = 0x2B1B, .end = 0x2B1C }, .{ .start = 0x2B50, .end = 0x2B50 },
    .{ .start = 0x2B55, .end = 0x2B55 },
    .{ .start = 0x3030, .end = 0x3030 }, .{ .start = 0x303D, .end = 0x303D },
    .{ .start = 0x3297, .end = 0x3297 }, .{ .start = 0x3299, .end = 0x3299 },
    .{ .start = 0x1F000, .end = 0x1FAFF },
};

// ============================================================================
// Script Ranges
// ============================================================================

/// Script=Han (Hani)
pub const sc_Han = [_]CodepointRange{
    .{ .start = 0x2E80, .end = 0x2E99 }, .{ .start = 0x2E9B, .end = 0x2EF3 },
    .{ .start = 0x2F00, .end = 0x2FD5 },
    .{ .start = 0x3005, .end = 0x3005 }, .{ .start = 0x3007, .end = 0x3007 },
    .{ .start = 0x3021, .end = 0x3029 }, .{ .start = 0x3038, .end = 0x303B },
    .{ .start = 0x3400, .end = 0x4DBF },
    .{ .start = 0x4E00, .end = 0x9FFF },
    .{ .start = 0xF900, .end = 0xFA6D }, .{ .start = 0xFA70, .end = 0xFAD9 },
    .{ .start = 0x16FE2, .end = 0x16FE3 },
    .{ .start = 0x20000, .end = 0x2A6DF },
    .{ .start = 0x2A700, .end = 0x2B739 },
    .{ .start = 0x2B740, .end = 0x2B81D },
    .{ .start = 0x2B820, .end = 0x2CEA1 },
    .{ .start = 0x2CEB0, .end = 0x2EBE0 },
    .{ .start = 0x2F800, .end = 0x2FA1D },
    .{ .start = 0x30000, .end = 0x323AF },
};

/// Script=Hiragana (Hira)
pub const sc_Hiragana = [_]CodepointRange{
    .{ .start = 0x3041, .end = 0x3096 },
    .{ .start = 0x309D, .end = 0x309F },
    .{ .start = 0x1B001, .end = 0x1B11F },
    .{ .start = 0x1B132, .end = 0x1B132 }, .{ .start = 0x1B150, .end = 0x1B152 },
    .{ .start = 0x1F200, .end = 0x1F200 },
};

/// Script=Katakana (Kana)
pub const sc_Katakana = [_]CodepointRange{
    .{ .start = 0x30A1, .end = 0x30FA },
    .{ .start = 0x30FD, .end = 0x30FF },
    .{ .start = 0x31F0, .end = 0x31FF },
    .{ .start = 0x32D0, .end = 0x32FE },
    .{ .start = 0x3300, .end = 0x3357 },
    .{ .start = 0xFF66, .end = 0xFF6F },
    .{ .start = 0xFF71, .end = 0xFF9D },
    .{ .start = 0x1B000, .end = 0x1B000 },
    .{ .start = 0x1B120, .end = 0x1B122 }, .{ .start = 0x1B155, .end = 0x1B155 }, .{ .start = 0x1B164, .end = 0x1B167 },
};

/// Script=Hangul (Hang)
pub const sc_Hangul = [_]CodepointRange{
    .{ .start = 0x1100, .end = 0x11FF },
    .{ .start = 0x302E, .end = 0x302F },
    .{ .start = 0x3131, .end = 0x318E },
    .{ .start = 0x3200, .end = 0x321E },
    .{ .start = 0x3260, .end = 0x327E },
    .{ .start = 0xA960, .end = 0xA97C },
    .{ .start = 0xAC00, .end = 0xD7A3 },
    .{ .start = 0xD7B0, .end = 0xD7C6 },
    .{ .start = 0xD7CB, .end = 0xD7FB },
    .{ .start = 0xFFA0, .end = 0xFFBE },
    .{ .start = 0xFFC2, .end = 0xFFC7 },
    .{ .start = 0xFFCA, .end = 0xFFCF },
    .{ .start = 0xFFD2, .end = 0xFFD7 },
    .{ .start = 0xFFDA, .end = 0xFFDC },
};

/// Script=Cyrillic (Cyrl)
pub const sc_Cyrillic = [_]CodepointRange{
    .{ .start = 0x0400, .end = 0x0484 },
    .{ .start = 0x0487, .end = 0x052F },
    .{ .start = 0x1C80, .end = 0x1C88 },
    .{ .start = 0x1D2B, .end = 0x1D2B }, .{ .start = 0x1D78, .end = 0x1D78 },
    .{ .start = 0x2DE0, .end = 0x2DFF },
    .{ .start = 0xA640, .end = 0xA69F },
    .{ .start = 0xFE2E, .end = 0xFE2F },
};

/// Script=Greek (Grek)
pub const sc_Greek = [_]CodepointRange{
    .{ .start = 0x0370, .end = 0x0373 }, .{ .start = 0x0375, .end = 0x0377 },
    .{ .start = 0x037A, .end = 0x037D }, .{ .start = 0x037F, .end = 0x037F },
    .{ .start = 0x0384, .end = 0x038A }, .{ .start = 0x038C, .end = 0x038C },
    .{ .start = 0x038E, .end = 0x03A1 }, .{ .start = 0x03A3, .end = 0x03E1 },
    .{ .start = 0x03F0, .end = 0x03FF },
    .{ .start = 0x1D26, .end = 0x1D2A }, .{ .start = 0x1D5D, .end = 0x1D61 },
    .{ .start = 0x1D66, .end = 0x1D6A }, .{ .start = 0x1DBF, .end = 0x1DBF },
    .{ .start = 0x1F00, .end = 0x1F15 }, .{ .start = 0x1F18, .end = 0x1F1D },
    .{ .start = 0x1F20, .end = 0x1F45 }, .{ .start = 0x1F48, .end = 0x1F4D },
    .{ .start = 0x1F50, .end = 0x1F57 }, .{ .start = 0x1F59, .end = 0x1F5F },
    .{ .start = 0x1F60, .end = 0x1F7D }, .{ .start = 0x1F80, .end = 0x1FB4 },
    .{ .start = 0x1FB6, .end = 0x1FC4 }, .{ .start = 0x1FC6, .end = 0x1FD3 },
    .{ .start = 0x1FD6, .end = 0x1FDB }, .{ .start = 0x1FDD, .end = 0x1FEF },
    .{ .start = 0x1FF2, .end = 0x1FF4 }, .{ .start = 0x1FF6, .end = 0x1FFE },
    .{ .start = 0x2126, .end = 0x2126 },
};

/// Script=Latin (Latn)
pub const sc_Latin = [_]CodepointRange{
    .{ .start = 0x0041, .end = 0x005A },
    .{ .start = 0x0061, .end = 0x007A },
    .{ .start = 0x00AA, .end = 0x00AA }, .{ .start = 0x00BA, .end = 0x00BA },
    .{ .start = 0x00C0, .end = 0x00D6 }, .{ .start = 0x00D8, .end = 0x00F6 },
    .{ .start = 0x00F8, .end = 0x02B8 },
    .{ .start = 0x02E0, .end = 0x02E4 },
    .{ .start = 0x1D00, .end = 0x1D25 }, .{ .start = 0x1D2C, .end = 0x1D5C },
    .{ .start = 0x1D62, .end = 0x1D65 }, .{ .start = 0x1D6B, .end = 0x1D77 },
    .{ .start = 0x1D79, .end = 0x1DBE },
    .{ .start = 0x1E00, .end = 0x1EFF },
    .{ .start = 0x2071, .end = 0x2071 }, .{ .start = 0x207F, .end = 0x207F },
    .{ .start = 0x2090, .end = 0x209C },
    .{ .start = 0x212A, .end = 0x212B }, .{ .start = 0x2132, .end = 0x2132 },
    .{ .start = 0x214E, .end = 0x214E }, .{ .start = 0x2160, .end = 0x2188 },
    .{ .start = 0x2C60, .end = 0x2C7F },
    .{ .start = 0xA722, .end = 0xA787 }, .{ .start = 0xA78B, .end = 0xA7FF },
    .{ .start = 0xAB30, .end = 0xAB5A }, .{ .start = 0xAB5C, .end = 0xAB64 },
    .{ .start = 0xFB00, .end = 0xFB06 },
    .{ .start = 0xFF21, .end = 0xFF3A }, .{ .start = 0xFF41, .end = 0xFF5A },
};

/// Script=Arabic (Arab)
pub const sc_Arabic = [_]CodepointRange{
    .{ .start = 0x0600, .end = 0x0604 }, .{ .start = 0x0606, .end = 0x060B },
    .{ .start = 0x060D, .end = 0x061A }, .{ .start = 0x061C, .end = 0x061E },
    .{ .start = 0x0620, .end = 0x063F }, .{ .start = 0x0641, .end = 0x064A },
    .{ .start = 0x0656, .end = 0x066F }, .{ .start = 0x0671, .end = 0x06DC },
    .{ .start = 0x06DE, .end = 0x06FF },
    .{ .start = 0x0750, .end = 0x077F },
    .{ .start = 0x08A0, .end = 0x08FF },
    .{ .start = 0xFB50, .end = 0xFBC2 }, .{ .start = 0xFBD3, .end = 0xFD3D },
    .{ .start = 0xFD50, .end = 0xFD8F }, .{ .start = 0xFD92, .end = 0xFDC7 },
    .{ .start = 0xFDF0, .end = 0xFDFD },
    .{ .start = 0xFE70, .end = 0xFE74 }, .{ .start = 0xFE76, .end = 0xFEFC },
};

/// Script=Hebrew (Hebr)
pub const sc_Hebrew = [_]CodepointRange{
    .{ .start = 0x0591, .end = 0x05C7 },
    .{ .start = 0x05D0, .end = 0x05EA },
    .{ .start = 0x05EF, .end = 0x05F4 },
    .{ .start = 0xFB1D, .end = 0xFB36 },
    .{ .start = 0xFB38, .end = 0xFB3C },
    .{ .start = 0xFB3E, .end = 0xFB3E },
    .{ .start = 0xFB40, .end = 0xFB41 },
    .{ .start = 0xFB43, .end = 0xFB44 },
    .{ .start = 0xFB46, .end = 0xFB4F },
};

/// Script=Devanagari (Deva)
pub const sc_Devanagari = [_]CodepointRange{
    .{ .start = 0x0900, .end = 0x0950 },
    .{ .start = 0x0955, .end = 0x0963 },
    .{ .start = 0x0966, .end = 0x097F },
    .{ .start = 0xA8E0, .end = 0xA8FF },
};

/// Script=Thai
pub const sc_Thai = [_]CodepointRange{
    .{ .start = 0x0E01, .end = 0x0E3A },
    .{ .start = 0x0E40, .end = 0x0E5B },
};

// ============================================================================
// UTS #18 Property Name Normalization & Lookup
// ============================================================================

fn normalizeName(raw: []const u8, buf: *[64]u8) ?[]const u8 {
    var len: usize = 0;
    for (raw) |c| {
        if (c == ' ' or c == '\t' or c == '\r' or c == '\n' or c == '-' or c == '_') continue;
        if (len >= buf.len) return null;
        buf[len] = std.ascii.toLower(c);
        len += 1;
    }
    return buf[0..len];
}

/// Resolves a Unicode property name or `key=value` expression under UTS #18 loose matching rules.
pub fn lookupProperty(raw_name: []const u8) ?PropertySpec {
    var value_part = raw_name;
    var prefix_kind: enum { any, gc, sc } = .any;

    if (std.mem.findAny(u8, raw_name, "=:")) |sep_idx| {
        var key_buf: [64]u8 = undefined;
        const key_norm = normalizeName(raw_name[0..sep_idx], &key_buf) orelse return null;
        if (std.mem.eql(u8, key_norm, "gc") or std.mem.eql(u8, key_norm, "generalcategory")) {
            prefix_kind = .gc;
        } else if (std.mem.eql(u8, key_norm, "sc") or std.mem.eql(u8, key_norm, "script") or std.mem.eql(u8, key_norm, "scx") or std.mem.eql(u8, key_norm, "scriptextensions")) {
            prefix_kind = .sc;
        } else {
            return null;
        }
        value_part = raw_name[sep_idx + 1 ..];
    }

    var norm_buf: [64]u8 = undefined;
    var norm = normalizeName(value_part, &norm_buf) orelse return null;
    if (norm.len == 0) return null;

    if (lookupNormalized(norm, prefix_kind)) |spec| return spec;
    if (prefix_kind == .any and norm.len > 2 and std.mem.startsWith(u8, norm, "is")) {
        if (lookupNormalized(norm[2..], .any)) |spec| return spec;
    }
    return null;
}

const gc_prop_map = std.StaticStringMap(PropertySpec).initComptime(.{
    // Letters
    .{ "l", PropertySpec{ .ranges = &gc_L } },
    .{ "letter", PropertySpec{ .ranges = &gc_L } },
    .{ "alpha", PropertySpec{ .ranges = &gc_L } },
    .{ "alphabetic", PropertySpec{ .ranges = &gc_L } },
    .{ "lu", PropertySpec{ .ranges = &gc_Lu, .is_cased_subcat = true } },
    .{ "uppercaseletter", PropertySpec{ .ranges = &gc_Lu, .is_cased_subcat = true } },
    .{ "upper", PropertySpec{ .ranges = &gc_Lu, .is_cased_subcat = true } },
    .{ "uppercase", PropertySpec{ .ranges = &gc_Lu, .is_cased_subcat = true } },
    .{ "ll", PropertySpec{ .ranges = &gc_Ll, .is_cased_subcat = true } },
    .{ "lowercaseletter", PropertySpec{ .ranges = &gc_Ll, .is_cased_subcat = true } },
    .{ "lower", PropertySpec{ .ranges = &gc_Ll, .is_cased_subcat = true } },
    .{ "lowercase", PropertySpec{ .ranges = &gc_Ll, .is_cased_subcat = true } },
    .{ "lt", PropertySpec{ .ranges = &gc_Lt, .is_cased_subcat = true } },
    .{ "titlecaseletter", PropertySpec{ .ranges = &gc_Lt, .is_cased_subcat = true } },
    .{ "lc", PropertySpec{ .ranges = &gc_LC } },
    .{ "casedletter", PropertySpec{ .ranges = &gc_LC } },
    .{ "lm", PropertySpec{ .ranges = &gc_Lm } },
    .{ "modifierletter", PropertySpec{ .ranges = &gc_Lm } },
    .{ "lo", PropertySpec{ .ranges = &gc_Lo } },
    .{ "otherletter", PropertySpec{ .ranges = &gc_Lo } },

    // Marks
    .{ "m", PropertySpec{ .ranges = &gc_M } },
    .{ "mark", PropertySpec{ .ranges = &gc_M } },
    .{ "combiningmark", PropertySpec{ .ranges = &gc_M } },
    .{ "mn", PropertySpec{ .ranges = &gc_Mn } },
    .{ "nonspacingmark", PropertySpec{ .ranges = &gc_Mn } },
    .{ "mc", PropertySpec{ .ranges = &gc_Mc } },
    .{ "spacingmark", PropertySpec{ .ranges = &gc_Mc } },
    .{ "me", PropertySpec{ .ranges = &gc_Me } },
    .{ "enclosingmark", PropertySpec{ .ranges = &gc_Me } },

    // Numbers
    .{ "n", PropertySpec{ .ranges = &gc_N } },
    .{ "number", PropertySpec{ .ranges = &gc_N } },
    .{ "nd", PropertySpec{ .ranges = &gc_Nd } },
    .{ "decimalnumber", PropertySpec{ .ranges = &gc_Nd } },
    .{ "digit", PropertySpec{ .ranges = &gc_Nd } },
    .{ "nl", PropertySpec{ .ranges = &gc_Nl } },
    .{ "letternumber", PropertySpec{ .ranges = &gc_Nl } },
    .{ "no", PropertySpec{ .ranges = &gc_No } },
    .{ "othernumber", PropertySpec{ .ranges = &gc_No } },

    // Punctuation
    .{ "p", PropertySpec{ .ranges = &gc_P } },
    .{ "punctuation", PropertySpec{ .ranges = &gc_P } },
    .{ "punct", PropertySpec{ .ranges = &gc_P } },
    .{ "pc", PropertySpec{ .ranges = &gc_Pc } },
    .{ "connectorpunctuation", PropertySpec{ .ranges = &gc_Pc } },
    .{ "pd", PropertySpec{ .ranges = &gc_Pd } },
    .{ "dashpunctuation", PropertySpec{ .ranges = &gc_Pd } },
    .{ "ps", PropertySpec{ .ranges = &gc_Ps } },
    .{ "openpunctuation", PropertySpec{ .ranges = &gc_Ps } },
    .{ "pe", PropertySpec{ .ranges = &gc_Pe } },
    .{ "closepunctuation", PropertySpec{ .ranges = &gc_Pe } },
    .{ "pi", PropertySpec{ .ranges = &gc_Pi } },
    .{ "initialpunctuation", PropertySpec{ .ranges = &gc_Pi } },
    .{ "pf", PropertySpec{ .ranges = &gc_Pf } },
    .{ "finalpunctuation", PropertySpec{ .ranges = &gc_Pf } },
    .{ "po", PropertySpec{ .ranges = &gc_Po } },
    .{ "otherpunctuation", PropertySpec{ .ranges = &gc_Po } },

    // Symbols
    .{ "s", PropertySpec{ .ranges = &gc_S } },
    .{ "symbol", PropertySpec{ .ranges = &gc_S } },
    .{ "sm", PropertySpec{ .ranges = &gc_Sm } },
    .{ "mathsymbol", PropertySpec{ .ranges = &gc_Sm } },
    .{ "sc", PropertySpec{ .ranges = &gc_Sc } },
    .{ "currencysymbol", PropertySpec{ .ranges = &gc_Sc } },
    .{ "sk", PropertySpec{ .ranges = &gc_Sk } },
    .{ "modifiersymbol", PropertySpec{ .ranges = &gc_Sk } },
    .{ "so", PropertySpec{ .ranges = &gc_So } },
    .{ "othersymbol", PropertySpec{ .ranges = &gc_So } },

    // Separators
    .{ "z", PropertySpec{ .ranges = &gc_Z } },
    .{ "separator", PropertySpec{ .ranges = &gc_Z } },
    .{ "space", PropertySpec{ .ranges = &gc_Z } },
    .{ "whitespace", PropertySpec{ .ranges = &gc_Z } },
    .{ "zs", PropertySpec{ .ranges = &gc_Zs } },
    .{ "spaceseparator", PropertySpec{ .ranges = &gc_Zs } },
    .{ "zl", PropertySpec{ .ranges = &gc_Zl } },
    .{ "lineseparator", PropertySpec{ .ranges = &gc_Zl } },
    .{ "zp", PropertySpec{ .ranges = &gc_Zp } },
    .{ "paragraphseparator", PropertySpec{ .ranges = &gc_Zp } },

    // Other / Control
    .{ "c", PropertySpec{ .ranges = &gc_C } },
    .{ "other", PropertySpec{ .ranges = &gc_C } },
    .{ "cc", PropertySpec{ .ranges = &gc_Cc } },
    .{ "control", PropertySpec{ .ranges = &gc_Cc } },
    .{ "cntrl", PropertySpec{ .ranges = &gc_Cc } },
    .{ "cf", PropertySpec{ .ranges = &gc_Cf } },
    .{ "format", PropertySpec{ .ranges = &gc_Cf } },
    .{ "co", PropertySpec{ .ranges = &gc_Co } },
    .{ "privateuse", PropertySpec{ .ranges = &gc_Co } },
    .{ "cn", PropertySpec{ .ranges = &gc_Cn } },
    .{ "unassigned", PropertySpec{ .ranges = &gc_Cn } },
});

const any_prop_map = std.StaticStringMap(PropertySpec).initComptime(.{
    .{ "ascii", PropertySpec{ .ranges = &prop_ASCII } },
    .{ "any", PropertySpec{ .ranges = &prop_Any } },
    .{ "assigned", PropertySpec{ .ranges = &prop_Any } },
    .{ "emoji", PropertySpec{ .ranges = &prop_Emoji } },
    .{ "emojipresentation", PropertySpec{ .ranges = &prop_Emoji } },
    .{ "extendedpictographic", PropertySpec{ .ranges = &prop_Emoji } },
    .{ "whitespace", PropertySpec{ .ranges = &prop_Whitespace } },
    .{ "wspace", PropertySpec{ .ranges = &prop_Whitespace } },
    .{ "space", PropertySpec{ .ranges = &prop_Whitespace } },
});

const sc_prop_map = std.StaticStringMap(PropertySpec).initComptime(.{
    .{ "han", PropertySpec{ .ranges = &sc_Han } },
    .{ "hani", PropertySpec{ .ranges = &sc_Han } },
    .{ "hiragana", PropertySpec{ .ranges = &sc_Hiragana } },
    .{ "hira", PropertySpec{ .ranges = &sc_Hiragana } },
    .{ "katakana", PropertySpec{ .ranges = &sc_Katakana } },
    .{ "kana", PropertySpec{ .ranges = &sc_Katakana } },
    .{ "hangul", PropertySpec{ .ranges = &sc_Hangul } },
    .{ "hang", PropertySpec{ .ranges = &sc_Hangul } },
    .{ "cyrillic", PropertySpec{ .ranges = &sc_Cyrillic } },
    .{ "cyrl", PropertySpec{ .ranges = &sc_Cyrillic } },
    .{ "greek", PropertySpec{ .ranges = &sc_Greek } },
    .{ "grek", PropertySpec{ .ranges = &sc_Greek } },
    .{ "latin", PropertySpec{ .ranges = &sc_Latin } },
    .{ "latn", PropertySpec{ .ranges = &sc_Latin } },
    .{ "arabic", PropertySpec{ .ranges = &sc_Arabic } },
    .{ "arab", PropertySpec{ .ranges = &sc_Arabic } },
    .{ "hebrew", PropertySpec{ .ranges = &sc_Hebrew } },
    .{ "hebr", PropertySpec{ .ranges = &sc_Hebrew } },
    .{ "devanagari", PropertySpec{ .ranges = &sc_Devanagari } },
    .{ "deva", PropertySpec{ .ranges = &sc_Devanagari } },
    .{ "thai", PropertySpec{ .ranges = &sc_Thai } },
});

fn lookupNormalized(norm: []const u8, prefix_kind: anytype) ?PropertySpec {
    if (prefix_kind == .any or prefix_kind == .gc) {
        if (gc_prop_map.get(norm)) |spec| return spec;
    }

    if (prefix_kind == .any) {
        if (any_prop_map.get(norm)) |spec| return spec;
    }

    if (prefix_kind == .any or prefix_kind == .sc) {
        if (sc_prop_map.get(norm)) |spec| return spec;
    }

    return null;
}

/// Unicode White_Space property (25 codepoints in 11 sorted ranges).
pub const prop_Whitespace = [_]CodepointRange{
    .{ .start = 0x0009, .end = 0x000D },
    .{ .start = 0x0020, .end = 0x0020 },
    .{ .start = 0x0085, .end = 0x0085 },
    .{ .start = 0x00A0, .end = 0x00A0 },
    .{ .start = 0x1680, .end = 0x1680 },
    .{ .start = 0x2000, .end = 0x200A },
    .{ .start = 0x2028, .end = 0x2029 },
    .{ .start = 0x202F, .end = 0x202F },
    .{ .start = 0x205F, .end = 0x205F },
    .{ .start = 0x3000, .end = 0x3000 },
};

/// UTS #18 Unicode Word (`\w`): `Alphabetic | M | Nd | Pc | Join_Control` (Unicode 16.0, 796 sorted ranges).
pub const prop_Word = [_]CodepointRange{
    .{ .start = 0x0030, .end = 0x0039 }, .{ .start = 0x0041, .end = 0x005A }, .{ .start = 0x005F, .end = 0x005F }, .{ .start = 0x0061, .end = 0x007A },
    .{ .start = 0x00AA, .end = 0x00AA }, .{ .start = 0x00B5, .end = 0x00B5 }, .{ .start = 0x00BA, .end = 0x00BA }, .{ .start = 0x00C0, .end = 0x00D6 },
    .{ .start = 0x00D8, .end = 0x00F6 }, .{ .start = 0x00F8, .end = 0x02C1 }, .{ .start = 0x02C6, .end = 0x02D1 }, .{ .start = 0x02E0, .end = 0x02E4 },
    .{ .start = 0x02EC, .end = 0x02EC }, .{ .start = 0x02EE, .end = 0x02EE }, .{ .start = 0x0300, .end = 0x0374 }, .{ .start = 0x0376, .end = 0x0377 },
    .{ .start = 0x037A, .end = 0x037D }, .{ .start = 0x037F, .end = 0x037F }, .{ .start = 0x0386, .end = 0x0386 }, .{ .start = 0x0388, .end = 0x038A },
    .{ .start = 0x038C, .end = 0x038C }, .{ .start = 0x038E, .end = 0x03A1 }, .{ .start = 0x03A3, .end = 0x03F5 }, .{ .start = 0x03F7, .end = 0x0481 },
    .{ .start = 0x0483, .end = 0x052F }, .{ .start = 0x0531, .end = 0x0556 }, .{ .start = 0x0559, .end = 0x0559 }, .{ .start = 0x0560, .end = 0x0588 },
    .{ .start = 0x0591, .end = 0x05BD }, .{ .start = 0x05BF, .end = 0x05BF }, .{ .start = 0x05C1, .end = 0x05C2 }, .{ .start = 0x05C4, .end = 0x05C5 },
    .{ .start = 0x05C7, .end = 0x05C7 }, .{ .start = 0x05D0, .end = 0x05EA }, .{ .start = 0x05EF, .end = 0x05F2 }, .{ .start = 0x0610, .end = 0x061A },
    .{ .start = 0x0620, .end = 0x0669 }, .{ .start = 0x066E, .end = 0x06D3 }, .{ .start = 0x06D5, .end = 0x06DC }, .{ .start = 0x06DF, .end = 0x06E8 },
    .{ .start = 0x06EA, .end = 0x06FC }, .{ .start = 0x06FF, .end = 0x06FF }, .{ .start = 0x0710, .end = 0x074A }, .{ .start = 0x074D, .end = 0x07B1 },
    .{ .start = 0x07C0, .end = 0x07F5 }, .{ .start = 0x07FA, .end = 0x07FA }, .{ .start = 0x07FD, .end = 0x07FD }, .{ .start = 0x0800, .end = 0x082D },
    .{ .start = 0x0840, .end = 0x085B }, .{ .start = 0x0860, .end = 0x086A }, .{ .start = 0x0870, .end = 0x0887 }, .{ .start = 0x0889, .end = 0x088E },
    .{ .start = 0x0897, .end = 0x08E1 }, .{ .start = 0x08E3, .end = 0x0963 }, .{ .start = 0x0966, .end = 0x096F }, .{ .start = 0x0971, .end = 0x0983 },
    .{ .start = 0x0985, .end = 0x098C }, .{ .start = 0x098F, .end = 0x0990 }, .{ .start = 0x0993, .end = 0x09A8 }, .{ .start = 0x09AA, .end = 0x09B0 },
    .{ .start = 0x09B2, .end = 0x09B2 }, .{ .start = 0x09B6, .end = 0x09B9 }, .{ .start = 0x09BC, .end = 0x09C4 }, .{ .start = 0x09C7, .end = 0x09C8 },
    .{ .start = 0x09CB, .end = 0x09CE }, .{ .start = 0x09D7, .end = 0x09D7 }, .{ .start = 0x09DC, .end = 0x09DD }, .{ .start = 0x09DF, .end = 0x09E3 },
    .{ .start = 0x09E6, .end = 0x09F1 }, .{ .start = 0x09FC, .end = 0x09FC }, .{ .start = 0x09FE, .end = 0x09FE }, .{ .start = 0x0A01, .end = 0x0A03 },
    .{ .start = 0x0A05, .end = 0x0A0A }, .{ .start = 0x0A0F, .end = 0x0A10 }, .{ .start = 0x0A13, .end = 0x0A28 }, .{ .start = 0x0A2A, .end = 0x0A30 },
    .{ .start = 0x0A32, .end = 0x0A33 }, .{ .start = 0x0A35, .end = 0x0A36 }, .{ .start = 0x0A38, .end = 0x0A39 }, .{ .start = 0x0A3C, .end = 0x0A3C },
    .{ .start = 0x0A3E, .end = 0x0A42 }, .{ .start = 0x0A47, .end = 0x0A48 }, .{ .start = 0x0A4B, .end = 0x0A4D }, .{ .start = 0x0A51, .end = 0x0A51 },
    .{ .start = 0x0A59, .end = 0x0A5C }, .{ .start = 0x0A5E, .end = 0x0A5E }, .{ .start = 0x0A66, .end = 0x0A75 }, .{ .start = 0x0A81, .end = 0x0A83 },
    .{ .start = 0x0A85, .end = 0x0A8D }, .{ .start = 0x0A8F, .end = 0x0A91 }, .{ .start = 0x0A93, .end = 0x0AA8 }, .{ .start = 0x0AAA, .end = 0x0AB0 },
    .{ .start = 0x0AB2, .end = 0x0AB3 }, .{ .start = 0x0AB5, .end = 0x0AB9 }, .{ .start = 0x0ABC, .end = 0x0AC5 }, .{ .start = 0x0AC7, .end = 0x0AC9 },
    .{ .start = 0x0ACB, .end = 0x0ACD }, .{ .start = 0x0AD0, .end = 0x0AD0 }, .{ .start = 0x0AE0, .end = 0x0AE3 }, .{ .start = 0x0AE6, .end = 0x0AEF },
    .{ .start = 0x0AF9, .end = 0x0AFF }, .{ .start = 0x0B01, .end = 0x0B03 }, .{ .start = 0x0B05, .end = 0x0B0C }, .{ .start = 0x0B0F, .end = 0x0B10 },
    .{ .start = 0x0B13, .end = 0x0B28 }, .{ .start = 0x0B2A, .end = 0x0B30 }, .{ .start = 0x0B32, .end = 0x0B33 }, .{ .start = 0x0B35, .end = 0x0B39 },
    .{ .start = 0x0B3C, .end = 0x0B44 }, .{ .start = 0x0B47, .end = 0x0B48 }, .{ .start = 0x0B4B, .end = 0x0B4D }, .{ .start = 0x0B55, .end = 0x0B57 },
    .{ .start = 0x0B5C, .end = 0x0B5D }, .{ .start = 0x0B5F, .end = 0x0B63 }, .{ .start = 0x0B66, .end = 0x0B6F }, .{ .start = 0x0B71, .end = 0x0B71 },
    .{ .start = 0x0B82, .end = 0x0B83 }, .{ .start = 0x0B85, .end = 0x0B8A }, .{ .start = 0x0B8E, .end = 0x0B90 }, .{ .start = 0x0B92, .end = 0x0B95 },
    .{ .start = 0x0B99, .end = 0x0B9A }, .{ .start = 0x0B9C, .end = 0x0B9C }, .{ .start = 0x0B9E, .end = 0x0B9F }, .{ .start = 0x0BA3, .end = 0x0BA4 },
    .{ .start = 0x0BA8, .end = 0x0BAA }, .{ .start = 0x0BAE, .end = 0x0BB9 }, .{ .start = 0x0BBE, .end = 0x0BC2 }, .{ .start = 0x0BC6, .end = 0x0BC8 },
    .{ .start = 0x0BCA, .end = 0x0BCD }, .{ .start = 0x0BD0, .end = 0x0BD0 }, .{ .start = 0x0BD7, .end = 0x0BD7 }, .{ .start = 0x0BE6, .end = 0x0BEF },
    .{ .start = 0x0C00, .end = 0x0C0C }, .{ .start = 0x0C0E, .end = 0x0C10 }, .{ .start = 0x0C12, .end = 0x0C28 }, .{ .start = 0x0C2A, .end = 0x0C39 },
    .{ .start = 0x0C3C, .end = 0x0C44 }, .{ .start = 0x0C46, .end = 0x0C48 }, .{ .start = 0x0C4A, .end = 0x0C4D }, .{ .start = 0x0C55, .end = 0x0C56 },
    .{ .start = 0x0C58, .end = 0x0C5A }, .{ .start = 0x0C5D, .end = 0x0C5D }, .{ .start = 0x0C60, .end = 0x0C63 }, .{ .start = 0x0C66, .end = 0x0C6F },
    .{ .start = 0x0C80, .end = 0x0C83 }, .{ .start = 0x0C85, .end = 0x0C8C }, .{ .start = 0x0C8E, .end = 0x0C90 }, .{ .start = 0x0C92, .end = 0x0CA8 },
    .{ .start = 0x0CAA, .end = 0x0CB3 }, .{ .start = 0x0CB5, .end = 0x0CB9 }, .{ .start = 0x0CBC, .end = 0x0CC4 }, .{ .start = 0x0CC6, .end = 0x0CC8 },
    .{ .start = 0x0CCA, .end = 0x0CCD }, .{ .start = 0x0CD5, .end = 0x0CD6 }, .{ .start = 0x0CDD, .end = 0x0CDE }, .{ .start = 0x0CE0, .end = 0x0CE3 },
    .{ .start = 0x0CE6, .end = 0x0CEF }, .{ .start = 0x0CF1, .end = 0x0CF3 }, .{ .start = 0x0D00, .end = 0x0D0C }, .{ .start = 0x0D0E, .end = 0x0D10 },
    .{ .start = 0x0D12, .end = 0x0D44 }, .{ .start = 0x0D46, .end = 0x0D48 }, .{ .start = 0x0D4A, .end = 0x0D4E }, .{ .start = 0x0D54, .end = 0x0D57 },
    .{ .start = 0x0D5F, .end = 0x0D63 }, .{ .start = 0x0D66, .end = 0x0D6F }, .{ .start = 0x0D7A, .end = 0x0D7F }, .{ .start = 0x0D81, .end = 0x0D83 },
    .{ .start = 0x0D85, .end = 0x0D96 }, .{ .start = 0x0D9A, .end = 0x0DB1 }, .{ .start = 0x0DB3, .end = 0x0DBB }, .{ .start = 0x0DBD, .end = 0x0DBD },
    .{ .start = 0x0DC0, .end = 0x0DC6 }, .{ .start = 0x0DCA, .end = 0x0DCA }, .{ .start = 0x0DCF, .end = 0x0DD4 }, .{ .start = 0x0DD6, .end = 0x0DD6 },
    .{ .start = 0x0DD8, .end = 0x0DDF }, .{ .start = 0x0DE6, .end = 0x0DEF }, .{ .start = 0x0DF2, .end = 0x0DF3 }, .{ .start = 0x0E01, .end = 0x0E3A },
    .{ .start = 0x0E40, .end = 0x0E4E }, .{ .start = 0x0E50, .end = 0x0E59 }, .{ .start = 0x0E81, .end = 0x0E82 }, .{ .start = 0x0E84, .end = 0x0E84 },
    .{ .start = 0x0E86, .end = 0x0E8A }, .{ .start = 0x0E8C, .end = 0x0EA3 }, .{ .start = 0x0EA5, .end = 0x0EA5 }, .{ .start = 0x0EA7, .end = 0x0EBD },
    .{ .start = 0x0EC0, .end = 0x0EC4 }, .{ .start = 0x0EC6, .end = 0x0EC6 }, .{ .start = 0x0EC8, .end = 0x0ECE }, .{ .start = 0x0ED0, .end = 0x0ED9 },
    .{ .start = 0x0EDC, .end = 0x0EDF }, .{ .start = 0x0F00, .end = 0x0F00 }, .{ .start = 0x0F18, .end = 0x0F19 }, .{ .start = 0x0F20, .end = 0x0F29 },
    .{ .start = 0x0F35, .end = 0x0F35 }, .{ .start = 0x0F37, .end = 0x0F37 }, .{ .start = 0x0F39, .end = 0x0F39 }, .{ .start = 0x0F3E, .end = 0x0F47 },
    .{ .start = 0x0F49, .end = 0x0F6C }, .{ .start = 0x0F71, .end = 0x0F84 }, .{ .start = 0x0F86, .end = 0x0F97 }, .{ .start = 0x0F99, .end = 0x0FBC },
    .{ .start = 0x0FC6, .end = 0x0FC6 }, .{ .start = 0x1000, .end = 0x1049 }, .{ .start = 0x1050, .end = 0x109D }, .{ .start = 0x10A0, .end = 0x10C5 },
    .{ .start = 0x10C7, .end = 0x10C7 }, .{ .start = 0x10CD, .end = 0x10CD }, .{ .start = 0x10D0, .end = 0x10FA }, .{ .start = 0x10FC, .end = 0x1248 },
    .{ .start = 0x124A, .end = 0x124D }, .{ .start = 0x1250, .end = 0x1256 }, .{ .start = 0x1258, .end = 0x1258 }, .{ .start = 0x125A, .end = 0x125D },
    .{ .start = 0x1260, .end = 0x1288 }, .{ .start = 0x128A, .end = 0x128D }, .{ .start = 0x1290, .end = 0x12B0 }, .{ .start = 0x12B2, .end = 0x12B5 },
    .{ .start = 0x12B8, .end = 0x12BE }, .{ .start = 0x12C0, .end = 0x12C0 }, .{ .start = 0x12C2, .end = 0x12C5 }, .{ .start = 0x12C8, .end = 0x12D6 },
    .{ .start = 0x12D8, .end = 0x1310 }, .{ .start = 0x1312, .end = 0x1315 }, .{ .start = 0x1318, .end = 0x135A }, .{ .start = 0x135D, .end = 0x135F },
    .{ .start = 0x1380, .end = 0x138F }, .{ .start = 0x13A0, .end = 0x13F5 }, .{ .start = 0x13F8, .end = 0x13FD }, .{ .start = 0x1401, .end = 0x166C },
    .{ .start = 0x166F, .end = 0x167F }, .{ .start = 0x1681, .end = 0x169A }, .{ .start = 0x16A0, .end = 0x16EA }, .{ .start = 0x16EE, .end = 0x16F8 },
    .{ .start = 0x1700, .end = 0x1715 }, .{ .start = 0x171F, .end = 0x1734 }, .{ .start = 0x1740, .end = 0x1753 }, .{ .start = 0x1760, .end = 0x176C },
    .{ .start = 0x176E, .end = 0x1770 }, .{ .start = 0x1772, .end = 0x1773 }, .{ .start = 0x1780, .end = 0x17D3 }, .{ .start = 0x17D7, .end = 0x17D7 },
    .{ .start = 0x17DC, .end = 0x17DD }, .{ .start = 0x17E0, .end = 0x17E9 }, .{ .start = 0x180B, .end = 0x180D }, .{ .start = 0x180F, .end = 0x1819 },
    .{ .start = 0x1820, .end = 0x1878 }, .{ .start = 0x1880, .end = 0x18AA }, .{ .start = 0x18B0, .end = 0x18F5 }, .{ .start = 0x1900, .end = 0x191E },
    .{ .start = 0x1920, .end = 0x192B }, .{ .start = 0x1930, .end = 0x193B }, .{ .start = 0x1946, .end = 0x196D }, .{ .start = 0x1970, .end = 0x1974 },
    .{ .start = 0x1980, .end = 0x19AB }, .{ .start = 0x19B0, .end = 0x19C9 }, .{ .start = 0x19D0, .end = 0x19D9 }, .{ .start = 0x1A00, .end = 0x1A1B },
    .{ .start = 0x1A20, .end = 0x1A5E }, .{ .start = 0x1A60, .end = 0x1A7C }, .{ .start = 0x1A7F, .end = 0x1A89 }, .{ .start = 0x1A90, .end = 0x1A99 },
    .{ .start = 0x1AA7, .end = 0x1AA7 }, .{ .start = 0x1AB0, .end = 0x1ACE }, .{ .start = 0x1B00, .end = 0x1B4C }, .{ .start = 0x1B50, .end = 0x1B59 },
    .{ .start = 0x1B6B, .end = 0x1B73 }, .{ .start = 0x1B80, .end = 0x1BF3 }, .{ .start = 0x1C00, .end = 0x1C37 }, .{ .start = 0x1C40, .end = 0x1C49 },
    .{ .start = 0x1C4D, .end = 0x1C7D }, .{ .start = 0x1C80, .end = 0x1C8A }, .{ .start = 0x1C90, .end = 0x1CBA }, .{ .start = 0x1CBD, .end = 0x1CBF },
    .{ .start = 0x1CD0, .end = 0x1CD2 }, .{ .start = 0x1CD4, .end = 0x1CFA }, .{ .start = 0x1D00, .end = 0x1F15 }, .{ .start = 0x1F18, .end = 0x1F1D },
    .{ .start = 0x1F20, .end = 0x1F45 }, .{ .start = 0x1F48, .end = 0x1F4D }, .{ .start = 0x1F50, .end = 0x1F57 }, .{ .start = 0x1F59, .end = 0x1F59 },
    .{ .start = 0x1F5B, .end = 0x1F5B }, .{ .start = 0x1F5D, .end = 0x1F5D }, .{ .start = 0x1F5F, .end = 0x1F7D }, .{ .start = 0x1F80, .end = 0x1FB4 },
    .{ .start = 0x1FB6, .end = 0x1FBC }, .{ .start = 0x1FBE, .end = 0x1FBE }, .{ .start = 0x1FC2, .end = 0x1FC4 }, .{ .start = 0x1FC6, .end = 0x1FCC },
    .{ .start = 0x1FD0, .end = 0x1FD3 }, .{ .start = 0x1FD6, .end = 0x1FDB }, .{ .start = 0x1FE0, .end = 0x1FEC }, .{ .start = 0x1FF2, .end = 0x1FF4 },
    .{ .start = 0x1FF6, .end = 0x1FFC }, .{ .start = 0x200C, .end = 0x200D }, .{ .start = 0x203F, .end = 0x2040 }, .{ .start = 0x2054, .end = 0x2054 },
    .{ .start = 0x2071, .end = 0x2071 }, .{ .start = 0x207F, .end = 0x207F }, .{ .start = 0x2090, .end = 0x209C }, .{ .start = 0x20D0, .end = 0x20F0 },
    .{ .start = 0x2102, .end = 0x2102 }, .{ .start = 0x2107, .end = 0x2107 }, .{ .start = 0x210A, .end = 0x2113 }, .{ .start = 0x2115, .end = 0x2115 },
    .{ .start = 0x2119, .end = 0x211D }, .{ .start = 0x2124, .end = 0x2124 }, .{ .start = 0x2126, .end = 0x2126 }, .{ .start = 0x2128, .end = 0x2128 },
    .{ .start = 0x212A, .end = 0x212D }, .{ .start = 0x212F, .end = 0x2139 }, .{ .start = 0x213C, .end = 0x213F }, .{ .start = 0x2145, .end = 0x2149 },
    .{ .start = 0x214E, .end = 0x214E }, .{ .start = 0x2160, .end = 0x2188 }, .{ .start = 0x24B6, .end = 0x24E9 }, .{ .start = 0x2C00, .end = 0x2CE4 },
    .{ .start = 0x2CEB, .end = 0x2CF3 }, .{ .start = 0x2D00, .end = 0x2D25 }, .{ .start = 0x2D27, .end = 0x2D27 }, .{ .start = 0x2D2D, .end = 0x2D2D },
    .{ .start = 0x2D30, .end = 0x2D67 }, .{ .start = 0x2D6F, .end = 0x2D6F }, .{ .start = 0x2D7F, .end = 0x2D96 }, .{ .start = 0x2DA0, .end = 0x2DA6 },
    .{ .start = 0x2DA8, .end = 0x2DAE }, .{ .start = 0x2DB0, .end = 0x2DB6 }, .{ .start = 0x2DB8, .end = 0x2DBE }, .{ .start = 0x2DC0, .end = 0x2DC6 },
    .{ .start = 0x2DC8, .end = 0x2DCE }, .{ .start = 0x2DD0, .end = 0x2DD6 }, .{ .start = 0x2DD8, .end = 0x2DDE }, .{ .start = 0x2DE0, .end = 0x2DFF },
    .{ .start = 0x2E2F, .end = 0x2E2F }, .{ .start = 0x3005, .end = 0x3007 }, .{ .start = 0x3021, .end = 0x302F }, .{ .start = 0x3031, .end = 0x3035 },
    .{ .start = 0x3038, .end = 0x303C }, .{ .start = 0x3041, .end = 0x3096 }, .{ .start = 0x3099, .end = 0x309A }, .{ .start = 0x309D, .end = 0x309F },
    .{ .start = 0x30A1, .end = 0x30FA }, .{ .start = 0x30FC, .end = 0x30FF }, .{ .start = 0x3105, .end = 0x312F }, .{ .start = 0x3131, .end = 0x318E },
    .{ .start = 0x31A0, .end = 0x31BF }, .{ .start = 0x31F0, .end = 0x31FF }, .{ .start = 0x3400, .end = 0x4DBF }, .{ .start = 0x4E00, .end = 0xA48C },
    .{ .start = 0xA4D0, .end = 0xA4FD }, .{ .start = 0xA500, .end = 0xA60C }, .{ .start = 0xA610, .end = 0xA62B }, .{ .start = 0xA640, .end = 0xA672 },
    .{ .start = 0xA674, .end = 0xA67D }, .{ .start = 0xA67F, .end = 0xA6F1 }, .{ .start = 0xA717, .end = 0xA71F }, .{ .start = 0xA722, .end = 0xA788 },
    .{ .start = 0xA78B, .end = 0xA7CD }, .{ .start = 0xA7D0, .end = 0xA7D1 }, .{ .start = 0xA7D3, .end = 0xA7D3 }, .{ .start = 0xA7D5, .end = 0xA7DC },
    .{ .start = 0xA7F2, .end = 0xA827 }, .{ .start = 0xA82C, .end = 0xA82C }, .{ .start = 0xA840, .end = 0xA873 }, .{ .start = 0xA880, .end = 0xA8C5 },
    .{ .start = 0xA8D0, .end = 0xA8D9 }, .{ .start = 0xA8E0, .end = 0xA8F7 }, .{ .start = 0xA8FB, .end = 0xA8FB }, .{ .start = 0xA8FD, .end = 0xA92D },
    .{ .start = 0xA930, .end = 0xA953 }, .{ .start = 0xA960, .end = 0xA97C }, .{ .start = 0xA980, .end = 0xA9C0 }, .{ .start = 0xA9CF, .end = 0xA9D9 },
    .{ .start = 0xA9E0, .end = 0xA9FE }, .{ .start = 0xAA00, .end = 0xAA36 }, .{ .start = 0xAA40, .end = 0xAA4D }, .{ .start = 0xAA50, .end = 0xAA59 },
    .{ .start = 0xAA60, .end = 0xAA76 }, .{ .start = 0xAA7A, .end = 0xAAC2 }, .{ .start = 0xAADB, .end = 0xAADD }, .{ .start = 0xAAE0, .end = 0xAAEF },
    .{ .start = 0xAAF2, .end = 0xAAF6 }, .{ .start = 0xAB01, .end = 0xAB06 }, .{ .start = 0xAB09, .end = 0xAB0E }, .{ .start = 0xAB11, .end = 0xAB16 },
    .{ .start = 0xAB20, .end = 0xAB26 }, .{ .start = 0xAB28, .end = 0xAB2E }, .{ .start = 0xAB30, .end = 0xAB5A }, .{ .start = 0xAB5C, .end = 0xAB69 },
    .{ .start = 0xAB70, .end = 0xABEA }, .{ .start = 0xABEC, .end = 0xABED }, .{ .start = 0xABF0, .end = 0xABF9 }, .{ .start = 0xAC00, .end = 0xD7A3 },
    .{ .start = 0xD7B0, .end = 0xD7C6 }, .{ .start = 0xD7CB, .end = 0xD7FB }, .{ .start = 0xF900, .end = 0xFA6D }, .{ .start = 0xFA70, .end = 0xFAD9 },
    .{ .start = 0xFB00, .end = 0xFB06 }, .{ .start = 0xFB13, .end = 0xFB17 }, .{ .start = 0xFB1D, .end = 0xFB28 }, .{ .start = 0xFB2A, .end = 0xFB36 },
    .{ .start = 0xFB38, .end = 0xFB3C }, .{ .start = 0xFB3E, .end = 0xFB3E }, .{ .start = 0xFB40, .end = 0xFB41 }, .{ .start = 0xFB43, .end = 0xFB44 },
    .{ .start = 0xFB46, .end = 0xFBB1 }, .{ .start = 0xFBD3, .end = 0xFD3D }, .{ .start = 0xFD50, .end = 0xFD8F }, .{ .start = 0xFD92, .end = 0xFDC7 },
    .{ .start = 0xFDF0, .end = 0xFDFB }, .{ .start = 0xFE00, .end = 0xFE0F }, .{ .start = 0xFE20, .end = 0xFE2F }, .{ .start = 0xFE33, .end = 0xFE34 },
    .{ .start = 0xFE4D, .end = 0xFE4F }, .{ .start = 0xFE70, .end = 0xFE74 }, .{ .start = 0xFE76, .end = 0xFEFC }, .{ .start = 0xFF10, .end = 0xFF19 },
    .{ .start = 0xFF21, .end = 0xFF3A }, .{ .start = 0xFF3F, .end = 0xFF3F }, .{ .start = 0xFF41, .end = 0xFF5A }, .{ .start = 0xFF66, .end = 0xFFBE },
    .{ .start = 0xFFC2, .end = 0xFFC7 }, .{ .start = 0xFFCA, .end = 0xFFCF }, .{ .start = 0xFFD2, .end = 0xFFD7 }, .{ .start = 0xFFDA, .end = 0xFFDC },
    .{ .start = 0x10000, .end = 0x1000B }, .{ .start = 0x1000D, .end = 0x10026 }, .{ .start = 0x10028, .end = 0x1003A }, .{ .start = 0x1003C, .end = 0x1003D },
    .{ .start = 0x1003F, .end = 0x1004D }, .{ .start = 0x10050, .end = 0x1005D }, .{ .start = 0x10080, .end = 0x100FA }, .{ .start = 0x10140, .end = 0x10174 },
    .{ .start = 0x101FD, .end = 0x101FD }, .{ .start = 0x10280, .end = 0x1029C }, .{ .start = 0x102A0, .end = 0x102D0 }, .{ .start = 0x102E0, .end = 0x102E0 },
    .{ .start = 0x10300, .end = 0x1031F }, .{ .start = 0x1032D, .end = 0x1034A }, .{ .start = 0x10350, .end = 0x1037A }, .{ .start = 0x10380, .end = 0x1039D },
    .{ .start = 0x103A0, .end = 0x103C3 }, .{ .start = 0x103C8, .end = 0x103CF }, .{ .start = 0x103D1, .end = 0x103D5 }, .{ .start = 0x10400, .end = 0x1049D },
    .{ .start = 0x104A0, .end = 0x104A9 }, .{ .start = 0x104B0, .end = 0x104D3 }, .{ .start = 0x104D8, .end = 0x104FB }, .{ .start = 0x10500, .end = 0x10527 },
    .{ .start = 0x10530, .end = 0x10563 }, .{ .start = 0x10570, .end = 0x1057A }, .{ .start = 0x1057C, .end = 0x1058A }, .{ .start = 0x1058C, .end = 0x10592 },
    .{ .start = 0x10594, .end = 0x10595 }, .{ .start = 0x10597, .end = 0x105A1 }, .{ .start = 0x105A3, .end = 0x105B1 }, .{ .start = 0x105B3, .end = 0x105B9 },
    .{ .start = 0x105BB, .end = 0x105BC }, .{ .start = 0x105C0, .end = 0x105F3 }, .{ .start = 0x10600, .end = 0x10736 }, .{ .start = 0x10740, .end = 0x10755 },
    .{ .start = 0x10760, .end = 0x10767 }, .{ .start = 0x10780, .end = 0x10785 }, .{ .start = 0x10787, .end = 0x107B0 }, .{ .start = 0x107B2, .end = 0x107BA },
    .{ .start = 0x10800, .end = 0x10805 }, .{ .start = 0x10808, .end = 0x10808 }, .{ .start = 0x1080A, .end = 0x10835 }, .{ .start = 0x10837, .end = 0x10838 },
    .{ .start = 0x1083C, .end = 0x1083C }, .{ .start = 0x1083F, .end = 0x10855 }, .{ .start = 0x10860, .end = 0x10876 }, .{ .start = 0x10880, .end = 0x1089E },
    .{ .start = 0x108E0, .end = 0x108F2 }, .{ .start = 0x108F4, .end = 0x108F5 }, .{ .start = 0x10900, .end = 0x10915 }, .{ .start = 0x10920, .end = 0x10939 },
    .{ .start = 0x10980, .end = 0x109B7 }, .{ .start = 0x109BE, .end = 0x109BF }, .{ .start = 0x10A00, .end = 0x10A03 }, .{ .start = 0x10A05, .end = 0x10A06 },
    .{ .start = 0x10A0C, .end = 0x10A13 }, .{ .start = 0x10A15, .end = 0x10A17 }, .{ .start = 0x10A19, .end = 0x10A35 }, .{ .start = 0x10A38, .end = 0x10A3A },
    .{ .start = 0x10A3F, .end = 0x10A3F }, .{ .start = 0x10A60, .end = 0x10A7C }, .{ .start = 0x10A80, .end = 0x10A9C }, .{ .start = 0x10AC0, .end = 0x10AC7 },
    .{ .start = 0x10AC9, .end = 0x10AE6 }, .{ .start = 0x10B00, .end = 0x10B35 }, .{ .start = 0x10B40, .end = 0x10B55 }, .{ .start = 0x10B60, .end = 0x10B72 },
    .{ .start = 0x10B80, .end = 0x10B91 }, .{ .start = 0x10C00, .end = 0x10C48 }, .{ .start = 0x10C80, .end = 0x10CB2 }, .{ .start = 0x10CC0, .end = 0x10CF2 },
    .{ .start = 0x10D00, .end = 0x10D27 }, .{ .start = 0x10D30, .end = 0x10D39 }, .{ .start = 0x10D40, .end = 0x10D65 }, .{ .start = 0x10D69, .end = 0x10D6D },
    .{ .start = 0x10D6F, .end = 0x10D85 }, .{ .start = 0x10E80, .end = 0x10EA9 }, .{ .start = 0x10EAB, .end = 0x10EAC }, .{ .start = 0x10EB0, .end = 0x10EB1 },
    .{ .start = 0x10EC2, .end = 0x10EC4 }, .{ .start = 0x10EFC, .end = 0x10F1C }, .{ .start = 0x10F27, .end = 0x10F27 }, .{ .start = 0x10F30, .end = 0x10F50 },
    .{ .start = 0x10F70, .end = 0x10F85 }, .{ .start = 0x10FB0, .end = 0x10FC4 }, .{ .start = 0x10FE0, .end = 0x10FF6 }, .{ .start = 0x11000, .end = 0x11046 },
    .{ .start = 0x11066, .end = 0x11075 }, .{ .start = 0x1107F, .end = 0x110BA }, .{ .start = 0x110C2, .end = 0x110C2 }, .{ .start = 0x110D0, .end = 0x110E8 },
    .{ .start = 0x110F0, .end = 0x110F9 }, .{ .start = 0x11100, .end = 0x11134 }, .{ .start = 0x11136, .end = 0x1113F }, .{ .start = 0x11144, .end = 0x11147 },
    .{ .start = 0x11150, .end = 0x11173 }, .{ .start = 0x11176, .end = 0x11176 }, .{ .start = 0x11180, .end = 0x111C4 }, .{ .start = 0x111C9, .end = 0x111CC },
    .{ .start = 0x111CE, .end = 0x111DA }, .{ .start = 0x111DC, .end = 0x111DC }, .{ .start = 0x11200, .end = 0x11211 }, .{ .start = 0x11213, .end = 0x11237 },
    .{ .start = 0x1123E, .end = 0x11241 }, .{ .start = 0x11280, .end = 0x11286 }, .{ .start = 0x11288, .end = 0x11288 }, .{ .start = 0x1128A, .end = 0x1128D },
    .{ .start = 0x1128F, .end = 0x1129D }, .{ .start = 0x1129F, .end = 0x112A8 }, .{ .start = 0x112B0, .end = 0x112EA }, .{ .start = 0x112F0, .end = 0x112F9 },
    .{ .start = 0x11300, .end = 0x11303 }, .{ .start = 0x11305, .end = 0x1130C }, .{ .start = 0x1130F, .end = 0x11310 }, .{ .start = 0x11313, .end = 0x11328 },
    .{ .start = 0x1132A, .end = 0x11330 }, .{ .start = 0x11332, .end = 0x11333 }, .{ .start = 0x11335, .end = 0x11339 }, .{ .start = 0x1133B, .end = 0x11344 },
    .{ .start = 0x11347, .end = 0x11348 }, .{ .start = 0x1134B, .end = 0x1134D }, .{ .start = 0x11350, .end = 0x11350 }, .{ .start = 0x11357, .end = 0x11357 },
    .{ .start = 0x1135D, .end = 0x11363 }, .{ .start = 0x11366, .end = 0x1136C }, .{ .start = 0x11370, .end = 0x11374 }, .{ .start = 0x11380, .end = 0x11389 },
    .{ .start = 0x1138B, .end = 0x1138B }, .{ .start = 0x1138E, .end = 0x1138E }, .{ .start = 0x11390, .end = 0x113B5 }, .{ .start = 0x113B7, .end = 0x113C0 },
    .{ .start = 0x113C2, .end = 0x113C2 }, .{ .start = 0x113C5, .end = 0x113C5 }, .{ .start = 0x113C7, .end = 0x113CA }, .{ .start = 0x113CC, .end = 0x113D3 },
    .{ .start = 0x113E1, .end = 0x113E2 }, .{ .start = 0x11400, .end = 0x1144A }, .{ .start = 0x11450, .end = 0x11459 }, .{ .start = 0x1145E, .end = 0x11461 },
    .{ .start = 0x11480, .end = 0x114C5 }, .{ .start = 0x114C7, .end = 0x114C7 }, .{ .start = 0x114D0, .end = 0x114D9 }, .{ .start = 0x11580, .end = 0x115B5 },
    .{ .start = 0x115B8, .end = 0x115C0 }, .{ .start = 0x115D8, .end = 0x115DD }, .{ .start = 0x11600, .end = 0x11640 }, .{ .start = 0x11644, .end = 0x11644 },
    .{ .start = 0x11650, .end = 0x11659 }, .{ .start = 0x11680, .end = 0x116B8 }, .{ .start = 0x116C0, .end = 0x116C9 }, .{ .start = 0x116D0, .end = 0x116E3 },
    .{ .start = 0x11700, .end = 0x1171A }, .{ .start = 0x1171D, .end = 0x1172B }, .{ .start = 0x11730, .end = 0x11739 }, .{ .start = 0x11740, .end = 0x11746 },
    .{ .start = 0x11800, .end = 0x1183A }, .{ .start = 0x118A0, .end = 0x118E9 }, .{ .start = 0x118FF, .end = 0x11906 }, .{ .start = 0x11909, .end = 0x11909 },
    .{ .start = 0x1190C, .end = 0x11913 }, .{ .start = 0x11915, .end = 0x11916 }, .{ .start = 0x11918, .end = 0x11935 }, .{ .start = 0x11937, .end = 0x11938 },
    .{ .start = 0x1193B, .end = 0x11943 }, .{ .start = 0x11950, .end = 0x11959 }, .{ .start = 0x119A0, .end = 0x119A7 }, .{ .start = 0x119AA, .end = 0x119D7 },
    .{ .start = 0x119DA, .end = 0x119E1 }, .{ .start = 0x119E3, .end = 0x119E4 }, .{ .start = 0x11A00, .end = 0x11A3E }, .{ .start = 0x11A47, .end = 0x11A47 },
    .{ .start = 0x11A50, .end = 0x11A99 }, .{ .start = 0x11A9D, .end = 0x11A9D }, .{ .start = 0x11AB0, .end = 0x11AF8 }, .{ .start = 0x11BC0, .end = 0x11BE0 },
    .{ .start = 0x11BF0, .end = 0x11BF9 }, .{ .start = 0x11C00, .end = 0x11C08 }, .{ .start = 0x11C0A, .end = 0x11C36 }, .{ .start = 0x11C38, .end = 0x11C40 },
    .{ .start = 0x11C50, .end = 0x11C59 }, .{ .start = 0x11C72, .end = 0x11C8F }, .{ .start = 0x11C92, .end = 0x11CA7 }, .{ .start = 0x11CA9, .end = 0x11CB6 },
    .{ .start = 0x11D00, .end = 0x11D06 }, .{ .start = 0x11D08, .end = 0x11D09 }, .{ .start = 0x11D0B, .end = 0x11D36 }, .{ .start = 0x11D3A, .end = 0x11D3A },
    .{ .start = 0x11D3C, .end = 0x11D3D }, .{ .start = 0x11D3F, .end = 0x11D47 }, .{ .start = 0x11D50, .end = 0x11D59 }, .{ .start = 0x11D60, .end = 0x11D65 },
    .{ .start = 0x11D67, .end = 0x11D68 }, .{ .start = 0x11D6A, .end = 0x11D8E }, .{ .start = 0x11D90, .end = 0x11D91 }, .{ .start = 0x11D93, .end = 0x11D98 },
    .{ .start = 0x11DA0, .end = 0x11DA9 }, .{ .start = 0x11EE0, .end = 0x11EF6 }, .{ .start = 0x11F00, .end = 0x11F10 }, .{ .start = 0x11F12, .end = 0x11F3A },
    .{ .start = 0x11F3E, .end = 0x11F42 }, .{ .start = 0x11F50, .end = 0x11F5A }, .{ .start = 0x11FB0, .end = 0x11FB0 }, .{ .start = 0x12000, .end = 0x12399 },
    .{ .start = 0x12400, .end = 0x1246E }, .{ .start = 0x12480, .end = 0x12543 }, .{ .start = 0x12F90, .end = 0x12FF0 }, .{ .start = 0x13000, .end = 0x1342F },
    .{ .start = 0x13440, .end = 0x13455 }, .{ .start = 0x13460, .end = 0x143FA }, .{ .start = 0x14400, .end = 0x14646 }, .{ .start = 0x16100, .end = 0x16139 },
    .{ .start = 0x16800, .end = 0x16A38 }, .{ .start = 0x16A40, .end = 0x16A5E }, .{ .start = 0x16A60, .end = 0x16A69 }, .{ .start = 0x16A70, .end = 0x16ABE },
    .{ .start = 0x16AC0, .end = 0x16AC9 }, .{ .start = 0x16AD0, .end = 0x16AED }, .{ .start = 0x16AF0, .end = 0x16AF4 }, .{ .start = 0x16B00, .end = 0x16B36 },
    .{ .start = 0x16B40, .end = 0x16B43 }, .{ .start = 0x16B50, .end = 0x16B59 }, .{ .start = 0x16B63, .end = 0x16B77 }, .{ .start = 0x16B7D, .end = 0x16B8F },
    .{ .start = 0x16D40, .end = 0x16D6C }, .{ .start = 0x16D70, .end = 0x16D79 }, .{ .start = 0x16E40, .end = 0x16E7F }, .{ .start = 0x16F00, .end = 0x16F4A },
    .{ .start = 0x16F4F, .end = 0x16F87 }, .{ .start = 0x16F8F, .end = 0x16F9F }, .{ .start = 0x16FE0, .end = 0x16FE1 }, .{ .start = 0x16FE3, .end = 0x16FE4 },
    .{ .start = 0x16FF0, .end = 0x16FF1 }, .{ .start = 0x17000, .end = 0x187F7 }, .{ .start = 0x18800, .end = 0x18CD5 }, .{ .start = 0x18CFF, .end = 0x18D08 },
    .{ .start = 0x1AFF0, .end = 0x1AFF3 }, .{ .start = 0x1AFF5, .end = 0x1AFFB }, .{ .start = 0x1AFFD, .end = 0x1AFFE }, .{ .start = 0x1B000, .end = 0x1B122 },
    .{ .start = 0x1B132, .end = 0x1B132 }, .{ .start = 0x1B150, .end = 0x1B152 }, .{ .start = 0x1B155, .end = 0x1B155 }, .{ .start = 0x1B164, .end = 0x1B167 },
    .{ .start = 0x1B170, .end = 0x1B2FB }, .{ .start = 0x1BC00, .end = 0x1BC6A }, .{ .start = 0x1BC70, .end = 0x1BC7C }, .{ .start = 0x1BC80, .end = 0x1BC88 },
    .{ .start = 0x1BC90, .end = 0x1BC99 }, .{ .start = 0x1BC9D, .end = 0x1BC9E }, .{ .start = 0x1CCF0, .end = 0x1CCF9 }, .{ .start = 0x1CF00, .end = 0x1CF2D },
    .{ .start = 0x1CF30, .end = 0x1CF46 }, .{ .start = 0x1D165, .end = 0x1D169 }, .{ .start = 0x1D16D, .end = 0x1D172 }, .{ .start = 0x1D17B, .end = 0x1D182 },
    .{ .start = 0x1D185, .end = 0x1D18B }, .{ .start = 0x1D1AA, .end = 0x1D1AD }, .{ .start = 0x1D242, .end = 0x1D244 }, .{ .start = 0x1D400, .end = 0x1D454 },
    .{ .start = 0x1D456, .end = 0x1D49C }, .{ .start = 0x1D49E, .end = 0x1D49F }, .{ .start = 0x1D4A2, .end = 0x1D4A2 }, .{ .start = 0x1D4A5, .end = 0x1D4A6 },
    .{ .start = 0x1D4A9, .end = 0x1D4AC }, .{ .start = 0x1D4AE, .end = 0x1D4B9 }, .{ .start = 0x1D4BB, .end = 0x1D4BB }, .{ .start = 0x1D4BD, .end = 0x1D4C3 },
    .{ .start = 0x1D4C5, .end = 0x1D505 }, .{ .start = 0x1D507, .end = 0x1D50A }, .{ .start = 0x1D50D, .end = 0x1D514 }, .{ .start = 0x1D516, .end = 0x1D51C },
    .{ .start = 0x1D51E, .end = 0x1D539 }, .{ .start = 0x1D53B, .end = 0x1D53E }, .{ .start = 0x1D540, .end = 0x1D544 }, .{ .start = 0x1D546, .end = 0x1D546 },
    .{ .start = 0x1D54A, .end = 0x1D550 }, .{ .start = 0x1D552, .end = 0x1D6A5 }, .{ .start = 0x1D6A8, .end = 0x1D6C0 }, .{ .start = 0x1D6C2, .end = 0x1D6DA },
    .{ .start = 0x1D6DC, .end = 0x1D6FA }, .{ .start = 0x1D6FC, .end = 0x1D714 }, .{ .start = 0x1D716, .end = 0x1D734 }, .{ .start = 0x1D736, .end = 0x1D74E },
    .{ .start = 0x1D750, .end = 0x1D76E }, .{ .start = 0x1D770, .end = 0x1D788 }, .{ .start = 0x1D78A, .end = 0x1D7A8 }, .{ .start = 0x1D7AA, .end = 0x1D7C2 },
    .{ .start = 0x1D7C4, .end = 0x1D7CB }, .{ .start = 0x1D7CE, .end = 0x1D7FF }, .{ .start = 0x1DA00, .end = 0x1DA36 }, .{ .start = 0x1DA3B, .end = 0x1DA6C },
    .{ .start = 0x1DA75, .end = 0x1DA75 }, .{ .start = 0x1DA84, .end = 0x1DA84 }, .{ .start = 0x1DA9B, .end = 0x1DA9F }, .{ .start = 0x1DAA1, .end = 0x1DAAF },
    .{ .start = 0x1DF00, .end = 0x1DF1E }, .{ .start = 0x1DF25, .end = 0x1DF2A }, .{ .start = 0x1E000, .end = 0x1E006 }, .{ .start = 0x1E008, .end = 0x1E018 },
    .{ .start = 0x1E01B, .end = 0x1E021 }, .{ .start = 0x1E023, .end = 0x1E024 }, .{ .start = 0x1E026, .end = 0x1E02A }, .{ .start = 0x1E030, .end = 0x1E06D },
    .{ .start = 0x1E08F, .end = 0x1E08F }, .{ .start = 0x1E100, .end = 0x1E12C }, .{ .start = 0x1E130, .end = 0x1E13D }, .{ .start = 0x1E140, .end = 0x1E149 },
    .{ .start = 0x1E14E, .end = 0x1E14E }, .{ .start = 0x1E290, .end = 0x1E2AE }, .{ .start = 0x1E2C0, .end = 0x1E2F9 }, .{ .start = 0x1E4D0, .end = 0x1E4F9 },
    .{ .start = 0x1E5D0, .end = 0x1E5FA }, .{ .start = 0x1E7E0, .end = 0x1E7E6 }, .{ .start = 0x1E7E8, .end = 0x1E7EB }, .{ .start = 0x1E7ED, .end = 0x1E7EE },
    .{ .start = 0x1E7F0, .end = 0x1E7FE }, .{ .start = 0x1E800, .end = 0x1E8C4 }, .{ .start = 0x1E8D0, .end = 0x1E8D6 }, .{ .start = 0x1E900, .end = 0x1E94B },
    .{ .start = 0x1E950, .end = 0x1E959 }, .{ .start = 0x1EE00, .end = 0x1EE03 }, .{ .start = 0x1EE05, .end = 0x1EE1F }, .{ .start = 0x1EE21, .end = 0x1EE22 },
    .{ .start = 0x1EE24, .end = 0x1EE24 }, .{ .start = 0x1EE27, .end = 0x1EE27 }, .{ .start = 0x1EE29, .end = 0x1EE32 }, .{ .start = 0x1EE34, .end = 0x1EE37 },
    .{ .start = 0x1EE39, .end = 0x1EE39 }, .{ .start = 0x1EE3B, .end = 0x1EE3B }, .{ .start = 0x1EE42, .end = 0x1EE42 }, .{ .start = 0x1EE47, .end = 0x1EE47 },
    .{ .start = 0x1EE49, .end = 0x1EE49 }, .{ .start = 0x1EE4B, .end = 0x1EE4B }, .{ .start = 0x1EE4D, .end = 0x1EE4F }, .{ .start = 0x1EE51, .end = 0x1EE52 },
    .{ .start = 0x1EE54, .end = 0x1EE54 }, .{ .start = 0x1EE57, .end = 0x1EE57 }, .{ .start = 0x1EE59, .end = 0x1EE59 }, .{ .start = 0x1EE5B, .end = 0x1EE5B },
    .{ .start = 0x1EE5D, .end = 0x1EE5D }, .{ .start = 0x1EE5F, .end = 0x1EE5F }, .{ .start = 0x1EE61, .end = 0x1EE62 }, .{ .start = 0x1EE64, .end = 0x1EE64 },
    .{ .start = 0x1EE67, .end = 0x1EE6A }, .{ .start = 0x1EE6C, .end = 0x1EE72 }, .{ .start = 0x1EE74, .end = 0x1EE77 }, .{ .start = 0x1EE79, .end = 0x1EE7C },
    .{ .start = 0x1EE7E, .end = 0x1EE7E }, .{ .start = 0x1EE80, .end = 0x1EE89 }, .{ .start = 0x1EE8B, .end = 0x1EE9B }, .{ .start = 0x1EEA1, .end = 0x1EEA3 },
    .{ .start = 0x1EEA5, .end = 0x1EEA9 }, .{ .start = 0x1EEAB, .end = 0x1EEBB }, .{ .start = 0x1F130, .end = 0x1F149 }, .{ .start = 0x1F150, .end = 0x1F169 },
    .{ .start = 0x1F170, .end = 0x1F189 }, .{ .start = 0x1FBF0, .end = 0x1FBF9 }, .{ .start = 0x20000, .end = 0x2A6DF }, .{ .start = 0x2A700, .end = 0x2B739 },
    .{ .start = 0x2B740, .end = 0x2B81D }, .{ .start = 0x2B820, .end = 0x2CEA1 }, .{ .start = 0x2CEB0, .end = 0x2EBE0 }, .{ .start = 0x2EBF0, .end = 0x2EE5D },
    .{ .start = 0x2F800, .end = 0x2FA1D }, .{ .start = 0x30000, .end = 0x3134A }, .{ .start = 0x31350, .end = 0x323AF }, .{ .start = 0xE0100, .end = 0xE01EF },
};

const ascii_word_lut: [128]bool = blk: {
    var lut: [128]bool = @splat(false);
    for ('0'..'9' + 1) |c| lut[c] = true;
    for ('A'..'Z' + 1) |c| lut[c] = true;
    for ('a'..'z' + 1) |c| lut[c] = true;
    lut['_'] = true;
    break :blk lut;
};

/// UAX #29 / UTS #18 Unicode Word character classification (`Alphabetic | M | Nd | Pc | Join_Control`).
pub fn isWordCodepoint(cp: u21) bool {
    if (cp < 0x80) return ascii_word_lut[@intCast(cp)];
    if (cp > 0x10FFFF) return false;
    return inRanges(cp, &prop_Word);
}

test "unicode_prop_table: sorted ranges and UTS #18 normalization" {
    try std.testing.expect(inRanges('A', lookupProperty("Lu").?.ranges));
    try std.testing.expect(inRanges('A', lookupProperty(" gc = Uppercase_Letter ").?.ranges));
    try std.testing.expect(inRanges('中', lookupProperty("sc=Han").?.ranges));
    try std.testing.expect(inRanges('あ', lookupProperty("Script=Hiragana").?.ranges));
    try std.testing.expect(inRanges('🚀', lookupProperty("Emoji").?.ranges));
    try std.testing.expect(inRanges('🚀', lookupProperty("So").?.ranges));
    try std.testing.expect(isWordCodepoint('中'));
    try std.testing.expect(isWordCodepoint(0x0301)); // combining acute accent
    try std.testing.expect(isWordCodepoint(0x203F)); // undertie (Pc)
    try std.testing.expect(!isWordCodepoint('🚀'));
    try std.testing.expect(!isWordCodepoint('。'));
    // UTS #18 \w excludes Other_Number (No) such as ², ½, ①
    try std.testing.expect(!isWordCodepoint(0x00B2)); // ²
    try std.testing.expect(!isWordCodepoint(0x00BD)); // ½
    try std.testing.expect(!isWordCodepoint(0x2460)); // ①
    // UTS #18 \w includes Join_Control and non-Latin/Indic/SE-Asian scripts
    try std.testing.expect(isWordCodepoint(0x200C)); // ZWNJ
    try std.testing.expect(isWordCodepoint(0x200D)); // ZWJ
    try std.testing.expect(isWordCodepoint(0x1000)); // Myanmar
    try std.testing.expect(isWordCodepoint(0x0C85)); // Kannada
    try std.testing.expect(isWordCodepoint(0x1780)); // Khmer
    try std.testing.expect(isWordCodepoint(0x0985)); // Bengali
    try std.testing.expect(isWordCodepoint(0x0B85)); // Tamil
    try std.testing.expect(isWordCodepoint(0x0C05)); // Telugu
    try std.testing.expect(isWordCodepoint(0x0D05)); // Malayalam
    try std.testing.expect(isWordCodepoint(0x0D85)); // Sinhala
    try std.testing.expect(isWordCodepoint(0x0E81)); // Lao
    try std.testing.expect(isWordCodepoint(0x0F40)); // Tibetan
    try std.testing.expect(isWordCodepoint(0x1200)); // Ethiopic
    // Verify prop_Word is strictly sorted and non-overlapping
    for (prop_Word, 0..) |r, idx| {
        try std.testing.expect(r.start <= r.end);
        if (idx > 0) try std.testing.expect(prop_Word[idx - 1].end < r.start);
    }
}
