//! [Module] finder/unicode_fold.zig
//! [Layer] Layer 2 — Pattern Matchers (Unicode Case Folding & Word Boundary Engine)
//! [Role] SIMD-prefiltered UTF-8 substring search, prefix equivalence, pattern variant expansion,
//!        and slice-level word boundary verification under Unicode Simple Case Folding.
//! [Invariants]
//!   1. Pure ASCII patterns without cross-ASCII folding codepoints (`k`/`K` with U+212A, `s`/`S` with U+017F)
//!      remain on the branchless ASCII SIMD fast path.
//!   2. Cross-byte-length equivalence pairs (such as `ß` [2 bytes] <-> `ẞ` [3 bytes]) return the actual matched
//!      haystack byte span rather than `pattern.len`.
//! [HotPath] `findFolded` -> `findNextLead` (`memchr.find` / `findEither` / `findAny`) -> `matchFoldedPrefix`.

const std = @import("std");
const memchr = @import("memchr.zig");
const case_table = @import("../tables/unicode_case_table.zig");

pub const FoldGroup = case_table.FoldGroup;
pub const isUpperCodepoint = case_table.isUpperCodepoint;
pub const foldEquivalents = case_table.foldEquivalents;
pub const toLowerSimple = case_table.toLowerSimple;
pub const toFoldedLower = case_table.toFoldedLower;
pub const isUnicodeWordCodepoint = case_table.isUnicodeWordCodepoint;

const Step = struct {
    cp: u21,
    len: usize,
};

fn nextCodepoint(bytes: []const u8, pos: usize) ?Step {
    if (pos >= bytes.len) return null;
    const b = bytes[pos];
    if (b < 0x80) return .{ .cp = b, .len = 1 };
    const seq_len = std.unicode.utf8ByteSequenceLength(b) catch {
        @branchHint(.cold);
        return .{ .cp = 0x110000 + @as(u21, b), .len = 1 };
    };
    if (pos + seq_len > bytes.len) {
        @branchHint(.cold);
        return .{ .cp = 0x110000 + @as(u21, b), .len = 1 };
    }
    const cp = std.unicode.utf8Decode(bytes[pos .. pos + seq_len]) catch {
        @branchHint(.cold);
        return .{ .cp = 0x110000 + @as(u21, b), .len = 1 };
    };
    return .{ .cp = cp, .len = seq_len };
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

/// Compares `a` and `b` for equality under Unicode Simple Case Folding without allocating.
pub fn eqlFolded(a: []const u8, b: []const u8) bool {
    var ia: usize = 0;
    var ib: usize = 0;
    while (ia < a.len and ib < b.len) {
        const sa = nextCodepoint(a, ia).?;
        const sb = nextCodepoint(b, ib).?;
        if (toLowerSimple(sa.cp) != toLowerSimple(sb.cp)) return false;
        ia += sa.len;
        ib += sb.len;
    }
    return ia == a.len and ib == b.len;
}

/// If `haystack` starts with a prefix equal to `pattern` under Unicode Simple Case Folding,
/// returns the matched byte length in `haystack` (which may differ from `pattern.len` for cross-byte-length pairs like `ß`/`ẞ`).
pub fn matchFoldedPrefix(pattern: []const u8, haystack: []const u8) ?usize {
    var ip: usize = 0;
    var ih: usize = 0;
    while (ip < pattern.len) {
        const sp = nextCodepoint(pattern, ip) orelse return null;
        const sh = nextCodepoint(haystack, ih) orelse return null;
        if (toLowerSimple(sp.cp) != toLowerSimple(sh.cp)) return null;
        ip += sp.len;
        ih += sh.len;
    }
    return ih;
}

fn leadBytesForCodepoint(cp: u21, leads: *[4]u8) usize {
    var eq: [4]u21 = undefined;
    const n_eq = foldEquivalents(cp, &eq);
    var n_leads: usize = 0;
    for (eq[0..n_eq]) |alt_cp| {
        var utf8_buf: [4]u8 = undefined;
        const enc_len = std.unicode.utf8Encode(alt_cp, &utf8_buf) catch return 5;
        if (enc_len == 0) continue;
        const lb = utf8_buf[0];
        var dup = false;
        for (leads[0..n_leads]) |existing| {
            if (existing == lb) {
                dup = true;
                break;
            }
        }
        if (!dup) {
            if (n_leads >= 4) return 5;
            leads[n_leads] = lb;
            n_leads += 1;
        }
    }
    return n_leads;
}

inline fn findNextLead(haystack: []const u8, pos: usize, leads: [4]u8, n_leads: usize) ?usize {
    return switch (n_leads) {
        1 => memchr.find(memchr.native_width, haystack, pos, leads[0]),
        2 => memchr.findEither(memchr.native_width, haystack, pos, leads[0], leads[1]),
        3 => if (memchr.findAny(memchr.native_width, haystack, pos, leads[0], leads[1], leads[2])) |h| h.index else null,
        else => if (pos < haystack.len) pos else null,
    };
}

/// Zero-allocation SIMD-accelerated substring search under Unicode Simple Case Folding.
pub fn findFolded(haystack: []const u8, pattern: []const u8, start: usize) ?struct { start: usize, end: usize } {
    if (start > haystack.len) return null;
    if (pattern.len == 0) return .{ .start = start, .end = start };
    const first_pat = nextCodepoint(pattern, 0).?;

    var anchor_idx: usize = 0;
    var anchor_folded: u21 = toLowerSimple(first_pat.cp);
    var anchor_leads: [4]u8 = undefined;
    var anchor_n_leads: usize = leadBytesForCodepoint(first_pat.cp, &anchor_leads);

    // If the pattern starts with an ASCII character (e.g., 's' in "strasse"), check whether one of the
    // first 16 codepoints is a non-ASCII codepoint whose folded variants all have non-ASCII lead bytes.
    if (first_pat.cp < 0x80) {
        var scan_pos: usize = first_pat.len;
        var cp_idx: usize = 1;
        while (scan_pos < pattern.len and cp_idx < 16) : (cp_idx += 1) {
            const sp = nextCodepoint(pattern, scan_pos) orelse break;
            scan_pos += sp.len;
            if (sp.cp >= 0x80) {
                var cand_leads: [4]u8 = undefined;
                const cand_n = leadBytesForCodepoint(sp.cp, &cand_leads);
                if (cand_n >= 1 and cand_n <= 3) {
                    var all_non_ascii = true;
                    for (cand_leads[0..cand_n]) |lb| {
                        if (lb < 0x80) {
                            all_non_ascii = false;
                            break;
                        }
                    }
                    if (all_non_ascii) {
                        anchor_idx = cp_idx;
                        anchor_folded = toLowerSimple(sp.cp);
                        anchor_leads = cand_leads;
                        anchor_n_leads = cand_n;
                        break;
                    }
                }
            }
        }
    }

    if (anchor_idx == 0 and anchor_n_leads >= 1 and anchor_n_leads <= 3) {
        var pos = start;
        while (pos < haystack.len) {
            pos = findNextLead(haystack, pos, anchor_leads, anchor_n_leads) orelse return null;
            if (matchFoldedPrefix(pattern, haystack[pos..])) |match_len| {
                return .{ .start = pos, .end = pos + match_len };
            }
            pos += 1;
        }
        return null;
    }

    if (anchor_idx > 0 and anchor_n_leads >= 1 and anchor_n_leads <= 3) {
        var search_pos = start +| anchor_idx;
        var checked_up_to = start;
        while (search_pos < haystack.len) {
            const hit_pos = findNextLead(haystack, search_pos, anchor_leads, anchor_n_leads) orelse return null;
            const sh = nextCodepoint(haystack, hit_pos).?;
            if (toLowerSimple(sh.cp) == anchor_folded) {
                const win_start = @max(checked_up_to, hit_pos -| (4 * anchor_idx));
                const win_end = hit_pos -| anchor_idx;
                var cand = win_start;
                while (cand <= win_end and cand < haystack.len) : (cand += 1) {
                    if ((haystack[cand] & 0xC0) == 0x80) continue;
                    if (matchFoldedPrefix(pattern, haystack[cand..])) |match_len| {
                        return .{ .start = cand, .end = cand + match_len };
                    }
                }
                checked_up_to = win_end + 1;
            }
            search_pos = hit_pos + 1;
        }
        return null;
    }

    var pos = start;
    while (pos < haystack.len) {
        const sh = nextCodepoint(haystack, pos).?;
        if (matchFoldedPrefix(pattern, haystack[pos..])) |match_len| {
            return .{ .start = pos, .end = pos + match_len };
        }
        pos += sh.len;
    }
    return null;
}

/// Returns whether the character immediately ending at `pos` in `haystack` is a word character (ASCII or UTF-8).
pub fn isWordBefore(haystack: []const u8, pos: usize) bool {
    if (pos == 0 or pos > haystack.len) return false;
    const prev = haystack[pos - 1];
    if (prev < 0x80) return isUnicodeWordCodepoint(prev);
    // Walk back up to 4 bytes to find the UTF-8 lead byte
    var start = pos - 1;
    const min_start = pos -| 4;
    while (start > min_start and (haystack[start] & 0xC0) == 0x80) {
        start -= 1;
    }
    const seq_len = std.unicode.utf8ByteSequenceLength(haystack[start]) catch return false;
    if (start + seq_len != pos) return false;
    const cp = std.unicode.utf8Decode(haystack[start..pos]) catch return false;
    return isUnicodeWordCodepoint(cp);
}

/// Returns whether the character starting at `pos` in `haystack` is a word character (ASCII or UTF-8).
pub fn isWordAt(haystack: []const u8, pos: usize) bool {
    if (pos >= haystack.len) return false;
    const b = haystack[pos];
    if (b < 0x80) return isUnicodeWordCodepoint(b);
    const seq_len = std.unicode.utf8ByteSequenceLength(b) catch return false;
    if (pos + seq_len > haystack.len) return false;
    const cp = std.unicode.utf8Decode(haystack[pos .. pos + seq_len]) catch return false;
    return isUnicodeWordCodepoint(cp);
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
    const include_cross_ascii = countBranches(pattern, true) <= max_variants;
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(allocator);
    const limit = out_list.items.len +| max_variants;
    try expandRecursive(allocator, pattern, 0, include_cross_ascii, &buf, out_list, limit);
}

pub fn countBranches(pattern: []const u8, include_cross_ascii: bool) usize {
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
            // Original ASCII byte (handled by ASCII case-folding or case-sensitive matching) + U+212A
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

test "BMP Unicode Simple Case Folding across scripts and cross-byte-length pairs" {
    try std.testing.expectEqual(@as(u21, 'a'), toLowerSimple('A'));
    try std.testing.expectEqual(@as(u21, 0x00DF), toLowerSimple(0x1E9E)); // U+1E9E -> U+00DF
    try std.testing.expectEqual(@as(u21, 0x03C3), toLowerSimple(0x03A3)); // U+03A3 -> U+03C3
    try std.testing.expectEqual(@as(u21, 0x03C3), toLowerSimple(0x03C2)); // U+03C2 -> U+03C3
    try std.testing.expectEqual(@as(u21, 0x044F), toLowerSimple(0x042F)); // U+042F -> U+044F
    try std.testing.expectEqual(@as(u21, 0x0451), toLowerSimple(0x0401)); // U+0401 -> U+0451
    try std.testing.expectEqual(@as(u21, 0xFF41), toLowerSimple(0xFF21)); // U+FF21 -> U+FF41
    try std.testing.expectEqual(@as(u21, 0x2D00), toLowerSimple(0x10A0)); // Georgian Asomtavruli -> Nuskhuri

    try std.testing.expect(patternHasUnicodeUpper("Δelta"));
    try std.testing.expect(patternHasUnicodeUpper("Привет"));
    try std.testing.expect(!patternHasUnicodeUpper("δelta привет 你好"));

    // Cross-byte-length eqlFolded, matchFoldedPrefix, & findFolded: "straße" (7 bytes) vs "STRAẞE" (8 bytes, U+1E9E is 3 bytes)
    try std.testing.expect(eqlFolded("straße", "STRA\u{1E9E}E"));
    try std.testing.expectEqual(@as(?usize, "STRA\u{1E9E}E".len), matchFoldedPrefix("straße", "STRA\u{1E9E}Eyy"));
    const hit = findFolded("xxSTRA\u{1E9E}Eyy", "straße", 0).?;
    try std.testing.expectEqual(@as(usize, 2), hit.start);
    try std.testing.expectEqual(@as(usize, 2 + "STRA\u{1E9E}E".len), hit.end);

    // Unicode word boundary checks
    const text = " (你好_мир) ";
    try std.testing.expect(!isWordBefore(text, 2)); // '(' before U+4F60
    try std.testing.expect(isWordAt(text, 2)); // U+4F60 at index 2
    try std.testing.expect(isWordBefore(text, 2 + "你好_мир".len)); // Cyrillic 'r' before ')'
    try std.testing.expect(!isWordAt(text, 2 + "你好_мир".len)); // ')'
}
