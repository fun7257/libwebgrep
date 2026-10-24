//! Unicode 简单大小写折叠（Unicode Simple Case Folding — B05）。
//!
//! 设计原则：
//! 1. 纯 ASCII 且不含跨 ASCII 折叠码点（如 `k`/`K` 对应 U+212A `K`、`s`/`S` 对应 U+017F `ſ`）时，
//!    直接保持现有的无分支 SIMD 快路径。
//! 2. 含有 Unicode 大小写变体的模式，在构造期按单条模式的智能大小写（`smart`）或 `insensitive`
//!    展开等价 UTF-8 模式变体（受 `checkPatternLimits` 硬顶保护），交由 `Multi` 的 SIMD 引擎搜索。

const std = @import("std");

pub const FoldGroup = struct {
    /// 同一简单大小写等价类中的所有码点（含大写与小写）。
    cps: []const u21,
    /// 其中属于大写（Uppercase / Titlecase）的码点，用于单条模式的 `smart` 判断。
    uppers: []const u21,
};

/// 常见多语言 Unicode Simple Case Folding 等价类表（覆盖拉丁扩展、希腊字母、西里尔字母、跨 ASCII 特殊码点等）。
/// 对于规则的连续区间（如 Latin-1、西里尔基本字母、希腊基本字母），结合区间算术与本表共同处理。
const special_groups = [_]FoldGroup{
    // 跨 ASCII 特殊码点
    .{ .cps = &.{ 'k', 'K', 0x212A }, .uppers = &.{'K', 0x212A} }, // Kelvin sign K
    .{ .cps = &.{ 's', 'S', 0x017F }, .uppers = &.{'S'} }, // Long s ſ
    // 德语 Sharp S (U+00DF ß <-> U+1E9E ẞ)
    .{ .cps = &.{ 0x00DF, 0x1E9E }, .uppers = &.{0x1E9E} },
    // 希腊语 Sigma (Σ U+03A3, σ U+03C3, ς U+03C2)
    .{ .cps = &.{ 0x03A3, 0x03C3, 0x03C2 }, .uppers = &.{0x03A3} },
    // 土耳其语 / 拉丁扩展常用特殊对
    .{ .cps = &.{ 0x00FF, 0x0178 }, .uppers = &.{0x0178} }, // ÿ / Ÿ
    .{ .cps = &.{ 0x0152, 0x0153 }, .uppers = &.{0x0152} }, // Œ / œ
};

/// 判断单个 Unicode 码点是否为大写字符（用于 `smart` 模式下按单条模式判断）。
pub fn isUpperCodepoint(cp: u21) bool {
    if (cp >= 'A' and cp <= 'Z') return true;
    // Latin-1 Supplement 大写: U+00C0..U+00D6, U+00D8..U+00DE
    if ((cp >= 0x00C0 and cp <= 0x00D6) or (cp >= 0x00D8 and cp <= 0x00DE)) return true;
    // Latin Extended-A 偶数位大写: U+0100..U+012E, U+0132..U+0136, U+014A..U+0176
    if (cp >= 0x0100 and cp <= 0x012E and (cp & 1) == 0) return true;
    // 希腊语基本大写: U+0391..U+03A1, U+03A3..U+03AB, 以及带调大写 U+0386, U+0388..U+038A, U+038C, U+038E..U+038F
    if ((cp >= 0x0391 and cp <= 0x03A1) or (cp >= 0x03A3 and cp <= 0x03AB)) return true;
    if (cp == 0x0386 or (cp >= 0x0388 and cp <= 0x038A) or cp == 0x038C or cp == 0x038E or cp == 0x038F) return true;
    // 西里尔基本大写: U+0410..U+042F, Ё U+0401
    if ((cp >= 0x0410 and cp <= 0x042F) or cp == 0x0401) return true;
    for (special_groups) |g| {
        for (g.uppers) |u| if (cp == u) return true;
    }
    return false;
}

/// 判断模式切片中是否含有任何 ASCII 或 Unicode 大写码点。
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

/// 返回与 `cp` 处于同一简单大小写等价类的全部码点（写入 `out`，返回个数）。
pub fn foldEquivalents(cp: u21, out: *[4]u21) usize {
    for (special_groups) |g| {
        for (g.cps) |item| {
            if (item == cp) {
                for (g.cps, 0..) |c, idx| out[idx] = c;
                return g.cps.len;
            }
        }
    }
    // ASCII 字母
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
    // Latin Extended-A: U+0100..U+012F (偶大奇小)
    if (cp >= 0x0100 and cp <= 0x012F) {
        out[0] = cp & ~@as(u21, 1);
        out[1] = cp | 1;
        return 2;
    }
    // 希腊语基本字母 (除 Sigma 已在 special_groups 处理): U+0391..U+03A1, U+03A4..U+03AB <-> +0x20
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
    // 西里尔基本字母: U+0410..U+042F <-> U+0430..U+044F
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

/// 将码点折叠为标准小写代表元（用于逐码点等价比较）。
pub fn toFoldedLower(cp: u21) u21 {
    var eq: [4]u21 = undefined;
    const n = foldEquivalents(cp, &eq);
    if (n <= 1) return cp;
    // 返回等价类中非大写的代表码点
    for (eq[0..n]) |c| {
        if (!isUpperCodepoint(c)) return c;
    }
    return eq[0];
}

/// 检查模式是否包含需要超出普通 ASCII 折叠的 Unicode 可折叠码点（如非 ASCII 字母或 `k`/`s` 跨 ASCII 码点）。
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

/// 将单条模式按 Unicode Simple Case Folding 展开为 UTF-8 变体列表并追加到 `out_list`。
/// 为防止组合爆炸，单条模式最多展开 `max_variants` 条（超出时仅展开非 ASCII 码点的大小写变体）。
pub fn expandPatternVariants(
    allocator: std.mem.Allocator,
    pattern: []const u8,
    out_list: *std.ArrayList([]u8),
    max_variants: usize,
) error{OutOfMemory}!void {
    // 先判断是否仅展开非 ASCII 变体即可控制分支数
    const include_cross_ascii = countBranches(pattern, true) <= max_variants;
    var buf = std.ArrayList(u8).empty;
    defer buf.deinit(allocator);
    try expandRecursive(allocator, pattern, 0, include_cross_ascii, &buf, out_list, max_variants);
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
            // 原 ASCII 字符（交给引擎自身的 ASCII 大小写或敏感匹配）+ U+212A (K)
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
