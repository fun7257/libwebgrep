//! 单字节查找。
//!
//! `find` 直接调用 `std.mem.findScalarPos`。决定改用 std 的那次是手写
//! 55.8 GB/s、std 54.6 GB/s，差距约 2%。后来的微基准记在 `BENCHMARKS.md`。
//! 两个不同字节的 `findEither`、反向查找和计数仍用手写 `@Vector`：
//! std 的 `findScalarLast` 是标量循环，计数也没有对应的向量实现。
//!
//! 16 字节比较的结果收成 64 位半字节掩码：把比较结果看成 8 个 16 位通道，
//! 右移 4 位再窄化成 8 位。匹配字节对应 4 个 1，所以下标是 `ctz / 4`，
//! 个数是 `popcount / 4`。32 字节拆成两段 16 字节做同样的事。

const std = @import("std");

/// 运行时默认宽度。不超过 32：AVX-512 要等基准证明有收益再加。
pub const native_width: comptime_int = blk: {
    const suggested = std.simd.suggestVectorLength(u8) orelse 16;
    if (suggested >= 32) break :blk 32;
    break :blk 16;
};

/// 在 `haystack[start..]` 中查找第一个 `needle`。
/// `width` 只用于保持和 `findEither` 相同的调用形式，实际走 std。
pub fn find(comptime width: comptime_int, haystack: []const u8, start: usize, needle: u8) ?usize {
    comptime checkWidth(width);
    return std.mem.findScalarPos(u8, haystack, start, needle);
}

/// 查找第一个等于 `a` 或 `b` 的字节。两者相同时就是 `find`。
pub fn findEither(comptime width: comptime_int, haystack: []const u8, start: usize, a: u8, b: u8) ?usize {
    comptime checkWidth(width);
    if (start >= haystack.len) return null;

    var i: usize = start;
    const n = haystack.len;
    if (n - i >= width) {
        const stride = width * 4;
        while (n - i >= stride) {
            inline for (0..4) |k| {
                const at = i + k * width;
                if (firstIn(width, haystack[at..][0..width].*, a, b)) |rel| return at + rel;
            }
            i += stride;
        }
        while (n - i >= width) {
            if (firstIn(width, haystack[i..][0..width].*, a, b)) |rel| return i + rel;
            i += width;
        }
    }
    return scalarEither(haystack, i, n, a, b);
}

/// 在 `haystack[start..end]` 中查找最后一个 `needle`。`end` 是开区间。
pub fn findLast(comptime width: comptime_int, haystack: []const u8, start: usize, end: usize, needle: u8) ?usize {
    comptime checkWidth(width);
    const limit = @min(end, haystack.len);
    if (start >= limit) return null;

    var i: usize = limit;
    while (i >= width and i - width >= start) {
        const at = i - width;
        if (lastIn(width, haystack[at..][0..width].*, needle)) |rel| return at + rel;
        i = at;
    }
    while (i > start) {
        i -= 1;
        if (haystack[i] == needle) return i;
    }
    return null;
}

/// 统计 `haystack[start..end]` 里 `needle` 的个数。
pub fn count(comptime width: comptime_int, haystack: []const u8, start: usize, end: usize, needle: u8) usize {
    comptime checkWidth(width);
    const limit = @min(end, haystack.len);
    if (start >= limit) return 0;

    var i: usize = start;
    var total: usize = 0;
    if (limit - i >= width) {
        const stride = width * 4;
        while (limit - i >= stride) {
            inline for (0..4) |k| {
                total += countIn(width, haystack[i + k * width ..][0..width].*, needle);
            }
            i += stride;
        }
        while (limit - i >= width) {
            total += countIn(width, haystack[i..][0..width].*, needle);
            i += width;
        }
    }
    while (i < limit) : (i += 1) {
        if (haystack[i] == needle) total += 1;
    }
    return total;
}

fn checkWidth(comptime width: comptime_int) void {
    if (width != 16 and width != 32) @compileError("memchr 宽度只支持 16 和 32");
}

pub const AnyHit = struct { index: usize, byte: u8 };

/// 查找 `a`、`b`、`c` 中最先出现的字节。三者可以相同。
/// 没命中的循环只做向量比较和归约，落到命中再算下标。
pub fn findAny(comptime width: comptime_int, haystack: []const u8, start: usize, a: u8, b: u8, c: u8) ?AnyHit {
    comptime checkWidth(width);
    if (start >= haystack.len) return null;
    var uniq: [3]u8 = .{ a, a, a };
    var n: usize = 1;
    if (b != a) {
        uniq[n] = b;
        n += 1;
    }
    if (c != a and c != b) {
        uniq[n] = c;
        n += 1;
    }
    const kind: u2 = if (n == 3) 3 else if (n == 2) 2 else 1;
    return switch (kind) {
        1 => findAnyN(width, haystack, start, 1, uniq),
        2 => findAnyN(width, haystack, start, 2, uniq),
        3 => findAnyN(width, haystack, start, 3, uniq),
        0 => null,
    };
}

fn findAnyN(
    comptime width: comptime_int,
    haystack: []const u8,
    start: usize,
    comptime n: u2,
    bytes: [3]u8,
) ?AnyHit {
    var i: usize = start;
    const len = haystack.len;
    if (len - i >= width) {
        const stride = width * 4;
        while (len - i >= stride) {
            inline for (0..4) |k| {
                const at = i + k * width;
                const block: @Vector(width, u8) = haystack[at..][0..width].*;
                if (anyMask(width, block, n, bytes)) {
                    @branchHint(.unlikely);
                    const rel = @call(.never_inline, firstAny, .{ width, block, n, bytes });
                    return .{ .index = at + rel, .byte = haystack[at + rel] };
                }
            }
            i += stride;
        }
        while (len - i >= width) {
            const block: @Vector(width, u8) = haystack[i..][0..width].*;
            if (anyMask(width, block, n, bytes)) {
                @branchHint(.unlikely);
                const rel = @call(.never_inline, firstAny, .{ width, block, n, bytes });
                return .{ .index = i + rel, .byte = haystack[i + rel] };
            }
            i += width;
        }
    }
    while (i < len) : (i += 1) {
        const byte = haystack[i];
        inline for (0..n) |k| {
            if (byte == bytes[k]) return .{ .index = i, .byte = byte };
        }
    }
    return null;
}

inline fn anyMask(comptime width: comptime_int, block: @Vector(width, u8), comptime n: u2, bytes: [3]u8) bool {
    var hits = block == @as(@Vector(width, u8), @splat(bytes[0]));
    inline for (1..n) |k| {
        hits = hits | (block == @as(@Vector(width, u8), @splat(bytes[k])));
    }
    return @reduce(.Or, hits);
}

fn firstAny(comptime width: comptime_int, block: @Vector(width, u8), comptime n: u2, bytes: [3]u8) usize {
    var hits = block == @as(@Vector(width, u8), @splat(bytes[0]));
    inline for (1..n) |k| {
        hits = hits | (block == @as(@Vector(width, u8), @splat(bytes[k])));
    }
    return std.simd.firstTrue(hits).?;
}

fn scalarEither(haystack: []const u8, start: usize, end: usize, a: u8, b: u8) ?usize {
    var i = start;
    while (i < end) : (i += 1) {
        const c = haystack[i];
        if (c == a or c == b) return i;
    }
    return null;
}

fn firstIn(comptime width: comptime_int, block: @Vector(width, u8), a: u8, b: u8) ?usize {
    if (width == 32) {
        const halves: [2]@Vector(16, u8) = @bitCast(block);
        if (indexFromMask(mask16(halves[0], a, b))) |rel| return rel;
        if (indexFromMask(mask16(halves[1], a, b))) |rel| return 16 + rel;
        return null;
    }
    return indexFromMask(mask16(block, a, b));
}

fn lastIn(comptime width: comptime_int, block: @Vector(width, u8), needle: u8) ?usize {
    if (width == 32) {
        const halves: [2]@Vector(16, u8) = @bitCast(block);
        if (lastFromMask(mask16(halves[1], needle, needle))) |rel| return 16 + rel;
        if (lastFromMask(mask16(halves[0], needle, needle))) |rel| return rel;
        return null;
    }
    return lastFromMask(mask16(block, needle, needle));
}

fn countIn(comptime width: comptime_int, block: @Vector(width, u8), needle: u8) usize {
    if (width == 32) {
        const halves: [2]@Vector(16, u8) = @bitCast(block);
        return countMask(mask16(halves[0], needle, needle)) + countMask(mask16(halves[1], needle, needle));
    }
    return countMask(mask16(block, needle, needle));
}

/// 匹配字节在掩码里占 4 个连续的 1。没有匹配时返回 null。
fn indexFromMask(mask: u64) ?usize {
    if (mask == 0) return null;
    return @as(usize, @ctz(mask)) / 4;
}

fn lastFromMask(mask: u64) ?usize {
    if (mask == 0) return null;
    return @as(usize, 63 - @clz(mask)) / 4;
}

fn countMask(mask: u64) usize {
    return @as(usize, @popCount(mask)) / 4;
}

/// 16 字节比较收成 64 位半字节掩码。
fn mask16(block: @Vector(16, u8), a: u8, b: u8) u64 {
    const cmp = if (a == b)
        block == @as(@Vector(16, u8), @splat(a))
    else
        (block == @as(@Vector(16, u8), @splat(a))) | (block == @as(@Vector(16, u8), @splat(b)));
    const bytes: @Vector(16, u8) = @select(u8, cmp, @as(@Vector(16, u8), @splat(@as(u8, 0xFF))), @as(@Vector(16, u8), @splat(@as(u8, 0))));
    return nibbleMask(bytes);
}

/// 命中字节是 `0xFF` 时，每字节收成 4 个 1。NEON 没有 movemask，用这个代替。
pub inline fn nibbleMask(flags: @Vector(16, u8)) u64 {
    const lanes: @Vector(8, u16) = @bitCast(flags);
    const shifted = lanes >> @as(@Vector(8, u16), @splat(@as(u16, 4)));
    const narrowed: @Vector(8, u8) = @truncate(shifted);
    return @bitCast(narrowed);
}

/// 半字节掩码里第一个命中的字节下标。没有命中时返回 null。
pub inline fn index16(flags: @Vector(16, u8)) ?usize {
    const mask = nibbleMask(flags);
    if (mask == 0) return null;
    return @as(usize, @ctz(mask)) / 4;
}

/// `native_width` 个 `0xFF` 标志里第一个字节下标。32 宽先拆成两段 16。
pub inline fn indexWidth(flags: @Vector(native_width, u8)) ?usize {
    if (comptime native_width == 32) {
        const halves: [2]@Vector(16, u8) = @bitCast(flags);
        if (index16(halves[0])) |rel| return rel;
        if (index16(halves[1])) |rel| return 16 + rel;
        return null;
    }
    return index16(flags);
}

fn scalarFind(haystack: []const u8, start: usize, needle: u8) ?usize {
    var i = start;
    while (i < haystack.len) : (i += 1) {
        if (haystack[i] == needle) return i;
    }
    return null;
}

fn scalarCount(haystack: []const u8, start: usize, end: usize, needle: u8) usize {
    var n: usize = 0;
    var i = start;
    const limit = @min(end, haystack.len);
    while (i < limit) : (i += 1) {
        if (haystack[i] == needle) n += 1;
    }
    return n;
}

test "空输入和越界起点" {
    inline for (.{ 16, 32 }) |w| {
        try std.testing.expectEqual(@as(?usize, null), find(w, "", 0, 'a'));
        try std.testing.expectEqual(@as(?usize, null), find(w, "abc", 3, 'a'));
        try std.testing.expectEqual(@as(?usize, null), find(w, "abc", 4, 'a'));
        try std.testing.expectEqual(@as(?usize, null), findLast(w, "", 0, 0, 'a'));
        try std.testing.expectEqual(@as(usize, 0), count(w, "", 0, 0, 'a'));
    }
}

test "每个偏移都能找到，也能数对" {
    var buf: [96]u8 = undefined;
    @memset(&buf, '.');
    inline for (.{ 16, 32 }) |w| {
        for (0..buf.len) |at| {
            buf[at] = 'Q';
            try std.testing.expectEqual(@as(?usize, at), find(w, &buf, 0, 'Q'));
            try std.testing.expectEqual(@as(?usize, at), findLast(w, &buf, 0, buf.len, 'Q'));
            try std.testing.expectEqual(@as(usize, 1), count(w, &buf, 0, buf.len, 'Q'));
            if (at > 0) {
                try std.testing.expectEqual(@as(?usize, null), find(w, &buf, at + 1, 'Q'));
            }
            buf[at] = '.';
        }
    }
}

test "同一向量里的多次命中" {
    var buf: [32]u8 = undefined;
    @memset(&buf, 0);
    const hits = [_]usize{ 0, 1, 7, 8, 15, 16, 31 };
    for (hits) |at| buf[at] = 1;
    inline for (.{ 16, 32 }) |w| {
        try std.testing.expectEqual(@as(?usize, 0), find(w, &buf, 0, 1));
        try std.testing.expectEqual(@as(?usize, 1), find(w, &buf, 1, 1));
        try std.testing.expectEqual(@as(?usize, 31), findLast(w, &buf, 0, buf.len, 1));
        try std.testing.expectEqual(@as(?usize, 15), findLast(w, &buf, 0, 16, 1));
        try std.testing.expectEqual(hits.len, count(w, &buf, 0, buf.len, 1));
        try std.testing.expectEqual(@as(usize, 5), count(w, &buf, 0, 16, 1));
    }
}

test "三个候选字节，先出现的那个胜出" {
    var buf: [80]u8 = undefined;
    @memset(&buf, 'a');
    buf[5] = 0;
    buf[40] = 'Z';
    inline for (.{ 16, 32 }) |w| {
        const nul = findAny(w, &buf, 0, 'Z', 0, 0).?;
        try std.testing.expectEqual(@as(usize, 5), nul.index);
        try std.testing.expectEqual(@as(u8, 0), nul.byte);
        const later = findAny(w, &buf, 6, 'Z', 0, 'Q').?;
        try std.testing.expectEqual(@as(usize, 40), later.index);
        try std.testing.expectEqual(@as(u8, 'Z'), later.byte);
        try std.testing.expect(findAny(w, &buf, 41, 'Z', 0, 'Q') == null);
    }
}

test "两个候选字节" {
    var buf: [40]u8 = undefined;
    @memset(&buf, 'a');
    buf[3] = 'B';
    buf[20] = 'b';
    inline for (.{ 16, 32 }) |w| {
        try std.testing.expectEqual(@as(?usize, 3), findEither(w, &buf, 0, 'b', 'B'));
        try std.testing.expectEqual(@as(?usize, 20), findEither(w, &buf, 4, 'b', 'B'));
        try std.testing.expectEqual(@as(?usize, null), findEither(w, &buf, 0, 'z', 'Z'));
    }
}

test "与标量和 std.mem.findScalarPos 一致" {
    var prng = std.Random.DefaultPrng.init(0x51);
    const random = prng.random();
    var buf: [300]u8 = undefined;
    for (0..40) |_| {
        random.bytes(&buf);
        const needle = random.int(u8);
        const start = random.intRangeAtMost(usize, 0, buf.len);
        const end = random.intRangeAtMost(usize, start, buf.len);
        inline for (.{ 16, 32 }) |w| {
            try std.testing.expectEqual(scalarFind(&buf, start, needle), find(w, &buf, start, needle));
            try std.testing.expectEqual(std.mem.findScalarPos(u8, &buf, start, needle), find(w, &buf, start, needle));
            try std.testing.expectEqual(scalarCount(&buf, start, end, needle), count(w, &buf, start, end, needle));
            var last: ?usize = null;
            var i = start;
            while (i < end) : (i += 1) {
                if (buf[i] == needle) last = i;
            }
            try std.testing.expectEqual(last, findLast(w, &buf, start, end, needle));
        }
    }
}

test "memchr 模糊对照" {
    try std.testing.fuzz({}, fuzzMemchr, .{});
}

fn fuzzMemchr(_: void, smith: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const n: usize = smith.slice(&buf);
    const hay = buf[0..n];
    const needle = smith.value(u8);
    const start: usize = if (n == 0) 0 else smith.valueRangeAtMost(u32, 0, @intCast(n));
    const end: usize = if (start == n) n else smith.valueRangeAtMost(u32, @intCast(start), @intCast(n));
    inline for (.{ 16, 32 }) |w| {
        try std.testing.expectEqual(scalarFind(hay, start, needle), find(w, hay, start, needle));
        try std.testing.expectEqual(scalarCount(hay, start, end, needle), count(w, hay, start, end, needle));
    }
}
