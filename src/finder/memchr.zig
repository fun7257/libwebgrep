//! Single-byte search.
//!
//! `find` delegates directly to `std.mem.findScalarPos`. At the time of that decision,
//! custom SIMD measured 55.8 GB/s vs. std's 54.6 GB/s (~2% difference); later microbenchmarks
//! are recorded in `BENCHMARKS.md`.
//! `findEither` (two distinct bytes), reverse search, and byte counting still use custom `@Vector`
//! loops because std's `findScalarLast` is scalar and std has no vectorized count.
//!
//! A 16-byte comparison is packed into a 64-bit nibble mask: reinterpret the comparison result
//! as 8x 16-bit lanes, shift right by 4 bits, and narrow to 8 bits. Each matching byte produces
//! four 1-bits, so its index is `ctz / 4` and the match count is `popcount / 4`.
//! 32-byte vectors are split into two 16-byte halves processed the same way.

const std = @import("std");

/// Default runtime vector width. Capped at 32 until benchmarks justify AVX-512.
pub const native_width: comptime_int = blk: {
    const suggested = std.simd.suggestVectorLength(u8) orelse 16;
    if (suggested >= 32) break :blk 32;
    break :blk 16;
};

/// Finds the first occurrence of `needle` in `haystack[start..]`.
/// `width` is kept only for call-site symmetry with `findEither`; delegates to std.
pub fn find(comptime width: comptime_int, haystack: []const u8, start: usize, needle: u8) ?usize {
    comptime checkWidth(width);
    return std.mem.findScalarPos(u8, haystack, start, needle);
}

/// Finds the first byte equal to `a` or `b`. Equivalent to `find` when `a == b`.
pub fn findEither(comptime width: comptime_int, haystack: []const u8, start: usize, a: u8, b: u8) ?usize {
    comptime checkWidth(width);
    if (start >= haystack.len) return null;
    if (a == b) return std.mem.findScalarPos(u8, haystack, start, a);

    const V = @Vector(width, u8);
    const va: V = @splat(a);
    const vb: V = @splat(b);
    var i: usize = start;
    const n = haystack.len;
    if (n - i >= width) {
        const stride = width * 4;
        while (n - i >= stride) {
            var hits: [4]@Vector(width, bool) = undefined;
            inline for (0..4) |k| {
                const block: V = haystack[i + k * width ..][0..width].*;
                hits[k] = (block == va) | (block == vb);
            }
            if (@reduce(.Or, (hits[0] | hits[1]) | (hits[2] | hits[3]))) {
                @branchHint(.unlikely);
                inline for (0..4) |k| {
                    if (@reduce(.Or, hits[k])) {
                        return i + k * width + @as(usize, std.simd.firstTrue(hits[k]).?);
                    }
                }
            }
            i += stride;
        }
        while (n - i >= width) {
            const block: V = haystack[i..][0..width].*;
            const hit = (block == va) | (block == vb);
            if (@reduce(.Or, hit)) {
                @branchHint(.unlikely);
                return i + @as(usize, std.simd.firstTrue(hit).?);
            }
            i += width;
        }
    }
    return scalarEither(haystack, i, n, a, b);
}

/// Finds the last occurrence of `needle` in `haystack[start..end]`. `end` is exclusive.
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

/// Counts occurrences of `needle` in `haystack[start..end]`.
pub fn count(comptime width: comptime_int, haystack: []const u8, start: usize, end: usize, needle: u8) usize {
    comptime checkWidth(width);
    const limit = @min(end, haystack.len);
    if (start >= limit) return 0;

    const V = @Vector(width, u8);
    const vn: V = @splat(needle);
    var i: usize = start;
    var total: usize = 0;
    if (limit - i >= width) {
        const stride = width * 4;
        while (limit - i >= stride) {
            var acc: V = @splat(0);
            var batches: usize = 0;
            while (limit - i >= stride and batches < 63) : (batches += 1) {
                inline for (0..4) |k| {
                    const block: V = haystack[i + k * width ..][0..width].*;
                    acc +%= @intFromBool(block == vn);
                }
                i += stride;
            }
            total += @reduce(.Add, @as(@Vector(width, u16), acc));
        }
        var tail_acc: V = @splat(0);
        while (limit - i >= width) {
            const block: V = haystack[i..][0..width].*;
            tail_acc +%= @intFromBool(block == vn);
            i += width;
        }
        total += @reduce(.Add, @as(@Vector(width, u16), tail_acc));
    }
    while (i < limit) : (i += 1) {
        if (haystack[i] == needle) total += 1;
    }
    return total;
}

fn checkWidth(comptime width: comptime_int) void {
    if (width != 16 and width != 32) @compileError("memchr width must be 16 or 32");
}

pub const AnyHit = struct { index: usize, byte: u8 };

/// Finds the first occurrence among `a`, `b`, or `c` (which need not be distinct).
/// The miss loop performs only vector comparisons and reductions, computing the index only on a hit.
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

/// Each matching byte occupies 4 consecutive 1-bits in the mask. Returns null if no match.
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

/// Packs a 16-byte comparison into a 64-bit nibble mask.
fn mask16(block: @Vector(16, u8), a: u8, b: u8) u64 {
    const cmp = if (a == b)
        block == @as(@Vector(16, u8), @splat(a))
    else
        (block == @as(@Vector(16, u8), @splat(a))) | (block == @as(@Vector(16, u8), @splat(b)));
    const bytes: @Vector(16, u8) = @select(u8, cmp, @as(@Vector(16, u8), @splat(@as(u8, 0xFF))), @as(@Vector(16, u8), @splat(@as(u8, 0))));
    return nibbleMask(bytes);
}

/// Compresses each `0xFF` hit byte into four 1-bits. Used in place of movemask on NEON.
pub inline fn nibbleMask(flags: @Vector(16, u8)) u64 {
    const lanes: @Vector(8, u16) = @bitCast(flags);
    const shifted = lanes >> @as(@Vector(8, u16), @splat(@as(u16, 4)));
    const narrowed: @Vector(8, u8) = @truncate(shifted);
    return @bitCast(narrowed);
}

/// Returns the byte index of the first hit in a nibble mask, or null if none.
pub inline fn index16(flags: @Vector(16, u8)) ?usize {
    const mask = nibbleMask(flags);
    if (mask == 0) return null;
    return @as(usize, @ctz(mask)) / 4;
}

/// Returns the first byte index among `native_width` `0xFF` flags, splitting 32-byte vectors into two 16-byte halves.
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

test "empty input and out-of-bounds start" {
    inline for (.{ 16, 32 }) |w| {
        try std.testing.expectEqual(@as(?usize, null), find(w, "", 0, 'a'));
        try std.testing.expectEqual(@as(?usize, null), find(w, "abc", 3, 'a'));
        try std.testing.expectEqual(@as(?usize, null), find(w, "abc", 4, 'a'));
        try std.testing.expectEqual(@as(?usize, null), findLast(w, "", 0, 0, 'a'));
        try std.testing.expectEqual(@as(usize, 0), count(w, "", 0, 0, 'a'));
    }
}

test "finds and counts accurately at every offset" {
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

test "multiple hits within the same vector" {
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

test "three candidate bytes: earliest occurrence wins" {
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

test "two candidate bytes" {
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

test "matches scalar and std.mem.findScalarPos" {
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

test "memchr fuzz differential" {
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
