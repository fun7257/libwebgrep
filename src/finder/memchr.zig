//! Single-byte search.
//!
//! `find`, `findEither`, `findLast`, `findAny`, and `findSepOrNul` use custom `@Vector` loops
//! with `@ctz`/`@clz` on bitcast lane masks (little-endian) to avoid horizontal reduction trees.
//! Byte counting uses a 63-batch `u8` accumulator to avoid per-vector horizontal reductions.
//!
//! `nibbleMask` compresses 16-byte `0xFF`/`0x00` flags into a 64-bit nibble mask for Teddy on NEON.

const builtin = @import("builtin");
const std = @import("std");

/// Default runtime vector width. Capped at 32 until benchmarks justify AVX-512.
pub const native_width: comptime_int = blk: {
    const suggested = std.simd.suggestVectorLength(u8) orelse 16;
    if (suggested >= 32) break :blk 32;
    break :blk 16;
};

/// Finds the first occurrence of `needle` in `haystack[start..]`.
pub fn find(comptime width: comptime_int, haystack: []const u8, start: usize, needle: u8) ?usize {
    comptime checkWidth(width);
    if (start >= haystack.len) return null;

    const V = @Vector(width, u8);
    const vn: V = @splat(needle);
    var i: usize = start;
    const n = haystack.len;
    if (n - i >= width) {
        // Probe one vector first so short line-end scans resolve in a single load.
        {
            const block: V = haystack[i..][0..width].*;
            const hit = block == vn;
            if (comptime builtin.cpu.arch.endian() == .little) {
                const MaskInt = @Int(.unsigned, width);
                const bits: MaskInt = @bitCast(hit);
                if (bits != 0) return i + @as(usize, @ctz(bits));
            } else if (@reduce(.Or, hit)) {
                return i + @as(usize, std.simd.firstTrue(hit).?);
            }
            i += width;
        }
        const stride = width * 4;
        while (n - i >= stride) {
            var hits: [4]@Vector(width, bool) = undefined;
            inline for (0..4) |k| {
                const block: V = haystack[i + k * width ..][0..width].*;
                hits[k] = block == vn;
            }
            if (@reduce(.Or, (hits[0] | hits[1]) | (hits[2] | hits[3]))) {
                @branchHint(.unlikely);
                inline for (0..4) |k| {
                    if (comptime builtin.cpu.arch.endian() == .little) {
                        const MaskInt = @Int(.unsigned, width);
                        const bits: MaskInt = @bitCast(hits[k]);
                        if (bits != 0) return i + k * width + @as(usize, @ctz(bits));
                    } else if (@reduce(.Or, hits[k])) {
                        return i + k * width + @as(usize, std.simd.firstTrue(hits[k]).?);
                    }
                }
            }
            i += stride;
        }
        while (n - i >= width) {
            const block: V = haystack[i..][0..width].*;
            const hit = block == vn;
            if (comptime builtin.cpu.arch.endian() == .little) {
                const MaskInt = @Int(.unsigned, width);
                const bits: MaskInt = @bitCast(hit);
                if (bits != 0) return i + @as(usize, @ctz(bits));
            } else if (@reduce(.Or, hit)) {
                return i + @as(usize, std.simd.firstTrue(hit).?);
            }
            i += width;
        }
    }
    while (i < n) : (i += 1) {
        if (haystack[i] == needle) return i;
    }
    return null;
}

pub const SepOrNul = struct { pos: ?usize, is_nul: bool };

/// Finds the earliest occurrence of `sep` or NUL (`0`) in `haystack[start..]`
/// in a single SIMD `vpcmpeqb` + `vpor` pass. If both occur in the same vector,
/// returns the earliest position and `is_nul = (haystack[pos] == 0)`.
/// When `sep == 0`, returns `is_nul = true` whenever found.
pub inline fn findSepOrNul(comptime width: usize, haystack: []const u8, start: usize, sep: u8) SepOrNul {
    const w: comptime_int = switch (width) {
        16 => 16,
        32 => 32,
        64 => 64,
        else => @compileError("memchr width must be 16, 32, or 64"),
    };
    if (start >= haystack.len) return .{ .pos = null, .is_nul = false };
    if (sep == 0) {
        const p = find(w, haystack, start, 0);
        return .{ .pos = p, .is_nul = (p != null) };
    }

    const V = @Vector(w, u8);
    const vsep: V = @splat(sep);
    const vzero: V = @splat(0);
    var i: usize = start;
    const n = haystack.len;
    while (n - i >= w) {
        const block: V = haystack[i..][0..w].*;
        const hit = (block == vsep) | (block == vzero);
        if (comptime builtin.cpu.arch.endian() == .little) {
            const MaskInt = @Int(.unsigned, w);
            const bits: MaskInt = @bitCast(hit);
            if (bits != 0) {
                const pos = i + @as(usize, @ctz(bits));
                return .{ .pos = pos, .is_nul = (haystack[pos] == 0) };
            }
        } else if (@reduce(.Or, hit)) {
            const pos = i + @as(usize, std.simd.firstTrue(hit).?);
            return .{ .pos = pos, .is_nul = (haystack[pos] == 0) };
        }
        i += w;
    }
    while (i < n) : (i += 1) {
        const b = haystack[i];
        if (b == sep or b == 0) {
            return .{ .pos = i, .is_nul = (b == 0) };
        }
    }
    return .{ .pos = null, .is_nul = false };
}

/// Finds the first byte equal to `a` or `b`. Equivalent to `find` when `a == b`.
pub fn findEither(comptime width: comptime_int, haystack: []const u8, start: usize, a: u8, b: u8) ?usize {
    comptime checkWidth(width);
    if (start >= haystack.len) return null;
    if (a == b) return find(width, haystack, start, a);

    const V = @Vector(width, u8);
    const va: V = @splat(a);
    const vb: V = @splat(b);
    var i: usize = start;
    const n = haystack.len;
    if (n - i >= width) {
        {
            const block: V = haystack[i..][0..width].*;
            const hit = (block == va) | (block == vb);
            if (comptime builtin.cpu.arch.endian() == .little) {
                const MaskInt = @Int(.unsigned, width);
                const bits: MaskInt = @bitCast(hit);
                if (bits != 0) return i + @as(usize, @ctz(bits));
            } else if (@reduce(.Or, hit)) {
                return i + @as(usize, std.simd.firstTrue(hit).?);
            }
            i += width;
        }
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
                    if (comptime builtin.cpu.arch.endian() == .little) {
                        const MaskInt = @Int(.unsigned, width);
                        const bits: MaskInt = @bitCast(hits[k]);
                        if (bits != 0) return i + k * width + @as(usize, @ctz(bits));
                    } else if (@reduce(.Or, hits[k])) {
                        return i + k * width + @as(usize, std.simd.firstTrue(hits[k]).?);
                    }
                }
            }
            i += stride;
        }
        while (n - i >= width) {
            const block: V = haystack[i..][0..width].*;
            const hit = (block == va) | (block == vb);
            if (comptime builtin.cpu.arch.endian() == .little) {
                const MaskInt = @Int(.unsigned, width);
                const bits: MaskInt = @bitCast(hit);
                if (bits != 0) return i + @as(usize, @ctz(bits));
            } else if (@reduce(.Or, hit)) {
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

    const V = @Vector(width, u8);
    const vn: V = @splat(needle);
    var i: usize = limit;
    while (i - start >= width) {
        const at = i - width;
        const block: V = haystack[at..][0..width].*;
        const cmp = block == vn;
        if (comptime builtin.cpu.arch.endian() == .little) {
            const MaskInt = @Int(.unsigned, width);
            const bits: MaskInt = @bitCast(cmp);
            if (bits != 0) return at + (width - 1 - @as(usize, @clz(bits)));
        } else if (@reduce(.Or, cmp)) {
            return at + @as(usize, std.simd.lastTrue(cmp).?);
        }
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

pub fn findWithWidth(comptime width: comptime_int, haystack: []const u8, start: usize, needle: u8) ?usize {
    return find(width, haystack, start, needle);
}

pub fn findEitherWithWidth(comptime width: comptime_int, haystack: []const u8, start: usize, a: u8, b: u8) ?usize {
    return findEither(width, haystack, start, a, b);
}

pub fn findLastWithWidth(comptime width: comptime_int, haystack: []const u8, start: usize, end: usize, needle: u8) ?usize {
    return findLast(width, haystack, start, end, needle);
}

pub fn countWithWidth(comptime width: comptime_int, haystack: []const u8, start: usize, end: usize, needle: u8) usize {
    return count(width, haystack, start, end, needle);
}

pub fn findAnyWithWidth(comptime width: comptime_int, haystack: []const u8, start: usize, a: u8, b: u8, c: u8) ?AnyHit {
    return findAny(width, haystack, start, a, b, c);
}

fn checkWidth(comptime width: comptime_int) void {
    if (width != 16 and width != 32 and width != 64) @compileError("memchr width must be 16, 32, or 64");
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
    if (comptime builtin.cpu.arch.endian() == .little) {
        const MaskInt = @Int(.unsigned, width);
        const bits: MaskInt = @bitCast(hits);
        return @as(usize, @ctz(bits));
    } else {
        return @as(usize, std.simd.firstTrue(hits).?);
    }
}

fn scalarEither(haystack: []const u8, start: usize, end: usize, a: u8, b: u8) ?usize {
    var i = start;
    while (i < end) : (i += 1) {
        const c = haystack[i];
        if (c == a or c == b) return i;
    }
    return null;
}

/// Compresses each `0xFF` hit byte into four 1-bits. Used in place of movemask on NEON.
pub inline fn nibbleMask(flags: @Vector(16, u8)) u64 {
    if (comptime builtin.cpu.arch.endian() == .little) {
        const lanes: @Vector(8, u16) = @bitCast(flags);
        const shifted = lanes >> @as(@Vector(8, u16), @splat(@as(u16, 4)));
        const narrowed: @Vector(8, u8) = @truncate(shifted);
        return @bitCast(narrowed);
    } else {
        var mask: u64 = 0;
        inline for (0..16) |k| {
            if (flags[k] != 0) mask |= @as(u64, 0xF) << @intCast(k * 4);
        }
        return mask;
    }
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
    inline for (.{ 16, 32, 64 }) |w| {
        try std.testing.expectEqual(@as(?usize, null), find(w, "", 0, 'a'));
        try std.testing.expectEqual(@as(?usize, null), find(w, "abc", 3, 'a'));
        try std.testing.expectEqual(@as(?usize, null), find(w, "abc", 4, 'a'));
        try std.testing.expectEqual(@as(?usize, null), findLast(w, "", 0, 0, 'a'));
        try std.testing.expectEqual(@as(usize, 0), count(w, "", 0, 0, 'a'));
    }
}

test "finds and counts accurately at every offset" {
    var buf: [192]u8 = undefined;
    @memset(&buf, '.');
    inline for (.{ 16, 32, 64 }) |w| {
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
    var buf: [64]u8 = undefined;
    @memset(&buf, 0);
    const hits = [_]usize{ 0, 1, 7, 8, 15, 16, 31, 32, 63 };
    for (hits) |at| buf[at] = 1;
    inline for (.{ 16, 32, 64 }) |w| {
        try std.testing.expectEqual(@as(?usize, 0), find(w, &buf, 0, 1));
        try std.testing.expectEqual(@as(?usize, 1), find(w, &buf, 1, 1));
        try std.testing.expectEqual(@as(?usize, 63), findLast(w, &buf, 0, buf.len, 1));
        try std.testing.expectEqual(@as(?usize, 15), findLast(w, &buf, 0, 16, 1));
        try std.testing.expectEqual(hits.len, count(w, &buf, 0, buf.len, 1));
        try std.testing.expectEqual(@as(usize, 5), count(w, &buf, 0, 16, 1));
    }
}

test "three candidate bytes: earliest occurrence wins" {
    var buf: [160]u8 = undefined;
    @memset(&buf, 'a');
    buf[5] = 0;
    buf[80] = 'Z';
    inline for (.{ 16, 32, 64 }) |w| {
        const nul = findAny(w, &buf, 0, 'Z', 0, 0).?;
        try std.testing.expectEqual(@as(usize, 5), nul.index);
        try std.testing.expectEqual(@as(u8, 0), nul.byte);
        const later = findAny(w, &buf, 6, 'Z', 0, 'Q').?;
        try std.testing.expectEqual(@as(usize, 80), later.index);
        try std.testing.expectEqual(@as(u8, 'Z'), later.byte);
        try std.testing.expect(findAny(w, &buf, 81, 'Z', 0, 'Q') == null);
    }
}

test "two candidate bytes" {
    var buf: [140]u8 = undefined;
    @memset(&buf, 'a');
    buf[3] = 'B';
    buf[70] = 'b';
    inline for (.{ 16, 32, 64 }) |w| {
        try std.testing.expectEqual(@as(?usize, 3), findEither(w, &buf, 0, 'b', 'B'));
        try std.testing.expectEqual(@as(?usize, 70), findEither(w, &buf, 4, 'b', 'B'));
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
        inline for (.{ 16, 32, 64 }) |w| {
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

test "findSepOrNul: NUL vs newline ordering, same vector, tail bytes, and sep==0" {
    @setEvalBranchQuota(10_000);
    inline for (.{ 16, 32, 64 }) |w| {
        // Empty and out-of-bounds start
        try std.testing.expectEqual(SepOrNul{ .pos = null, .is_nul = false }, findSepOrNul(w, "", 0, '\n'));
        try std.testing.expectEqual(SepOrNul{ .pos = null, .is_nul = false }, findSepOrNul(w, "abc", 3, '\n'));
        try std.testing.expectEqual(SepOrNul{ .pos = null, .is_nul = false }, findSepOrNul(w, "abc", 5, '\n'));

        // Same 32B vector: NUL precedes '\n'
        var buf: [160]u8 = @splat('x');
        buf[5] = 0;
        buf[12] = '\n';
        try std.testing.expectEqual(SepOrNul{ .pos = 5, .is_nul = true }, findSepOrNul(w, &buf, 0, '\n'));
        try std.testing.expectEqual(SepOrNul{ .pos = 12, .is_nul = false }, findSepOrNul(w, &buf, 6, '\n'));

        // Same 32B vector: '\n' precedes NUL
        @memset(&buf, 'x');
        buf[5] = '\n';
        buf[12] = 0;
        try std.testing.expectEqual(SepOrNul{ .pos = 5, .is_nul = false }, findSepOrNul(w, &buf, 0, '\n'));
        try std.testing.expectEqual(SepOrNul{ .pos = 12, .is_nul = true }, findSepOrNul(w, &buf, 6, '\n'));

        // Adjacent bytes inside same vector at lane boundaries
        @memset(&buf, 'x');
        buf[30] = 0;
        buf[31] = '\n';
        try std.testing.expectEqual(SepOrNul{ .pos = 30, .is_nul = true }, findSepOrNul(w, &buf, 0, '\n'));
        buf[30] = '\n';
        buf[31] = 0;
        try std.testing.expectEqual(SepOrNul{ .pos = 30, .is_nul = false }, findSepOrNul(w, &buf, 0, '\n'));

        // Across vector boundaries: NUL in later vector vs '\n' in later vector
        @memset(&buf, 'x');
        buf[75] = 0;
        buf[120] = '\n';
        try std.testing.expectEqual(SepOrNul{ .pos = 75, .is_nul = true }, findSepOrNul(w, &buf, 0, '\n'));
        buf[75] = '\n';
        buf[120] = 0;
        try std.testing.expectEqual(SepOrNul{ .pos = 75, .is_nul = false }, findSepOrNul(w, &buf, 0, '\n'));

        // Tail bytes (< width)
        var tail_buf: [73]u8 = @splat('y');
        tail_buf[68] = 0;
        tail_buf[71] = '\n';
        try std.testing.expectEqual(SepOrNul{ .pos = 68, .is_nul = true }, findSepOrNul(w, &tail_buf, 0, '\n'));
        tail_buf[68] = '\n';
        tail_buf[71] = 0;
        try std.testing.expectEqual(SepOrNul{ .pos = 68, .is_nul = false }, findSepOrNul(w, &tail_buf, 0, '\n'));
        try std.testing.expectEqual(SepOrNul{ .pos = 71, .is_nul = true }, findSepOrNul(w, &tail_buf, 69, '\n'));
        try std.testing.expectEqual(SepOrNul{ .pos = null, .is_nul = false }, findSepOrNul(w, &tail_buf, 72, '\n'));

        // Short slice (< 16 bytes)
        try std.testing.expectEqual(SepOrNul{ .pos = 2, .is_nul = true }, findSepOrNul(w, "ab\x00c\nd", 0, '\n'));
        try std.testing.expectEqual(SepOrNul{ .pos = 2, .is_nul = false }, findSepOrNul(w, "ab\nc\x00d", 0, '\n'));
        try std.testing.expectEqual(SepOrNul{ .pos = null, .is_nul = false }, findSepOrNul(w, "abcdef", 0, '\n'));

        // sep == 0 returns is_nul = true when found, false when absent
        @memset(&buf, 'z');
        try std.testing.expectEqual(SepOrNul{ .pos = null, .is_nul = false }, findSepOrNul(w, &buf, 0, 0));
        buf[45] = 0;
        try std.testing.expectEqual(SepOrNul{ .pos = 45, .is_nul = true }, findSepOrNul(w, &buf, 0, 0));
        try std.testing.expectEqual(SepOrNul{ .pos = 2, .is_nul = true }, findSepOrNul(w, "ab\x00cd", 0, 0));
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
    inline for (.{ 16, 32, 64 }) |w| {
        try std.testing.expectEqual(scalarFind(hay, start, needle), find(w, hay, start, needle));
        try std.testing.expectEqual(scalarCount(hay, start, end, needle), count(w, hay, start, end, needle));
    }
}
