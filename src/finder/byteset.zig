//! 全部是单字节模式时的成员查找。
//!
//! 不超过 16 个不同字节时，按个数在编译期展开 `@Vector` 比较，splat 提在循环外。
//! 更多字节用一张 256 项的表。运行时按半字节查表需要 `tbl` / `pshufb`，
//! 那部分放在 Teddy 里，不进这条通用路径。

const std = @import("std");
const ascii = @import("ascii.zig");
const memchr = @import("memchr.zig");

const absent = std.math.maxInt(u32);
const width = memchr.native_width;

pub const Set = struct {
    id_of: [256]u32 = @splat(absent),
    bytes: [16]u8 = @splat(0),
    used: u16 = 0,

    /// 成员扫描用。重复字节只记一次。不分配。
    pub fn initBytes(bytes: []const u8) Set {
        var self = Set{};
        for (bytes) |byte| self.note(byte, 0);
        return self;
    }

    pub fn init(patterns: []const []const u8, ignore_case: bool) Set {
        if (ignore_case) return initPatterns(patterns, true);
        return initPatterns(patterns, false);
    }

    fn initPatterns(patterns: []const []const u8, comptime ignore: bool) Set {
        var self = Set{};
        for (patterns, 0..) |pat, id| {
            if (pat.len != 1) continue;
            const pid: u32 = @intCast(id);
            if (ignore) {
                const forms = ascii.caseVariants(pat[0]);
                self.note(forms[0], pid);
                if (forms[1] != forms[0]) self.note(forms[1], pid);
            } else {
                self.note(pat[0], pid);
            }
        }
        return self;
    }

    fn note(self: *Set, byte: u8, id: u32) void {
        if (self.id_of[byte] != absent) return;
        self.id_of[byte] = id;
        if (self.used < self.bytes.len) self.bytes[self.used] = byte;
        self.used += 1;
    }

    pub fn find(self: *const Set, haystack: []const u8, start: usize) ?usize {
        if (start >= haystack.len or self.used == 0) return null;
        if (self.used <= 16) return findSmall(self.bytes, self.used, haystack, start, false, undefined);
        var i = start;
        while (i < haystack.len) : (i += 1) {
            if (self.id_of[haystack[i]] != absent) return i;
        }
        return null;
    }

    pub fn findWatchingNul(self: *const Set, haystack: []const u8, start: usize, nul_out: *?usize) ?usize {
        if (start >= haystack.len) return null;
        if (self.used == 0) {
            if (memchr.find(width, haystack, start, 0)) |at| nul_out.* = at;
            return null;
        }
        if (self.used <= 16) return findSmall(self.bytes, self.used, haystack, start, true, nul_out);
        var i = start;
        while (i < haystack.len) : (i += 1) {
            const b = haystack[i];
            if (b == 0) {
                nul_out.* = i;
                return null;
            }
            if (self.id_of[b] != absent) return i;
        }
        return null;
    }
};

fn findSmall(
    bytes: [16]u8,
    used: u16,
    haystack: []const u8,
    start: usize,
    comptime watch_nul: bool,
    nul_out: *?usize,
) ?usize {
    switch (used) {
        inline 1...16 => |n| return findN(n, &bytes, haystack, start, watch_nul, nul_out),
        else => return null,
    }
}

fn findN(
    comptime n: u16,
    bytes: *const [16]u8,
    haystack: []const u8,
    start: usize,
    comptime watch_nul: bool,
    nul_out: *?usize,
) ?usize {
    const V = @Vector(width, u8);
    const zero: V = @splat(0);
    var splats: [n]V = undefined;
    inline for (0..n) |k| splats[k] = @splat(bytes[k]);
    var i: usize = start;
    const len = haystack.len;
    if (len - i >= width) {
        const stride = width * 4;
        while (len - i >= stride) {
            var hits: [4]@Vector(width, bool) = undefined;
            inline for (0..4) |w| {
                const block: V = haystack[i + w * width ..][0..width].*;
                const m = maskOf(n, block, &splats);
                hits[w] = if (watch_nul) m | (block == zero) else m;
            }
            if (@reduce(.Or, (hits[0] | hits[1]) | (hits[2] | hits[3]))) {
                @branchHint(.unlikely);
                inline for (0..4) |w| {
                    if (@reduce(.Or, hits[w])) {
                        const at = i + w * width;
                        const block: V = haystack[at..][0..width].*;
                        const m = maskOf(n, block, &splats);
                        if (watch_nul) {
                            const z = block == zero;
                            if (@reduce(.Or, z)) {
                                const z_rel = @as(usize, std.simd.firstTrue(z).?);
                                if (!@reduce(.Or, m) or z_rel < @as(usize, std.simd.firstTrue(m).?)) {
                                    nul_out.* = at + z_rel;
                                    return null;
                                }
                            }
                        }
                        if (@reduce(.Or, m)) {
                            return at + @as(usize, std.simd.firstTrue(m).?);
                        }
                    }
                }
            }
            i += stride;
        }
        while (len - i >= width) {
            const block: V = haystack[i..][0..width].*;
            const hit = maskOf(n, block, &splats);
            if (watch_nul) {
                const z = block == zero;
                if (@reduce(.Or, z)) {
                    @branchHint(.unlikely);
                    const z_rel = @as(usize, std.simd.firstTrue(z).?);
                    if (!@reduce(.Or, hit) or z_rel < @as(usize, std.simd.firstTrue(hit).?)) {
                        nul_out.* = i + z_rel;
                        return null;
                    }
                }
            }
            if (@reduce(.Or, hit)) {
                @branchHint(.unlikely);
                return i + @as(usize, std.simd.firstTrue(hit).?);
            }
            i += width;
        }
    }
    while (i < len) : (i += 1) {
        const c = haystack[i];
        if (watch_nul and c == 0) {
            nul_out.* = i;
            return null;
        }
        inline for (0..n) |k| {
            if (c == bytes[k]) return i;
        }
    }
    return null;
}

inline fn maskOf(comptime n: u16, block: @Vector(width, u8), splats: *const [n]@Vector(width, u8)) @Vector(width, bool) {
    var hits: @Vector(width, bool) = @splat(false);
    inline for (0..n) |k| hits = hits | (block == splats[k]);
    return hits;
}

fn scalarPos(set: *const Set, haystack: []const u8, start: usize) ?usize {
    var i = start;
    while (i < haystack.len) : (i += 1) {
        if (set.id_of[haystack[i]] != absent) return i;
    }
    return null;
}

fn expectByte(set: Set, needle: u8) !void {
    const stride = width * 4;
    const spots = [_]usize{ 1, stride + 1, stride * 2 + 3 };
    for (spots) |at| {
        var hay: [stride * 2 + 4]u8 = @splat(0);
        hay[at] = needle;
        try std.testing.expectEqual(scalarPos(&set, &hay, 0), set.find(&hay, 0));
        try std.testing.expectEqual(at, set.find(&hay, 0).?);
        try std.testing.expectEqual(scalarPos(&set, &hay, at + 1), set.find(&hay, at + 1));
    }
    var blank: [stride * 2 + 4]u8 = @splat(0);
    try std.testing.expect(set.find(&blank, 0) == null);
}

test "1 个、16 个、17 个字节，第二跨和表一致" {
    var one_buf: [1]u8 = .{7};
    const one = Set.init(&.{&one_buf}, false);
    try std.testing.expectEqual(@as(u16, 1), one.used);
    try expectByte(one, 7);

    var mid_buf: [16][1]u8 = undefined;
    var mid_pats: [16][]const u8 = undefined;
    for (&mid_buf, 0..) |*slot, i| {
        slot[0] = @intCast(i + 1);
        mid_pats[i] = slot;
    }
    const mid = Set.init(&mid_pats, false);
    try std.testing.expectEqual(@as(u16, 16), mid.used);
    try expectByte(mid, 1);
    try expectByte(mid, 16);

    var wide_buf: [17][1]u8 = undefined;
    var wide_pats: [17][]const u8 = undefined;
    for (&wide_buf, 0..) |*slot, i| {
        slot[0] = @intCast(i + 1);
        wide_pats[i] = slot;
    }
    const wide = Set.init(&wide_pats, false);
    try std.testing.expectEqual(@as(u16, 17), wide.used);
    try expectByte(wide, 17);
    try expectByte(wide, 1);
}
