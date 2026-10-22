//! 全部是单字节模式时的成员查找。
//!
//! 不超过 16 个不同字节时用 `@Vector` 比较。更多字节用一张 256 项的表：
//! 运行时按半字节查表需要 `tbl` / `pshufb`，那部分放在 Teddy 里，不进这条通用路径。

const std = @import("std");
const memchr = @import("memchr.zig");

const absent = std.math.maxInt(u32);
const width = memchr.native_width;

pub const Set = struct {
    id_of: [256]u32 = @splat(absent),
    bytes: [16]u8 = @splat(0),
    used: u16 = 0,

    pub fn init(patterns: []const []const u8, ignore_case: bool) Set {
        var self = Set{};
        for (patterns, 0..) |pat, id| {
            if (pat.len != 1) continue;
            const forms = if (ignore_case) asciiForms(pat[0]) else [2]u8{ pat[0], pat[0] };
            self.note(forms[0], @intCast(id));
            if (forms[1] != forms[0]) self.note(forms[1], @intCast(id));
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
        if (self.used <= 16) return findSmall(self.bytes, self.used, haystack, start);
        var i = start;
        while (i < haystack.len) : (i += 1) {
            if (self.id_of[haystack[i]] != absent) return i;
        }
        return null;
    }
};

fn asciiForms(b: u8) [2]u8 {
    if (b >= 'A' and b <= 'Z') return .{ b, b + ('a' - 'A') };
    if (b >= 'a' and b <= 'z') return .{ b, b - ('a' - 'A') };
    return .{ b, b };
}

fn findSmall(bytes: [16]u8, used: u16, haystack: []const u8, start: usize) ?usize {
    var i: usize = start;
    const n = haystack.len;
    if (n - i >= width) {
        const stride = width * 4;
        while (n - i >= stride) {
            inline for (0..4) |k| {
                const at = i + k * width;
                if (firstOf(haystack[at..][0..width].*, bytes, used)) |rel| return at + rel;
            }
            i += stride;
        }
        while (n - i >= width) {
            if (firstOf(haystack[i..][0..width].*, bytes, used)) |rel| return i + rel;
            i += width;
        }
    }
    while (i < n) : (i += 1) {
        const c = haystack[i];
        var k: u16 = 0;
        while (k < used) : (k += 1) {
            if (c == bytes[k]) return i;
        }
    }
    return null;
}

fn firstOf(block: @Vector(width, u8), bytes: [16]u8, used: u16) ?usize {
    var hits: @Vector(width, bool) = @splat(false);
    var k: u16 = 0;
    while (k < used) : (k += 1) {
        hits = hits | (block == @as(@Vector(width, u8), @splat(bytes[k])));
    }
    if (comptime width == 32) {
        const halves: [2]@Vector(16, u8) = @bitCast(@as(@Vector(width, u8), @select(u8, hits, @as(@Vector(width, u8), @splat(@as(u8, 0xFF))), @as(@Vector(width, u8), @splat(@as(u8, 0))))));
        if (indexFrom(halves[0])) |rel| return rel;
        if (indexFrom(halves[1])) |rel| return 16 + rel;
        return null;
    }
    const flags: @Vector(width, u8) = @select(u8, hits, @as(@Vector(width, u8), @splat(@as(u8, 0xFF))), @as(@Vector(width, u8), @splat(@as(u8, 0))));
    return indexFrom(flags);
}

fn indexFrom(flags: @Vector(16, u8)) ?usize {
    const lanes: @Vector(8, u16) = @bitCast(flags);
    const shifted = lanes >> @as(@Vector(8, u16), @splat(@as(u16, 4)));
    const narrowed: @Vector(8, u8) = @truncate(shifted);
    const mask: u64 = @bitCast(narrowed);
    if (mask == 0) return null;
    return @as(usize, @ctz(mask)) / 4;
}
