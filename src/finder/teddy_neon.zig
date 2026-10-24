//! AArch64 NEON Teddy lookup. Compiled only when `-Dteddy=neon` and targeting aarch64.
//!
//! `tbl` indexes a 16-byte table using the low 4 bits and yields 0 for indices > 15.
//! Callers pass nibbles in the range 0..15.
//! `ext` concatenates two 16-byte vectors and extracts a shifted 16-byte window to align subsequent fingerprint bytes.

const std = @import("std");

pub const lanes: usize = 16;

pub inline fn lookup(table_v: @Vector(16, u8), idx: @Vector(16, u8)) @Vector(16, u8) {
    return asm (
        \\ tbl %[out].16b, {%[table].16b}, %[idx].16b
        : [out] "=w" (-> @Vector(16, u8)),
        : [table] "w" (table_v),
          [idx] "w" (idx),
    );
}

pub inline fn shift(a: @Vector(16, u8), b: @Vector(16, u8), comptime n: u8) @Vector(16, u8) {
    const mask = comptime blk: {
        var m: [lanes]i32 = undefined;
        for (0..lanes) |i| {
            m[i] = if (i + n < lanes) @intCast(i + n) else -@as(i32, @intCast(i + n - lanes)) - 1;
        }
        break :blk m;
    };
    return @shuffle(u8, a, b, mask);
}

test "NEON shift aligns lane i with start offset i" {
    const a: @Vector(16, u8) = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const b: @Vector(16, u8) = .{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const one = shift(a, b, 1);
    const two = shift(a, b, 2);
    try std.testing.expectEqual(@as(u8, 1), one[0]);
    try std.testing.expectEqual(@as(u8, 15), one[14]);
    try std.testing.expectEqual(@as(u8, 16), one[15]);
    try std.testing.expectEqual(@as(u8, 2), two[0]);
    try std.testing.expectEqual(@as(u8, 17), two[15]);
}
