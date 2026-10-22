//! AArch64 NEON 的 Teddy 查表。只在 `-Dteddy=neon` 且目标是 aarch64 时编入。
//!
//! `tbl` 用索引的低 4 位查 16 字节表，索引大于 15 则结果为 0。调用方传入的是半字节，范围是 0 到 15。
//! `ext` 把两段 16 字节接起来再取后面的 16 字节，用来对齐指纹的后续字节。

const std = @import("std");

pub const lanes: usize = 16;

pub fn lookup(table: *const [16]u8, idx: @Vector(16, u8)) @Vector(16, u8) {
    const table_v: @Vector(16, u8) = table.*;
    return asm (
        \\ tbl %[out].16b, {%[table].16b}, %[idx].16b
        : [out] "=w" (-> @Vector(16, u8)),
        : [table] "w" (table_v),
          [idx] "w" (idx),
    );
}

pub fn shift(a: @Vector(16, u8), b: @Vector(16, u8), comptime n: u8) @Vector(16, u8) {
    return switch (n) {
        1 => asm (
            \\ ext %[out].16b, %[a].16b, %[b].16b, #1
            : [out] "=w" (-> @Vector(16, u8)),
            : [a] "w" (a),
              [b] "w" (b),
        ),
        2 => asm (
            \\ ext %[out].16b, %[a].16b, %[b].16b, #2
            : [out] "=w" (-> @Vector(16, u8)),
            : [a] "w" (a),
              [b] "w" (b),
        ),
        else => unreachable,
    };
}

test "NEON 移位让第 i 路对应起点 i" {
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
