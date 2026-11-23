//! x86_64 AVX2 Teddy lookup. Compiled only when `-Dteddy=avx2` and targeting x86_64.
//!
//! `vpshufb` is three-operand and performs independent lookups in each 16-byte lane,
//! so the 16-byte nibble table must be duplicated into the high half.
//! `vpalignr` does not cross the 16-byte lane boundary; `vperm2i128` first combines the high
//! 16 bytes of the previous vector with the low 16 bytes of the next vector before shifting within lanes.

const std = @import("std");

pub const lanes: usize = 32;

pub inline fn lookup(table_v: @Vector(32, u8), idx: @Vector(32, u8)) @Vector(32, u8) {
    return asm (
        \\ vpshufb %[idx], %[table], %[out]
        : [out] "=v" (-> @Vector(32, u8)),
        : [table] "v" (table_v),
          [idx] "v" (idx),
    );
}

pub inline fn shift(a: @Vector(32, u8), b: @Vector(32, u8), comptime n: u8) @Vector(32, u8) {
    return std.simd.mergeShift(a, b, @intCast(n));
}
