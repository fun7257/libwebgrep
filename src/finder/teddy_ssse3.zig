//! x86_64 SSSE3 Teddy lookup. Compiled only when `-Dteddy=ssse3` and targeting x86_64.
//!
//! `pshufb` clobbers the destination register, so the table is copied first. When the high bit
//! of an index byte is 1, the result is 0; callers pass nibbles with high bit 0 and low 4 bits as the table index.
//! `palignr` concatenates the destination register (low 16 bytes) and source register (high 16 bytes) and shifts right by bytes.

pub const lanes: usize = 16;

pub inline fn lookup(table_v: @Vector(16, u8), idx: @Vector(16, u8)) @Vector(16, u8) {
    return asm (
        \\ movdqa %[table], %[out]
        \\ pshufb %[idx], %[out]
        : [out] "=&x" (-> @Vector(16, u8)),
        : [table] "x" (table_v),
          [idx] "x" (idx),
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
