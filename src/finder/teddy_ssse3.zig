//! x86_64 SSSE3 的 Teddy 查表。只在 `-Dteddy=ssse3` 且目标是 x86_64 时编入。
//!
//! `pshufb` 会改掉目的寄存器，所以先把表复制过去。索引的最高位为 1 时结果是 0。
//! 调用方传入的半字节最高位是 0，低 4 位就是表下标。
//! `palignr` 把目的寄存器当低 16 字节、源寄存器当高 16 字节，再按字节右移。

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
