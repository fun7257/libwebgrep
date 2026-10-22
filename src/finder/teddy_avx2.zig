//! x86_64 AVX2 的 Teddy 查表。只在 `-Dteddy=avx2` 且目标是 x86_64 时编入。
//!
//! `vpshufb` 是三操作数，两条 16 字节通道各自查自己的表，所以 16 字节的半字节表要复制到高半。
//! `vpalignr` 不会跨过 16 字节边界。先用 `vperm2i128` 拼出「上一段的高 16 字节接上下一段的低 16 字节」，再在通道内右移。

pub const lanes: usize = 32;

pub fn lookup(table: *const [16]u8, idx: @Vector(32, u8)) @Vector(32, u8) {
    var wide: [32]u8 = undefined;
    wide[0..16].* = table.*;
    wide[16..32].* = table.*;
    const table_v: @Vector(32, u8) = wide;
    return asm (
        \\ vpshufb %[idx], %[table], %[out]
        : [out] "=v" (-> @Vector(32, u8)),
        : [table] "v" (table_v),
          [idx] "v" (idx),
    );
}

pub fn shift(a: @Vector(32, u8), b: @Vector(32, u8), comptime n: u8) @Vector(32, u8) {
    var tmp: @Vector(32, u8) = @splat(0);
    return switch (n) {
        1 => asm (
            \\ vperm2i128 $0x21, %[b], %[a], %[tmp]
            \\ vpalignr $1, %[a], %[tmp], %[out]
            : [out] "=&v" (-> @Vector(32, u8)),
              [tmp] "=&v" (tmp),
            : [a] "v" (a),
              [b] "v" (b),
        ),
        2 => asm (
            \\ vperm2i128 $0x21, %[b], %[a], %[tmp]
            \\ vpalignr $2, %[a], %[tmp], %[out]
            : [out] "=&v" (-> @Vector(32, u8)),
              [tmp] "=&v" (tmp),
            : [a] "v" (a),
              [b] "v" (b),
        ),
        else => unreachable,
    };
}
