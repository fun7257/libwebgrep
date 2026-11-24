//! Runtime AVX2 Teddy 32-byte miss-skip kernels compiled without `-mavx2` target flags.
//!
//! Only invoked on `x86_64` when `-Dteddy=runtime` is active and `cpuid.detectX86().avx2`
//! confirmed OSXSAVE/YMM + AVX2 support. Keeps baseline binaries free of AVX2 instructions
//! outside these functions while scanning 32 bytes per iteration on capable CPUs.

/// Scans 32 bytes per step starting at `pos_in` while `pos <= limit` for fingerprint length 1,
/// stopping at the first 32-byte window with any nibble-table match (or NUL byte when `watch_nul` is true).
pub noinline fn skipMissesFp1(
    hay_ptr: [*]const u8,
    pos_in: usize,
    limit: usize,
    lo0: *const [16]u8,
    hi0: *const [16]u8,
    watch_nul: bool,
) usize {
    var pos: usize = pos_in;
    const wn: usize = @intFromBool(watch_nul);
    asm volatile (
        \\ vbroadcasti128 (%[lo0]), %%ymm4
        \\ vbroadcasti128 (%[hi0]), %%ymm5
        \\ mov $0x0f0f0f0f, %%eax
        \\ vmovd %%eax, %%xmm8
        \\ vpbroadcastd %%xmm8, %%ymm8
        \\ vpxor %%ymm9, %%ymm9, %%ymm9
        \\1:
        \\ cmp %[limit], %[pos]
        \\ ja 2f
        \\ vmovdqu (%[hay], %[pos], 1), %%ymm0
        \\ vpand %%ymm8, %%ymm0, %%ymm1
        \\ vpsrlw $4, %%ymm0, %%ymm2
        \\ vpand %%ymm8, %%ymm2, %%ymm2
        \\ vpshufb %%ymm1, %%ymm4, %%ymm1
        \\ vpshufb %%ymm2, %%ymm5, %%ymm2
        \\ vpand %%ymm2, %%ymm1, %%ymm1
        \\ test %[wn], %[wn]
        \\ jz 3f
        \\ vpcmpeqb %%ymm9, %%ymm0, %%ymm0
        \\ vpor %%ymm0, %%ymm1, %%ymm1
        \\3:
        \\ vptest %%ymm1, %%ymm1
        \\ jnz 2f
        \\ add $32, %[pos]
        \\ jmp 1b
        \\2:
        \\ vzeroupper
        : [pos] "+r" (pos),
        : [hay] "r" (hay_ptr),
          [limit] "r" (limit),
          [lo0] "r" (lo0),
          [hi0] "r" (hi0),
          [wn] "r" (wn),
        : .{
          .rax = true, .cc = true, .memory = true,
          .xmm0 = true, .xmm1 = true, .xmm2 = true,
          .xmm4 = true, .xmm5 = true, .xmm8 = true, .xmm9 = true,
        });
    return pos;
}

/// Scans 32 bytes per step starting at `pos_in` while `pos <= limit` for fingerprint length >= 2,
/// filtering the first 2 fingerprint bytes with AVX2 `vpshufb` and stopping on candidate hits (or NUL).
pub noinline fn skipMissesFp2(
    hay_ptr: [*]const u8,
    pos_in: usize,
    limit: usize,
    lo0: *const [16]u8,
    hi0: *const [16]u8,
    lo1: *const [16]u8,
    hi1: *const [16]u8,
    watch_nul: bool,
) usize {
    var pos: usize = pos_in;
    const wn: usize = @intFromBool(watch_nul);
    asm volatile (
        \\ vbroadcasti128 (%[lo0]), %%ymm4
        \\ vbroadcasti128 (%[hi0]), %%ymm5
        \\ vbroadcasti128 (%[lo1]), %%ymm6
        \\ vbroadcasti128 (%[hi1]), %%ymm7
        \\ mov $0x0f0f0f0f, %%eax
        \\ vmovd %%eax, %%xmm8
        \\ vpbroadcastd %%xmm8, %%ymm8
        \\ vpxor %%ymm9, %%ymm9, %%ymm9
        \\1:
        \\ cmp %[limit], %[pos]
        \\ ja 2f
        \\ vmovdqu (%[hay], %[pos], 1), %%ymm0
        \\ vpand %%ymm8, %%ymm0, %%ymm1
        \\ vpsrlw $4, %%ymm0, %%ymm2
        \\ vpand %%ymm8, %%ymm2, %%ymm2
        \\ vpshufb %%ymm1, %%ymm4, %%ymm1
        \\ vpshufb %%ymm2, %%ymm5, %%ymm2
        \\ vpand %%ymm2, %%ymm1, %%ymm1
        \\ vmovdqu 1(%[hay], %[pos], 1), %%ymm3
        \\ vpand %%ymm8, %%ymm3, %%ymm2
        \\ vpsrlw $4, %%ymm3, %%ymm3
        \\ vpand %%ymm8, %%ymm3, %%ymm3
        \\ vpshufb %%ymm2, %%ymm6, %%ymm2
        \\ vpshufb %%ymm3, %%ymm7, %%ymm3
        \\ vpand %%ymm3, %%ymm2, %%ymm2
        \\ vpand %%ymm2, %%ymm1, %%ymm1
        \\ test %[wn], %[wn]
        \\ jz 3f
        \\ vpcmpeqb %%ymm9, %%ymm0, %%ymm0
        \\ vpor %%ymm0, %%ymm1, %%ymm1
        \\3:
        \\ vptest %%ymm1, %%ymm1
        \\ jnz 2f
        \\ add $32, %[pos]
        \\ jmp 1b
        \\2:
        \\ vzeroupper
        : [pos] "+r" (pos),
        : [hay] "r" (hay_ptr),
          [limit] "r" (limit),
          [lo0] "r" (lo0),
          [hi0] "r" (hi0),
          [lo1] "r" (lo1),
          [hi1] "r" (hi1),
          [wn] "r" (wn),
        : .{
          .rax = true, .cc = true, .memory = true,
          .xmm0 = true, .xmm1 = true, .xmm2 = true, .xmm3 = true,
          .xmm4 = true, .xmm5 = true, .xmm6 = true, .xmm7 = true,
          .xmm8 = true, .xmm9 = true,
        });
    return pos;
}
