//! Runtime CPU ISA feature detection without global mutable state.
//!
//! Queries CPUID / XGETBV on x86_64 when features are not already statically enabled
//! at compile time, enabling safe baseline distribution with dynamic SSSE3 / AVX2 dispatch.

const builtin = @import("builtin");
const std = @import("std");

pub const CpuFeatures = struct {
    ssse3: bool = false,
    avx2: bool = false,
};

/// Returns the host CPU's supported SIMD features for the current target.
/// Safe to call concurrently from any thread; uses no global mutable state.
pub fn detectX86() CpuFeatures {
    if (comptime builtin.cpu.arch != .x86_64) return .{};

    const static_ssse3 = comptime std.Target.x86.featureSetHas(builtin.cpu.features, .ssse3);
    const static_avx2 = comptime std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);
    if (comptime static_avx2) {
        return .{ .ssse3 = true, .avx2 = true };
    }

    var max_leaf: u32 = 0;
    asm volatile ("cpuid"
        : [eax] "={eax}" (max_leaf),
        : [leaf] "{eax}" (@as(u32, 0)),
        : .{ .ebx = true, .ecx = true, .edx = true });
    if (max_leaf < 1) return .{ .ssse3 = static_ssse3, .avx2 = false };

    var ecx1: u32 = 0;
    asm volatile ("cpuid"
        : [ecx] "={ecx}" (ecx1),
        : [leaf] "{eax}" (@as(u32, 1)),
        : .{ .eax = true, .ebx = true, .edx = true });
    const has_ssse3 = static_ssse3 or ((ecx1 & (@as(u32, 1) << 9)) != 0);
    const has_osxsave = (ecx1 & (@as(u32, 1) << 27)) != 0;
    const has_avx = (ecx1 & (@as(u32, 1) << 28)) != 0;
    if (!has_osxsave or !has_avx or max_leaf < 7) {
        return .{ .ssse3 = has_ssse3, .avx2 = false };
    }

    var xcr0_lo: u32 = 0;
    var xcr0_hi: u32 = 0;
    asm volatile ("xgetbv"
        : [lo] "={eax}" (xcr0_lo),
          [hi] "={edx}" (xcr0_hi),
        : [idx] "{ecx}" (@as(u32, 0)),
    );
    // Both XMM (bit 1) and YMM (bit 2) OS state must be enabled.
    if ((xcr0_lo & 0x6) != 0x6) {
        return .{ .ssse3 = has_ssse3, .avx2 = false };
    }

    var ebx7: u32 = 0;
    asm volatile ("cpuid"
        : [ebx] "={ebx}" (ebx7),
        : [leaf] "{eax}" (@as(u32, 7)),
          [subleaf] "{ecx}" (@as(u32, 0)),
        : .{ .eax = true, .ecx = true, .edx = true });
    const has_avx2 = (ebx7 & (@as(u32, 1) << 5)) != 0;
    return .{ .ssse3 = has_ssse3, .avx2 = has_avx2 };
}

test "cpuid detection matches static target feature guarantees" {
    const f = detectX86();
    if (comptime builtin.cpu.arch != .x86_64) {
        try std.testing.expect(!f.ssse3);
        try std.testing.expect(!f.avx2);
        return;
    }
    if (comptime std.Target.x86.featureSetHas(builtin.cpu.features, .avx2)) {
        try std.testing.expect(f.avx2);
        try std.testing.expect(f.ssse3);
    }
    if (comptime std.Target.x86.featureSetHas(builtin.cpu.features, .ssse3)) {
        try std.testing.expect(f.ssse3);
    }
    if (f.avx2) {
        try std.testing.expect(f.ssse3);
    }
}
