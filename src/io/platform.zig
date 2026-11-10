//! Platform-specific OS and ISA optimization helpers with strict compile-time guards.
//!
//! All operating-system syscalls and target-specific hints are gated via `comptime` checks
//! on `builtin.os.tag` and `builtin.cpu` so non-Linux, non-POSIX, and baseline-ISA builds
//! compile cleanly without linking `libc`.

const builtin = @import("builtin");
const std = @import("std");

/// Advises the OS kernel that `file` will be read sequentially from start to end,
/// expanding kernel readahead windows for cold NVMe/disk streaming.
/// No-op on platforms without a direct libc-free `fadvise` syscall.
pub inline fn adviseSequentialFile(file: std.Io.File) void {
    switch (comptime builtin.os.tag) {
        .linux => {
            // POSIX_FADV_SEQUENTIAL = 2 on all Linux architectures.
            _ = std.os.linux.fadvise(file.handle, 0, 0, 2);
        },
        else => {},
    }
}

/// Advises the OS kernel that mapped pages in `memory` will be accessed sequentially
/// and encourages transparent huge pages where supported.
pub inline fn adviseMappedSequential(memory: []align(std.heap.page_size_min) const u8) void {
    switch (comptime builtin.os.tag) {
        .linux => {
            const ptr: [*]align(std.heap.page_size_min) u8 = @ptrFromInt(@intFromPtr(memory.ptr));
            _ = std.os.linux.madvise(ptr, memory.len, std.os.linux.MADV.SEQUENTIAL);
            if (@hasDecl(std.os.linux.MADV, "HUGEPAGE")) {
                _ = std.os.linux.madvise(ptr, memory.len, std.os.linux.MADV.HUGEPAGE);
            }
        },
        else => {},
    }
}

/// True at comptime when targeting `x86_64` with AVX2 enabled.
pub const has_x86_avx2: bool = builtin.cpu.arch == .x86_64 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);

/// True at comptime when targeting `aarch64` with NEON enabled.
pub const has_aarch64_neon: bool = builtin.cpu.arch == .aarch64 and
    std.Target.aarch64.featureSetHas(builtin.cpu.features, .neon);
