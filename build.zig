const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const sanitize_thread = b.option(bool, "sanitize-thread", "启用 ThreadSanitizer") orelse false;
    const fuzz_filter = b.option([]const u8, "fuzz-filter", "只运行名称包含该子串的测试");
    // 系统和 CPU 专属优化都走构建选项。窗口映射和裸 getdents64 默认关闭。
    // Teddy 在 aarch64 上默认 neon，其它架构默认关闭。通用路径不依赖它们。
    const want_linux_getdents = b.option(
        bool,
        "linux-getdents",
        "Linux 上用裸 getdents64 枚举目录。默认关闭，走 std.Io.Dir.Reader",
    ) orelse false;
    const mmap_windows = b.option(
        bool,
        "mmap-windows",
        "大文件按 8 MiB 窗口映射后再搜索。默认关闭，走 readPositional",
    ) orelse false;
    const TeddyIsa = enum { off, neon, ssse3, avx2 };
    // aarch64 上 NEON 比稠密 DFA 快，测过之后才作为默认。x86 没有计时，仍要显式打开。
    const teddy_default: TeddyIsa = if (target.result.cpu.arch == .aarch64) .neon else .off;
    const teddy_request = b.option(
        TeddyIsa,
        "teddy",
        "多模式 Teddy：off、neon、ssse3、avx2。aarch64 默认 neon，其他架构默认 off",
    ) orelse teddy_default;
    const teddy_matches = switch (teddy_request) {
        .off => true,
        .neon => target.result.cpu.arch == .aarch64,
        .ssse3, .avx2 => target.result.cpu.arch == .x86_64,
    };
    const teddy: TeddyIsa = if (teddy_matches) teddy_request else .off;
    // x86_64 的 Debug 走自研后端，编不出 pshufb / vpshufb。这两档改用 LLVM，不因此链接 libc。
    // AVX2 还要打开 ymm。只加 avx2，标准库会补上它依赖的 avx 和 sse。
    const use_llvm: ?bool = if (teddy == .ssse3 or teddy == .avx2) true else null;
    const compile_target = if (teddy == .avx2) blk: {
        var query = target.query;
        query.cpu_features_add.addFeature(@backingInt(std.Target.x86.Feature.avx2));
        break :blk b.resolveTargetQuery(query);
    } else target;
    const linux_getdents = want_linux_getdents and target.result.os.tag == .linux;
    const options = b.addOptions();
    options.addOption(bool, "linux_getdents", linux_getdents);
    options.addOption(bool, "mmap_windows", mmap_windows);
    options.addOption(TeddyIsa, "teddy", teddy);
    const test_filters: []const []const u8 = if (fuzz_filter) |filter| &.{filter} else &.{};

    const mod = b.addModule("libwebgrep", .{
        .root_source_file = b.path("src/root.zig"),
        .target = compile_target,
        .optimize = optimize,
        .sanitize_thread = sanitize_thread,
    });
    mod.addOptions("build_options", options);

    const lib_tests = b.addTest(.{
        .name = "libwebgrep-test",
        .root_module = mod,
        .filters = test_filters,
        .use_llvm = use_llvm,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const test_step = b.step("test", "运行单元测试");
    test_step.dependOn(&run_lib_tests.step);

    // 交叉编译时只编译，不运行。例如：
    // zig build check -Dtarget=x86_64-linux-musl
    const check_step = b.step("check", "编译库和测试，不运行");
    check_step.dependOn(&lib_tests.step);
    if (want_linux_getdents and target.result.os.tag != .linux) {
        const fail = b.addFail("-Dlinux-getdents 只适用于 os 为 linux 的目标");
        test_step.dependOn(&fail.step);
        check_step.dependOn(&fail.step);
        b.getInstallStep().dependOn(&fail.step);
    }
    if (!teddy_matches) {
        const message = switch (teddy_request) {
            .neon => "-Dteddy=neon 只适用于 aarch64",
            .ssse3 => "-Dteddy=ssse3 只适用于 x86_64",
            .avx2 => "-Dteddy=avx2 只适用于 x86_64",
            .off => unreachable,
        };
        const fail = b.addFail(message);
        test_step.dependOn(&fail.step);
        check_step.dependOn(&fail.step);
        b.getInstallStep().dependOn(&fail.step);
    }

    const bench_step = b.step("bench", "ReleaseFast 内核微基准，直接调用库");
    if (optimize != .fast) {
        const fail = b.addFail("基准只在 ReleaseFast 下运行：zig build bench -Doptimize=ReleaseFast");
        bench_step.dependOn(&fail.step);
    } else {
        const micro = b.addExecutable(.{
            .name = "libwebgrep-bench",
            .use_llvm = use_llvm,
            .root_module = b.createModule(.{
                .root_source_file = b.path("bench/micro.zig"),
                .target = compile_target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "libwebgrep", .module = mod },
                },
            }),
        });
        const run_micro = b.addRunArtifact(micro);
        bench_step.dependOn(&run_micro.step);
    }
}
