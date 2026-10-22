const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const sanitize_thread = b.option(bool, "sanitize-thread", "启用 ThreadSanitizer") orelse false;
    const fuzz_filter = b.option([]const u8, "fuzz-filter", "只运行名称包含该子串的测试");
    // 系统和 CPU 专属优化都走构建选项，默认关闭。通用路径不依赖它们。
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
    const linux_getdents = want_linux_getdents and target.result.os.tag == .linux;
    const options = b.addOptions();
    options.addOption(bool, "linux_getdents", linux_getdents);
    options.addOption(bool, "mmap_windows", mmap_windows);
    const test_filters: []const []const u8 = if (fuzz_filter) |filter| &.{filter} else &.{};

    const mod = b.addModule("zrg", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_thread = sanitize_thread,
    });
    mod.addOptions("build_options", options);

    const exe = b.addExecutable(.{
        .name = "zrg",
        .root_module = b.createModule(.{
            .root_source_file = b.path("examples/cli.zig"),
            .target = target,
            .optimize = optimize,
            .sanitize_thread = sanitize_thread,
            .imports = &.{
                .{ .name = "zrg", .module = mod },
            },
        }),
    });
    b.installArtifact(exe);

    const run_step = b.step("run", "运行示例 CLI");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    run_cmd.addPassthruArgs();

    const lib_tests = b.addTest(.{
        .name = "zrg-test",
        .root_module = mod,
        .filters = test_filters,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const exe_tests = b.addTest(.{
        .name = "zrg-cli-test",
        .root_module = exe.root_module,
        .filters = test_filters,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);

    const test_step = b.step("test", "运行单元测试");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    // 交叉编译时只编译，不运行。例如：
    // zig build check -Dtarget=x86_64-linux-musl
    const check_step = b.step("check", "编译库、示例和测试，不运行");
    check_step.dependOn(&lib_tests.step);
    check_step.dependOn(&exe_tests.step);
    check_step.dependOn(&exe.step);
    if (want_linux_getdents and target.result.os.tag != .linux) {
        const fail = b.addFail("-Dlinux-getdents 只适用于 os 为 linux 的目标");
        test_step.dependOn(&fail.step);
        check_step.dependOn(&fail.step);
        b.getInstallStep().dependOn(&fail.step);
    }

    const bench_step = b.step("bench", "ReleaseFast 基准（内核微基准，随后是端到端脚本）");
    if (optimize != .fast) {
        const fail = b.addFail("基准只在 ReleaseFast 下运行：zig build bench -Doptimize=ReleaseFast");
        bench_step.dependOn(&fail.step);
    } else {
        const micro = b.addExecutable(.{
            .name = "zrg-bench",
            .root_module = b.createModule(.{
                .root_source_file = b.path("bench/micro.zig"),
                .target = target,
                .optimize = optimize,
                .imports = &.{
                    .{ .name = "zrg", .module = mod },
                },
            }),
        });
        const run_micro = b.addRunArtifact(micro);
        const e2e = b.addSystemCommand(&.{ "bash", "bench/e2e.sh" });
        e2e.setCwd(b.path("."));
        e2e.step.dependOn(b.getInstallStep());
        e2e.step.dependOn(&run_micro.step);
        bench_step.dependOn(&e2e.step);
    }
}
