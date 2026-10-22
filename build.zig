const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const sanitize_thread = b.option(bool, "sanitize-thread", "启用 ThreadSanitizer") orelse false;

    const mod = b.addModule("zrg", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .sanitize_thread = sanitize_thread,
    });

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
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    const exe_tests = b.addTest(.{
        .name = "zrg-cli-test",
        .root_module = exe.root_module,
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
        bench_step.dependOn(&run_micro.step);
    }
}
