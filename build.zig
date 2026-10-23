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
    const window_map = b.option(
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
    options.addOption(bool, "window_map", window_map);
    options.addOption(TeddyIsa, "teddy", teddy);
    const test_filters: []const []const u8 = if (fuzz_filter) |filter| &.{filter} else &.{};

    const mod = b.addModule("libwebgrep", .{
        .root_source_file = b.path("src/root.zig"),
        .target = compile_target,
        .optimize = optimize,
        .sanitize_thread = sanitize_thread,
    });
    mod.addOptions("build_options", options);

    const internal_mod = b.createModule(.{
        .root_source_file = b.path("src/internal.zig"),
        .target = compile_target,
        .optimize = optimize,
        .sanitize_thread = sanitize_thread,
    });
    internal_mod.addOptions("build_options", options);

    const lib_tests = b.addTest(.{
        .name = "libwebgrep-test",
        .root_module = mod,
        .filters = test_filters,
        .use_llvm = use_llvm,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);

    // 示例只有 docs/API.md 里的那一份。这里抽出它，编成测试，避免另写一份会漂移的副本。
    const api_doc = readRepoFile(b, "docs/API.md");
    const root_src = readRepoFile(b, "src/root.zig");
    checkApiDoc(b, root_src, api_doc);
    const example_wf = b.addWriteFiles();
    const example_src = example_wf.add("api_doc_example.zig", extractApiExample(api_doc));
    const example_mod = b.createModule(.{
        .root_source_file = example_src,
        .target = compile_target,
        .optimize = optimize,
        .sanitize_thread = sanitize_thread,
        .imports = &.{
            .{ .name = "libwebgrep", .module = mod },
        },
    });
    const example_tests = b.addTest(.{
        .name = "api-doc-example",
        .root_module = example_mod,
        .filters = test_filters,
        .use_llvm = use_llvm,
    });
    const run_example_tests = b.addRunArtifact(example_tests);

    const test_step = b.step("test", "运行单元测试");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_example_tests.step);

    // 交叉编译时只编译，不运行。例如：
    // zig build check -Dtarget=x86_64-linux-musl
    const check_step = b.step("check", "编译库和测试，不运行");
    check_step.dependOn(&lib_tests.step);
    check_step.dependOn(&example_tests.step);
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
                    .{ .name = "libwebgrep_internal", .module = internal_mod },
                },
            }),
        });
        const run_micro = b.addRunArtifact(micro);
        bench_step.dependOn(&run_micro.step);
    }
}

fn readRepoFile(b: *std.Build, sub_path: []const u8) []const u8 {
    b.dependOnFileContents(b.path(sub_path));
    const full = if (b.root.sub_path.len == 0)
        sub_path
    else
        b.pathJoin(&.{ b.root.sub_path, sub_path });
    return b.root.root_dir.handle.readFileAlloc(
        b.graph.io,
        full,
        b.allocator,
        .limited(4 * 1024 * 1024),
    ) catch |err| {
        std.process.fatal("读取 {s} 失败：{s}", .{ sub_path, @errorName(err) });
    };
}

fn extractApiExample(md: []const u8) []const u8 {
    const open = "```zig\n";
    const marker = "test \"API 文档示例能跑通\"";
    var rest = md;
    var found: ?[]const u8 = null;
    while (std.mem.indexOf(u8, rest, open)) |rel| {
        if (rel != 0 and rest[rel - 1] != '\n') {
            rest = rest[rel + 1 ..];
            continue;
        }
        const tail = rest[rel + open.len ..];
        const end = std.mem.indexOf(u8, tail, "\n```") orelse {
            std.process.fatal("docs/API.md 的示例代码块没有结束", .{});
        };
        const after = tail[end + 1 ..];
        const line_end = std.mem.indexOfScalar(u8, after, '\n') orelse after.len;
        if (!std.mem.eql(u8, after[0..line_end], "```")) {
            rest = tail[end + 1 ..];
            continue;
        }
        const body = tail[0..end];
        if (std.mem.indexOf(u8, body, marker) == null) {
            rest = tail[end + 1 + line_end ..];
            continue;
        }
        if (found != null) std.process.fatal("docs/API.md 里的 API 文档示例出现了两次", .{});
        found = body;
        rest = tail[end + 1 + line_end ..];
    }
    return found orelse std.process.fatal("docs/API.md 缺少能编译的 API 文档示例", .{});
}

fn checkApiDoc(b: *std.Build, root_src: []const u8, api_md: []const u8) void {
    const required = [_][]const u8{
        "\n## 范围\n",
        "\n## 入口\n",
        "\n## 来源\n",
        "\n## 匹配\n",
        "\n## 行与编码\n",
        "\n## 二进制\n",
        "\n## 上下文\n",
        "\n## 事件\n",
        "\n## 预算与错误\n",
        "\n## 默认值\n",
        "\n## 示例\n",
        "智能大小写按模式分别判断",
        "大小写折叠只支持 ASCII",
        "二进制默认跳过",
        "未命中的来源也有 begin 和 end",
        "尚未提供",
        "不接收文件系统路径",
        "不执行外部命令",
        "不输出终端文本或 NDJSON",
        "切片只在回调返回前有效",
    };
    for (required) |text| {
        if (std.mem.indexOf(u8, api_md, text) == null) {
            std.process.fatal("docs/API.md 缺少：{s}", .{text});
        }
    }
    const banned = [_][]const u8{ "路径参数", "ANSI", "PCRE", "子进程", "--" };
    for (banned) |text| {
        if (std.mem.indexOf(u8, api_md, text) != null) {
            std.process.fatal("docs/API.md 含有不允许出现的文本：{s}", .{text});
        }
    }

    var prev_doc = false;
    var lines = std.mem.splitScalar(u8, root_src, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "///")) {
            prev_doc = true;
            continue;
        }
        if (std.mem.startsWith(u8, line, "pub const ")) {
            const rest = line["pub const ".len..];
            const name_len = std.mem.indexOfAny(u8, rest, " :=") orelse rest.len;
            const name = std.mem.trim(u8, rest[0..name_len], " ");
            if (!prev_doc) std.process.fatal("src/root.zig 的 {s} 缺少文档注释", .{name});
            const heading = std.fmt.allocPrint(b.allocator, "\n### {s}\n", .{name}) catch @panic("OOM");
            if (std.mem.indexOf(u8, api_md, heading) == null) {
                std.process.fatal("docs/API.md 缺少小节 {s}", .{name});
            }
            prev_doc = false;
            continue;
        }
        prev_doc = false;
    }
}
