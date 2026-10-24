const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const sanitize_thread = b.option(bool, "sanitize-thread", "Enable ThreadSanitizer") orelse false;
    const fuzz_filter = b.option([]const u8, "fuzz-filter", "Run only tests whose name contains this substring");
    // OS- and ISA-specific optimizations are controlled via build options.
    // Windowed mmap and raw getdents64 are disabled by default.
    // Teddy defaults to neon on aarch64 and off on other architectures.
    const want_linux_getdents = b.option(
        bool,
        "linux-getdents",
        "Use raw getdents64 syscall for directory enumeration on Linux (default: false, uses std.Io.Dir.Reader)",
    ) orelse false;
    const window_map = b.option(
        bool,
        "mmap-windows",
        "Map large files in 8 MiB windows before searching (default: false, uses readPositional)",
    ) orelse false;
    const TeddyIsa = enum { off, neon, ssse3, avx2 };
    const teddy_default: TeddyIsa = if (target.result.cpu.arch == .aarch64) .neon else .off;
    const teddy_request = b.option(
        TeddyIsa,
        "teddy",
        "Multi-pattern Teddy SIMD engine: off, neon, ssse3, avx2 (default: neon on aarch64, off otherwise)",
    ) orelse teddy_default;
    const teddy_matches = switch (teddy_request) {
        .off => true,
        .neon => target.result.cpu.arch == .aarch64,
        .ssse3, .avx2 => target.result.cpu.arch == .x86_64,
    };
    const teddy: TeddyIsa = if (teddy_matches) teddy_request else .off;
    // x86_64 Debug uses the self-hosted backend which does not encode pshufb/vpshufb.
    // Use the LLVM backend when SSSE3 or AVX2 Teddy is requested, without linking libc.
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

    // Extract the single canonical code example from docs/API.md and compile it as a test
    // so the documentation example can never drift out of sync with the library API.
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

    const test_step = b.step("test", "Run all unit and documentation tests");
    test_step.dependOn(&run_lib_tests.step);
    test_step.dependOn(&run_example_tests.step);

    // Cross-compilation verification step (compiles library and tests without executing):
    // e.g. zig build check -Dtarget=x86_64-linux-musl -Dteddy=avx2
    const check_step = b.step("check", "Compile library and tests without running");
    check_step.dependOn(&lib_tests.step);
    check_step.dependOn(&example_tests.step);
    if (want_linux_getdents and target.result.os.tag != .linux) {
        const fail = b.addFail("-Dlinux-getdents is only supported when targeting Linux");
        test_step.dependOn(&fail.step);
        check_step.dependOn(&fail.step);
        b.getInstallStep().dependOn(&fail.step);
    }
    if (!teddy_matches) {
        const message = switch (teddy_request) {
            .neon => "-Dteddy=neon is only supported on aarch64",
            .ssse3 => "-Dteddy=ssse3 is only supported on x86_64",
            .avx2 => "-Dteddy=avx2 is only supported on x86_64",
            .off => unreachable,
        };
        const fail = b.addFail(message);
        test_step.dependOn(&fail.step);
        check_step.dependOn(&fail.step);
        b.getInstallStep().dependOn(&fail.step);
    }

    const bench_step = b.step("bench", "Run in-process ReleaseFast microbenchmarks");
    if (optimize != .fast) {
        const fail = b.addFail("Benchmarks must be run with ReleaseFast: zig build bench -Doptimize=ReleaseFast");
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
        std.process.fatal("failed to read {s}: {s}", .{ sub_path, @errorName(err) });
    };
}

fn extractApiExample(md: []const u8) []const u8 {
    const open = "```zig\n";
    const marker = "test \"API documentation example\"";
    var rest = md;
    var found: ?[]const u8 = null;
    while (std.mem.indexOf(u8, rest, open)) |rel| {
        if (rel != 0 and rest[rel - 1] != '\n') {
            rest = rest[rel + 1 ..];
            continue;
        }
        const tail = rest[rel + open.len ..];
        const end = std.mem.indexOf(u8, tail, "\n```") orelse {
            std.process.fatal("unclosed zig code block in docs/API.md", .{});
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
        if (found != null) std.process.fatal("duplicate API documentation example in docs/API.md", .{});
        found = body;
        rest = tail[end + 1 + line_end ..];
    }
    return found orelse std.process.fatal("docs/API.md is missing compilable test \"API documentation example\"", .{});
}

fn checkApiDoc(b: *std.Build, root_src: []const u8, api_md: []const u8) void {
    const required = [_][]const u8{
        "\n## Scope\n",
        "\n## Entry Points\n",
        "\n## Sources\n",
        "\n## Matching\n",
        "\n## Lines and Encoding\n",
        "\n## Binary Detection\n",
        "\n## Context\n",
        "\n## Events\n",
        "\n## Budgets and Errors\n",
        "\n## Defaults\n",
        "\n## Non-Goals\n",
        "\n## Example\n",
        "Smart case is evaluated per pattern",
        "ASCII case folding by default",
        "Binary inputs are skipped by default",
        "Sources with zero matches still emit begin and end",
        "does not accept filesystem paths",
        "does not spawn external processes",
        "does not format terminal colors or serialize NDJSON",
        "Borrowed slices are valid only until the callback returns",
    };
    for (required) |text| {
        if (std.mem.indexOf(u8, api_md, text) == null) {
            std.process.fatal("docs/API.md is missing required text: {s}", .{text});
        }
    }
    const banned = [_][]const u8{ "ANSI", "PCRE", "ChildProcess", "--pretty", "--vimgrep" };
    for (banned) |text| {
        if (std.mem.indexOf(u8, api_md, text) != null) {
            std.process.fatal("docs/API.md contains banned text: {s}", .{text});
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
            if (!prev_doc) std.process.fatal("src/root.zig export '{s}' is missing a /// doc comment", .{name});
            const heading = std.fmt.allocPrint(b.allocator, "\n### {s}\n", .{name}) catch @panic("OOM");
            if (std.mem.indexOf(u8, api_md, heading) == null) {
                std.process.fatal("docs/API.md is missing section '### {s}'", .{name});
            }
            prev_doc = false;
            continue;
        }
        prev_doc = false;
    }
}
