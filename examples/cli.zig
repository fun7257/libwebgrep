//! 示例 CLI。只用于测试和基准，不追求兼容 rg 的全部参数。
//!
//! 模式始终按字面量处理。没有路径时读标准输入，单独的 `-` 也表示标准输入。
//! 退出码：0 有匹配，1 没有，2 是用法或 I/O 错误。

const std = @import("std");
const zrg = @import("zrg");

pub fn main(init: std.process.Init) !void {
    const code = try runMain(init);
    if (code != 0) std.process.exit(code);
}

fn runMain(init: std.process.Init) !u8 {
    var iter = try std.process.Args.Iterator.initAllocator(init.minimal.args, init.gpa);
    defer iter.deinit();
    _ = iter.next();

    var owned: std.ArrayList([]u8) = .empty;
    defer {
        for (owned.items) |arg| init.gpa.free(arg);
        owned.deinit(init.gpa);
    }
    while (iter.next()) |arg| {
        try owned.append(init.gpa, try init.gpa.dupe(u8, arg));
    }

    const view = try init.gpa.alloc([]const u8, owned.items.len);
    defer init.gpa.free(view);
    for (owned.items, view) |arg, *slot| slot.* = arg;

    var out_buf: [8192]u8 = undefined;
    var err_buf: [1024]u8 = undefined;
    var out_w = std.Io.File.stdout().writer(init.io, &out_buf);
    var err_w = std.Io.File.stderr().writer(init.io, &err_buf);
    const code = execute(init.gpa, init.io, view, &out_w.interface, &err_w.interface);
    out_w.interface.flush() catch {};
    err_w.interface.flush() catch {};
    return code;
}

/// 跑一次示例命令行。`argv` 不含程序名。
/// 返回 0 表示有匹配，1 表示没有，2 表示用法或 I/O 错误。
pub fn execute(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
) u8 {
    var parsed = parse(allocator, argv, stderr) catch {
        stderr.flush() catch {};
        return 2;
    };
    defer parsed.paths.deinit(allocator);

    if (parsed.help) {
        stdout.writeAll(usage) catch return 2;
        stdout.flush() catch return 2;
        return 0;
    }

    var finder = zrg.Finder.init(parsed.pattern, .{ .case = parsed.case_mode }) catch {
        stderr.writeAll("zrg: 模式不能包含换行\n") catch {};
        stderr.flush() catch {};
        return 2;
    };

    const config = zrg.SearchConfig{
        .line_numbers = parsed.line_numbers or parsed.column,
        .invert = parsed.invert,
        .before = parsed.before,
        .after = parsed.after,
        .max_count = parsed.max_count,
        .binary = parsed.binary,
    };
    const input_count: usize = if (parsed.paths.items.len == 0) 1 else parsed.paths.items.len;
    const spec = SinkSpec{
        .kind = if (parsed.quiet) .quiet else if (parsed.count) .count else .text,
        .show_path = parsed.force_path or input_count > 1,
        .column = parsed.column,
        .use_separator = !parsed.quiet and !parsed.count and (parsed.before > 0 or parsed.after > 0),
    };

    var scratch: std.Io.Writer.Allocating = .init(allocator);
    defer scratch.deinit();

    var stdin_buf: [64 * 1024]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().readerStreaming(io, &stdin_buf);

    var saw_output = false;
    var any_match = false;
    var any_error = false;

    if (parsed.paths.items.len == 0) {
        const matched = driveOne(
            allocator,
            io,
            .{ .reader = &stdin_reader.interface },
            "<stdin>",
            &finder,
            config,
            spec,
            stdout,
            &scratch,
            &saw_output,
        ) catch |err| {
            return failInput(stderr, "<stdin>", err);
        };
        any_match = matched;
    } else {
        for (parsed.paths.items) |path| {
            if (std.mem.eql(u8, path, "-")) {
                const matched = driveOne(
                    allocator,
                    io,
                    .{ .reader = &stdin_reader.interface },
                    "<stdin>",
                    &finder,
                    config,
                    spec,
                    stdout,
                    &scratch,
                    &saw_output,
                ) catch |err| {
                    return failInput(stderr, "<stdin>", err);
                };
                any_match = any_match or matched;
                continue;
            }

            const file = openInput(io, path) catch |err| {
                stderr.print("zrg: 打不开 {s}：{t}\n", .{ path, err }) catch {};
                any_error = true;
                continue;
            };
            defer file.close(io);

            const stat = file.stat(io) catch |err| {
                stderr.print("zrg: 无法读取 {s} 的信息：{t}\n", .{ path, err }) catch {};
                any_error = true;
                continue;
            };
            if (stat.kind == .directory) {
                stderr.print("zrg: {s}: 目录遍历还没做\n", .{path}) catch {};
                any_error = true;
                continue;
            }

            const matched = driveOne(
                allocator,
                io,
                .{ .file = file },
                path,
                &finder,
                config,
                spec,
                stdout,
                &scratch,
                &saw_output,
            ) catch |err| {
                return failInput(stderr, path, err);
            };
            any_match = any_match or matched;
        }
    }

    stdout.flush() catch return 2;
    stderr.flush() catch {};
    if (any_error) return 2;
    return if (any_match) 0 else 1;
}

const usage =
    \\zrg：字面量行搜索的示例程序
    \\
    \\用法：zrg [选项] 模式 [路径...]
    \\
    \\没有路径时从标准输入读。单独的 - 也表示标准输入。
    \\模式始终按字面量匹配，不能包含换行。
    \\
    \\选项：
    \\  -F, --fixed-strings      接受并忽略（始终是字面量）
    \\  -n, --line-number        打印行号
    \\      --column             打印列号，同时打开行号
    \\  -H, --with-filename      总是打印路径
    \\  -A, --after-context NUM  匹配行之后的上下文
    \\  -B, --before-context NUM 匹配行之前的上下文
    \\  -C, --context NUM        前后上下文
    \\  -v, --invert-match       打印不匹配的行
    \\  -c, --count              只打印每个输入的匹配行数
    \\  -i, --ignore-case        ASCII 忽略大小写
    \\  -S, --smart-case         模式含大写字母时区分大小写
    \\  -m, --max-count NUM      每个输入最多多少条匹配
    \\  -a, --text               不检测 NUL
    \\  -q, --quiet              不写匹配，只用退出码
    \\      --no-config, --color, -j, --threads, --binary
    \\                           接受并忽略，方便和 rg 的命令对齐
    \\
;

const Quiet = struct {
    pub fn matched(self: *Quiet, line: zrg.Line) bool {
        _ = self;
        _ = line;
        return false;
    }
};

const SinkKind = enum { text, count, quiet };

const SinkSpec = struct {
    kind: SinkKind,
    show_path: bool,
    column: bool,
    use_separator: bool,
};

const Input = union(enum) {
    file: std.Io.File,
    reader: *std.Io.Reader,
};

fn failInput(stderr: *std.Io.Writer, name: []const u8, err: anyerror) u8 {
    if (err == error.WriteFailed) {
        stderr.writeAll("zrg: 写出失败\n") catch {};
    } else {
        stderr.print("zrg: {s}: {t}\n", .{ name, err }) catch {};
    }
    stderr.flush() catch {};
    return 2;
}

fn openInput(io: std.Io, path: []const u8) std.Io.File.OpenError!std.Io.File {
    if (std.fs.path.isAbsolute(path)) return std.Io.Dir.openFileAbsolute(io, path, .{});
    return std.Io.Dir.cwd().openFile(io, path, .{});
}

/// 搜索一个输入。返回值表示这个输入有没有匹配行。
fn driveOne(
    allocator: std.mem.Allocator,
    io: std.Io,
    input: Input,
    name: []const u8,
    finder: *zrg.Finder,
    config: zrg.SearchConfig,
    spec: SinkSpec,
    stdout: *std.Io.Writer,
    scratch: *std.Io.Writer.Allocating,
    saw_output: *bool,
) !bool {
    switch (spec.kind) {
        .quiet => {
            var sink = Quiet{};
            const result = switch (input) {
                .file => |file| try zrg.searchFile(Quiet, allocator, io, &sink, file, name, finder, config),
                .reader => |reader| try zrg.searchReader(Quiet, allocator, &sink, reader, name, finder, config),
            };
            return result.matched_lines > 0;
        },
        .count => {
            var sink = zrg.CountPrinter{ .writer = stdout, .show_path = spec.show_path };
            const result = switch (input) {
                .file => |file| try zrg.searchFile(zrg.CountPrinter, allocator, io, &sink, file, name, finder, config),
                .reader => |reader| try zrg.searchReader(zrg.CountPrinter, allocator, &sink, reader, name, finder, config),
            };
            if (sink.write_error) |err| return err;
            return result.matched_lines > 0;
        },
        .text => {
            if (spec.use_separator) {
                scratch.clearRetainingCapacity();
                var sink = zrg.TextPrinter{
                    .writer = &scratch.writer,
                    .show_path = spec.show_path,
                    .column = spec.column,
                };
                const result = switch (input) {
                    .file => |file| try zrg.searchFile(zrg.TextPrinter, allocator, io, &sink, file, name, finder, config),
                    .reader => |reader| try zrg.searchReader(zrg.TextPrinter, allocator, &sink, reader, name, finder, config),
                };
                if (sink.write_error) |err| return err;
                const bytes = scratch.written();
                if (bytes.len > 0) {
                    if (saw_output.*) try stdout.writeAll("--\n");
                    try stdout.writeAll(bytes);
                    saw_output.* = true;
                }
                return result.matched_lines > 0;
            }

            var sink = zrg.TextPrinter{
                .writer = stdout,
                .show_path = spec.show_path,
                .column = spec.column,
            };
            const result = switch (input) {
                .file => |file| try zrg.searchFile(zrg.TextPrinter, allocator, io, &sink, file, name, finder, config),
                .reader => |reader| try zrg.searchReader(zrg.TextPrinter, allocator, &sink, reader, name, finder, config),
            };
            if (sink.write_error) |err| return err;
            return result.matched_lines > 0;
        },
    }
}

const Parsed = struct {
    pattern: []const u8 = "",
    paths: std.ArrayList([]const u8) = .empty,
    line_numbers: bool = false,
    column: bool = false,
    force_path: bool = false,
    invert: bool = false,
    count: bool = false,
    quiet: bool = false,
    case_mode: zrg.CaseMode = .sensitive,
    before: u32 = 0,
    after: u32 = 0,
    max_count: ?u64 = null,
    binary: zrg.BinaryPolicy = .report,
    help: bool = false,
};

const ParseError = error{
    MissingValue,
    BadNumber,
    UnknownFlag,
    NoPattern,
    MultiplePatterns,
    OutOfMemory,
    WriteFailed,
};

fn parse(allocator: std.mem.Allocator, argv: []const []const u8, stderr: *std.Io.Writer) ParseError!Parsed {
    var parsed = Parsed{};
    errdefer parsed.paths.deinit(allocator);

    var pattern: ?[]const u8 = null;
    var end_flags = false;
    var index: usize = 0;
    while (index < argv.len) {
        if (parsed.help) break;
        const arg = argv[index];
        if (!end_flags and std.mem.eql(u8, arg, "--")) {
            end_flags = true;
            index += 1;
            continue;
        }
        if (!end_flags and arg.len > 1 and arg[0] == '-') {
            if (arg[1] == '-') {
                index = try parseLong(&parsed, argv, index, stderr);
            } else {
                index = try parseShort(&parsed, &pattern, argv, index, stderr);
            }
            continue;
        }
        if (pattern == null) {
            pattern = arg;
        } else {
            try parsed.paths.append(allocator, arg);
        }
        index += 1;
    }

    if (parsed.help) return parsed;
    if (pattern == null) {
        stderr.writeAll("zrg: 需要一个模式\n") catch {};
        return error.NoPattern;
    }
    parsed.pattern = pattern.?;
    return parsed;
}

fn parseShort(
    parsed: *Parsed,
    pattern: *?[]const u8,
    argv: []const []const u8,
    index: usize,
    stderr: *std.Io.Writer,
) ParseError!usize {
    const arg = argv[index];
    var k: usize = 1;
    while (k < arg.len) : (k += 1) {
        switch (arg[k]) {
            'h' => {
                parsed.help = true;
                return index + 1;
            },
            'n' => parsed.line_numbers = true,
            'v' => parsed.invert = true,
            'c' => parsed.count = true,
            'q' => parsed.quiet = true,
            'i' => parsed.case_mode = .insensitive,
            'S' => parsed.case_mode = .smart,
            'H' => parsed.force_path = true,
            'a' => parsed.binary = .none,
            'F' => {},
            'A', 'B', 'C', 'm', 'e', 'j' => {
                const flag = arg[k];
                const rest = arg[k + 1 ..];
                const value = if (rest.len != 0) rest else blk: {
                    if (index + 1 >= argv.len) {
                        stderr.print("zrg: -{c} 缺少参数\n", .{flag}) catch {};
                        return error.MissingValue;
                    }
                    break :blk argv[index + 1];
                };
                const took_next = rest.len == 0;
                try applyShortValue(parsed, pattern, flag, value, stderr);
                return index + 1 + @intFromBool(took_next);
            },
            else => {
                stderr.print("zrg: 无法识别的选项：-{c}\n", .{arg[k]}) catch {};
                return error.UnknownFlag;
            },
        }
    }
    return index + 1;
}

fn applyShortValue(
    parsed: *Parsed,
    pattern: *?[]const u8,
    flag: u8,
    value: []const u8,
    stderr: *std.Io.Writer,
) ParseError!void {
    switch (flag) {
        'A' => parsed.after = try parseU32(value, stderr),
        'B' => parsed.before = try parseU32(value, stderr),
        'C' => {
            const n = try parseU32(value, stderr);
            parsed.before = n;
            parsed.after = n;
        },
        'm' => parsed.max_count = try parseU64(value, stderr),
        'e' => {
            if (pattern.* != null) {
                stderr.writeAll("zrg: 目前只支持一个模式\n") catch {};
                return error.MultiplePatterns;
            }
            pattern.* = value;
        },
        'j' => {},
        else => return error.UnknownFlag,
    }
}

const LongValue = enum { after, before, context, max_count, color, threads };

fn parseLong(
    parsed: *Parsed,
    argv: []const []const u8,
    index: usize,
    stderr: *std.Io.Writer,
) ParseError!usize {
    const body = argv[index][2..];
    var name = body;
    var inline_value: ?[]const u8 = null;
    if (std.mem.findScalar(u8, body, '=')) |eq| {
        name = body[0..eq];
        inline_value = body[eq + 1 ..];
    }

    if (std.mem.eql(u8, name, "help")) {
        if (inline_value != null) {
            stderr.writeAll("zrg: 无法识别的选项：--help\n") catch {};
            return error.UnknownFlag;
        }
        parsed.help = true;
        return index + 1;
    }

    if (longValueKind(name)) |kind| {
        const value = if (inline_value) |text| text else blk: {
            if (index + 1 >= argv.len) {
                stderr.print("zrg: --{s} 缺少参数\n", .{name}) catch {};
                return error.MissingValue;
            }
            break :blk argv[index + 1];
        };
        const took_next = inline_value == null;
        switch (kind) {
            .after => parsed.after = try parseU32(value, stderr),
            .before => parsed.before = try parseU32(value, stderr),
            .context => {
                const n = try parseU32(value, stderr);
                parsed.before = n;
                parsed.after = n;
            },
            .max_count => parsed.max_count = try parseU64(value, stderr),
            .color, .threads => {},
        }
        return index + 1 + @intFromBool(took_next);
    }

    if (inline_value != null) {
        stderr.print("zrg: 无法识别的选项：--{s}\n", .{name}) catch {};
        return error.UnknownFlag;
    }
    try applyLongFlag(parsed, name, stderr);
    return index + 1;
}

fn longValueKind(name: []const u8) ?LongValue {
    if (std.mem.eql(u8, name, "after-context")) return .after;
    if (std.mem.eql(u8, name, "before-context")) return .before;
    if (std.mem.eql(u8, name, "context")) return .context;
    if (std.mem.eql(u8, name, "max-count")) return .max_count;
    if (std.mem.eql(u8, name, "color")) return .color;
    if (std.mem.eql(u8, name, "threads")) return .threads;
    return null;
}

fn applyLongFlag(parsed: *Parsed, name: []const u8, stderr: *std.Io.Writer) ParseError!void {
    if (std.mem.eql(u8, name, "line-number")) {
        parsed.line_numbers = true;
    } else if (std.mem.eql(u8, name, "column")) {
        parsed.column = true;
    } else if (std.mem.eql(u8, name, "with-filename")) {
        parsed.force_path = true;
    } else if (std.mem.eql(u8, name, "invert-match")) {
        parsed.invert = true;
    } else if (std.mem.eql(u8, name, "count")) {
        parsed.count = true;
    } else if (std.mem.eql(u8, name, "quiet")) {
        parsed.quiet = true;
    } else if (std.mem.eql(u8, name, "ignore-case")) {
        parsed.case_mode = .insensitive;
    } else if (std.mem.eql(u8, name, "smart-case")) {
        parsed.case_mode = .smart;
    } else if (std.mem.eql(u8, name, "text")) {
        parsed.binary = .none;
    } else if (std.mem.eql(u8, name, "fixed-strings") or
        std.mem.eql(u8, name, "no-config") or
        std.mem.eql(u8, name, "binary"))
    {
        // --binary 在显式文件上和默认的 report 一样。目录遍历的 quit 留到下一阶段。
    } else {
        stderr.print("zrg: 无法识别的选项：--{s}\n", .{name}) catch {};
        return error.UnknownFlag;
    }
}

fn parseU32(text: []const u8, stderr: *std.Io.Writer) ParseError!u32 {
    return std.fmt.parseInt(u32, text, 10) catch {
        stderr.print("zrg: 需要无符号整数：{s}\n", .{text}) catch {};
        return error.BadNumber;
    };
}

fn parseU64(text: []const u8, stderr: *std.Io.Writer) ParseError!u64 {
    return std.fmt.parseInt(u64, text, 10) catch {
        stderr.print("zrg: 需要无符号整数：{s}\n", .{text}) catch {};
        return error.BadNumber;
    };
}

const testing = std.testing;

test "示例链接到库" {
    try testing.expectEqual(@as(usize, 256 * 1024), zrg.SearchConfig.default_buffer_size);
}

test "没有模式时退出码是 2" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err_w: std.Io.Writer.Allocating = .init(testing.allocator);
    defer err_w.deinit();
    const code = execute(testing.allocator, testing.io, &.{}, &out.writer, &err_w.writer);
    try testing.expectEqual(@as(u8, 2), code);
    try testing.expect(std.mem.find(u8, err_w.written(), "模式") != null);
}

test "帮助写到标准输出" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err_w: std.Io.Writer.Allocating = .init(testing.allocator);
    defer err_w.deinit();
    const code = execute(testing.allocator, testing.io, &.{"--help"}, &out.writer, &err_w.writer);
    try testing.expectEqual(@as(u8, 0), code);
    try testing.expect(std.mem.find(u8, out.written(), "用法") != null);
}

test "标准输入的路径名是 <stdin>" {
    var reader = std.Io.Reader.fixed("a\nMATCH\n");
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var scratch: std.Io.Writer.Allocating = .init(testing.allocator);
    defer scratch.deinit();
    var finder = try zrg.Finder.init("MATCH", .{});
    var saw = false;
    const matched = try driveOne(
        testing.allocator,
        testing.io,
        .{ .reader = &reader },
        "<stdin>",
        &finder,
        .{ .line_numbers = true },
        .{ .kind = .text, .show_path = true, .column = false, .use_separator = false },
        &out.writer,
        &scratch,
        &saw,
    );
    try testing.expect(matched);
    try testing.expectEqualStrings("<stdin>:2:MATCH\n", out.written());
}

fn pathOf(dir: std.Io.Dir, name: []const u8) ![]u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try dir.realPathFile(testing.io, name, &buf);
    return testing.allocator.dupe(u8, buf[0..n]);
}

fn expectRg(flags: []const []const u8, pattern: []const u8, files: []const []const u8) !void {
    var z_args: std.ArrayList([]const u8) = .empty;
    defer z_args.deinit(testing.allocator);
    try z_args.appendSlice(testing.allocator, &.{ "--no-config", "--color=never", "-F" });
    try z_args.appendSlice(testing.allocator, flags);
    try z_args.append(testing.allocator, pattern);
    try z_args.appendSlice(testing.allocator, files);

    var rg_args: std.ArrayList([]const u8) = .empty;
    defer rg_args.deinit(testing.allocator);
    try rg_args.appendSlice(testing.allocator, &.{ "rg", "--no-config", "--color=never", "-F", "-j", "1" });
    try rg_args.appendSlice(testing.allocator, flags);
    try rg_args.append(testing.allocator, pattern);
    try rg_args.appendSlice(testing.allocator, files);

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err_w: std.Io.Writer.Allocating = .init(testing.allocator);
    defer err_w.deinit();
    const code = execute(testing.allocator, testing.io, z_args.items, &out.writer, &err_w.writer);

    const rg = try std.process.run(testing.allocator, testing.io, .{ .argv = rg_args.items });
    defer testing.allocator.free(rg.stdout);
    defer testing.allocator.free(rg.stderr);

    const rg_code: u8 = switch (rg.term) {
        .exited => |exited| exited,
        else => return error.TestUnexpectedResult,
    };
    if (rg.stderr.len != 0) {
        std.debug.print("rg stderr: {s}\n", .{rg.stderr});
    }
    try testing.expectEqualStrings("", rg.stderr);
    try testing.expectEqualStrings(rg.stdout, out.written());
    try testing.expectEqual(rg_code, code);
    try testing.expectEqualStrings("", err_w.written());
}

test "样例语料和 rg 逐字节一致" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "t.txt", .data = "a\nb\nMATCH\nc\nd\ne\nMATCH2\nf\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "ok.txt", .data = "a\nMATCH\nb\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "c.txt", .data = "a\nMATCH\nb\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "no.txt", .data = "nope\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "case.txt", .data = "Foo\nFOO\nfoo\nbar\nFooBar\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "empty.txt", .data = "a\n\nb\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "nonew.txt", .data = "foo" });
    try tmp.dir.writeFile(io, .{ .sub_path = "crlf.txt", .data = "a\r\nMATCH\r\nb\r\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "col.txt", .data = "xxMATCHyy\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "bin.txt", .data = "xxMATCH\x00yy\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "mm.txt", .data = "MATCH MATCH\nno\nMATCH\n" });

    const t = try pathOf(tmp.dir, "t.txt");
    defer testing.allocator.free(t);
    const ok = try pathOf(tmp.dir, "ok.txt");
    defer testing.allocator.free(ok);
    const c = try pathOf(tmp.dir, "c.txt");
    defer testing.allocator.free(c);
    const no = try pathOf(tmp.dir, "no.txt");
    defer testing.allocator.free(no);
    const case_path = try pathOf(tmp.dir, "case.txt");
    defer testing.allocator.free(case_path);
    const empty = try pathOf(tmp.dir, "empty.txt");
    defer testing.allocator.free(empty);
    const nonew = try pathOf(tmp.dir, "nonew.txt");
    defer testing.allocator.free(nonew);
    const crlf = try pathOf(tmp.dir, "crlf.txt");
    defer testing.allocator.free(crlf);
    const col = try pathOf(tmp.dir, "col.txt");
    defer testing.allocator.free(col);
    const bin = try pathOf(tmp.dir, "bin.txt");
    defer testing.allocator.free(bin);
    const mm = try pathOf(tmp.dir, "mm.txt");
    defer testing.allocator.free(mm);

    try expectRg(&.{"-n"}, "MATCH", &.{t});
    try expectRg(&.{ "-n", "-C", "1" }, "MATCH", &.{t});
    try expectRg(&.{"-nC1"}, "MATCH", &.{t});
    try expectRg(&.{ "-n", "-v" }, "MATCH", &.{ok});
    try expectRg(&.{ "-n", "-v", "-C", "1" }, "MATCH", &.{ok});
    try expectRg(&.{ "-n", "--column", "-v", "-C", "1" }, "MATCH", &.{ok});
    try expectRg(&.{"-c"}, "MATCH", &.{t});
    try expectRg(&.{"-c"}, "NOMATCH", &.{t});
    try expectRg(&.{ "-c", "-H" }, "MATCH", &.{t});
    try expectRg(&.{"-c"}, "MATCH", &.{ ok, c, no });
    try expectRg(&.{ "-i", "-n" }, "foo", &.{case_path});
    try expectRg(&.{ "-S", "-n" }, "foo", &.{case_path});
    try expectRg(&.{ "-S", "-n" }, "Foo", &.{case_path});
    try expectRg(&.{ "-n", "-C", "1" }, "b", &.{empty});
    try expectRg(&.{"-n"}, "foo", &.{nonew});
    try expectRg(&.{"-n"}, "MATCH", &.{crlf});
    try expectRg(&.{"--column"}, "MATCH", &.{col});
    try expectRg(&.{ "-n", "--column" }, "MATCH", &.{mm});
    try expectRg(&.{"-c"}, "MATCH", &.{mm});
    try expectRg(&.{ "-H", "-n" }, "MATCH", &.{t});
    try expectRg(&.{"-n"}, "MATCH", &.{ ok, no, c });
    try expectRg(&.{ "-n", "-C", "1" }, "MATCH", &.{ ok, no, c });
    try expectRg(&.{ "-n", "-m", "1", "-A", "4" }, "MATCH", &.{t});
    try expectRg(&.{ "-c", "-m", "1", "-A", "4" }, "MATCH", &.{t});
    try expectRg(&.{"-q"}, "MATCH", &.{t});
    try expectRg(&.{"-q"}, "NOMATCH", &.{t});
    try expectRg(&.{}, "MATCH", &.{bin});
    try expectRg(&.{"-n"}, "MATCH", &.{bin});
    try expectRg(&.{"-H"}, "MATCH", &.{bin});
    try expectRg(&.{"-c"}, "MATCH", &.{bin});
    try expectRg(&.{"-q"}, "MATCH", &.{bin});
    try expectRg(&.{ "-a", "-n" }, "MATCH", &.{bin});
    try expectRg(&.{ "-n", "--column", "-C", "1" }, "MATCH", &.{ok});
    try expectRg(&.{"-n"}, "", &.{ok});
}
