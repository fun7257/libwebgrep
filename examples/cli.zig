//! 示例 CLI。只用于测试和基准，不追求兼容 rg 的全部参数。
//!
//! 模式始终按字面量处理。没有路径时读标准输入，单独的 `-` 也表示标准输入。
//! `--files` 没有模式，位置参数都是路径；没有路径时从当前目录列起。
//! 显式文件按参数顺序逐个搜索。目录交给并行遍历，输出顺序不固定。
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
    var parsed = parse(allocator, io, argv, stderr) catch {
        stderr.flush() catch {};
        return 2;
    };
    defer parsed.deinit(allocator);

    if (parsed.help) {
        stdout.writeAll(usage) catch return 2;
        stdout.flush() catch return 2;
        return 0;
    }
    if (parsed.files_only and parsed.paths.items.len == 0) {
        parsed.paths.append(allocator, ".") catch return 2;
    }

    var finder: zrg.Finder = undefined;
    var many: ?zrg.Multi = null;
    defer if (many) |*engine| engine.deinit();
    if (!parsed.files_only) {
        if (parsed.explicit and parsed.patterns.items.len > 1) {
            many = zrg.Multi.init(allocator, parsed.patterns.items, .{ .case = parsed.case_mode }) catch |err| {
                switch (err) {
                    error.PatternHasNewline => stderr.writeAll("zrg: 模式不能包含换行\n") catch {},
                    error.OutOfMemory => stderr.writeAll("zrg: 内存不足\n") catch {},
                }
                stderr.flush() catch {};
                return 2;
            };
        } else {
            const text = if (parsed.explicit) parsed.patterns.items[0] else parsed.pattern;
            finder = zrg.Finder.init(text, .{ .case = parsed.case_mode }) catch {
                stderr.writeAll("zrg: 模式不能包含换行\n") catch {};
                stderr.flush() catch {};
                return 2;
            };
        }
    }

    var config = zrg.SearchConfig{
        .line_numbers = parsed.line_numbers or parsed.column or parsed.json,
        .invert = parsed.invert,
        .before = parsed.before,
        .after = parsed.after,
        .max_count = parsed.max_count,
        .binary = parsed.binary,
    };
    if (many != null) config.match_mode = .leftmost_first;
    const input_count: usize = if (parsed.paths.items.len == 0) 1 else parsed.paths.items.len;
    const spec = SinkSpec{
        .kind = sinkKind(parsed),
        .show_path = parsed.force_path or input_count > 1,
        .column = parsed.column,
        .use_separator = !parsed.quiet and !parsed.count and !parsed.json and !parsed.files_with_matches and (parsed.before > 0 or parsed.after > 0),
    };
    const started = std.Io.Timestamp.now(io, .awake);

    var scratch: std.Io.Writer.Allocating = .init(allocator);
    defer scratch.deinit();

    var stdin_buf: [64 * 1024]u8 = undefined;
    var stdin_reader = std.Io.File.stdin().readerStreaming(io, &stdin_buf);

    var saw_output = false;
    var any_match = false;
    var any_error = false;
    var totals = zrg.json_printer.Totals{
        .searches = 0,
        .searches_with_match = 0,
        .bytes_searched = 0,
        .bytes_printed = 0,
        .matched_lines = 0,
        .matches = 0,
    };

    if (!parsed.files_only and parsed.paths.items.len == 0) {
        const one = driveInput(
            allocator,
            io,
            .{ .reader = &stdin_reader.interface },
            "<stdin>",
            &finder,
            if (many) |*engine| engine else null,
            config,
            spec,
            stdout,
            &scratch,
            &saw_output,
        ) catch |err| {
            return failInput(stderr, "<stdin>", err);
        };
        any_match = one.matched;
        addOne(&totals, one);
    } else {
        for (parsed.paths.items) |path| {
            if (parsed.quiet and any_match) break;
            if (!parsed.files_only and std.mem.eql(u8, path, "-")) {
                const one = driveInput(
                    allocator,
                    io,
                    .{ .reader = &stdin_reader.interface },
                    "<stdin>",
                    &finder,
                    if (many) |*engine| engine else null,
                    config,
                    spec,
                    stdout,
                    &scratch,
                    &saw_output,
                ) catch |err| {
                    return failInput(stderr, "<stdin>", err);
                };
                any_match = any_match or one.matched;
                addOne(&totals, one);
                continue;
            }

            const stat = std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = true }) catch |err| {
                stderr.print("zrg: 打不开 {s}：{t}\n", .{ path, err }) catch {};
                any_error = true;
                continue;
            };
            if (stat.kind == .directory) {
                const summary = zrg.parallel.run(allocator, io, .{
                    .pattern = if (parsed.files_only) "" else if (parsed.explicit) parsed.patterns.items[0] else parsed.pattern,
                    .patterns = if (many != null) parsed.patterns.items else &.{},
                    .find = .{ .case = parsed.case_mode },
                    .roots = &.{path},
                    .search = config,
                    .walk = .{
                        .hidden = parsed.hidden,
                        .follow_symlinks = parsed.follow,
                        .read_ignore = !parsed.no_ignore,
                        .max_depth = parsed.max_depth,
                        .max_filesize = parsed.max_filesize,
                        .globs = parsed.globs.items,
                        .types = parsed.types.items,
                        .threads = parsed.threads,
                    },
                    .emit = toEmit(spec.kind),
                    .stdout = stdout,
                    .stderr = stderr,
                    .column = parsed.column,
                    .use_separator = spec.use_separator,
                    .saw_output = &saw_output,
                }) catch |err| {
                    stderr.print("zrg: {s}: {t}\n", .{ path, err }) catch {};
                    any_error = true;
                    continue;
                };
                any_match = any_match or summary.matched;
                if (summary.errors != 0) any_error = true;
                totals.searches += summary.searches;
                totals.searches_with_match += summary.searches_with_match;
                totals.bytes_searched += summary.bytes_searched;
                totals.bytes_printed += summary.bytes_printed;
                totals.matched_lines += summary.matched_lines;
                totals.matches += summary.matches;
                continue;
            }

            if (parsed.files_only) {
                stdout.print("{s}\n", .{path}) catch return 2;
                any_match = true;
                continue;
            }

            const file = openInput(io, path) catch |err| {
                stderr.print("zrg: 打不开 {s}：{t}\n", .{ path, err }) catch {};
                any_error = true;
                continue;
            };
            defer file.close(io);
            const one = driveInput(
                allocator,
                io,
                .{ .file = file },
                path,
                &finder,
                if (many) |*engine| engine else null,
                config,
                spec,
                stdout,
                &scratch,
                &saw_output,
            ) catch |err| {
                return failInput(stderr, path, err);
            };
            any_match = any_match or one.matched;
            addOne(&totals, one);
        }
    }

    if (parsed.json) {
        const elapsed = elapsedNanos(started.durationTo(std.Io.Timestamp.now(io, .awake)));
        zrg.json_printer.writeSummary(stdout, elapsed, totals) catch return 2;
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
    \\      zrg [选项] -e 模式 ... [路径...]
    \\      zrg [选项] -f 模式文件 ... [路径...]
    \\
    \\没有路径时从标准输入读。单独的 - 也表示标准输入。
    \\模式始终按字面量匹配，不能包含换行。
    \\用了 -e 或 -f 之后，位置参数都是路径。多个模式按 rg 的顺序：起点靠左优先，同一起点更早给出的模式优先。
    \\
    \\选项：
    \\  -F, --fixed-strings      接受并忽略（始终是字面量）
    \\  -e, --regexp PATTERN     增加一个字面量模式，可重复
    \\  -f, --file FILE          从文件读模式，一行一个，空行也算，可重复
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
    \\  -l, --files-with-matches 只打印有匹配的路径
    \\      --files              只列文件，不需要模式
    \\      --json               按 rg 的 JSON Lines 写出
    \\  -g, --glob GLOB          文件名过滤，可重复。正模式是白名单
    \\  -t, --type TYPE          按内置类型过滤，可重复
    \\      --max-depth NUM      起始目录深度为 1，0 什么也不列
    \\      --max-filesize SIZE  跳过更大的文件。K/M/G 按 1024 计
    \\  -j, --threads NUM        工人数，0 表示 CPU 数
    \\      --hidden             不跳过隐藏文件
    \\      --no-ignore          不读 .gitignore、.ignore 和 exclude
    \\      --follow             跟随符号链接，并用设备号加 inode 防环
    \\      --no-config, --color, --binary
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

const SinkKind = enum { text, count, quiet, json, files_with_matches, files_only };

fn sinkKind(parsed: Parsed) SinkKind {
    if (parsed.files_only) return .files_only;
    if (parsed.quiet) return .quiet;
    if (parsed.json) return .json;
    if (parsed.files_with_matches) return .files_with_matches;
    if (parsed.count) return .count;
    return .text;
}

fn toEmit(kind: SinkKind) zrg.parallel.Emit {
    return switch (kind) {
        .text => .text,
        .count => .count,
        .quiet => .quiet,
        .json => .json,
        .files_with_matches => .files_with_matches,
        .files_only => .files_only,
    };
}

const One = struct {
    matched: bool,
    matched_lines: u64 = 0,
    matches: u64 = 0,
    bytes_printed: u64 = 0,
};

fn addOne(totals: *zrg.json_printer.Totals, one: One) void {
    totals.searches += 1;
    if (one.matched) totals.searches_with_match += 1;
    totals.matched_lines += one.matched_lines;
    totals.matches += one.matches;
    totals.bytes_printed += one.bytes_printed;
}

fn elapsedNanos(duration: std.Io.Duration) u64 {
    if (duration.nanoseconds <= 0) return 0;
    const wide: u128 = @intCast(duration.nanoseconds);
    if (wide > std.math.maxInt(u64)) return std.math.maxInt(u64);
    return @intCast(wide);
}

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

fn driveInput(
    allocator: std.mem.Allocator,
    io: std.Io,
    input: Input,
    name: []const u8,
    finder: *zrg.Finder,
    many: ?*zrg.Multi,
    config: zrg.SearchConfig,
    spec: SinkSpec,
    stdout: *std.Io.Writer,
    scratch: *std.Io.Writer.Allocating,
    saw_output: *bool,
) !One {
    if (many) |engine| {
        return driveOne(allocator, io, input, name, engine, config, spec, stdout, scratch, saw_output);
    }
    return driveOne(allocator, io, input, name, finder, config, spec, stdout, scratch, saw_output);
}

/// 搜索一个显式输入。目录不走这里。一个模式走 Finder，多个模式走 Multi。
fn driveOne(
    allocator: std.mem.Allocator,
    io: std.Io,
    input: Input,
    name: []const u8,
    finder: anytype,
    config: zrg.SearchConfig,
    spec: SinkSpec,
    stdout: *std.Io.Writer,
    scratch: *std.Io.Writer.Allocating,
    saw_output: *bool,
) !One {
    switch (spec.kind) {
        .files_only => unreachable,
        .quiet => {
            var sink = Quiet{};
            const result = switch (input) {
                .file => |file| try zrg.searchFile(Quiet, allocator, io, &sink, file, name, finder, config),
                .reader => |reader| try zrg.searchReader(Quiet, allocator, &sink, reader, name, finder, config),
            };
            return .{ .matched = result.matched_lines > 0, .matched_lines = result.matched_lines, .matches = result.matched_lines };
        },
        .count => {
            var sink = zrg.CountPrinter{ .writer = stdout, .show_path = spec.show_path };
            const result = switch (input) {
                .file => |file| try zrg.searchFile(zrg.CountPrinter, allocator, io, &sink, file, name, finder, config),
                .reader => |reader| try zrg.searchReader(zrg.CountPrinter, allocator, &sink, reader, name, finder, config),
            };
            if (sink.write_error) |err| return err;
            return .{ .matched = result.matched_lines > 0, .matched_lines = result.matched_lines, .matches = result.matched_lines };
        },
        .files_with_matches => {
            var sink = zrg.files_printer.Files{ .writer = stdout };
            const result = switch (input) {
                .file => |file| try zrg.searchFile(zrg.files_printer.Files, allocator, io, &sink, file, name, finder, config),
                .reader => |reader| try zrg.searchReader(zrg.files_printer.Files, allocator, &sink, reader, name, finder, config),
            };
            if (sink.write_error) |err| return err;
            return .{ .matched = result.matched_lines > 0, .matched_lines = result.matched_lines, .matches = result.matched_lines };
        },
        .json => {
            const JsonSink = zrg.json_printer.Printer(@TypeOf(finder.*));
            scratch.clearRetainingCapacity();
            var sink = JsonSink{ .writer = &scratch.writer, .finder = finder };
            const result = switch (input) {
                .file => |file| try zrg.searchFile(JsonSink, allocator, io, &sink, file, name, finder, config),
                .reader => |reader| try zrg.searchReader(JsonSink, allocator, &sink, reader, name, finder, config),
            };
            if (sink.write_error) |err| return err;
            if (sink.started and !sink.writeEnd(0)) {
                if (sink.write_error) |err| return err;
            }
            const bytes = scratch.written();
            if (sink.started) try stdout.writeAll(bytes);
            return .{
                .matched = result.matched_lines > 0,
                .matched_lines = result.matched_lines,
                .matches = sink.matches,
                .bytes_printed = bytes.len,
            };
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
                return .{ .matched = result.matched_lines > 0, .matched_lines = result.matched_lines, .matches = result.matched_lines, .bytes_printed = bytes.len };
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
            return .{ .matched = result.matched_lines > 0, .matched_lines = result.matched_lines, .matches = result.matched_lines };
        },
    }
}

const Parsed = struct {
    pattern: []const u8 = "",
    /// `-e` 或 `-f` 出现过。这时位置参数全部是路径。
    explicit: bool = false,
    patterns: std.ArrayList([]const u8) = .empty,
    owned_patterns: std.ArrayList([]u8) = .empty,
    paths: std.ArrayList([]const u8) = .empty,
    line_numbers: bool = false,
    column: bool = false,
    force_path: bool = false,
    invert: bool = false,
    count: bool = false,
    quiet: bool = false,
    files_with_matches: bool = false,
    files_only: bool = false,
    json: bool = false,
    hidden: bool = false,
    no_ignore: bool = false,
    follow: bool = false,
    threads: u32 = 0,
    max_depth: ?u32 = null,
    max_filesize: ?u64 = null,
    globs: std.ArrayList([]const u8) = .empty,
    types: std.ArrayList([]const u8) = .empty,
    case_mode: zrg.CaseMode = .sensitive,
    before: u32 = 0,
    after: u32 = 0,
    max_count: ?u64 = null,
    binary: zrg.BinaryPolicy = .report,
    help: bool = false,

    fn deinit(self: *Parsed, allocator: std.mem.Allocator) void {
        for (self.owned_patterns.items) |item| allocator.free(item);
        self.owned_patterns.deinit(allocator);
        self.patterns.deinit(allocator);
        self.paths.deinit(allocator);
        self.globs.deinit(allocator);
        self.types.deinit(allocator);
    }
};

const ParseError = error{
    MissingValue,
    BadNumber,
    UnknownFlag,
    NoPattern,
    PatternFile,
    OutOfMemory,
    WriteFailed,
};

fn parse(allocator: std.mem.Allocator, io: std.Io, argv: []const []const u8, stderr: *std.Io.Writer) ParseError!Parsed {
    var parsed = Parsed{};
    errdefer parsed.deinit(allocator);
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, "--")) break;
        if (std.mem.eql(u8, arg, "--files")) parsed.files_only = true;
    }

    var positionals: std.ArrayList([]const u8) = .empty;
    defer positionals.deinit(allocator);
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
                index = try parseLong(allocator, io, &parsed, argv, index, stderr);
            } else {
                index = try parseShort(allocator, io, &parsed, argv, index, stderr);
            }
            continue;
        }
        try positionals.append(allocator, arg);
        index += 1;
    }

    if (parsed.help or parsed.files_only or parsed.explicit) {
        try parsed.paths.appendSlice(allocator, positionals.items);
    } else if (positionals.items.len == 0) {
        stderr.writeAll("zrg: 需要一个模式\n") catch {};
        return error.NoPattern;
    } else {
        parsed.pattern = positionals.items[0];
        try parsed.paths.appendSlice(allocator, positionals.items[1..]);
    }
    if (!parsed.help and !parsed.files_only and parsed.explicit and parsed.patterns.items.len == 0) {
        stderr.writeAll("zrg: 需要一个模式\n") catch {};
        return error.NoPattern;
    }
    return parsed;
}

fn parseShort(
    allocator: std.mem.Allocator,
    io: std.Io,
    parsed: *Parsed,
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
            'l' => parsed.files_with_matches = true,
            'A', 'B', 'C', 'm', 'e', 'f', 'j', 'g', 't' => {
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
                try applyShortValue(allocator, io, parsed, flag, value, stderr);
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
    allocator: std.mem.Allocator,
    io: std.Io,
    parsed: *Parsed,
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
        'e' => try addPattern(parsed, allocator, value),
        'f' => try addPatternFile(parsed, allocator, io, value, stderr),
        'j' => parsed.threads = try parseU32(value, stderr),
        'g' => try parsed.globs.append(allocator, value),
        't' => try appendType(parsed, allocator, value, stderr),
        else => return error.UnknownFlag,
    }
}

const LongValue = enum { after, before, context, max_count, color, threads, glob, type_name, max_depth, max_filesize, regexp, file };

fn parseLong(
    allocator: std.mem.Allocator,
    io: std.Io,
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
            .color => {},
            .threads => parsed.threads = try parseU32(value, stderr),
            .glob => try parsed.globs.append(allocator, value),
            .type_name => try appendType(parsed, allocator, value, stderr),
            .max_depth => parsed.max_depth = try parseU32(value, stderr),
            .max_filesize => parsed.max_filesize = try parseSize(value, stderr),
            .regexp => try addPattern(parsed, allocator, value),
            .file => try addPatternFile(parsed, allocator, io, value, stderr),
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
    if (std.mem.eql(u8, name, "glob")) return .glob;
    if (std.mem.eql(u8, name, "type")) return .type_name;
    if (std.mem.eql(u8, name, "max-depth")) return .max_depth;
    if (std.mem.eql(u8, name, "max-filesize")) return .max_filesize;
    if (std.mem.eql(u8, name, "regexp")) return .regexp;
    if (std.mem.eql(u8, name, "file")) return .file;
    return null;
}

fn addPattern(parsed: *Parsed, allocator: std.mem.Allocator, text: []const u8) ParseError!void {
    parsed.explicit = true;
    const copy = try allocator.dupe(u8, text);
    errdefer allocator.free(copy);
    try parsed.owned_patterns.append(allocator, copy);
    errdefer _ = parsed.owned_patterns.pop();
    try parsed.patterns.append(allocator, copy);
}

fn addPatternFile(
    parsed: *Parsed,
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    stderr: *std.Io.Writer,
) ParseError!void {
    parsed.explicit = true;
    const file = openInput(io, path) catch |err| {
        stderr.print("zrg: 打不开模式文件 {s}：{t}\n", .{ path, err }) catch {};
        return error.PatternFile;
    };
    defer file.close(io);
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    var buf: [8192]u8 = undefined;
    var off: u64 = 0;
    while (true) {
        var iov = [_][]u8{&buf};
        const n = file.readPositional(io, &iov, off) catch |err| {
            stderr.print("zrg: 打不开模式文件 {s}：{t}\n", .{ path, err }) catch {};
            return error.PatternFile;
        };
        if (n == 0) break;
        if (bytes.items.len + n > (1 << 20)) {
            stderr.print("zrg: 模式文件太大：{s}\n", .{path}) catch {};
            return error.PatternFile;
        }
        try bytes.appendSlice(allocator, buf[0..n]);
        off += n;
    }
    var i: usize = 0;
    while (i < bytes.items.len) {
        const nl = std.mem.indexOfScalarPos(u8, bytes.items, i, '\n') orelse bytes.items.len;
        var line = bytes.items[i..nl];
        if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
        try addPattern(parsed, allocator, line);
        if (nl == bytes.items.len) break;
        i = nl + 1;
    }
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
    } else if (std.mem.eql(u8, name, "files-with-matches")) {
        parsed.files_with_matches = true;
    } else if (std.mem.eql(u8, name, "files")) {
        parsed.files_only = true;
    } else if (std.mem.eql(u8, name, "json")) {
        parsed.json = true;
    } else if (std.mem.eql(u8, name, "hidden")) {
        parsed.hidden = true;
    } else if (std.mem.eql(u8, name, "no-ignore")) {
        parsed.no_ignore = true;
    } else if (std.mem.eql(u8, name, "follow")) {
        parsed.follow = true;
    } else if (std.mem.eql(u8, name, "fixed-strings") or
        std.mem.eql(u8, name, "no-config") or
        std.mem.eql(u8, name, "binary"))
    {
        // 显式文件保持 report。目录搜索在 parallel 里改成 quit，除非用户传了 -a。
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

fn appendType(parsed: *Parsed, allocator: std.mem.Allocator, value: []const u8, stderr: *std.Io.Writer) ParseError!void {
    if (zrg.walk_types.find(value) == null) {
        stderr.print("zrg: 未知的类型：{s}\n", .{value}) catch {};
        return error.UnknownFlag;
    }
    try parsed.types.append(allocator, value);
}

fn parseSize(text: []const u8, stderr: *std.Io.Writer) ParseError!u64 {
    if (text.len == 0) {
        stderr.writeAll("zrg: 需要大小\n") catch {};
        return error.BadNumber;
    }
    var body = text;
    var mul: u64 = 1;
    switch (text[text.len - 1]) {
        'K', 'k' => {
            mul = 1024;
            body = text[0 .. text.len - 1];
        },
        'M', 'm' => {
            mul = 1024 * 1024;
            body = text[0 .. text.len - 1];
        },
        'G', 'g' => {
            mul = 1024 * 1024 * 1024;
            body = text[0 .. text.len - 1];
        },
        else => {},
    }
    const n = std.fmt.parseInt(u64, body, 10) catch {
        stderr.print("zrg: 需要大小：{s}\n", .{text}) catch {};
        return error.BadNumber;
    };
    return std.math.mul(u64, n, mul) catch {
        stderr.print("zrg: 大小溢出：{s}\n", .{text}) catch {};
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
    try testing.expectEqual(@as(usize, 1024 * 1024), zrg.SearchConfig.default_buffer_size);
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
    try testing.expect(matched.matched);
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

fn sortedLines(text: []const u8) ![]u8 {
    var lines: std.ArrayList([]const u8) = .empty;
    defer lines.deinit(testing.allocator);
    var rest = text;
    while (rest.len > 0) {
        if (std.mem.indexOfScalar(u8, rest, '\n')) |nl| {
            if (nl > 0) try lines.append(testing.allocator, rest[0..nl]);
            rest = rest[nl + 1 ..];
        } else {
            try lines.append(testing.allocator, rest);
            break;
        }
    }
    std.mem.sort([]const u8, lines.items, {}, struct {
        fn less(_: void, a: []const u8, b: []const u8) bool {
            return std.mem.order(u8, a, b) == .lt;
        }
    }.less);
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(testing.allocator);
    for (lines.items) |line| {
        try out.appendSlice(testing.allocator, line);
        try out.append(testing.allocator, '\n');
    }
    return out.toOwnedSlice(testing.allocator);
}

fn expectSorted(z_args: []const []const u8, rg_args: []const []const u8) !void {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err_w: std.Io.Writer.Allocating = .init(testing.allocator);
    defer err_w.deinit();
    const code = execute(testing.allocator, testing.io, z_args, &out.writer, &err_w.writer);
    const rg = try std.process.run(testing.allocator, testing.io, .{ .argv = rg_args });
    defer testing.allocator.free(rg.stdout);
    defer testing.allocator.free(rg.stderr);
    const rg_code: u8 = switch (rg.term) {
        .exited => |exited| exited,
        else => return error.TestUnexpectedResult,
    };
    const z_sorted = try sortedLines(out.written());
    defer testing.allocator.free(z_sorted);
    const r_sorted = try sortedLines(rg.stdout);
    defer testing.allocator.free(r_sorted);
    if (rg.stderr.len != 0) std.debug.print("rg stderr: {s}\n", .{rg.stderr});
    if (err_w.written().len != 0) std.debug.print("zrg stderr: {s}\n", .{err_w.written()});
    try testing.expectEqualStrings("", rg.stderr);
    try testing.expectEqualStrings("", err_w.written());
    try testing.expectEqualStrings(r_sorted, z_sorted);
    try testing.expectEqual(rg_code, code);
}

fn dirRoot(dir: std.Io.Dir) ![]u8 {
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const n = try dir.realPath(testing.io, &buf);
    return testing.allocator.dupe(u8, buf[0..n]);
}

test "目录列表和搜索排序后与 rg 一致" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    try tmp.dir.createDir(io, "sub", .default_dir);
    try tmp.dir.createDir(io, "nested", .default_dir);
    try tmp.dir.createDir(io, "dir", .default_dir);
    try tmp.dir.createDir(io, ".git", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "keep.txt", .data = "needle\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "skip.log", .data = "needle\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "keep.log", .data = "needle\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/nope.txt", .data = "nope\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/keep.txt", .data = "needle\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "nested/a.zig", .data = "needle\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "nested/b.txt", .data = "nope\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "dir/keep.txt", .data = "needle\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = ".git/config", .data = "needle\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = ".gitignore", .data = "dir/\n*.log\n!keep.log\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "tiny.txt", .data = "x" });

    const root = try dirRoot(tmp.dir);
    defer testing.allocator.free(root);

    try expectSorted(&.{ "--files", root }, &.{ "rg", "--no-config", "--files", root });
    try expectSorted(&.{ "-F", "-j", "1", "needle", root }, &.{ "rg", "--no-config", "--color=never", "-F", "-j", "1", "needle", root });
    try expectSorted(&.{ "-F", "-j", "2", "needle", root }, &.{ "rg", "--no-config", "--color=never", "-F", "-j", "1", "needle", root });
    try expectSorted(&.{ "-F", "-g", "*.zig", "needle", root }, &.{ "rg", "--no-config", "--color=never", "-F", "-g", "*.zig", "needle", root });
    try expectSorted(&.{ "-F", "--max-depth", "1", "needle", root }, &.{ "rg", "--no-config", "--color=never", "-F", "--max-depth", "1", "needle", root });
    try expectSorted(&.{ "--files", "--max-filesize", "2", root }, &.{ "rg", "--no-config", "--files", "--max-filesize", "2", root });
    try expectSorted(&.{ "--files", "-t", "zig", root }, &.{ "rg", "--no-config", "--files", "-t", "zig", root });
    try expectSorted(&.{ "--files", "--no-ignore", root }, &.{ "rg", "--no-config", "--files", "--no-ignore", root });
    try expectSorted(&.{ "-F", "-l", "needle", root }, &.{ "rg", "--no-config", "--color=never", "-F", "-l", "needle", root });
    try expectSorted(&.{ "-c", "-F", "needle", root }, &.{ "rg", "--no-config", "--color=never", "-c", "-F", "needle", root });

    var hidden_out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer hidden_out.deinit();
    var hidden_err: std.Io.Writer.Allocating = .init(testing.allocator);
    defer hidden_err.deinit();
    const hidden_code = execute(testing.allocator, io, &.{ "--files", "--hidden", root }, &hidden_out.writer, &hidden_err.writer);
    try testing.expectEqual(@as(u8, 0), hidden_code);
    try testing.expect(std.mem.indexOf(u8, hidden_out.written(), ".gitignore") != null);
    try testing.expect(std.mem.indexOf(u8, hidden_out.written(), ".git/config") == null);

    var json_out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer json_out.deinit();
    var json_err: std.Io.Writer.Allocating = .init(testing.allocator);
    defer json_err.deinit();
    const json_code = execute(testing.allocator, io, &.{ "--json", "-F", "-j", "1", "needle", root }, &json_out.writer, &json_err.writer);
    try testing.expectEqual(@as(u8, 0), json_code);
    const json_text = json_out.written();
    try testing.expect(std.mem.indexOf(u8, json_text, "\"type\":\"summary\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_text, "keep.txt") != null);
    try testing.expect(std.mem.indexOf(u8, json_text, "nope.txt") == null);
    try testing.expect(std.mem.indexOf(u8, json_text, "skip.log") == null);
}

fn expectLiteral(args: []const []const u8) !void {
    var rg_args: std.ArrayList([]const u8) = .empty;
    defer rg_args.deinit(testing.allocator);
    try rg_args.appendSlice(testing.allocator, &.{ "rg", "--no-config", "--color=never" });
    try rg_args.appendSlice(testing.allocator, args);
    try expectArgv(args, rg_args.items);
}

fn expectArgv(z_args: []const []const u8, rg_args: []const []const u8) !void {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err_w: std.Io.Writer.Allocating = .init(testing.allocator);
    defer err_w.deinit();
    const code = execute(testing.allocator, testing.io, z_args, &out.writer, &err_w.writer);
    const rg = try std.process.run(testing.allocator, testing.io, .{ .argv = rg_args });
    defer testing.allocator.free(rg.stdout);
    defer testing.allocator.free(rg.stderr);
    const rg_code: u8 = switch (rg.term) {
        .exited => |exited| exited,
        else => return error.TestUnexpectedResult,
    };
    if (rg.stderr.len != 0) std.debug.print("rg stderr: {s}\n", .{rg.stderr});
    if (!std.mem.eql(u8, rg.stdout, out.written())) {
        std.debug.print("zrg:\n{s}\nrg:\n{s}\n", .{ out.written(), rg.stdout });
    }
    try testing.expectEqualStrings("", rg.stderr);
    try testing.expectEqualStrings("", err_w.written());
    try testing.expectEqualStrings(rg.stdout, out.written());
    try testing.expectEqual(rg_code, code);
}

test "多个 -e 和 -f 与 rg 的顺序一致" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "t.txt", .data = "foobar\naaa\nfoo\nBAR\nFoo\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "pats", .data = "foo\nbar\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "a.txt", .data = "foo\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b.txt", .data = "bar\n" });
    const file = try pathOf(tmp.dir, "t.txt");
    defer testing.allocator.free(file);
    const pats = try pathOf(tmp.dir, "pats");
    defer testing.allocator.free(pats);
    const root = try dirRoot(tmp.dir);
    defer testing.allocator.free(root);

    try expectLiteral(&.{ "-F", "--column", "-e", "foo", "-e", "foobar", file });
    try expectLiteral(&.{ "-F", "--column", "-e", "foobar", "-e", "foo", file });
    try expectLiteral(&.{ "-F", "-n", "--column", "-e", "aa", "-e", "a", file });
    try expectLiteral(&.{ "-F", "-n", "--column", "-e", "a", "-e", "aa", file });
    try expectLiteral(&.{ "-F", "-f", pats, file });
    try expectLiteral(&.{ "-F", "-S", "-e", "foo", "-e", "bar", file });
    try expectLiteral(&.{ "-F", "-S", "-e", "Foo", "-e", "bar", file });

    var json_out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer json_out.deinit();
    var json_err: std.Io.Writer.Allocating = .init(testing.allocator);
    defer json_err.deinit();
    const json_code = execute(testing.allocator, io, &.{ "--json", "-F", "-e", "foo", "-e", "foobar", file }, &json_out.writer, &json_err.writer);
    try testing.expectEqual(@as(u8, 0), json_code);
    try testing.expect(std.mem.indexOf(u8, json_out.written(), "\"text\":\"foo\"") != null);
    try testing.expect(std.mem.indexOf(u8, json_out.written(), "\"start\":0,\"end\":3") != null);
    try testing.expect(std.mem.indexOf(u8, json_out.written(), "\"text\":\"foobar\"") == null);

    var flipped: std.Io.Writer.Allocating = .init(testing.allocator);
    defer flipped.deinit();
    var flipped_err: std.Io.Writer.Allocating = .init(testing.allocator);
    defer flipped_err.deinit();
    const flipped_code = execute(testing.allocator, io, &.{ "--json", "-F", "-e", "foobar", "-e", "foo", file }, &flipped.writer, &flipped_err.writer);
    try testing.expectEqual(@as(u8, 0), flipped_code);
    try testing.expect(std.mem.indexOf(u8, flipped.written(), "\"text\":\"foobar\"") != null);
    try testing.expect(std.mem.indexOf(u8, flipped.written(), "\"start\":0,\"end\":6") != null);

    try expectSorted(
        &.{ "-F", "-j", "1", "-e", "foo", "-e", "bar", root },
        &.{ "rg", "--no-config", "--color=never", "-F", "-j", "1", "-e", "foo", "-e", "bar", root },
    );
}

test "父目录被忽略时 git check-ignore 也拒绝再包含" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const root = try dirRoot(tmp.dir);
    defer testing.allocator.free(root);
    const init_git = try std.process.run(testing.allocator, io, .{
        .argv = &.{ "git", "init", "-q" },
        .cwd = .{ .path = root },
    });
    defer testing.allocator.free(init_git.stdout);
    defer testing.allocator.free(init_git.stderr);
    try tmp.dir.createDir(io, "dir", .default_dir);
    try tmp.dir.createDir(io, "sub", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = ".gitignore", .data = "dir/\n*.log\n!keep.log\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "dir/keep.txt", .data = "a\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "keep.log", .data = "a\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "other.log", .data = "a\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "keep.txt", .data = "a\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/keep.log", .data = "a\n" });

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err_w: std.Io.Writer.Allocating = .init(testing.allocator);
    defer err_w.deinit();
    const code = execute(testing.allocator, io, &.{ "--files", root }, &out.writer, &err_w.writer);
    try testing.expectEqual(@as(u8, 0), code);
    const listed = out.written();

    const paths = [_][]const u8{ "dir/keep.txt", "keep.log", "other.log", "keep.txt", "sub/keep.log" };
    for (paths) |rel| {
        const checked = try std.process.run(testing.allocator, io, .{
            .argv = &.{ "git", "check-ignore", "-q", "--", rel },
            .cwd = .{ .path = root },
        });
        defer testing.allocator.free(checked.stdout);
        defer testing.allocator.free(checked.stderr);
        const ignored = switch (checked.term) {
            .exited => |exited| exited == 0,
            else => return error.TestUnexpectedResult,
        };
        const full = try std.fmt.allocPrint(testing.allocator, "{s}/{s}\n", .{ root, rel });
        defer testing.allocator.free(full);
        const shown = std.mem.indexOf(u8, listed, full) != null;
        try testing.expectEqual(!ignored, shown);
    }
}
