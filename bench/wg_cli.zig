//! Standalone search CLI built on top of `libwebgrep` (`src/root.zig`) and `libwebgrep_internal` (`src/internal_root.zig`).
//! Supports `-c`, `-n`, `-F`, `-i`, `-v`, `-w`, `-C <n>`, `-f <file>`, `-a`/`--text`, `--binary`, `--no-binary`,
//! `-g <glob>`, `-e <pat>`, `-j <threads>`, `--no-config`, `--no-unicode`, `--no-ignore`, `--mmap`, and `--no-mmap`,
//! emitting output format & exit codes identical to `rg`.

const std = @import("std");
const libwebgrep = @import("libwebgrep_internal");
const internal = libwebgrep;

const IoMode = enum { no_mmap, mmap };

const CliArgs = struct {
    count_only: bool = false,
    line_numbers: bool = false,
    fixed_strings: bool = false,
    ignore_case: bool = false,
    invert: bool = false,
    whole_word: bool = false,
    context: u32 = 0,
    multiline: bool = false,
    multiline_dotall: bool = false,
    no_unicode: bool = false,
    no_ignore: bool = false,
    binary_policy: libwebgrep.BinaryPolicy = .quit,
    threads: u32 = 1,
    io_mode: IoMode = .no_mmap,
    globs: std.ArrayList([]const u8) = .empty,
    patterns: std.ArrayList([]const u8) = .empty,
    pattern_file_bufs: std.ArrayList([]u8) = .empty,
    saw_pattern_flag: bool = false,
    target_path: []const u8 = "",

    pub fn deinit(self: *CliArgs, allocator: std.mem.Allocator) void {
        self.globs.deinit(allocator);
        self.patterns.deinit(allocator);
        for (self.pattern_file_bufs.items) |buf| allocator.free(buf);
        self.pattern_file_bufs.deinit(allocator);
    }
};

const CountSink = struct {};

const PrintSink = struct {
    pub const matched_fast_line = true;

    out: *std.Io.Writer,
    file_path: []const u8 = "",
    prefix_path: ?[]const u8 = null,
    line_numbers: bool = false,

    fn writeLine(self: *PrintSink, line: libwebgrep.Line, sep: u8) bool {
        if (line.binary_status == .detected) return false;
        if ((self.prefix_path != null or self.line_numbers) and std.mem.findScalar(u8, line.bytes, '\n') != null) {
            var it = std.mem.splitScalar(u8, line.bytes, '\n');
            var idx: u64 = 0;
            while (it.next()) |sub| : (idx += 1) {
                if (self.prefix_path) |p| {
                    self.out.writeAll(p) catch return false;
                    self.out.writeByte(sep) catch return false;
                }
                if (self.line_numbers) {
                    if (line.number) |num| {
                        self.out.print("{d}{c}", .{ num + idx, sep }) catch return false;
                    }
                }
                self.out.writeAll(sub) catch return false;
                self.out.writeByte('\n') catch return false;
            }
            return true;
        }
        if (self.prefix_path) |p| {
            self.out.writeAll(p) catch return false;
            self.out.writeByte(sep) catch return false;
        }
        if (self.line_numbers) {
            if (line.number) |num| {
                self.out.print("{d}{c}", .{ num, sep }) catch return false;
            }
        }
        self.out.writeAll(line.bytes) catch return false;
        self.out.writeByte('\n') catch return false;
        return true;
    }

    pub fn matched(self: *PrintSink, line: libwebgrep.Line) bool {
        return self.writeLine(line, ':');
    }

    pub fn context(self: *PrintSink, line: libwebgrep.Line) bool {
        return self.writeLine(line, '-');
    }

    pub fn contextBreak(self: *PrintSink) bool {
        self.out.writeAll("--\n") catch return false;
        return true;
    }

    pub fn finish(self: *PrintSink, res: libwebgrep.Result) bool {
        if (res.outcome == .binary_matched) {
            self.out.print("Binary file {s} matches\n", .{self.file_path}) catch return false;
        }
        return true;
    }
};

const CompiledMatcher = union(enum) {
    finder: libwebgrep.Finder,
    multi: libwebgrep.Multi,
    regex: libwebgrep.Regex,

    fn deinit(self: *CompiledMatcher) void {
        switch (self.*) {
            .finder => {},
            .multi => |*m| m.deinit(),
            .regex => |*r| r.deinit(),
        }
    }
};

const FileRa = struct {
    file: std.Io.File,
    io: std.Io,

    fn readAt(ctx: ?*anyopaque, offset: u64, dest: []u8) anyerror!usize {
        const self: *FileRa = @ptrCast(@alignCast(ctx.?));
        return self.file.readPositional(self.io, &.{dest}, offset);
    }
};

fn searchSingleFileWithSink(
    comptime S: type,
    gpa: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
    path: []const u8,
    sink: *S,
    cm: *const CompiledMatcher,
    cfg: libwebgrep.SearchConfig,
    io_mode: IoMode,
    threads: u32,
) !libwebgrep.Result {
    if (io_mode == .mmap) {
        const st = try file.stat(io);
        if (st.kind == .file and st.size > 0 and st.size <= std.math.maxInt(usize)) {
            var mm = std.Io.File.MemoryMap.create(io, file, .{
                .len = @intCast(st.size),
                .offset = 0,
                .protection = .{ .read = true, .write = false },
                .populate = false,
            }) catch null;
            if (mm) |*mapped| {
                defer mapped.destroy(io);
                if (cfg.binary != .quit or std.mem.findScalar(u8, mapped.memory[0..@min(mapped.memory.len, 4096)], 0) == null) {
                    internal.platform.adviseMappedSequential(mapped.memory);
                }
                if (threads > 1 and mapped.memory.len >= 512 * 1024) {
                    return switch (cm.*) {
                        .finder => |*f| internal.searchSliceParallel(S, gpa, io, sink, mapped.memory, path, f, cfg, .{ .workers = threads }),
                        .multi => |*m| internal.searchSliceParallel(S, gpa, io, sink, mapped.memory, path, m, cfg, .{ .workers = threads }),
                        .regex => |*r| internal.searchSliceParallel(S, gpa, io, sink, mapped.memory, path, r, cfg, .{ .workers = threads }),
                    };
                }
                return switch (cm.*) {
                    .finder => |*f| libwebgrep.searchSlice(S, sink, mapped.memory, path, f, cfg),
                    .multi => |*m| libwebgrep.searchSlice(S, sink, mapped.memory, path, m, cfg),
                    .regex => |*r| libwebgrep.searchSlice(S, sink, mapped.memory, path, r, cfg),
                };
            }
        }
    } else if (threads > 1) {
        const st = file.stat(io) catch null;
        if (st) |info| {
            if (info.kind == .file and info.size >= 512 * 1024) {
                var fra = FileRa{ .file = file, .io = io };
                const ra = internal.probe.RandomAccess{
                    .ctx = &fra,
                    .read_at = FileRa.readAt,
                    .size = info.size,
                };
                return switch (cm.*) {
                    .finder => |*f| internal.searchParallelAt(S, gpa, io, sink, ra, path, f, cfg, .{ .workers = threads }),
                    .multi => |*m| internal.searchParallelAt(S, gpa, io, sink, ra, path, m, cfg, .{ .workers = threads }),
                    .regex => |*r| internal.searchParallelAt(S, gpa, io, sink, ra, path, r, cfg, .{ .workers = threads }),
                };
            }
        }
    }

    return switch (cm.*) {
        .finder => |*f| internal.searchFile(S, gpa, io, sink, file, path, f, cfg),
        .multi => |*m| internal.searchFile(S, gpa, io, sink, file, path, m, cfg),
        .regex => |*r| internal.searchFile(S, gpa, io, sink, file, path, r, cfg),
    };
}

fn loadPatternFile(gpa: std.mem.Allocator, io: std.Io, path: []const u8, cli: *CliArgs) !void {
    const data = try std.Io.Dir.cwd().readFileAlloc(io, path, gpa, .limited(64 * 1024 * 1024));
    errdefer gpa.free(data);
    try cli.pattern_file_bufs.append(gpa, data);
    if (data.len == 0) return;
    const body = if (data[data.len - 1] == '\n') data[0 .. data.len - 1] else data;
    var it = std.mem.splitScalar(u8, body, '\n');
    while (it.next()) |raw_line| {
        const pat = if (raw_line.len > 0 and raw_line[raw_line.len - 1] == '\r')
            raw_line[0 .. raw_line.len - 1]
        else
            raw_line;
        try cli.patterns.append(gpa, pat);
    }
}

fn searchOneFile(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    args: *const CliArgs,
    cm: *const CompiledMatcher,
    scratch: *libwebgrep.Scratch,
    stdout_writer: *std.Io.Writer,
) !u64 {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| {
        var err_buf: [512]u8 = undefined;
        var err_fw = std.Io.File.stderr().writerStreaming(io, &err_buf);
        err_fw.interface.print("{s}: {s}\n", .{ path, @errorName(err) }) catch {};
        err_fw.interface.flush() catch {};
        return err;
    };
    defer file.close(io);

    const ctx_lines: u32 = if (args.count_only) 0 else args.context;
    const cfg = libwebgrep.SearchConfig{
        .line_numbers = args.line_numbers,
        .invert = args.invert,
        .whole_word = args.whole_word,
        .context = ctx_lines,
        .max_context_lines = if (ctx_lines > libwebgrep.SearchConfig.context_lines_hard_cap) ctx_lines else null,
        .multiline = args.multiline,
        .match_mode = if (args.multiline) .leftmost_first else .earliest,
        .binary = args.binary_policy,
        .buffer_size = libwebgrep.SearchConfig.optimalBufferSize(args.threads),
        .scratch_pool = scratch,
    };

    if (args.count_only) {
        var csink = CountSink{};
        const res = try searchSingleFileWithSink(CountSink, gpa, io, file, path, &csink, cm, cfg, args.io_mode, args.threads);
        if (res.matched_lines > 0) {
            try stdout_writer.print("{d}\n", .{res.matched_lines});
            try stdout_writer.flush();
        }
        return res.matched_lines;
    } else {
        var psink = PrintSink{
            .out = stdout_writer,
            .file_path = path,
            .prefix_path = null,
            .line_numbers = args.line_numbers,
        };
        const res = try searchSingleFileWithSink(PrintSink, gpa, io, file, path, &psink, cm, cfg, args.io_mode, args.threads);
        return res.matched_lines;
    }
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = std.heap.smp_allocator;
    const io = init.io;

    var cli = CliArgs{};
    defer cli.deinit(gpa);
    var argv_it = try init.minimal.args.iterateAllocator(gpa);
    defer argv_it.deinit();
    _ = argv_it.next(); // skip argv[0]

    var positional_pat: ?[]const u8 = null;
    var end_of_flags = false;
    while (argv_it.next()) |arg| {
        if (!end_of_flags) {
            if (std.mem.eql(u8, arg, "--")) {
                end_of_flags = true;
                continue;
            } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--count")) {
                cli.count_only = true;
                continue;
            } else if (std.mem.eql(u8, arg, "-n") or std.mem.eql(u8, arg, "--line-number")) {
                cli.line_numbers = true;
                continue;
            } else if (std.mem.eql(u8, arg, "-F") or std.mem.eql(u8, arg, "--fixed-strings")) {
                cli.fixed_strings = true;
                continue;
            } else if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--ignore-case")) {
                cli.ignore_case = true;
                continue;
            } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--invert-match")) {
                cli.invert = true;
                continue;
            } else if (std.mem.eql(u8, arg, "-w") or std.mem.eql(u8, arg, "--word-regexp")) {
                cli.whole_word = true;
                continue;
            } else if (std.mem.eql(u8, arg, "-C") or std.mem.eql(u8, arg, "--context")) {
                const c_str = argv_it.next() orelse return 2;
                cli.context = std.fmt.parseInt(u32, c_str, 10) catch return 2;
                continue;
            } else if (std.mem.startsWith(u8, arg, "--context=")) {
                cli.context = std.fmt.parseInt(u32, arg["--context=".len..], 10) catch return 2;
                continue;
            } else if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--file")) {
                const f_path = argv_it.next() orelse return 2;
                cli.saw_pattern_flag = true;
                loadPatternFile(gpa, io, f_path, &cli) catch return 2;
                continue;
            } else if (std.mem.startsWith(u8, arg, "--file=")) {
                cli.saw_pattern_flag = true;
                loadPatternFile(gpa, io, arg["--file=".len..], &cli) catch return 2;
                continue;
            } else if (std.mem.eql(u8, arg, "-U") or std.mem.eql(u8, arg, "--multiline")) {
                cli.multiline = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-multiline")) {
                cli.multiline = false;
                continue;
            } else if (std.mem.eql(u8, arg, "--multiline-dotall")) {
                cli.multiline_dotall = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-multiline-dotall")) {
                cli.multiline_dotall = false;
                continue;
            } else if (std.mem.eql(u8, arg, "-a") or std.mem.eql(u8, arg, "--text")) {
                cli.binary_policy = .none;
                continue;
            } else if (std.mem.eql(u8, arg, "--binary")) {
                cli.binary_policy = .report;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-binary")) {
                cli.binary_policy = .quit;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-unicode")) {
                cli.no_unicode = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-ignore")) {
                cli.no_ignore = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-config")) {
                continue;
            } else if (std.mem.eql(u8, arg, "--mmap")) {
                cli.io_mode = .mmap;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-mmap")) {
                cli.io_mode = .no_mmap;
                continue;
            } else if (std.mem.eql(u8, arg, "-g") or std.mem.eql(u8, arg, "--glob")) {
                const g = argv_it.next() orelse return 2;
                try cli.globs.append(gpa, g);
                continue;
            } else if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--regexp")) {
                const p = argv_it.next() orelse return 2;
                cli.saw_pattern_flag = true;
                try cli.patterns.append(gpa, p);
                continue;
            } else if (std.mem.eql(u8, arg, "-j") or std.mem.eql(u8, arg, "--threads")) {
                const j_str = argv_it.next() orelse return 2;
                cli.threads = std.fmt.parseInt(u32, j_str, 10) catch return 2;
                if (cli.threads == 0) cli.threads = 1;
                continue;
            } else if (arg.len > 2 and arg[0] == '-' and arg[1] != '-') {
                var i: usize = 1;
                while (i < arg.len) : (i += 1) {
                    switch (arg[i]) {
                        'c' => cli.count_only = true,
                        'n' => cli.line_numbers = true,
                        'F' => cli.fixed_strings = true,
                        'i' => cli.ignore_case = true,
                        'v' => cli.invert = true,
                        'w' => cli.whole_word = true,
                        'a' => cli.binary_policy = .none,
                        'U' => cli.multiline = true,
                        'C' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse return 2);
                            cli.context = std.fmt.parseInt(u32, val, 10) catch return 2;
                            break;
                        },
                        'f' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse return 2);
                            cli.saw_pattern_flag = true;
                            loadPatternFile(gpa, io, val, &cli) catch return 2;
                            break;
                        },
                        'e' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse return 2);
                            cli.saw_pattern_flag = true;
                            try cli.patterns.append(gpa, val);
                            break;
                        },
                        'g' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse return 2);
                            try cli.globs.append(gpa, val);
                            break;
                        },
                        'j' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse return 2);
                            cli.threads = std.fmt.parseInt(u32, val, 10) catch return 2;
                            if (cli.threads == 0) cli.threads = 1;
                            break;
                        },
                        else => return 2,
                    }
                }
                continue;
            } else if (arg.len > 1 and arg[0] == '-') {
                return 2;
            }
        }
        if (!cli.saw_pattern_flag and positional_pat == null) {
            positional_pat = arg;
        } else {
            cli.target_path = arg;
        }
    }

    if (cli.saw_pattern_flag) {
        if (cli.target_path.len == 0) {
            if (positional_pat) |p| {
                cli.target_path = p;
                positional_pat = null;
            }
        }
    } else if (cli.patterns.items.len == 0) {
        if (positional_pat) |p| {
            try cli.patterns.append(gpa, p);
        } else return 2;
    }
    if (cli.target_path.len == 0) return 2;
    if (cli.patterns.items.len == 0) {
        if (!cli.invert) return 1;
        // With -v and an empty pattern file, no line matches any pattern, so every line is an inverted match.
        // Use a never-matching regex ([^\s\S]) so all lines are emitted identically to `rg -v -f /dev/null`.
        cli.fixed_strings = false;
        try cli.patterns.append(gpa, "a^");
    }

    var total_pattern_bytes: usize = 0;
    for (cli.patterns.items) |pat| total_pattern_bytes += pat.len;

    const case_mode: libwebgrep.CaseMode = if (cli.ignore_case) .insensitive else .sensitive;
    const max_pat_count: usize = @max(@as(usize, 1024), cli.patterns.items.len);
    const max_pat_bytes: usize = @max(@as(usize, 256 * 1024), total_pattern_bytes);
    const find_opts = libwebgrep.FindOptions{
        .case = case_mode,
        .unicode_case = !cli.no_unicode,
        .multiline = cli.multiline,
        .max_pattern_count = max_pat_count,
        .max_pattern_bytes = max_pat_bytes,
    };
    var cm: CompiledMatcher = if (cli.fixed_strings) blk: {
        if (cli.patterns.items.len == 1) {
            break :blk .{ .finder = libwebgrep.Finder.init(cli.patterns.items[0], find_opts) catch return 2 };
        } else {
            break :blk .{ .multi = libwebgrep.Multi.init(gpa, cli.patterns.items, find_opts) catch return 2 };
        }
    } else blk: {
        if (cli.patterns.items.len == 1) {
            break :blk .{ .regex = libwebgrep.Regex.init(gpa, cli.patterns.items[0], .{
                .case = case_mode,
                .unicode_case = !cli.no_unicode,
                .unicode_classes = !cli.no_unicode,
                .multiline = cli.multiline,
                .dot_all = cli.multiline_dotall,
            }) catch return 2 };
        } else {
            var total_len: usize = 0;
            for (cli.patterns.items, 0..) |pat, idx| {
                if (idx > 0) total_len += 1;
                total_len += 4 + pat.len;
            }
            const joined = try gpa.alloc(u8, total_len);
            defer gpa.free(joined);
            var pos: usize = 0;
            for (cli.patterns.items, 0..) |pat, idx| {
                if (idx > 0) {
                    joined[pos] = '|';
                    pos += 1;
                }
                @memcpy(joined[pos .. pos + 3], "(?:");
                pos += 3;
                @memcpy(joined[pos .. pos + pat.len], pat);
                pos += pat.len;
                joined[pos] = ')';
                pos += 1;
            }
            break :blk .{ .regex = libwebgrep.Regex.init(gpa, joined, .{
                .case = case_mode,
                .unicode_case = !cli.no_unicode,
                .unicode_classes = !cli.no_unicode,
                .multiline = cli.multiline,
                .dot_all = cli.multiline_dotall,
                .max_inst = @max(@as(usize, 8192), joined.len * 4),
                .max_pattern_count = max_pat_count,
                .max_pattern_bytes = max_pat_bytes,
            }) catch return 2 };
        }
    };
    defer cm.deinit();

    var stdout_buf: [256 * 1024]u8 = undefined;
    var stdout_fw = std.Io.File.stdout().writerStreaming(io, &stdout_buf);

    var is_dir = false;
    if (std.Io.Dir.cwd().openDir(io, cli.target_path, .{})) |d| {
        var dir = d;
        dir.close(io);
        is_dir = true;
    } else |_| {}

    var total_matched: u64 = 0;
    if (!is_dir) {
        var scratch = libwebgrep.Scratch.init(gpa);
        defer scratch.deinit();
        total_matched = searchOneFile(gpa, io, cli.target_path, &cli, &cm, &scratch, &stdout_fw.interface) catch return 2;
        try stdout_fw.interface.flush();
    } else {
        var saw_output = false;
        const roots = [_][]const u8{cli.target_path};
        const ctx_lines: u32 = if (cli.count_only) 0 else cli.context;
        const stats = try internal.parallel.run(gpa, io, .{
            .pattern = if (cli.fixed_strings and cli.patterns.items.len == 1) cli.patterns.items[0] else "",
            .patterns = if (cli.fixed_strings and cli.patterns.items.len > 1) cli.patterns.items else &.{},
            .regex = switch (cm) {
                .regex => |*r| r,
                else => null,
            },
            .find = find_opts,
            .roots = &roots,
            .search = .{
                .line_numbers = cli.line_numbers,
                .invert = cli.invert,
                .whole_word = cli.whole_word,
                .context = ctx_lines,
                .max_context_lines = if (ctx_lines > libwebgrep.SearchConfig.context_lines_hard_cap) ctx_lines else null,
                .multiline = cli.multiline,
                .match_mode = if (cli.multiline) .leftmost_first else .earliest,
                .binary = cli.binary_policy,
                .buffer_size = libwebgrep.SearchConfig.optimalBufferSize(cli.threads),
                .max_concurrency = cli.threads,
            },
            .walk = .{
                .threads = cli.threads,
                .read_ignore = !cli.no_ignore,
                .globs = cli.globs.items,
            },
            .enforce_service_budgets = false,
            .use_mmap = (cli.io_mode == .mmap),
            .count_lines_only = cli.count_only,
            .emit = if (cli.count_only) .count else .text,
            .stdout = &stdout_fw.interface,
            .saw_output = &saw_output,
            .write_output = true,
        });
        try stdout_fw.interface.flush();
        total_matched = stats.matched_lines;
    }

    return if (total_matched > 0) 0 else 1;
}
