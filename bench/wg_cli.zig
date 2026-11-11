//! Standalone search CLI built on top of `libwebgrep` (`src/root.zig`) and `libwebgrep_internal` (`src/internal_root.zig`).
//! Supports `-c`, `-n`, `-F`, `-i`, `-a`/`--text`, `--binary`, `--no-binary`, `-g <glob>`, `-e <pat>`, `-j <threads>`,
//! `--no-config`, `--no-unicode`, `--no-ignore`, `--mmap`, and `--no-mmap`, emitting output format & exit codes identical to `rg`.

const std = @import("std");
const libwebgrep = @import("libwebgrep_internal");
const internal = libwebgrep;

const IoMode = enum { no_mmap, mmap };

const CliArgs = struct {
    count_only: bool = false,
    line_numbers: bool = false,
    fixed_strings: bool = false,
    ignore_case: bool = false,
    no_unicode: bool = false,
    no_ignore: bool = false,
    binary_policy: libwebgrep.BinaryPolicy = .quit,
    threads: u32 = 1,
    io_mode: IoMode = .no_mmap,
    globs: [16][]const u8 = undefined,
    globs_len: usize = 0,
    patterns: [32][]const u8 = undefined,
    patterns_len: usize = 0,
    target_path: []const u8 = "",
};

const CountSink = struct {};

const PrintSink = struct {
    out: *std.Io.Writer,
    prefix_path: ?[]const u8 = null,
    line_numbers: bool = false,

    pub fn matched(self: *PrintSink, line: libwebgrep.Line) bool {
        if (self.prefix_path) |p| {
            self.out.writeAll(p) catch return false;
            self.out.writeByte(':') catch return false;
        }
        if (self.line_numbers) {
            if (line.number) |num| {
                self.out.print("{d}:", .{num}) catch return false;
            }
        }
        self.out.writeAll(line.bytes) catch return false;
        self.out.writeByte('\n') catch return false;
        return true;
    }
};

const DirEventCtx = struct {
    out: *std.Io.Writer,
    count_only: bool,
    line_numbers: bool,

    fn onEvent(raw_ctx: *anyopaque, ev: libwebgrep.sink.Event) libwebgrep.sink.Flow {
        const self: *DirEventCtx = @ptrCast(@alignCast(raw_ctx));
        if (self.count_only) {
            switch (ev) {
                .end => |e| {
                    if (e.matched_lines > 0) {
                        self.out.print("{s}:{d}\n", .{ e.source_id, e.matched_lines }) catch return .stop;
                    }
                },
                else => {},
            }
        } else {
            switch (ev) {
                .match => |m| {
                    if (self.line_numbers) {
                        self.out.print("{s}:{d}:{s}\n", .{ m.source_id, m.line_number, m.bytes }) catch return .stop;
                    } else {
                        self.out.print("{s}:{s}\n", .{ m.source_id, m.bytes }) catch return .stop;
                    }
                },
                else => {},
            }
        }
        return .cont;
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
                if (cfg.binary != .quit or std.mem.indexOfScalar(u8, mapped.memory[0..@min(mapped.memory.len, 4096)], 0) == null) {
                    internal.platform.adviseMappedSequential(mapped.memory);
                }
                return switch (cm.*) {
                    .finder => |*f| libwebgrep.searchSlice(S, sink, mapped.memory, path, f, cfg),
                    .multi => |*m| libwebgrep.searchSlice(S, sink, mapped.memory, path, m, cfg),
                    .regex => |*r| libwebgrep.searchSlice(S, sink, mapped.memory, path, r, cfg),
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

    const cfg = libwebgrep.SearchConfig{
        .line_numbers = args.line_numbers,
        .binary = args.binary_policy,
        .buffer_size = libwebgrep.SearchConfig.optimalBufferSize(args.threads),
        .scratch_pool = scratch,
    };

    if (args.count_only) {
        var csink = CountSink{};
        const res = try searchSingleFileWithSink(CountSink, gpa, io, file, path, &csink, cm, cfg, args.io_mode);
        if (res.matched_lines > 0) {
            try stdout_writer.print("{d}\n", .{res.matched_lines});
            try stdout_writer.flush();
        }
        return res.matched_lines;
    } else {
        var psink = PrintSink{
            .out = stdout_writer,
            .prefix_path = null,
            .line_numbers = args.line_numbers,
        };
        const res = try searchSingleFileWithSink(PrintSink, gpa, io, file, path, &psink, cm, cfg, args.io_mode);
        return res.matched_lines;
    }
}

pub fn main(init: std.process.Init) !u8 {
    const gpa = init.gpa;
    const io = init.io;

    var cli = CliArgs{};
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
                if (cli.globs_len >= cli.globs.len) return 2;
                cli.globs[cli.globs_len] = g;
                cli.globs_len += 1;
                continue;
            } else if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--regexp")) {
                const p = argv_it.next() orelse return 2;
                if (cli.patterns_len >= cli.patterns.len) return 2;
                cli.patterns[cli.patterns_len] = p;
                cli.patterns_len += 1;
                continue;
            } else if (std.mem.eql(u8, arg, "-j") or std.mem.eql(u8, arg, "--threads")) {
                const j_str = argv_it.next() orelse return 2;
                cli.threads = std.fmt.parseInt(u32, j_str, 10) catch return 2;
                if (cli.threads == 0) cli.threads = 1;
                continue;
            } else if (arg.len > 1 and arg[0] == '-') {
                return 2;
            }
        }
        if (cli.patterns_len == 0 and positional_pat == null) {
            positional_pat = arg;
        } else {
            cli.target_path = arg;
        }
    }

    if (cli.patterns_len == 0) {
        if (positional_pat) |p| {
            cli.patterns[0] = p;
            cli.patterns_len = 1;
        } else return 2;
    }
    if (cli.target_path.len == 0) return 2;

    const case_mode: libwebgrep.CaseMode = if (cli.ignore_case) .insensitive else .sensitive;
    var cm: CompiledMatcher = if (cli.fixed_strings) blk: {
        if (cli.patterns_len == 1) {
            break :blk .{ .finder = try libwebgrep.Finder.init(cli.patterns[0], .{ .case = case_mode }) };
        } else {
            break :blk .{ .multi = try libwebgrep.Multi.init(gpa, cli.patterns[0..cli.patterns_len], .{ .case = case_mode }) };
        }
    } else blk: {
        if (cli.patterns_len == 1) {
            break :blk .{ .regex = libwebgrep.Regex.init(gpa, cli.patterns[0], .{
                .case = case_mode,
                .unicode_case = !cli.no_unicode,
            }) catch return 2 };
        } else {
            var total_len: usize = 0;
            for (cli.patterns[0..cli.patterns_len], 0..) |pat, idx| {
                if (idx > 0) total_len += 1;
                total_len += 4 + pat.len;
            }
            const joined = try gpa.alloc(u8, total_len);
            defer gpa.free(joined);
            var pos: usize = 0;
            for (cli.patterns[0..cli.patterns_len], 0..) |pat, idx| {
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
            }) catch return 2 };
        }
    };
    defer cm.deinit();

    var stdout_buf: [65536]u8 = undefined;
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
        var dir_ctx = DirEventCtx{
            .out = &stdout_fw.interface,
            .count_only = cli.count_only,
            .line_numbers = cli.line_numbers,
        };
        const stats = try internal.parallel.run(gpa, io, .{
            .pattern = if (cli.fixed_strings and cli.patterns_len == 1) cli.patterns[0] else "",
            .patterns = if (cli.fixed_strings and cli.patterns_len > 1) cli.patterns[0..cli.patterns_len] else &.{},
            .regex = switch (cm) {
                .regex => |*r| r,
                else => null,
            },
            .find = .{ .case = case_mode },
            .roots = &roots,
            .search = .{
                .line_numbers = cli.line_numbers,
                .binary = cli.binary_policy,
                .buffer_size = libwebgrep.SearchConfig.optimalBufferSize(cli.threads),
                .max_concurrency = cli.threads,
            },
            .walk = .{
                .threads = cli.threads,
                .read_ignore = !cli.no_ignore,
                .globs = cli.globs[0..cli.globs_len],
            },
            .enforce_service_budgets = false,
            .use_mmap = (cli.io_mode == .mmap),
            .count_lines_only = cli.count_only,
            .emit = if (cli.count_only) .count else .text,
            .stdout = &stdout_fw.interface,
            .saw_output = &saw_output,
            .on_event = DirEventCtx.onEvent,
            .event_ctx = &dir_ctx,
        });
        try stdout_fw.interface.flush();
        total_matched = stats.matched_lines;
    }

    return if (total_matched > 0) 0 else 1;
}
