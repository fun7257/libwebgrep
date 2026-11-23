//! Standalone search CLI built on top of `libwebgrep` (`src/root.zig`) and `libwebgrep_internal` (`src/internal_root.zig`).
//! Supports `-c`, `-n`, `-F`, `-i`, `-s`, `-S`, `-v`, `-w`, `-x`, `-o`, `-r`, `-l`, `-m`, `-A`, `-B`, `-C`,
//! `-f`, `-e`, `-g`, `-t`, `-T`, `--type-list`, `-U`, `--multiline-dotall`, `-z`, `-E`, `-L`/`--follow`,
//! `--files`, `--sort`/`--sortr`, `-a`/`--text`, `--binary`, `--no-binary`, `-j`, `--no-config`,
//! `--no-unicode`, `--no-ignore`, `--mmap`, and `--no-mmap`, emitting output format & exit codes identical to `rg`.

const std = @import("std");
const libwebgrep = @import("libwebgrep_internal");
const internal = libwebgrep;

const IoMode = enum { no_mmap, mmap };

const CliArgs = struct {
    count_only: bool = false,
    files_with_matches: bool = false,
    files_only: bool = false,
    type_list: bool = false,
    line_numbers: bool = false,
    fixed_strings: bool = false,
    case_mode: libwebgrep.CaseMode = .sensitive,
    invert: bool = false,
    whole_word: bool = false,
    whole_line: bool = false,
    only_matching: bool = false,
    replacement: ?[]const u8 = null,
    context: u32 = 0,
    before_context: ?u32 = null,
    after_context: ?u32 = null,
    max_count: ?u64 = null,
    multiline: bool = false,
    multiline_dotall: bool = false,
    no_unicode: bool = false,
    no_ignore: bool = false,
    follow_symlinks: bool = false,
    search_zip: bool = false,
    encoding: internal.encoding.Encoding = .auto,
    sort_by: internal.walker.SortBy = .none,
    binary_policy: libwebgrep.BinaryPolicy = .quit,
    threads: u32 = 1,
    io_mode: IoMode = .no_mmap,
    globs: std.ArrayList([]const u8) = .empty,
    types: std.ArrayList([]const u8) = .empty,
    types_not: std.ArrayList([]const u8) = .empty,
    patterns: std.ArrayList([]const u8) = .empty,
    pattern_file_bufs: std.ArrayList([]u8) = .empty,
    saw_pattern_flag: bool = false,
    target_path: []const u8 = "",

    pub fn deinit(self: *CliArgs, allocator: std.mem.Allocator) void {
        self.globs.deinit(allocator);
        self.types.deinit(allocator);
        self.types_not.deinit(allocator);
        self.patterns.deinit(allocator);
        for (self.pattern_file_bufs.items) |buf| allocator.free(buf);
        self.pattern_file_bufs.deinit(allocator);
    }
};

const CountSink = struct {};

const PrintMode = enum {
    line,
    replace,
    only_matching,
    only_matching_replace,
};

fn PrintSink(comptime mode: PrintMode) type {
    return struct {
        pub const matched_fast_line = (mode == .line);
        pub const matched_raw_spans = (mode != .line);
        pub const only_matching_replace = (mode == .only_matching_replace);

        out: *std.Io.Writer,
        file_path: []const u8 = "",
        prefix_path: ?[]const u8 = null,
        line_numbers: bool = false,
        multiline: bool = false,

        inline fn writeFastBytes(out: *std.Io.Writer, bytes: []const u8) bool {
            const need = bytes.len + 1;
            if (out.end + need <= out.buffer.len) {
                const dst = out.buffer[out.end .. out.end + need];
                @memcpy(dst[0..bytes.len], bytes);
                dst[bytes.len] = '\n';
                out.end += need;
                return true;
            }
            out.writeAll(bytes) catch return false;
            out.writeByte('\n') catch return false;
            return true;
        }

        inline fn writeFastNumberedBytes(out: *std.Io.Writer, num: u64, sep: u8, bytes: []const u8) bool {
            const max_need = 22 + bytes.len;
            if (out.end + max_need <= out.buffer.len) {
                const nlen = std.fmt.printInt(out.buffer[out.end..], num, 10, .lower, .{});
                var pos = out.end + nlen;
                out.buffer[pos] = sep;
                pos += 1;
                @memcpy(out.buffer[pos .. pos + bytes.len], bytes);
                pos += bytes.len;
                out.buffer[pos] = '\n';
                out.end = pos + 1;
                return true;
            }
            out.print("{d}{c}", .{ num, sep }) catch return false;
            out.writeAll(bytes) catch return false;
            out.writeByte('\n') catch return false;
            return true;
        }

        fn writeBytes(self: *@This(), bytes: []const u8, base_line_num: ?u64, sep: u8) bool {
            if (self.prefix_path == null and !self.line_numbers) {
                return writeFastBytes(self.out, bytes);
            }
            if (std.mem.findScalar(u8, bytes, '\n') != null) {
                var it = std.mem.splitScalar(u8, bytes, '\n');
                var idx: u64 = 0;
                while (it.next()) |sub| : (idx += 1) {
                    if (self.prefix_path) |p| {
                        self.out.writeAll(p) catch return false;
                        self.out.writeByte(sep) catch return false;
                        if (self.line_numbers) {
                            if (base_line_num) |num| {
                                self.out.print("{d}{c}", .{ num + idx, sep }) catch return false;
                            }
                        }
                        if (!writeFastBytes(self.out, sub)) return false;
                    } else if (self.line_numbers) {
                        if (base_line_num) |num| {
                            if (!writeFastNumberedBytes(self.out, num + idx, sep, sub)) return false;
                        } else {
                            if (!writeFastBytes(self.out, sub)) return false;
                        }
                    } else {
                        if (!writeFastBytes(self.out, sub)) return false;
                    }
                }
                return true;
            }
            if (self.prefix_path) |p| {
                self.out.writeAll(p) catch return false;
                self.out.writeByte(sep) catch return false;
                if (self.line_numbers) {
                    if (base_line_num) |num| {
                        self.out.print("{d}{c}", .{ num, sep }) catch return false;
                    }
                }
                return writeFastBytes(self.out, bytes);
            }
            if (self.line_numbers) {
                if (base_line_num) |num| {
                    return writeFastNumberedBytes(self.out, num, sep, bytes);
                }
            }
            return writeFastBytes(self.out, bytes);
        }

        pub fn matched(self: *@This(), line: libwebgrep.Line) bool {
            if (line.binary_status == .detected) return false;
            switch (mode) {
                .line => return self.writeBytes(line.bytes, line.number, ':'),
                .replace => return self.writeBytes(line.replaced orelse line.bytes, line.number, ':'),
                .only_matching, .only_matching_replace => {
                    if (self.prefix_path == null and !self.line_numbers) {
                        for (line.matches) |sp| {
                            const from = @min(sp.start, line.bytes.len);
                            const to = @min(@max(sp.end, from), line.bytes.len);
                            const seg = if (mode == .only_matching_replace)
                                (sp.replacement orelse line.bytes[from..to])
                            else
                                line.bytes[from..to];
                            if (!writeFastBytes(self.out, seg)) return false;
                        }
                        return true;
                    }
                    var prev_pos: usize = 0;
                    var nl_acc: u64 = 0;
                    for (line.matches) |sp| {
                        const from = @min(sp.start, line.bytes.len);
                        const to = @min(@max(sp.end, from), line.bytes.len);
                        const seg = if (mode == .only_matching_replace)
                            (sp.replacement orelse line.bytes[from..to])
                        else
                            line.bytes[from..to];
                        const base_ln: ?u64 = if (self.line_numbers) blk: {
                            const n = line.number orelse break :blk null;
                            if (self.multiline and from > prev_pos) {
                                nl_acc += internal.memchr.count(internal.memchr.native_width, line.bytes, prev_pos, from, '\n');
                                prev_pos = from;
                            }
                            break :blk n + nl_acc;
                        } else null;
                        if (!self.writeBytes(seg, base_ln, ':')) return false;
                    }
                    return true;
                },
            }
        }

        pub fn context(self: *@This(), line: libwebgrep.Line) bool {
            if (line.binary_status == .detected) return false;
            return self.writeBytes(line.bytes, line.number, '-');
        }

        pub fn contextBreak(self: *@This()) bool {
            self.out.writeAll("--\n") catch return false;
            return true;
        }

        pub fn finish(self: *@This(), res: libwebgrep.Result) bool {
            if (res.outcome == .binary_matched) {
                self.out.print("Binary file {s} matches\n", .{self.file_path}) catch return false;
            }
            return true;
        }
    };
}

const CompiledMatcher = union(enum) {
    none,
    finder: libwebgrep.Finder,
    multi: libwebgrep.Multi,
    regex: libwebgrep.Regex,
    regex_set: libwebgrep.RegexSet,

    fn deinit(self: *CompiledMatcher) void {
        switch (self.*) {
            .none, .finder => {},
            .multi => |*m| m.deinit(),
            .regex => |*r| r.deinit(),
            .regex_set => |*rs| rs.deinit(),
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

const StderrLogger = struct {
    io: std.Io,
    mu: std.Io.Mutex = .init,

    fn log(ctx: ?*anyopaque, msg: []const u8) void {
        const self: *StderrLogger = @ptrCast(@alignCast(ctx orelse return));
        self.mu.lockUncancelable(self.io);
        defer self.mu.unlock(self.io);
        var buf: [512]u8 = undefined;
        var fw = std.Io.File.stderr().writerStreaming(self.io, &buf);
        fw.interface.print("wg-cli: {s}\n", .{msg}) catch {};
        fw.interface.flush() catch {};
    }
};

const AncestorIgnores = struct {
    abs_target: []u8 = &.{},
    file_bufs: std.ArrayList([]u8) = .empty,
    scoped: std.ArrayList(internal.walker.ScopedIgnore) = .empty,

    fn deinit(self: *AncestorIgnores, gpa: std.mem.Allocator) void {
        self.scoped.deinit(gpa);
        for (self.file_bufs.items) |buf| gpa.free(buf);
        self.file_bufs.deinit(gpa);
        if (self.abs_target.len != 0) gpa.free(self.abs_target);
    }
};

fn appendScopedFile(
    gpa: std.mem.Allocator,
    io: std.Io,
    dir: std.Io.Dir,
    sub_path: []const u8,
    repo_prefix: []const u8,
    out: *AncestorIgnores,
) !void {
    const data = dir.readFileAlloc(io, sub_path, gpa, .limited(1024 * 1024)) catch return;
    errdefer gpa.free(data);
    try out.file_bufs.append(gpa, data);
    try out.scoped.append(gpa, .{
        .repo_prefix = repo_prefix,
        .text = data,
    });
}

fn discoverAncestorIgnores(gpa: std.mem.Allocator, io: std.Io, target_path: []const u8) !AncestorIgnores {
    var result = AncestorIgnores{};
    errdefer result.deinit(gpa);

    var target_dir = std.Io.Dir.cwd().openDir(io, target_path, .{}) catch return result;
    defer target_dir.close(io);

    var abs_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const abs_len = target_dir.realPath(io, &abs_buf) catch return result;
    if (abs_len <= 1) return result;
    result.abs_target = try gpa.dupe(u8, abs_buf[0..abs_len]);
    const abs_target = result.abs_target;

    const target_is_git_root = if (target_dir.statFile(io, ".git", .{})) |_| true else |_| false;

    const Ancestor = struct {
        anc_path: []const u8,
        rel_subpath: []const u8,
    };
    var ancestors: std.ArrayList(Ancestor) = .empty;
    defer ancestors.deinit(gpa);

    var found_git = false;
    var git_root_has_dir = false;
    var cur_end: usize = abs_target.len;
    while (cur_end > 1) {
        const slash = std.mem.findScalarLast(u8, abs_target[0..cur_end], '/') orelse break;
        const anc_path = if (slash == 0) abs_target[0..1] else abs_target[0..slash];
        const rel_subpath = abs_target[slash + 1 ..];
        try ancestors.append(gpa, .{
            .anc_path = anc_path,
            .rel_subpath = rel_subpath,
        });
        if (!target_is_git_root) {
            if (std.Io.Dir.cwd().openDir(io, anc_path, .{})) |opened| {
                var dir = opened;
                defer dir.close(io);
                if (dir.statFile(io, ".git", .{})) |st| {
                    found_git = true;
                    git_root_has_dir = (st.kind == .directory);
                    break;
                } else |_| {}
            } else |_| {}
        }
        if (slash == 0) break;
        cur_end = slash;
    }

    if (ancestors.items.len == 0) return result;

    // Chain outermost-to-innermost:
    // If a .git ancestor was found: git_root/.git/info/exclude first, then each ancestor's .gitignore < .ignore < .rgignore.
    // Otherwise (matching `rg` default --require-git): only ancestor .ignore < .rgignore.
    var idx: usize = ancestors.items.len;
    while (idx > 0) {
        idx -= 1;
        const anc = ancestors.items[idx];
        var dir = std.Io.Dir.cwd().openDir(io, anc.anc_path, .{}) catch continue;
        defer dir.close(io);

        if (found_git) {
            if (idx == ancestors.items.len - 1 and git_root_has_dir) {
                try appendScopedFile(gpa, io, dir, ".git/info/exclude", anc.rel_subpath, &result);
            }
            try appendScopedFile(gpa, io, dir, ".gitignore", anc.rel_subpath, &result);
        }
        try appendScopedFile(gpa, io, dir, ".ignore", anc.rel_subpath, &result);
        try appendScopedFile(gpa, io, dir, ".rgignore", anc.rel_subpath, &result);
    }

    return result;
}

fn replacementNeedsCaptures(repl: ?[]const u8) bool {
    const r = repl orelse return false;
    var i: usize = 0;
    while (i < r.len) : (i += 1) {
        if (r[i] != '$') continue;
        if (i + 1 >= r.len) break;
        const next = r[i + 1];
        if (next == '$') {
            i += 1;
            continue;
        }
        if (next == '&' or next == '0') continue;
        if ((next >= '1' and next <= '9') or next == '{' or std.ascii.isAlphabetic(next) or next == '_') {
            return true;
        }
    }
    return false;
}

fn parseEncodingArg(val: []const u8) ?internal.encoding.Encoding {
    if (std.ascii.eqlIgnoreCase(val, "auto")) return .auto;
    if (std.ascii.eqlIgnoreCase(val, "none")) return .none;
    return internal.encoding.fromCharset(val);
}

fn parseSortArg(val: []const u8, reverse: bool) ?internal.walker.SortBy {
    if (std.mem.eql(u8, val, "none")) return .none;
    if (std.mem.eql(u8, val, "path")) return if (reverse) .path_reverse else .path;
    return null;
}

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
    const can_parallel = threads > 1 and
        cfg.compression == .none and
        (cfg.encoding == .none or cfg.encoding == .auto) and
        cfg.charset == null;

    const can_mmap = io_mode == .mmap and
        cfg.compression == .none and
        (cfg.encoding == .none or cfg.encoding == .auto) and
        cfg.charset == null;

    if (can_mmap) {
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
                if (can_parallel and mapped.memory.len >= 512 * 1024) {
                    return switch (cm.*) {
                        .finder => |*f| internal.searchSliceParallel(S, gpa, io, sink, mapped.memory, path, f, cfg, .{ .workers = threads }),
                        .multi => |*m| internal.searchSliceParallel(S, gpa, io, sink, mapped.memory, path, m, cfg, .{ .workers = threads }),
                        .regex => |*r| internal.searchSliceParallel(S, gpa, io, sink, mapped.memory, path, r, cfg, .{ .workers = threads }),
                        .regex_set => |*rs| internal.searchSliceParallel(S, gpa, io, sink, mapped.memory, path, rs, cfg, .{ .workers = threads }),
                        .none => unreachable,
                    };
                }
                return switch (cm.*) {
                    .finder => |*f| libwebgrep.searchSlice(S, sink, mapped.memory, path, f, cfg),
                    .multi => |*m| libwebgrep.searchSlice(S, sink, mapped.memory, path, m, cfg),
                    .regex => |*r| libwebgrep.searchSlice(S, sink, mapped.memory, path, r, cfg),
                    .regex_set => |*rs| libwebgrep.searchSlice(S, sink, mapped.memory, path, rs, cfg),
                    .none => unreachable,
                };
            }
        }
    } else if (can_parallel) {
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
                    .regex_set => |*rs| internal.searchParallelAt(S, gpa, io, sink, ra, path, rs, cfg, .{ .workers = threads }),
                    .none => unreachable,
                };
            }
        }
    }

    return switch (cm.*) {
        .finder => |*f| internal.searchFile(S, gpa, io, sink, file, path, f, cfg),
        .multi => |*m| internal.searchFile(S, gpa, io, sink, file, path, m, cfg),
        .regex => |*r| internal.searchFile(S, gpa, io, sink, file, path, r, cfg),
        .regex_set => |*rs| internal.searchFile(S, gpa, io, sink, file, path, rs, cfg),
        .none => unreachable,
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

fn buildSearchConfig(args: *const CliArgs, gpa: std.mem.Allocator, scratch: ?*libwebgrep.Scratch) libwebgrep.SearchConfig {
    const suppress_ctx = args.count_only or args.files_with_matches;
    const ctx_lines: u32 = if (suppress_ctx) 0 else args.context;
    const before_ctx: ?u32 = if (suppress_ctx) null else args.before_context;
    const after_ctx: ?u32 = if (suppress_ctx) null else args.after_context;
    const max_ctx: u32 = @max(ctx_lines, @max(before_ctx orelse 0, after_ctx orelse 0));
    const need_leftmost = args.multiline or args.only_matching or args.replacement != null;

    return .{
        .line_numbers = args.line_numbers,
        .invert = args.invert,
        .whole_word = args.whole_word,
        .whole_word_unicode = !args.no_unicode,
        .whole_line = args.whole_line,
        .context = ctx_lines,
        .before = before_ctx,
        .after = after_ctx,
        .max_context_lines = if (max_ctx > libwebgrep.SearchConfig.context_lines_hard_cap) max_ctx else null,
        .max_count = args.max_count,
        .multiline = args.multiline,
        .match_mode = if (need_leftmost) .leftmost_first else .earliest,
        .binary = args.binary_policy,
        .compression = if (args.search_zip) .auto else .none,
        .max_compression_ratio = if (args.search_zip) std.math.maxInt(u64) else null,
        .encoding = args.encoding,
        .max_decode_bytes = std.math.maxInt(usize),
        .decode_allocator = gpa,
        .replacement = args.replacement,
        .exists = args.files_with_matches,
        .buffer_size = libwebgrep.SearchConfig.optimalBufferSize(args.threads),
        .scratch_pool = scratch,
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

    const cfg = buildSearchConfig(args, gpa, scratch);

    if (args.files_with_matches) {
        var csink = CountSink{};
        const res = try searchSingleFileWithSink(CountSink, gpa, io, file, path, &csink, cm, cfg, args.io_mode, args.threads);
        if (res.matched_lines > 0) {
            try stdout_writer.print("{s}\n", .{path});
            try stdout_writer.flush();
        }
        return res.matched_lines;
    } else if (args.count_only) {
        var csink = CountSink{};
        const res = try searchSingleFileWithSink(CountSink, gpa, io, file, path, &csink, cm, cfg, args.io_mode, args.threads);
        if (res.matched_lines > 0) {
            try stdout_writer.print("{d}\n", .{res.matched_lines});
            try stdout_writer.flush();
        }
        return res.matched_lines;
    } else if (args.only_matching and args.replacement != null) {
        var psink = PrintSink(.only_matching_replace){
            .out = stdout_writer,
            .file_path = path,
            .prefix_path = null,
            .line_numbers = args.line_numbers,
            .multiline = args.multiline,
        };
        const res = try searchSingleFileWithSink(PrintSink(.only_matching_replace), gpa, io, file, path, &psink, cm, cfg, args.io_mode, args.threads);
        return res.matched_lines;
    } else if (args.only_matching) {
        var psink = PrintSink(.only_matching){
            .out = stdout_writer,
            .file_path = path,
            .prefix_path = null,
            .line_numbers = args.line_numbers,
            .multiline = args.multiline,
        };
        const res = try searchSingleFileWithSink(PrintSink(.only_matching), gpa, io, file, path, &psink, cm, cfg, args.io_mode, args.threads);
        return res.matched_lines;
    } else if (args.replacement != null) {
        var psink = PrintSink(.replace){
            .out = stdout_writer,
            .file_path = path,
            .prefix_path = null,
            .line_numbers = args.line_numbers,
            .multiline = args.multiline,
        };
        const res = try searchSingleFileWithSink(PrintSink(.replace), gpa, io, file, path, &psink, cm, cfg, args.io_mode, args.threads);
        return res.matched_lines;
    } else {
        var psink = PrintSink(.line){
            .out = stdout_writer,
            .file_path = path,
            .prefix_path = null,
            .line_numbers = args.line_numbers,
            .multiline = args.multiline,
        };
        const res = try searchSingleFileWithSink(PrintSink(.line), gpa, io, file, path, &psink, cm, cfg, args.io_mode, args.threads);
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
            } else if (std.mem.eql(u8, arg, "-l") or std.mem.eql(u8, arg, "--files-with-matches")) {
                cli.files_with_matches = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--files")) {
                cli.files_only = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--type-list")) {
                cli.type_list = true;
                continue;
            } else if (std.mem.eql(u8, arg, "-n") or std.mem.eql(u8, arg, "--line-number")) {
                cli.line_numbers = true;
                continue;
            } else if (std.mem.eql(u8, arg, "-F") or std.mem.eql(u8, arg, "--fixed-strings")) {
                cli.fixed_strings = true;
                continue;
            } else if (std.mem.eql(u8, arg, "-i") or std.mem.eql(u8, arg, "--ignore-case")) {
                cli.case_mode = .insensitive;
                continue;
            } else if (std.mem.eql(u8, arg, "-S") or std.mem.eql(u8, arg, "--smart-case")) {
                cli.case_mode = .smart;
                continue;
            } else if (std.mem.eql(u8, arg, "-s") or std.mem.eql(u8, arg, "--case-sensitive")) {
                cli.case_mode = .sensitive;
                continue;
            } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--invert-match")) {
                cli.invert = true;
                continue;
            } else if (std.mem.eql(u8, arg, "-w") or std.mem.eql(u8, arg, "--word-regexp")) {
                cli.whole_word = true;
                continue;
            } else if (std.mem.eql(u8, arg, "-x") or std.mem.eql(u8, arg, "--line-regexp")) {
                cli.whole_line = true;
                continue;
            } else if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--only-matching")) {
                cli.only_matching = true;
                continue;
            } else if (std.mem.eql(u8, arg, "-r") or std.mem.eql(u8, arg, "--replace")) {
                cli.replacement = argv_it.next() orelse return 2;
                continue;
            } else if (std.mem.startsWith(u8, arg, "--replace=")) {
                cli.replacement = arg["--replace=".len..];
                continue;
            } else if (std.mem.eql(u8, arg, "-C") or std.mem.eql(u8, arg, "--context")) {
                const c_str = argv_it.next() orelse return 2;
                cli.context = std.fmt.parseInt(u32, c_str, 10) catch return 2;
                continue;
            } else if (std.mem.startsWith(u8, arg, "--context=")) {
                cli.context = std.fmt.parseInt(u32, arg["--context=".len..], 10) catch return 2;
                continue;
            } else if (std.mem.eql(u8, arg, "-A") or std.mem.eql(u8, arg, "--after-context")) {
                const v = argv_it.next() orelse return 2;
                cli.after_context = std.fmt.parseInt(u32, v, 10) catch return 2;
                continue;
            } else if (std.mem.startsWith(u8, arg, "--after-context=")) {
                cli.after_context = std.fmt.parseInt(u32, arg["--after-context=".len..], 10) catch return 2;
                continue;
            } else if (std.mem.eql(u8, arg, "-B") or std.mem.eql(u8, arg, "--before-context")) {
                const v = argv_it.next() orelse return 2;
                cli.before_context = std.fmt.parseInt(u32, v, 10) catch return 2;
                continue;
            } else if (std.mem.startsWith(u8, arg, "--before-context=")) {
                cli.before_context = std.fmt.parseInt(u32, arg["--before-context=".len..], 10) catch return 2;
                continue;
            } else if (std.mem.eql(u8, arg, "-m") or std.mem.eql(u8, arg, "--max-count")) {
                const v = argv_it.next() orelse return 2;
                cli.max_count = std.fmt.parseInt(u64, v, 10) catch return 2;
                continue;
            } else if (std.mem.startsWith(u8, arg, "--max-count=")) {
                cli.max_count = std.fmt.parseInt(u64, arg["--max-count=".len..], 10) catch return 2;
                continue;
            } else if (std.mem.eql(u8, arg, "-z") or std.mem.eql(u8, arg, "--search-zip")) {
                cli.search_zip = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-search-zip")) {
                cli.search_zip = false;
                continue;
            } else if (std.mem.eql(u8, arg, "-E") or std.mem.eql(u8, arg, "--encoding")) {
                const v = argv_it.next() orelse return 2;
                cli.encoding = parseEncodingArg(v) orelse return 2;
                continue;
            } else if (std.mem.startsWith(u8, arg, "--encoding=")) {
                cli.encoding = parseEncodingArg(arg["--encoding=".len..]) orelse return 2;
                continue;
            } else if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--type")) {
                const v = argv_it.next() orelse return 2;
                if (internal.types.find(v) == null) return 2;
                try cli.types.append(gpa, v);
                continue;
            } else if (std.mem.startsWith(u8, arg, "--type=")) {
                const v = arg["--type=".len..];
                if (internal.types.find(v) == null) return 2;
                try cli.types.append(gpa, v);
                continue;
            } else if (std.mem.eql(u8, arg, "-T") or std.mem.eql(u8, arg, "--type-not")) {
                const v = argv_it.next() orelse return 2;
                if (internal.types.find(v) == null) return 2;
                try cli.types_not.append(gpa, v);
                continue;
            } else if (std.mem.startsWith(u8, arg, "--type-not=")) {
                const v = arg["--type-not=".len..];
                if (internal.types.find(v) == null) return 2;
                try cli.types_not.append(gpa, v);
                continue;
            } else if (std.mem.eql(u8, arg, "-L") or std.mem.eql(u8, arg, "--follow")) {
                cli.follow_symlinks = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-follow")) {
                cli.follow_symlinks = false;
                continue;
            } else if (std.mem.eql(u8, arg, "--sort")) {
                const v = argv_it.next() orelse return 2;
                cli.sort_by = parseSortArg(v, false) orelse return 2;
                continue;
            } else if (std.mem.startsWith(u8, arg, "--sort=")) {
                cli.sort_by = parseSortArg(arg["--sort=".len..], false) orelse return 2;
                continue;
            } else if (std.mem.eql(u8, arg, "--sortr")) {
                const v = argv_it.next() orelse return 2;
                cli.sort_by = parseSortArg(v, true) orelse return 2;
                continue;
            } else if (std.mem.startsWith(u8, arg, "--sortr=")) {
                cli.sort_by = parseSortArg(arg["--sortr=".len..], true) orelse return 2;
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
            } else if (std.mem.startsWith(u8, arg, "--glob=")) {
                try cli.globs.append(gpa, arg["--glob=".len..]);
                continue;
            } else if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--regexp")) {
                const p = argv_it.next() orelse return 2;
                cli.saw_pattern_flag = true;
                try cli.patterns.append(gpa, p);
                continue;
            } else if (std.mem.startsWith(u8, arg, "--regexp=")) {
                cli.saw_pattern_flag = true;
                try cli.patterns.append(gpa, arg["--regexp=".len..]);
                continue;
            } else if (std.mem.eql(u8, arg, "-j") or std.mem.eql(u8, arg, "--threads")) {
                const j_str = argv_it.next() orelse return 2;
                cli.threads = std.fmt.parseInt(u32, j_str, 10) catch return 2;
                if (cli.threads == 0) cli.threads = 1;
                continue;
            } else if (std.mem.startsWith(u8, arg, "--threads=")) {
                cli.threads = std.fmt.parseInt(u32, arg["--threads=".len..], 10) catch return 2;
                if (cli.threads == 0) cli.threads = 1;
                continue;
            } else if (arg.len > 2 and arg[0] == '-' and arg[1] != '-') {
                var i: usize = 1;
                while (i < arg.len) : (i += 1) {
                    switch (arg[i]) {
                        'c' => cli.count_only = true,
                        'l' => cli.files_with_matches = true,
                        'n' => cli.line_numbers = true,
                        'F' => cli.fixed_strings = true,
                        'i' => cli.case_mode = .insensitive,
                        'S' => cli.case_mode = .smart,
                        's' => cli.case_mode = .sensitive,
                        'v' => cli.invert = true,
                        'w' => cli.whole_word = true,
                        'x' => cli.whole_line = true,
                        'o' => cli.only_matching = true,
                        'z' => cli.search_zip = true,
                        'L' => cli.follow_symlinks = true,
                        'a' => cli.binary_policy = .none,
                        'U' => cli.multiline = true,
                        'r' => {
                            cli.replacement = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse return 2);
                            break;
                        },
                        'C' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse return 2);
                            cli.context = std.fmt.parseInt(u32, val, 10) catch return 2;
                            break;
                        },
                        'A' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse return 2);
                            cli.after_context = std.fmt.parseInt(u32, val, 10) catch return 2;
                            break;
                        },
                        'B' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse return 2);
                            cli.before_context = std.fmt.parseInt(u32, val, 10) catch return 2;
                            break;
                        },
                        'm' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse return 2);
                            cli.max_count = std.fmt.parseInt(u64, val, 10) catch return 2;
                            break;
                        },
                        'E' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse return 2);
                            cli.encoding = parseEncodingArg(val) orelse return 2;
                            break;
                        },
                        't' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse return 2);
                            if (internal.types.find(val) == null) return 2;
                            try cli.types.append(gpa, val);
                            break;
                        },
                        'T' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse return 2);
                            if (internal.types.find(val) == null) return 2;
                            try cli.types_not.append(gpa, val);
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
        if (cli.files_only) {
            cli.target_path = arg;
        } else if (!cli.saw_pattern_flag and positional_pat == null) {
            positional_pat = arg;
        } else {
            cli.target_path = arg;
        }
    }

    var stdout_buf: [256 * 1024]u8 = undefined;
    var stdout_fw = std.Io.File.stdout().writerStreaming(io, &stdout_buf);

    if (cli.type_list) {
        for (internal.types.builtin) |t| {
            try stdout_fw.interface.print("{s}: ", .{t.name});
            for (t.patterns, 0..) |p, idx| {
                if (idx > 0) try stdout_fw.interface.writeAll(", ");
                try stdout_fw.interface.writeAll(p);
            }
            try stdout_fw.interface.writeByte('\n');
        }
        try stdout_fw.interface.flush();
        return 0;
    }

    if (cli.files_only) {
        if (cli.target_path.len == 0) {
            if (positional_pat) |p| {
                cli.target_path = p;
                positional_pat = null;
            } else {
                cli.target_path = ".";
            }
        }
    } else if (cli.saw_pattern_flag) {
        if (cli.target_path.len == 0) {
            if (positional_pat) |p| {
                cli.target_path = p;
                positional_pat = null;
            } else {
                cli.target_path = ".";
            }
        }
    } else if (cli.patterns.items.len == 0) {
        if (positional_pat) |p| {
            try cli.patterns.append(gpa, p);
        } else return 2;
        if (cli.target_path.len == 0) {
            cli.target_path = ".";
        }
    }

    if (!cli.files_only and cli.patterns.items.len == 0) {
        if (!cli.invert) return 1;
        // With -v and an empty pattern file, no line matches any pattern, so every line is an inverted match.
        // Use a never-matching regex (a^) so all lines are emitted identically to `rg -v -f /dev/null`.
        cli.fixed_strings = false;
        try cli.patterns.append(gpa, "a^");
    }

    var total_pattern_bytes: usize = 0;
    for (cli.patterns.items) |pat| total_pattern_bytes += pat.len;

    const max_pat_count: usize = @max(@as(usize, 1024), cli.patterns.items.len);
    const max_pat_bytes: usize = @max(@as(usize, 256 * 1024), total_pattern_bytes);
    const find_opts = libwebgrep.FindOptions{
        .case = cli.case_mode,
        .unicode_case = !cli.no_unicode,
        .multiline = cli.multiline,
        .max_pattern_count = max_pat_count,
        .max_pattern_bytes = max_pat_bytes,
    };

    var cm: CompiledMatcher = if (cli.files_only)
        .none
    else if (cli.fixed_strings) blk: {
        if (cli.patterns.items.len == 1) {
            break :blk .{ .finder = libwebgrep.Finder.init(cli.patterns.items[0], find_opts) catch return 2 };
        } else {
            break :blk .{ .multi = libwebgrep.Multi.init(gpa, cli.patterns.items, find_opts) catch return 2 };
        }
    } else blk: {
        const eff_dot_all = cli.multiline and cli.multiline_dotall;
        if (cli.patterns.items.len == 1) {
            break :blk .{ .regex = libwebgrep.Regex.init(gpa, cli.patterns.items[0], .{
                .case = cli.case_mode,
                .unicode_case = !cli.no_unicode,
                .unicode_classes = !cli.no_unicode,
                .unicode_word_boundary = !cli.no_unicode,
                .multiline = cli.multiline,
                .dot_all = eff_dot_all,
            }) catch return 2 };
        } else if (!replacementNeedsCaptures(cli.replacement)) {
            break :blk .{ .regex_set = libwebgrep.RegexSet.init(gpa, cli.patterns.items, .{
                .case = cli.case_mode,
                .unicode_case = !cli.no_unicode,
                .unicode_classes = !cli.no_unicode,
                .unicode_word_boundary = !cli.no_unicode,
                .multiline = cli.multiline,
                .dot_all = eff_dot_all,
                .max_pattern_count = max_pat_count,
                .max_pattern_bytes = max_pat_bytes,
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
                .case = cli.case_mode,
                .unicode_case = !cli.no_unicode,
                .unicode_classes = !cli.no_unicode,
                .unicode_word_boundary = !cli.no_unicode,
                .multiline = cli.multiline,
                .dot_all = eff_dot_all,
                .max_inst = @max(@as(usize, 8192), joined.len * 4),
                .max_pattern_count = max_pat_count,
                .max_pattern_bytes = max_pat_bytes,
            }) catch return 2 };
        }
    };
    defer cm.deinit();

    var is_dir = false;
    if (std.Io.Dir.cwd().openDir(io, cli.target_path, .{})) |d| {
        var dir = d;
        dir.close(io);
        is_dir = true;
    } else |_| {}

    if (cli.files_only and !is_dir) {
        const f = std.Io.Dir.cwd().openFile(io, cli.target_path, .{}) catch |err| {
            var err_buf: [512]u8 = undefined;
            var err_fw = std.Io.File.stderr().writerStreaming(io, &err_buf);
            err_fw.interface.print("{s}: {s}\n", .{ cli.target_path, @errorName(err) }) catch {};
            err_fw.interface.flush() catch {};
            return 2;
        };
        f.close(io);
        try stdout_fw.interface.print("{s}\n", .{cli.target_path});
        try stdout_fw.interface.flush();
        return 0;
    }

    if (!is_dir) {
        var scratch = libwebgrep.Scratch.init(gpa);
        defer scratch.deinit();
        const total_matched = searchOneFile(gpa, io, cli.target_path, &cli, &cm, &scratch, &stdout_fw.interface) catch return 2;
        try stdout_fw.interface.flush();
        return if (total_matched > 0) 0 else 1;
    }

    var anc_ignores = if (!cli.no_ignore)
        try discoverAncestorIgnores(gpa, io, cli.target_path)
    else
        AncestorIgnores{};
    defer anc_ignores.deinit(gpa);

    var saw_output = false;
    var has_soft_errors = false;
    var stderr_logger = StderrLogger{ .io = io };
    const roots = [_][]const u8{cli.target_path};
    var search_cfg = buildSearchConfig(&cli, gpa, null);
    search_cfg.max_concurrency = cli.threads;
    search_cfg.log = StderrLogger.log;
    search_cfg.log_ctx = &stderr_logger;

    const emit_mode: internal.parallel.Emit = if (cli.files_only)
        .files_only
    else if (cli.files_with_matches)
        .files_with_matches
    else if (cli.count_only)
        .count
    else
        .text;

    const stats = try internal.parallel.run(gpa, io, .{
        .pattern = if (!cli.files_only and cli.fixed_strings and cli.patterns.items.len == 1) cli.patterns.items[0] else "",
        .patterns = if (!cli.files_only and cli.fixed_strings and cli.patterns.items.len > 1) cli.patterns.items else &.{},
        .regex = switch (cm) {
            .regex => |*r| r,
            else => null,
        },
        .regex_set = switch (cm) {
            .regex_set => |*rs| rs,
            else => null,
        },
        .find = find_opts,
        .roots = &roots,
        .search = search_cfg,
        .walk = .{
            .threads = cli.threads,
            .read_ignore = !cli.no_ignore,
            .scoped_ignores = anc_ignores.scoped.items,
            .globs = cli.globs.items,
            .types = cli.types.items,
            .types_not = cli.types_not.items,
            .follow_symlinks = cli.follow_symlinks,
            .sort_by = cli.sort_by,
        },
        .enforce_service_budgets = false,
        .use_mmap = (cli.io_mode == .mmap),
        .count_lines_only = cli.count_only,
        .only_matching = cli.only_matching,
        .has_soft_errors = &has_soft_errors,
        .emit = emit_mode,
        .stdout = &stdout_fw.interface,
        .saw_output = &saw_output,
        .write_output = true,
    });
    try stdout_fw.interface.flush();

    if (stats.errors > 0 or has_soft_errors) return 2;
    if (cli.files_only) return if (stats.searches > 0) 0 else 1;
    return if (stats.matched or stats.matched_lines > 0) 0 else 1;
}
