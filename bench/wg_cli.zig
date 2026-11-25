//! Standalone search CLI built on top of `libwebgrep` (`src/root.zig`) and `libwebgrep_internal` (`src/internal.zig`).
//! Supports `-V`/`--version`, `-c`, `-n`, `-b`/`--byte-offset`, `-I`/`--no-filename`, `-H`/`--with-filename`,
//! `-0`/`--null`, `--null-data`, `-F`, `-i`, `-s`, `-S`, `-v`, `--passthru`, `-w`, `-x`, `-o`, `-r`, `-l`, `-m`,
//! `-A`, `-B`, `-C`, `-f`, `-e`, `-g`, `-t`, `-T`, `--type-list`, `-U`, `--multiline-dotall`, `-z`, `-E`,
//! `-L`/`--follow`, `--files`, `--sort`/`--sortr`, `-a`/`--text`, `--binary`, `--no-binary`, `-u`/`-uu`/`-uuu`,
//! `-.`/`--hidden`, `-d`/`--max-depth`, `--max-filesize`, `-j`, `--no-config`, `--no-unicode`, `--no-ignore`,
//! `--mmap`, `--no-mmap`, multiple positional paths, stdin / `-`, and clean `EPIPE` exit,
//! emitting output format & exit codes matching `rg`.

const builtin = @import("builtin");
const std = @import("std");
const build_options = @import("build_options");
const libwebgrep = @import("libwebgrep_internal");
const internal = libwebgrep;

const wg_version = "0.10.3";

const IoMode = enum { no_mmap, mmap };
const FilenameMode = enum { auto, always, never };

const CliArgs = struct {
    show_version: bool = false,
    count_only: bool = false,
    files_with_matches: bool = false,
    files_only: bool = false,
    type_list: bool = false,
    line_numbers: bool = false,
    byte_offset: bool = false,
    filename_mode: FilenameMode = .auto,
    null_filename: bool = false,
    null_data: bool = false,
    crlf: bool = false,
    fixed_strings: bool = false,
    case_mode: libwebgrep.CaseMode = .sensitive,
    invert: bool = false,
    passthru: bool = false,
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
    hidden: bool = false,
    max_depth: ?u32 = null,
    max_filesize: ?u64 = null,
    unrestricted: u8 = 0,
    follow_symlinks: bool = false,
    search_zip: bool = false,
    encoding: internal.encoding.Encoding = .auto,
    sort_by: internal.walker.SortBy = .none,
    binary_policy: libwebgrep.BinaryPolicy = .quit,
    binary_policy_explicit: bool = false,
    threads: u32 = 1,
    io_mode: IoMode = .no_mmap,
    globs: std.ArrayList([]const u8) = .empty,
    types: std.ArrayList([]const u8) = .empty,
    types_not: std.ArrayList([]const u8) = .empty,
    patterns: std.ArrayList([]const u8) = .empty,
    pattern_file_bufs: std.ArrayList([]u8) = .empty,
    paths: std.ArrayList([]const u8) = .empty,
    saw_pattern_flag: bool = false,

    pub fn deinit(self: *CliArgs, allocator: std.mem.Allocator) void {
        self.globs.deinit(allocator);
        self.types.deinit(allocator);
        self.types_not.deinit(allocator);
        self.patterns.deinit(allocator);
        for (self.pattern_file_bufs.items) |buf| allocator.free(buf);
        self.pattern_file_bufs.deinit(allocator);
        self.paths.deinit(allocator);
    }

    fn hasContext(self: *const CliArgs) bool {
        if (self.count_only or self.files_with_matches or self.files_only) return false;
        return self.context > 0 or (self.before_context orelse 0) > 0 or (self.after_context orelse 0) > 0;
    }
};

const CountSink = struct {};

const PrintMode = enum {
    line,
    replace,
    only_matching,
    only_matching_replace,
};

fn writeStderr(io: std.Io, comptime fmt: []const u8, args: anytype) void {
    var buf: [512]u8 = undefined;
    var fw = std.Io.File.stderr().writerStreaming(io, &buf);
    fw.interface.print("wg-cli: " ++ fmt ++ "\n", args) catch {};
    fw.interface.flush() catch {};
}

fn ignoreSigpipe() void {
    if (comptime builtin.os.tag != .windows and builtin.os.tag != .wasi) {
        const act = std.posix.Sigaction{
            .handler = .{ .handler = std.posix.SIG.IGN },
            .mask = std.posix.sigemptyset(),
            .flags = 0,
        };
        std.posix.sigaction(std.posix.SIG.PIPE, &act, null);
    }
}

fn isBrokenPipe(fw: *const std.Io.File.Writer) bool {
    if (fw.err) |e| {
        return e == error.BrokenPipe;
    }
    return false;
}

fn isStdinTty(io: std.Io) bool {
    return std.Io.File.stdin().isTty(io) catch false;
}

fn parseFilesizeArg(val: []const u8) ?u64 {
    if (val.len == 0) return null;
    var mult: u64 = 1;
    var num_slice = val;
    const last = val[val.len - 1];
    if (std.ascii.isAlphabetic(last)) {
        switch (std.ascii.toUpper(last)) {
            'B' => mult = 1,
            'K' => mult = 1024,
            'M' => mult = 1024 * 1024,
            'G' => mult = 1024 * 1024 * 1024,
            else => return null,
        }
        num_slice = val[0 .. val.len - 1];
    }
    if (num_slice.len == 0) return null;
    const base = std.fmt.parseInt(u64, num_slice, 10) catch return null;
    return std.math.mul(u64, base, mult) catch null;
}

inline fn writeFastBytesTo(out: *std.Io.Writer, bytes: []const u8) bool {
    if (bytes.len < out.buffer.len - out.end) {
        const dst = out.buffer[out.end .. out.end + bytes.len + 1];
        @memcpy(dst[0..bytes.len], bytes);
        dst[bytes.len] = '\n';
        out.end += bytes.len + 1;
        return true;
    }
    out.writeAll(bytes) catch return false;
    out.writeByte('\n') catch return false;
    return true;
}

inline fn writeFastNumberedBytesTo(out: *std.Io.Writer, num: u64, sep: u8, bytes: []const u8) bool {
    const avail = out.buffer.len - out.end;
    if (avail >= 22 and bytes.len <= avail - 22) {
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

fn writePrefixedLine(
    out: *std.Io.Writer,
    show_filename: bool,
    null_filename: bool,
    file_path: []const u8,
    line_num: ?u64,
    byte_off: ?u64,
    sep: u8,
    bytes: []const u8,
) bool {
    if (!show_filename and byte_off == null) {
        if (line_num) |num| {
            return writeFastNumberedBytesTo(out, num, sep, bytes);
        }
        return writeFastBytesTo(out, bytes);
    }
    if (show_filename) {
        out.writeAll(file_path) catch return false;
        out.writeByte(if (null_filename) 0 else sep) catch return false;
    }
    if (line_num) |num| {
        out.print("{d}{c}", .{ num, sep }) catch return false;
    }
    if (byte_off) |off| {
        out.print("{d}{c}", .{ off, sep }) catch return false;
    }
    out.writeAll(bytes) catch return false;
    out.writeByte('\n') catch return false;
    return true;
}

fn writeSinkBytes(
    out: *std.Io.Writer,
    show_filename: bool,
    null_filename: bool,
    file_path: []const u8,
    line_numbers: bool,
    show_byte_offset: bool,
    may_contain_nl: bool,
    bytes: []const u8,
    base_line_num: ?u64,
    base_offset: u64,
    sep: u8,
) bool {
    if (!show_filename and !line_numbers and !show_byte_offset) {
        return writeFastBytesTo(out, bytes);
    }
    if (may_contain_nl and std.mem.findScalar(u8, bytes, '\n') != null) {
        var it = std.mem.splitScalar(u8, bytes, '\n');
        var idx: u64 = 0;
        var off_acc: u64 = base_offset;
        while (it.next()) |sub| : (idx += 1) {
            const ln: ?u64 = if (line_numbers) (if (base_line_num) |num| num + idx else null) else null;
            const bo: ?u64 = if (show_byte_offset) off_acc else null;
            if (!writePrefixedLine(out, show_filename, null_filename, file_path, ln, bo, sep, sub)) return false;
            off_acc += sub.len + 1;
        }
        return true;
    }
    const ln: ?u64 = if (line_numbers) base_line_num else null;
    const bo: ?u64 = if (show_byte_offset) base_offset else null;
    return writePrefixedLine(out, show_filename, null_filename, file_path, ln, bo, sep, bytes);
}

fn writeOnlyMatchingSpans(
    comptime with_replace: bool,
    out: *std.Io.Writer,
    show_filename: bool,
    null_filename: bool,
    file_path: []const u8,
    line_numbers: bool,
    show_byte_offset: bool,
    multiline: bool,
    line: libwebgrep.Line,
) bool {
    if (!show_filename and !line_numbers and !show_byte_offset) {
        for (line.matches) |sp| {
            const from = @min(sp.start, line.bytes.len);
            const to = @min(@max(sp.end, from), line.bytes.len);
            const seg = if (with_replace)
                (sp.replacement orelse line.bytes[from..to])
            else
                line.bytes[from..to];
            if (!writeFastBytesTo(out, seg)) return false;
        }
        return true;
    }
    var prev_pos: usize = 0;
    var nl_acc: u64 = 0;
    for (line.matches) |sp| {
        const from = @min(sp.start, line.bytes.len);
        const to = @min(@max(sp.end, from), line.bytes.len);
        const seg = if (with_replace)
            (sp.replacement orelse line.bytes[from..to])
        else
            line.bytes[from..to];
        const base_ln: ?u64 = if (line_numbers) blk: {
            const n = line.number orelse break :blk null;
            if (multiline and from > prev_pos) {
                nl_acc += internal.memchr.count(internal.memchr.native_width, line.bytes, prev_pos, from, '\n');
                prev_pos = from;
            }
            break :blk n + nl_acc;
        } else null;
        if (!writeSinkBytes(
            out,
            show_filename,
            null_filename,
            file_path,
            line_numbers,
            show_byte_offset,
            if (with_replace) true else multiline,
            seg,
            base_ln,
            line.offset + from,
            ':',
        )) return false;
    }
    return true;
}

fn writeBinaryMatchBanner(
    out: *std.Io.Writer,
    show_filename: bool,
    null_filename: bool,
    file_path: []const u8,
    nul_offset: u64,
) bool {
    _ = null_filename;
    if (show_filename) {
        out.writeAll(file_path) catch return false;
        out.writeAll(": ") catch return false;
    }
    out.print("binary file matches (found \"\\0\" byte around offset {d})\n", .{nul_offset}) catch return false;
    return true;
}

fn PrintSink(comptime mode: PrintMode) type {
    if (mode == .only_matching) {
        return struct {
            pub const matched_fast_line = false;
            pub const matched_raw_spans = true;
            pub const only_matching_replace = false;
            pub const matched_span_skip_line_count = true;

            out: *std.Io.Writer,
            file_path: []const u8 = "",
            show_filename: bool = false,
            null_filename: bool = false,
            line_numbers: bool = false,
            byte_offset: bool = false,
            multiline: bool = false,
            context_file_sep: bool = false,
            saw_output: *bool,
            file_emitted: bool = false,
            last_line_number: u64 = 0,
            last_line_offset: u64 = 0,

            inline fn maybeEmitFileSep(self: *@This()) bool {
                if (!self.file_emitted) {
                    if (self.context_file_sep and self.saw_output.*) {
                        self.out.writeAll("--\n") catch return false;
                    }
                    self.file_emitted = true;
                    self.saw_output.* = true;
                }
                return true;
            }

            inline fn writeFastBytes(self: *@This(), bytes: []const u8) bool {
                return writeFastBytesTo(self.out, bytes);
            }

            pub inline fn canStreamSpans(self: *const @This()) bool {
                return !self.line_numbers and !self.byte_offset and !self.show_filename and !self.context_file_sep;
            }

            pub inline fn matchedSpan(self: *@This(), bytes: []const u8) bool {
                self.saw_output.* = true;
                return self.writeFastBytes(bytes);
            }

            pub fn matched(self: *@This(), line: libwebgrep.Line) bool {
                if (line.binary_status == .detected) return false;
                if (!self.maybeEmitFileSep()) return false;
                if (self.line_numbers) {
                    if (line.number) |n| {
                        self.last_line_number = n;
                        self.last_line_offset = line.offset;
                    }
                }
                return writeOnlyMatchingSpans(
                    false,
                    self.out,
                    self.show_filename,
                    self.null_filename,
                    self.file_path,
                    self.line_numbers,
                    self.byte_offset,
                    self.multiline,
                    line,
                );
            }

            pub fn context(self: *@This(), line: libwebgrep.Line) bool {
                if (line.binary_status == .detected) return false;
                if (!self.maybeEmitFileSep()) return false;
                return writeSinkBytes(
                    self.out,
                    self.show_filename,
                    self.null_filename,
                    self.file_path,
                    self.line_numbers,
                    self.byte_offset,
                    self.multiline,
                    line.bytes,
                    line.number,
                    line.offset,
                    '-',
                );
            }

            pub fn contextBreak(self: *@This()) bool {
                self.out.writeAll("--\n") catch return false;
                return true;
            }

            pub fn finish(self: *@This(), res: libwebgrep.Result) bool {
                if (res.outcome == .binary_matched) {
                    if (!self.maybeEmitFileSep()) return false;
                    return writeBinaryMatchBanner(self.out, self.show_filename, self.null_filename, self.file_path, res.binary_offset orelse 0);
                }
                return true;
            }
        };
    }

    return struct {
        pub const matched_fast_line = (mode == .line);
        pub const matched_raw_spans = (mode != .line);
        pub const only_matching_replace = (mode == .only_matching_replace);

        out: *std.Io.Writer,
        file_path: []const u8 = "",
        show_filename: bool = false,
        null_filename: bool = false,
        line_numbers: bool = false,
        byte_offset: bool = false,
        multiline: bool = false,
        context_file_sep: bool = false,
        saw_output: *bool,
        file_emitted: bool = false,
        last_line_number: u64 = 0,
        last_line_offset: u64 = 0,

        inline fn maybeEmitFileSep(self: *@This()) bool {
            if (!self.file_emitted) {
                if (self.context_file_sep and self.saw_output.*) {
                    self.out.writeAll("--\n") catch return false;
                }
                self.file_emitted = true;
                self.saw_output.* = true;
            }
            return true;
        }

        pub fn matched(self: *@This(), line: libwebgrep.Line) bool {
            if (line.binary_status == .detected) return false;
            if (!self.maybeEmitFileSep()) return false;
            if (self.line_numbers) {
                if (line.number) |n| {
                    self.last_line_number = n;
                    self.last_line_offset = line.offset;
                }
            }
            switch (mode) {
                .line => return writeSinkBytes(
                    self.out,
                    self.show_filename,
                    self.null_filename,
                    self.file_path,
                    self.line_numbers,
                    self.byte_offset,
                    self.multiline,
                    line.bytes,
                    line.number,
                    line.offset,
                    ':',
                ),
                .replace => return writeSinkBytes(
                    self.out,
                    self.show_filename,
                    self.null_filename,
                    self.file_path,
                    self.line_numbers,
                    self.byte_offset,
                    true,
                    line.replaced orelse line.bytes,
                    line.number,
                    line.offset,
                    ':',
                ),
                .only_matching_replace => return writeOnlyMatchingSpans(
                    true,
                    self.out,
                    self.show_filename,
                    self.null_filename,
                    self.file_path,
                    self.line_numbers,
                    self.byte_offset,
                    self.multiline,
                    line,
                ),
                .only_matching => comptime unreachable,
            }
        }

        pub fn context(self: *@This(), line: libwebgrep.Line) bool {
            if (line.binary_status == .detected) return false;
            if (!self.maybeEmitFileSep()) return false;
            return writeSinkBytes(
                self.out,
                self.show_filename,
                self.null_filename,
                self.file_path,
                self.line_numbers,
                self.byte_offset,
                self.multiline,
                line.bytes,
                line.number,
                line.offset,
                '-',
            );
        }

        pub fn contextBreak(self: *@This()) bool {
            self.out.writeAll("--\n") catch return false;
            return true;
        }

        pub fn finish(self: *@This(), res: libwebgrep.Result) bool {
            if (res.outcome == .binary_matched) {
                if (!self.maybeEmitFileSep()) return false;
                return writeBinaryMatchBanner(self.out, self.show_filename, self.null_filename, self.file_path, res.binary_offset orelse 0);
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

inline fn searchSliceCompiled(
    comptime S: type,
    sink: *S,
    haystack: []const u8,
    path: []const u8,
    cm: *const CompiledMatcher,
    cfg: libwebgrep.SearchConfig,
) !libwebgrep.Result {
    return switch (cm.*) {
        .finder => |*f| libwebgrep.searchSlice(S, sink, haystack, path, f, cfg),
        .multi => |*m| libwebgrep.searchSlice(S, sink, haystack, path, m, cfg),
        .regex => |*r| libwebgrep.searchSlice(S, sink, haystack, path, r, cfg),
        .regex_set => |*rs| libwebgrep.searchSlice(S, sink, haystack, path, rs, cfg),
        .none => unreachable,
    };
}

inline fn searchReaderCompiled(
    comptime S: type,
    gpa: std.mem.Allocator,
    sink: *S,
    reader: *std.Io.Reader,
    path: []const u8,
    cm: *const CompiledMatcher,
    cfg: libwebgrep.SearchConfig,
) !libwebgrep.Result {
    return switch (cm.*) {
        .finder => |*f| libwebgrep.searchReader(S, gpa, sink, reader, path, f, cfg),
        .multi => |*m| libwebgrep.searchReader(S, gpa, sink, reader, path, m, cfg),
        .regex => |*r| libwebgrep.searchReader(S, gpa, sink, reader, path, r, cfg),
        .regex_set => |*rs| libwebgrep.searchReader(S, gpa, sink, reader, path, rs, cfg),
        .none => unreachable,
    };
}

inline fn searchWindowedCompiled(
    comptime S: type,
    sink: *S,
    io: std.Io,
    file: std.Io.File,
    file_size: u64,
    path: []const u8,
    cm: *const CompiledMatcher,
    cfg: libwebgrep.SearchConfig,
) !internal.parallel.window_map.WindowSearchOutcome {
    return switch (cm.*) {
        .finder => |*f| internal.parallel.window_map.searchFileWindowed(S, sink, io, file, file_size, path, f, cfg),
        .multi => |*m| internal.parallel.window_map.searchFileWindowed(S, sink, io, file, file_size, path, m, cfg),
        .regex => |*r| internal.parallel.window_map.searchFileWindowed(S, sink, io, file, file_size, path, r, cfg),
        .regex_set => |*rs| internal.parallel.window_map.searchFileWindowed(S, sink, io, file, file_size, path, rs, cfg),
        .none => unreachable,
    };
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
    const is_coded = (cfg.encoding != .none and cfg.encoding != .auto) or cfg.charset != null;
    const can_parallel = threads > 1 and cfg.compression == .none and !is_coded;
    const can_mmap = io_mode == .mmap and cfg.compression == .none;

    if (can_mmap) {
        const st = file.stat(io) catch null;
        if (st) |info| {
            if (info.kind == .file and info.size > 0 and info.size <= std.math.maxInt(usize)) {
                if (!can_parallel) {
                    switch (try searchWindowedCompiled(S, sink, io, file, info.size, path, cm, cfg)) {
                        .done => |res| return res,
                        .fallback => {},
                    }
                }
                var mm = std.Io.File.MemoryMap.create(io, file, .{
                    .len = @intCast(info.size),
                    .offset = 0,
                    .protection = .{ .read = true, .write = false },
                    .populate = false,
                }) catch null;
                if (mm) |*mapped| {
                    defer mapped.destroy(io);
                    if (is_coded) {
                        internal.platform.adviseMappedSequential(mapped.memory);
                        var mem_reader = std.Io.Reader.fixed(mapped.memory);
                        var stream_cfg = cfg;
                        stream_cfg.buffer_size = @min(cfg.buffer_size, 64 * 1024);
                        return searchReaderCompiled(S, gpa, sink, &mem_reader, path, cm, stream_cfg);
                    }
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
                    return searchSliceCompiled(S, sink, mapped.memory, path, cm, cfg);
                }
            }
        }
    } else if (can_parallel) {
        const st = file.stat(io) catch null;
        if (st) |info| {
            if (info.kind == .file and info.size >= 512 * 1024) {
                if (cfg.byte_range == null and cfg.resume_from == 0) {
                    internal.platform.adviseSequentialFile(file);
                }
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
        .passthru = args.passthru,
        .null_data = args.null_data,
        .strip_cr = args.crlf,
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

fn writeCountOrFilename(
    stdout_writer: *std.Io.Writer,
    args: *const CliArgs,
    display_path: []const u8,
    show_filename: bool,
    matched_lines: u64,
    saw_output: *bool,
) !void {
    if (matched_lines == 0) return;
    if (args.files_with_matches) {
        try stdout_writer.writeAll(display_path);
        try stdout_writer.writeByte(if (args.null_filename) 0 else '\n');
        saw_output.* = true;
    } else if (args.count_only) {
        if (show_filename) {
            try stdout_writer.writeAll(display_path);
            try stdout_writer.writeByte(if (args.null_filename) 0 else ':');
        }
        try stdout_writer.print("{d}\n", .{matched_lines});
        saw_output.* = true;
    }
}

fn searchStreamWithArgs(
    gpa: std.mem.Allocator,
    reader: *std.Io.Reader,
    display_path: []const u8,
    show_filename: bool,
    args: *const CliArgs,
    cm: *const CompiledMatcher,
    scratch: *libwebgrep.Scratch,
    stdout_writer: *std.Io.Writer,
    saw_output: *bool,
) !u64 {
    const cfg = buildSearchConfig(args, gpa, scratch);
    const has_ctx = args.hasContext();

    if (args.files_with_matches or args.count_only) {
        var csink = CountSink{};
        const res = try searchReaderCompiled(CountSink, gpa, &csink, reader, display_path, cm, cfg);
        try writeCountOrFilename(stdout_writer, args, display_path, show_filename, res.matched_lines, saw_output);
        return res.matched_lines;
    } else if (args.only_matching and args.replacement != null) {
        var psink = PrintSink(.only_matching_replace){
            .out = stdout_writer,
            .file_path = display_path,
            .show_filename = show_filename,
            .null_filename = args.null_filename,
            .line_numbers = args.line_numbers,
            .byte_offset = args.byte_offset,
            .multiline = args.multiline,
            .context_file_sep = has_ctx,
            .saw_output = saw_output,
        };
        const res = try searchReaderCompiled(PrintSink(.only_matching_replace), gpa, &psink, reader, display_path, cm, cfg);
        return res.matched_lines;
    } else if (args.only_matching) {
        var psink = PrintSink(.only_matching){
            .out = stdout_writer,
            .file_path = display_path,
            .show_filename = show_filename,
            .null_filename = args.null_filename,
            .line_numbers = args.line_numbers,
            .byte_offset = args.byte_offset,
            .multiline = args.multiline,
            .context_file_sep = has_ctx,
            .saw_output = saw_output,
        };
        const res = try searchReaderCompiled(PrintSink(.only_matching), gpa, &psink, reader, display_path, cm, cfg);
        return @max(res.matched_lines, res.matches);
    } else if (args.replacement != null) {
        var psink = PrintSink(.replace){
            .out = stdout_writer,
            .file_path = display_path,
            .show_filename = show_filename,
            .null_filename = args.null_filename,
            .line_numbers = args.line_numbers,
            .byte_offset = args.byte_offset,
            .multiline = args.multiline,
            .context_file_sep = has_ctx,
            .saw_output = saw_output,
        };
        const res = try searchReaderCompiled(PrintSink(.replace), gpa, &psink, reader, display_path, cm, cfg);
        return res.matched_lines;
    } else {
        var psink = PrintSink(.line){
            .out = stdout_writer,
            .file_path = display_path,
            .show_filename = show_filename,
            .null_filename = args.null_filename,
            .line_numbers = args.line_numbers,
            .byte_offset = args.byte_offset,
            .multiline = args.multiline,
            .context_file_sep = has_ctx,
            .saw_output = saw_output,
        };
        const res = try searchReaderCompiled(PrintSink(.line), gpa, &psink, reader, display_path, cm, cfg);
        return res.matched_lines;
    }
}

fn inferCompressionForPath(path: []const u8) @FieldType(libwebgrep.SearchConfig, "compression") {
    if (std.ascii.endsWithIgnoreCase(path, ".br")) return .brotli;
    if (std.ascii.endsWithIgnoreCase(path, ".zlib")) return .zlib;
    return .auto;
}

fn searchOneFile(
    gpa: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    show_filename: bool,
    args: *const CliArgs,
    cm: *const CompiledMatcher,
    scratch: *libwebgrep.Scratch,
    stdout_writer: *std.Io.Writer,
    saw_output: *bool,
) !u64 {
    const file = std.Io.Dir.cwd().openFile(io, path, .{}) catch |err| {
        writeStderr(io, "{s}: {s}", .{ path, @errorName(err) });
        return err;
    };
    defer file.close(io);

    var cfg = buildSearchConfig(args, gpa, scratch);
    if (args.search_zip) cfg.compression = inferCompressionForPath(path);
    const has_ctx = args.hasContext();

    if (args.files_with_matches or args.count_only) {
        var csink = CountSink{};
        const res = try searchSingleFileWithSink(CountSink, gpa, io, file, path, &csink, cm, cfg, args.io_mode, args.threads);
        try writeCountOrFilename(stdout_writer, args, path, show_filename, res.matched_lines, saw_output);
        return res.matched_lines;
    } else if (args.only_matching and args.replacement != null) {
        var psink = PrintSink(.only_matching_replace){
            .out = stdout_writer,
            .file_path = path,
            .show_filename = show_filename,
            .null_filename = args.null_filename,
            .line_numbers = args.line_numbers,
            .byte_offset = args.byte_offset,
            .multiline = args.multiline,
            .context_file_sep = has_ctx,
            .saw_output = saw_output,
        };
        const res = try searchSingleFileWithSink(PrintSink(.only_matching_replace), gpa, io, file, path, &psink, cm, cfg, args.io_mode, args.threads);
        return res.matched_lines;
    } else if (args.only_matching) {
        var psink = PrintSink(.only_matching){
            .out = stdout_writer,
            .file_path = path,
            .show_filename = show_filename,
            .null_filename = args.null_filename,
            .line_numbers = args.line_numbers,
            .byte_offset = args.byte_offset,
            .multiline = args.multiline,
            .context_file_sep = has_ctx,
            .saw_output = saw_output,
        };
        const res = try searchSingleFileWithSink(PrintSink(.only_matching), gpa, io, file, path, &psink, cm, cfg, args.io_mode, args.threads);
        return @max(res.matched_lines, res.matches);
    } else if (args.replacement != null) {
        var psink = PrintSink(.replace){
            .out = stdout_writer,
            .file_path = path,
            .show_filename = show_filename,
            .null_filename = args.null_filename,
            .line_numbers = args.line_numbers,
            .byte_offset = args.byte_offset,
            .multiline = args.multiline,
            .context_file_sep = has_ctx,
            .saw_output = saw_output,
        };
        const res = try searchSingleFileWithSink(PrintSink(.replace), gpa, io, file, path, &psink, cm, cfg, args.io_mode, args.threads);
        return res.matched_lines;
    } else {
        var psink = PrintSink(.line){
            .out = stdout_writer,
            .file_path = path,
            .show_filename = show_filename,
            .null_filename = args.null_filename,
            .line_numbers = args.line_numbers,
            .byte_offset = args.byte_offset,
            .multiline = args.multiline,
            .context_file_sep = has_ctx,
            .saw_output = saw_output,
        };
        const res = try searchSingleFileWithSink(PrintSink(.line), gpa, io, file, path, &psink, cm, cfg, args.io_mode, args.threads);
        return res.matched_lines;
    }
}

pub fn main(init: std.process.Init) !u8 {
    ignoreSigpipe();

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
            } else if (std.mem.eql(u8, arg, "-V") or std.mem.eql(u8, arg, "--version")) {
                cli.show_version = true;
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
            } else if (std.mem.eql(u8, arg, "-N") or std.mem.eql(u8, arg, "--no-line-number")) {
                cli.line_numbers = false;
                continue;
            } else if (std.mem.eql(u8, arg, "-b") or std.mem.eql(u8, arg, "--byte-offset")) {
                cli.byte_offset = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-byte-offset")) {
                cli.byte_offset = false;
                continue;
            } else if (std.mem.eql(u8, arg, "-I") or std.mem.eql(u8, arg, "--no-filename")) {
                cli.filename_mode = .never;
                continue;
            } else if (std.mem.eql(u8, arg, "-H") or std.mem.eql(u8, arg, "--with-filename")) {
                cli.filename_mode = .always;
                continue;
            } else if (std.mem.eql(u8, arg, "-0") or std.mem.eql(u8, arg, "--null")) {
                cli.null_filename = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--null-data")) {
                cli.null_data = true;
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
            } else if (std.mem.eql(u8, arg, "--passthru")) {
                cli.passthru = true;
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
                cli.replacement = argv_it.next() orelse {
                    writeStderr(io, "option '{s}' requires a value", .{arg});
                    return 2;
                };
                continue;
            } else if (std.mem.startsWith(u8, arg, "--replace=")) {
                cli.replacement = arg["--replace=".len..];
                continue;
            } else if (std.mem.eql(u8, arg, "-C") or std.mem.eql(u8, arg, "--context")) {
                const c_str = argv_it.next() orelse {
                    writeStderr(io, "option '{s}' requires a value", .{arg});
                    return 2;
                };
                cli.context = std.fmt.parseInt(u32, c_str, 10) catch {
                    writeStderr(io, "invalid integer for {s}: '{s}'", .{ arg, c_str });
                    return 2;
                };
                continue;
            } else if (std.mem.startsWith(u8, arg, "--context=")) {
                const v = arg["--context=".len..];
                cli.context = std.fmt.parseInt(u32, v, 10) catch {
                    writeStderr(io, "invalid integer for --context: '{s}'", .{v});
                    return 2;
                };
                continue;
            } else if (std.mem.eql(u8, arg, "-A") or std.mem.eql(u8, arg, "--after-context")) {
                const v = argv_it.next() orelse {
                    writeStderr(io, "option '{s}' requires a value", .{arg});
                    return 2;
                };
                cli.after_context = std.fmt.parseInt(u32, v, 10) catch {
                    writeStderr(io, "invalid integer for {s}: '{s}'", .{ arg, v });
                    return 2;
                };
                continue;
            } else if (std.mem.startsWith(u8, arg, "--after-context=")) {
                const v = arg["--after-context=".len..];
                cli.after_context = std.fmt.parseInt(u32, v, 10) catch {
                    writeStderr(io, "invalid integer for --after-context: '{s}'", .{v});
                    return 2;
                };
                continue;
            } else if (std.mem.eql(u8, arg, "-B") or std.mem.eql(u8, arg, "--before-context")) {
                const v = argv_it.next() orelse {
                    writeStderr(io, "option '{s}' requires a value", .{arg});
                    return 2;
                };
                cli.before_context = std.fmt.parseInt(u32, v, 10) catch {
                    writeStderr(io, "invalid integer for {s}: '{s}'", .{ arg, v });
                    return 2;
                };
                continue;
            } else if (std.mem.startsWith(u8, arg, "--before-context=")) {
                const v = arg["--before-context=".len..];
                cli.before_context = std.fmt.parseInt(u32, v, 10) catch {
                    writeStderr(io, "invalid integer for --before-context: '{s}'", .{v});
                    return 2;
                };
                continue;
            } else if (std.mem.eql(u8, arg, "-m") or std.mem.eql(u8, arg, "--max-count")) {
                const v = argv_it.next() orelse {
                    writeStderr(io, "option '{s}' requires a value", .{arg});
                    return 2;
                };
                cli.max_count = std.fmt.parseInt(u64, v, 10) catch {
                    writeStderr(io, "invalid integer for {s}: '{s}'", .{ arg, v });
                    return 2;
                };
                continue;
            } else if (std.mem.startsWith(u8, arg, "--max-count=")) {
                const v = arg["--max-count=".len..];
                cli.max_count = std.fmt.parseInt(u64, v, 10) catch {
                    writeStderr(io, "invalid integer for --max-count: '{s}'", .{v});
                    return 2;
                };
                continue;
            } else if (std.mem.eql(u8, arg, "-d") or std.mem.eql(u8, arg, "--max-depth")) {
                const v = argv_it.next() orelse {
                    writeStderr(io, "option '{s}' requires a value", .{arg});
                    return 2;
                };
                cli.max_depth = std.fmt.parseInt(u32, v, 10) catch {
                    writeStderr(io, "invalid integer for {s}: '{s}'", .{ arg, v });
                    return 2;
                };
                continue;
            } else if (std.mem.startsWith(u8, arg, "--max-depth=")) {
                const v = arg["--max-depth=".len..];
                cli.max_depth = std.fmt.parseInt(u32, v, 10) catch {
                    writeStderr(io, "invalid integer for --max-depth: '{s}'", .{v});
                    return 2;
                };
                continue;
            } else if (std.mem.eql(u8, arg, "--max-filesize")) {
                const v = argv_it.next() orelse {
                    writeStderr(io, "option '{s}' requires a value", .{arg});
                    return 2;
                };
                cli.max_filesize = parseFilesizeArg(v) orelse {
                    writeStderr(io, "invalid filesize for --max-filesize: '{s}'", .{v});
                    return 2;
                };
                continue;
            } else if (std.mem.startsWith(u8, arg, "--max-filesize=")) {
                const v = arg["--max-filesize=".len..];
                cli.max_filesize = parseFilesizeArg(v) orelse {
                    writeStderr(io, "invalid filesize for --max-filesize: '{s}'", .{v});
                    return 2;
                };
                continue;
            } else if (std.mem.eql(u8, arg, "-u") or std.mem.eql(u8, arg, "--unrestricted")) {
                cli.unrestricted = @min(@as(u8, 3), cli.unrestricted + 1);
                continue;
            } else if (std.mem.eql(u8, arg, "-.") or std.mem.eql(u8, arg, "--hidden")) {
                cli.hidden = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-hidden")) {
                cli.hidden = false;
                continue;
            } else if (std.mem.eql(u8, arg, "-z") or std.mem.eql(u8, arg, "--search-zip")) {
                cli.search_zip = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-search-zip")) {
                cli.search_zip = false;
                continue;
            } else if (std.mem.eql(u8, arg, "-E") or std.mem.eql(u8, arg, "--encoding")) {
                const v = argv_it.next() orelse {
                    writeStderr(io, "option '{s}' requires a value", .{arg});
                    return 2;
                };
                cli.encoding = parseEncodingArg(v) orelse {
                    writeStderr(io, "unsupported encoding: '{s}'", .{v});
                    return 2;
                };
                continue;
            } else if (std.mem.startsWith(u8, arg, "--encoding=")) {
                const v = arg["--encoding=".len..];
                cli.encoding = parseEncodingArg(v) orelse {
                    writeStderr(io, "unsupported encoding: '{s}'", .{v});
                    return 2;
                };
                continue;
            } else if (std.mem.eql(u8, arg, "-t") or std.mem.eql(u8, arg, "--type")) {
                const v = argv_it.next() orelse {
                    writeStderr(io, "option '{s}' requires a value", .{arg});
                    return 2;
                };
                if (internal.types.find(v) == null) {
                    writeStderr(io, "unrecognized file type: '{s}'", .{v});
                    return 2;
                }
                try cli.types.append(gpa, v);
                continue;
            } else if (std.mem.startsWith(u8, arg, "--type=")) {
                const v = arg["--type=".len..];
                if (internal.types.find(v) == null) {
                    writeStderr(io, "unrecognized file type: '{s}'", .{v});
                    return 2;
                }
                try cli.types.append(gpa, v);
                continue;
            } else if (std.mem.eql(u8, arg, "-T") or std.mem.eql(u8, arg, "--type-not")) {
                const v = argv_it.next() orelse {
                    writeStderr(io, "option '{s}' requires a value", .{arg});
                    return 2;
                };
                if (internal.types.find(v) == null) {
                    writeStderr(io, "unrecognized file type: '{s}'", .{v});
                    return 2;
                }
                try cli.types_not.append(gpa, v);
                continue;
            } else if (std.mem.startsWith(u8, arg, "--type-not=")) {
                const v = arg["--type-not=".len..];
                if (internal.types.find(v) == null) {
                    writeStderr(io, "unrecognized file type: '{s}'", .{v});
                    return 2;
                }
                try cli.types_not.append(gpa, v);
                continue;
            } else if (std.mem.eql(u8, arg, "-L") or std.mem.eql(u8, arg, "--follow")) {
                cli.follow_symlinks = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-follow")) {
                cli.follow_symlinks = false;
                continue;
            } else if (std.mem.eql(u8, arg, "--sort")) {
                const v = argv_it.next() orelse {
                    writeStderr(io, "option '{s}' requires a value", .{arg});
                    return 2;
                };
                cli.sort_by = parseSortArg(v, false) orelse {
                    writeStderr(io, "invalid sort criterion: '{s}'", .{v});
                    return 2;
                };
                continue;
            } else if (std.mem.startsWith(u8, arg, "--sort=")) {
                const v = arg["--sort=".len..];
                cli.sort_by = parseSortArg(v, false) orelse {
                    writeStderr(io, "invalid sort criterion: '{s}'", .{v});
                    return 2;
                };
                continue;
            } else if (std.mem.eql(u8, arg, "--sortr")) {
                const v = argv_it.next() orelse {
                    writeStderr(io, "option '{s}' requires a value", .{arg});
                    return 2;
                };
                cli.sort_by = parseSortArg(v, true) orelse {
                    writeStderr(io, "invalid sortr criterion: '{s}'", .{v});
                    return 2;
                };
                continue;
            } else if (std.mem.startsWith(u8, arg, "--sortr=")) {
                const v = arg["--sortr=".len..];
                cli.sort_by = parseSortArg(v, true) orelse {
                    writeStderr(io, "invalid sortr criterion: '{s}'", .{v});
                    return 2;
                };
                continue;
            } else if (std.mem.eql(u8, arg, "-f") or std.mem.eql(u8, arg, "--file")) {
                const f_path = argv_it.next() orelse {
                    writeStderr(io, "option '{s}' requires a value", .{arg});
                    return 2;
                };
                cli.saw_pattern_flag = true;
                loadPatternFile(gpa, io, f_path, &cli) catch |err| {
                    writeStderr(io, "{s}: {s}", .{ f_path, @errorName(err) });
                    return 2;
                };
                continue;
            } else if (std.mem.startsWith(u8, arg, "--file=")) {
                const f_path = arg["--file=".len..];
                cli.saw_pattern_flag = true;
                loadPatternFile(gpa, io, f_path, &cli) catch |err| {
                    writeStderr(io, "{s}: {s}", .{ f_path, @errorName(err) });
                    return 2;
                };
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
                cli.binary_policy_explicit = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--binary")) {
                cli.binary_policy = .report;
                cli.binary_policy_explicit = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-binary")) {
                cli.binary_policy = .quit;
                cli.binary_policy_explicit = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-unicode")) {
                cli.no_unicode = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-ignore")) {
                cli.no_ignore = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--crlf")) {
                cli.crlf = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--no-crlf")) {
                cli.crlf = false;
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
                const g = argv_it.next() orelse {
                    writeStderr(io, "option '{s}' requires a value", .{arg});
                    return 2;
                };
                try cli.globs.append(gpa, g);
                continue;
            } else if (std.mem.startsWith(u8, arg, "--glob=")) {
                try cli.globs.append(gpa, arg["--glob=".len..]);
                continue;
            } else if (std.mem.eql(u8, arg, "-e") or std.mem.eql(u8, arg, "--regexp")) {
                const p = argv_it.next() orelse {
                    writeStderr(io, "option '{s}' requires a value", .{arg});
                    return 2;
                };
                cli.saw_pattern_flag = true;
                try cli.patterns.append(gpa, p);
                continue;
            } else if (std.mem.startsWith(u8, arg, "--regexp=")) {
                cli.saw_pattern_flag = true;
                try cli.patterns.append(gpa, arg["--regexp=".len..]);
                continue;
            } else if (std.mem.eql(u8, arg, "-j") or std.mem.eql(u8, arg, "--threads")) {
                const j_str = argv_it.next() orelse {
                    writeStderr(io, "option '{s}' requires a value", .{arg});
                    return 2;
                };
                cli.threads = std.fmt.parseInt(u32, j_str, 10) catch {
                    writeStderr(io, "invalid integer for {s}: '{s}'", .{ arg, j_str });
                    return 2;
                };
                if (cli.threads == 0) cli.threads = 1;
                continue;
            } else if (std.mem.startsWith(u8, arg, "--threads=")) {
                const v = arg["--threads=".len..];
                cli.threads = std.fmt.parseInt(u32, v, 10) catch {
                    writeStderr(io, "invalid integer for --threads: '{s}'", .{v});
                    return 2;
                };
                if (cli.threads == 0) cli.threads = 1;
                continue;
            } else if (arg.len > 2 and arg[0] == '-' and arg[1] != '-') {
                var i: usize = 1;
                while (i < arg.len) : (i += 1) {
                    switch (arg[i]) {
                        'V' => cli.show_version = true,
                        'c' => cli.count_only = true,
                        'l' => cli.files_with_matches = true,
                        'n' => cli.line_numbers = true,
                        'N' => cli.line_numbers = false,
                        'b' => cli.byte_offset = true,
                        'I' => cli.filename_mode = .never,
                        'H' => cli.filename_mode = .always,
                        '0' => cli.null_filename = true,
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
                        'a' => {
                            cli.binary_policy = .none;
                            cli.binary_policy_explicit = true;
                        },
                        'U' => cli.multiline = true,
                        'u' => cli.unrestricted = @min(@as(u8, 3), cli.unrestricted + 1),
                        '.' => cli.hidden = true,
                        'r' => {
                            cli.replacement = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse {
                                writeStderr(io, "option '-r' requires a value", .{});
                                return 2;
                            });
                            break;
                        },
                        'C' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse {
                                writeStderr(io, "option '-C' requires a value", .{});
                                return 2;
                            });
                            cli.context = std.fmt.parseInt(u32, val, 10) catch {
                                writeStderr(io, "invalid integer for -C: '{s}'", .{val});
                                return 2;
                            };
                            break;
                        },
                        'A' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse {
                                writeStderr(io, "option '-A' requires a value", .{});
                                return 2;
                            });
                            cli.after_context = std.fmt.parseInt(u32, val, 10) catch {
                                writeStderr(io, "invalid integer for -A: '{s}'", .{val});
                                return 2;
                            };
                            break;
                        },
                        'B' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse {
                                writeStderr(io, "option '-B' requires a value", .{});
                                return 2;
                            });
                            cli.before_context = std.fmt.parseInt(u32, val, 10) catch {
                                writeStderr(io, "invalid integer for -B: '{s}'", .{val});
                                return 2;
                            };
                            break;
                        },
                        'm' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse {
                                writeStderr(io, "option '-m' requires a value", .{});
                                return 2;
                            });
                            cli.max_count = std.fmt.parseInt(u64, val, 10) catch {
                                writeStderr(io, "invalid integer for -m: '{s}'", .{val});
                                return 2;
                            };
                            break;
                        },
                        'd' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse {
                                writeStderr(io, "option '-d' requires a value", .{});
                                return 2;
                            });
                            cli.max_depth = std.fmt.parseInt(u32, val, 10) catch {
                                writeStderr(io, "invalid integer for -d: '{s}'", .{val});
                                return 2;
                            };
                            break;
                        },
                        'E' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse {
                                writeStderr(io, "option '-E' requires a value", .{});
                                return 2;
                            });
                            cli.encoding = parseEncodingArg(val) orelse {
                                writeStderr(io, "unsupported encoding: '{s}'", .{val});
                                return 2;
                            };
                            break;
                        },
                        't' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse {
                                writeStderr(io, "option '-t' requires a value", .{});
                                return 2;
                            });
                            if (internal.types.find(val) == null) {
                                writeStderr(io, "unrecognized file type: '{s}'", .{val});
                                return 2;
                            }
                            try cli.types.append(gpa, val);
                            break;
                        },
                        'T' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse {
                                writeStderr(io, "option '-T' requires a value", .{});
                                return 2;
                            });
                            if (internal.types.find(val) == null) {
                                writeStderr(io, "unrecognized file type: '{s}'", .{val});
                                return 2;
                            }
                            try cli.types_not.append(gpa, val);
                            break;
                        },
                        'f' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse {
                                writeStderr(io, "option '-f' requires a value", .{});
                                return 2;
                            });
                            cli.saw_pattern_flag = true;
                            loadPatternFile(gpa, io, val, &cli) catch |err| {
                                writeStderr(io, "{s}: {s}", .{ val, @errorName(err) });
                                return 2;
                            };
                            break;
                        },
                        'e' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse {
                                writeStderr(io, "option '-e' requires a value", .{});
                                return 2;
                            });
                            cli.saw_pattern_flag = true;
                            try cli.patterns.append(gpa, val);
                            break;
                        },
                        'g' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse {
                                writeStderr(io, "option '-g' requires a value", .{});
                                return 2;
                            });
                            try cli.globs.append(gpa, val);
                            break;
                        },
                        'j' => {
                            const val = if (i + 1 < arg.len) arg[i + 1 ..] else (argv_it.next() orelse {
                                writeStderr(io, "option '-j' requires a value", .{});
                                return 2;
                            });
                            cli.threads = std.fmt.parseInt(u32, val, 10) catch {
                                writeStderr(io, "invalid integer for -j: '{s}'", .{val});
                                return 2;
                            };
                            if (cli.threads == 0) cli.threads = 1;
                            break;
                        },
                        else => {
                            writeStderr(io, "unrecognized flag '-{c}' in '{s}'", .{ arg[i], arg });
                            return 2;
                        },
                    }
                }
                continue;
            } else if (arg.len > 1 and arg[0] == '-') {
                writeStderr(io, "unrecognized option '{s}'", .{arg});
                return 2;
            }
        }
        if (cli.files_only or cli.saw_pattern_flag) {
            try cli.paths.append(gpa, arg);
        } else if (positional_pat == null) {
            positional_pat = arg;
        } else {
            try cli.paths.append(gpa, arg);
        }
    }

    var stdout_buf: [256 * 1024]u8 = undefined;
    var stdout_fw = std.Io.File.stdout().writerStreaming(io, &stdout_buf);

    if (cli.show_version) {
        stdout_fw.interface.print("wg-cli {s} (optimize={s}, teddy={s})\n", .{
            wg_version,
            @tagName(builtin.mode),
            @tagName(build_options.teddy),
        }) catch |err| {
            if (isBrokenPipe(&stdout_fw)) return 0;
            return err;
        };
        stdout_fw.interface.flush() catch |err| {
            if (isBrokenPipe(&stdout_fw)) return 0;
            return err;
        };
        return 0;
    }

    if (cli.type_list) {
        for (internal.types.builtin) |t| {
            stdout_fw.interface.print("{s}: ", .{t.name}) catch |err| {
                if (isBrokenPipe(&stdout_fw)) return 0;
                return err;
            };
            for (t.patterns, 0..) |p, idx| {
                if (idx > 0) stdout_fw.interface.writeAll(", ") catch |err| {
                    if (isBrokenPipe(&stdout_fw)) return 0;
                    return err;
                };
                stdout_fw.interface.writeAll(p) catch |err| {
                    if (isBrokenPipe(&stdout_fw)) return 0;
                    return err;
                };
            }
            stdout_fw.interface.writeByte('\n') catch |err| {
                if (isBrokenPipe(&stdout_fw)) return 0;
                return err;
            };
        }
        stdout_fw.interface.flush() catch |err| {
            if (isBrokenPipe(&stdout_fw)) return 0;
            return err;
        };
        return 0;
    }

    // Apply -u / -uu / -uuu unrestricted levels
    if (cli.unrestricted >= 1) cli.no_ignore = true;
    if (cli.unrestricted >= 2) cli.hidden = true;
    if (cli.unrestricted >= 3 and !cli.binary_policy_explicit) cli.binary_policy = .none;

    if (cli.files_only or cli.saw_pattern_flag) {
        if (positional_pat) |p| {
            try cli.paths.insert(gpa, 0, p);
            positional_pat = null;
        }
    } else if (cli.patterns.items.len == 0) {
        if (positional_pat) |p| {
            try cli.patterns.append(gpa, p);
        } else {
            writeStderr(io, "missing search pattern", .{});
            return 2;
        }
    }

    if (cli.paths.items.len == 0) {
        if (cli.files_only) {
            try cli.paths.append(gpa, ".");
        } else if (!isStdinTty(io)) {
            try cli.paths.append(gpa, "-");
        } else {
            try cli.paths.append(gpa, ".");
        }
    }

    if (!cli.files_only and cli.patterns.items.len == 0) {
        if (!cli.invert) return 1;
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
            break :blk .{ .finder = libwebgrep.Finder.init(cli.patterns.items[0], find_opts) catch |err| {
                writeStderr(io, "invalid literal pattern: {s}", .{@errorName(err)});
                return 2;
            } };
        } else {
            break :blk .{ .multi = libwebgrep.Multi.init(gpa, cli.patterns.items, find_opts) catch |err| {
                writeStderr(io, "invalid literal patterns: {s}", .{@errorName(err)});
                return 2;
            } };
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
            }) catch |err| {
                writeStderr(io, "regex parse error: {s}", .{@errorName(err)});
                return 2;
            } };
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
            }) catch |err| {
                writeStderr(io, "regex set parse error: {s}", .{@errorName(err)});
                return 2;
            } };
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
            }) catch |err| {
                writeStderr(io, "regex parse error: {s}", .{@errorName(err)});
                return 2;
            } };
        }
    };
    defer cm.deinit();

    const multi_target = cli.paths.items.len > 1;
    var saw_output = false;
    var total_matched: u64 = 0;
    var total_files_listed: u64 = 0;
    var had_errors = false;

    var scratch = libwebgrep.Scratch.init(gpa);
    defer scratch.deinit();

    for (cli.paths.items) |target_path| {
        if (std.mem.eql(u8, target_path, "-")) {
            if (cli.files_only) {
                stdout_fw.interface.writeAll("<stdin>") catch |err| {
                    if (isBrokenPipe(&stdout_fw)) return 0;
                    return err;
                };
                stdout_fw.interface.writeByte(if (cli.null_filename) 0 else '\n') catch |err| {
                    if (isBrokenPipe(&stdout_fw)) return 0;
                    return err;
                };
                total_files_listed += 1;
                saw_output = true;
                continue;
            }
            const show_fn = switch (cli.filename_mode) {
                .always => true,
                .never => false,
                .auto => multi_target,
            };
            var stdin_buf: [64 * 1024]u8 = undefined;
            var stdin_fr = std.Io.File.stdin().readerStreaming(io, &stdin_buf);
            const matched = searchStreamWithArgs(
                gpa,
                &stdin_fr.interface,
                "<stdin>",
                show_fn,
                &cli,
                &cm,
                &scratch,
                &stdout_fw.interface,
                &saw_output,
            ) catch |err| {
                if (isBrokenPipe(&stdout_fw)) return 0;
                writeStderr(io, "<stdin>: {s}", .{@errorName(err)});
                had_errors = true;
                continue;
            };
            total_matched += matched;
            if (isBrokenPipe(&stdout_fw)) return 0;
            continue;
        }

        var is_dir = false;
        if (std.Io.Dir.cwd().openDir(io, target_path, .{})) |d| {
            var dir = d;
            dir.close(io);
            is_dir = true;
        } else |_| {}

        if (cli.files_only and !is_dir) {
            const f = std.Io.Dir.cwd().openFile(io, target_path, .{}) catch |err| {
                writeStderr(io, "{s}: {s}", .{ target_path, @errorName(err) });
                had_errors = true;
                continue;
            };
            f.close(io);
            stdout_fw.interface.writeAll(target_path) catch |err| {
                if (isBrokenPipe(&stdout_fw)) return 0;
                return err;
            };
            stdout_fw.interface.writeByte(if (cli.null_filename) 0 else '\n') catch |err| {
                if (isBrokenPipe(&stdout_fw)) return 0;
                return err;
            };
            total_files_listed += 1;
            saw_output = true;
            continue;
        }

        if (!is_dir) {
            const show_fn = switch (cli.filename_mode) {
                .always => true,
                .never => false,
                .auto => multi_target,
            };
            const matched = searchOneFile(
                gpa,
                io,
                target_path,
                show_fn,
                &cli,
                &cm,
                &scratch,
                &stdout_fw.interface,
                &saw_output,
            ) catch |err| {
                if (isBrokenPipe(&stdout_fw)) return 0;
                if (err == error.WriteFailed) return err;
                had_errors = true;
                continue;
            };
            total_matched += matched;
            if (isBrokenPipe(&stdout_fw)) return 0;
            continue;
        }

        const dir_show_fn = switch (cli.filename_mode) {
            .always => true,
            .never => false,
            .auto => true,
        };

        var anc_ignores = if (!cli.no_ignore)
            try discoverAncestorIgnores(gpa, io, target_path)
        else
            AncestorIgnores{};
        defer anc_ignores.deinit(gpa);

        var has_soft_errors = false;
        var stderr_logger = StderrLogger{ .io = io };
        const roots = [_][]const u8{target_path};
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

        const stats = internal.parallel.run(gpa, io, .{
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
                .hidden = cli.hidden,
                .read_ignore = !cli.no_ignore,
                .scoped_ignores = anc_ignores.scoped.items,
                .max_depth = cli.max_depth,
                .max_filesize = cli.max_filesize,
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
            .show_filename = dir_show_fn,
            .byte_offset = cli.byte_offset,
            .null_filename = cli.null_filename,
            .context_file_sep = cli.hasContext(),
            .has_soft_errors = &has_soft_errors,
            .emit = emit_mode,
            .stdout = &stdout_fw.interface,
            .saw_output = &saw_output,
            .write_output = true,
        }) catch |err| {
            if (isBrokenPipe(&stdout_fw)) return 0;
            return err;
        };

        if (stats.errors > 0 or has_soft_errors) had_errors = true;
        if (cli.files_only) {
            total_files_listed += stats.searches;
        } else if (stats.matched or stats.matched_lines > 0) {
            total_matched += @max(@as(u64, 1), stats.matched_lines);
        }
    }

    stdout_fw.interface.flush() catch |err| {
        if (isBrokenPipe(&stdout_fw)) return 0;
        return err;
    };

    if (had_errors) return 2;
    if (cli.files_only) return if (total_files_listed > 0) 0 else 1;
    return if (total_matched > 0) 0 else 1;
}
