//! Large files can be mapped in 8 MiB windows either via the zero-copy `searchFileWindowed`
//! helper (used by `--mmap` on Linux to keep PTE pages L2/L3-hot at `munmap` time) or via
//! the optional copying `Reader` path enabled by `-Dmmap-windows`.
//!
//! Small files, files smaller than the search buffer, and mapping failures all fall back cleanly.
//!
//! When dropping a `Reader` window, the kernel is advised that pages can be reclaimed. Linux uses the `madvise` syscall without linking libc.
//! macOS uses `madvise` from system libc. Windows and WASI are no-ops.
//! There is no CPU dispatch here; vector width is still determined by `suggestVectorLength`.

const builtin = @import("builtin");
const std = @import("std");
const encoding = @import("../codec/encoding.zig");
const matcher_mod = @import("../matcher.zig");
const memchr = @import("../finder/memchr.zig");
const platform = @import("platform.zig");
const searcher = @import("../searcher.zig");
const sink_mod = @import("../sink.zig");

pub const window_len: usize = 8 * 1024 * 1024;

pub const WindowSearchOutcome = union(enum) {
    done: sink_mod.Result,
    fallback,
};

/// Returns true when `config` and `matcher` satisfy every invariant required for
/// independent per-window `searchSlice` execution without changing semantics.
pub fn isEligible(matcher: anytype, config: searcher.SearchConfig) bool {
    if (comptime builtin.os.tag != .linux) return false;
    if (config.compression != .none) return false;
    if (config.encoding != .none and config.encoding != .auto) return false;
    if (config.charset != null) return false;
    if (config.multiline or searcher.state_mod.isMultilineMatcher(matcher)) return false;
    if (config.binary == .report) return false;
    if (config.byte_range != null or config.resume_from != 0 or config.stream_offset != null or config.continuation != null) return false;
    if (config.before != null or config.after != null or config.context != 0) return false;
    if (config.max_count != null or config.max_results != null) return false;
    if (config.max_source_bytes != null or config.max_request_bytes != null or config.max_output_bytes != null) return false;
    if (config.time_budget_ns != null) return false;
    if (config.exists or config.files_without_match or config.stop_on_nonmatch) return false;
    if (config.progress_interval != null or config.line_filter != null) return false;
    return true;
}

/// Zero-copy 8 MiB windowed `mmap` search for large files on Linux.
/// Keeps PTE pages and `struct page` refcount entries L2/L3-hot at `munmap` time,
/// avoiding the L3-cold teardown cost of whole-file `munmap` while preserving
/// kernel sequential readahead via one-time `POSIX_FADV_SEQUENTIAL` and per-window
/// `MADV_SEQUENTIAL` (no `MADV_HUGEPAGE`, no `MADV_DONTNEED`).
/// Returns `.fallback` when windowing does not apply (non-Linux, `file_size <= 12 MiB`,
/// ineligible config, BOM detected at offset 0, or window 0 contains no record separator),
/// letting the caller fall back to whole-file `MemoryMap` or streaming I/O.
pub fn searchFileWindowed(
    comptime S: type,
    sink: *S,
    io: std.Io,
    file: std.Io.File,
    file_size: u64,
    name: []const u8,
    matcher: anytype,
    config: searcher.SearchConfig,
) !WindowSearchOutcome {
    return searchFileWindowedSized(S, sink, io, file, file_size, name, matcher, config, window_len);
}

fn searchWindowSlice(
    comptime S: type,
    sink: *S,
    bytes: []const u8,
    base_offset: u64,
    name: []const u8,
    matcher: anytype,
    config: searcher.SearchConfig,
) !sink_mod.Result {
    var win_cfg = config;
    win_cfg.encoding = .none;
    if (base_offset > 0) win_cfg.stream_offset = base_offset;
    var prepared = searcher.pipeline_mod.Prepared{
        .bytes = bytes,
        .base_searchable_offset = base_offset,
        .offset_map = .{ .base_raw_offset = base_offset },
    };
    return searcher.pipeline_mod.searchPrepared(S, sink, &prepared, name, matcher, win_cfg);
}

/// Parameterized-window-size variant of `searchFileWindowed` (exposed for fast unit testing
/// with smaller windows such as 64 KiB). Requires `file_size > win_size + win_size / 2`.
pub fn searchFileWindowedSized(
    comptime S: type,
    sink: *S,
    io: std.Io,
    file: std.Io.File,
    file_size: u64,
    name: []const u8,
    matcher: anytype,
    config: searcher.SearchConfig,
    win_size: usize,
) !WindowSearchOutcome {
    _ = io;
    if (comptime builtin.os.tag != .linux) return .fallback;
    if (!isEligible(matcher, config)) return .fallback;
    if (win_size == 0) return .fallback;
    matcher_mod.validateMatcher(@TypeOf(matcher));

    const min_file_size: u64 = @as(u64, win_size) + @as(u64, win_size / 2);
    if (file_size <= min_file_size or file_size > std.math.maxInt(usize)) return .fallback;

    const page_size: u64 = std.heap.pageSize();
    if (page_size == 0 or !std.math.isPowerOfTwo(page_size) or page_size >= win_size) return .fallback;
    const page_mask: u64 = page_size - 1;
    const sep: u8 = if (config.null_data) 0 else '\n';
    const has_tail_line_tracking = comptime (@hasField(S, "last_line_number") and @hasField(S, "last_line_offset"));
    const track_line_numbers = (config.line_numbers or config.initial_line_number != null or config.line_number_mode == .from_one) and config.line_number_mode != .unknown;

    platform.adviseSequentialFile(file);

    var offset: u64 = 0;
    var next_line_no: u64 = config.initial_line_number orelse 1;
    var agg = sink_mod.Result{ .outcome = .complete };

    while (offset < file_size) {
        if (offset > 0 and searcher.state_mod.flagIsSet(config)) {
            agg.outcome = .stopped;
            agg.scanned_all = false;
            return .{ .done = agg };
        }

        const map_off: u64 = offset & ~page_mask;
        const delta: usize = @intCast(offset - map_off);
        const remaining: u64 = file_size - map_off;
        const map_len: usize = @intCast(@min(remaining, @as(u64, win_size)));
        const valid_len: usize = map_len - delta;
        const at_eof: bool = (offset + valid_len >= file_size);

        const mapped = std.posix.mmap(
            null,
            map_len,
            .{ .READ = true },
            .{ .TYPE = .PRIVATE },
            file.handle,
            map_off,
        ) catch {
            if (offset == 0) return .fallback;
            return error.ReadFailed;
        };
        var still_mapped = true;
        defer if (still_mapped) std.posix.munmap(mapped);

        std.posix.madvise(mapped.ptr, mapped.len, std.posix.MADV.SEQUENTIAL) catch {};
        const slice = mapped[delta .. delta + valid_len];

        if (offset == 0 and config.encoding == .auto) {
            const bom = encoding.sniff(slice, true);
            if (bom != .raw and bom != .need_more) return .fallback;
        }

        const chunk: []const u8 = if (at_eof)
            slice
        else blk: {
            const last_nl = memchr.findLast(memchr.native_width, slice, 0, slice.len, sep) orelse {
                std.posix.munmap(mapped);
                still_mapped = false;
                if (offset == 0) return .fallback;
                const rem_len: usize = @intCast(remaining);
                const rem_mapped = std.posix.mmap(
                    null,
                    rem_len,
                    .{ .READ = true },
                    .{ .TYPE = .PRIVATE },
                    file.handle,
                    map_off,
                ) catch return error.ReadFailed;
                defer std.posix.munmap(rem_mapped);
                std.posix.madvise(rem_mapped.ptr, rem_mapped.len, std.posix.MADV.SEQUENTIAL) catch {};
                var rem_cfg = config;
                if (track_line_numbers) rem_cfg.initial_line_number = next_line_no;
                const rem_res = try searchWindowSlice(S, sink, rem_mapped[delta..rem_len], offset, name, matcher, rem_cfg);
                agg.matched_lines += rem_res.matched_lines;
                agg.matches += rem_res.matches;
                agg.bytes_read += rem_res.bytes_read;
                agg.bytes_searched += rem_res.bytes_searched;
                agg.output_bytes += rem_res.output_bytes;
                agg.elapsed_ns += rem_res.elapsed_ns;
                agg.outcome = rem_res.outcome;
                if (rem_res.nul_offset) |no| {
                    if (agg.nul_offset == null) {
                        agg.nul_offset = no;
                        agg.binary_offset = no;
                    }
                }
                if (rem_res.resume_at) |ra| agg.resume_at = ra;
                agg.limit_hit = rem_res.limit_hit;
                agg.partial = rem_res.partial;
                agg.paused = rem_res.paused;
                agg.soft_error = rem_res.soft_error;
                agg.scanned_all = rem_res.scanned_all;
                return .{ .done = agg };
            };
            break :blk slice[0 .. last_nl + 1];
        };

        var win_cfg = config;
        if (track_line_numbers) win_cfg.initial_line_number = next_line_no;
        if (has_tail_line_tracking) {
            sink.last_line_number = 0;
            sink.last_line_offset = 0;
        }

        const res = try searchWindowSlice(S, sink, chunk, offset, name, matcher, win_cfg);

        agg.matched_lines += res.matched_lines;
        agg.matches += res.matches;
        agg.bytes_read += res.bytes_read;
        agg.bytes_searched += res.bytes_searched;
        agg.output_bytes += res.output_bytes;
        agg.elapsed_ns += res.elapsed_ns;
        if (res.nul_offset) |no| {
            if (agg.nul_offset == null) {
                agg.nul_offset = no;
                agg.binary_offset = no;
            }
        }

        if (res.outcome == .binary_quit or res.outcome == .binary_matched or res.outcome == .stopped) {
            agg.outcome = res.outcome;
            if (res.resume_at) |ra| agg.resume_at = ra;
            agg.limit_hit = res.limit_hit;
            agg.partial = res.partial;
            agg.paused = res.paused;
            agg.soft_error = res.soft_error;
            agg.scanned_all = false;
            return .{ .done = agg };
        }

        if (track_line_numbers and !at_eof) {
            if (has_tail_line_tracking) {
                if (sink.last_line_number != 0 and sink.last_line_offset >= offset and sink.last_line_offset - offset <= chunk.len) {
                    const tail_start: usize = @intCast(sink.last_line_offset - offset);
                    next_line_no = sink.last_line_number + memchr.count(memchr.native_width, chunk, tail_start, chunk.len, sep);
                } else {
                    next_line_no += memchr.count(memchr.native_width, chunk, 0, chunk.len, sep);
                }
            } else {
                next_line_no += memchr.count(memchr.native_width, chunk, 0, chunk.len, sep);
            }
        }

        offset += chunk.len;
    }

    agg.scanned_all = true;
    return .{ .done = agg };
}

const ReadError = error{ OutOfMemory, ReadFailed } || std.Io.File.ReadPositionalError;

pub const Reader = struct {
    io: std.Io,
    file: std.Io.File,
    size: u64,
    page: usize,
    offset: u64 = 0,
    window: ?std.Io.File.MemoryMap = null,
    window_off: u64 = 0,
    window_len: usize = 0,
    fallback: bool = false,

    pub fn close(self: *Reader) void {
        self.drop();
    }

    fn drop(self: *Reader) void {
        if (self.window) |*mapped| {
            adviseDontNeed(mapped.memory);
            mapped.destroy(self.io);
            self.window = null;
        }
    }

    fn ensure(self: *Reader) ReadError!void {
        if (self.fallback or self.offset >= self.size) return;
        if (self.window != null and self.offset < self.window_off + self.window_len) return;
        self.drop();
        const off = self.offset - (self.offset % self.page);
        const remain = self.size - off;
        const len: usize = @intCast(@min(remain, window_len));
        const mapped = std.Io.File.MemoryMap.create(self.io, self.file, .{
            .len = len,
            .offset = off,
            .protection = .{ .read = true, .write = false },
            .populate = false,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                self.fallback = true;
                return;
            },
        };
        self.window = mapped;
        self.window_off = off;
        self.window_len = len;
    }
};

/// Returns null if the file is no larger than `small_limit` or if the initial mapping fails. Only `OutOfMemory` is propagated.
pub fn open(io: std.Io, file: std.Io.File, small_limit: usize) error{OutOfMemory}!?Reader {
    const stat = file.stat(io) catch return null;
    if (stat.kind != .file) return null;
    if (stat.size <= small_limit) return null;
    if (stat.size > std.math.maxInt(usize)) return null;
    const page = std.heap.pageSize();
    if (page == 0) return null;
    var reader = Reader{
        .io = io,
        .file = file,
        .size = stat.size,
        .page = page,
    };
    reader.ensure() catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    if (reader.fallback or reader.window == null) {
        reader.close();
        return null;
    }
    return reader;
}

pub fn readBytes(raw: *anyopaque, dest: []u8) ReadError!usize {
    const self: *Reader = @ptrCast(@alignCast(raw));
    if (dest.len == 0 or self.offset >= self.size) return 0;
    if (self.fallback) return readPositional(self, dest);
    try self.ensure();
    if (self.fallback or self.window == null) return readPositional(self, dest);
    const mapped = &self.window.?;
    const local: usize = @intCast(self.offset - self.window_off);
    if (local >= mapped.memory.len) return readPositional(self, dest);
    const avail = @min(mapped.memory.len - local, self.window_len -| local);
    const want = @min(dest.len, @min(avail, @as(usize, @intCast(self.size - self.offset))));
    if (want == 0) return 0;
    @memcpy(dest[0..want], mapped.memory[local..][0..want]);
    self.offset += want;
    if (self.offset >= self.window_off + self.window_len) self.drop();
    return want;
}

fn readPositional(self: *Reader, dest: []u8) ReadError!usize {
    var iov = [_][]u8{dest};
    const n = try self.file.readPositional(self.io, &iov, self.offset);
    self.offset += n;
    return n;
}

fn adviseDontNeed(memory: []align(std.heap.page_size_min) u8) void {
    switch (comptime builtin.os.tag) {
        .windows, .wasi => {},
        else => {
            if (comptime @TypeOf(std.posix.MADV) == void) return;
            if (comptime !@hasDecl(std.posix.MADV, "DONTNEED")) return;
            std.posix.madvise(memory.ptr, memory.len, std.posix.MADV.DONTNEED) catch {};
        },
    }
}

test "file larger than buffer can be read from window" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const payload = "abcdefghijklmnopqrstuvwxyz012345";
    try tmp.dir.writeFile(io, .{ .sub_path = "wide.txt", .data = payload });
    const file = try tmp.dir.openFile(io, "wide.txt", .{});
    defer file.close(io);
    var reader = (try open(io, file, 8)) orelse return error.TestUnexpectedResult;
    defer reader.close();
    var got: [64]u8 = undefined;
    var n: usize = 0;
    while (n < payload.len) {
        const read = try readBytes(&reader, got[n..]);
        if (read == 0) break;
        n += read;
    }
    try std.testing.expectEqualStrings(payload, got[0..n]);
}

const TestCountSink = struct {};

fn TestLineSink(comptime track_tail: bool) type {
    if (track_tail) {
        return struct {
            allocator: std.mem.Allocator,
            out: std.ArrayList(u8) = .empty,
            last_line_number: u64 = 0,
            last_line_offset: u64 = 0,

            fn deinit(self: *@This()) void {
                self.out.deinit(self.allocator);
            }

            pub fn matched(self: *@This(), line: sink_mod.Line) bool {
                if (line.number) |n| {
                    self.last_line_number = n;
                    self.last_line_offset = line.offset;
                    var num_buf: [32]u8 = undefined;
                    const prefix = std.fmt.bufPrint(&num_buf, "{d}:", .{n}) catch return false;
                    self.out.appendSlice(self.allocator, prefix) catch return false;
                }
                self.out.appendSlice(self.allocator, line.bytes) catch return false;
                self.out.append(self.allocator, '\n') catch return false;
                return true;
            }
        };
    }
    return struct {
        allocator: std.mem.Allocator,
        out: std.ArrayList(u8) = .empty,

        fn deinit(self: *@This()) void {
            self.out.deinit(self.allocator);
        }

        pub fn matched(self: *@This(), line: sink_mod.Line) bool {
            if (line.number) |n| {
                var num_buf: [32]u8 = undefined;
                const prefix = std.fmt.bufPrint(&num_buf, "{d}:", .{n}) catch return false;
                self.out.appendSlice(self.allocator, prefix) catch return false;
            }
            self.out.appendSlice(self.allocator, line.bytes) catch return false;
            self.out.append(self.allocator, '\n') catch return false;
            return true;
        }
    };
}

test "searchFileWindowedSized multi-window CountSink and line-numbered parity vs searchSlice" {
    if (comptime builtin.os.tag != .linux) return;

    const alloc = std.testing.allocator;
    const io = std.testing.io;
    const finder_mod = @import("../finder/finder.zig");
    const win_size: usize = 64 * 1024;

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);

    // Build ~210 KiB across ~4 windows of 64 KiB, including a zero-match window (window 1),
    // empty lines, and a final matching line without trailing newline.
    var line_idx: usize = 0;
    while (buf.items.len < 210 * 1024) : (line_idx += 1) {
        const cur_len = buf.items.len;
        const in_quiet_window = (cur_len >= 60 * 1024 and cur_len < 135 * 1024);
        if (line_idx % 97 == 0) {
            try buf.append(alloc, '\n');
        } else if (!in_quiet_window and line_idx % 37 == 0) {
            var tmp_line: [64]u8 = undefined;
            const s = try std.fmt.bufPrint(&tmp_line, "line-{d:0>6} contains needle hit\n", .{line_idx});
            try buf.appendSlice(alloc, s);
        } else {
            var tmp_line: [64]u8 = undefined;
            const s = try std.fmt.bufPrint(&tmp_line, "line-{d:0>6} filler payload data 0123456789abcdef\n", .{line_idx});
            try buf.appendSlice(alloc, s);
        }
    }
    try buf.appendSlice(alloc, "final-line-without-newline needle");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "multi.txt", .data = buf.items });
    const file = try tmp.dir.openFile(io, "multi.txt", .{});
    defer file.close(io);

    const finder = try finder_mod.Finder.init("needle", .{});
    const base_cfg = searcher.SearchConfig{ .encoding = .auto, .binary = .quit };

    // 1. Small-file threshold returns `.fallback`.
    var small_sink = TestCountSink{};
    const small_out = try searchFileWindowedSized(TestCountSink, &small_sink, io, file, win_size + win_size / 2, "multi.txt", &finder, base_cfg, win_size);
    try std.testing.expect(small_out == .fallback);

    // 2. CountSink parity vs searchSlice.
    var ref_count = TestCountSink{};
    const ref_count_res = try searcher.searchSlice(TestCountSink, &ref_count, buf.items, "multi.txt", &finder, base_cfg);

    var win_count = TestCountSink{};
    const win_count_out = try searchFileWindowedSized(TestCountSink, &win_count, io, file, buf.items.len, "multi.txt", &finder, base_cfg, win_size);
    const win_count_res = switch (win_count_out) {
        .done => |r| r,
        .fallback => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(ref_count_res.outcome, win_count_res.outcome);
    try std.testing.expectEqual(ref_count_res.matched_lines, win_count_res.matched_lines);
    try std.testing.expectEqual(ref_count_res.matches, win_count_res.matches);
    try std.testing.expectEqual(ref_count_res.bytes_searched, win_count_res.bytes_searched);
    try std.testing.expectEqual(ref_count_res.bytes_read, win_count_res.bytes_read);
    try std.testing.expectEqual(ref_count_res.scanned_all, win_count_res.scanned_all);
    try std.testing.expect(win_count_res.matched_lines > 10);

    // 3. Line-numbered sink WITH fast tail tracking parity vs searchSlice.
    const ln_cfg = searcher.SearchConfig{ .line_numbers = true, .encoding = .auto, .binary = .quit };
    var ref_ln = TestLineSink(true){ .allocator = alloc };
    defer ref_ln.deinit();
    const ref_ln_res = try searcher.searchSlice(TestLineSink(true), &ref_ln, buf.items, "multi.txt", &finder, ln_cfg);

    var win_ln_fast = TestLineSink(true){ .allocator = alloc };
    defer win_ln_fast.deinit();
    const win_ln_fast_out = try searchFileWindowedSized(TestLineSink(true), &win_ln_fast, io, file, buf.items.len, "multi.txt", &finder, ln_cfg, win_size);
    const win_ln_fast_res = switch (win_ln_fast_out) {
        .done => |r| r,
        .fallback => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(ref_ln_res.matched_lines, win_ln_fast_res.matched_lines);
    try std.testing.expectEqual(ref_ln_res.matches, win_ln_fast_res.matches);
    try std.testing.expectEqualStrings(ref_ln.out.items, win_ln_fast.out.items);

    // 4. Line-numbered sink WITHOUT tail tracking fields parity vs searchSlice.
    var win_ln_plain = TestLineSink(false){ .allocator = alloc };
    defer win_ln_plain.deinit();
    const win_ln_plain_out = try searchFileWindowedSized(TestLineSink(false), &win_ln_plain, io, file, buf.items.len, "multi.txt", &finder, ln_cfg, win_size);
    const win_ln_plain_res = switch (win_ln_plain_out) {
        .done => |r| r,
        .fallback => return error.TestUnexpectedResult,
    };
    try std.testing.expectEqual(ref_ln_res.matched_lines, win_ln_plain_res.matched_lines);
    try std.testing.expectEqualStrings(ref_ln.out.items, win_ln_plain.out.items);
}

test "searchFileWindowedSized preserves CRLF across window boundaries" {
    if (comptime builtin.os.tag != .linux) return;

    const alloc = std.testing.allocator;
    const io = std.testing.io;
    const finder_mod = @import("../finder/finder.zig");
    const win_size: usize = 64 * 1024;

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);

    // Craft exact CRLF split across byte 65535 ('\r') and 65536 ('\n').
    while (buf.items.len + 64 < win_size - 16) {
        try buf.appendSlice(alloc, "0123456789abcdef0123456789abcdef0123456789abcdefneedle01234567\r\n");
    }
    const pad_needed = (win_size - 1) - buf.items.len - "needle".len;
    try buf.appendNTimes(alloc, 'x', pad_needed);
    try buf.appendSlice(alloc, "needle\r\n");
    try std.testing.expectEqual(@as(u8, '\r'), buf.items[win_size - 1]);
    try std.testing.expectEqual(@as(u8, '\n'), buf.items[win_size]);

    var i: usize = 0;
    while (buf.items.len < 200 * 1024) : (i += 1) {
        if (i % 19 == 0) {
            try buf.appendSlice(alloc, "crlf match needle line\r\n");
        } else {
            try buf.appendSlice(alloc, "crlf filler line payload 0123456789abcdef0123456789abcdef\r\n");
        }
    }

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "crlf.txt", .data = buf.items });
    const file = try tmp.dir.openFile(io, "crlf.txt", .{});
    defer file.close(io);

    const finder = try finder_mod.Finder.init("needle", .{});
    const cfg = searcher.SearchConfig{ .line_numbers = true, .encoding = .auto, .binary = .quit };

    var ref_sink = TestLineSink(true){ .allocator = alloc };
    defer ref_sink.deinit();
    const ref_res = try searcher.searchSlice(TestLineSink(true), &ref_sink, buf.items, "crlf.txt", &finder, cfg);

    var win_sink = TestLineSink(true){ .allocator = alloc };
    defer win_sink.deinit();
    const win_out = try searchFileWindowedSized(TestLineSink(true), &win_sink, io, file, buf.items.len, "crlf.txt", &finder, cfg, win_size);
    const win_res = switch (win_out) {
        .done => |r| r,
        .fallback => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqual(ref_res.matched_lines, win_res.matched_lines);
    try std.testing.expectEqual(ref_res.matches, win_res.matches);
    try std.testing.expectEqualStrings(ref_sink.out.items, win_sink.out.items);
    try std.testing.expect(std.mem.findScalar(u8, win_sink.out.items, '\r') == null);
}

test "searchFileWindowedSized stops on mid-window NUL with binary quit" {
    if (comptime builtin.os.tag != .linux) return;

    const alloc = std.testing.allocator;
    const io = std.testing.io;
    const finder_mod = @import("../finder/finder.zig");
    const win_size: usize = 64 * 1024;

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);

    while (buf.items.len < 140 * 1024) {
        try buf.appendSlice(alloc, "before-nul line with needle hit 0123456789abcdef\n");
    }
    const nul_pos: u64 = buf.items.len + 7;
    try buf.appendSlice(alloc, "midline\x00binary_payload\n");
    while (buf.items.len < 210 * 1024) {
        try buf.appendSlice(alloc, "after-nul line with needle hit 0123456789abcdef\n");
    }

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "bin.dat", .data = buf.items });
    const file = try tmp.dir.openFile(io, "bin.dat", .{});
    defer file.close(io);

    const finder = try finder_mod.Finder.init("needle", .{});
    const cfg = searcher.SearchConfig{ .line_numbers = true, .encoding = .auto, .binary = .quit };

    var ref_sink = TestLineSink(true){ .allocator = alloc };
    defer ref_sink.deinit();
    const ref_res = try searcher.searchSlice(TestLineSink(true), &ref_sink, buf.items, "bin.dat", &finder, cfg);

    var win_sink = TestLineSink(true){ .allocator = alloc };
    defer win_sink.deinit();
    const win_out = try searchFileWindowedSized(TestLineSink(true), &win_sink, io, file, buf.items.len, "bin.dat", &finder, cfg, win_size);
    const win_res = switch (win_out) {
        .done => |r| r,
        .fallback => return error.TestUnexpectedResult,
    };

    try std.testing.expectEqual(sink_mod.Outcome.binary_quit, win_res.outcome);
    try std.testing.expectEqual(@as(?u64, nul_pos), win_res.nul_offset);
    try std.testing.expectEqual(@as(?u64, nul_pos), win_res.binary_offset);
    try std.testing.expectEqual(false, win_res.scanned_all);
    try std.testing.expectEqual(ref_res.matched_lines, win_res.matched_lines);
    try std.testing.expectEqualStrings(ref_sink.out.items, win_sink.out.items);
}

test "searchFileWindowedSized handles > window single-line fallback, mid-file long line, and BOM fallback" {
    if (comptime builtin.os.tag != .linux) return;

    const alloc = std.testing.allocator;
    const io = std.testing.io;
    const finder_mod = @import("../finder/finder.zig");
    const win_size: usize = 64 * 1024;
    const finder = try finder_mod.Finder.init("needle", .{});

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Case A: window 0 has no newline -> `.fallback` without emitting anything.
    {
        var single: std.ArrayList(u8) = .empty;
        defer single.deinit(alloc);
        try single.appendNTimes(alloc, 'a', 130 * 1024);
        try single.appendSlice(alloc, "needle");
        try tmp.dir.writeFile(io, .{ .sub_path = "single.txt", .data = single.items });
        const file = try tmp.dir.openFile(io, "single.txt", .{});
        defer file.close(io);

        var sink = TestLineSink(true){ .allocator = alloc };
        defer sink.deinit();
        const out = try searchFileWindowedSized(TestLineSink(true), &sink, io, file, single.items.len, "single.txt", &finder, .{ .line_numbers = true }, win_size);
        try std.testing.expect(out == .fallback);
        try std.testing.expectEqual(@as(usize, 0), sink.out.items.len);
    }

    // Case B: normal window 0 followed by a > win_size single line -> maps tail once without duplicating output.
    {
        var mid: std.ArrayList(u8) = .empty;
        defer mid.deinit(alloc);
        while (mid.items.len < 70 * 1024) {
            try mid.appendSlice(alloc, "prefix-line needle 0123456789abcdef\n");
        }
        try mid.appendNTimes(alloc, 'z', 45 * 1024);
        try mid.appendSlice(alloc, "needle");
        try mid.appendNTimes(alloc, 'y', 45 * 1024);
        try mid.append(alloc, '\n');
        try mid.appendSlice(alloc, "tail-after-long needle\n");

        try tmp.dir.writeFile(io, .{ .sub_path = "midlong.txt", .data = mid.items });
        const file = try tmp.dir.openFile(io, "midlong.txt", .{});
        defer file.close(io);

        const cfg = searcher.SearchConfig{ .line_numbers = true, .encoding = .auto, .binary = .quit };
        var ref_sink = TestLineSink(true){ .allocator = alloc };
        defer ref_sink.deinit();
        const ref_res = try searcher.searchSlice(TestLineSink(true), &ref_sink, mid.items, "midlong.txt", &finder, cfg);

        var win_sink = TestLineSink(true){ .allocator = alloc };
        defer win_sink.deinit();
        const win_out = try searchFileWindowedSized(TestLineSink(true), &win_sink, io, file, mid.items.len, "midlong.txt", &finder, cfg, win_size);
        const win_res = switch (win_out) {
            .done => |r| r,
            .fallback => return error.TestUnexpectedResult,
        };
        try std.testing.expectEqual(ref_res.outcome, win_res.outcome);
        try std.testing.expectEqual(ref_res.matched_lines, win_res.matched_lines);
        try std.testing.expectEqual(ref_res.matches, win_res.matches);
        try std.testing.expectEqual(ref_res.scanned_all, win_res.scanned_all);
        try std.testing.expectEqualStrings(ref_sink.out.items, win_sink.out.items);
    }

    // Case C: UTF-8 BOM at offset 0 with `encoding = .auto` -> `.fallback`.
    {
        var bom_buf: std.ArrayList(u8) = .empty;
        defer bom_buf.deinit(alloc);
        try bom_buf.appendSlice(alloc, "\xEF\xBB\xBF");
        while (bom_buf.items.len < 130 * 1024) {
            try bom_buf.appendSlice(alloc, "bom line with needle\n");
        }
        try tmp.dir.writeFile(io, .{ .sub_path = "bom.txt", .data = bom_buf.items });
        const file = try tmp.dir.openFile(io, "bom.txt", .{});
        defer file.close(io);

        var sink = TestCountSink{};
        const out = try searchFileWindowedSized(TestCountSink, &sink, io, file, bom_buf.items.len, "bom.txt", &finder, .{ .encoding = .auto }, win_size);
        try std.testing.expect(out == .fallback);
    }
}

fn TestOffsetSink(comptime fast_line: bool) type {
    return struct {
        pub const matched_fast_line = fast_line;

        allocator: std.mem.Allocator,
        out: std.ArrayList(u8) = .empty,
        last_line_number: u64 = 0,
        last_line_offset: u64 = 0,

        fn deinit(self: *@This()) void {
            self.out.deinit(self.allocator);
        }

        pub fn matched(self: *@This(), line: sink_mod.Line) bool {
            if (line.number) |n| {
                self.last_line_number = n;
                self.last_line_offset = line.offset;
            }
            var prefix_buf: [96]u8 = undefined;
            const prefix = std.fmt.bufPrint(&prefix_buf, "{d}:{d}:{d}:", .{
                line.number orelse 0,
                line.offset,
                line.raw_offset,
            }) catch return false;
            self.out.appendSlice(self.allocator, prefix) catch return false;
            self.out.appendSlice(self.allocator, line.bytes) catch return false;
            self.out.append(self.allocator, '\n') catch return false;
            return true;
        }
    };
}

test "searchFileWindowedSized preserves absolute byte_offset and raw_offset across windows" {
    if (comptime builtin.os.tag != .linux) return;

    const alloc = std.testing.allocator;
    const io = std.testing.io;
    const finder_mod = @import("../finder/finder.zig");
    const win_size: usize = 64 * 1024;

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(alloc);

    // Build ~220 KiB across ~4 windows of 64 KiB, including a quiet window and matches in windows 0, 2, 3.
    var line_idx: usize = 0;
    while (buf.items.len < 220 * 1024) : (line_idx += 1) {
        const cur_len = buf.items.len;
        const in_quiet_window = (cur_len >= 64 * 1024 and cur_len < 130 * 1024);
        if (!in_quiet_window and line_idx % 41 == 0) {
            var tmp_line: [64]u8 = undefined;
            const s = try std.fmt.bufPrint(&tmp_line, "row-{d:0>6} needle hit\n", .{line_idx});
            try buf.appendSlice(alloc, s);
        } else {
            var tmp_line: [64]u8 = undefined;
            const s = try std.fmt.bufPrint(&tmp_line, "row-{d:0>6} filler 0123456789abcdef0123456789\n", .{line_idx});
            try buf.appendSlice(alloc, s);
        }
    }
    try buf.appendSlice(alloc, "eof-tail needle");

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "offsets.txt", .data = buf.items });
    const file = try tmp.dir.openFile(io, "offsets.txt", .{});
    defer file.close(io);

    const finder = try finder_mod.Finder.init("needle", .{});
    const cfg = searcher.SearchConfig{ .line_numbers = true, .encoding = .auto, .binary = .quit };

    // Fast-line sink with tail tracking (matches wg-cli PrintSink / FastLineSink).
    {
        var ref_sink = TestOffsetSink(true){ .allocator = alloc };
        defer ref_sink.deinit();
        const ref_res = try searcher.searchSlice(TestOffsetSink(true), &ref_sink, buf.items, "offsets.txt", &finder, cfg);

        var win_sink = TestOffsetSink(true){ .allocator = alloc };
        defer win_sink.deinit();
        const win_out = try searchFileWindowedSized(TestOffsetSink(true), &win_sink, io, file, buf.items.len, "offsets.txt", &finder, cfg, win_size);
        const win_res = switch (win_out) {
            .done => |r| r,
            .fallback => return error.TestUnexpectedResult,
        };
        try std.testing.expectEqual(ref_res.matched_lines, win_res.matched_lines);
        try std.testing.expectEqual(ref_res.bytes_read, win_res.bytes_read);
        try std.testing.expectEqual(ref_res.bytes_searched, win_res.bytes_searched);
        try std.testing.expectEqualStrings(ref_sink.out.items, win_sink.out.items);
    }

    // Standard buildLine sink (verifies offset_map.base_raw_offset -> line.raw_offset across windows).
    {
        var ref_sink = TestOffsetSink(false){ .allocator = alloc };
        defer ref_sink.deinit();
        const ref_res = try searcher.searchSlice(TestOffsetSink(false), &ref_sink, buf.items, "offsets.txt", &finder, cfg);

        var win_sink = TestOffsetSink(false){ .allocator = alloc };
        defer win_sink.deinit();
        const win_out = try searchFileWindowedSized(TestOffsetSink(false), &win_sink, io, file, buf.items.len, "offsets.txt", &finder, cfg, win_size);
        const win_res = switch (win_out) {
            .done => |r| r,
            .fallback => return error.TestUnexpectedResult,
        };
        try std.testing.expectEqual(ref_res.matched_lines, win_res.matched_lines);
        try std.testing.expectEqual(ref_res.bytes_read, win_res.bytes_read);
        try std.testing.expectEqual(ref_res.bytes_searched, win_res.bytes_searched);
        try std.testing.expectEqualStrings(ref_sink.out.items, win_sink.out.items);
    }

    // Mid-file > win_size single line tail also preserves absolute offsets.
    {
        var mid: std.ArrayList(u8) = .empty;
        defer mid.deinit(alloc);
        while (mid.items.len < 70 * 1024) {
            try mid.appendSlice(alloc, "prefix needle 0123456789abcdef\n");
        }
        try mid.appendNTimes(alloc, 'z', 45 * 1024);
        try mid.appendSlice(alloc, "needle");
        try mid.appendNTimes(alloc, 'y', 45 * 1024);
        try mid.append(alloc, '\n');
        try mid.appendSlice(alloc, "after-long needle\n");

        try tmp.dir.writeFile(io, .{ .sub_path = "midlong_off.txt", .data = mid.items });
        const mid_file = try tmp.dir.openFile(io, "midlong_off.txt", .{});
        defer mid_file.close(io);

        var ref_sink = TestOffsetSink(false){ .allocator = alloc };
        defer ref_sink.deinit();
        const ref_res = try searcher.searchSlice(TestOffsetSink(false), &ref_sink, mid.items, "midlong_off.txt", &finder, cfg);

        var win_sink = TestOffsetSink(false){ .allocator = alloc };
        defer win_sink.deinit();
        const win_out = try searchFileWindowedSized(TestOffsetSink(false), &win_sink, io, mid_file, mid.items.len, "midlong_off.txt", &finder, cfg, win_size);
        const win_res = switch (win_out) {
            .done => |r| r,
            .fallback => return error.TestUnexpectedResult,
        };
        try std.testing.expectEqual(ref_res.matched_lines, win_res.matched_lines);
        try std.testing.expectEqual(ref_res.bytes_read, win_res.bytes_read);
        try std.testing.expectEqual(ref_res.bytes_searched, win_res.bytes_searched);
        try std.testing.expectEqualStrings(ref_sink.out.items, win_sink.out.items);
    }
}
