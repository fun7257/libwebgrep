//! 库场景基准。只在 ReleaseFast 下有意义。直接调用库，不经过命令行。
//!
//! 每一行是 `scenario 名字 bytes 字节数 gbs 吞吐 iters 次数 sink 累计结果`。
//! 吞吐是 `字节 / 秒 / 1e9`。先空跑一次，不计入。之后至少再跑 300 ms，并且至少两次。
//! 每次调用前有内存屏障。会改写缓冲的查找还会翻转第一个字节，避免被当成死代码删掉。
//! `sink` 是各次返回值的和。返回值和预期不一致时，基准直接失败，不把空结果当成吞吐。
//!
//! 单模式 `Finder` 在计时外建好，循环里只清统计再查找。多模式表在 `multi.zig`，
//! 和 `zig build test` 的场景测试同一份，也在计时外建好。目录场景每次都走完整的
//! `parallel.run`，包含建工人和拆工人。

const std = @import("std");
const libwebgrep = @import("libwebgrep");

const bytes_64m = 64 * 1024 * 1024;
const sweep_body = 128 * 1024 * 1024;
const sweep_tail = "NEEDLE\n";
const sweep_bytes = sweep_body + sweep_tail.len;
const walk_files = 384;
const walk_file_bytes = 2048;
const walk_bytes = walk_files * walk_file_bytes;

const Sample = struct {
    gbs: f64,
    iters: u64,
    sink: usize,
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    std.debug.print("libwebgrep bench width {d} walk_default_threads {d}\n", .{
        libwebgrep.memchr.native_width,
        libwebgrep.parallel.resolveThreads(0),
    });

    const buf = try gpa.alloc(u8, bytes_64m);
    defer gpa.free(buf);
    libwebgrep.multi.fillScenarioText(buf);

    try benchScalar(io, buf);
    try benchFinder(io, buf);
    try benchMulti(gpa, io, buf);

    fillAlphabet(buf);
    var alphabet = try libwebgrep.Finder.init("libwebgrep", .{ .case = .sensitive });
    const alphabet_at = buf.len - "libwebgrep\n".len;
    var alphabet_ctx = FinderCtx{ .data = buf, .finder = &alphabet, .at = alphabet_at };
    try report(io, "finder_alphabet", buf.len, alphabet_at, finderRun, &alphabet_ctx);

    try benchSweep(gpa, io);
    try benchWalk(gpa, io);
}

fn fillAlphabet(buf: []u8) void {
    const line = "abcdefghijklmnopqrstuvwxyz\n";
    var i: usize = 0;
    while (i + line.len <= buf.len) : (i += line.len) {
        @memcpy(buf[i..][0..line.len], line);
    }
    if (i < buf.len) @memset(buf[i..], 'a');
    const needle = "libwebgrep\n";
    @memcpy(buf[buf.len - needle.len ..], needle);
}

fn benchScalar(io: std.Io, buf: []u8) !void {
    var find_miss = Miss{ .data = buf, .kind = .find };
    var either_miss = Miss{ .data = buf, .kind = .either };
    var std_miss = Miss{ .data = buf, .kind = .std };
    try report(io, "memchr_find", buf.len, 0, missByte, &find_miss);
    try report(io, "memchr_either", buf.len, 0, missByte, &either_miss);
    try report(io, "std_find_scalar", buf.len, 0, missByte, &std_miss);
}

const MissKind = enum { find, either, std };

const Miss = struct {
    data: []u8,
    kind: MissKind,
};

fn missByte(ctx: *Miss) !usize {
    ctx.data[0] ^= 1;
    defer ctx.data[0] ^= 1;
    const hit = switch (ctx.kind) {
        .find => libwebgrep.memchr.find(libwebgrep.memchr.native_width, ctx.data, 0, 0xff) != null,
        .either => libwebgrep.memchr.findEither(libwebgrep.memchr.native_width, ctx.data, 0, 0xff, 0xfe) != null,
        .std => std.mem.findScalar(u8, ctx.data, 0xff) != null,
    };
    if (hit) return error.UnexpectedMatch;
    return 0;
}

fn benchFinder(io: std.Io, buf: []u8) !void {
    const at = buf.len - sweep_tail.len;
    var sensitive = try libwebgrep.Finder.init("NEEDLE", .{ .case = .sensitive });
    var ignore = try libwebgrep.Finder.init("needle", .{ .case = .insensitive });
    var smart = try libwebgrep.Finder.init("needle", .{ .case = .smart });
    var slice_finder = try libwebgrep.Finder.init("NEEDLE", .{});

    var sensitive_ctx = FinderCtx{ .data = buf, .finder = &sensitive, .at = at };
    var ignore_ctx = FinderCtx{ .data = buf, .finder = &ignore, .at = at };
    var smart_ctx = FinderCtx{ .data = buf, .finder = &smart, .at = at };
    var slice_ctx = SliceCtx{ .data = buf, .finder = &slice_finder };
    try report(io, "finder_sensitive", buf.len, at, finderRun, &sensitive_ctx);
    try report(io, "finder_ignore", buf.len, at, finderRun, &ignore_ctx);
    try report(io, "finder_smart", buf.len, at, finderRun, &smart_ctx);
    try report(io, "search_slice", buf.len, 1, sliceRun, &slice_ctx);
}

const FinderCtx = struct {
    data: []u8,
    finder: *libwebgrep.Finder,
    at: usize,
};

fn finderRun(ctx: *FinderCtx) !usize {
    ctx.data[0] ^= 1;
    defer ctx.data[0] ^= 1;
    ctx.finder.resetStats();
    const hit = ctx.finder.find(ctx.data, 0, .earliest) orelse return error.UnexpectedMatch;
    if (hit.start != ctx.at) return error.UnexpectedMatch;
    return hit.start;
}

const SliceCtx = struct {
    data: []u8,
    finder: *libwebgrep.Finder,
};

fn sliceRun(ctx: *SliceCtx) !usize {
    ctx.data[0] ^= 1;
    defer ctx.data[0] ^= 1;
    var nop = Nop{};
    const result = try libwebgrep.searchSlice(Nop, &nop, ctx.data, "", ctx.finder, .{});
    if (result.matched_lines != 1) return error.UnexpectedMatch;
    return 1;
}

const MultiCtx = struct {
    data: []u8,
    many: *libwebgrep.Multi,
    lines: u64,
};

fn benchMulti(gpa: std.mem.Allocator, io: std.Io, buf: []u8) !void {
    try benchOneMulti(gpa, io, buf, "multi_bytes", libwebgrep.multi.scenario_bytes, 0);
    try benchOneMulti(gpa, io, buf, "multi_pairs", libwebgrep.multi.scenario_pairs, 1);
    try benchOneMulti(gpa, io, buf, "multi_teddy", libwebgrep.multi.scenario_teddy, 0);
    try benchOneMulti(gpa, io, buf, "multi_ac", libwebgrep.multi.scenario_ac, 0);
}

fn benchOneMulti(
    gpa: std.mem.Allocator,
    io: std.Io,
    buf: []u8,
    name: []const u8,
    patterns: []const []const u8,
    lines: u64,
) !void {
    var many = try libwebgrep.Multi.init(gpa, patterns, .{});
    defer many.deinit();
    std.debug.print("engine {s} {s}\n", .{ name, many.engineName() });
    var ctx = MultiCtx{ .data = buf, .many = &many, .lines = lines };
    try report(io, name, buf.len, @intCast(lines), multiRun, &ctx);
}

fn multiRun(ctx: *MultiCtx) !usize {
    ctx.data[0] ^= 1;
    defer ctx.data[0] ^= 1;
    var nop = Nop{};
    const result = try libwebgrep.searchSlice(Nop, &nop, ctx.data, "", ctx.many, .{});
    if (result.matched_lines != ctx.lines) return error.UnexpectedMatch;
    return @intCast(result.matched_lines);
}

fn benchSweep(gpa: std.mem.Allocator, io: std.Io) !void {
    var dir = try std.Io.Dir.cwd().createDirPathOpen(io, "bench/tmp", .{});
    defer dir.close(io);
    {
        var file = try dir.createFile(io, "sweep.txt", .{});
        defer file.close(io);
        var chunk: [1024 * 1024]u8 = undefined;
        @memset(&chunk, 'a');
        var i: usize = 63;
        while (i < chunk.len) : (i += 64) chunk[i] = '\n';
        var left: usize = sweep_body;
        while (left > 0) {
            const n = @min(left, chunk.len);
            try file.writeStreamingAll(io, chunk[0..n]);
            left -= n;
        }
        try file.writeStreamingAll(io, sweep_tail);
    }

    var file = try dir.openFile(io, "sweep.txt", .{});
    defer file.close(io);
    var sweep = Sweep{
        .gpa = gpa,
        .io = io,
        .file = file,
        .finder = try libwebgrep.Finder.init("NEEDLE", .{}),
        .buffer_size = 0,
        .file_bytes = sweep_bytes,
    };
    const sizes = [_]usize{ 64 * 1024, 128 * 1024, 256 * 1024, 1024 * 1024, sweep_bytes };
    const names = [_][]const u8{ "file_64KiB", "file_128KiB", "file_256KiB", "file_1MiB", "file_readall" };
    for (sizes, names) |size, name| {
        sweep.buffer_size = size;
        try report(io, name, sweep_bytes, 1, fileRun, &sweep);
    }
}

const Sweep = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
    finder: libwebgrep.Finder,
    buffer_size: usize,
    file_bytes: u64,
};

fn fileRun(ctx: *Sweep) !usize {
    var nop = Nop{};
    const result = try libwebgrep.searchFile(
        Nop,
        ctx.gpa,
        ctx.io,
        &nop,
        ctx.file,
        "sweep.txt",
        &ctx.finder,
        .{ .buffer_size = ctx.buffer_size },
    );
    if (result.matched_lines != 1 or result.bytes_read != ctx.file_bytes) {
        std.debug.print("file buffer {d} lines {d} bytes_read {d}\n", .{
            ctx.buffer_size,
            result.matched_lines,
            result.bytes_read,
        });
        return error.UnexpectedMatch;
    }
    return 1;
}

fn benchWalk(gpa: std.mem.Allocator, io: std.Io) !void {
    const hits = try prepareWalk(io);
    var ctx = WalkCtx{ .gpa = gpa, .io = io, .hits = hits, .threads = 1 };
    try report(io, "walk_1", walk_bytes, @intCast(hits), walkRun, &ctx);
    ctx.threads = 0;
    try report(io, "walk_default", walk_bytes, @intCast(hits), walkRun, &ctx);
}

const WalkCtx = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    hits: u64,
    threads: u32,
};

fn walkRun(ctx: *WalkCtx) !usize {
    var saw = false;
    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer.Discarding = .init(&out_buf);
    const stats = try libwebgrep.parallel.run(ctx.gpa, ctx.io, .{
        .pattern = "NEEDLE",
        .roots = &.{"bench/tmp/walk"},
        .emit = .count,
        .stdout = &out.writer,
        .saw_output = &saw,
        .walk = .{ .threads = ctx.threads, .read_ignore = false },
    });
    if (stats.errors != 0 or stats.searches != walk_files or stats.matched_lines != ctx.hits or stats.bytes_searched != walk_bytes) {
        std.debug.print("walk threads {d} errors {d} searches {d} lines {d} bytes {d}\n", .{
            ctx.threads,
            stats.errors,
            stats.searches,
            stats.matched_lines,
            stats.bytes_searched,
        });
        return error.UnexpectedMatch;
    }
    return @intCast(stats.matched_lines);
}

fn prepareWalk(io: std.Io) !u64 {
    var cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, "bench/tmp");
    try cwd.deleteTree(io, "bench/tmp/walk");
    var root = try cwd.createDirPathOpen(io, "bench/tmp/walk", .{});
    defer root.close(io);

    var made: usize = 0;
    var hits: u64 = 0;
    try writeDir(io, root, "flat", 128, &made, &hits);
    var index: usize = 0;
    while (made < walk_files) : (index += 1) {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "d{d}", .{index});
        const n = @min(walk_files - made, 32);
        try writeDir(io, root, name, n, &made, &hits);
    }
    return hits;
}

fn writeDir(
    io: std.Io,
    parent: std.Io.Dir,
    name: []const u8,
    n: usize,
    made: *usize,
    hits: *u64,
) !void {
    var dir = try parent.createDirPathOpen(io, name, .{});
    defer dir.close(io);
    var body: [walk_file_bytes]u8 = undefined;
    @memset(&body, 'a');
    var at: usize = 63;
    while (at < body.len) : (at += 64) body[at] = '\n';
    for (0..n) |i| {
        var file_name: [16]u8 = undefined;
        const file = try std.fmt.bufPrint(&file_name, "f{d:0>3}.txt", .{i});
        if (i == 0) {
            @memcpy(body[body.len - sweep_tail.len ..], sweep_tail);
            hits.* += 1;
        }
        var handle = try dir.createFile(io, file, .{});
        defer handle.close(io);
        try handle.writeStreamingAll(io, &body);
        if (i == 0) {
            @memset(body[body.len - sweep_tail.len ..], 'a');
            body[body.len - 1] = '\n';
        }
        made.* += 1;
    }
}

const Nop = struct {
    pub fn matched(self: *Nop, line: libwebgrep.Line) bool {
        _ = self;
        _ = line;
        return true;
    }
};

fn barrier() void {
    asm volatile ("" ::: .{ .memory = true });
}

fn report(
    io: std.Io,
    name: []const u8,
    nbytes: usize,
    expect: usize,
    comptime run: anytype,
    ctx: anytype,
) !void {
    const sample = try measure(io, nbytes, run, ctx);
    const total = expect *% @as(usize, @intCast(sample.iters));
    if (sample.iters == 0 or sample.sink != total) {
        std.debug.print("scenario {s} sink {d} iters {d} expected each {d}\n", .{
            name,
            sample.sink,
            sample.iters,
            expect,
        });
        return error.UnexpectedMatch;
    }
    std.debug.print("scenario {s} bytes {d} gbs {d:.3} iters {d} sink {d}\n", .{
        name,
        nbytes,
        sample.gbs,
        sample.iters,
        sample.sink,
    });
}

/// 空跑一次后开始计时。返回处理过的字节除以秒，单位 GB/s（10^9）。
fn measure(io: std.Io, nbytes: usize, comptime run: anytype, ctx: anytype) !Sample {
    barrier();
    _ = try run(ctx);
    var sink: usize = 0;
    var iters: u64 = 0;
    const start = std.Io.Timestamp.now(io, .awake);
    var elapsed: i96 = 0;
    while (elapsed < 300 * std.time.ns_per_ms or iters < 2) {
        barrier();
        sink +%= try run(ctx);
        iters += 1;
        const now = std.Io.Timestamp.now(io, .awake);
        elapsed = start.durationTo(now).nanoseconds;
    }
    const bytes = @as(f64, @floatFromInt(nbytes)) * @as(f64, @floatFromInt(iters));
    const seconds = @as(f64, @floatFromInt(elapsed)) / @as(f64, std.time.ns_per_s);
    return .{
        .gbs = bytes / seconds / 1e9,
        .iters = iters,
        .sink = sink,
    };
}
