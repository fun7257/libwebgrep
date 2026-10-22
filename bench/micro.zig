//! 内核微基准。只在 ReleaseFast 下有意义。
//!
//! 打印单字节查找和字面量查找的 GB/s，以及四种缓冲大小下的文件扫描吞吐。
//! 单字节查找会和 `std.mem.findScalar` 放在同一块缓冲上比。

const std = @import("std");
const zrg = @import("zrg");

const bytes_64m = 64 * 1024 * 1024;
const sweep_bytes = 128 * 1024 * 1024;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    std.debug.print("zrg microbench width={d}\n", .{zrg.memchr.native_width});

    const buf = try gpa.alloc(u8, bytes_64m);
    defer gpa.free(buf);
    fillText(buf);

    try benchScalar(io, buf);
    try benchFinder(io, buf);
    try benchSweep(gpa, io);
}

fn fillText(buf: []u8) void {
    @memset(buf, 'a');
    var i: usize = 63;
    while (i < buf.len) : (i += 64) buf[i] = '\n';
    const needle = "NEEDLE\n";
    @memcpy(buf[buf.len - needle.len ..], needle);
}

fn benchScalar(io: std.Io, buf: []u8) !void {
    const ours = measure(io, buf.len, struct {
        fn run(data: []u8) usize {
            data[0] ^= 1;
            const at = zrg.memchr.find(zrg.memchr.native_width, data, 0, 0xff) orelse 0;
            data[0] ^= 1;
            return at;
        }
    }.run, buf);
    const either = measure(io, buf.len, struct {
        fn run(data: []u8) usize {
            data[0] ^= 1;
            const at = zrg.memchr.findEither(zrg.memchr.native_width, data, 0, 0xff, 0xff) orelse 0;
            data[0] ^= 1;
            return at;
        }
    }.run, buf);
    const std_find = measure(io, buf.len, struct {
        fn run(data: []u8) usize {
            data[0] ^= 1;
            const at = std.mem.findScalar(u8, data, 0xff) orelse 0;
            data[0] ^= 1;
            return at;
        }
    }.run, buf);
    const ratio = ours / std_find;
    std.debug.print("memchr_find_gbs {d:.3}\n", .{ours});
    std.debug.print("memchr_either_gbs {d:.3}\n", .{either});
    std.debug.print("std_find_scalar_gbs {d:.3}\n", .{std_find});
    std.debug.print("memchr_over_std {d:.3}\n", .{ratio});
    std.debug.print("either_over_std {d:.3}\n", .{either / std_find});
}

fn benchFinder(io: std.Io, buf: []u8) !void {
    const sensitive = try measureFinder(io, buf, "NEEDLE", .sensitive);
    const ignore = try measureFinder(io, buf, "needle", .insensitive);
    const smart = try measureFinder(io, buf, "needle", .smart);
    std.debug.print("finder_pair_gbs {d:.3}\n", .{sensitive});
    std.debug.print("finder_ignore_gbs {d:.3}\n", .{ignore});
    std.debug.print("finder_smart_gbs {d:.3}\n", .{smart});

    const slice_finder = try zrg.Finder.init("NEEDLE", .{});
    var slice_ctx = SliceCtx{ .data = buf, .finder = slice_finder };
    const searched = measure(io, buf.len, struct {
        fn run(ctx: *SliceCtx) usize {
            ctx.data[0] ^= 1;
            var nop = Nop{};
            const result = zrg.searchSlice(Nop, &nop, ctx.data, "", &ctx.finder, .{}) catch return 0;
            ctx.data[0] ^= 1;
            return @intCast(result.matched_lines);
        }
    }.run, &slice_ctx);
    std.debug.print("search_slice_gbs {d:.3}\n", .{searched});
}

const SliceCtx = struct {
    data: []u8,
    finder: zrg.Finder,
};

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
        var left: usize = sweep_bytes;
        while (left > 0) {
            const n = @min(left, chunk.len);
            try file.writeStreamingAll(io, chunk[0..n]);
            left -= n;
        }
        try file.writeStreamingAll(io, "NEEDLE\n");
    }

    var file = try dir.openFile(io, "sweep.txt", .{});
    defer file.close(io);
    const sizes = [_]usize{ 64 * 1024, 128 * 1024, 256 * 1024, 1024 * 1024 };
    const names = [_][]const u8{ "64KiB", "128KiB", "256KiB", "1MiB" };
    for (sizes, names) |size, name| {
        var samples: [3]f64 = undefined;
        for (&samples) |*sample| {
            var sweep = Sweep{
                .gpa = gpa,
                .io = io,
                .file = file,
                .finder = try zrg.Finder.init("NEEDLE", .{}),
                .buffer_size = size,
            };
            const gbs = measure(io, sweep_bytes, struct {
                fn run(ctx: *Sweep) usize {
                    var nop = Nop{};
                    ctx.finder.resetStats();
                    const result = zrg.searchFile(
                        Nop,
                        ctx.gpa,
                        ctx.io,
                        &nop,
                        ctx.file,
                        "sweep.txt",
                        &ctx.finder,
                        .{ .buffer_size = ctx.buffer_size },
                    ) catch return 0;
                    return @intCast(result.matched_lines);
                }
            }.run, &sweep);
            sample.* = gbs;
        }
        std.mem.sort(f64, &samples, {}, struct {
            fn less(_: void, a: f64, b: f64) bool {
                return a < b;
            }
        }.less);
        std.debug.print("buffer_{s}_gbs {d:.3}\n", .{ name, samples[1] });
    }
}

const Sweep = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
    finder: zrg.Finder,
    buffer_size: usize,
};

const Nop = struct {
    pub fn matched(self: *Nop, line: zrg.Line) bool {
        _ = self;
        _ = line;
        return true;
    }
};

fn measureFinder(io: std.Io, buf: []u8, pattern: []const u8, case: zrg.CaseMode) !f64 {
    var ctx = FindCtx{
        .data = buf,
        .finder = try zrg.Finder.init(pattern, .{ .case = case }),
    };
    return measure(io, buf.len, struct {
        fn run(found: *FindCtx) usize {
            found.data[0] ^= 1;
            found.finder.resetStats();
            const at = if (found.finder.find(found.data, 0, .earliest)) |m| m.start else 0;
            found.data[0] ^= 1;
            return at;
        }
    }.run, &ctx);
}

const FindCtx = struct {
    data: []u8,
    finder: zrg.Finder,
};

/// 至少跑 300ms。返回处理过的字节除以秒，单位 GB/s（10^9）。
fn barrier() void {
    asm volatile ("" ::: .{ .memory = true });
}

fn measure(io: std.Io, nbytes: usize, comptime run: anytype, ctx: anytype) f64 {
    var sink: usize = 0;
    barrier();
    sink +%= run(ctx);
    var iters: u64 = 0;
    const start = std.Io.Timestamp.now(io, .awake);
    var elapsed: i96 = 0;
    while (elapsed < 300 * std.time.ns_per_ms or iters < 2) {
        barrier();
        sink +%= run(ctx);
        iters += 1;
        const now = std.Io.Timestamp.now(io, .awake);
        elapsed = start.durationTo(now).nanoseconds;
    }
    const bytes = @as(f64, @floatFromInt(nbytes)) * @as(f64, @floatFromInt(iters));
    const seconds = @as(f64, @floatFromInt(elapsed)) / @as(f64, std.time.ns_per_s);
    const gbs = bytes / seconds / 1e9;
    std.debug.print("sink {d} iters {d}\n", .{ sink, iters });
    return gbs;
}
