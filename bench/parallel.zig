//! Intra-source parallel search benchmark (`ReleaseFast` only): throughput and peak RSS.
//!
//! The input is read through a file-backed `RandomAccess` (positional reads), so the source itself never
//! counts toward resident memory; the reported peak RSS is the library's working set plus process overhead.
//! Run ONE invocation at a time so `ru_maxrss` reflects a single configuration:
//!
//!   wg-par-bench gen <path> <MiB>
//!   wg-par-bench run <path> <seq|par|count-seq|count-par> <rare|lit|regex|ci> [workers] [chunk_kib]
//!
//! Output: `mode=.. pattern=.. workers=.. bytes=.. secs=.. gbs=.. matched=.. rss_before_mib=.. rss_peak_mib=..`

const std = @import("std");
const builtin = @import("builtin");
const internal = @import("libwebgrep_internal");

const FileRa = struct {
    file: std.Io.File,
    io: std.Io,

    fn readAt(ctx: ?*anyopaque, offset: u64, dest: []u8) anyerror!usize {
        const self: *FileRa = @ptrCast(@alignCast(ctx.?));
        return self.file.readPositional(self.io, &.{dest}, offset);
    }
};

const MatchCounter = struct {
    matches: u64 = 0,
    bytes: u64 = 0,

    pub fn event(self: *MatchCounter, ev: internal.sink.Event) bool {
        switch (ev) {
            .match => |le| {
                self.matches += 1;
                self.bytes += le.bytes.len;
            },
            else => {},
        }
        return true;
    }
};

const CountSink = struct {};

fn peakRssBytes() u64 {
    const ru = std.posix.getrusage(0);
    const raw: u64 = @intCast(ru.maxrss);
    // macOS reports bytes, Linux reports KiB.
    return if (builtin.os.tag == .linux) raw * 1024 else raw;
}

fn mib(b: u64) f64 {
    return @as(f64, @floatFromInt(b)) / (1024.0 * 1024.0);
}

fn generate(io: std.Io, path: []const u8, total_mib: u64) !void {
    const file = try std.Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    const gpa = std.heap.smp_allocator;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    const target = total_mib * 1024 * 1024;
    var written: u64 = 0;
    var seed: u64 = 0x2545_F491_4F6C_DD1D;
    var line: u64 = 0;
    while (written < target) {
        buf.clearRetainingCapacity();
        while (buf.items.len < 1024 * 1024) : (line += 1) {
            seed = seed *% 6364136223846793005 +% 1442695040888963407;
            const r = (seed >> 33) % 64;
            switch (r) {
                0...39 => try buf.print(gpa, "2026-11-21T10:{d:0>2}:{d:0>2}.{d:0>3}Z INFO  svc=api-{d} req={x} path=/v1/items/{d} status=200 dur_ms={d}\n", .{ (line / 60) % 60, line % 60, line % 1000, line % 17, seed >> 20, line % 9973, (seed >> 40) % 400 }),
                40...51 => try buf.print(gpa, "2026-11-21T10:{d:0>2}:{d:0>2}.{d:0>3}Z DEBUG svc=worker-{d} cache hit ratio={d}.{d} shard={d}\n", .{ (line / 60) % 60, line % 60, line % 1000, line % 5, (seed >> 30) % 100, (seed >> 37) % 10, line % 64 }),
                52...59 => try buf.print(gpa, "2026-11-21T10:{d:0>2}:{d:0>2}.{d:0>3}Z WARN  svc=db-{d} slow query Timeout after {d}ms table=orders\n", .{ (line / 60) % 60, line % 60, line % 1000, line % 3, (seed >> 35) % 5000 }),
                60...62 => try buf.print(gpa, "2026-11-21T10:{d:0>2}:{d:0>2}.{d:0>3}Z ERROR svc=api-{d} ERRCONN code={d} upstream reset by peer\n", .{ (line / 60) % 60, line % 60, line % 1000, line % 17, 500 + (seed >> 40) % 100 }),
                else => {
                    if ((seed >> 45) % 512 == 0) {
                        try buf.print(gpa, "2026-11-21T10:00:00.000Z FATAL QQQ_RARE_TOKEN line={d}\n", .{line});
                    } else {
                        try buf.print(gpa, "2026-11-21T10:{d:0>2}:{d:0>2}.{d:0>3}Z INFO  heartbeat ok\n", .{ (line / 60) % 60, line % 60, line % 1000 });
                    }
                },
            }
        }
        try file.writeStreamingAll(io, buf.items);
        written += buf.items.len;
    }
    std.debug.print("generated {s}: {d} bytes, {d} lines\n", .{ path, written, line });
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    const gpa = std.heap.smp_allocator;
    var args_it = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer args_it.deinit();
    _ = args_it.next();
    const cmd = args_it.next() orelse return usage();
    const path = args_it.next() orelse return usage();

    if (std.mem.eql(u8, cmd, "gen")) {
        const n = try std.fmt.parseInt(u64, args_it.next() orelse "256", 10);
        return generate(io, path, n);
    }
    if (!std.mem.eql(u8, cmd, "run")) return usage();
    const mode = args_it.next() orelse return usage();
    const pat = args_it.next() orelse return usage();
    const workers: ?u32 = if (args_it.next()) |w| try std.fmt.parseInt(u32, w, 10) else null;
    const chunk_kib: usize = if (args_it.next()) |c| try std.fmt.parseInt(usize, c, 10) else internal.ParallelOptions.default_chunk_kib;

    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const size = try file.length(io);
    var fra = FileRa{ .file = file, .io = io };
    const ra = internal.probe.RandomAccess{ .ctx = &fra, .read_at = FileRa.readAt, .size = size };

    var lit = try internal.Finder.init(switch (pat[0]) {
        'r' => "QQQ_RARE_TOKEN",
        'l' => "ERROR",
        else => "timeout",
    }, .{ .case = if (pat[0] == 'c') .insensitive else .sensitive });
    var re = try internal.Regex.init(gpa, "ERR[A-Z]+ code=5[0-9]{2}", .{});
    defer re.deinit();
    const use_regex = std.mem.eql(u8, pat, "regex");

    const cfg = internal.SearchConfig{
        .max_source_bytes = std.math.maxInt(u64),
        .max_request_bytes = std.math.maxInt(u64),
        .max_output_bytes = std.math.maxInt(u64),
        .time_budget_ns = 600 * std.time.ns_per_s,
    };
    const opts = internal.ParallelOptions{ .workers = workers, .chunk_size = chunk_kib * 1024 };

    const rss_before = peakRssBytes();
    const t0 = std.Io.Timestamp.now(io, .awake);
    var matched: u64 = 0;
    if (std.mem.eql(u8, mode, "seq")) {
        var mc = MatchCounter{};
        const res = if (use_regex)
            try internal.searchSourceRange(MatchCounter, gpa, &mc, ra, .{}, "f", &re, cfg)
        else
            try internal.searchSourceRange(MatchCounter, gpa, &mc, ra, .{}, "f", &lit, cfg);
        matched = res.matched_lines;
    } else if (std.mem.eql(u8, mode, "par")) {
        var mc = MatchCounter{};
        const res = if (use_regex)
            try internal.searchSourceParallelAt(MatchCounter, gpa, io, &mc, ra, "f", &re, cfg, opts)
        else
            try internal.searchSourceParallelAt(MatchCounter, gpa, io, &mc, ra, "f", &lit, cfg, opts);
        matched = res.matched_lines;
    } else if (std.mem.eql(u8, mode, "count-seq")) {
        var cs = CountSink{};
        const res = if (use_regex)
            try internal.searchRange(CountSink, gpa, &cs, ra, .{}, "f", &re, .{})
        else
            try internal.searchRange(CountSink, gpa, &cs, ra, .{}, "f", &lit, .{});
        matched = res.matched_lines;
    } else if (std.mem.eql(u8, mode, "count-par")) {
        const res = if (use_regex)
            try internal.countParallelAt(gpa, io, ra, &re, .{}, opts)
        else
            try internal.countParallelAt(gpa, io, ra, &lit, .{}, opts);
        matched = res.matched_lines;
    } else return usage();
    const t1 = std.Io.Timestamp.now(io, .awake);
    const secs = @as(f64, @floatFromInt(t0.durationTo(t1).nanoseconds)) / 1e9;
    const gbs = @as(f64, @floatFromInt(size)) / secs / 1e9;
    std.debug.print("mode={s} pattern={s} workers={?d} chunk_kib={d} bytes={d} secs={d:.3} gbs={d:.2} matched={d} rss_before_mib={d:.1} rss_peak_mib={d:.1}\n", .{
        mode, pat, workers, chunk_kib, size, secs, gbs, matched, mib(rss_before), mib(peakRssBytes()),
    });
}

fn usage() void {
    std.debug.print("usage: wg-par-bench gen <path> <MiB> | run <path> <seq|par|count-seq|count-par> <rare|lit|regex|ci> [workers] [chunk_kib]\n", .{});
}
