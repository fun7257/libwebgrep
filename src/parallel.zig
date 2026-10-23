//! 目录搜索的调度。每个工人有自己的 Chase-Lev 队列、Finder 和搜索缓冲。
//!
//! 工人从自己的队列尾部取任务（后进先出），从别人的队列头部偷（先进先出）。
//! 忙的时候不加锁。这一轮取不到，就在 `std.Io.Condition` 上等待。
//! 子目录入队时若已有空闲工人，就 `signal` 一个。全部空闲且锁里再偷一轮仍空，
//! 或者搜索要提前停，就在同一把锁下置停止标志并 `broadcast`。
//! 一个人时不建 `Io.Group`，调用线程自己跑同一套循环。
//!
//! 显式文件不进这里。调用方按参数顺序处理路径，目录才走这套调度。
//! 工人之间不共享可变的搜索状态。输出用一把锁，按整个文件写出。

const builtin = @import("builtin");
const std = @import("std");
const deque = @import("walk/deque.zig");
const finder_mod = @import("finder/finder.zig");
const matcher = @import("matcher.zig");
const files_printer = @import("printer/files.zig");
const json_printer = @import("printer/json.zig");
const count_printer = @import("printer/count.zig");
const text_printer = @import("printer/text.zig");
const multi_mod = @import("finder/multi.zig");
const searcher = @import("searcher.zig");
const walker = @import("walk/walker.zig");

pub const Emit = enum {
    text,
    count,
    files_with_matches,
    files_only,
    json,
    quiet,
};

pub const Stats = struct {
    matched: bool = false,
    errors: u32 = 0,
    searches: u64 = 0,
    searches_with_match: u64 = 0,
    matched_lines: u64 = 0,
    matches: u64 = 0,
    bytes_searched: u64 = 0,
    bytes_printed: u64 = 0,
};

pub const Run = struct {
    pattern: []const u8 = "",
    /// 多于一个时走多模式。空切片表示只用 `pattern`。
    patterns: []const []const u8 = &.{},
    find: matcher.FindOptions = .{},
    roots: []const []const u8,
    search: searcher.SearchConfig = .{},
    walk: walker.Config = .{},
    emit: Emit = .text,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    column: bool = false,
    /// 文本上下文分组之间写 `--`。
    use_separator: bool = false,
    saw_output: *bool,
    /// 为真时在结束时写一条 JSON summary。调用方要自己汇总多次调用时保持默认，不写。
    write_summary: bool = false,
};

const Queue = deque.Deque(walker.Job);

const Shared = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    deques: []Queue,
    session: *walker.Session,
    walk: walker.Config,
    search: searcher.SearchConfig,
    emit: Emit,
    finder: finder_mod.Finder,
    /// 非 null 时工人共享这一份只读自动机，不再使用 `finder`。
    many: ?*multi_mod.Multi = null,
    stdout: *std.Io.Writer,
    stderr: *std.Io.Writer,
    column: bool,
    use_separator: bool,
    saw: *bool,
    lock: std.Io.Mutex = .init,
    /// 只保护空闲等待。队列本身仍是 Chase-Lev，搜索热路径不拿这把锁。
    idle_mu: std.Io.Mutex = .init,
    idle_cv: std.Io.Condition = .init,
    stop: std.atomic.Value(bool) = .init(false),
    idle: std.atomic.Value(u32) = .init(0),
    workers: u32,
    searches: std.atomic.Value(u64) = .init(0),
    searches_with_match: std.atomic.Value(u64) = .init(0),
    matched_lines: std.atomic.Value(u64) = .init(0),
    matches: std.atomic.Value(u64) = .init(0),
    bytes_searched: std.atomic.Value(u64) = .init(0),
    bytes_printed: std.atomic.Value(u64) = .init(0),
    errors: std.atomic.Value(u32) = .init(0),
    any_match: std.atomic.Value(bool) = .init(false),
    write_failed: std.atomic.Value(bool) = .init(false),

    fn note(self: *Shared, path: []const u8, err: anyerror) void {
        _ = self.errors.fetchAdd(1, .monotonic);
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        self.stderr.print("libwebgrep: {s}: {t}\n", .{ path, err }) catch {};
    }

    fn addSearch(self: *Shared, result: searcher.Result, matches: u64, bytes: u64, printed: usize) void {
        _ = self.searches.fetchAdd(1, .monotonic);
        _ = self.bytes_searched.fetchAdd(bytes, .monotonic);
        _ = self.bytes_printed.fetchAdd(printed, .monotonic);
        _ = self.matched_lines.fetchAdd(result.matched_lines, .monotonic);
        _ = self.matches.fetchAdd(matches, .monotonic);
        if (result.matched_lines > 0) {
            _ = self.searches_with_match.fetchAdd(1, .monotonic);
            self.any_match.store(true, .release);
        }
    }
};

const Worker = struct {
    shared: *Shared,
    index: u32,
    finder: finder_mod.Finder,
    scratch: []u8 = &.{},
    buf: std.Io.Writer.Allocating,

    fn deinit(self: *Worker) void {
        if (self.scratch.len != 0) self.shared.allocator.free(self.scratch);
        self.buf.deinit();
    }

    fn config(self: *Worker) searcher.SearchConfig {
        var cfg = self.shared.search;
        cfg.scratch = &self.scratch;
        cfg.stop = &self.shared.stop;
        if (self.shared.emit == .json) cfg.line_numbers = true;
        if (cfg.binary != .none) cfg.binary = .quit;
        return cfg;
    }

    fn flush(self: *Worker, bytes: []const u8) !void {
        if (bytes.len == 0) return;
        self.shared.lock.lockUncancelable(self.shared.io);
        defer self.shared.lock.unlock(self.shared.io);
        if (self.shared.use_separator and self.shared.saw.*) {
            self.shared.stdout.writeAll("--\n") catch |err| {
                self.shared.write_failed.store(true, .release);
                return err;
            };
        }
        self.shared.stdout.writeAll(bytes) catch |err| {
            self.shared.write_failed.store(true, .release);
            return err;
        };
        self.shared.saw.* = true;
    }
};

const Slot = struct {
    worker: *Worker,
};

pub fn run(allocator: std.mem.Allocator, io: std.Io, req: Run) !Stats {
    const workers = resolveThreads(req.walk.threads);
    var walk_cfg = req.walk;
    walk_cfg.threads = workers;
    const deques = try allocator.alloc(Queue, workers);
    var ready: usize = 0;
    var session = walker.Session.init(allocator);
    defer {
        for (deques[0..ready]) |*queue| {
            while (queue.pop()) |job| job.destroy(io);
            queue.deinit();
        }
        allocator.free(deques);
        session.deinit();
    }
    for (deques) |*queue| {
        queue.* = try Queue.init(allocator, 8);
        ready += 1;
    }
    try session.prepareGlobs(io, req.walk.globs);

    const started = std.Io.Timestamp.now(io, .awake);
    var many: ?multi_mod.Multi = null;
    defer if (many) |*engine| engine.deinit();
    if (req.patterns.len > 1) {
        many = try multi_mod.Multi.init(allocator, req.patterns, req.find);
    }
    const finder = if (many != null)
        try finder_mod.Finder.init("", .{})
    else
        try finder_mod.Finder.init(req.pattern, req.find);
    var shared = Shared{
        .allocator = allocator,
        .io = io,
        .deques = deques,
        .session = &session,
        .walk = walk_cfg,
        .search = req.search,
        .emit = req.emit,
        .finder = finder,
        .many = if (many) |*engine| engine else null,
        .stdout = req.stdout,
        .stderr = req.stderr,
        .column = req.column,
        .use_separator = req.use_separator and req.emit == .text,
        .saw = req.saw_output,
        .workers = workers,
    };

    var bootstrap = Worker{
        .shared = &shared,
        .index = 0,
        .finder = finder,
        .buf = .init(allocator),
    };
    defer bootstrap.deinit();
    try pushRoots(&bootstrap, req.roots);

    if (workers == 1) {
        try workerMain(&shared, 0);
    } else {
        var group: std.Io.Group = .init;
        var index: u32 = 0;
        while (index < workers) : (index += 1) {
            try group.concurrent(io, workerMain, .{ &shared, index });
        }
        try group.await(io);
    }
    if (shared.write_failed.load(.acquire)) return error.WriteFailed;

    const elapsed = elapsedNanos(started.durationTo(std.Io.Timestamp.now(io, .awake)));
    if (req.write_summary and req.emit == .json) {
        const totals = json_printer.Totals{
            .searches = shared.searches.load(.monotonic),
            .searches_with_match = shared.searches_with_match.load(.monotonic),
            .bytes_searched = shared.bytes_searched.load(.monotonic),
            .bytes_printed = shared.bytes_printed.load(.monotonic),
            .matched_lines = shared.matched_lines.load(.monotonic),
            .matches = shared.matches.load(.monotonic),
        };
        var summary_buf: [512]u8 = undefined;
        var summary = std.Io.Writer.fixed(&summary_buf);
        json_printer.writeSummary(&summary, elapsed, totals) catch {
            try json_printer.writeSummary(req.stdout, elapsed, totals);
            return snapshot(&shared);
        };
        try req.stdout.writeAll(summary.buffered());
        _ = shared.bytes_printed.fetchAdd(summary.buffered().len, .monotonic);
    }
    return snapshot(&shared);
}

fn snapshot(shared: *Shared) Stats {
    return .{
        .matched = shared.any_match.load(.acquire),
        .errors = shared.errors.load(.monotonic),
        .searches = shared.searches.load(.monotonic),
        .searches_with_match = shared.searches_with_match.load(.monotonic),
        .matched_lines = shared.matched_lines.load(.monotonic),
        .matches = shared.matches.load(.monotonic),
        .bytes_searched = shared.bytes_searched.load(.monotonic),
        .bytes_printed = shared.bytes_printed.load(.monotonic),
    };
}

fn pushRoots(worker: *Worker, roots: []const []const u8) !void {
    var slot = Slot{ .worker = worker };
    var host = makeHost(worker, &slot);
    for (roots) |root| {
        const job = walker.createRoot(&host, root) catch |err| {
            worker.shared.note(root, err);
            continue;
        };
        worker.shared.deques[0].push(job) catch |err| {
            job.destroy(worker.shared.io);
            worker.shared.note(root, err);
        };
    }
}

fn workerMain(shared: *Shared, index: u32) std.Io.Cancelable!void {
    var worker = Worker{
        .shared = shared,
        .index = index,
        .finder = shared.finder,
        .buf = .init(shared.allocator),
    };
    defer worker.deinit();
    try workerLoop(&worker);
}

fn workerLoop(worker: *Worker) !void {
    const shared = worker.shared;
    const index = worker.index;
    while (true) {
        try shared.io.checkCancel();
        if (shared.stop.load(.acquire)) return;
        if (shared.deques[index].pop()) |job| {
            runJob(worker, job);
            continue;
        }
        if (stealJob(shared, index)) |job| {
            runJob(worker, job);
            continue;
        }
        if (try park(worker)) |job| {
            runJob(worker, job);
            continue;
        }
        return;
    }
}

/// 锁里复查队列，没有活就睡。返回 `null` 表示已经停止。
///
/// `Condition.signal` 在没有等待者时会丢掉。入队一侧看见空闲人数是 0 就不再加锁，
/// 所以先公布空闲，再在这把锁里复查；两边用同一把锁接上。
fn park(worker: *Worker) !?*walker.Job {
    const shared = worker.shared;
    const index = worker.index;
    try shared.idle_mu.lock(shared.io);
    defer shared.idle_mu.unlock(shared.io);

    if (shared.deques[index].pop()) |job| return job;
    if (stealJob(shared, index)) |job| return job;

    var announced = false;
    errdefer if (announced) {
        _ = shared.idle.fetchSub(1, .acq_rel);
    };
    const idle_now = shared.idle.fetchAdd(1, .acq_rel) + 1;
    announced = true;

    if (idle_now == shared.workers) {
        if (shared.deques[index].pop()) |job| {
            _ = shared.idle.fetchSub(1, .acq_rel);
            announced = false;
            return job;
        }
        if (stealJob(shared, index)) |job| {
            _ = shared.idle.fetchSub(1, .acq_rel);
            announced = false;
            return job;
        }
        shared.stop.store(true, .release);
        shared.idle_cv.broadcast(shared.io);
        return null;
    }

    while (!shared.stop.load(.acquire)) {
        if (shared.deques[index].pop()) |job| {
            _ = shared.idle.fetchSub(1, .acq_rel);
            announced = false;
            return job;
        }
        if (stealJob(shared, index)) |job| {
            _ = shared.idle.fetchSub(1, .acq_rel);
            announced = false;
            return job;
        }
        try shared.idle_cv.wait(shared.io, &shared.idle_mu);
    }
    return null;
}

fn requestStop(shared: *Shared) void {
    shared.idle_mu.lockUncancelable(shared.io);
    defer shared.idle_mu.unlock(shared.io);
    shared.stop.store(true, .release);
    shared.idle_cv.broadcast(shared.io);
}

fn stealJob(shared: *Shared, index: u32) ?*walker.Job {
    var step: u32 = 1;
    while (step < shared.workers) : (step += 1) {
        const other = (index + step) % shared.workers;
        if (shared.deques[other].steal()) |job| return job;
    }
    return null;
}

fn runJob(worker: *Worker, job: *walker.Job) void {
    var slot = Slot{ .worker = worker };
    var host = makeHost(worker, &slot);
    walker.process(&host, job);
}

fn makeHost(worker: *Worker, slot: *Slot) walker.Host {
    return .{
        .allocator = worker.shared.allocator,
        .io = worker.shared.io,
        .config = worker.shared.walk,
        .session = worker.shared.session,
        .stop = &worker.shared.stop,
        .push = pushJob,
        .push_ctx = slot,
        .on_file = onFile,
        .file_ctx = slot,
        .on_error = onError,
        .error_ctx = slot,
    };
}

fn pushJob(ctx: *anyopaque, job: *walker.Job) anyerror!void {
    const slot: *Slot = @ptrCast(@alignCast(ctx));
    const shared = slot.worker.shared;
    try shared.deques[slot.worker.index].push(job);
    if (shared.idle.load(.acquire) == 0) return;
    shared.idle_mu.lockUncancelable(shared.io);
    defer shared.idle_mu.unlock(shared.io);
    shared.idle_cv.signal(shared.io);
}

fn onError(ctx: *anyopaque, path: []const u8, err: anyerror) void {
    const slot: *Slot = @ptrCast(@alignCast(ctx));
    slot.worker.shared.note(path, err);
}

fn onFile(ctx: *anyopaque, visit: walker.Visit) anyerror!walker.Control {
    const slot: *Slot = @ptrCast(@alignCast(ctx));
    const worker = slot.worker;
    const shared = worker.shared;
    shared.io.checkCancel() catch {
        requestStop(shared);
        return .stop;
    };
    if (shared.stop.load(.acquire)) return .stop;
    if (shared.emit == .files_only) {
        printPath(worker, visit.path) catch |err| {
            requestStop(shared);
            shared.note(visit.path, err);
            return .stop;
        };
        _ = shared.searches.fetchAdd(1, .monotonic);
        shared.any_match.store(true, .release);
        return .cont;
    }

    const file = visit.dir.openFile(shared.io, visit.name, .{}) catch |err| {
        shared.note(visit.path, err);
        return .cont;
    };
    defer file.close(shared.io);
    searchOpen(worker, file, visit.path) catch |err| {
        requestStop(shared);
        shared.note(visit.path, err);
        return .stop;
    };
    if (shared.stop.load(.acquire)) return .stop;
    return .cont;
}

fn printPath(worker: *Worker, path: []const u8) !void {
    worker.buf.clearRetainingCapacity();
    try worker.buf.writer.print("{s}\n", .{path});
    const bytes = worker.buf.written();
    try worker.flush(bytes);
    _ = worker.shared.bytes_printed.fetchAdd(bytes.len, .monotonic);
}

fn searchOpen(worker: *Worker, file: std.Io.File, path: []const u8) !void {
    if (worker.shared.many) |many| return searchWith(worker, many, file, path);
    return searchWith(worker, &worker.finder, file, path);
}

fn searchWith(worker: *Worker, engine: anytype, file: std.Io.File, path: []const u8) !void {
    worker.buf.clearRetainingCapacity();
    const cfg = worker.config();
    const started = std.Io.Timestamp.now(worker.shared.io, .awake);
    switch (worker.shared.emit) {
        .files_only => unreachable,
        .text => {
            var sink = text_printer.Text{
                .writer = &worker.buf.writer,
                .show_path = true,
                .column = worker.shared.column,
            };
            const result = try searcher.searchFile(text_printer.Text, worker.shared.allocator, worker.shared.io, &sink, file, path, engine, cfg);
            if (sink.write_error) |err| return err;
            const bytes = worker.buf.written();
            try worker.flush(bytes);
            worker.shared.addSearch(result, result.matched_lines, result.bytes_read, bytes.len);
        },
        .count => {
            var sink = count_printer.Count{ .writer = &worker.buf.writer, .show_path = true };
            const result = try searcher.searchFile(count_printer.Count, worker.shared.allocator, worker.shared.io, &sink, file, path, engine, cfg);
            if (sink.write_error) |err| return err;
            const bytes = worker.buf.written();
            try worker.flush(bytes);
            worker.shared.addSearch(result, result.matched_lines, result.bytes_read, bytes.len);
        },
        .files_with_matches => {
            var sink = files_printer.Files{ .writer = &worker.buf.writer };
            const result = try searcher.searchFile(files_printer.Files, worker.shared.allocator, worker.shared.io, &sink, file, path, engine, cfg);
            if (sink.write_error) |err| return err;
            const bytes = worker.buf.written();
            try worker.flush(bytes);
            worker.shared.addSearch(result, result.matched_lines, result.bytes_read, bytes.len);
        },
        .quiet => {
            var sink = Quiet{ .shared = worker.shared };
            const result = try searcher.searchFile(Quiet, worker.shared.allocator, worker.shared.io, &sink, file, path, engine, cfg);
            worker.shared.addSearch(result, result.matched_lines, result.bytes_read, 0);
        },
        .json => {
            const JsonSink = json_printer.Printer(@TypeOf(engine.*));
            var sink = JsonSink{
                .writer = &worker.buf.writer,
                .finder = engine,
                .bytes_searched = 0,
            };
            const result = try searcher.searchFile(JsonSink, worker.shared.allocator, worker.shared.io, &sink, file, path, engine, cfg);
            if (sink.write_error) |err| return err;
            sink.bytes_searched = result.bytes_read;
            const elapsed = elapsedNanos(started.durationTo(std.Io.Timestamp.now(worker.shared.io, .awake)));
            if (sink.started and !sink.writeEnd(elapsed)) {
                if (sink.write_error) |err| return err;
            }
            const bytes = worker.buf.written();
            if (sink.started) try worker.flush(bytes);
            worker.shared.addSearch(result, sink.matches, result.bytes_read, bytes.len);
        },
    }
}

const Quiet = struct {
    shared: *Shared,

    pub fn matched(self: *Quiet, line: searcher.Line) bool {
        _ = line;
        requestStop(self.shared);
        return false;
    }
};

pub fn resolveThreads(requested: u32) u32 {
    if (builtin.single_threaded) return 1;
    if (requested != 0) return requested;
    const logical = std.Thread.getCpuCount() catch 1;
    var count = logical;
    // 大小核上，逻辑 CPU 数会把一半工人放到能效核。目录搜索要等最慢的工人，
    // 8 线程的合计 system 时间大约是 4 个性能核的两倍，墙钟更慢。显式 -j 不走这里。
    if (performanceCoreCount()) |perf| {
        if (perf > 0 and perf < logical) count = perf;
    }
    if (count == 0) return 1;
    return @intCast(@min(count, std.math.maxInt(u32)));
}

fn performanceCoreCount() ?usize {
    if (comptime !builtin.os.tag.isDarwin()) return null;
    var count: c_int = 0;
    var len: usize = @sizeOf(c_int);
    const rc = std.posix.system.sysctlbyname("hw.perflevel0.physicalcpu", &count, &len, null, 0);
    switch (std.posix.errno(rc)) {
        .SUCCESS => {},
        else => return null,
    }
    if (count <= 0) return null;
    return @intCast(count);
}

test "默认工人数在性能核更少时用性能核" {
    if (builtin.single_threaded) return;
    const logical = std.Thread.getCpuCount() catch 1;
    const n = resolveThreads(0);
    if (performanceCoreCount()) |perf| {
        if (perf > 0 and perf < logical) {
            try testing.expectEqual(@as(u32, @intCast(perf)), n);
            return;
        }
    }
    const expect: u32 = @intCast(@min(@max(logical, 1), std.math.maxInt(u32)));
    try testing.expectEqual(expect, n);
}

fn elapsedNanos(duration: std.Io.Duration) u64 {
    if (duration.nanoseconds <= 0) return 0;
    const wide: u128 = @intCast(duration.nanoseconds);
    if (wide > std.math.maxInt(u64)) return std.math.maxInt(u64);
    return @intCast(wide);
}

const testing = std.testing;

fn tempRoot(dir: std.Io.Dir) ![]u8 {
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const n = try dir.realPath(testing.io, &buf);
    return testing.allocator.dupe(u8, buf[0..n]);
}

test "单线程遍历会跳过 gitignore 并统计命中" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "a.txt", .data = "needle\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b.txt", .data = "nope\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "skip.log", .data = "needle\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = ".gitignore", .data = "*.log\n" });
    try tmp.dir.createDir(io, "sub", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/c.txt", .data = "needle\n" });
    try tmp.dir.createDir(io, ".git", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = ".git/config", .data = "needle\n" });

    const root = try tempRoot(tmp.dir);
    defer testing.allocator.free(root);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err_w: std.Io.Writer.Allocating = .init(testing.allocator);
    defer err_w.deinit();
    var saw = false;
    const stats = try run(testing.allocator, io, .{
        .pattern = "needle",
        .roots = &.{root},
        .walk = .{ .threads = 1 },
        .emit = .count,
        .stdout = &out.writer,
        .stderr = &err_w.writer,
        .saw_output = &saw,
    });
    try testing.expectEqual(@as(u64, 2), stats.matched_lines);
    try testing.expectEqual(@as(u64, 2), stats.searches_with_match);
    try testing.expectEqual(@as(u64, 3), stats.searches);
    try testing.expectEqual(@as(u32, 0), stats.errors);
    try testing.expectEqualStrings("", err_w.written());
    try testing.expect(std.mem.indexOf(u8, out.written(), "skip.log") == null);
    try testing.expect(std.mem.indexOf(u8, out.written(), ".git") == null);
}

test "两个工人不会丢匹配" {
    if (builtin.single_threaded) return;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "a.txt", .data = "needle\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b.txt", .data = "needle\n" });
    try tmp.dir.createDir(io, "sub", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/c.txt", .data = "needle\nno\nneedle\n" });

    const root = try tempRoot(tmp.dir);
    defer testing.allocator.free(root);
    var out: std.Io.Writer.Allocating = .init(std.heap.smp_allocator);
    defer out.deinit();
    var err_w: std.Io.Writer.Allocating = .init(std.heap.smp_allocator);
    defer err_w.deinit();
    var saw = false;
    const stats = try run(std.heap.smp_allocator, io, .{
        .pattern = "needle",
        .roots = &.{root},
        .walk = .{ .threads = 2 },
        .emit = .count,
        .stdout = &out.writer,
        .stderr = &err_w.writer,
        .saw_output = &saw,
    });
    try testing.expectEqual(@as(u64, 4), stats.matched_lines);
    try testing.expectEqual(@as(u64, 3), stats.searches_with_match);
    try testing.expectEqual(@as(u32, 0), stats.errors);
}

test "目录搜索共享只读的多模式自动机" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "a.txt", .data = "foobar\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b.txt", .data = "nope\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "c.txt", .data = "bar\n" });

    const root = try tempRoot(tmp.dir);
    defer testing.allocator.free(root);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var err_w: std.Io.Writer.Allocating = .init(testing.allocator);
    defer err_w.deinit();
    var saw = false;
    const stats = try run(testing.allocator, io, .{
        .patterns = &.{ "foo", "bar" },
        .roots = &.{root},
        .search = .{ .match_mode = .leftmost_first },
        .walk = .{ .threads = 1 },
        .emit = .count,
        .stdout = &out.writer,
        .stderr = &err_w.writer,
        .saw_output = &saw,
    });
    try testing.expectEqual(@as(u64, 2), stats.matched_lines);
    try testing.expectEqual(@as(u64, 2), stats.searches_with_match);
    try testing.expectEqual(@as(u64, 3), stats.searches);
    try testing.expectEqual(@as(u32, 0), stats.errors);
}

test "空闲工人被子目录叫醒后不会丢匹配" {
    if (builtin.single_threaded) return;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    const names = [_][]const u8{ "d0", "d1", "d2", "d3", "d4", "d5", "d6", "d7" };
    for (names) |name| {
        try tmp.dir.createDir(io, name, .default_dir);
        var path_buf: [16]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "{s}/a.txt", .{name});
        try tmp.dir.writeFile(io, .{ .sub_path = path, .data = "needle\n" });
    }

    const root = try tempRoot(tmp.dir);
    defer testing.allocator.free(root);
    var out: std.Io.Writer.Allocating = .init(std.heap.smp_allocator);
    defer out.deinit();
    var err_w: std.Io.Writer.Allocating = .init(std.heap.smp_allocator);
    defer err_w.deinit();
    var saw = false;
    const stats = try run(std.heap.smp_allocator, io, .{
        .pattern = "needle",
        .roots = &.{root},
        .walk = .{ .threads = 4 },
        .emit = .count,
        .stdout = &out.writer,
        .stderr = &err_w.writer,
        .saw_output = &saw,
    });
    try testing.expectEqual(@as(u64, 8), stats.matched_lines);
    try testing.expectEqual(@as(u64, 8), stats.searches_with_match);
    try testing.expectEqual(@as(u32, 0), stats.errors);
}

test "同一个大目录里的文件不会被多工人丢掉" {
    if (builtin.single_threaded) return;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    var i: usize = 0;
    while (i < 40) : (i += 1) {
        var path_buf: [16]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "f{d:0>2}.txt", .{i});
        try tmp.dir.writeFile(io, .{ .sub_path = path, .data = "needle\n" });
    }

    const root = try tempRoot(tmp.dir);
    defer testing.allocator.free(root);
    var out: std.Io.Writer.Allocating = .init(std.heap.smp_allocator);
    defer out.deinit();
    var err_w: std.Io.Writer.Allocating = .init(std.heap.smp_allocator);
    defer err_w.deinit();
    var saw = false;
    const stats = try run(std.heap.smp_allocator, io, .{
        .pattern = "needle",
        .roots = &.{root},
        .walk = .{ .threads = 4 },
        .emit = .count,
        .stdout = &out.writer,
        .stderr = &err_w.writer,
        .saw_output = &saw,
    });
    try testing.expectEqual(@as(u64, 40), stats.matched_lines);
    try testing.expectEqual(@as(u64, 40), stats.searches);
    try testing.expectEqual(@as(u32, 0), stats.errors);
    try testing.expect(stats.bytes_searched >= 40);
}

test "quiet 命中会叫醒已经睡着的工人" {
    if (builtin.single_threaded) return;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "hit.txt", .data = "needle\n" });
    try tmp.dir.createDir(io, "sub", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/a.txt", .data = "needle\n" });

    const root = try tempRoot(tmp.dir);
    defer testing.allocator.free(root);
    var out: std.Io.Writer.Allocating = .init(std.heap.smp_allocator);
    defer out.deinit();
    var err_w: std.Io.Writer.Allocating = .init(std.heap.smp_allocator);
    defer err_w.deinit();
    var saw = false;
    const stats = try run(std.heap.smp_allocator, io, .{
        .pattern = "needle",
        .roots = &.{root},
        .walk = .{ .threads = 4 },
        .emit = .quiet,
        .stdout = &out.writer,
        .stderr = &err_w.writer,
        .saw_output = &saw,
    });
    try testing.expect(stats.matched);
    try testing.expect(stats.matched_lines >= 1);
    try testing.expectEqual(@as(u32, 0), stats.errors);
}
