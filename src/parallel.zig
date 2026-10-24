//! Directory scheduling stays internal to the library; `run` and `Run.roots` are not exported from `src/root.zig`.
//! Service entry points are `searcher.searchSource` and `searcher.searchSourceSlice`.
//!
//! Scheduling for directory search. Each worker owns a Chase-Lev deque, a Finder, and a search buffer.
//!
//! Workers pop jobs from the bottom of their own deque (LIFO) and steal from the top of others' deques (FIFO).
//! No locks are acquired while busy. When a worker finds no work in a pass, it waits on a `std.Io.Condition`.
//! Enqueuing a subdirectory signals one worker if any are idle. When all workers are idle and a re-check under the lock
//! still finds no work, or when search stops early, the stop flag is set and broadcasted under the same lock.
//! With a single worker, no `Io.Group` is created; the calling thread runs the loop directly.
//!
//! Explicit files do not pass through here; callers process paths in argument order and use this scheduler only for directories.
//! Workers share no mutable search state. Output uses a single lock and writes per complete file.

const builtin = @import("builtin");
const std = @import("std");
const deque = @import("walk/deque.zig");
const finder_mod = @import("finder/finder.zig");
const matcher = @import("matcher.zig");
const multi_mod = @import("finder/multi.zig");
const searcher = @import("searcher.zig");
const sink_mod = @import("sink.zig");
const walker = @import("walk/walker.zig");

pub const max_concurrency_hard_cap: u32 = 32;

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
    /// Uses multi-pattern search when more than one pattern is present. An empty slice uses `pattern`.
    patterns: []const []const u8 = &.{},
    find: matcher.FindOptions = .{},
    roots: []const []const u8,
    search: searcher.SearchConfig = .{},
    walk: walker.Config = .{},
    emit: Emit = .text,
    stdout: *std.Io.Writer,
    column: bool = false,
    /// Retained for callers; the library no longer writes group separator text internally.
    use_separator: bool = false,
    saw_output: *bool,
    /// Retained field; summaries are now emitted via service-entry summary events rather than terminal text here.
    write_summary: bool = false,
    /// Optional streaming event callback: delivers events immediately as each source completes without buffering full results for sorting.
    on_event: ?*const fn (*anyopaque, sink_mod.Event) sink_mod.Flow = null,
    event_ctx: ?*anyopaque = null,
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
    /// When non-null, workers share this read-only automaton instead of using `finder`.
    many: ?*multi_mod.Multi = null,
    column: bool,
    use_separator: bool,
    saw: *bool,
    lock: std.Io.Mutex = .init,
    /// Guards idle waiting only. Deques remain Chase-Lev and the hot search path does not acquire this lock.
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
    request_cap: u64 = 0,
    request_used: std.atomic.Value(u64) = .init(0),
    errors: std.atomic.Value(u32) = .init(0),
    any_match: std.atomic.Value(bool) = .init(false),
    write_failed: std.atomic.Value(bool) = .init(false),
    on_event: ?*const fn (*anyopaque, sink_mod.Event) sink_mod.Flow = null,
    event_ctx: ?*anyopaque = null,

    fn emitEvent(self: *Shared, ev: sink_mod.Event) bool {
        const cb = self.on_event orelse return true;
        const ctx = self.event_ctx orelse return true;
        self.lock.lockUncancelable(self.io);
        defer self.lock.unlock(self.io);
        return switch (cb(ctx, ev)) {
            .cont => true,
            .pause, .stop => blk: {
                requestStop(self);
                break :blk false;
            },
        };
    }

    fn note(self: *Shared, path: []const u8, err: anyerror) void {
        _ = self.errors.fetchAdd(1, .monotonic);
        const log = self.search.log orelse return;
        var buf: [192]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "{s}: {s}", .{ path, @errorName(err) }) catch path;
        log(self.search.log_ctx, msg);
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
};

const Slot = struct {
    worker: *Worker,
};

const Budgets = struct {
    search: searcher.SearchConfig,
    walk: walker.Config,
    request_cap: u64,
};

fn alignBudgets(search: searcher.SearchConfig, walk: walker.Config) Budgets {
    var out_search = search;
    var out_walk = walk;
    const source_raw = search.max_source_bytes orelse walk.max_filesize orelse searcher.SearchConfig.default_max_source_bytes;
    const request_raw = search.max_request_bytes orelse searcher.SearchConfig.default_max_request_bytes;
    const source_cap = @min(source_raw, request_raw);
    out_search.max_source_bytes = source_cap;
    out_search.max_request_bytes = request_raw;
    out_walk.max_filesize = source_cap;
    if (out_search.time_budget_ns == null) {
        out_search.time_budget_ns = searcher.SearchConfig.default_time_budget_ns;
    }
    return .{
        .search = out_search,
        .walk = out_walk,
        .request_cap = request_raw,
    };
}

pub fn run(allocator: std.mem.Allocator, io: std.Io, req: Run) !Stats {
    const workers = resolveConcurrency(req.walk.threads, req.search.max_concurrency);
    const budgets = alignBudgets(req.search, req.walk);
    var walk_cfg = budgets.walk;
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
    try session.prepareConfig(io, req.walk);

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
        .search = budgets.search,
        .request_cap = budgets.request_cap,
        .emit = req.emit,
        .finder = finder,
        .many = if (many) |*engine| engine else null,
        .column = req.column,
        .use_separator = req.use_separator and req.emit == .text,
        .saw = req.saw_output,
        .workers = workers,
        .on_event = req.on_event,
        .event_ctx = req.event_ctx,
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

    _ = started;
    _ = req.stdout;
    _ = req.write_summary;
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

/// Re-checks queues under the lock and sleeps if no work is available. Returns `null` when stopped.
///
/// `Condition.signal` is lost when there are no waiters, and the enqueue side skips locking when the idle count is 0,
/// so a worker announces itself idle first and then re-checks under this lock; both sides synchronize on the same mutex.
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
    if (shared.request_used.load(.monotonic) >= shared.request_cap) {
        requestStop(shared);
        return .stop;
    }
    if (shared.emit == .files_only) {
        const count = shared.searches.fetchAdd(1, .monotonic) + 1;
        _ = shared.searches_with_match.fetchAdd(1, .monotonic);
        shared.any_match.store(true, .release);
        _ = shared.emitEvent(.{ .begin = .{ .source_id = visit.path } });
        _ = shared.emitEvent(.{ .end = .{
            .source_id = visit.path,
            .matched_lines = 0,
            .matches = 0,
            .bytes_read = 0,
            .outcome = .complete,
        } });
        if (shared.search.max_results) |max_res| {
            if (count >= max_res) {
                requestStop(shared);
                return .stop;
            }
        }
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

fn noteSoft(worker: *Worker, path: []const u8, result: searcher.Result) void {
    if (result.soft_error != null) worker.shared.note(path, error.ReadFailed);
}

fn searchOpen(worker: *Worker, file: std.Io.File, path: []const u8) !void {
    if (worker.shared.many) |many| return searchWith(worker, many, file, path);
    return searchWith(worker, &worker.finder, file, path);
}

fn searchWith(worker: *Worker, engine: anytype, file: std.Io.File, path: []const u8) !void {
    var cfg = worker.config();
    const used = worker.shared.request_used.load(.monotonic);
    if (used >= worker.shared.request_cap) return;
    const room = worker.shared.request_cap - used;
    if (cfg.max_source_bytes) |n| cfg.max_source_bytes = @min(n, room) else cfg.max_source_bytes = room;
    cfg.max_request_bytes = if (cfg.max_request_bytes) |n| @min(n, room) else room;
    var sink = Tally{
        .shared = worker.shared,
        .stop_file = worker.shared.emit == .files_with_matches,
        .source_id = path,
    };
    _ = worker.shared.emitEvent(.{ .begin = .{ .source_id = path } });
    const result = try searcher.searchFile(Tally, worker.shared.allocator, worker.shared.io, &sink, file, path, engine, cfg);
    noteSoft(worker, path, result);
    worker.shared.addSearch(result, result.matches, result.bytes_read, 0);
    _ = worker.shared.emitEvent(.{ .end = .{
        .source_id = path,
        .binary_status = if (result.nul_offset == null) .none else if (result.outcome == .binary_quit) .suppressed else .detected,
        .binary_offset = result.binary_offset,
        .matched_lines = result.matched_lines,
        .matches = result.matches,
        .bytes_read = result.bytes_read,
        .outcome = result.outcome,
        .limit_hit = result.limit_hit,
        .partial = result.partial,
        .resume_at = result.resume_at,
        .soft_error = result.soft_error,
    } });
    const charged = worker.shared.request_used.fetchAdd(result.bytes_read, .monotonic);
    if (charged + result.bytes_read >= worker.shared.request_cap) requestStop(worker.shared);
}

const Tally = struct {
    shared: *Shared,
    stop_file: bool,
    source_id: []const u8 = "",

    pub fn matched(self: *Tally, line: searcher.Line) bool {
        if (self.shared.on_event != null) {
            if (!self.shared.emitEvent(.{ .match = .{
                .source_id = self.source_id,
                .line_number = line.number orelse 1,
                .column = line.column,
                .u16_column = line.u16_column,
                .absolute_offset = line.offset,
                .raw_offset = line.raw_offset,
                .bytes = line.bytes,
                .text = line.text,
                .raw = line.raw,
                .replaced = line.replaced,
                .matches = line.matches,
                .truncated = line.truncated,
                .line_len = line.line_len,
                .window_start = line.window_start,
                .binary_status = line.binary_status,
            } })) return false;
        }
        if (self.shared.emit == .quiet) {
            requestStop(self.shared);
            return false;
        }
        if (self.stop_file) return false;
        return true;
    }
};

/// Worker thread count is determined strictly by caller configuration and never probes the host CPU core count.
/// Defaults to 1 (single-threaded) when unspecified (0) and is capped at `max_concurrency_hard_cap`.
pub fn resolveThreads(requested: u32) u32 {
    if (builtin.single_threaded) return 1;
    if (requested == 0) return 1;
    return @min(requested, max_concurrency_hard_cap);
}

pub fn resolveConcurrency(walk_threads: u32, max_concurrency: ?u32) u32 {
    if (max_concurrency) |mc| return resolveThreads(mc);
    return resolveThreads(walk_threads);
}

test "thread count is strictly bounded without probing CPU core count" {
    try testing.expectEqual(@as(u32, 1), resolveThreads(0));
    try testing.expectEqual(@as(u32, 1), resolveConcurrency(0, null));
    if (!builtin.single_threaded) {
        try testing.expectEqual(@as(u32, 4), resolveThreads(4));
        try testing.expectEqual(@as(u32, 6), resolveConcurrency(2, 6));
        try testing.expectEqual(max_concurrency_hard_cap, resolveThreads(999));
        try testing.expectEqual(max_concurrency_hard_cap, resolveConcurrency(1, 999));
    }
}

const testing = std.testing;

fn tempRoot(dir: std.Io.Dir) ![]u8 {
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const n = try dir.realPath(testing.io, &buf);
    return testing.allocator.dupe(u8, buf[0..n]);
}

test "single-threaded traversal skips gitignore and counts matches" {
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
    var saw = false;
    const stats = try run(testing.allocator, io, .{
        .pattern = "needle",
        .roots = &.{root},
        .walk = .{ .threads = 1 },
        .emit = .count,
        .stdout = &out.writer,
        .saw_output = &saw,
    });
    try testing.expectEqual(@as(u64, 2), stats.matched_lines);
    try testing.expectEqual(@as(u64, 2), stats.searches_with_match);
    try testing.expectEqual(@as(u64, 3), stats.searches);
    try testing.expectEqual(@as(u32, 0), stats.errors);
    try testing.expect(std.mem.indexOf(u8, out.written(), "skip.log") == null);
    try testing.expect(std.mem.indexOf(u8, out.written(), ".git") == null);
}

test "two workers do not lose matches" {
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
    var saw = false;
    const stats = try run(std.heap.smp_allocator, io, .{
        .pattern = "needle",
        .roots = &.{root},
        .walk = .{ .threads = 2 },
        .emit = .count,
        .stdout = &out.writer,
        .saw_output = &saw,
    });
    try testing.expectEqual(@as(u64, 4), stats.matched_lines);
    try testing.expectEqual(@as(u64, 3), stats.searches_with_match);
    try testing.expectEqual(@as(u32, 0), stats.errors);
}

test "directory search shares read-only multi-pattern automaton" {
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
    var saw = false;
    const stats = try run(testing.allocator, io, .{
        .patterns = &.{ "foo", "bar" },
        .roots = &.{root},
        .search = .{ .match_mode = .leftmost_first },
        .walk = .{ .threads = 1 },
        .emit = .count,
        .stdout = &out.writer,
        .saw_output = &saw,
    });
    try testing.expectEqual(@as(u64, 2), stats.matched_lines);
    try testing.expectEqual(@as(u64, 2), stats.searches_with_match);
    try testing.expectEqual(@as(u64, 3), stats.searches);
    try testing.expectEqual(@as(u32, 0), stats.errors);
}

test "idle workers woken by subdirectories do not lose matches" {
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
    var saw = false;
    const stats = try run(std.heap.smp_allocator, io, .{
        .pattern = "needle",
        .roots = &.{root},
        .walk = .{ .threads = 4 },
        .emit = .count,
        .stdout = &out.writer,
        .saw_output = &saw,
    });
    try testing.expectEqual(@as(u64, 8), stats.matched_lines);
    try testing.expectEqual(@as(u64, 8), stats.searches_with_match);
    try testing.expectEqual(@as(u32, 0), stats.errors);
}

test "files in a single large directory are not lost across multiple workers" {
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
    var saw = false;
    const stats = try run(std.heap.smp_allocator, io, .{
        .pattern = "needle",
        .roots = &.{root},
        .walk = .{ .threads = 4 },
        .emit = .count,
        .stdout = &out.writer,
        .saw_output = &saw,
    });
    try testing.expectEqual(@as(u64, 40), stats.matched_lines);
    try testing.expectEqual(@as(u64, 40), stats.searches);
    try testing.expectEqual(@as(u32, 0), stats.errors);
    try testing.expect(stats.bytes_searched >= 40);
}

test "quiet match wakes sleeping workers" {
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
    var saw = false;
    const stats = try run(std.heap.smp_allocator, io, .{
        .pattern = "needle",
        .roots = &.{root},
        .walk = .{ .threads = 4 },
        .emit = .quiet,
        .stdout = &out.writer,
        .saw_output = &saw,
    });
    try testing.expect(stats.matched);
    try testing.expect(stats.matched_lines >= 1);
    try testing.expectEqual(@as(u32, 0), stats.errors);
}

test "files-only listing counts toward traversal budget" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "a.txt", .data = "1\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b.txt", .data = "2\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "c.txt", .data = "3\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "d.txt", .data = "4\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "skip.log", .data = "5\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = ".gitignore", .data = "*.log\n" });

    const root = try tempRoot(tmp.dir);
    defer testing.allocator.free(root);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var saw = false;

    // 1. max_results limits the number of sources listed in files_only mode
    const stats_res = try run(testing.allocator, io, .{
        .roots = &.{root},
        .emit = .files_only,
        .search = .{ .max_results = 2 },
        .walk = .{ .threads = 1 },
        .stdout = &out.writer,
        .saw_output = &saw,
    });
    try testing.expectEqual(@as(u64, 2), stats_res.searches);
    try testing.expectEqual(@as(u64, 0), stats_res.bytes_searched);

    // 2. walk.max_entries limits the traversal entry budget
    const stats_entries = try run(testing.allocator, io, .{
        .roots = &.{root},
        .emit = .files_only,
        .walk = .{ .threads = 1, .max_entries = 3 },
        .stdout = &out.writer,
        .saw_output = &saw,
    });
    try testing.expectEqual(@as(u64, 3), stats_entries.searches);
}

test "multi-source streaming delivers events immediately without buffering all results for sorting" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "s1.txt", .data = "needle\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "s2.txt", .data = "other\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "s3.txt", .data = "needle\n" });

    const root = try tempRoot(tmp.dir);
    defer testing.allocator.free(root);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var saw = false;

    const StreamCheck = struct {
        begins: u32 = 0,
        matches: u32 = 0,
        ends: u32 = 0,
        stopped_after_first_end: bool = false,

        fn onEvent(ctx: *anyopaque, ev: sink_mod.Event) sink_mod.Flow {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            switch (ev) {
                .begin => self.begins += 1,
                .match => self.matches += 1,
                .end => {
                    self.ends += 1;
                    // Verify that end events are streamed as sources finish: stopping right after the first end proves results are not buffered and sorted across all sources first
                    if (self.stopped_after_first_end) return .stop;
                },
                else => {},
            }
            return .cont;
        }
    };

    var stream_all = StreamCheck{};
    const stats_all = try run(testing.allocator, io, .{
        .pattern = "needle",
        .roots = &.{root},
        .walk = .{ .threads = 1 },
        .emit = .count,
        .stdout = &out.writer,
        .saw_output = &saw,
        .on_event = StreamCheck.onEvent,
        .event_ctx = &stream_all,
    });
    try testing.expectEqual(@as(u64, 3), stats_all.searches);
    try testing.expectEqual(@as(u32, 3), stream_all.begins);
    try testing.expectEqual(@as(u32, 2), stream_all.matches);
    try testing.expectEqual(@as(u32, 3), stream_all.ends);

    // Verify that stopping on the first end event prevents subsequent sources from being scanned (proving streaming delivery rather than full buffering)
    var stream_early = StreamCheck{ .stopped_after_first_end = true };
    const stats_early = try run(testing.allocator, io, .{
        .pattern = "needle",
        .roots = &.{root},
        .walk = .{ .threads = 1 },
        .emit = .count,
        .stdout = &out.writer,
        .saw_output = &saw,
        .on_event = StreamCheck.onEvent,
        .event_ctx = &stream_early,
    });
    try testing.expectEqual(@as(u64, 1), stats_early.searches);
    try testing.expectEqual(@as(u32, 1), stream_early.ends);
}
