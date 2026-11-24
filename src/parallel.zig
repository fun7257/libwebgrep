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
const decompress = @import("codec/decompress.zig");
const platform = @import("io/platform.zig");
const deque = @import("walk/deque.zig");
const finder_mod = @import("finder/finder.zig");
const matcher = @import("matcher.zig");
const memchr = @import("finder/memchr.zig");
const multi_mod = @import("finder/multi.zig");
const probe = @import("probe.zig");
const regex_mod = @import("regex/vm.zig");
const regex_set_mod = @import("regex/set.zig");
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
    /// Optional compiled regex shared read-only across all worker threads.
    regex: ?*const regex_mod.Regex = null,
    /// Optional compiled regex set shared read-only across all worker threads.
    regex_set: ?*const regex_set_mod.RegexSet = null,
    find: matcher.FindOptions = .{},
    roots: []const []const u8,
    search: searcher.SearchConfig = .{},
    walk: walker.Config = .{},
    max_threads: ?u32 = null,
    /// When true (default), applies multi-tenant default byte and time budgets matching `serviceConfig`.
    /// Set to false for unconstrained local CLI/benchmark directory runs.
    enforce_service_budgets: bool = true,
    use_mmap: bool = false,
    count_lines_only: bool = false,
    /// Emit only matched spans (equivalent to `-o`/`--only-matching`) in direct text output mode.
    only_matching: bool = false,
    /// Optional output flag set to true if any soft walk/open/read errors occurred during the run.
    has_soft_errors: ?*bool = null,
    emit: Emit = .text,
    stdout: *std.Io.Writer,
    column: bool = false,
    /// Retained for callers; the library no longer writes group separator text internally.
    use_separator: bool = false,
    saw_output: *bool,
    /// Retained field; summaries are now emitted via service-entry summary events rather than terminal text here.
    write_summary: bool = false,
    /// When true and `on_event == null`, workers format matched lines/counts directly into bounded
    /// worker-local buffers and batch-flush to `stdout` under `shared.lock`, eliminating per-line
    /// mutex contention while keeping per-worker output memory bounded.
    write_output: bool = false,
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
    use_mmap: bool = false,
    count_lines_only: bool = false,
    only_matching: bool = false,
    finder: finder_mod.Finder,
    /// When non-null, workers share this read-only automaton instead of using `finder`.
    many: ?*multi_mod.Multi = null,
    regex: ?*const regex_mod.Regex = null,
    regex_set: ?*const regex_set_mod.RegexSet = null,
    column: bool,
    use_separator: bool,
    stdout: *std.Io.Writer,
    write_output: bool = false,
    saw: *bool,
    lock: std.Io.Mutex = .init,
    /// Guards idle waiting only. Deques remain Chase-Lev and the hot search path does not acquire this lock.
    idle_mu: std.Io.Mutex = .init,
    idle_cv: std.Io.Condition = .init,
    stop: std.atomic.Value(bool) = .init(false),
    idle: std.atomic.Value(u32) = .init(0),
    /// Workers not currently executing a job (includes both parked workers and freshly spawned workers
    /// that have not yet claimed their first job). Passed to `walker.Host.idle` so the root worker
    /// fans out initial files deterministically instead of racing worker startup and scanning a huge file inline.
    available_workers: std.atomic.Value(u32) = .init(0),
    /// Number of jobs currently queued across all worker deques.
    pending_jobs: std.atomic.Value(u32) = .init(0),
    /// Additional sub-worker threads currently leased to intra-source parallel scans.
    extra_workers: std.atomic.Value(u32) = .init(0),
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
    decomp_stream_buf: []u8 = &.{},
    zstd_win_buf: []u8 = &.{},
    out_buf: std.ArrayList(u8) = .empty,
    local_searches: u64 = 0,
    local_searches_with_match: u64 = 0,
    local_matched_lines: u64 = 0,
    local_matches: u64 = 0,
    local_bytes_searched: u64 = 0,
    local_bytes_printed: u64 = 0,

    fn deinit(self: *Worker) void {
        if (self.scratch.len != 0) self.shared.allocator.free(self.scratch);
        if (self.decomp_stream_buf.len != 0) self.shared.allocator.free(self.decomp_stream_buf);
        if (self.zstd_win_buf.len != 0) self.shared.allocator.free(self.zstd_win_buf);
        self.out_buf.deinit(self.shared.allocator);
    }

    fn recordSearch(self: *Worker, result: searcher.Result, matches: u64, bytes: u64) void {
        self.local_searches += 1;
        self.local_bytes_searched += bytes;
        self.local_matched_lines += result.matched_lines;
        self.local_matches += matches;
        if (result.matched_lines > 0) {
            self.local_searches_with_match += 1;
        }
    }

    fn flushOut(self: *Worker) void {
        if (self.out_buf.items.len == 0) return;
        const data = self.out_buf.items;
        self.shared.lock.lockUncancelable(self.shared.io);
        defer self.shared.lock.unlock(self.shared.io);
        if (!self.shared.write_failed.load(.monotonic)) {
            self.shared.stdout.writeAll(data) catch {
                self.shared.write_failed.store(true, .release);
                requestStop(self.shared);
            };
            self.shared.saw.* = true;
        }
        self.local_bytes_printed += data.len;
        self.out_buf.clearRetainingCapacity();
    }

    fn flushStats(self: *Worker) void {
        if (self.local_searches > 0) _ = self.shared.searches.fetchAdd(self.local_searches, .monotonic);
        if (self.local_searches_with_match > 0) {
            _ = self.shared.searches_with_match.fetchAdd(self.local_searches_with_match, .monotonic);
            self.shared.any_match.store(true, .release);
        }
        if (self.local_matched_lines > 0) _ = self.shared.matched_lines.fetchAdd(self.local_matched_lines, .monotonic);
        if (self.local_matches > 0) _ = self.shared.matches.fetchAdd(self.local_matches, .monotonic);
        if (self.local_bytes_searched > 0) _ = self.shared.bytes_searched.fetchAdd(self.local_bytes_searched, .monotonic);
        if (self.local_bytes_printed > 0) _ = self.shared.bytes_printed.fetchAdd(self.local_bytes_printed, .monotonic);
    }

    fn config(self: *Worker) searcher.SearchConfig {
        var cfg = self.shared.search;
        if (cfg.buffer_size == searcher.SearchConfig.default_buffer_size) {
            cfg.buffer_size = searcher.SearchConfig.optimalBufferSize(self.shared.workers);
        }
        cfg.scratch = &self.scratch;
        cfg.stop = &self.shared.stop;
        if (cfg.decode_allocator == null) cfg.decode_allocator = self.shared.allocator;
        if (self.shared.emit == .json) cfg.line_numbers = true;
        if (cfg.binary != .none and cfg.binary != .report) cfg.binary = .quit;
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

fn alignBudgets(search: searcher.SearchConfig, walk: walker.Config, enforce_defaults: bool) Budgets {
    var out_search = search;
    var out_walk = walk;
    if (enforce_defaults) {
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
    const source_cap = if (search.max_source_bytes) |s|
        if (walk.max_filesize) |w| @min(s, w) else s
    else
        walk.max_filesize;
    const request_cap = search.max_request_bytes;
    const effective_source = if (source_cap) |s|
        if (request_cap) |r| @min(s, r) else s
    else
        request_cap;

    out_search.max_source_bytes = effective_source;
    out_search.max_request_bytes = request_cap;
    out_walk.max_filesize = effective_source;
    return .{
        .search = out_search,
        .walk = out_walk,
        .request_cap = request_cap orelse std.math.maxInt(u64),
    };
}

pub fn run(allocator: std.mem.Allocator, io: std.Io, req: Run) !Stats {
    const workers = if (req.walk.sort_by != .none)
        @as(u32, 1)
    else
        resolveConcurrencyWithCap(req.walk.threads, req.search.max_concurrency, req.max_threads);
    const budgets = alignBudgets(req.search, req.walk, req.enforce_service_budgets);
    var walk_cfg = budgets.walk;
    walk_cfg.threads = workers;
    if (req.emit == .files_only) walk_cfg.inline_files = true;
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
    try session.prepareConfig(io, walk_cfg);

    var many: ?multi_mod.Multi = null;
    defer if (many) |*engine| engine.deinit();
    if (req.patterns.len > 1 and req.regex == null and req.regex_set == null) {
        many = try multi_mod.Multi.init(allocator, req.patterns, req.find);
    }
    const finder = if (many != null or req.regex != null or req.regex_set != null)
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
        .use_mmap = req.use_mmap,
        .count_lines_only = req.count_lines_only,
        .only_matching = req.only_matching,
        .finder = finder,
        .many = if (many) |*engine| engine else null,
        .regex = req.regex,
        .regex_set = req.regex_set,
        .column = req.column,
        .use_separator = req.use_separator and req.emit == .text,
        .stdout = req.stdout,
        .write_output = req.write_output,
        .saw = req.saw_output,
        .workers = workers,
        .available_workers = .init(workers),
        .on_event = req.on_event,
        .event_ctx = req.event_ctx,
    };

    var bootstrap = Worker{
        .shared = &shared,
        .index = 0,
        .finder = finder,
    };
    defer bootstrap.deinit();
    try pushRoots(&bootstrap, req.roots);

    if (workers == 1) {
        try workerMain(&shared, 0);
    } else {
        // Spawn `workers - 1` helper tasks and execute worker 0 on the calling thread
        // to avoid an idle coordinator thread and unnecessary stack/scheduler overhead.
        var group: std.Io.Group = .init;
        var spawn_err: ?anyerror = null;
        var index: u32 = 1;
        while (index < workers) : (index += 1) {
            group.concurrent(io, workerMain, .{ &shared, index }) catch |err| {
                requestStop(&shared);
                spawn_err = err;
                break;
            };
        }
        var self_res: std.Io.Cancelable!void = {};
        if (spawn_err == null) {
            self_res = workerMain(&shared, 0);
        }
        const await_res = group.await(io);
        if (spawn_err) |err| return err;
        try self_res;
        try await_res;
    }
    if (shared.write_failed.load(.acquire)) return error.WriteFailed;

    _ = req.write_summary;
    const stats = snapshot(&shared);
    if (req.has_soft_errors) |flag| flag.* = (stats.errors > 0);
    return stats;
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
            continue;
        };
        _ = worker.shared.pending_jobs.fetchAdd(1, .release);
    }
}

fn workerMain(shared: *Shared, index: u32) std.Io.Cancelable!void {
    errdefer requestStop(shared);
    var worker = Worker{
        .shared = shared,
        .index = index,
        .finder = shared.finder,
    };
    defer {
        worker.flushOut();
        worker.flushStats();
        worker.deinit();
    }
    try workerLoop(&worker);
}

fn workerLoop(worker: *Worker) !void {
    const shared = worker.shared;
    const index = worker.index;
    while (true) {
        try shared.io.checkCancel();
        if (shared.stop.load(.acquire)) return;
        if (popLocalJob(shared, index)) |job| {
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

fn popLocalJob(shared: *Shared, index: u32) ?*walker.Job {
    const job = shared.deques[index].pop() orelse return null;
    _ = shared.pending_jobs.fetchSub(1, .acq_rel);
    return job;
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

    if (popLocalJob(shared, index)) |job| return job;
    if (stealJob(shared, index)) |job| return job;

    var announced = false;
    errdefer if (announced) {
        _ = shared.idle.fetchSub(1, .acq_rel);
    };
    const idle_now = shared.idle.fetchAdd(1, .acq_rel) + 1;
    announced = true;

    if (idle_now == shared.workers) {
        if (popLocalJob(shared, index)) |job| {
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
        if (popLocalJob(shared, index)) |job| {
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
        if (shared.deques[other].steal()) |job| {
            _ = shared.pending_jobs.fetchSub(1, .acq_rel);
            return job;
        }
    }
    return null;
}

fn runJob(worker: *Worker, job: *walker.Job) void {
    _ = worker.shared.available_workers.fetchSub(1, .acq_rel);
    defer _ = worker.shared.available_workers.fetchAdd(1, .acq_rel);
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
        .idle = &worker.shared.available_workers,
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
    _ = shared.pending_jobs.fetchAdd(1, .release);
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
    if (shared.request_cap != std.math.maxInt(u64) and shared.request_used.load(.monotonic) >= shared.request_cap) {
        requestStop(shared);
        return .stop;
    }
    if (shared.emit == .files_only) {
        if (shared.write_output and shared.on_event == null) {
            if (shared.search.max_results) |max_res| {
                const count = shared.searches.fetchAdd(1, .monotonic) + 1;
                if (count > max_res) {
                    requestStop(shared);
                    return .stop;
                }
                _ = shared.searches_with_match.fetchAdd(1, .monotonic);
                shared.any_match.store(true, .release);
                const alloc = shared.allocator;
                worker.out_buf.ensureUnusedCapacity(alloc, visit.path.len + 1) catch {
                    requestStop(shared);
                    return .stop;
                };
                worker.out_buf.appendSliceAssumeCapacity(visit.path);
                worker.out_buf.appendAssumeCapacity('\n');
                if (worker.out_buf.items.len >= 64 * 1024) {
                    worker.flushOut();
                    if (shared.write_failed.load(.acquire)) return .stop;
                }
                if (count >= max_res) {
                    requestStop(shared);
                    return .stop;
                }
                return .cont;
            }
            worker.local_searches += 1;
            worker.local_searches_with_match += 1;
            const alloc = shared.allocator;
            worker.out_buf.ensureUnusedCapacity(alloc, visit.path.len + 1) catch {
                requestStop(shared);
                return .stop;
            };
            worker.out_buf.appendSliceAssumeCapacity(visit.path);
            worker.out_buf.appendAssumeCapacity('\n');
            if (worker.out_buf.items.len >= 64 * 1024) {
                worker.flushOut();
                if (shared.write_failed.load(.acquire)) return .stop;
            }
            return .cont;
        }
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
        shared.note(visit.path, err);
        switch (err) {
            error.OutOfMemory, error.ContextLinesExceeded, error.BudgetExceeded => {
                requestStop(shared);
                return .stop;
            },
            else => {
                _ = shared.emitEvent(.{ .end = .{
                    .source_id = visit.path,
                    .outcome = .complete,
                    .soft_error = .read_failed,
                } });
                return .cont;
            },
        }
    };
    if (shared.stop.load(.acquire)) return .stop;
    return .cont;
}

fn noteSoft(worker: *Worker, path: []const u8, result: searcher.Result) void {
    if (result.soft_error != null) worker.shared.note(path, error.ReadFailed);
}

fn searchOpen(worker: *Worker, file: std.Io.File, path: []const u8) !void {
    if (worker.shared.regex) |re| return searchWith(worker, re, file, path);
    if (worker.shared.regex_set) |rs| return searchWith(worker, rs, file, path);
    if (worker.shared.many) |many| return searchWith(worker, many, file, path);
    return searchWith(worker, &worker.finder, file, path);
}

const CountTally = struct {};

const FileRa = struct {
    file: std.Io.File,
    io: std.Io,

    fn readAt(ctx: ?*anyopaque, offset: u64, dest: []u8) anyerror!usize {
        const self: *FileRa = @ptrCast(@alignCast(ctx.?));
        return self.file.readPositional(self.io, &.{dest}, offset);
    }
};

/// Atomically leases spare thread capacity from currently parked top-level workers so that
/// huge-file escalation accelerates skewed directories without ever oversubscribing `shared.workers`.
fn claimExtraWorkers(shared: *Shared) u32 {
    if (shared.workers <= 1) return 0;
    if (shared.pending_jobs.load(.acquire) != 0) return 0;
    while (true) {
        const idle_now = shared.idle.load(.acquire);
        if (idle_now == 0) return 0;
        const cur_extra = shared.extra_workers.load(.acquire);
        const cap = @min(idle_now, shared.workers - 1);
        if (cur_extra >= cap) return 0;
        const avail = cap - cur_extra;
        const busy_top: u32 = if (shared.workers > idle_now) shared.workers - idle_now else 1;
        const claim: u32 = if (busy_top <= 1) avail else @max(@as(u32, 1), avail / busy_top);
        if (shared.extra_workers.cmpxchgWeak(cur_extra, cur_extra + claim, .acq_rel, .acquire) == null) {
            return claim;
        }
    }
}

fn zstdFrameWindowLen(compressed: []const u8) u32 {
    const default_win: u32 = std.compress.zstd.default_window_len;
    const min_win: u64 = 128 * 1024;
    if (compressed.len < 6) return default_win;
    if (!std.mem.eql(u8, compressed[0..4], &.{ 0x28, 0xB5, 0x2F, 0xFD })) return default_win;
    const fhd = compressed[4];
    const single_segment = ((fhd >> 5) & 1) != 0;
    if (!single_segment) {
        const wd = compressed[5];
        const exp: u6 = @intCast(wd >> 3);
        if (exp > 20) return default_win;
        const man: u64 = wd & 7;
        const base: u64 = @as(u64, 1) << (@as(u6, 10) + exp);
        const win = base + (base >> 3) * man;
        return @intCast(@min(@max(win, min_win), @as(u64, default_win)));
    }
    const did_flag = fhd & 3;
    const did_size: usize = switch (did_flag) {
        0 => 0,
        1 => 1,
        2 => 2,
        else => 4,
    };
    const fcs_flag = fhd >> 6;
    const fcs_size: usize = switch (fcs_flag) {
        0 => 1,
        1 => 2,
        2 => 4,
        else => 8,
    };
    const fcs_off = 5 + did_size;
    if (fcs_off + fcs_size > compressed.len) return default_win;
    const fcs: u64 = switch (fcs_flag) {
        0 => compressed[fcs_off],
        1 => @as(u64, std.mem.readInt(u16, compressed[fcs_off..][0..2], .little)) + 256,
        2 => std.mem.readInt(u32, compressed[fcs_off..][0..4], .little),
        else => std.mem.readInt(u64, compressed[fcs_off..][0..8], .little),
    };
    return @intCast(@min(@max(fcs, min_win), @as(u64, default_win)));
}

fn tryStreamCompressed(
    comptime S: type,
    worker: *Worker,
    sink: *S,
    file: std.Io.File,
    path: []const u8,
    engine: anytype,
    cfg: searcher.SearchConfig,
) !?searcher.Result {
    const shared = worker.shared;
    if (shared.on_event != null or cfg.compression == .none) return null;
    if (cfg.byte_range != null or cfg.resume_from != 0) return null;
    if (cfg.max_source_bytes != null or cfg.max_request_bytes != null or cfg.max_decompressed_bytes != null) return null;
    if (cfg.max_compression_ratio == null or cfg.max_compression_ratio.? != std.math.maxInt(u64)) return null;

    const st = file.stat(shared.io) catch return null;
    if (st.kind != .file) return null;
    if (st.size == 0) {
        var slice_cfg = cfg;
        slice_cfg.compression = .none;
        return try searcher.searchSlice(S, sink, &.{}, path, engine, slice_cfg);
    }
    const max_comp_size: u64 = 64 * 1024 * 1024;
    if (st.size > max_comp_size) return null;

    const need: usize = @intCast(st.size);
    if (worker.scratch.len < need) {
        const alloc_sz = @max(need, @as(usize, 64 * 1024));
        if (worker.scratch.len != 0) shared.allocator.free(worker.scratch);
        worker.scratch = &.{};
        worker.scratch = try shared.allocator.alloc(u8, alloc_sz);
    }
    var got: usize = 0;
    while (got < need) {
        var iov = [_][]u8{worker.scratch[got..need]};
        const n = file.readPositional(shared.io, &iov, got) catch return null;
        if (n == 0) break;
        got += n;
    }
    const compressed = worker.scratch[0..got];
    const format: decompress.Detected = switch (cfg.compression) {
        .auto => decompress.sniff(compressed, true),
        .gzip => .gzip,
        .zstd => .zstd,
        .zlib => .zlib,
        .deflate => .deflate,
        else => return null,
    };
    switch (format) {
        .raw, .need_more => {
            var slice_cfg = cfg;
            slice_cfg.compression = .none;
            return try searcher.searchSlice(S, sink, compressed, path, engine, slice_cfg);
        },
        .gzip, .zlib, .deflate => {
            var in_reader = std.Io.Reader.fixed(compressed);
            var window: [std.compress.flate.max_window_len]u8 = undefined;
            const container: std.compress.flate.Container = switch (format) {
                .gzip => .gzip,
                .zlib => .zlib,
                .deflate => .raw,
                else => unreachable,
            };
            var dec = std.compress.flate.Decompress.init(&in_reader, container, &window);
            var stream_cfg = cfg;
            stream_cfg.compression = .none;
            stream_cfg.scratch = &worker.decomp_stream_buf;
            return try searcher.searchReader(S, shared.allocator, sink, &dec.reader, path, engine, stream_cfg);
        },
        .zstd => {
            var win_len = zstdFrameWindowLen(compressed);
            while (true) {
                const need_win: usize = @as(usize, win_len) + std.compress.zstd.block_size_max;
                if (worker.zstd_win_buf.len < need_win) {
                    if (worker.zstd_win_buf.len != 0) shared.allocator.free(worker.zstd_win_buf);
                    worker.zstd_win_buf = &.{};
                    worker.zstd_win_buf = try shared.allocator.alloc(u8, need_win);
                }
                var in_reader = std.Io.Reader.fixed(compressed);
                var dec = std.compress.zstd.Decompress.init(&in_reader, worker.zstd_win_buf[0..need_win], .{
                    .window_len = win_len,
                });
                var stream_cfg = cfg;
                stream_cfg.compression = .none;
                stream_cfg.scratch = &worker.decomp_stream_buf;
                const res = try searcher.searchReader(S, shared.allocator, sink, &dec.reader, path, engine, stream_cfg);
                const undersize = if (dec.err) |e| e == error.OutputBufferUndersize else false;
                if (undersize and win_len < std.compress.zstd.default_window_len and (S == CountTally or res.matched_lines == 0)) {
                    win_len = std.compress.zstd.default_window_len;
                    continue;
                }
                return res;
            }
        },
        else => return null,
    }
}

fn runFileOrMmap(
    comptime S: type,
    worker: *Worker,
    sink: *S,
    file: std.Io.File,
    path: []const u8,
    engine: anytype,
    cfg: searcher.SearchConfig,
) !searcher.Result {
    const shared = worker.shared;
    if (cfg.compression != .none) {
        if (try tryStreamCompressed(S, worker, sink, file, path, engine, cfg)) |res| {
            return res;
        }
    }
    if (shared.use_mmap and
        cfg.compression == .none and
        (cfg.encoding == .none or cfg.encoding == .auto) and
        cfg.charset == null)
    {
        const st = file.stat(shared.io) catch null;
        if (st) |info| {
            if (info.kind == .file and info.size > 0 and info.size <= std.math.maxInt(usize)) {
                var mm = std.Io.File.MemoryMap.create(shared.io, file, .{
                    .len = @intCast(info.size),
                    .offset = 0,
                    .protection = .{ .read = true, .write = false },
                    .populate = false,
                }) catch null;
                if (mm) |*mapped| {
                    defer mapped.destroy(shared.io);
                    if (cfg.binary != .quit or std.mem.findScalar(u8, mapped.memory[0..@min(mapped.memory.len, 4096)], 0) == null) {
                        platform.adviseMappedSequential(mapped.memory);
                    }
                    return searcher.searchSlice(S, sink, mapped.memory, path, engine, cfg);
                }
            }
        }
    } else if (shared.on_event == null) {
        const st = file.stat(shared.io) catch null;
        if (st) |info| {
            if (info.kind == .file) {
                if (info.size == 0) {
                    return searcher.searchSlice(S, sink, &.{}, path, engine, cfg);
                }
                if (shared.workers > 1 and
                    info.size >= 16 * 1024 * 1024 and
                    !cfg.multiline and
                    cfg.binary != .report and
                    cfg.compression == .none and
                    (cfg.encoding == .none or cfg.encoding == .auto) and
                    cfg.charset == null and
                    cfg.max_count == null and
                    !cfg.exists)
                {
                    // Escalate huge regular files (>= 16 MiB) to intra-source parallel scanning
                    // only when all queued directory/file jobs are already claimed and parked
                    // workers exist, leasing strictly bounded spare slots so total active threads
                    // never exceed `shared.workers`.
                    const claimed = claimExtraWorkers(shared);
                    if (claimed >= 1) {
                        defer _ = shared.extra_workers.fetchSub(claimed, .acq_rel);
                        if (cfg.byte_range == null and cfg.resume_from == 0) {
                            platform.adviseSequentialFile(file);
                        }
                        var fra = FileRa{ .file = file, .io = shared.io };
                        const ra = probe.RandomAccess{
                            .ctx = &fra,
                            .read_at = FileRa.readAt,
                            .size = info.size,
                        };
                        return searcher.searchParallelAt(
                            S,
                            shared.allocator,
                            shared.io,
                            sink,
                            ra,
                            path,
                            engine,
                            cfg,
                            .{ .workers = 1 + claimed },
                        );
                    }
                }
                // Small regular file fast path: read exact size in one `pread` into reusable
                // `worker.scratch` and invoke `searchSlice` directly (avoiding EOF second `pread`
                // and `drive()` streaming state-machine overhead).
                const small_cap: u64 = 256 * 1024;
                if (info.size <= small_cap and
                    cfg.byte_range == null and
                    cfg.resume_from == 0 and
                    cfg.max_source_bytes == null and
                    cfg.max_request_bytes == null and
                    cfg.compression == .none and
                    (cfg.encoding == .none or cfg.encoding == .auto) and
                    cfg.charset == null)
                {
                    const need: usize = @intCast(info.size);
                    if (worker.scratch.len < need) {
                        const alloc_sz = @max(need, @as(usize, 64 * 1024));
                        if (worker.scratch.len != 0) shared.allocator.free(worker.scratch);
                        worker.scratch = &.{};
                        worker.scratch = try shared.allocator.alloc(u8, alloc_sz);
                    }
                    var got: usize = 0;
                    while (got < need) {
                        var iov = [_][]u8{worker.scratch[got..need]};
                        const n = file.readPositional(shared.io, &iov, got) catch break;
                        if (n == 0) break;
                        got += n;
                    }
                    var slice_cfg = cfg;
                    if (slice_cfg.decode_allocator == null) slice_cfg.decode_allocator = shared.allocator;
                    return searcher.searchSlice(S, sink, worker.scratch[0..got], path, engine, slice_cfg);
                }
            }
        }
    }
    return searcher.searchFile(S, shared.allocator, shared.io, sink, file, path, engine, cfg);
}

inline fn appendU64(buf: *std.ArrayList(u8), val: u64) void {
    const len = std.fmt.printInt(buf.unusedCapacitySlice(), val, 10, .lower, .{});
    buf.items.len += len;
}

inline fn appendFormattedLineSep(
    alloc: std.mem.Allocator,
    buf: *std.ArrayList(u8),
    path: []const u8,
    line_number: ?u64,
    sep: u8,
    bytes: []const u8,
) !void {
    try buf.ensureUnusedCapacity(alloc, path.len + 24 + bytes.len);
    buf.appendSliceAssumeCapacity(path);
    buf.appendAssumeCapacity(sep);
    if (line_number) |num| {
        appendU64(buf, num);
        buf.appendAssumeCapacity(sep);
    }
    buf.appendSliceAssumeCapacity(bytes);
    buf.appendAssumeCapacity('\n');
}

const FastLineMode = enum {
    line,
    replace,
    only_matching,
    only_matching_replace,
};

fn FastLineSink(comptime mode: FastLineMode) type {
    return struct {
        pub const matched_fast_line = (mode == .line);
        pub const matched_raw_spans = (mode != .line);
        pub const only_matching_replace = (mode == .only_matching_replace);

        worker: *Worker,
        path: []const u8,
        line_numbers: bool,
        multiline: bool,

        const mid_file_flush_threshold: usize = 256 * 1024;

        fn writeBytes(self: *@This(), bytes: []const u8, base_line_num: ?u64, sep: u8) bool {
            const alloc = self.worker.shared.allocator;
            const buf = &self.worker.out_buf;
            if (self.multiline and std.mem.findScalar(u8, bytes, '\n') != null) {
                var it = std.mem.splitScalar(u8, bytes, '\n');
                var idx: u64 = 0;
                while (it.next()) |sub| : (idx += 1) {
                    const ln: ?u64 = if (self.line_numbers) (if (base_line_num) |n| n + idx else null) else null;
                    appendFormattedLineSep(alloc, buf, self.path, ln, sep, sub) catch return false;
                }
            } else {
                appendFormattedLineSep(alloc, buf, self.path, if (self.line_numbers) base_line_num else null, sep, bytes) catch return false;
            }
            return true;
        }

        fn maybeFlush(self: *@This()) bool {
            if (self.worker.out_buf.items.len >= mid_file_flush_threshold) {
                self.worker.flushOut();
                if (self.worker.shared.write_failed.load(.acquire)) return false;
            }
            return true;
        }

        pub fn matched(self: *@This(), line: searcher.Line) bool {
            if (line.binary_status == .detected) return false;
            switch (mode) {
                .line => {
                    if (!self.writeBytes(line.bytes, line.number, ':')) return false;
                },
                .replace => {
                    const text = line.replaced orelse line.bytes;
                    if (!self.writeBytes(text, line.number, ':')) return false;
                },
                .only_matching, .only_matching_replace => {
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
                                nl_acc += memchr.count(memchr.native_width, line.bytes, prev_pos, from, '\n');
                                prev_pos = from;
                            }
                            break :blk n + nl_acc;
                        } else null;
                        if (!self.writeBytes(seg, base_ln, ':')) return false;
                    }
                },
            }
            return self.maybeFlush();
        }

        pub fn context(self: *@This(), line: searcher.Line) bool {
            if (line.binary_status == .detected) return false;
            if (!self.writeBytes(line.bytes, line.number, '-')) return false;
            return self.maybeFlush();
        }

        pub fn contextBreak(self: *@This()) bool {
            self.worker.out_buf.appendSlice(self.worker.shared.allocator, "--\n") catch return false;
            return self.maybeFlush();
        }
    };
}

fn searchWith(worker: *Worker, engine: anytype, file: std.Io.File, path: []const u8) !void {
    const shared = worker.shared;
    var cfg = worker.config();
    if (shared.request_cap != std.math.maxInt(u64)) {
        const used = shared.request_used.load(.monotonic);
        if (used >= shared.request_cap) return;
        const room = shared.request_cap - used;
        if (cfg.max_source_bytes) |n| cfg.max_source_bytes = @min(n, room) else cfg.max_source_bytes = room;
        cfg.max_request_bytes = if (cfg.max_request_bytes) |n| @min(n, room) else room;
    }

    const direct_out = shared.write_output and shared.on_event == null;
    if (!direct_out and shared.on_event != null) {
        _ = shared.emitEvent(.{ .begin = .{ .source_id = path } });
    }

    const result = if (shared.emit == .count and shared.count_lines_only) blk: {
        var count_sink = CountTally{};
        break :blk try runFileOrMmap(CountTally, worker, &count_sink, file, path, engine, cfg);
    } else if (direct_out and shared.emit == .files_with_matches) blk: {
        cfg.exists = true;
        var count_sink = CountTally{};
        break :blk try runFileOrMmap(CountTally, worker, &count_sink, file, path, engine, cfg);
    } else if (direct_out and shared.emit == .text) blk: {
        if (shared.only_matching and cfg.replacement != null) {
            var text_sink = FastLineSink(.only_matching_replace){
                .worker = worker,
                .path = path,
                .line_numbers = cfg.line_numbers,
                .multiline = cfg.multiline,
            };
            break :blk try runFileOrMmap(FastLineSink(.only_matching_replace), worker, &text_sink, file, path, engine, cfg);
        } else if (shared.only_matching) {
            var text_sink = FastLineSink(.only_matching){
                .worker = worker,
                .path = path,
                .line_numbers = cfg.line_numbers,
                .multiline = cfg.multiline,
            };
            break :blk try runFileOrMmap(FastLineSink(.only_matching), worker, &text_sink, file, path, engine, cfg);
        } else if (cfg.replacement != null) {
            var text_sink = FastLineSink(.replace){
                .worker = worker,
                .path = path,
                .line_numbers = cfg.line_numbers,
                .multiline = cfg.multiline,
            };
            break :blk try runFileOrMmap(FastLineSink(.replace), worker, &text_sink, file, path, engine, cfg);
        } else {
            var text_sink = FastLineSink(.line){
                .worker = worker,
                .path = path,
                .line_numbers = cfg.line_numbers,
                .multiline = cfg.multiline,
            };
            break :blk try runFileOrMmap(FastLineSink(.line), worker, &text_sink, file, path, engine, cfg);
        }
    } else blk: {
        var sink = Tally{
            .shared = shared,
            .stop_file = shared.emit == .files_with_matches,
            .source_id = path,
        };
        break :blk try runFileOrMmap(Tally, worker, &sink, file, path, engine, cfg);
    };

    noteSoft(worker, path, result);
    worker.recordSearch(result, result.matches, result.bytes_read);

    if (direct_out) {
        const alloc = shared.allocator;
        if (shared.emit == .count and shared.count_lines_only) {
            if (result.matched_lines > 0) {
                try worker.out_buf.ensureUnusedCapacity(alloc, path.len + 24);
                worker.out_buf.appendSliceAssumeCapacity(path);
                worker.out_buf.appendAssumeCapacity(':');
                appendU64(&worker.out_buf, result.matched_lines);
                worker.out_buf.appendAssumeCapacity('\n');
            }
        } else if (shared.emit == .files_with_matches) {
            if (result.matched_lines > 0) {
                try worker.out_buf.ensureUnusedCapacity(alloc, path.len + 1);
                worker.out_buf.appendSliceAssumeCapacity(path);
                worker.out_buf.appendAssumeCapacity('\n');
            }
        } else if (result.outcome == .binary_matched) {
            const prefix = "Binary file ";
            const suffix = " matches\n";
            try worker.out_buf.ensureUnusedCapacity(alloc, prefix.len + path.len + suffix.len);
            worker.out_buf.appendSliceAssumeCapacity(prefix);
            worker.out_buf.appendSliceAssumeCapacity(path);
            worker.out_buf.appendSliceAssumeCapacity(suffix);
        }
        if (worker.out_buf.items.len >= 64 * 1024) {
            worker.flushOut();
        }
    } else if (shared.on_event != null) {
        _ = shared.emitEvent(.{ .end = .{
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
    }
    if (shared.request_cap != std.math.maxInt(u64)) {
        const charged = shared.request_used.fetchAdd(result.bytes_read, .monotonic);
        if (charged + result.bytes_read >= shared.request_cap) requestStop(shared);
    }
}

const Tally = struct {
    shared: *Shared,
    stop_file: bool,
    source_id: []const u8 = "",

    pub fn matched(self: *Tally, line: searcher.Line) bool {
        if (self.shared.on_event != null) {
            if (!self.shared.emitEvent(.{ .match = .{
                .source_id = self.source_id,
                .line_number = line.number orelse 0,
                .line_number_known = line.number != null,
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
        if (line.binary_status == .detected and self.shared.emit != .count) return false;
        if (self.stop_file) return false;
        return true;
    }
};

/// Worker thread count is determined strictly by caller configuration and never probes the host CPU core count.
/// Defaults to 1 (single-threaded) when unspecified (0). Clamped to `cap` only when `cap` is non-null.
pub fn resolveThreadsWithCap(requested: u32, cap: ?u32) u32 {
    if (builtin.single_threaded) return 1;
    if (requested == 0) return 1;
    if (cap) |c| return @min(requested, c);
    return requested;
}

pub fn resolveThreads(requested: u32) u32 {
    return resolveThreadsWithCap(requested, null);
}

pub fn resolveConcurrency(walk_threads: u32, max_concurrency: ?u32) u32 {
    return resolveConcurrencyWithCap(walk_threads, max_concurrency, null);
}

pub fn resolveConcurrencyWithCap(walk_threads: u32, max_concurrency: ?u32, cap: ?u32) u32 {
    if (max_concurrency) |mc| return resolveThreadsWithCap(mc, cap);
    return resolveThreadsWithCap(walk_threads, cap);
}

test "thread count is strictly bounded without probing CPU core count" {
    try testing.expectEqual(@as(u32, 1), resolveThreads(0));
    try testing.expectEqual(@as(u32, 1), resolveConcurrency(0, null));
    if (!builtin.single_threaded) {
        try testing.expectEqual(@as(u32, 4), resolveThreads(4));
        try testing.expectEqual(@as(u32, 6), resolveConcurrency(2, 6));
        try testing.expectEqual(@as(u32, 999), resolveThreads(999));
        try testing.expectEqual(@as(u32, 999), resolveConcurrency(1, 999));
        try testing.expectEqual(max_concurrency_hard_cap, resolveThreadsWithCap(999, max_concurrency_hard_cap));
        try testing.expectEqual(max_concurrency_hard_cap, resolveConcurrencyWithCap(1, 999, max_concurrency_hard_cap));
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
    try testing.expect(std.mem.find(u8, out.written(), "skip.log") == null);
    try testing.expect(std.mem.find(u8, out.written(), ".git") == null);
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
