//! [Module] scheduler.zig
//! [Layer] Layer 1/4 — Generic Path-Free Work-Stealing Task Scheduler
//! [Role] Executes arbitrary in-memory recursive / fan-out task graphs (`Task` over `*Context`)
//!        using per-worker Chase-Lev work-stealing deques (`walk/deque.zig`), `std.Io.Group`,
//!        idle `std.Io.Condition` parking, cooperative `stop`/`cancel` tokens, and a zero-overhead
//!        single-worker inline fast path.
//! [Invariants]
//!   1. Zero filesystem file or directory handle references; completely decoupled from filesystem I/O.
//!   2. Single-worker runs (`workers == 1`) execute inline on the calling thread without spawning
//!      an `Io.Group` or acquiring mutexes.
//!   3. Multi-worker runs pop locally in LIFO order for cache locality, steal from peers in FIFO
//!      order for large-subtree parallelism, and cleanly drain unexecuted tasks on early stop/error.

const builtin = @import("builtin");
const std = @import("std");
const deque_mod = @import("walk/deque.zig");

/// Hard cap on worker concurrency to prevent unbounded resource exhaustion.
pub const max_threads_hard_cap: u32 = 64;

/// Configuration for `Scheduler(Task, Context).run`.
pub const SchedulerConfig = struct {
    /// Maximum worker concurrency. `null` or `<= 1` runs inline on the calling thread (`1` worker).
    max_threads: ?u32 = null,
    /// Optional cooperative early-stop flag observed before each task and via `handle.isStopped()`.
    stop: ?*const std.atomic.Value(bool) = null,
    /// Optional cooperative cancellation token observed before each task and via `handle.isStopped()`.
    cancel: ?*const std.atomic.Value(bool) = null,
};

/// Resolves the effective worker count strictly from caller configuration without probing host CPU cores.
pub fn resolveWorkerCount(max_threads: ?u32) u32 {
    if (builtin.single_threaded) return 1;
    const requested = max_threads orelse return 1;
    if (requested <= 1) return 1;
    return @min(requested, max_threads_hard_cap);
}

/// Generic Chase-Lev work-stealing scheduler parameterized over value type `Task` and shared `Context`.
///
/// `Context` must declare one of `run`, `process`, or `execute`:
///   `pub fn run(self: *Context, task: Task, handle: *Handle) !void` (or `Handle` / `*const Handle`, returning `void` or `!void`).
pub fn Scheduler(comptime Task: type, comptime Context: type) type {
    return struct {
        const Self = @This();

        const Node = struct {
            task: Task,
            next_free: ?*Node = null,
        };

        const Queue = deque_mod.Deque(Node);

        const WorkerPool = struct {
            free_head: ?*Node = null,
            free_count: usize = 0,
            max_cached: usize = 64,
        };

        const State = struct {
            allocator: std.mem.Allocator,
            io: std.Io,
            config: SchedulerConfig,
            ctx: *Context,
            workers: u32,
            stopped: std.atomic.Value(bool) = .init(false),

            // Single-worker inline LIFO stack
            single_stack: std.ArrayList(Task) = .empty,

            // Multi-worker Chase-Lev deques + node pools + idle parking
            deques: []Queue = &.{},
            pools: []WorkerPool = &.{},
            alloc_mu: std.Io.Mutex = .init,
            global_free: ?*Node = null,
            idle_mu: std.Io.Mutex = .init,
            idle_cv: std.Io.Condition = .init,
            idle: std.atomic.Value(u32) = .init(0),
            err_mu: std.Io.Mutex = .init,
            first_err: ?anyerror = null,

            inline fn checkExternalStop(self: *const State) bool {
                if (self.config.stop) |s| {
                    if (s.load(.acquire)) return true;
                }
                if (self.config.cancel) |c| {
                    if (c.load(.acquire)) return true;
                }
                return false;
            }

            inline fn checkStopped(self: *const State) bool {
                if (self.stopped.load(.acquire)) return true;
                return self.checkExternalStop();
            }

            fn requestStop(self: *State) void {
                if (self.workers == 1) {
                    self.stopped.store(true, .release);
                    return;
                }
                self.idle_mu.lockUncancelable(self.io);
                defer self.idle_mu.unlock(self.io);
                self.stopped.store(true, .release);
                self.idle_cv.broadcast(self.io);
            }

            fn recordError(self: *State, err: anyerror) void {
                if (self.workers == 1) {
                    if (self.first_err == null) self.first_err = err;
                    self.stopped.store(true, .release);
                    return;
                }
                self.err_mu.lockUncancelable(self.io);
                if (self.first_err == null) {
                    self.first_err = err;
                }
                self.err_mu.unlock(self.io);
                self.requestStop();
            }

            fn allocNode(self: *State, worker_index: u32, task: Task) error{OutOfMemory}!*Node {
                const pool = &self.pools[worker_index];
                if (pool.free_head) |n| {
                    pool.free_head = n.next_free;
                    pool.free_count -= 1;
                    n.* = .{ .task = task, .next_free = null };
                    return n;
                }

                self.alloc_mu.lockUncancelable(self.io);
                defer self.alloc_mu.unlock(self.io);

                if (self.global_free) |gn| {
                    self.global_free = gn.next_free;
                    gn.* = .{ .task = task, .next_free = null };
                    return gn;
                }

                const created = try self.allocator.create(Node);
                created.* = .{ .task = task, .next_free = null };
                return created;
            }

            fn recycleNode(self: *State, worker_index: u32, node: *Node) void {
                const pool = &self.pools[worker_index];
                if (pool.free_count < pool.max_cached) {
                    node.next_free = pool.free_head;
                    pool.free_head = node;
                    pool.free_count += 1;
                    return;
                }

                self.alloc_mu.lockUncancelable(self.io);
                node.next_free = self.global_free;
                self.global_free = node;
                self.alloc_mu.unlock(self.io);
            }

            fn pushMulti(self: *State, worker_index: u32, subtask: Task) error{OutOfMemory}!void {
                const node = try self.allocNode(worker_index, subtask);
                self.deques[worker_index].push(node) catch |err| {
                    self.recycleNode(worker_index, node);
                    return err;
                };
                if (self.idle.load(.acquire) == 0) return;
                self.idle_mu.lockUncancelable(self.io);
                defer self.idle_mu.unlock(self.io);
                self.idle_cv.signal(self.io);
            }

            fn stealFromPeers(self: *State, index: u32) ?*Node {
                var step: u32 = 1;
                while (step < self.workers) : (step += 1) {
                    const other = (index + step) % self.workers;
                    if (self.deques[other].steal()) |node| return node;
                }
                return null;
            }

            fn park(self: *State, index: u32) std.Io.Cancelable!?*Node {
                try self.idle_mu.lock(self.io);
                defer self.idle_mu.unlock(self.io);

                if (self.checkStopped()) {
                    self.stopped.store(true, .release);
                    self.idle_cv.broadcast(self.io);
                    return null;
                }
                if (self.deques[index].pop()) |node| return node;
                if (self.stealFromPeers(index)) |node| return node;

                var announced = false;
                errdefer if (announced) {
                    _ = self.idle.fetchSub(1, .acq_rel);
                };
                const idle_now = self.idle.fetchAdd(1, .acq_rel) + 1;
                announced = true;

                if (idle_now == self.workers) {
                    if (self.deques[index].pop()) |node| {
                        _ = self.idle.fetchSub(1, .acq_rel);
                        announced = false;
                        return node;
                    }
                    if (self.stealFromPeers(index)) |node| {
                        _ = self.idle.fetchSub(1, .acq_rel);
                        announced = false;
                        return node;
                    }
                    self.stopped.store(true, .release);
                    self.idle_cv.broadcast(self.io);
                    return null;
                }

                while (!self.checkStopped()) {
                    if (self.deques[index].pop()) |node| {
                        _ = self.idle.fetchSub(1, .acq_rel);
                        announced = false;
                        return node;
                    }
                    if (self.stealFromPeers(index)) |node| {
                        _ = self.idle.fetchSub(1, .acq_rel);
                        announced = false;
                        return node;
                    }
                    try self.idle_cv.wait(self.io, &self.idle_mu);
                }

                self.stopped.store(true, .release);
                return null;
            }
        };

        /// Per-worker execution handle passed to `Context.run(task, handle)`.
        pub const Handle = struct {
            state: *State,
            worker_index: u32,

            /// Spawns a child `subtask` onto this worker's local Chase-Lev deque (or inline stack).
            pub fn spawn(self: *const Handle, subtask: Task) error{OutOfMemory}!void {
                if (self.isStopped()) return;
                if (self.state.workers == 1) {
                    try self.state.single_stack.append(self.state.allocator, subtask);
                    return;
                }
                try self.state.pushMulti(self.worker_index, subtask);
            }

            /// Cooperatively stops all workers after their current task completes.
            pub fn stop(self: *const Handle) void {
                self.state.requestStop();
            }

            /// Returns true if `handle.stop()`, `config.stop`, or `config.cancel` has been triggered.
            pub fn isStopped(self: *const Handle) bool {
                return self.state.checkStopped();
            }

            /// Returns true if `config.cancel` was triggered.
            pub fn isCancelled(self: *const Handle) bool {
                if (self.state.config.cancel) |c| {
                    if (c.load(.acquire)) return true;
                }
                return false;
            }
        };

        fn invokeContext(ctx: *Context, task: Task, handle: Handle) anyerror!void {
            const method_name = comptime if (@hasDecl(Context, "run"))
                "run"
            else if (@hasDecl(Context, "process"))
                "process"
            else if (@hasDecl(Context, "execute"))
                "execute"
            else
                @compileError("Scheduler Context type '" ++ @typeName(Context) ++ "' must declare `pub fn run(self: *Context, task: Task, handle: *Handle)`");

            const Method = @field(Context, method_name);
            const fn_info = @typeInfo(@TypeOf(Method)).@"fn";
            comptime {
                if (fn_info.param_types.len != 3) {
                    @compileError("Scheduler Context." ++ method_name ++ " must take 3 parameters: (self, task, handle)");
                }
            }

            if (fn_info.param_types[2]) |HandleParam| {
                const RetType = fn_info.return_type.?;
                if (HandleParam == *Handle) {
                    var h_mut = handle;
                    if (@typeInfo(RetType) == .error_union) {
                        try Method(ctx, task, &h_mut);
                    } else {
                        Method(ctx, task, &h_mut);
                    }
                } else if (HandleParam == Handle) {
                    if (@typeInfo(RetType) == .error_union) {
                        try Method(ctx, task, handle);
                    } else {
                        Method(ctx, task, handle);
                    }
                } else if (HandleParam == *const Handle) {
                    if (@typeInfo(RetType) == .error_union) {
                        try Method(ctx, task, &handle);
                    } else {
                        Method(ctx, task, &handle);
                    }
                } else {
                    @compileError("Scheduler Context." ++ method_name ++ " 3rd parameter must be Handle, *Handle, *const Handle, or anytype");
                }
            } else {
                // Generic `handle: anytype` parameter: infer return type via @TypeOf
                const res = Method(ctx, task, &handle);
                if (@typeInfo(@TypeOf(res)) == .error_union) {
                    try res;
                }
            }
        }

        fn workerMain(state: *State, index: u32) std.Io.Cancelable!void {
            const handle = Handle{
                .state = state,
                .worker_index = index,
            };

            while (true) {
                state.io.checkCancel() catch |err| {
                    state.requestStop();
                    return err;
                };
                if (state.checkStopped()) {
                    if (!state.stopped.load(.acquire)) state.requestStop();
                    return;
                }

                if (state.deques[index].pop()) |node| {
                    const task = node.task;
                    state.recycleNode(index, node);
                    invokeContext(state.ctx, task, handle) catch |err| {
                        state.recordError(err);
                        return;
                    };
                    continue;
                }

                if (state.stealFromPeers(index)) |node| {
                    const task = node.task;
                    state.recycleNode(index, node);
                    invokeContext(state.ctx, task, handle) catch |err| {
                        state.recordError(err);
                        return;
                    };
                    continue;
                }

                const parked = try state.park(index);
                if (parked) |node| {
                    const task = node.task;
                    state.recycleNode(index, node);
                    invokeContext(state.ctx, task, handle) catch |err| {
                        state.recordError(err);
                        return;
                    };
                    continue;
                }
                return;
            }
        }

        /// Executes `initial_tasks` (and any recursively spawned subtasks) across up to `config.max_threads` workers.
        pub fn run(
            allocator: std.mem.Allocator,
            io: std.Io,
            config: SchedulerConfig,
            ctx: *Context,
            initial_tasks: []const Task,
        ) anyerror!void {
            try io.checkCancel();
            if (initial_tasks.len == 0) return;

            const workers = resolveWorkerCount(config.max_threads);
            var state = State{
                .allocator = allocator,
                .io = io,
                .config = config,
                .ctx = ctx,
                .workers = workers,
            };
            if (state.checkStopped()) return;

            // Fast path: 1 worker runs inline on the calling thread without Io.Group or Chase-Lev deques
            if (workers == 1) {
                defer state.single_stack.deinit(allocator);
                try state.single_stack.ensureTotalCapacity(allocator, initial_tasks.len);
                // Push in reverse so pop() processes initial_tasks[0] first
                var i: usize = initial_tasks.len;
                while (i > 0) {
                    i -= 1;
                    state.single_stack.appendAssumeCapacity(initial_tasks[i]);
                }

                const handle = Handle{
                    .state = &state,
                    .worker_index = 0,
                };
                while (state.single_stack.pop()) |task| {
                    try io.checkCancel();
                    if (state.checkStopped()) break;
                    try invokeContext(ctx, task, handle);
                }
                return;
            }

            // Multi-worker path: Chase-Lev deques + per-worker node pools + Io.Group
            const deques = try allocator.alloc(Queue, workers);
            var ready_deques: usize = 0;
            const pools = try allocator.alloc(WorkerPool, workers);
            @memset(pools, .{});

            state.deques = deques;
            state.pools = pools;

            defer {
                for (deques[0..ready_deques]) |*q| {
                    while (q.pop()) |leftover| {
                        allocator.destroy(leftover);
                    }
                    q.deinit();
                }
                for (pools) |*p| {
                    var cur = p.free_head;
                    while (cur) |n| {
                        const next = n.next_free;
                        allocator.destroy(n);
                        cur = next;
                    }
                }
                var gcur = state.global_free;
                while (gcur) |n| {
                    const next = n.next_free;
                    allocator.destroy(n);
                    gcur = next;
                }
                allocator.free(pools);
                allocator.free(deques);
            }

            for (deques) |*q| {
                q.* = try Queue.init(allocator, 32);
                ready_deques += 1;
            }

            for (initial_tasks, 0..) |t, idx| {
                const target_worker: u32 = @intCast(idx % workers);
                const node = try allocator.create(Node);
                node.* = .{ .task = t, .next_free = null };
                deques[target_worker].push(node) catch |err| {
                    allocator.destroy(node);
                    return err;
                };
            }

            var group: std.Io.Group = .init;
            var spawn_err: ?anyerror = null;
            var w_idx: u32 = 0;
            while (w_idx < workers) : (w_idx += 1) {
                group.concurrent(io, workerMain, .{ &state, w_idx }) catch |err| {
                    state.requestStop();
                    spawn_err = err;
                    break;
                };
            }

            const await_res = group.await(io);
            if (spawn_err) |err| return err;
            try await_res;
            if (state.first_err) |err| return err;
        }
    };
}

// ============================================================================
// Unit Tests
// ============================================================================

const TreeTask = struct {
    depth: u32,
    value: u64,
};

const TreeSumContext = struct {
    max_depth: u32,
    branch_factor: u32,
    leaf_sum: std.atomic.Value(u64) = .init(0),
    nodes_visited: std.atomic.Value(u64) = .init(0),
    worker_mask: std.atomic.Value(u32) = .init(0),

    pub fn run(self: *TreeSumContext, task: TreeTask, handle: *Scheduler(TreeTask, TreeSumContext).Handle) !void {
        _ = self.nodes_visited.fetchAdd(1, .monotonic);
        if (handle.worker_index < 32) {
            const bit: u32 = @as(u32, 1) << @as(u5, @intCast(handle.worker_index));
            _ = self.worker_mask.fetchOr(bit, .monotonic);
        }

        if (task.depth >= self.max_depth) {
            _ = self.leaf_sum.fetchAdd(task.value, .monotonic);
            return;
        }

        var b: u32 = 0;
        while (b < self.branch_factor) : (b += 1) {
            try handle.spawn(.{
                .depth = task.depth + 1,
                .value = task.value * 2 + b,
            });
        }
    }
};

test "Scheduler: 1-thread inline fast path executes initial order and recursive tree fan-out" {
    const OrderCtx = struct {
        seen: std.ArrayList(u32) = .empty,
        alloc: std.mem.Allocator,

        pub fn run(self: *@This(), val: u32, handle: Scheduler(u32, @This()).Handle) !void {
            try std.testing.expectEqual(@as(u32, 0), handle.worker_index);
            try self.seen.append(self.alloc, val);
            if (val == 10) {
                try handle.spawn(12);
                try handle.spawn(11);
            }
        }
    };

    var octx = OrderCtx{ .alloc = std.testing.allocator };
    defer octx.seen.deinit(std.testing.allocator);

    try Scheduler(u32, OrderCtx).run(
        std.testing.allocator,
        std.testing.io,
        .{ .max_threads = 1 },
        &octx,
        &.{ 10, 20, 30 },
    );
    // LIFO stack pops 10, spawns 12 then 11 -> pops 11, 12, then 20, 30
    try std.testing.expectEqualSlices(u32, &.{ 10, 11, 12, 20, 30 }, octx.seen.items);

    // Binary tree depth 10 (1024 leaves, 2047 total nodes) single-threaded
    var tctx1 = TreeSumContext{ .max_depth = 10, .branch_factor = 2 };
    try Scheduler(TreeTask, TreeSumContext).run(
        std.testing.allocator,
        std.testing.io,
        .{ .max_threads = 1 },
        &tctx1,
        &.{.{ .depth = 0, .value = 1 }},
    );
    try std.testing.expectEqual(@as(u64, 2047), tctx1.nodes_visited.load(.acquire));
    try std.testing.expectEqual(@as(u32, 1), tctx1.worker_mask.load(.acquire));
}

test "Scheduler: 4-thread work-stealing recursive fan-out matches single-thread oracle" {
    if (builtin.single_threaded) return;

    var single_ctx = TreeSumContext{ .max_depth = 11, .branch_factor = 2 };
    try Scheduler(TreeTask, TreeSumContext).run(
        std.testing.allocator,
        std.testing.io,
        .{ .max_threads = 1 },
        &single_ctx,
        &.{.{ .depth = 0, .value = 3 }},
    );

    var multi_ctx = TreeSumContext{ .max_depth = 11, .branch_factor = 2 };
    try Scheduler(TreeTask, TreeSumContext).run(
        std.testing.allocator,
        std.testing.io,
        .{ .max_threads = 4 },
        &multi_ctx,
        &.{.{ .depth = 0, .value = 3 }},
    );

    try std.testing.expectEqual(single_ctx.nodes_visited.load(.acquire), multi_ctx.nodes_visited.load(.acquire));
    try std.testing.expectEqual(single_ctx.leaf_sum.load(.acquire), multi_ctx.leaf_sum.load(.acquire));
}

test "Scheduler: early handle.stop(), external cancel token, and error propagation clean up without leaks" {
    const StopCtx = struct {
        count: std.atomic.Value(u32) = .init(0),
        limit: u32 = 25,

        pub fn run(self: *@This(), depth: u32, handle: *const Scheduler(u32, @This()).Handle) !void {
            const c = self.count.fetchAdd(1, .acq_rel) + 1;
            if (c >= self.limit) {
                handle.stop();
                return;
            }
            if (depth < 14) {
                try handle.spawn(depth + 1);
                try handle.spawn(depth + 1);
            }
        }
    };

    // Multi-thread early handle.stop() must drain unexecuted Chase-Lev nodes without leaking
    var sctx = StopCtx{};
    try Scheduler(u32, StopCtx).run(
        std.testing.allocator,
        std.testing.io,
        .{ .max_threads = 4 },
        &sctx,
        &.{ 0, 0, 0, 0 },
    );
    try std.testing.expect(sctx.count.load(.acquire) >= 25);
    try std.testing.expect(sctx.count.load(.acquire) < 10_000);

    // External cancel token set mid-flight (and pre-cancelled)
    var cancel_flag = std.atomic.Value(bool).init(false);
    const CancelCtx = struct {
        visited: std.atomic.Value(u32) = .init(0),
        flag: *std.atomic.Value(bool),

        pub fn process(self: *@This(), item: u32, handle: Scheduler(u32, @This()).Handle) !void {
            const n = self.visited.fetchAdd(1, .acq_rel) + 1;
            if (n == 10) {
                self.flag.store(true, .release);
            }
            if (item < 12 and !handle.isStopped()) {
                try handle.spawn(item + 1);
                try handle.spawn(item + 1);
            }
        }
    };

    var cctx = CancelCtx{ .flag = &cancel_flag };
    try Scheduler(u32, CancelCtx).run(
        std.testing.allocator,
        std.testing.io,
        .{ .max_threads = 4, .cancel = &cancel_flag },
        &cctx,
        &.{ 0, 0 },
    );
    try std.testing.expect(cancel_flag.load(.acquire));
    try std.testing.expect(cctx.visited.load(.acquire) >= 10);
    try std.testing.expect(cctx.visited.load(.acquire) < 8192);

    // Pre-cancelled run executes 0 tasks
    var cctx_pre = CancelCtx{ .flag = &cancel_flag };
    try Scheduler(u32, CancelCtx).run(
        std.testing.allocator,
        std.testing.io,
        .{ .max_threads = 4, .cancel = &cancel_flag },
        &cctx_pre,
        &.{ 1, 2, 3 },
    );
    try std.testing.expectEqual(@as(u32, 0), cctx_pre.visited.load(.acquire));

    // Task error propagation across worker threads
    const ErrCtx = struct {
        pub fn execute(_: *@This(), x: u32, handle: Scheduler(u32, @This()).Handle) anyerror!void {
            if (x == 7) return error.SyntheticTaskFailure;
            if (x < 7) try handle.spawn(x + 1);
        }
    };
    var ectx = ErrCtx{};
    try std.testing.expectError(
        error.SyntheticTaskFailure,
        Scheduler(u32, ErrCtx).run(
            std.testing.allocator,
            std.testing.io,
            .{ .max_threads = 4 },
            &ectx,
            &.{0},
        ),
    );
}
