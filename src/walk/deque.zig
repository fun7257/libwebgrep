//! Chase-Lev 工作窃取双端队列。
//!
//! owner 从 bottom 压入、弹出，是 LIFO。stealer 从 top 取，是 FIFO。
//! 只有 owner 会扩容。旧缓冲留到 `deinit`，stealer 仍能读到已经发布的元素。
//! 队列里放指针。空位是 null。

const std = @import("std");

pub fn Deque(comptime T: type) type {
    return struct {
        const Self = @This();
        const Slot = std.atomic.Value(?*T);

        const Buf = struct {
            slots: []Slot,
            mask: usize,
            prev: ?*Buf,
        };

        allocator: std.mem.Allocator,
        buf: std.atomic.Value(*Buf),
        top: std.atomic.Value(isize) = .init(0),
        bottom: std.atomic.Value(isize) = .init(0),

        pub fn init(allocator: std.mem.Allocator, cap: usize) !Self {
            const buf = try allocBuf(allocator, cap, null);
            return .{
                .allocator = allocator,
                .buf = .init(buf),
            };
        }

        pub fn deinit(self: *Self) void {
            var current: ?*Buf = self.buf.load(.monotonic);
            while (current) |buf| {
                const prev = buf.prev;
                self.allocator.free(buf.slots);
                self.allocator.destroy(buf);
                current = prev;
            }
            self.* = undefined;
        }

        /// 只给 owner 调用。
        pub fn push(self: *Self, item: *T) !void {
            const b = self.bottom.load(.monotonic);
            const t = self.top.load(.acquire);
            var buf = self.buf.load(.monotonic);
            if (b -% t >= @as(isize, @intCast(buf.slots.len))) {
                buf = try self.grow(buf, b, t);
            }
            buf.slots[@as(usize, @intCast(b)) & buf.mask].store(item, .unordered);
            // release 存储本身发布之前的槽位写入。Zig 0.14 起没有独立的 @fence。
            self.bottom.store(b +% 1, .release);
        }

        /// 只给 owner 调用。
        pub fn pop(self: *Self) ?*T {
            const b = self.bottom.load(.monotonic) -% 1;
            const buf = self.buf.load(.monotonic);
            // 原来的 seq_cst 栅栏改成两边都用 seq_cst，让 bottom 的存储和 top 的加载进入同一全序。
            self.bottom.store(b, .seq_cst);
            const t = self.top.load(.seq_cst);
            if (t <= b) {
                var item = buf.slots[@as(usize, @intCast(b)) & buf.mask].load(.unordered);
                if (t == b) {
                    if (self.top.cmpxchgWeak(t, t +% 1, .seq_cst, .monotonic) != null) item = null;
                    self.bottom.store(t +% 1, .monotonic);
                }
                return item;
            }
            self.bottom.store(t, .monotonic);
            return null;
        }

        /// 任意线程可以调用。
        pub fn steal(self: *Self) ?*T {
            while (true) {
                // 同样用 seq_cst 负载代替独立栅栏，避免 owner 和 stealer 同时拿走最后一个元素。
                const t = self.top.load(.seq_cst);
                const b = self.bottom.load(.seq_cst);
                if (t >= b) return null;
                const buf = self.buf.load(.acquire);
                const item = buf.slots[@as(usize, @intCast(t)) & buf.mask].load(.unordered);
                if (self.top.cmpxchgWeak(t, t +% 1, .seq_cst, .monotonic) == null) return item;
            }
        }

        fn grow(self: *Self, old: *Buf, bottom: isize, top: isize) !*Buf {
            const buf = try allocBuf(self.allocator, old.slots.len * 2, old);
            var i = top;
            while (i != bottom) : (i +%= 1) {
                const item = old.slots[@as(usize, @intCast(i)) & old.mask].load(.unordered);
                buf.slots[@as(usize, @intCast(i)) & buf.mask].store(item, .unordered);
            }
            self.buf.store(buf, .release);
            return buf;
        }

        fn allocBuf(allocator: std.mem.Allocator, cap: usize, prev: ?*Buf) !*Buf {
            const size = std.math.ceilPowerOfTwo(usize, @max(cap, 8)) catch return error.OutOfMemory;
            const buf = try allocator.create(Buf);
            errdefer allocator.destroy(buf);
            const slots = try allocator.alloc(Slot, size);
            for (slots) |*slot| slot.* = .init(null);
            buf.* = .{
                .slots = slots,
                .mask = size - 1,
                .prev = prev,
            };
            return buf;
        }
    };
}

const Box = struct { value: usize };

test "owner 后进先出，stealer 先进先出" {
    const Q = Deque(Box);
    var q = try Q.init(std.testing.allocator, 8);
    defer q.deinit();

    var boxes: [4]Box = .{ .{ .value = 1 }, .{ .value = 2 }, .{ .value = 3 }, .{ .value = 4 } };
    for (&boxes) |*box| try q.push(box);
    try std.testing.expectEqual(@as(usize, 4), q.pop().?.value);
    try std.testing.expectEqual(@as(usize, 1), q.steal().?.value);
    try std.testing.expectEqual(@as(usize, 2), q.steal().?.value);
    try std.testing.expectEqual(@as(usize, 3), q.pop().?.value);
    try std.testing.expect(q.pop() == null);
    try std.testing.expect(q.steal() == null);
}

test "扩容之后 owner 和 stealer 还能取到原来的元素" {
    const Q = Deque(Box);
    var q = try Q.init(std.testing.allocator, 8);
    defer q.deinit();
    var boxes: [20]Box = undefined;
    for (&boxes, 0..) |*box, i| {
        box.* = .{ .value = i };
        try q.push(box);
    }
    var seen: [20]bool = @splat(false);
    var left: usize = 20;
    while (left > 0) : (left -= 1) {
        const item = if (left % 2 == 0) q.pop() else q.steal();
        const box = item orelse return error.TestUnexpectedResult;
        try std.testing.expect(!seen[box.value]);
        seen[box.value] = true;
    }
    try std.testing.expect(q.pop() == null);
}

const Shared = struct {
    queue: Deque(Box),
    taken: std.atomic.Value(usize) = .init(0),
};

fn stealLoop(shared: *Shared, total: usize) void {
    while (shared.taken.load(.acquire) < total) {
        if (shared.queue.steal()) |_| {
            _ = shared.taken.fetchAdd(1, .release);
        } else {
            std.Thread.yield() catch {};
        }
    }
}

test "两个 stealer 和 owner 交错不会丢元素" {
    if (builtinSingleThread()) return;
    const total: usize = 4000;
    var shared = Shared{ .queue = try Deque(Box).init(std.testing.allocator, 8) };
    defer shared.queue.deinit();
    const boxes = try std.testing.allocator.alloc(Box, total);
    defer std.testing.allocator.free(boxes);

    const t1 = try std.Thread.spawn(.{}, stealLoop, .{ &shared, total });
    const t2 = try std.Thread.spawn(.{}, stealLoop, .{ &shared, total });
    for (boxes, 0..) |*box, i| {
        box.* = .{ .value = i };
        try shared.queue.push(box);
        if (i % 3 == 0) {
            if (shared.queue.pop()) |_| _ = shared.taken.fetchAdd(1, .release);
        }
    }
    while (shared.queue.pop()) |_| _ = shared.taken.fetchAdd(1, .release);
    t1.join();
    t2.join();
    try std.testing.expectEqual(total, shared.taken.load(.monotonic));
}

fn builtinSingleThread() bool {
    return @import("builtin").single_threaded;
}
