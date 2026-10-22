//! 带字节等价类的 Aho-Corasick 稠密 DFA。
//!
//! 建自动机时分配内存。建完之后的查找不分配。
//! 等价类把「在所有状态上转移都相同」的字节合成一类，转移表按类存储。
//! 这是按 Aho 与 Corasick 的失败函数另写的，没有复制别的项目的源码。

const std = @import("std");
const ascii = @import("ascii.zig");
const matcher = @import("../matcher.zig");

const sentinel: u32 = 0;

const Out = struct {
    len: u32,
    id: u32,
    next: u32,
};

const Cand = struct {
    start: usize,
    end: usize,
    id: u32,
};

pub const Ac = struct {
    dense: []u32,
    class_of: [256]u16,
    nclasses: u16,
    out_head: []u32,
    outs: []Out,
    max_len: u32,
    empty_id: ?u32,
    ignore_case: bool,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Ac) void {
        self.allocator.free(self.dense);
        self.allocator.free(self.out_head);
        self.allocator.free(self.outs);
        self.* = undefined;
    }

    pub fn find(self: *const Ac, haystack: []const u8, start: usize, mode: matcher.MatchMode) ?matcher.Match {
        if (start > haystack.len) return null;
        var best: ?Cand = null;
        if (self.empty_id) |id| {
            consider(&best, start, start, id, mode);
            if (mode == .earliest or id == 0) return toMatch(best);
        }
        if (self.max_len == 0 or start == haystack.len) return toMatch(best);

        var state: u32 = 0;
        var i = start;
        while (i < haystack.len) : (i += 1) {
            const raw = haystack[i];
            const byte = if (self.ignore_case) ascii.fold(raw) else raw;
            const idx = @as(usize, state) * @as(usize, self.nclasses) + self.class_of[byte];
            state = self.dense[idx];
            const end = i + 1;
            var link = self.out_head[state];
            while (link != sentinel) {
                const item = self.outs[link - 1];
                if (item.len <= end) {
                    consider(&best, end - item.len, end, item.id, mode);
                }
                link = item.next;
            }
            if (best) |chosen| {
                if (mode == .earliest and chosen.end == end) return toMatch(best);
                if (mode == .leftmost_first) {
                    const next_end = end + 1;
                    const future = if (next_end > self.max_len) next_end - self.max_len else 0;
                    if (future > chosen.start) return toMatch(best);
                }
            }
        }
        return toMatch(best);
    }
};

pub fn build(
    allocator: std.mem.Allocator,
    patterns: []const []const u8,
    ignore_case: bool,
) !Ac {
    var nodes: std.ArrayList(Node) = .empty;
    errdefer deinitNodes(allocator, &nodes);
    try nodes.append(allocator, blankNode());

    var max_len: u32 = 0;
    var empty_id: ?u32 = null;
    for (patterns, 0..) |pat, id_usize| {
        if (pat.len > std.math.maxInt(u32)) return error.OutOfMemory;
        const id: u32 = @intCast(id_usize);
        if (pat.len == 0) {
            if (empty_id == null) empty_id = id;
            continue;
        }
        max_len = @max(max_len, @as(u32, @intCast(pat.len)));
        var state: usize = 0;
        for (pat) |raw| {
            const byte = if (ignore_case) ascii.fold(raw) else raw;
            const child = nodes.items[state].next[byte];
            if (child < 0) {
                const created: i32 = @intCast(nodes.items.len);
                try nodes.append(allocator, blankNode());
                nodes.items[state].next[byte] = created;
                state = @intCast(created);
            } else {
                state = @intCast(child);
            }
        }
        try nodes.items[state].out.append(allocator, .{
            .len = @intCast(pat.len),
            .id = id,
        });
    }

    var queue: std.ArrayList(u32) = .empty;
    defer queue.deinit(allocator);
    var byte: usize = 0;
    while (byte < 256) : (byte += 1) {
        const child = nodes.items[0].next[byte];
        if (child >= 0) {
            const id: u32 = @intCast(child);
            nodes.items[id].fail = 0;
            try appendOuts(allocator, &nodes, id, 0);
            try queue.append(allocator, id);
        } else {
            nodes.items[0].next[byte] = 0;
        }
    }
    var q_at: usize = 0;
    while (q_at < queue.items.len) : (q_at += 1) {
        const current = queue.items[q_at];
        byte = 0;
        while (byte < 256) : (byte += 1) {
            const child = nodes.items[current].next[byte];
            const fail = nodes.items[current].fail;
            const via = nodes.items[fail].next[byte];
            if (child >= 0) {
                const id: u32 = @intCast(child);
                const dest: u32 = if (via >= 0) @intCast(via) else 0;
                nodes.items[id].fail = dest;
                try appendOuts(allocator, &nodes, id, dest);
                try queue.append(allocator, id);
            } else {
                nodes.items[current].next[byte] = if (via >= 0) via else 0;
            }
        }
    }

    const nstates = nodes.items.len;
    var class_of: [256]u16 = undefined;
    @memset(&class_of, 0);
    var nclasses: u16 = 1;
    for (nodes.items) |node| {
        var keys: [256]u64 = undefined;
        var vals: [256]u16 = undefined;
        var nkeys: usize = 0;
        var next_class: u16 = 0;
        var new_of: [256]u16 = undefined;
        for (0..256) |b| {
            const dest: u32 = if (node.next[b] >= 0) @intCast(node.next[b]) else 0;
            const key = (@as(u64, class_of[b]) << 32) | dest;
            const slot = findKey(keys[0..nkeys], key);
            if (slot) |at| {
                new_of[b] = vals[at];
            } else {
                keys[nkeys] = key;
                vals[nkeys] = next_class;
                new_of[b] = next_class;
                nkeys += 1;
                next_class += 1;
            }
        }
        class_of = new_of;
        nclasses = next_class;
    }

    const cells = nstates * @as(usize, nclasses);
    const dense = try allocator.alloc(u32, cells);
    errdefer allocator.free(dense);
    for (nodes.items, 0..) |node, state| {
        for (0..256) |b| {
            const dest: u32 = if (node.next[b] >= 0) @intCast(node.next[b]) else 0;
            dense[state * @as(usize, nclasses) + class_of[b]] = dest;
        }
    }

    var outs: std.ArrayList(Out) = .empty;
    errdefer outs.deinit(allocator);
    const out_head = try allocator.alloc(u32, nstates);
    errdefer allocator.free(out_head);
    @memset(out_head, sentinel);
    for (nodes.items, 0..) |node, state| {
        if (node.out.items.len == 0) continue;
        out_head[state] = @intCast(outs.items.len + 1);
        for (node.out.items, 0..) |item, k| {
            const last = k + 1 == node.out.items.len;
            try outs.append(allocator, .{
                .len = item.len,
                .id = item.id,
                .next = if (last) sentinel else @intCast(outs.items.len + 2),
            });
        }
    }

    const owned_outs = try outs.toOwnedSlice(allocator);
    deinitNodes(allocator, &nodes);
    return .{
        .dense = dense,
        .class_of = class_of,
        .nclasses = nclasses,
        .out_head = out_head,
        .outs = owned_outs,
        .max_len = max_len,
        .empty_id = empty_id,
        .ignore_case = ignore_case,
        .allocator = allocator,
    };
}

const OwnedOut = struct { len: u32, id: u32 };

const Node = struct {
    next: [256]i32,
    fail: u32,
    out: std.ArrayList(OwnedOut),
};

fn blankNode() Node {
    var node = Node{
        .next = undefined,
        .fail = 0,
        .out = .empty,
    };
    @memset(&node.next, -1);
    return node;
}

fn deinitNodes(allocator: std.mem.Allocator, nodes: *std.ArrayList(Node)) void {
    for (nodes.items) |*node| node.out.deinit(allocator);
    nodes.deinit(allocator);
}

fn appendOuts(
    allocator: std.mem.Allocator,
    nodes: *std.ArrayList(Node),
    dest: u32,
    from: u32,
) !void {
    if (dest == from) return;
    const n = nodes.items[from].out.items.len;
    var k: usize = 0;
    while (k < n) : (k += 1) {
        const item = nodes.items[from].out.items[k];
        try nodes.items[dest].out.append(allocator, item);
    }
}

fn findKey(keys: []const u64, key: u64) ?usize {
    for (keys, 0..) |have, i| {
        if (have == key) return i;
    }
    return null;
}

fn consider(best: *?Cand, start: usize, end: usize, id: u32, mode: matcher.MatchMode) void {
    const cand = Cand{ .start = start, .end = end, .id = id };
    if (best.*) |cur| {
        if (prefer(cand, cur, mode)) best.* = cand;
    } else best.* = cand;
}

fn prefer(a: Cand, b: Cand, mode: matcher.MatchMode) bool {
    switch (mode) {
        .earliest => {
            if (a.end != b.end) return a.end < b.end;
            if (a.start != b.start) return a.start < b.start;
            return a.id < b.id;
        },
        .leftmost_first => {
            if (a.start != b.start) return a.start < b.start;
            return a.id < b.id;
        },
    }
}

fn toMatch(best: ?Cand) ?matcher.Match {
    const cand = best orelse return null;
    return .{ .start = cand.start, .end = cand.end };
}
