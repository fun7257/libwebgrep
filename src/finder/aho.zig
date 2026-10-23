//! 带字节等价类的 Aho-Corasick 稠密 DFA。
//!
//! 建自动机时分配内存。建完之后的查找不分配。
//! 等价类把「在所有状态上转移都相同」的字节合成一类，转移表按类存储。
//! 锚点字节不超过 16 种时，查找先用向量扫这些字节，再只确认挂在上面的模式。
//! 这是按 Aho 与 Corasick 的失败函数另写的，没有复制别的项目的源码。

const std = @import("std");
const ascii = @import("ascii.zig");
const byteset = @import("byteset.zig");
const frequency = @import("frequency.zig");
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

const Anchor = struct {
    offset: u32,
    id: u32,
};

const Span = struct {
    begin: u32 = 0,
    count: u32 = 0,
};

const AnchorSet = struct {
    use: bool = false,
    items: []Anchor = &.{},
    spans: [256]Span = @splat(.{}),
    members: byteset.Set = .{},
    max_off: u32 = 0,
    min_len: u32 = 0,
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
    patterns: []const []const u8,
    anchored: []Anchor,
    spans: [256]Span,
    members: byteset.Set,
    max_off: u32,
    min_len: u32,
    use_anchor: bool,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Ac) void {
        self.allocator.free(self.dense);
        self.allocator.free(self.out_head);
        self.allocator.free(self.outs);
        if (self.use_anchor) self.allocator.free(self.anchored);
        self.* = undefined;
    }

    pub fn find(self: *const Ac, haystack: []const u8, start: usize, mode: matcher.MatchMode) ?matcher.Match {
        if (start > haystack.len) return null;
        if (self.use_anchor) return self.findAnchored(haystack, start, mode);
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

    fn findAnchored(self: *const Ac, haystack: []const u8, start: usize, mode: matcher.MatchMode) ?matcher.Match {
        var best: ?Cand = null;
        if (self.empty_id) |id| {
            consider(&best, start, start, id, mode);
            if (mode == .earliest or id == 0) return toMatch(best);
        }
        if (self.min_len == 0 or start == haystack.len) return toMatch(best);

        const restrict = best != null and mode == .leftmost_first;
        var pos = start;
        while (pos < haystack.len) {
            if (mode == .leftmost_first) {
                if (best) |chosen| {
                    if (pos > chosen.start + @as(usize, self.max_off)) break;
                }
            } else if (best) |chosen| {
                const back: usize = self.max_off;
                const earliest_start = if (pos > back) pos - back else 0;
                if (@max(earliest_start, start) + @as(usize, self.min_len) > chosen.end) break;
            }
            const at = self.members.find(haystack, pos) orelse break;
            if (mode == .leftmost_first) {
                if (best) |chosen| {
                    if (at > chosen.start + @as(usize, self.max_off)) break;
                }
            }
            self.noteAnchor(haystack, at, start, mode, &best, restrict);
            pos = at + 1;
        }
        return toMatch(best);
    }

    fn noteAnchor(
        self: *const Ac,
        haystack: []const u8,
        at: usize,
        start: usize,
        mode: matcher.MatchMode,
        best: *?Cand,
        only_here: bool,
    ) void {
        const key = if (self.ignore_case) ascii.fold(haystack[at]) else haystack[at];
        const span = self.spans[key];
        const list = self.anchored[span.begin..][0..span.count];
        for (list) |item| {
            if (at < item.offset) continue;
            const begin = at - @as(usize, item.offset);
            if (begin < start) continue;
            if (only_here and begin != start) continue;
            const pat = self.patterns[item.id];
            if (begin > haystack.len or pat.len > haystack.len - begin) continue;
            if (!equalAt(pat, haystack[begin..][0..pat.len], self.ignore_case)) continue;
            consider(best, begin, begin + pat.len, item.id, mode);
        }
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
    errdefer allocator.free(owned_outs);
    const anchor = try buildAnchor(allocator, patterns, ignore_case);
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
        .patterns = patterns,
        .anchored = anchor.items,
        .spans = anchor.spans,
        .members = anchor.members,
        .max_off = anchor.max_off,
        .min_len = anchor.min_len,
        .use_anchor = anchor.use,
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

fn equalAt(pat: []const u8, hay: []const u8, ignore: bool) bool {
    for (pat, hay) |p, h| {
        if (!ascii.eq(p, h, ignore)) return false;
    }
    return true;
}

fn buildAnchor(allocator: std.mem.Allocator, patterns: []const []const u8, ignore: bool) !AnchorSet {
    var n: usize = 0;
    for (patterns) |pat| {
        if (pat.len != 0) n += 1;
    }
    if (n == 0) return .{};

    const Draft = struct { byte: u8, offset: u32, id: u32 };
    const draft = try allocator.alloc(Draft, n);
    defer allocator.free(draft);
    var min_len: u32 = std.math.maxInt(u32);
    var max_off: u32 = 0;
    var filled: usize = 0;
    for (patterns, 0..) |pat, id_usize| {
        if (pat.len == 0) continue;
        const pick = rarest(pat, ignore);
        draft[filled] = .{ .byte = pick.byte, .offset = pick.offset, .id = @intCast(id_usize) };
        filled += 1;
        min_len = @min(min_len, @as(u32, @intCast(pat.len)));
        max_off = @max(max_off, pick.offset);
    }

    var counts: [256]u32 = @splat(0);
    for (draft[0..filled]) |item| counts[item.byte] += 1;
    var member_buf: [16]u8 = undefined;
    var member_n: usize = 0;
    for (counts, 0..) |count, byte| {
        if (count == 0) continue;
        const forms = if (ignore) ascii.caseVariants(@intCast(byte)) else [2]u8{ @intCast(byte), @intCast(byte) };
        for (forms) |form| {
            var seen = false;
            for (member_buf[0..member_n]) |have| {
                if (have == form) seen = true;
            }
            if (seen) continue;
            if (member_n == member_buf.len) return .{};
            member_buf[member_n] = form;
            member_n += 1;
        }
    }

    var spans: [256]Span = @splat(.{});
    var cursor: u32 = 0;
    for (counts, 0..) |count, byte| {
        spans[byte] = .{ .begin = cursor, .count = count };
        cursor += count;
    }
    const items = try allocator.alloc(Anchor, filled);
    errdefer allocator.free(items);
    var placed: [256]u32 = @splat(0);
    for (draft[0..filled]) |item| {
        const index = spans[item.byte].begin + placed[item.byte];
        items[index] = .{ .offset = item.offset, .id = item.id };
        placed[item.byte] += 1;
    }
    return .{
        .use = true,
        .items = items,
        .spans = spans,
        .members = byteset.Set.initBytes(member_buf[0..member_n]),
        .max_off = max_off,
        .min_len = min_len,
    };
}

fn rarest(pat: []const u8, ignore: bool) struct { byte: u8, offset: u32 } {
    var best_i: usize = 0;
    var best_rank: u8 = 255;
    for (pat, 0..) |raw, i| {
        const byte = if (ignore) ascii.fold(raw) else raw;
        const rank = frequency.default_rank[byte];
        if (rank < best_rank) {
            best_rank = rank;
            best_i = i;
        }
    }
    const byte = if (ignore) ascii.fold(pat[best_i]) else pat[best_i];
    return .{ .byte = byte, .offset = @intCast(best_i) };
}

test "锚点预过滤和稠密自动机同一处命中" {
    const alloc = std.testing.allocator;
    const pats = [_][]const u8{ "abcdef", "de", "xxqz", "alpha", "zq0004miss" };
    var engine = try build(alloc, &pats, false);
    defer engine.deinit();
    try std.testing.expect(engine.use_anchor);
    const hay = "....abcdef....de..xxqz..alpha";
    const left = engine.find(hay, 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 4), left.start);
    try std.testing.expectEqual(@as(usize, 10), left.end);
    const early = engine.find(hay, 0, .earliest).?;
    try std.testing.expectEqual(@as(usize, 7), early.start);
    try std.testing.expectEqual(@as(usize, 9), early.end);
    const tail = engine.find(hay, 10, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 14), tail.start);

    var folded = try build(alloc, &.{ "AbC", "zzz" }, true);
    defer folded.deinit();
    const hit = folded.find("xxabcYY", 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 2), hit.start);
    try std.testing.expectEqual(@as(usize, 5), hit.end);

    var many_buf: [20][1]u8 = undefined;
    var many: [20][]const u8 = undefined;
    for (&many_buf, 0..) |*slot, i| {
        slot[0] = @intCast(i + 1);
        many[i] = slot;
    }
    var wide = try build(alloc, &many, false);
    defer wide.deinit();
    try std.testing.expect(!wide.use_anchor);
    const raw = [_]u8{ 0, 9, 0 };
    const found = wide.find(&raw, 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 1), found.start);
}

fn scalarAc(hay: []const u8, start: usize, pats: []const []const u8, mode: matcher.MatchMode) ?matcher.Match {
    const Pick = struct { start: usize, end: usize, id: u32 };
    var best: ?Pick = null;
    var i = start;
    while (i <= hay.len) : (i += 1) {
        for (pats, 0..) |pat, id_usize| {
            if (i + pat.len > hay.len) continue;
            if (!std.mem.eql(u8, pat, hay[i..][0..pat.len])) continue;
            const cand = Pick{ .start = i, .end = i + pat.len, .id = @intCast(id_usize) };
            if (best) |cur| {
                const replace = switch (mode) {
                    .earliest => cand.end < cur.end or (cand.end == cur.end and (cand.start < cur.start or (cand.start == cur.start and cand.id < cur.id))),
                    .leftmost_first => cand.start < cur.start or (cand.start == cur.start and cand.id < cur.id),
                };
                if (replace) best = cand;
            } else best = cand;
        }
    }
    const chosen = best orelse return null;
    return .{ .start = chosen.start, .end = chosen.end };
}

test "锚点预过滤扫过第一跨，第二跨和朴素查找一致" {
    const stride = @import("memchr.zig").native_width * 4;
    const pats = [_][]const u8{ "abcdef", "de", "xxqz", "alpha", "zq0004miss" };
    var engine = try build(std.testing.allocator, &pats, false);
    defer engine.deinit();
    try std.testing.expect(engine.use_anchor);

    var hay: [stride * 2 + 8]u8 = @splat('y');
    const at = stride + 2;
    @memcpy(hay[at..][0.."abcdef".len], "abcdef");
    inline for (.{ .earliest, .leftmost_first }) |mode| {
        const got = engine.find(&hay, 0, mode).?;
        const want = scalarAc(&hay, 0, &pats, mode).?;
        try std.testing.expectEqual(want.start, got.start);
        try std.testing.expectEqual(want.end, got.end);
    }
    try std.testing.expectEqual(at, engine.find(&hay, 0, .leftmost_first).?.start);
    try std.testing.expectEqual(at + 3, engine.find(&hay, 0, .earliest).?.start);

    var dense_buf: [20][1]u8 = undefined;
    var dense_pats: [20][]const u8 = undefined;
    for (&dense_buf, 0..) |*slot, i| {
        slot[0] = @intCast(i + 1);
        dense_pats[i] = slot;
    }
    var dense = try build(std.testing.allocator, &dense_pats, false);
    defer dense.deinit();
    try std.testing.expect(!dense.use_anchor);
    var long: [stride * 2 + 4]u8 = @splat(0);
    long[stride + 1] = 9;
    const dense_hit = dense.find(&long, 0, .leftmost_first).?;
    try std.testing.expectEqual(stride + 1, dense_hit.start);
    try std.testing.expectEqual(scalarAc(&long, 0, &dense_pats, .leftmost_first).?.end, dense_hit.end);
}
