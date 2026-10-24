//! 用两个稀有字节做预过滤，再对候选做整段确认。
//! 模式至少两个字节。单字节走 memchr，本模块不处理。
//!
//! 热路径是通用 SIMD（Wojciech Muła 的 generic SIMD，memchr 的 packed pair
//! 也是这个算法）：每个向量同时比较两个偏移上的字节，掩码取与。
//! 只有两个字节一起命中才离开向量循环。单字节很常见、但两个字节的
//! 相对位置对不上时，循环仍然整段留在向量指令里。

const std = @import("std");
const ascii = @import("ascii.zig");

/// 不超过这个长度时，packed pair 自己完成查找，不把剩余输入交给 Two-Way。
/// 假阳性再乘一次最长 32 字节的比较，总时间仍是线性的常数倍。
/// 这个上界和 memchr 的 `do_packed_search` 一致。
pub const owns_search_max_len: usize = 32;

/// 长模式上的预过滤记账。平均每次确认失败跳过的字节太少时，调用方应改走 Two-Way。
/// 数字和 memchr 的 PrefilterState 一致：至少 50 个候选，且平均每次跳过少于 8 字节。
pub const Guard = struct {
    candidates: u32 = 0,
    skipped: u64 = 0,
    /// 预过滤放弃之后，Two-Way 从这里继续。不能叫 resume，那是关键字。
    restart: usize = 0,
    gave_up: bool = false,

    const min_candidates: u32 = 50;
    const min_skip_bytes: u64 = 8;

    fn noteMiss(self: *Guard, origin: usize, previous: usize) void {
        const stride = origin - previous;
        self.candidates +|= 1;
        self.skipped +|= stride;
        if (self.candidates < min_candidates) return;
        if (self.skipped >= min_skip_bytes * @as(u64, self.candidates)) return;
        self.gave_up = true;
        self.restart = origin + 1;
    }
};

pub const PackedPair = struct {
    pattern: []const u8,
    anchor_index: usize,
    other_index: usize,
    anchor: u8,
    other: u8,
    ignore_case: bool,

    /// `rank` 的值越小越稀有。`pattern` 由调用方持有。
    pub fn init(pattern: []const u8, rank: *const [256]u8, ignore_case: bool) PackedPair {
        std.debug.assert(pattern.len >= 2);
        var best: usize = 0;
        var second: usize = 1;
        if (rank[pattern[second]] < rank[pattern[best]]) {
            best = 1;
            second = 0;
        }
        var i: usize = 2;
        while (i < pattern.len) : (i += 1) {
            const r = rank[pattern[i]];
            if (r < rank[pattern[best]]) {
                second = best;
                best = i;
            } else if (r < rank[pattern[second]]) {
                second = i;
            }
        }
        return .{
            .pattern = pattern,
            .anchor_index = best,
            .other_index = second,
            .anchor = pattern[best],
            .other = pattern[second],
            .ignore_case = ignore_case,
        };
    }

    /// 在 `haystack[start..]` 中查找下一次完整匹配的起点。
    /// `guard` 非空且模式长于 `owns_search_max_len` 时，预过滤跳得太近就停，
    /// 并在 `guard` 里写下 Two-Way 应该接上的位置。
    pub fn find(
        self: PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        guard: ?*Guard,
    ) ?usize {
        return self.findInner(width, haystack, start, guard, false, undefined);
    }

    /// 和 `find` 一样，但顺手在已经加载的向量上找 NUL。
    /// 看到 NUL 时写入 `nul_out` 并返回 null，调用方按二进制策略处理这一块。
    /// 返回匹配时，只保证匹配起点之前没有 NUL；匹配之后的字节由调用方再看。
    pub fn findWatchingNul(
        self: PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        guard: ?*Guard,
        nul_out: *?usize,
    ) ?usize {
        return self.findInner(width, haystack, start, guard, true, nul_out);
    }

    fn findInner(
        self: PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        guard: ?*Guard,
        comptime watch_nul: bool,
        nul_out: *?usize,
    ) ?usize {
        comptime if (width != 16 and width != 32) @compileError("packed pair 宽度只支持 16 和 32");
        const m = self.pattern.len;
        if (m > haystack.len or start > haystack.len - m) {
            if (watch_nul and start <= haystack.len) {
                _ = noteNul(haystack[start..], start, nul_out);
            }
            return null;
        }
        const last = haystack.len - m;
        // 大小写、记账和 NUL 都在循环外定死，没命中的循环里只剩加载、比较和归约。
        if (self.ignore_case) {
            if (guard) |g| return self.findLoop(width, haystack, start, last, true, true, watch_nul, g, nul_out);
            return self.findLoop(width, haystack, start, last, true, false, watch_nul, undefined, nul_out);
        }
        if (guard) |g| return self.findLoop(width, haystack, start, last, false, true, watch_nul, g, nul_out);
        return self.findLoop(width, haystack, start, last, false, false, watch_nul, undefined, nul_out);
    }

    fn findLoop(
        self: PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        last: usize,
        comptime fold: bool,
        comptime watched: bool,
        comptime watch_nul: bool,
        guard: *Guard,
        nul_out: *?usize,
    ) ?usize {
        const max_index = @max(self.anchor_index, self.other_index);
        const cover_index = @min(self.anchor_index, self.other_index);
        // 锚点不是 0 时，向量覆盖不到起点前面这几字节。
        if (watch_nul and cover_index > 0) {
            const prefix_end = @min(haystack.len, start + cover_index);
            if (noteNul(haystack[start..prefix_end], start, nul_out)) return null;
        }
        var origin = start;
        var previous = start;
        // 密集匹配时下一次命中通常就在几十字节内。先标量看完这一小段，
        // 避免为了一次确认走进向量循环。稀有字面量上这只是每块多看几十个字节。
        if (!watch_nul) {
            const bound = @min(last, start + 47);
            if (scalarFrom(self, haystack, origin, bound, &previous, fold, watched, guard)) |hit| return hit;
            if (watched and guard.gave_up) return null;
            origin = bound + 1;
        }
        // 一次推进 4 个向量，把 4 个窗口的掩码并起来做单次归约，减少 75% 的归约与分支指令。
        const stride = width * 4;
        while (origin <= last and origin + max_index + stride <= haystack.len) {
            var masks: [4]@Vector(width, bool) = undefined;
            inline for (0..4) |k| {
                masks[k] = hotMask(self, width, haystack, origin + k * width, fold, watch_nul);
            }
            if (@reduce(.Or, (masks[0] | masks[1]) | (masks[2] | masks[3]))) {
                @branchHint(.unlikely);
                inline for (0..4) |k| {
                    if (@reduce(.Or, masks[k])) {
                        const at = origin + k * width;
                        const rel = @call(
                            .never_inline,
                            takeHit,
                            .{ self, width, haystack, at, last, &previous, fold, watched, watch_nul, guard, nul_out },
                        );
                        if (watch_nul and nul_out.* != null) return null;
                        if (rel) |found| return at + found;
                        if (watched and guard.gave_up) return null;
                    }
                }
            }
            origin += stride;
        }
        while (origin <= last and origin + max_index + width <= haystack.len) {
            if (@reduce(.Or, hotMask(self, width, haystack, origin, fold, watch_nul))) {
                @branchHint(.unlikely);
                const rel = @call(
                    .never_inline,
                    takeHit,
                    .{ self, width, haystack, origin, last, &previous, fold, watched, watch_nul, guard, nul_out },
                );
                if (watch_nul and nul_out.* != null) return null;
                if (rel) |found| return origin + found;
                if (watched and guard.gave_up) return null;
            }
            origin += width;
        }
        if (watch_nul) {
            const from = @min(haystack.len, origin + cover_index);
            if (noteNul(haystack[from..], from, nul_out)) return null;
        }
        return scalarFrom(self, haystack, origin, last, &previous, fold, watched, guard);
    }
};

fn confirm(self: PackedPair, haystack: []const u8, origin: usize) bool {
    const pat = self.pattern;
    const window = haystack[origin..][0..pat.len];
    // 敏感比较交给 std。它会在第一个不相等的字节返回，假阳性不用看完整个模式。
    if (!self.ignore_case) return std.mem.eql(u8, pat, window);
    for (pat, window) |p, h| {
        if (!ascii.eq(p, h, true)) return false;
    }
    return true;
}

inline fn byteMask(comptime width: comptime_int, block: @Vector(width, u8), byte: u8, comptime fold: bool) @Vector(width, bool) {
    if (!fold) return block == @as(@Vector(width, u8), @splat(byte));
    const forms = ascii.caseVariants(byte);
    if (forms[0] == forms[1]) return block == @as(@Vector(width, u8), @splat(forms[0]));
    // ASCII 字母的大写与小写只差 0x20 位，置位后等于小写形式，无假阳性且省掉一次比较与或运算。
    return (block | @as(@Vector(width, u8), @splat(0x20))) == @as(@Vector(width, u8), @splat(forms[0]));
}

/// 这一窗里两个锚点字节的命中掩码。`watch_nul` 时顺带并入覆盖向量里的 NUL 掩码。
/// 覆盖向量是下标更小的那个锚点，已经在寄存器里，不再多加载一次。
inline fn hotMask(
    self: PackedPair,
    comptime width: comptime_int,
    haystack: []const u8,
    origin: usize,
    comptime fold: bool,
    comptime watch_nul: bool,
) @Vector(width, bool) {
    const left: @Vector(width, u8) = haystack[origin + self.anchor_index ..][0..width].*;
    const right: @Vector(width, u8) = haystack[origin + self.other_index ..][0..width].*;
    const hits = byteMask(width, left, self.anchor, fold) & byteMask(width, right, self.other, fold);
    if (!watch_nul) return hits;
    const cover = if (self.anchor_index <= self.other_index) left else right;
    return hits | (cover == @as(@Vector(width, u8), @splat(0)));
}

fn noteNul(haystack: []const u8, base: usize, nul_out: *?usize) bool {
    const rel = std.mem.findScalarPos(u8, haystack, 0, 0) orelse return false;
    nul_out.* = base + rel;
    return true;
}

/// 返回相对 `origin` 的匹配起点。单独成函数，确认逻辑不要嵌进快循环。
fn takeHit(
    self: PackedPair,
    comptime width: comptime_int,
    haystack: []const u8,
    origin: usize,
    last: usize,
    previous: *usize,
    comptime fold: bool,
    comptime watched: bool,
    comptime watch_nul: bool,
    guard: *Guard,
    nul_out: *?usize,
) ?usize {
    if (watch_nul) {
        const cover_index = @min(self.anchor_index, self.other_index);
        const block: @Vector(width, u8) = haystack[origin + cover_index ..][0..width].*;
        const zeros = block == @as(@Vector(width, u8), @splat(0));
        if (@reduce(.Or, zeros)) {
            const rel = std.simd.firstTrue(zeros).?;
            nul_out.* = origin + cover_index + @as(usize, rel);
            return null;
        }
    }
    const left: @Vector(width, u8) = haystack[origin + self.anchor_index ..][0..width].*;
    const right: @Vector(width, u8) = haystack[origin + self.other_index ..][0..width].*;
    var hits = byteMask(width, left, self.anchor, fold) & byteMask(width, right, self.other, fold);
    const Index = std.simd.VectorIndex(@TypeOf(hits));
    const indices = comptime std.simd.iota(Index, width);
    while (std.simd.firstTrue(hits)) |rel| {
        hits = @select(
            bool,
            indices == @as(@Vector(width, Index), @splat(rel)),
            @as(@Vector(width, bool), @splat(false)),
            hits,
        );
        const at = origin + @as(usize, rel);
        if (at > last) continue;
        if (confirm(self, haystack, at)) return @as(usize, rel);
        if (!watched) continue;
        guard.noteMiss(at, previous.*);
        previous.* = at + 1;
        if (guard.gave_up) return null;
    }
    return null;
}

inline fn scalarFrom(
    self: PackedPair,
    haystack: []const u8,
    origin: usize,
    last: usize,
    previous: *usize,
    comptime fold: bool,
    comptime watched: bool,
    guard: *Guard,
) ?usize {
    var i = origin;
    while (i <= last) : (i += 1) {
        const anchor_byte = haystack[i + self.anchor_index];
        const other_byte = haystack[i + self.other_index];
        if (!ascii.eq(anchor_byte, self.anchor, fold)) continue;
        if (!ascii.eq(other_byte, self.other, fold)) continue;
        if (confirm(self, haystack, i)) return i;
        if (!watched) continue;
        guard.noteMiss(i, previous.*);
        previous.* = i + 1;
        if (guard.gave_up) return null;
    }
    return null;
}

fn scalarFind(haystack: []const u8, pattern: []const u8, start: usize, ignore_case: bool) ?usize {
    if (pattern.len > haystack.len or start > haystack.len - pattern.len) return null;
    var i = start;
    while (i + pattern.len <= haystack.len) : (i += 1) {
        var ok = true;
        for (pattern, haystack[i..][0..pattern.len]) |p, h| {
            if (!ascii.eq(p, h, ignore_case)) {
                ok = false;
                break;
            }
        }
        if (ok) return i;
    }
    return null;
}

fn findAll(pair: PackedPair, comptime width: comptime_int, haystack: []const u8, start: usize) ?usize {
    return pair.find(width, haystack, start, null);
}

test "按秩选择最稀有的两个字节" {
    var rank: [256]u8 = @splat(200);
    rank['z'] = 0;
    rank['q'] = 1;
    rank['a'] = 50;
    const pair = PackedPair.init("aqz", &rank, false);
    try std.testing.expectEqual(@as(usize, 2), pair.anchor_index);
    try std.testing.expectEqual(@as(u8, 'z'), pair.anchor);
    try std.testing.expectEqual(@as(usize, 1), pair.other_index);
    try std.testing.expectEqual(@as(u8, 'q'), pair.other);
}

test "扫描时发现 NUL，锚点覆盖不到的前缀也算" {
    const mid = PackedPair.init("QX", &frequency.default_rank, false);
    var buf: [200]u8 = undefined;
    @memset(&buf, 'a');
    buf[80] = 0;
    @memcpy(buf[120..][0..2], "QX");
    inline for (.{ 16, 32 }) |w| {
        var nul: ?usize = null;
        try std.testing.expect(mid.findWatchingNul(w, &buf, 0, null, &nul) == null);
        try std.testing.expectEqual(@as(?usize, 80), nul);
    }

    @memset(&buf, 'a');
    @memcpy(buf[30..][0..2], "QX");
    buf[150] = 0;
    inline for (.{ 16, 32 }) |w| {
        var nul: ?usize = null;
        try std.testing.expectEqual(@as(?usize, 30), mid.findWatchingNul(w, &buf, 0, null, &nul));
        try std.testing.expect(nul == null);
    }

    const shifted = PackedPair.init("aQX", &frequency.default_rank, false);
    try std.testing.expect(shifted.anchor_index != 0 and shifted.other_index != 0);
    @memset(&buf, 'b');
    buf[0] = 0;
    @memcpy(buf[40..][0..3], "aQX");
    inline for (.{ 16, 32 }) |w| {
        var nul: ?usize = null;
        try std.testing.expect(shifted.findWatchingNul(w, &buf, 0, null, &nul) == null);
        try std.testing.expectEqual(@as(?usize, 0), nul);
    }
}

test "确认候选，假阳性继续往后" {
    const pair = PackedPair.init("qx", &frequency.default_rank, false);
    inline for (.{ 16, 32 }) |w| {
        try std.testing.expectEqual(@as(?usize, 3), findAll(pair, w, "qqqqxqx", 0));
        try std.testing.expectEqual(@as(?usize, null), findAll(pair, w, "qqqqqq", 0));
        try std.testing.expectEqual(@as(?usize, null), findAll(pair, w, "qx", 1));
    }
}

test "忽略大小写" {
    const pair = PackedPair.init("Ab", &frequency.default_rank, true);
    inline for (.{ 16, 32 }) |w| {
        try std.testing.expectEqual(@as(?usize, 1), findAll(pair, w, "xabXAB", 0));
        try std.testing.expectEqual(@as(?usize, 4), findAll(pair, w, "xabXAB", 2));
        try std.testing.expectEqual(@as(?usize, null), findAll(pair, w, "axb", 0));
    }
}

const frequency = @import("frequency.zig");

test "随机对照朴素查找" {
    var prng = std.Random.DefaultPrng.init(0x9A11);
    const random = prng.random();
    var hay: [100]u8 = undefined;
    var pat: [8]u8 = undefined;
    const rank = frequency.default_rank;
    for (0..60) |_| {
        const hlen = random.intRangeAtMost(usize, 0, hay.len);
        const plen = random.intRangeAtMost(usize, 2, pat.len);
        random.bytes(hay[0..hlen]);
        random.bytes(pat[0..plen]);
        const start = if (hlen == 0) 0 else random.intRangeAtMost(usize, 0, hlen);
        inline for (.{ false, true }) |fold| {
            const pair = PackedPair.init(pat[0..plen], &rank, fold);
            inline for (.{ 16, 32 }) |w| {
                try std.testing.expectEqual(
                    scalarFind(hay[0..hlen], pat[0..plen], start, fold),
                    findAll(pair, w, hay[0..hlen], start),
                );
            }
        }
    }
}

test "packed pair 模糊对照" {
    try std.testing.fuzz({}, fuzzPair, .{});
}

fn fuzzPair(_: void, smith: *std.testing.Smith) !void {
    var hay_buf: [80]u8 = undefined;
    var pat_buf: [10]u8 = undefined;
    const hlen: usize = smith.slice(&hay_buf);
    var plen: usize = smith.slice(&pat_buf);
    if (plen < 2) plen = 0;
    if (plen < 2) return;
    const fold = smith.value(bool);
    const start: usize = if (hlen == 0) 0 else smith.valueRangeAtMost(u32, 0, @intCast(hlen));
    const pair = PackedPair.init(pat_buf[0..plen], &frequency.default_rank, fold);
    inline for (.{ 16, 32 }) |w| {
        try std.testing.expectEqual(
            scalarFind(hay_buf[0..hlen], pat_buf[0..plen], start, fold),
            findAll(pair, w, hay_buf[0..hlen], start),
        );
    }
}
