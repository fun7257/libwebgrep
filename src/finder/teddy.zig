//! Teddy：少量多模式的半字节 SIMD 过滤。
//!
//! 每 8 个模式一组，一个字节里的一位对应一个模式。指纹长度是 `min(最短模式, 3)`。
//! 每个指纹偏移有一张低半字节表和一张高半字节表。一次看 `lanes` 个起点，
//! 把各偏移的查表结果按位与，非 0 的路再逐个模式确认。假阳性可以留下，漏掉才是错误。
//!
//! 查表指令按 ISA 分文件。本文件只在 `-Dteddy` 不是 off 时被引用。
//! 模式字节由调用方持有。这里不分配内存。

const std = @import("std");
const ascii = @import("ascii.zig");
const build_options = @import("build_options");
const matcher = @import("../matcher.zig");
const memchr = @import("memchr.zig");

const isa = switch (build_options.teddy) {
    .neon => @import("teddy_neon.zig"),
    .ssse3 => @import("teddy_ssse3.zig"),
    .avx2 => @import("teddy_avx2.zig"),
    .off => unreachable,
};

const lanes = isa.lanes;
const num_buckets = 8;
const max_patterns = 32;
const max_fp = 3;

const Vec = @Vector(lanes, u8);

const Group = struct {
    lo: [max_fp][16]u8,
    hi: [max_fp][16]u8,
};

const Cand = struct {
    start: usize,
    end: usize,
    id: u32,
};

pub const Engine = struct {
    patterns: []const []const u8,
    ignore_case: bool,
    min_len: usize,
    fingerprint: u8,
    group: Group,
    bucket_pats: [num_buckets]u32,

    pub fn init(patterns: []const []const u8, ignore_case: bool) Engine {
        std.debug.assert(patterns.len > 0 and patterns.len <= max_patterns);
        var min_len: usize = std.math.maxInt(usize);
        for (patterns) |pat| {
            std.debug.assert(pat.len > 0);
            min_len = @min(min_len, pat.len);
        }
        const fingerprint: u8 = @intCast(@min(min_len, max_fp));
        var group: Group = std.mem.zeroes(Group);
        var bucket_pats: [num_buckets]u32 = @splat(0);
        for (patterns, 0..) |pat, id| {
            const bucket: u3 = @intCast(id % num_buckets);
            const bit: u8 = @as(u8, 1) << bucket;
            bucket_pats[bucket] |= @as(u32, 1) << @intCast(id);
            for (0..fingerprint) |k| {
                const forms = if (ignore_case) ascii.caseVariants(pat[k]) else [2]u8{ pat[k], pat[k] };
                for (forms) |byte| {
                    group.lo[k][byte & 0x0f] |= bit;
                    group.hi[k][byte >> 4] |= bit;
                }
            }
        }
        return .{
            .patterns = patterns,
            .ignore_case = ignore_case,
            .min_len = min_len,
            .fingerprint = fingerprint,
            .group = group,
            .bucket_pats = bucket_pats,
        };
    }

    pub fn deinit(self: *Engine) void {
        self.* = undefined;
    }

    pub fn find(self: *const Engine, haystack: []const u8, start: usize, mode: matcher.MatchMode) ?matcher.Match {
        var unused: ?usize = null;
        if (start > haystack.len) return null;
        return switch (self.fingerprint) {
            inline 1...max_fp => |fp| self.findFp(fp, haystack, start, mode, false, &unused),
            else => unreachable,
        };
    }

    pub fn findWatchingNul(
        self: *const Engine,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        nul_out: *?usize,
    ) ?matcher.Match {
        if (start > haystack.len) return null;
        return switch (self.fingerprint) {
            inline 1...max_fp => |fp| self.findFp(fp, haystack, start, mode, true, nul_out),
            else => unreachable,
        };
    }

    noinline fn findFp(
        self: *const Engine,
        comptime fp: u8,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        comptime watch_nul: bool,
        nul_out: *?usize,
    ) ?matcher.Match {
        var lo_tab: [fp]Vec = undefined;
        var hi_tab: [fp]Vec = undefined;
        inline for (0..fp) |k| {
            lo_tab[k] = expandTable(&self.group.lo[k]);
            hi_tab[k] = expandTable(&self.group.hi[k]);
        }

        var best: ?Cand = null;
        var pos = start;
        var nul_checked = start;
        const fast_extra: usize = fp - 1;
        const stride = lanes * 4;
        const zero: Vec = @splat(0);

        outer: while (pos + stride + fast_extra <= haystack.len) {
            if (mode == .earliest and best != null and done(best, pos, self.min_len)) break;
            var accs: [4]Vec = undefined;
            var nul_hit: @Vector(lanes, bool) = @splat(false);
            inline for (0..4) |w| {
                const at = pos + w * lanes;
                const b0: Vec = haystack[at..][0..lanes].*;
                accs[w] = nibbleVec(lo_tab[0], hi_tab[0], b0);
                if (watch_nul) nul_hit = nul_hit | (b0 == zero);
            }
            const combined = (accs[0] | accs[1]) | (accs[2] | accs[3]);
            const check_v = if (watch_nul) combined | @as(Vec, @intFromBool(nul_hit)) else combined;
            if (@reduce(.Or, check_v) == 0) {
                pos += stride;
                if (watch_nul and best == null) nul_checked = pos;
                continue;
            }
            inline for (0..4) |w| {
                const at = pos + w * lanes;
                if (mode == .earliest and done(best, at, self.min_len)) break :outer;
                if (@reduce(.Or, accs[w]) != 0) {
                    const acc = evalRefine(fp, accs[w], haystack, at, &lo_tab, &hi_tab);
                    if (@reduce(.Or, acc) != 0) {
                        if (self.scanVec(haystack, at, mode, &best, acc)) break :outer;
                    }
                }
            }
            if (watch_nul and best == null and @reduce(.Or, nul_hit)) {
                if (memchr.find(lanes, haystack[0 .. pos + stride], nul_checked, 0)) |nul_at| {
                    nul_out.* = nul_at;
                    return null;
                }
                nul_checked = pos + stride;
            }
            pos += stride;
        }

        while (pos < haystack.len) {
            if (mode == .earliest and done(best, pos, self.min_len)) break;
            if (haystack.len - pos >= lanes) {
                const acc = self.maskTail(fp, haystack, pos, &lo_tab, &hi_tab);
                if (@reduce(.Or, acc) != 0) {
                    if (self.scanVec(haystack, pos, mode, &best, acc)) break;
                }
                pos += lanes;
            } else {
                if (self.confirm(haystack, pos, mode, &best, null)) break;
                pos += 1;
            }
        }
        const chosen = best orelse {
            if (watch_nul and nul_checked < haystack.len) {
                if (memchr.find(lanes, haystack, nul_checked, 0)) |nul_at| nul_out.* = nul_at;
            }
            return null;
        };
        if (watch_nul and nul_checked < chosen.start) {
            if (memchr.find(lanes, haystack[0..chosen.start], nul_checked, 0)) |nul_at| {
                nul_out.* = nul_at;
                return null;
            }
        }
        return .{ .start = chosen.start, .end = chosen.end };
    }

    inline fn evalRefine(
        comptime fp: u8,
        acc0: Vec,
        haystack: []const u8,
        at: usize,
        lo_tab: *const [fp]Vec,
        hi_tab: *const [fp]Vec,
    ) Vec {
        var acc = acc0;
        if (comptime fp > 1) {
            const b1: Vec = haystack[at + 1 ..][0..lanes].*;
            acc &= nibbleVec(lo_tab[1], hi_tab[1], b1);
        }
        if (comptime fp > 2) {
            const b2: Vec = haystack[at + 2 ..][0..lanes].*;
            acc &= nibbleVec(lo_tab[2], hi_tab[2], b2);
        }
        return acc;
    }

    fn maskTail(
        self: *const Engine,
        comptime fp: u8,
        haystack: []const u8,
        pos: usize,
        lo_tab: *const [fp]Vec,
        hi_tab: *const [fp]Vec,
    ) Vec {
        _ = self;
        const base = loadAt(haystack, pos);
        const next = if (comptime fp > 1) loadAt(haystack, pos + lanes) else base;
        var acc = nibbleVec(lo_tab[0], hi_tab[0], base);
        if (comptime fp > 1) {
            acc &= nibbleVec(lo_tab[1], hi_tab[1], isa.shift(base, next, 1));
        }
        if (comptime fp > 2) {
            acc &= nibbleVec(lo_tab[2], hi_tab[2], isa.shift(base, next, 2));
        }
        return acc;
    }

    fn scanVec(
        self: *const Engine,
        haystack: []const u8,
        pos: usize,
        mode: matcher.MatchMode,
        best: *?Cand,
        acc: Vec,
    ) bool {
        if (comptime lanes == 16) {
            var bits = nonzero16(acc);
            while (bits != 0) {
                @branchHint(.unlikely);
                const lane = @ctz(bits) / 4;
                const shift: u6 = @intCast(lane * 4);
                bits &= ~(@as(u64, 0xF) << shift);
                if (self.confirmLane(haystack, pos, lane, mode, best, laneByte(acc, lane))) return true;
            }
            return false;
        } else {
            const halves: [2]@Vector(16, u8) = @bitCast(acc);
            var half: usize = 0;
            while (half < 2) : (half += 1) {
                var bits = nonzero16(halves[half]);
                while (bits != 0) {
                    @branchHint(.unlikely);
                    const lane = half * 16 + @ctz(bits) / 4;
                    const shift: u6 = @intCast((@ctz(bits) / 4) * 4);
                    bits &= ~(@as(u64, 0xF) << shift);
                    if (self.confirmLane(haystack, pos, lane, mode, best, laneByte(acc, lane))) return true;
                }
            }
            return false;
        }
    }

    fn confirmLane(
        self: *const Engine,
        haystack: []const u8,
        pos: usize,
        lane: usize,
        mode: matcher.MatchMode,
        best: *?Cand,
        bucket_mask: u8,
    ) bool {
        const at = pos + lane;
        if (at >= haystack.len) return false;
        if (mode == .earliest and done(best.*, at, self.min_len)) return true;
        return self.confirm(haystack, at, mode, best, bucket_mask);
    }

    /// `bucket_mask` 为空时检查全部模式，供窗口尾巴使用。否则只确认置位桶里的模式。
    fn confirm(
        self: *const Engine,
        haystack: []const u8,
        at: usize,
        mode: matcher.MatchMode,
        best: *?Cand,
        bucket_mask: ?u8,
    ) bool {
        var pat_bits: u32 = 0;
        if (bucket_mask) |bmask| {
            var b = bmask;
            while (b != 0) {
                const bucket = @ctz(b);
                b &= b - 1;
                pat_bits |= self.bucket_pats[bucket];
            }
        } else {
            pat_bits = if (self.patterns.len == 32)
                std.math.maxInt(u32)
            else
                (@as(u32, 1) << @intCast(self.patterns.len)) - 1;
        }

        var found = false;
        while (pat_bits != 0) {
            const id: u32 = @ctz(pat_bits);
            pat_bits &= pat_bits - 1;
            const pat = self.patterns[id];
            if (!matchesAt(pat, haystack, at, self.ignore_case)) continue;
            const cand = Cand{ .start = at, .end = at + pat.len, .id = id };
            found = true;
            switch (mode) {
                .leftmost_first => {
                    best.* = cand;
                    return true;
                },
                .earliest => {
                    if (best.*) |cur| {
                        if (prefer(cand, cur)) best.* = cand;
                    } else best.* = cand;
                },
            }
        }
        if (mode == .earliest and found) {
            if (best.*) |cur| {
                if (at + 1 + self.min_len > cur.end) return true;
            }
        }
        return false;
    }
};

fn toMatch(best: ?Cand) ?matcher.Match {
    const chosen = best orelse return null;
    return .{ .start = chosen.start, .end = chosen.end };
}

fn expandTable(table: *const [16]u8) Vec {
    if (comptime lanes == 16) return table.*;
    var wide: [32]u8 = undefined;
    wide[0..16].* = table.*;
    wide[16..32].* = table.*;
    return wide;
}

fn nonzero16(block: @Vector(16, u8)) u64 {
    const hits = block != @as(@Vector(16, u8), @splat(0));
    const flags: @Vector(16, u8) = @select(u8, hits, @as(@Vector(16, u8), @splat(@as(u8, 0xFF))), @as(@Vector(16, u8), @splat(@as(u8, 0))));
    return memchr.nibbleMask(flags);
}

fn laneByte(acc: Vec, lane: usize) u8 {
    const bytes: [lanes]u8 = acc;
    return bytes[lane];
}

inline fn nibbleVec(lo_v: Vec, hi_v: Vec, bytes: Vec) Vec {
    const lo_idx = bytes & @as(Vec, @splat(0x0f));
    const hi_idx = bytes >> @as(Vec, @splat(@as(u8, 4)));
    return isa.lookup(lo_v, lo_idx) & isa.lookup(hi_v, hi_idx);
}

fn loadAt(haystack: []const u8, at: usize) Vec {
    if (at >= haystack.len) return @splat(0);
    if (haystack.len - at >= lanes) return haystack[at..][0..lanes].*;
    var tmp: [lanes]u8 = @splat(0);
    @memcpy(tmp[0 .. haystack.len - at], haystack[at..]);
    return tmp;
}

fn matchesAt(pat: []const u8, haystack: []const u8, at: usize, ignore: bool) bool {
    if (at > haystack.len or pat.len > haystack.len - at) return false;
    for (pat, haystack[at..][0..pat.len]) |p, h| {
        if (!ascii.eq(p, h, ignore)) return false;
    }
    return true;
}

fn done(best: ?Cand, at: usize, min_len: usize) bool {
    const chosen = best orelse return false;
    return at + min_len > chosen.end;
}

fn prefer(a: Cand, b: Cand) bool {
    if (a.end != b.end) return a.end < b.end;
    if (a.start != b.start) return a.start < b.start;
    return a.id < b.id;
}

test "指纹对齐后的命中和更早结束" {
    const pats = [_][]const u8{ "abcdef", "de", "xyz", "qr" };
    const engine = Engine.init(&pats, false);
    const hay = "............abcdef....de";
    const left = engine.find(hay, 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 12), left.start);
    try std.testing.expectEqual(@as(usize, 18), left.end);
    const early = engine.find(hay, 0, .earliest).?;
    try std.testing.expectEqual(@as(usize, 15), early.start);
    try std.testing.expectEqual(@as(usize, 17), early.end);

    var buf: [40]u8 = @splat('x');
    @memcpy(buf[15..18], "xyz");
    const at = engine.find(&buf, 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 15), at.start);
    try std.testing.expectEqual(@as(usize, 18), at.end);
}
