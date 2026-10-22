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

const isa = switch (build_options.teddy) {
    .neon => @import("teddy_neon.zig"),
    .ssse3 => @import("teddy_ssse3.zig"),
    .avx2 => @import("teddy_avx2.zig"),
    .off => unreachable,
};

const lanes = isa.lanes;
const max_groups = 4;
const max_patterns = max_groups * 8;
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
    ngroups: u8,
    groups: [max_groups]Group,

    pub fn init(patterns: []const []const u8, ignore_case: bool) Engine {
        std.debug.assert(patterns.len > 0 and patterns.len <= max_patterns);
        var min_len: usize = std.math.maxInt(usize);
        for (patterns) |pat| {
            std.debug.assert(pat.len > 0);
            min_len = @min(min_len, pat.len);
        }
        const fingerprint: u8 = @intCast(@min(min_len, max_fp));
        var groups: [max_groups]Group = std.mem.zeroes([max_groups]Group);
        for (patterns, 0..) |pat, id| {
            const group = id / 8;
            const bit: u8 = @as(u8, 1) << @intCast(id % 8);
            for (0..fingerprint) |k| {
                const forms = if (ignore_case) ascii.caseVariants(pat[k]) else [2]u8{ pat[k], pat[k] };
                for (forms) |byte| {
                    groups[group].lo[k][byte & 0x0f] |= bit;
                    groups[group].hi[k][byte >> 4] |= bit;
                }
            }
        }
        return .{
            .patterns = patterns,
            .ignore_case = ignore_case,
            .min_len = min_len,
            .fingerprint = fingerprint,
            .ngroups = @intCast((patterns.len + 7) / 8),
            .groups = groups,
        };
    }

    pub fn deinit(self: *Engine) void {
        self.* = undefined;
    }

    pub fn find(self: *const Engine, haystack: []const u8, start: usize, mode: matcher.MatchMode) ?matcher.Match {
        if (start > haystack.len) return null;
        var best: ?Cand = null;
        var pos = start;
        while (pos < haystack.len) {
            if (mode == .earliest and done(best, pos, self.min_len)) break;
            if (haystack.len - pos >= lanes) {
                if (self.scan(haystack, pos, mode, &best)) break;
                pos += lanes;
            } else {
                if (self.confirm(haystack, pos, mode, &best, null)) break;
                pos += 1;
            }
        }
        const chosen = best orelse return null;
        return .{ .start = chosen.start, .end = chosen.end };
    }

    fn scan(self: *const Engine, haystack: []const u8, pos: usize, mode: matcher.MatchMode, best: *?Cand) bool {
        const base = loadAt(haystack, pos);
        const next = if (self.fingerprint > 1) loadAt(haystack, pos + lanes) else base;
        var masks: [max_groups][lanes]u8 = undefined;
        var g: usize = 0;
        while (g < self.ngroups) : (g += 1) {
            masks[g] = self.maskOf(g, base, next);
        }
        var lane: usize = 0;
        while (lane < lanes) : (lane += 1) {
            const at = pos + lane;
            if (at >= haystack.len) return false;
            if (mode == .earliest and done(best.*, at, self.min_len)) return true;
            var row: [max_groups]u8 = @splat(0);
            var any = false;
            g = 0;
            while (g < self.ngroups) : (g += 1) {
                row[g] = masks[g][lane];
                if (row[g] != 0) any = true;
            }
            if (!any) continue;
            if (self.confirm(haystack, at, mode, best, row)) return true;
        }
        return false;
    }

    fn maskOf(self: *const Engine, group: usize, base: Vec, next: Vec) [lanes]u8 {
        var acc = nibble(&self.groups[group].lo[0], &self.groups[group].hi[0], base);
        if (self.fingerprint > 1) {
            acc &= nibble(&self.groups[group].lo[1], &self.groups[group].hi[1], isa.shift(base, next, 1));
        }
        if (self.fingerprint > 2) {
            acc &= nibble(&self.groups[group].lo[2], &self.groups[group].hi[2], isa.shift(base, next, 2));
        }
        return acc;
    }

    /// `lane_bits` 为空时检查全部模式，供窗口尾巴使用。否则只确认这一路上置位的模式。
    fn confirm(
        self: *const Engine,
        haystack: []const u8,
        at: usize,
        mode: matcher.MatchMode,
        best: *?Cand,
        lane_bits: ?[max_groups]u8,
    ) bool {
        var found = false;
        var g: usize = 0;
        while (g < self.ngroups) : (g += 1) {
            const bits: u8 = if (lane_bits) |row| row[g] else 0xff;
            if (bits == 0) continue;
            var local: u32 = 0;
            var rest = bits;
            while (rest != 0) : (local += 1) {
                const on: u8 = @intCast(rest & 1);
                rest >>= 1;
                if (on == 0) continue;
                const id: u32 = @intCast(g * 8 + local);
                if (id >= self.patterns.len) continue;
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
        }
        if (mode == .earliest and found) {
            if (best.*) |cur| {
                if (at + 1 + self.min_len > cur.end) return true;
            }
        }
        return false;
    }
};

fn nibble(lo: *const [16]u8, hi: *const [16]u8, bytes: Vec) Vec {
    const lo_idx = bytes & @as(Vec, @splat(0x0f));
    const hi_idx = bytes >> @as(Vec, @splat(@as(u8, 4)));
    return isa.lookup(lo, lo_idx) & isa.lookup(hi, hi_idx);
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
