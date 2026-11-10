//! Teddy: nibble-based SIMD prefilter for small multi-pattern sets.
//!
//! Patterns are grouped into 8 buckets (one bit per bucket in a byte). The fingerprint length is `min(shortest_pattern, 3)`.
//! Each fingerprint offset has a low-nibble table and a high-nibble table. Examining `lanes` start positions at once,
//! table lookups across fingerprint offsets are bitwise-ANDed, and non-zero lanes are verified per pattern.
//! False positives are acceptable; false negatives are not.
//!
//! Lookup instructions are separated by ISA. This file is referenced only when `-Dteddy` is not `off`.
//! Pattern bytes are owned by the caller; no memory is allocated here.

const std = @import("std");
const builtin = @import("builtin");
const ascii = @import("ascii.zig");
const build_options = @import("build_options");
const frequency = @import("frequency.zig");
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
    min_tail_len: usize,
    max_offset: usize,
    fingerprint: u8,
    group: Group,
    bucket_pats: [num_buckets]u32,
    pat_offsets: [max_patterns]u32,

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
        var pat_offsets: [max_patterns]u32 = @splat(0);
        var max_offset: usize = 0;
        var min_tail_len: usize = std.math.maxInt(usize);

        for (patterns, 0..) |pat, id| {
            const bucket: u3 = @intCast(id % num_buckets);
            const bit: u8 = @as(u8, 1) << bucket;
            bucket_pats[bucket] |= @as(u32, 1) << @intCast(id);

            const off = pickWindowOffset(pat, fingerprint, ignore_case, &group);
            pat_offsets[id] = @intCast(off);
            max_offset = @max(max_offset, off);
            min_tail_len = @min(min_tail_len, pat.len - off);

            for (0..fingerprint) |k| {
                const b = pat[off + k];
                const forms = if (ignore_case) ascii.caseVariants(b) else [2]u8{ b, b };
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
            .min_tail_len = min_tail_len,
            .max_offset = max_offset,
            .fingerprint = fingerprint,
            .group = group,
            .bucket_pats = bucket_pats,
            .pat_offsets = pat_offsets,
        };
    }

    fn pickWindowOffset(
        pat: []const u8,
        fingerprint: u8,
        ignore_case: bool,
        group: *const Group,
    ) usize {
        if (pat.len <= fingerprint) return 0;
        const max_scan = @min(pat.len - fingerprint + 1, 64);
        var best_off: usize = 0;
        var best_score: u32 = std.math.maxInt(u32);

        for (0..max_scan) |off| {
            const w = pat[off .. off + fingerprint];
            var score: u32 = @intCast(off);
            for (0..fingerprint) |k| {
                const b = w[k];
                const forms = ascii.caseVariants(b);
                const r: u32 = if (ignore_case)
                    @max(frequency.default_rank[forms[0]], frequency.default_rank[forms[1]])
                else
                    frequency.default_rank[b];
                // Weight the first two window bytes higher because the hot 128-byte loop filters on them.
                const weight: u32 = if (k < 2) 2 else 1;
                score += r * weight;
                if (b == '=' or b == ':') score += 220;
                if ((group.lo[k][b & 0x0f] & group.hi[k][b >> 4]) != 0) score += 45;
            }
            if (fingerprint >= 2 and ascii.eq(w[0], w[1], ignore_case)) score += 140;
            if (fingerprint >= 3) {
                if (ascii.eq(w[1], w[2], ignore_case)) score += 100;
                if (ascii.eq(w[0], w[2], ignore_case)) score += 35;
            }
            if (score < best_score) {
                best_score = score;
                best_off = off;
            }
        }
        return best_off;
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
            if (best != null and self.done(best, pos, mode)) break;
            var accs: [4]Vec = undefined;
            var nul_hit: @Vector(lanes, bool) = @splat(false);
            inline for (0..4) |w| {
                const at = pos + w * lanes;
                const b0: Vec = haystack[at..][0..lanes].*;
                var acc = nibbleVec(lo_tab[0], hi_tab[0], b0);
                if (comptime fp > 1) {
                    const b1: Vec = haystack[at + 1 ..][0..lanes].*;
                    acc &= nibbleVec(lo_tab[1], hi_tab[1], b1);
                }
                accs[w] = acc;
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
                if (best != null and self.done(best, at, mode)) break :outer;
                if (@reduce(.Or, accs[w]) != 0) {
                    const acc = evalRefine(fp, accs[w], haystack, at, &lo_tab, &hi_tab);
                    if (@reduce(.Or, acc) != 0) {
                        if (self.scanVec(haystack, at, start, mode, &best, acc)) break :outer;
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
            if (best != null and self.done(best, pos, mode)) break;
            if (haystack.len - pos >= lanes) {
                const acc = self.maskTail(fp, haystack, pos, &lo_tab, &hi_tab);
                if (@reduce(.Or, acc) != 0) {
                    if (self.scanVec(haystack, pos, start, mode, &best, acc)) break;
                }
                pos += lanes;
            } else {
                if (self.confirm(haystack, pos, start, mode, &best, null)) break;
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
        return .{ .start = chosen.start, .end = chosen.end, .pattern_id = chosen.id };
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
        start: usize,
        mode: matcher.MatchMode,
        best: *?Cand,
        acc: Vec,
    ) bool {
        if (comptime builtin.cpu.arch.endian() == .little) {
            const MaskInt = @Int(.unsigned, lanes);
            const zero: Vec = @splat(0);
            var bits: MaskInt = @bitCast(acc != zero);
            while (bits != 0) {
                @branchHint(.unlikely);
                const lane: usize = @ctz(bits);
                bits &= bits - 1;
                if (self.confirmLane(haystack, pos, start, lane, mode, best, laneByte(acc, lane))) return true;
            }
            return false;
        } else if (comptime lanes == 16) {
            var bits = nonzero16(acc);
            while (bits != 0) {
                @branchHint(.unlikely);
                const lane = @ctz(bits) / 4;
                const shift: u6 = @intCast(lane * 4);
                bits &= ~(@as(u64, 0xF) << shift);
                if (self.confirmLane(haystack, pos, start, lane, mode, best, laneByte(acc, lane))) return true;
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
                    if (self.confirmLane(haystack, pos, start, lane, mode, best, laneByte(acc, lane))) return true;
                }
            }
            return false;
        }
    }

    fn confirmLane(
        self: *const Engine,
        haystack: []const u8,
        pos: usize,
        start: usize,
        lane: usize,
        mode: matcher.MatchMode,
        best: *?Cand,
        bucket_mask: u8,
    ) bool {
        const at = pos + lane;
        if (at >= haystack.len) return false;
        if (best.* != null and self.done(best.*, at, mode)) return true;
        return self.confirm(haystack, at, start, mode, best, bucket_mask);
    }

    /// Checks all patterns when `bucket_mask` is null (used for tail bytes); otherwise verifies only patterns in set buckets.
    fn confirm(
        self: *const Engine,
        haystack: []const u8,
        at: usize,
        start: usize,
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
            const off: usize = self.pat_offsets[id];
            if (at < off) continue;
            const pat_start = at - off;
            if (pat_start < start) continue;
            const pat = self.patterns[id];
            if (!matchesAt(pat, haystack, pat_start, self.ignore_case)) continue;
            const cand = Cand{ .start = pat_start, .end = pat_start + pat.len, .id = id };
            found = true;
            switch (mode) {
                .leftmost_first => {
                    if (best.*) |cur| {
                        if (preferLeftmost(cand, cur)) best.* = cand;
                    } else best.* = cand;
                    if (self.max_offset == 0) return true;
                },
                .earliest => {
                    if (best.*) |cur| {
                        if (prefer(cand, cur)) best.* = cand;
                    } else best.* = cand;
                },
            }
        }
        if (found and self.done(best.*, at + 1, mode)) return true;
        return false;
    }

    inline fn done(self: *const Engine, best: ?Cand, at: usize, mode: matcher.MatchMode) bool {
        const chosen = best orelse return false;
        return switch (mode) {
            .leftmost_first => at > chosen.start + self.max_offset,
            .earliest => at + self.min_tail_len > chosen.end,
        };
    }
};

fn toMatch(best: ?Cand) ?matcher.Match {
    const chosen = best orelse return null;
    return .{ .start = chosen.start, .end = chosen.end, .pattern_id = chosen.id };
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

fn preferLeftmost(a: Cand, b: Cand) bool {
    if (a.start != b.start) return a.start < b.start;
    return a.id < b.id;
}

fn prefer(a: Cand, b: Cand) bool {
    if (a.end != b.end) return a.end < b.end;
    if (a.start != b.start) return a.start < b.start;
    return a.id < b.id;
}

test "aligned fingerprint hits and earliest match termination" {
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

test "rarest window offset preserves leftmost_first and earliest ordering" {
    const pats = [_][]const u8{
        "req=99999999-e89b-12d3-a456-426614174000",
        "req=ffffffff-ffff-ffff-ffff-ffffffffffff",
        "FATAL [auth]",
    };
    const engine = Engine.init(&pats, false);
    try std.testing.expect(engine.pat_offsets[0] > 0);
    try std.testing.expect(engine.pat_offsets[1] > 0);

    const hay = "prefix req=99999999-e89b-12d3-a456-426614174000 FATAL [auth] suffix";
    const left = engine.find(hay, 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 7), left.start);
    try std.testing.expectEqual(@as(u32, 0), left.pattern_id);
}
