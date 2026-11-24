//! Prefilters using two rare bytes, then verifies candidate spans in full.
//! Patterns must be at least two bytes; single-byte patterns use memchr and are not handled here.
//!
//! The hot path uses generic SIMD (Wojciech Muła's generic SIMD algorithm, also used by
//! memchr's packed pair): each vector compares bytes at two offsets simultaneously and ANDs their masks.
//! The loop exits SIMD only when both bytes hit together. Even if individual bytes are common,
//! as long as their relative offset does not match, execution stays entirely within vector instructions.

const builtin = @import("builtin");
const std = @import("std");
const ascii = @import("ascii.zig");
const memchr = @import("memchr.zig");

/// Up to this length, packed pair completes the search itself without handing the remaining input to Two-Way.
/// False positives multiplied by at most a 32-byte comparison still run in constant-factor linear time.
/// Matches memchr's `do_packed_search` upper bound.
pub const owns_search_max_len: usize = 32;

/// Prefilter accounting for long patterns. When failed verifications skip too few bytes on average,
/// the caller should switch to Two-Way.
/// Thresholds match memchr's PrefilterState: at least 50 candidates and fewer than 8 bytes skipped per candidate on average.
pub const Guard = struct {
    candidates: u32 = 0,
    skipped: u64 = 0,
    /// Offset where Two-Way should resume after the prefilter gives up (`resume` is a reserved keyword).
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
    third_index: usize,
    fourth_index: usize,
    anchor: u8,
    other: u8,
    third: u8,
    fourth: u8,
    anchor_match: u8,
    other_match: u8,
    ignore_case: bool,
    anchor_fold: bool,
    other_fold: bool,
    pattern_has_nul: bool,
    pat_lower: [owns_search_max_len]u8,
    pat_mask: [owns_search_max_len]u8,

    /// Smaller `rank` values indicate rarer bytes. `pattern` is owned by the caller.
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
            } else if (r == rank[pattern[second]]) {
                const cur_dist = if (second > best) second - best else best - second;
                const new_dist = if (i > best) i - best else best - i;
                if (new_dist > cur_dist) {
                    second = i;
                }
            }
        }
        var third_idx: usize = second;
        var third_rank: u16 = 256;
        for (pattern, 0..) |b, idx| {
            if (idx == best or idx == second) continue;
            if (rank[b] < third_rank) {
                third_rank = rank[b];
                third_idx = idx;
            }
        }
        var fourth_idx: usize = third_idx;
        var fourth_rank: u16 = 256;
        for (pattern, 0..) |b, idx| {
            if (idx == best or idx == second or idx == third_idx) continue;
            if (rank[b] < fourth_rank) {
                fourth_rank = rank[b];
                fourth_idx = idx;
            }
        }
        const a_forms = ascii.caseVariants(pattern[best]);
        const o_forms = ascii.caseVariants(pattern[second]);
        const anchor_fold = ignore_case and (a_forms[0] != a_forms[1]);
        const other_fold = ignore_case and (o_forms[0] != o_forms[1]);
        const anchor_match = if (anchor_fold) a_forms[0] else pattern[best];
        const other_match = if (other_fold) o_forms[0] else pattern[second];

        var pat_lower: [owns_search_max_len]u8 = @splat(0);
        var pat_mask: [owns_search_max_len]u8 = @splat(0);
        if (ignore_case and pattern.len <= owns_search_max_len) {
            for (pattern, 0..) |b, idx| {
                const forms = ascii.caseVariants(b);
                if (forms[0] != forms[1]) {
                    pat_lower[idx] = forms[0];
                    pat_mask[idx] = 0x20;
                } else {
                    pat_lower[idx] = b;
                    pat_mask[idx] = 0x00;
                }
            }
        }
        const pattern_has_nul = std.mem.findScalar(u8, pattern, 0) != null;

        return .{
            .pattern = pattern,
            .anchor_index = best,
            .other_index = second,
            .third_index = third_idx,
            .fourth_index = fourth_idx,
            .anchor = pattern[best],
            .other = pattern[second],
            .third = pattern[third_idx],
            .fourth = pattern[fourth_idx],
            .anchor_match = anchor_match,
            .other_match = other_match,
            .ignore_case = ignore_case,
            .anchor_fold = anchor_fold,
            .other_fold = other_fold,
            .pattern_has_nul = pattern_has_nul,
            .pat_lower = pat_lower,
            .pat_mask = pat_mask,
        };
    }

    /// Finds the start of the next full match in `haystack[start..]`.
    /// When `guard` is non-null and the pattern is longer than `owns_search_max_len`, stops if the prefilter
    /// advances too slowly and records the resume offset for Two-Way in `guard`.
    pub inline fn find(
        self: *const PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        guard: ?*Guard,
    ) ?usize {
        return self.findInner(width, haystack, start, guard, false, undefined);
    }

    pub fn findWithWidth(
        self: *const PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        guard: ?*Guard,
    ) ?usize {
        return self.find(width, haystack, start, guard);
    }

    /// Same as `find`, while also checking already-loaded vectors for NUL bytes.
    /// If a NUL is seen before a match completes, writes its offset to `nul_out` and returns null so the caller can apply its binary policy.
    /// When returning a match, guarantees no NUL precedes or lies within the matched span; bytes after the match are checked by the caller.
    pub inline fn findWatchingNul(
        self: *const PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        guard: ?*Guard,
        nul_out: *?usize,
    ) ?usize {
        return self.findInner(width, haystack, start, guard, true, nul_out);
    }

    pub fn findWatchingNulWithWidth(
        self: *const PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        guard: ?*Guard,
        nul_out: *?usize,
    ) ?usize {
        return self.findWatchingNul(width, haystack, start, guard, nul_out);
    }

    inline fn findInner(
        self: *const PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        guard: ?*Guard,
        comptime watch_nul: bool,
        nul_out: *?usize,
    ) ?usize {
        comptime if (width != 16 and width != 32 and width != 64) @compileError("packed pair width must be 16, 32, or 64");
        const m = self.pattern.len;
        if (m > haystack.len or start > haystack.len - m) {
            if (watch_nul and start <= haystack.len) {
                _ = noteNul(haystack[start..], start, nul_out);
            }
            return null;
        }
        const last = haystack.len - m;
        // Case folding (specialized on per-anchor letter-ness), guard accounting, and NUL watching are specialized
        // outside the loop so the miss loop contains only loads, comparisons, and reductions.
        // Keep the case-sensitive unwatched loop inline so `Finder.findPair` avoids a nested call and stack frame;
        // outline fold/guarded variants so they never inflate the hot frame.
        if (self.ignore_case) {
            if (guard) |g| return self.dispatchFoldOutOfLine(width, haystack, start, last, true, watch_nul, g, nul_out);
            return self.dispatchFoldOutOfLine(width, haystack, start, last, false, watch_nul, undefined, nul_out);
        }
        if (guard) |g| return self.findLoopOutOfLine(width, haystack, start, last, false, false, false, true, watch_nul, g, nul_out);
        return self.findLoop(width, haystack, start, last, false, false, false, false, watch_nul, undefined, nul_out);
    }

    fn dispatchFoldOutOfLine(
        self: *const PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        last: usize,
        comptime watched: bool,
        comptime watch_nul: bool,
        guard: *Guard,
        nul_out: *?usize,
    ) ?usize {
        if (!self.anchor_fold) {
            if (!self.other_fold) {
                return self.findLoopOutOfLine(width, haystack, start, last, true, false, false, watched, watch_nul, guard, nul_out);
            }
            return self.findLoopOutOfLine(width, haystack, start, last, true, false, true, watched, watch_nul, guard, nul_out);
        } else {
            if (!self.other_fold) {
                return self.findLoopOutOfLine(width, haystack, start, last, true, true, false, watched, watch_nul, guard, nul_out);
            }
            return self.findLoopOutOfLine(width, haystack, start, last, true, true, true, watched, watch_nul, guard, nul_out);
        }
    }

    noinline fn findLoopOutOfLine(
        self: *const PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        last: usize,
        comptime fold: bool,
        comptime a_fold: bool,
        comptime o_fold: bool,
        comptime watched: bool,
        comptime watch_nul: bool,
        guard: *Guard,
        nul_out: *?usize,
    ) ?usize {
        return self.findLoop(width, haystack, start, last, fold, a_fold, o_fold, watched, watch_nul, guard, nul_out);
    }

    inline fn findLoop(
        self: *const PackedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        last: usize,
        comptime fold: bool,
        comptime a_fold: bool,
        comptime o_fold: bool,
        comptime watched: bool,
        comptime watch_nul: bool,
        guard: *Guard,
        nul_out: *?usize,
    ) ?usize {
        const max_index = @max(@max(self.anchor_index, self.other_index), @max(self.third_index, self.fourth_index));
        const cover_index = @min(self.anchor_index, self.other_index);
        // When the minimum anchor offset is non-zero, SIMD loads do not cover the leading bytes after `start`.
        if (watch_nul and cover_index > 0) {
            const prefix_end = @min(haystack.len, start + cover_index);
            if (noteNul(haystack[start..prefix_end], start, nul_out)) return null;
        }
        var origin = start;
        var previous = start;

        // Probe a single `width`-byte vector at `origin = start` before entering the 4-vector (128B) unrolled loop.
        // Dense hits in the first 32 bytes resolve in 2 vector loads + inline confirm instead of preloading 8 vectors.
        if (origin <= last and origin + max_index + width <= haystack.len) {
            const first_mask = hotMask(self, width, haystack, origin, a_fold, o_fold, watch_nul);
            if (comptime builtin.cpu.arch.endian() == .little) {
                const MaskInt = @Int(.unsigned, width);
                const bits: MaskInt = @bitCast(first_mask);
                if (bits != 0) {
                    if (!watched and self.pattern.len <= owns_search_max_len) {
                        switch (confirmBitsInline(self, width, haystack, origin, last, bits, cover_index, fold, watch_nul, nul_out)) {
                            .match => |at| return at,
                            .nul => return null,
                            .none => {},
                        }
                    } else {
                        const rel = @call(
                            .never_inline,
                            takeHitMask,
                            .{ self, width, haystack, origin, last, bits, &previous, fold, watched, watch_nul, guard, nul_out },
                        );
                        if (watch_nul and nul_out.* != null) return null;
                        if (rel) |found| return origin + found;
                        if (watched and guard.gave_up) return null;
                    }
                }
            } else if (@reduce(.Or, first_mask)) {
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

        // Advance 4 vectors per iteration and OR their masks into a single reduction, cutting reduction and branch instructions by 75%.
        const stride = width * 4;
        while (origin <= last and origin + max_index + stride <= haystack.len) {
            var masks: [4]@Vector(width, bool) = undefined;
            inline for (0..4) |k| {
                masks[k] = hotMask(self, width, haystack, origin + k * width, a_fold, o_fold, watch_nul);
            }
            if (@reduce(.Or, (masks[0] | masks[1]) | (masks[2] | masks[3]))) {
                @branchHint(.unlikely);
                if (comptime builtin.cpu.arch.endian() == .little) {
                    const MaskInt = @Int(.unsigned, width);
                    const bit_arr = [4]MaskInt{
                        @bitCast(masks[0]),
                        @bitCast(masks[1]),
                        @bitCast(masks[2]),
                        @bitCast(masks[3]),
                    };
                    for (bit_arr, 0..) |bits, k| {
                        if (bits == 0) continue;
                        const at_origin = origin + k * width;
                        if (!watched and self.pattern.len <= owns_search_max_len) {
                            switch (confirmBitsInline(self, width, haystack, at_origin, last, bits, cover_index, fold, watch_nul, nul_out)) {
                                .match => |at| return at,
                                .nul => return null,
                                .none => {},
                            }
                        } else {
                            const rel = @call(
                                .never_inline,
                                takeHitMask,
                                .{ self, width, haystack, at_origin, last, bits, &previous, fold, watched, watch_nul, guard, nul_out },
                            );
                            if (watch_nul and nul_out.* != null) return null;
                            if (rel) |found| return at_origin + found;
                            if (watched and guard.gave_up) return null;
                        }
                    }
                } else {
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
            }
            origin += stride;
        }
        while (origin <= last and origin + max_index + width <= haystack.len) {
            const vec_mask = hotMask(self, width, haystack, origin, a_fold, o_fold, watch_nul);
            if (comptime builtin.cpu.arch.endian() == .little) {
                const MaskInt = @Int(.unsigned, width);
                const bits: MaskInt = @bitCast(vec_mask);
                if (bits != 0) {
                    @branchHint(.unlikely);
                    if (!watched and self.pattern.len <= owns_search_max_len) {
                        switch (confirmBitsInline(self, width, haystack, origin, last, bits, cover_index, fold, watch_nul, nul_out)) {
                            .match => |at| return at,
                            .nul => return null,
                            .none => {},
                        }
                    } else {
                        const rel = @call(
                            .never_inline,
                            takeHitMask,
                            .{ self, width, haystack, origin, last, bits, &previous, fold, watched, watch_nul, guard, nul_out },
                        );
                        if (watch_nul and nul_out.* != null) return null;
                        if (rel) |found| return origin + found;
                        if (watched and guard.gave_up) return null;
                    }
                }
            } else if (@reduce(.Or, vec_mask)) {
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
        const tail_hit = scalarFrom(self, haystack, origin, last, &previous, fold, watched, guard);
        if (watch_nul) {
            const from = @min(haystack.len, origin + cover_index);
            const nul_limit = if (tail_hit) |pos| @min(haystack.len, @max(from, pos + self.pattern.len)) else haystack.len;
            if (noteNul(haystack[from..nul_limit], from, nul_out)) return null;
        }
        return tail_hit;
    }
};

/// Exact SIMD packed-pair matcher where each pattern byte has an optional single-bit OR-mask
/// (`(h | mask) == val`, where `mask == 0` for exact bytes or `@popCount(mask) == 1` for 2-variant
/// case-folded UTF-8 bytes such as ASCII `a/A`, Latin-1 `é/É` (`0xA9/0x89`), Greek `δ/Δ`, etc.).
/// Guarantees zero false positives and zero false negatives without UTF-8 decoding in the hot path.
pub const MaskedPair = struct {
    len: u8,
    values: [64]u8,
    masks: [64]u8,
    anchor_index: u8,
    other_index: u8,
    third_index: u8,
    fourth_index: u8,
    anchor_val: u8,
    anchor_mask: u8,
    other_val: u8,
    other_mask: u8,
    third_val: u8,
    third_mask: u8,
    fourth_val: u8,
    fourth_mask: u8,

    pub fn init(values: []const u8, masks: []const u8, rank: *const [256]u8) MaskedPair {
        std.debug.assert(values.len >= 2 and values.len <= 64 and values.len == masks.len);
        var vals_buf: [64]u8 = @splat(0);
        var mask_buf: [64]u8 = @splat(0);
        @memcpy(vals_buf[0..values.len], values);
        @memcpy(mask_buf[0..masks.len], masks);

        var eff_ranks: [64]u16 = undefined;
        for (0..values.len) |i| {
            const v = vals_buf[i];
            const m = mask_buf[i];
            eff_ranks[i] = if (m == 0)
                rank[v]
            else
                @as(u16, @max(rank[v], rank[v ^ m])) + 15;
        }

        var best: usize = 0;
        var second: usize = 1;
        if (eff_ranks[second] < eff_ranks[best]) {
            best = 1;
            second = 0;
        }
        var i: usize = 2;
        while (i < values.len) : (i += 1) {
            const r = eff_ranks[i];
            if (r < eff_ranks[best]) {
                second = best;
                best = i;
            } else if (r < eff_ranks[second]) {
                second = i;
            } else if (r == eff_ranks[second]) {
                const cur_dist = if (second > best) second - best else best - second;
                const new_dist = if (i > best) i - best else best - i;
                if (new_dist > cur_dist) second = i;
            }
        }
        var third_idx: usize = second;
        var third_rank: u16 = std.math.maxInt(u16);
        for (0..values.len) |idx| {
            if (idx == best or idx == second) continue;
            if (eff_ranks[idx] < third_rank) {
                third_rank = eff_ranks[idx];
                third_idx = idx;
            }
        }
        var fourth_idx: usize = third_idx;
        var fourth_rank: u16 = std.math.maxInt(u16);
        for (0..values.len) |idx| {
            if (idx == best or idx == second or idx == third_idx) continue;
            if (eff_ranks[idx] < fourth_rank) {
                fourth_rank = eff_ranks[idx];
                fourth_idx = idx;
            }
        }
        return .{
            .len = @intCast(values.len),
            .values = vals_buf,
            .masks = mask_buf,
            .anchor_index = @intCast(best),
            .other_index = @intCast(second),
            .third_index = @intCast(third_idx),
            .fourth_index = @intCast(fourth_idx),
            .anchor_val = vals_buf[best],
            .anchor_mask = mask_buf[best],
            .other_val = vals_buf[second],
            .other_mask = mask_buf[second],
            .third_val = vals_buf[third_idx],
            .third_mask = mask_buf[third_idx],
            .fourth_val = vals_buf[fourth_idx],
            .fourth_mask = mask_buf[fourth_idx],
        };
    }

    pub inline fn confirmAt(self: *const MaskedPair, haystack: []const u8, origin: usize) bool {
        const m: usize = self.len;
        const window = haystack[origin..][0..m];
        for (0..m) |k| {
            if ((window[k] | self.masks[k]) != self.values[k]) return false;
        }
        return true;
    }

    pub fn find(self: *const MaskedPair, comptime width: comptime_int, haystack: []const u8, start: usize) ?usize {
        var unused: ?usize = null;
        return self.findInner(width, haystack, start, false, &unused);
    }

    pub fn findWatchingNul(
        self: *const MaskedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        nul_out: *?usize,
    ) ?usize {
        return self.findInner(width, haystack, start, true, nul_out);
    }

    fn findInner(
        self: *const MaskedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        comptime watch_nul: bool,
        nul_out: *?usize,
    ) ?usize {
        comptime if (width != 16 and width != 32 and width != 64) @compileError("packed pair width must be 16, 32, or 64");
        const m: usize = self.len;
        if (m > haystack.len or start > haystack.len - m) {
            if (watch_nul and start <= haystack.len) {
                _ = noteNul(haystack[start..], start, nul_out);
            }
            return null;
        }
        const last = haystack.len - m;
        if (self.anchor_mask == 0) {
            if (self.other_mask == 0) {
                return self.findLoop(width, haystack, start, last, false, false, watch_nul, nul_out);
            }
            return self.findLoop(width, haystack, start, last, false, true, watch_nul, nul_out);
        } else {
            if (self.other_mask == 0) {
                return self.findLoop(width, haystack, start, last, true, false, watch_nul, nul_out);
            }
            return self.findLoop(width, haystack, start, last, true, true, watch_nul, nul_out);
        }
    }

    inline fn maskedByteVec(
        comptime width: comptime_int,
        block: @Vector(width, u8),
        val: u8,
        mask: u8,
        comptime use_mask: bool,
    ) @Vector(width, bool) {
        if (!use_mask) return block == @as(@Vector(width, u8), @splat(val));
        return (block | @as(@Vector(width, u8), @splat(mask))) == @as(@Vector(width, u8), @splat(val));
    }

    inline fn hotMask(
        self: *const MaskedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        origin: usize,
        comptime a_masked: bool,
        comptime o_masked: bool,
        comptime watch_nul: bool,
    ) @Vector(width, bool) {
        const left: @Vector(width, u8) = haystack[origin + self.anchor_index ..][0..width].*;
        const right: @Vector(width, u8) = haystack[origin + self.other_index ..][0..width].*;
        const hits = maskedByteVec(width, left, self.anchor_val, self.anchor_mask, a_masked) &
            maskedByteVec(width, right, self.other_val, self.other_mask, o_masked);
        if (!watch_nul) return hits;
        const cover = if (self.anchor_index <= self.other_index) left else right;
        return hits | (cover == @as(@Vector(width, u8), @splat(0)));
    }

    fn findLoop(
        self: *const MaskedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        start: usize,
        last: usize,
        comptime a_masked: bool,
        comptime o_masked: bool,
        comptime watch_nul: bool,
        nul_out: *?usize,
    ) ?usize {
        const max_index: usize = @max(@max(self.anchor_index, self.other_index), @max(self.third_index, self.fourth_index));
        const cover_index: usize = @min(self.anchor_index, self.other_index);
        if (watch_nul and cover_index > 0) {
            const prefix_end = @min(haystack.len, start + cover_index);
            if (noteNul(haystack[start..prefix_end], start, nul_out)) return null;
        }
        var origin = start;
        const stride = width * 4;
        while (origin <= last and origin + max_index + stride <= haystack.len) {
            var masks: [4]@Vector(width, bool) = undefined;
            inline for (0..4) |k| {
                masks[k] = self.hotMask(width, haystack, origin + k * width, a_masked, o_masked, watch_nul);
            }
            if (@reduce(.Or, (masks[0] | masks[1]) | (masks[2] | masks[3]))) {
                @branchHint(.unlikely);
                inline for (0..4) |k| {
                    if (@reduce(.Or, masks[k])) {
                        const at = origin + k * width;
                        const rel = @call(
                            .never_inline,
                            takeHitMasked,
                            .{ self, width, haystack, at, last, a_masked, o_masked, watch_nul, nul_out },
                        );
                        if (watch_nul and nul_out.* != null) return null;
                        if (rel) |found| return at + found;
                    }
                }
            }
            origin += stride;
        }
        while (origin <= last and origin + max_index + width <= haystack.len) {
            if (@reduce(.Or, self.hotMask(width, haystack, origin, a_masked, o_masked, watch_nul))) {
                @branchHint(.unlikely);
                const rel = @call(
                    .never_inline,
                    takeHitMasked,
                    .{ self, width, haystack, origin, last, a_masked, o_masked, watch_nul, nul_out },
                );
                if (watch_nul and nul_out.* != null) return null;
                if (rel) |found| return origin + found;
            }
            origin += width;
        }
        var tail_hit: ?usize = null;
        var i = origin;
        while (i <= last) : (i += 1) {
            if ((haystack[i + self.anchor_index] | self.anchor_mask) != self.anchor_val) continue;
            if ((haystack[i + self.other_index] | self.other_mask) != self.other_val) continue;
            if (self.confirmAt(haystack, i)) {
                tail_hit = i;
                break;
            }
        }
        if (watch_nul) {
            const from = @min(haystack.len, origin + cover_index);
            const nul_limit = if (tail_hit) |pos| @min(haystack.len, @max(from, pos + self.len)) else haystack.len;
            if (noteNul(haystack[from..nul_limit], from, nul_out)) return null;
        }
        return tail_hit;
    }

    fn takeHitMasked(
        self: *const MaskedPair,
        comptime width: comptime_int,
        haystack: []const u8,
        origin: usize,
        last: usize,
        comptime a_masked: bool,
        comptime o_masked: bool,
        comptime watch_nul: bool,
        nul_out: *?usize,
    ) ?usize {
        const cover_index: usize = @min(self.anchor_index, self.other_index);
        const left: @Vector(width, u8) = haystack[origin + self.anchor_index ..][0..width].*;
        const right: @Vector(width, u8) = haystack[origin + self.other_index ..][0..width].*;
        var hits = maskedByteVec(width, left, self.anchor_val, self.anchor_mask, a_masked) &
            maskedByteVec(width, right, self.other_val, self.other_mask, o_masked);
        if (self.len >= 4) {
            const b3: @Vector(width, u8) = haystack[origin + self.third_index ..][0..width].*;
            const b4: @Vector(width, u8) = haystack[origin + self.fourth_index ..][0..width].*;
            hits = hits &
                maskedByteVec(width, b3, self.third_val, self.third_mask, true) &
                maskedByteVec(width, b4, self.fourth_val, self.fourth_mask, true);
        }

        if (comptime builtin.cpu.arch.endian() == .little) {
            const MaskInt = @Int(.unsigned, width);
            var mask: MaskInt = @bitCast(hits);
            while (mask != 0) : (mask &= mask - 1) {
                const rel: usize = @ctz(mask);
                const at = origin + rel;
                if (at > last) continue;
                if (self.confirmAt(haystack, at)) {
                    if (watch_nul) {
                        const check_start = @min(haystack.len, origin + cover_index);
                        const check_end = @min(haystack.len, @max(check_start, at + self.len));
                        if (noteNul(haystack[check_start..check_end], check_start, nul_out)) return null;
                    }
                    return rel;
                }
            }
        } else {
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
                if (self.confirmAt(haystack, at)) {
                    if (watch_nul) {
                        const check_start = @min(haystack.len, origin + cover_index);
                        const check_end = @min(haystack.len, @max(check_start, at + self.len));
                        if (noteNul(haystack[check_start..check_end], check_start, nul_out)) return null;
                    }
                    return @as(usize, rel);
                }
            }
        }

        if (watch_nul) {
            const block: @Vector(width, u8) = haystack[origin + cover_index ..][0..width].*;
            const zeros = block == @as(@Vector(width, u8), @splat(0));
            if (comptime builtin.cpu.arch.endian() == .little) {
                const MaskInt = @Int(.unsigned, width);
                const zmask: MaskInt = @bitCast(zeros);
                if (zmask != 0) {
                    nul_out.* = origin + cover_index + @as(usize, @ctz(zmask));
                    return null;
                }
            } else if (@reduce(.Or, zeros)) {
                const zrel = std.simd.firstTrue(zeros).?;
                nul_out.* = origin + cover_index + @as(usize, zrel);
                return null;
            }
        }
        return null;
    }
};

const InlineHit = union(enum) {
    none,
    match: usize,
    nul,
};

inline fn confirmBitsInline(
    self: *const PackedPair,
    comptime width: comptime_int,
    haystack: []const u8,
    at_origin: usize,
    last: usize,
    bits: @Int(.unsigned, width),
    cover_index: usize,
    comptime fold: bool,
    comptime watch_nul: bool,
    nul_out: *?usize,
) InlineHit {
    const MaskInt = @Int(.unsigned, width);
    var m_bits = bits;
    while (m_bits != 0) : (m_bits &= m_bits - 1) {
        const rel: usize = @ctz(m_bits);
        const at = at_origin + rel;
        if (at > last) break;
        if (confirmFast(self, haystack, at, fold)) {
            if (watch_nul) {
                const check_start = at_origin + cover_index;
                const check_end = at + self.pattern.len;
                const cover: @Vector(width, u8) = haystack[check_start..][0..width].*;
                const zmask: MaskInt = @bitCast(cover == @as(@Vector(width, u8), @splat(0)));
                if (zmask != 0) {
                    @branchHint(.cold);
                    const zpos = check_start + @as(usize, @ctz(zmask));
                    if (zpos < check_end) {
                        nul_out.* = zpos;
                        return .nul;
                    }
                }
                if (self.pattern_has_nul and check_end > check_start + width) {
                    @branchHint(.cold);
                    if (noteNul(haystack[check_start + width .. check_end], check_start + width, nul_out)) {
                        return .nul;
                    }
                }
            }
            return .{ .match = at };
        }
    }
    if (watch_nul) {
        const check_start = at_origin + cover_index;
        const cover: @Vector(width, u8) = haystack[check_start..][0..width].*;
        const zmask: MaskInt = @bitCast(cover == @as(@Vector(width, u8), @splat(0)));
        if (zmask != 0) {
            @branchHint(.cold);
            nul_out.* = check_start + @as(usize, @ctz(zmask));
            return .nul;
        }
    }
    return .none;
}

inline fn confirmFastFold(self: *const PackedPair, haystack: []const u8, origin: usize) bool {
    const pat = self.pattern;
    const m = pat.len;
    const win = haystack[origin..][0..m];
    if (m <= owns_search_max_len) {
        const lower = &self.pat_lower;
        const mask = &self.pat_mask;
        if (m >= 16) {
            const V16 = @Vector(16, u8);
            const w0: V16 = win[0..16].*;
            const m0: V16 = mask[0..16].*;
            const l0: V16 = lower[0..16].*;
            const w1: V16 = win[m - 16 ..][0..16].*;
            const m1: V16 = mask[m - 16 ..][0..16].*;
            const l1: V16 = lower[m - 16 ..][0..16].*;
            return @reduce(.Or, ((w0 | m0) ^ l0) | ((w1 | m1) ^ l1)) == 0;
        }
        if (m >= 8) {
            const w0: u64 = @bitCast(win[0..8].*);
            const m0: u64 = @bitCast(mask[0..8].*);
            const l0: u64 = @bitCast(lower[0..8].*);
            const w1: u64 = @bitCast(win[m - 8 ..][0..8].*);
            const m1: u64 = @bitCast(mask[m - 8 ..][0..8].*);
            const l1: u64 = @bitCast(lower[m - 8 ..][0..8].*);
            return (((w0 | m0) ^ l0) | ((w1 | m1) ^ l1)) == 0;
        }
        if (m >= 4) {
            const w0: u32 = @bitCast(win[0..4].*);
            const m0: u32 = @bitCast(mask[0..4].*);
            const l0: u32 = @bitCast(lower[0..4].*);
            const w1: u32 = @bitCast(win[m - 4 ..][0..4].*);
            const m1: u32 = @bitCast(mask[m - 4 ..][0..4].*);
            const l1: u32 = @bitCast(lower[m - 4 ..][0..4].*);
            return (((w0 | m0) ^ l0) | ((w1 | m1) ^ l1)) == 0;
        }
        if (m >= 2) {
            const w0: u16 = @bitCast(win[0..2].*);
            const m0: u16 = @bitCast(mask[0..2].*);
            const l0: u16 = @bitCast(lower[0..2].*);
            const w1: u16 = @bitCast(win[m - 2 ..][0..2].*);
            const m1: u16 = @bitCast(mask[m - 2 ..][0..2].*);
            const l1: u16 = @bitCast(lower[m - 2 ..][0..2].*);
            return (((w0 | m0) ^ l0) | ((w1 | m1) ^ l1)) == 0;
        }
        return m == 0 or (win[0] | mask[0]) == lower[0];
    }
    return std.ascii.eqlIgnoreCase(pat, win);
}

inline fn confirmFast(self: *const PackedPair, haystack: []const u8, origin: usize, comptime fold: bool) bool {
    if (fold) return confirmFastFold(self, haystack, origin);
    const pat = self.pattern;
    const m = pat.len;
    const win = haystack[origin..][0..m];
    if (m <= owns_search_max_len) {
        if (m >= 16) {
            const V16 = @Vector(16, u8);
            const a0: V16 = pat[0..16].*;
            const b0: V16 = win[0..16].*;
            const a1: V16 = pat[m - 16 ..][0..16].*;
            const b1: V16 = win[m - 16 ..][0..16].*;
            return @reduce(.Or, (a0 ^ b0) | (a1 ^ b1)) == 0;
        }
        if (m >= 8) {
            const a0: u64 = @bitCast(pat[0..8].*);
            const b0: u64 = @bitCast(win[0..8].*);
            const a1: u64 = @bitCast(pat[m - 8 ..][0..8].*);
            const b1: u64 = @bitCast(win[m - 8 ..][0..8].*);
            return ((a0 ^ b0) | (a1 ^ b1)) == 0;
        }
        if (m >= 4) {
            const a0: u32 = @bitCast(pat[0..4].*);
            const b0: u32 = @bitCast(win[0..4].*);
            const a1: u32 = @bitCast(pat[m - 4 ..][0..4].*);
            const b1: u32 = @bitCast(win[m - 4 ..][0..4].*);
            return ((a0 ^ b0) | (a1 ^ b1)) == 0;
        }
        if (m >= 2) {
            const a0: u16 = @bitCast(pat[0..2].*);
            const b0: u16 = @bitCast(win[0..2].*);
            const a1: u16 = @bitCast(pat[m - 2 ..][0..2].*);
            const b1: u16 = @bitCast(win[m - 2 ..][0..2].*);
            return ((a0 ^ b0) | (a1 ^ b1)) == 0;
        }
        return m == 0 or pat[0] == win[0];
    }
    return std.mem.eql(u8, pat, win);
}

inline fn byteMaskSpec(comptime width: comptime_int, block: @Vector(width, u8), match_byte: u8, comptime use_fold: bool) @Vector(width, bool) {
    if (!use_fold) return block == @as(@Vector(width, u8), @splat(match_byte));
    return (block | @as(@Vector(width, u8), @splat(0x20))) == @as(@Vector(width, u8), @splat(match_byte));
}

inline fn byteMask(comptime width: comptime_int, block: @Vector(width, u8), byte: u8, comptime fold: bool) @Vector(width, bool) {
    if (!fold) return block == @as(@Vector(width, u8), @splat(byte));
    const forms = ascii.caseVariants(byte);
    if (forms[0] == forms[1]) return block == @as(@Vector(width, u8), @splat(forms[0]));
    // Uppercase and lowercase ASCII letters differ only by bit 0x20; setting that bit matches the lowercase form without false positives and saves a comparison and OR.
    return (block | @as(@Vector(width, u8), @splat(0x20))) == @as(@Vector(width, u8), @splat(forms[0]));
}

/// Hit mask for both anchor bytes in this window. When `watch_nul` is enabled, ORs in the NUL mask from the covering vector.
/// The covering vector is the anchor at the smaller offset, which is already in a register and requires no extra load.
inline fn hotMask(
    self: *const PackedPair,
    comptime width: comptime_int,
    haystack: []const u8,
    origin: usize,
    comptime a_fold: bool,
    comptime o_fold: bool,
    comptime watch_nul: bool,
) @Vector(width, bool) {
    const left: @Vector(width, u8) = haystack[origin + self.anchor_index ..][0..width].*;
    const right: @Vector(width, u8) = haystack[origin + self.other_index ..][0..width].*;
    const hits = byteMaskSpec(width, left, self.anchor_match, a_fold) & byteMaskSpec(width, right, self.other_match, o_fold);
    if (!watch_nul) return hits;
    const cover = if (self.anchor_index <= self.other_index) left else right;
    return hits | (cover == @as(@Vector(width, u8), @splat(0)));
}

fn noteNul(haystack: []const u8, base: usize, nul_out: *?usize) bool {
    const rel = memchr.find(memchr.native_width, haystack, 0, 0) orelse return false;
    nul_out.* = base + rel;
    return true;
}

/// Little-endian out-of-line verification path consuming the already-computed `MaskInt` bitmask
/// instead of reloading `left`/`right` (and avoiding `b3`/`b4` loads for short patterns).
fn takeHitMask(
    self: *const PackedPair,
    comptime width: comptime_int,
    haystack: []const u8,
    origin: usize,
    last: usize,
    raw_mask: @Int(.unsigned, width),
    previous: *usize,
    comptime fold: bool,
    comptime watched: bool,
    comptime watch_nul: bool,
    guard: *Guard,
    nul_out: *?usize,
) ?usize {
    const MaskInt = @Int(.unsigned, width);
    const cover_index = @min(self.anchor_index, self.other_index);
    var mask: MaskInt = raw_mask;
    if (watch_nul and watched) {
        // When both guard accounting and NUL watching are active, separate true pair hits from NUL bits
        // so NUL-only positions are never counted as prefilter false positives.
        const left: @Vector(width, u8) = haystack[origin + self.anchor_index ..][0..width].*;
        const right: @Vector(width, u8) = haystack[origin + self.other_index ..][0..width].*;
        var hits = byteMask(width, left, self.anchor, fold) & byteMask(width, right, self.other, fold);
        if (self.pattern.len >= 4) {
            const b3: @Vector(width, u8) = haystack[origin + self.third_index ..][0..width].*;
            const b4: @Vector(width, u8) = haystack[origin + self.fourth_index ..][0..width].*;
            hits = hits & byteMask(width, b3, self.third, fold) & byteMask(width, b4, self.fourth, fold);
        }
        mask = @bitCast(hits);
    } else if (!watch_nul and (watched or self.pattern.len > owns_search_max_len) and self.pattern.len >= 4) {
        // Long patterns refine the precomputed 2-byte mask with third & fourth rare bytes without reloading anchor/other.
        const b3: @Vector(width, u8) = haystack[origin + self.third_index ..][0..width].*;
        const b4: @Vector(width, u8) = haystack[origin + self.fourth_index ..][0..width].*;
        const extra: MaskInt = @bitCast(byteMask(width, b3, self.third, fold) & byteMask(width, b4, self.fourth, fold));
        mask &= extra;
    }

    while (mask != 0) : (mask &= mask - 1) {
        const rel: usize = @ctz(mask);
        const at = origin + rel;
        if (at > last) break;
        if (confirmFast(self, haystack, at, fold)) {
            if (watch_nul) {
                const check_start = @min(haystack.len, origin + cover_index);
                const check_end = @min(haystack.len, @max(check_start, at + self.pattern.len));
                if (noteNul(haystack[check_start..check_end], check_start, nul_out)) return null;
            }
            return rel;
        }
        if (!watched) continue;
        guard.noteMiss(at, previous.*);
        previous.* = at + 1;
        if (guard.gave_up) {
            if (watch_nul) {
                const block: @Vector(width, u8) = haystack[origin + cover_index ..][0..width].*;
                const zeros = block == @as(@Vector(width, u8), @splat(0));
                const zmask: MaskInt = @bitCast(zeros);
                if (zmask != 0) {
                    nul_out.* = origin + cover_index + @as(usize, @ctz(zmask));
                }
            }
            return null;
        }
    }

    if (watch_nul) {
        const block: @Vector(width, u8) = haystack[origin + cover_index ..][0..width].*;
        const zeros = block == @as(@Vector(width, u8), @splat(0));
        const zmask: MaskInt = @bitCast(zeros);
        if (zmask != 0) {
            nul_out.* = origin + cover_index + @as(usize, @ctz(zmask));
            return null;
        }
    }
    return null;
}

/// Returns the match start relative to `origin`. Outlined fallback for big-endian targets.
fn takeHit(
    self: *const PackedPair,
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
    const cover_index = @min(self.anchor_index, self.other_index);
    const left: @Vector(width, u8) = haystack[origin + self.anchor_index ..][0..width].*;
    const right: @Vector(width, u8) = haystack[origin + self.other_index ..][0..width].*;
    var hits = byteMask(width, left, self.anchor, fold) & byteMask(width, right, self.other, fold);
    if (self.pattern.len >= 4) {
        const b3: @Vector(width, u8) = haystack[origin + self.third_index ..][0..width].*;
        const b4: @Vector(width, u8) = haystack[origin + self.fourth_index ..][0..width].*;
        hits = hits & byteMask(width, b3, self.third, fold) & byteMask(width, b4, self.fourth, fold);
    }

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
        if (confirmFast(self, haystack, at, fold)) {
            if (watch_nul) {
                const check_start = @min(haystack.len, origin + cover_index);
                const check_end = @min(haystack.len, @max(check_start, at + self.pattern.len));
                if (noteNul(haystack[check_start..check_end], check_start, nul_out)) return null;
            }
            return @as(usize, rel);
        }
        if (!watched) continue;
        guard.noteMiss(at, previous.*);
        previous.* = at + 1;
        if (guard.gave_up) {
            if (watch_nul) {
                const block: @Vector(width, u8) = haystack[origin + cover_index ..][0..width].*;
                const zeros = block == @as(@Vector(width, u8), @splat(0));
                if (@reduce(.Or, zeros)) {
                    const zrel = std.simd.firstTrue(zeros).?;
                    nul_out.* = origin + cover_index + @as(usize, zrel);
                }
            }
            return null;
        }
    }

    if (watch_nul) {
        const block: @Vector(width, u8) = haystack[origin + cover_index ..][0..width].*;
        const zeros = block == @as(@Vector(width, u8), @splat(0));
        if (@reduce(.Or, zeros)) {
            const zrel = std.simd.firstTrue(zeros).?;
            nul_out.* = origin + cover_index + @as(usize, zrel);
            return null;
        }
    }
    return null;
}

inline fn scalarFrom(
    self: *const PackedPair,
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
        if (confirmFast(self, haystack, i, fold)) return i;
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

test "selects the two rarest bytes by rank" {
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

test "detects NUL during scan, including prefix before minimum anchor offset and NUL after match in same block" {
    const mid = PackedPair.init("QX", &frequency.default_rank, false);
    var buf: [200]u8 = undefined;
    @memset(&buf, 'a');
    buf[80] = 0;
    @memcpy(buf[120..][0..2], "QX");
    inline for (.{ 16, 32, 64 }) |w| {
        var nul: ?usize = null;
        try std.testing.expect(mid.findWatchingNul(w, &buf, 0, null, &nul) == null);
        try std.testing.expectEqual(@as(?usize, 80), nul);
    }

    @memset(&buf, 'a');
    @memcpy(buf[30..][0..2], "QX");
    buf[150] = 0;
    inline for (.{ 16, 32, 64 }) |w| {
        var nul: ?usize = null;
        try std.testing.expectEqual(@as(?usize, 30), mid.findWatchingNul(w, &buf, 0, null, &nul));
        try std.testing.expect(nul == null);
    }

    // NUL immediately after match in the same SIMD block must still return the match!
    @memset(&buf, 'a');
    @memcpy(buf[2..][0..2], "QX");
    buf[5] = 0;
    inline for (.{ 16, 32, 64 }) |w| {
        var nul: ?usize = null;
        try std.testing.expectEqual(@as(?usize, 2), mid.findWatchingNul(w, &buf, 0, null, &nul));
        try std.testing.expect(nul == null);
    }

    const shifted = PackedPair.init("aQX", &frequency.default_rank, false);
    try std.testing.expect(shifted.anchor_index != 0 and shifted.other_index != 0);
    @memset(&buf, 'b');
    buf[0] = 0;
    @memcpy(buf[40..][0..3], "aQX");
    inline for (.{ 16, 32, 64 }) |w| {
        var nul: ?usize = null;
        try std.testing.expect(shifted.findWatchingNul(w, &buf, 0, null, &nul) == null);
        try std.testing.expectEqual(@as(?usize, 0), nul);
    }
}

test "verifies candidates and continues past false positives" {
    const pair = PackedPair.init("qx", &frequency.default_rank, false);
    inline for (.{ 16, 32, 64 }) |w| {
        try std.testing.expectEqual(@as(?usize, 3), findAll(pair, w, "qqqqxqx", 0));
        try std.testing.expectEqual(@as(?usize, null), findAll(pair, w, "qqqqqq", 0));
        try std.testing.expectEqual(@as(?usize, null), findAll(pair, w, "qx", 1));
    }
}

test "case-insensitive matching" {
    const pair = PackedPair.init("Ab", &frequency.default_rank, true);
    inline for (.{ 16, 32, 64 }) |w| {
        try std.testing.expectEqual(@as(?usize, 1), findAll(pair, w, "xabXAB", 0));
        try std.testing.expectEqual(@as(?usize, 4), findAll(pair, w, "xabXAB", 2));
        try std.testing.expectEqual(@as(?usize, null), findAll(pair, w, "axb", 0));
    }
}

const frequency = @import("frequency.zig");

test "random differential against naive search" {
    var prng = std.Random.DefaultPrng.init(0x9A11);
    const random = prng.random();
    var hay: [200]u8 = undefined;
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
            inline for (.{ 16, 32, 64 }) |w| {
                try std.testing.expectEqual(
                    scalarFind(hay[0..hlen], pat[0..plen], start, fold),
                    findAll(pair, w, hay[0..hlen], start),
                );
            }
        }
    }
}

test "confirmFastFold and watch_nul across ASCII letters, non-letters, lengths, boundaries, and embedded NULs" {
    @setEvalBranchQuota(20_000);
    const rank = frequency.default_rank;

    // Non-letters must NEVER fold via bit 0x20: '['(0x5B) != '{'(0x7B), '0'(0x30) != 'p'(0x70),
    // '_'(0x5F) != 0x7F, '@'(0x40) != '`'(0x60).
    const bracket_pat = "[ERROR_09]";
    const bp = PackedPair.init(bracket_pat, &rank, true);
    var hay: [220]u8 = @splat('.');
    // Decoys with 0x20-flipped non-letters must NOT match
    @memcpy(hay[10..20], "{ERROR_09]");
    @memcpy(hay[35..45], "[ERROR\x7f09]");
    @memcpy(hay[60..70], "[ERROR_p9]");
    @memcpy(hay[95..105], "[ERROR_09}");
    // Real mixed-case match inside 4-vector unrolled loop
    @memcpy(hay[140..150], "[eRrOr_09]");
    inline for (.{ 16, 32, 64 }) |w| {
        try std.testing.expectEqual(@as(?usize, 140), bp.find(w, &hay, 0, null));
        var nul: ?usize = null;
        try std.testing.expectEqual(@as(?usize, 140), bp.findWatchingNul(w, &hay, 0, null, &nul));
        try std.testing.expect(nul == null);
    }

    // All length classes covering u16 (2,3), u32 (4..7), u64 (8..15), V16 (16..32), and >32 fallback
    const pats = [_][]const u8{
        "[A",
        "[_0",
        "[Er]",
        "[ERROR]",
        "[eRrOr_0]",
        "zQ_0123456789Ab",
        "[AbCdEfGhIjKlMnOp]",
        "[0123456789_AbCdEfGhIjKlMnOpQrS]",
        "[0123456789_AbCdEfGhIjKlMnOpQrSt]",
    };
    const offsets = [_]usize{ 0, 1, 15, 16, 31, 32, 63, 64, 130, 170 };
    for (pats) |pat| {
        const pair = PackedPair.init(pat, &rank, true);
        var flipped: [40]u8 = undefined;
        for (pat, 0..) |c, idx| {
            flipped[idx] = if (std.ascii.isLower(c)) std.ascii.toUpper(c) else if (std.ascii.isUpper(c)) std.ascii.toLower(c) else c;
        }
        for (offsets) |off| {
            var buf: [220]u8 = @splat('~');
            @memcpy(buf[off .. off + pat.len], flipped[0..pat.len]);
            inline for (.{ 16, 32, 64 }) |w| {
                try std.testing.expectEqual(@as(?usize, off), pair.find(w, &buf, 0, null));
                var nul: ?usize = null;
                try std.testing.expectEqual(@as(?usize, off), pair.findWatchingNul(w, &buf, 0, null, &nul));
                try std.testing.expect(nul == null);
            }
        }
    }

    // Embedded NULs with fold=true and watch_nul=true:
    // 1) NUL before match in same 32B vector
    const p_err = PackedPair.init("[ERROR]", &rank, true);
    var nbuf: [200]u8 = @splat(' ');
    nbuf[3] = 0;
    @memcpy(nbuf[10..17], "[error]");
    inline for (.{ 16, 32, 64 }) |w| {
        var nul: ?usize = null;
        try std.testing.expect(p_err.findWatchingNul(w, &nbuf, 0, null, &nul) == null);
        try std.testing.expectEqual(@as(?usize, 3), nul);
    }

    // 2) NUL immediately after match in same 32B vector -> match MUST succeed!
    @memset(&nbuf, ' ');
    @memcpy(nbuf[10..17], "[ErRoR]");
    nbuf[17] = 0;
    inline for (.{ 16, 32, 64 }) |w| {
        var nul: ?usize = null;
        try std.testing.expectEqual(@as(?usize, 10), p_err.findWatchingNul(w, &nbuf, 0, null, &nul));
        try std.testing.expect(nul == null);
    }

    // 3) NUL embedded inside pattern itself (including overhanging past a 32B cover boundary)
    const p_nul = PackedPair.init("qX\x00zY", &rank, true);
    @memset(&nbuf, 'a');
    @memcpy(nbuf[30..35], "Qx\x00Zy");
    inline for (.{ 16, 32, 64 }) |w| {
        var nul: ?usize = null;
        try std.testing.expect(p_nul.findWatchingNul(w, &nbuf, 0, null, &nul) == null);
        try std.testing.expectEqual(@as(?usize, 32), nul);
    }

    // 4) Non-zero cover_index with NUL in prefix and NUL in same block before match
    const p_shift = PackedPair.init("ee[Z]", &rank, true);
    @memset(&nbuf, ' ');
    nbuf[0] = 0;
    @memcpy(nbuf[40..45], "EE[z]");
    inline for (.{ 16, 32, 64 }) |w| {
        var nul: ?usize = null;
        try std.testing.expect(p_shift.findWatchingNul(w, &nbuf, 0, null, &nul) == null);
        try std.testing.expectEqual(@as(?usize, 0), nul);
    }
    nbuf[0] = ' ';
    nbuf[39] = 0;
    inline for (.{ 16, 32, 64 }) |w| {
        var nul: ?usize = null;
        try std.testing.expect(p_shift.findWatchingNul(w, &nbuf, 0, null, &nul) == null);
        try std.testing.expectEqual(@as(?usize, 39), nul);
    }
}

test "packed pair fuzz differential" {
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
    inline for (.{ 16, 32, 64 }) |w| {
        try std.testing.expectEqual(
            scalarFind(hay_buf[0..hlen], pat_buf[0..plen], start, fold),
            findAll(pair, w, hay_buf[0..hlen], start),
        );
    }
}
