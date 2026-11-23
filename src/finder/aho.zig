//! Hybrid Dense-Prefix + Compact Contiguous-NFA Aho-Corasick automaton with byte equivalence classes.
//!
//! Memory is allocated only during automaton construction; searches do not allocate.
//! Construction builds a compact linked-edge trie (20 bytes/node, zero per-node heap allocations),
//! computes failure links in BFS order, derives exact O(256) byte equivalence classes (every byte
//! appearing in a pattern gets a distinct class; all absent bytes share dead class 0), and shares
//! output lists via suffix links in O(patterns) space.
//!
//! States are ordered by BFS depth so depth 0 (root), all depth-1 states, and hot depth-2 states
//! form a cache-resident pre-multiplied dense DFA table (~16–256 KiB, with `MATCH_BIT` and
//! `SPARSE_BIT` packed into each `u32` transition to eliminate multiplies and per-byte `out_head`
//! loads). Deeper states (for 500–2,000+ pattern sets) use a compact contiguous sorted-edge NFA
//! whose failure links drop back into the dense prefix in O(1).
//! When there are at most 16 distinct anchor bytes, search first scans for those bytes with SIMD
//! vectors and verifies only the patterns attached to them.
//! Implemented directly from the Aho and Corasick failure function without copying third-party source.

const std = @import("std");
const builtin = @import("builtin");
const ascii = @import("ascii.zig");
const build_options = @import("build_options");
const byteset = @import("byteset.zig");
const cpuid = @import("../io/cpuid.zig");
const frequency = @import("frequency.zig");
const matcher = @import("../matcher.zig");
const memchr = @import("memchr.zig");

const static_avx2_nibble = builtin.cpu.arch == .x86_64 and build_options.teddy == .avx2 and
    std.Target.x86.featureSetHas(builtin.cpu.features, .avx2);
const static_nibble_isa = static_avx2_nibble or switch (builtin.cpu.arch) {
    .aarch64 => std.Target.aarch64.featureSetHas(builtin.cpu.features, .neon),
    .x86_64 => std.Target.x86.featureSetHas(builtin.cpu.features, .ssse3),
    else => false,
};
const runtime_nibble_isa = !static_nibble_isa and builtin.cpu.arch == .x86_64 and build_options.teddy == .runtime;
const has_nibble_isa = static_nibble_isa or runtime_nibble_isa;
const nibble_isa = if (static_avx2_nibble)
    @import("teddy_avx2.zig")
else if (has_nibble_isa) switch (builtin.cpu.arch) {
    .aarch64 => @import("teddy_neon.zig"),
    .x86_64 => @import("teddy_ssse3.zig"),
    else => struct {},
} else struct {};
const nibble_lanes: usize = if (has_nibble_isa) nibble_isa.lanes else 16;
const NibbleVec = @Vector(nibble_lanes, u8);

const sentinel: u32 = 0;

/// Bit 31 marks a state with at least one matching pattern output.
const match_bit: u32 = 0x8000_0000;
/// Bit 30 marks a sparse (contiguous NFA) state; clear means pre-multiplied dense row offset.
const sparse_bit: u32 = 0x4000_0000;
/// Lower 30 bits hold either `dense_state_idx * nclasses` (dense) or `state_idx - dense_count` (sparse).
const payload_mask: u32 = 0x3FFF_FFFF;

/// Dense table cell budget (~263 KiB max): fits cleanly in L2 cache while guaranteeing depth 0 and
/// all depth-1 states remain 100% dense even for a full 256-byte alphabet.
const dense_budget_cells: usize = 65_792;

/// Chunk size for cache-hot periodic NUL detection in `findWatchingNul` when not using SIMD skip.
const nul_chunk_bytes: usize = 32 * 1024;

const Out = struct {
    len: u32,
    id: u32,
    next: u32,
};

const SparseState = struct {
    /// Pre-encoded failure state (`dense_row_off` if `< sparse_bit`, else `sparse_bit | sparse_idx`).
    /// `match_bit` is never set here.
    fail: u32,
    edge_off: u32,
    edge_len: u16,
    _pad: u16 = 0,
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
    dense_count: u32,
    class_of: [256]u8,
    nclasses: u16,
    inv_nclasses: u64,
    sparse_states: []SparseState,
    sparse_edge_bytes: []u8,
    sparse_edge_next: []u32,
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
    use_nibble_skip: bool = false,
    start_lo: [16]u8,
    start_hi: [16]u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Ac) void {
        if (self.dense.len != 0) self.allocator.free(self.dense);
        if (self.sparse_states.len != 0) self.allocator.free(self.sparse_states);
        if (self.sparse_edge_bytes.len != 0) self.allocator.free(self.sparse_edge_bytes);
        if (self.sparse_edge_next.len != 0) self.allocator.free(self.sparse_edge_next);
        if (self.out_head.len != 0) self.allocator.free(self.out_head);
        if (self.outs.len != 0) self.allocator.free(self.outs);
        if (self.use_anchor) self.allocator.free(self.anchored);
        self.* = undefined;
    }

    pub fn find(self: *const Ac, haystack: []const u8, start: usize, mode: matcher.MatchMode) ?matcher.Match {
        var unused: ?usize = null;
        return switch (mode) {
            .earliest => self.findImpl(haystack, start, .earliest, false, &unused),
            .leftmost_first => self.findImpl(haystack, start, .leftmost_first, false, &unused),
        };
    }

    pub fn findWatchingNul(
        self: *const Ac,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        nul_out: *?usize,
    ) ?matcher.Match {
        return switch (mode) {
            .earliest => self.findImpl(haystack, start, .earliest, true, nul_out),
            .leftmost_first => self.findImpl(haystack, start, .leftmost_first, true, nul_out),
        };
    }

    noinline fn findImpl(
        self: *const Ac,
        haystack: []const u8,
        start: usize,
        comptime mode: matcher.MatchMode,
        comptime watch_nul: bool,
        nul_out: *?usize,
    ) ?matcher.Match {
        if (start > haystack.len) return null;
        if (self.use_anchor) return self.findAnchored(haystack, start, mode, watch_nul, nul_out);
        var best: ?Cand = null;
        if (self.empty_id) |id| {
            consider(&best, start, start, id, mode);
            if (comptime mode == .earliest) return toMatch(best);
            if (id == 0) return toMatch(best);
        }
        if (self.max_len == 0 or start == haystack.len) {
            if (watch_nul and best == null and start < haystack.len) {
                if (memchr.find(memchr.native_width, haystack, start, 0)) |nul_at| nul_out.* = nul_at;
            }
            return toMatch(best);
        }

        const dense = self.dense.ptr;
        const class_of = &self.class_of;

        const LoopState = struct {
            state: u32 = 0, // Invariant: (state & match_bit) == 0 at outer/loop boundaries
            i: usize,
            scan_end: usize,
            step_limit: usize = 0,
            nul_checked: usize,
            skip_cooldown: usize,
            skip_backoff: usize = 64,
        };
        var ls = LoopState{
            .i = start,
            .scan_end = haystack.len,
            .nul_checked = start,
            .skip_cooldown = start,
        };
        if (comptime mode == .leftmost_first) {
            if (best) |chosen| {
                ls.scan_end = @min(haystack.len, chosen.start +| @as(usize, self.max_len));
            }
        }

        outer: while (ls.i < ls.scan_end) {
            if (comptime has_nibble_isa) {
                const nibble_stride = nibble_lanes * 4;
                if (self.use_nibble_skip and ls.state == 0 and best == null and
                    ls.i >= ls.skip_cooldown and ls.i + nibble_stride <= ls.scan_end)
                {
                    // Flush any unchecked scalar gap [ls.nul_checked .. ls.i) before nibbleSkip
                    // advances ls.nul_checked past ls.i. Safe because state == 0 and best == null
                    // guarantees any future match starts >= ls.i.
                    if (watch_nul and ls.nul_checked < ls.i) {
                        if (memchr.find(memchr.native_width, haystack[0..ls.i], ls.nul_checked, 0)) |nul_at| {
                            nul_out.* = nul_at;
                            return null;
                        }
                        ls.nul_checked = ls.i;
                    }
                    const lo_v: NibbleVec = std.simd.repeat(nibble_lanes, @as(@Vector(16, u8), self.start_lo));
                    const hi_v: NibbleVec = std.simd.repeat(nibble_lanes, @as(@Vector(16, u8), self.start_hi));
                    const before = ls.i;
                    const skip_res = nibbleSkip(
                        lo_v,
                        hi_v,
                        haystack,
                        ls.i,
                        watch_nul,
                        &ls.nul_checked,
                        nul_out,
                    );
                    if (skip_res.nul_hit) return null;
                    ls.i = skip_res.pos;
                    if (ls.i >= ls.scan_end) break :outer;
                    if (ls.i > before) {
                        ls.skip_backoff = 64;
                        ls.skip_cooldown = ls.i + 16;
                    } else {
                        ls.skip_cooldown = ls.i + ls.skip_backoff;
                        if (ls.skip_backoff < 4096) ls.skip_backoff *= 2;
                    }
                }
            }

            ls.step_limit = ls.scan_end;
            if (comptime has_nibble_isa) {
                if (self.use_nibble_skip and best == null and ls.skip_cooldown > ls.i and ls.skip_cooldown < ls.step_limit) {
                    ls.step_limit = ls.skip_cooldown;
                }
            }
            if (watch_nul and best == null) {
                const nul_limit = ls.i +| nul_chunk_bytes;
                if (nul_limit < ls.step_limit) ls.step_limit = nul_limit;
            }

            var i = ls.i;
            var state = ls.state;
            while (i < ls.step_limit) {
                if (state >= sparse_bit) {
                    const next = self.stepSparse(state & payload_mask, haystack[i]);
                    i += 1;
                    if ((next & match_bit) != 0) {
                        @branchHint(.unlikely);
                        self.recordMatches(next, i, mode, &best, &ls.scan_end);
                        if (comptime mode == .earliest) {
                            ls.i = i;
                            ls.state = next & ~match_bit;
                            break :outer;
                        }
                        if (ls.scan_end < ls.step_limit) ls.step_limit = ls.scan_end;
                    }
                    state = next & ~match_bit;
                    continue;
                }

                // Hot 4x unrolled dense prefix loop: zero multiplies, zero out_head loads.
                const step_limit = ls.step_limit;
                while (i + 4 <= step_limit) {
                    const s0 = dense[state + class_of[haystack[i]]];
                    if (s0 >= sparse_bit) {
                        state = s0;
                        break;
                    }
                    const s1 = dense[s0 + class_of[haystack[i + 1]]];
                    if (s1 >= sparse_bit) {
                        state = s1;
                        i += 1;
                        break;
                    }
                    const s2 = dense[s1 + class_of[haystack[i + 2]]];
                    if (s2 >= sparse_bit) {
                        state = s2;
                        i += 2;
                        break;
                    }
                    const s3 = dense[s2 + class_of[haystack[i + 3]]];
                    if (s3 >= sparse_bit) {
                        state = s3;
                        i += 3;
                        break;
                    }
                    state = s3;
                    i += 4;
                }

                if (state < sparse_bit) {
                    while (i < step_limit) {
                        const next = dense[state + class_of[haystack[i]]];
                        if (next >= sparse_bit) {
                            state = next;
                            break;
                        }
                        state = next;
                        i += 1;
                    }
                }

                if (state >= sparse_bit) {
                    i += 1;
                    if ((state & match_bit) != 0) {
                        @branchHint(.unlikely);
                        self.recordMatches(state, i, mode, &best, &ls.scan_end);
                        if (comptime mode == .earliest) {
                            ls.i = i;
                            ls.state = state & ~match_bit;
                            break :outer;
                        }
                        if (ls.scan_end < ls.step_limit) ls.step_limit = ls.scan_end;
                        state &= ~match_bit;
                    }
                }
            }
            ls.i = i;
            ls.state = state;

            if (watch_nul and best == null) {
                const safe_end = if (ls.state == 0) ls.i else ls.i -| @as(usize, self.max_len);
                if (safe_end > ls.nul_checked and (safe_end - ls.nul_checked >= nul_chunk_bytes or ls.i >= ls.scan_end)) {
                    if (memchr.find(memchr.native_width, haystack[0..safe_end], ls.nul_checked, 0)) |nul_at| {
                        nul_out.* = nul_at;
                        return null;
                    }
                    ls.nul_checked = safe_end;
                }
            }
        }

        const chosen = best orelse {
            if (watch_nul and ls.nul_checked < haystack.len) {
                if (memchr.find(memchr.native_width, haystack, ls.nul_checked, 0)) |nul_at| nul_out.* = nul_at;
            }
            return null;
        };
        if (watch_nul and ls.nul_checked < chosen.start) {
            if (memchr.find(memchr.native_width, haystack[0..chosen.start], ls.nul_checked, 0)) |nul_at| {
                nul_out.* = nul_at;
                return null;
            }
        }
        return .{ .start = chosen.start, .end = chosen.end, .pattern_id = chosen.id };
    }

    inline fn stepSparse(self: *const Ac, start_sparse_idx: u32, raw: u8) u32 {
        const b = if (self.ignore_case) ascii.fold(raw) else raw;
        var s_idx = start_sparse_idx;
        while (true) {
            const st = self.sparse_states[s_idx];
            const len = st.edge_len;
            if (len != 0) {
                const off = st.edge_off;
                if (len == 1) {
                    if (self.sparse_edge_bytes[off] == b) return self.sparse_edge_next[off];
                } else if (len <= 8) {
                    const bytes = self.sparse_edge_bytes[off..][0..len];
                    for (bytes, 0..) |eb, k| {
                        if (eb == b) return self.sparse_edge_next[off + k];
                    }
                } else {
                    const bytes = self.sparse_edge_bytes[off..][0..len];
                    var lo: usize = 0;
                    var hi: usize = len;
                    while (lo < hi) {
                        const mid = lo + (hi - lo) / 2;
                        const eb = bytes[mid];
                        if (eb == b) return self.sparse_edge_next[off + mid];
                        if (eb < b) lo = mid + 1 else hi = mid;
                    }
                }
            }
            const fail = st.fail;
            if (fail < sparse_bit) {
                return self.dense[fail + self.class_of[raw]];
            }
            s_idx = fail & payload_mask;
        }
    }

    inline fn recordMatches(
        self: *const Ac,
        encoded_state: u32,
        end: usize,
        comptime mode: matcher.MatchMode,
        best: *?Cand,
        scan_end: *usize,
    ) void {
        const payload = encoded_state & payload_mask;
        const state_idx: usize = if ((encoded_state & sparse_bit) != 0)
            @as(usize, self.dense_count) + payload
        else
            divNclasses(payload, self.inv_nclasses);
        var link = self.out_head[state_idx];
        while (link != sentinel) {
            const item = self.outs[link - 1];
            consider(best, end - item.len, end, item.id, mode);
            link = item.next;
        }
        if (comptime mode == .leftmost_first) {
            if (best.*) |chosen| {
                const limit = chosen.start +| @as(usize, self.max_len);
                if (limit < scan_end.*) scan_end.* = limit;
            }
        }
    }

    const NibbleSkipResult = struct {
        pos: usize,
        nul_hit: bool = false,
    };

    noinline fn nibbleSkip(
        lo_v: NibbleVec,
        hi_v: NibbleVec,
        haystack: []const u8,
        start_i: usize,
        comptime watch_nul: bool,
        nul_checked: *usize,
        nul_out: *?usize,
    ) NibbleSkipResult {
        const zero: NibbleVec = @splat(0);
        const stride = nibble_lanes * 4;
        var i = start_i;
        while (i + stride <= haystack.len) {
            var accs: [4]NibbleVec = undefined;
            var min_b: NibbleVec = @splat(1);
            inline for (0..4) |w| {
                const b: NibbleVec = haystack[i + w * nibble_lanes ..][0..nibble_lanes].*;
                const lo_idx = b & @as(NibbleVec, @splat(0x0f));
                const hi_idx = b >> @as(NibbleVec, @splat(@as(u8, 4)));
                accs[w] = nibble_isa.lookup(lo_v, lo_idx) & nibble_isa.lookup(hi_v, hi_idx);
                if (watch_nul) {
                    min_b = if (w == 0) b else @min(min_b, b);
                }
            }
            const combined = (accs[0] | accs[1]) | (accs[2] | accs[3]);
            const nul_mask: NibbleVec = if (watch_nul)
                @select(u8, min_b == zero, @as(NibbleVec, @splat(0xFF)), zero)
            else
                zero;
            const check_v = if (watch_nul) combined | nul_mask else combined;
            if (@reduce(.Or, check_v) == 0) {
                i += stride;
                if (watch_nul) nul_checked.* = i;
                continue;
            }
            if (watch_nul and @reduce(.Or, combined) == 0) {
                if (memchr.find(nibble_lanes, haystack[0 .. i + stride], nul_checked.*, 0)) |nul_at| {
                    nul_out.* = nul_at;
                    return .{ .pos = i, .nul_hit = true };
                }
            }
            inline for (0..4) |w| {
                if (@reduce(.Or, accs[w]) != 0) {
                    if (watch_nul and @reduce(.Or, nul_mask) != 0) {
                        if (memchr.find(nibble_lanes, haystack[0 .. i + w * nibble_lanes], nul_checked.*, 0)) |nul_at| {
                            nul_out.* = nul_at;
                            return .{ .pos = i, .nul_hit = true };
                        }
                    }
                    i += w * nibble_lanes;
                    if (watch_nul and i > nul_checked.*) nul_checked.* = i;
                    break;
                }
            }
            return .{ .pos = i };
        }
        return .{ .pos = i };
    }

    noinline fn findAnchored(
        self: *const Ac,
        haystack: []const u8,
        start: usize,
        mode: matcher.MatchMode,
        comptime watch_nul: bool,
        nul_out: *?usize,
    ) ?matcher.Match {
        var best: ?Cand = null;
        if (self.empty_id) |id| {
            consider(&best, start, start, id, mode);
            if (mode == .earliest or id == 0) return toMatch(best);
        }
        if (self.min_len == 0 or start == haystack.len) {
            if (watch_nul and best == null and start < haystack.len) {
                if (memchr.find(memchr.native_width, haystack, start, 0)) |nul_at| nul_out.* = nul_at;
            }
            return toMatch(best);
        }

        const restrict = best != null and mode == .leftmost_first;
        var pos = start;
        var nul_checked = start;
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
            const at = (if (watch_nul)
                self.members.findWatchingNul(haystack, pos, nul_out)
            else
                self.members.find(haystack, pos)) orelse break;
            if (watch_nul and at > nul_checked) nul_checked = at;
            if (mode == .leftmost_first) {
                if (best) |chosen| {
                    if (at > chosen.start + @as(usize, self.max_off)) break;
                }
            }
            self.noteAnchor(haystack, at, start, mode, &best, restrict);
            if (watch_nul and haystack[at] == 0) {
                if (best == null or at < best.?.start) {
                    nul_out.* = at;
                    return null;
                }
            }
            if (watch_nul and at + 1 > nul_checked) nul_checked = at + 1;
            pos = at + 1;
        }
        if (watch_nul) {
            if (nul_out.*) |nul_at| {
                if (best) |chosen| {
                    if (chosen.start <= nul_at) {
                        nul_out.* = null;
                        return .{ .start = chosen.start, .end = chosen.end, .pattern_id = chosen.id };
                    }
                }
                return null;
            }
        }
        const chosen = best orelse {
            if (watch_nul and nul_checked < haystack.len) {
                if (memchr.find(memchr.native_width, haystack, nul_checked, 0)) |nul_at| nul_out.* = nul_at;
            }
            return null;
        };
        if (watch_nul and nul_checked < chosen.start) {
            if (memchr.find(memchr.native_width, haystack[0..chosen.start], nul_checked, 0)) |nul_at| {
                nul_out.* = nul_at;
                return null;
            }
        }
        return .{ .start = chosen.start, .end = chosen.end, .pattern_id = chosen.id };
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

const BuildNode = struct {
    first_child: u32 = 0,
    next_sibling: u32 = 0,
    fail: u32 = 0,
    out_head: u32 = 0,
    child_count: u16 = 0,
    edge_byte: u8 = 0,
};

const BuildOut = struct {
    len: u32,
    id: u32,
    next: u32,
};

pub fn build(
    allocator: std.mem.Allocator,
    patterns: []const []const u8,
    ignore_case: bool,
) !Ac {
    var max_len: u32 = 0;
    var empty_id: ?u32 = null;
    var total_pat_bytes: usize = 0;
    var non_empty_count: usize = 0;
    for (patterns, 0..) |pat, id_usize| {
        if (pat.len > std.math.maxInt(u32)) return error.OutOfMemory;
        const id: u32 = @intCast(id_usize);
        if (pat.len == 0) {
            if (empty_id == null) empty_id = id;
            continue;
        }
        non_empty_count += 1;
        total_pat_bytes +|= pat.len;
        max_len = @max(max_len, @as(u32, @intCast(pat.len)));
    }

    // Fast path: if all non-empty patterns fit within 16 distinct rarest anchor bytes,
    // search uses SIMD anchor scanning directly and never touches the automaton tables.
    const anchor = try buildAnchor(allocator, patterns, ignore_case);
    if (anchor.use) {
        return .{
            .dense = &.{},
            .dense_count = 0,
            .class_of = @splat(0),
            .nclasses = 1,
            .inv_nclasses = @as(u64, 1) << 32,
            .sparse_states = &.{},
            .sparse_edge_bytes = &.{},
            .sparse_edge_next = &.{},
            .out_head = &.{},
            .outs = &.{},
            .max_len = max_len,
            .empty_id = empty_id,
            .ignore_case = ignore_case,
            .patterns = patterns,
            .anchored = anchor.items,
            .spans = anchor.spans,
            .members = anchor.members,
            .max_off = anchor.max_off,
            .min_len = anchor.min_len,
            .use_anchor = true,
            .use_nibble_skip = false,
            .start_lo = @splat(0),
            .start_hi = @splat(0),
            .allocator = allocator,
        };
    }

    // 1. Build compact linked-edge trie (20 bytes/node, zero per-node heap allocations).
    var nodes: std.ArrayList(BuildNode) = .empty;
    defer nodes.deinit(allocator);
    try nodes.ensureTotalCapacity(allocator, @min(total_pat_bytes +| 1, 65_536));
    try nodes.append(allocator, .{});

    var build_outs: std.ArrayList(BuildOut) = .empty;
    defer build_outs.deinit(allocator);
    try build_outs.ensureTotalCapacity(allocator, @min(non_empty_count, 65_536));

    var root_children: [256]u32 = @splat(0);
    var used_bytes: [256]bool = @splat(false);

    for (patterns, 0..) |pat, id_usize| {
        if (pat.len == 0) continue;
        const id: u32 = @intCast(id_usize);
        var state: u32 = 0;
        for (pat) |raw| {
            const byte = if (ignore_case) ascii.fold(raw) else raw;
            used_bytes[byte] = true;
            if (state == 0) {
                const child = root_children[byte];
                if (child == 0) {
                    if (nodes.items.len > payload_mask) return error.OutOfMemory;
                    const created: u32 = @intCast(nodes.items.len);
                    try nodes.append(allocator, .{ .edge_byte = byte });
                    root_children[byte] = created;
                    nodes.items[0].child_count += 1;
                    state = created;
                } else {
                    state = child;
                }
            } else {
                if (findChild(nodes.items, state, byte)) |child| {
                    state = child;
                } else {
                    if (nodes.items.len > payload_mask) return error.OutOfMemory;
                    const created: u32 = @intCast(nodes.items.len);
                    const prev_first = nodes.items[state].first_child;
                    try nodes.append(allocator, .{
                        .next_sibling = prev_first,
                        .edge_byte = byte,
                    });
                    nodes.items[state].first_child = created;
                    nodes.items[state].child_count += 1;
                    state = created;
                }
            }
        }
        const prev_out = nodes.items[state].out_head;
        try build_outs.append(allocator, .{
            .len = @intCast(pat.len),
            .id = id,
            .next = prev_out,
        });
        nodes.items[state].out_head = @intCast(build_outs.items.len);
    }

    const nstates: usize = nodes.items.len;

    // 2. BFS traversal: compute failure links in O(nstates) and establish BFS state numbering
    //    (depth 0, then all depth 1, then all depth 2, ...).
    const bfs_order = try allocator.alloc(u32, nstates);
    defer allocator.free(bfs_order);
    const old_to_new = try allocator.alloc(u32, nstates);
    defer allocator.free(old_to_new);

    bfs_order[0] = 0;
    old_to_new[0] = 0;
    var q_len: usize = 1;
    for (0..256) |b| {
        const cid = root_children[b];
        if (cid != 0) {
            nodes.items[cid].fail = 0;
            old_to_new[cid] = @intCast(q_len);
            bfs_order[q_len] = cid;
            q_len += 1;
        }
    }

    var q_at: usize = 1;
    while (q_at < q_len) : (q_at += 1) {
        const u = bfs_order[q_at];
        var v = nodes.items[u].first_child;
        while (v != 0) : (v = nodes.items[v].next_sibling) {
            const b = nodes.items[v].edge_byte;
            var f = nodes.items[u].fail;
            var dest: u32 = 0;
            while (true) {
                if (f == 0) {
                    dest = root_children[b];
                    break;
                }
                if (findChild(nodes.items, f, b)) |hit| {
                    dest = hit;
                    break;
                }
                f = nodes.items[f].fail;
            }
            nodes.items[v].fail = dest;
            old_to_new[v] = @intCast(q_len);
            bfs_order[q_len] = v;
            q_len += 1;
        }
    }
    std.debug.assert(q_len == nstates);

    // 3. O(256) exact byte equivalence classes: in an AC trie every active byte has a unique
    //    incoming edge label so no two active bytes can merge; all unused bytes share dead class 0.
    var used_count: usize = 0;
    for (used_bytes) |u_flag| {
        if (u_flag) used_count += 1;
    }
    var class_of: [256]u8 = @splat(0);
    var nclasses: u16 = 1;
    if (used_count == 256) {
        for (0..256) |b| class_of[b] = @intCast(b);
        nclasses = 256;
    } else {
        var next_cls: u8 = 1;
        for (0..256) |b| {
            if (used_bytes[b]) {
                class_of[b] = next_cls;
                next_cls +%= 1;
            }
        }
        nclasses = @intCast(used_count + 1);
    }
    if (ignore_case) {
        for ('A'..'Z' + 1) |b| class_of[b] = class_of[b + 32];
    }
    const inv_nclasses: u64 = ((@as(u64, 1) << 32) + @as(u64, nclasses) - 1) / @as(u64, nclasses);

    // 4. Shared suffix-linked output lists in BFS order: O(patterns) space, never quadratic.
    const out_head = try allocator.alloc(u32, nstates);
    errdefer allocator.free(out_head);
    const outs = if (build_outs.items.len != 0)
        try allocator.alloc(Out, build_outs.items.len)
    else
        @as([]Out, &.{});
    errdefer if (outs.len != 0) allocator.free(outs);

    out_head[0] = sentinel;
    var out_cursor: usize = 0;
    for (1..nstates) |new_s| {
        const old_s = bfs_order[new_s];
        const fail_new = old_to_new[nodes.items[old_s].fail];
        const inherited = out_head[fail_new];
        var b_link = nodes.items[old_s].out_head;
        if (b_link == sentinel) {
            out_head[new_s] = inherited;
        } else {
            out_head[new_s] = @intCast(out_cursor + 1);
            while (b_link != sentinel) {
                const bo = build_outs.items[b_link - 1];
                const next_b = bo.next;
                outs[out_cursor] = .{
                    .len = bo.len,
                    .id = bo.id,
                    .next = if (next_b != sentinel) @intCast(out_cursor + 2) else inherited,
                };
                out_cursor += 1;
                b_link = next_b;
            }
        }
    }
    std.debug.assert(out_cursor == build_outs.items.len);

    // 5. Build cache-resident dense prefix (BFS states 0..dense_count-1) + compact sparse NFA tail.
    const dense_count_usize: usize = @max(@as(usize, 1), @min(nstates, dense_budget_cells / @as(usize, nclasses)));
    const dense_count: u32 = @intCast(dense_count_usize);
    const dense_cells = dense_count_usize * @as(usize, nclasses);
    const dense = try allocator.alloc(u32, dense_cells);
    errdefer allocator.free(dense);

    // Root row (state 0)
    @memset(dense[0..nclasses], 0);
    for (0..256) |b| {
        const cid = root_children[b];
        if (cid != 0) {
            dense[class_of[b]] = encodeState(old_to_new[cid], dense_count, nclasses, out_head);
        }
    }

    // Dense rows 1..dense_count-1: in BFS order fail[s] < s < dense_count ALWAYS, so inheriting
    // failure transitions is a single row memcpy followed by direct trie child overwrites.
    for (1..dense_count_usize) |new_s| {
        const old_s = bfs_order[new_s];
        const fail_new: usize = old_to_new[nodes.items[old_s].fail];
        std.debug.assert(fail_new < new_s);
        const dst_off = new_s * @as(usize, nclasses);
        const src_off = fail_new * @as(usize, nclasses);
        @memcpy(dense[dst_off..][0..nclasses], dense[src_off..][0..nclasses]);
        var v = nodes.items[old_s].first_child;
        while (v != 0) : (v = nodes.items[v].next_sibling) {
            dense[dst_off + class_of[nodes.items[v].edge_byte]] =
                encodeState(old_to_new[v], dense_count, nclasses, out_head);
        }
    }

    // Compact sparse NFA states (dense_count..nstates-1)
    const sparse_count = nstates - dense_count_usize;
    var sparse_states: []SparseState = &.{};
    var sparse_edge_bytes: []u8 = &.{};
    var sparse_edge_next: []u32 = &.{};

    if (sparse_count != 0) {
        var total_sparse_edges: usize = 0;
        for (dense_count_usize..nstates) |new_s| {
            total_sparse_edges += nodes.items[bfs_order[new_s]].child_count;
        }
        sparse_states = try allocator.alloc(SparseState, sparse_count);
        errdefer allocator.free(sparse_states);
        if (total_sparse_edges != 0) {
            sparse_edge_bytes = try allocator.alloc(u8, total_sparse_edges);
            errdefer allocator.free(sparse_edge_bytes);
            sparse_edge_next = try allocator.alloc(u32, total_sparse_edges);
            errdefer allocator.free(sparse_edge_next);
        }

        var edge_cursor: usize = 0;
        var tmp_bytes: [256]u8 = undefined;
        var tmp_next: [256]u32 = undefined;

        for (0..sparse_count) |s_idx| {
            const new_s = dense_count_usize + s_idx;
            const old_s = bfs_order[new_s];
            const fail_new = old_to_new[nodes.items[old_s].fail];
            const fail_enc: u32 = if (fail_new < dense_count)
                fail_new * @as(u32, nclasses)
            else
                sparse_bit | (fail_new - dense_count);

            var cnt: usize = 0;
            var v = nodes.items[old_s].first_child;
            while (v != 0) : (v = nodes.items[v].next_sibling) {
                tmp_bytes[cnt] = nodes.items[v].edge_byte;
                tmp_next[cnt] = encodeState(old_to_new[v], dense_count, nclasses, out_head);
                cnt += 1;
            }
            // Insertion sort edges by byte ascending for binary search when cnt > 8.
            if (cnt > 1) {
                var a: usize = 1;
                while (a < cnt) : (a += 1) {
                    const kb = tmp_bytes[a];
                    const kn = tmp_next[a];
                    var j = a;
                    while (j > 0 and tmp_bytes[j - 1] > kb) : (j -= 1) {
                        tmp_bytes[j] = tmp_bytes[j - 1];
                        tmp_next[j] = tmp_next[j - 1];
                    }
                    tmp_bytes[j] = kb;
                    tmp_next[j] = kn;
                }
            }
            if (cnt != 0) {
                @memcpy(sparse_edge_bytes[edge_cursor..][0..cnt], tmp_bytes[0..cnt]);
                @memcpy(sparse_edge_next[edge_cursor..][0..cnt], tmp_next[0..cnt]);
            }
            sparse_states[s_idx] = .{
                .fail = fail_enc,
                .edge_off = @intCast(edge_cursor),
                .edge_len = @intCast(cnt),
            };
            edge_cursor += cnt;
        }
        std.debug.assert(edge_cursor == total_sparse_edges);
    }

    // 6. Start-byte nibble SIMD prefilter tables.
    var start_lo: [16]u8 = @splat(0);
    var start_hi: [16]u8 = @splat(0);
    for (0..256) |b| {
        if (dense[class_of[b]] != 0) {
            const bit: u8 = @as(u8, 1) << @as(u3, @truncate(b >> 4));
            start_lo[b & 0x0f] |= bit;
            start_hi[b >> 4] |= bit;
        }
    }
    var nibble_pass: usize = 0;
    for (0..256) |b| {
        if ((start_lo[b & 0x0f] & start_hi[b >> 4]) != 0) nibble_pass += 1;
    }

    const isa_ok = if (comptime static_nibble_isa)
        true
    else if (comptime runtime_nibble_isa)
        cpuid.detectX86().ssse3
    else
        false;
    const use_nibble_skip = isa_ok and nibble_pass <= 160;

    return .{
        .dense = dense,
        .dense_count = dense_count,
        .class_of = class_of,
        .nclasses = nclasses,
        .inv_nclasses = inv_nclasses,
        .sparse_states = sparse_states,
        .sparse_edge_bytes = sparse_edge_bytes,
        .sparse_edge_next = sparse_edge_next,
        .out_head = out_head,
        .outs = outs,
        .max_len = max_len,
        .empty_id = empty_id,
        .ignore_case = ignore_case,
        .patterns = patterns,
        .anchored = anchor.items,
        .spans = anchor.spans,
        .members = anchor.members,
        .max_off = anchor.max_off,
        .min_len = anchor.min_len,
        .use_anchor = false,
        .use_nibble_skip = use_nibble_skip,
        .start_lo = start_lo,
        .start_hi = start_hi,
        .allocator = allocator,
    };
}

inline fn findChild(nodes: []const BuildNode, parent: u32, byte: u8) ?u32 {
    var cur = nodes[parent].first_child;
    while (cur != 0) : (cur = nodes[cur].next_sibling) {
        if (nodes[cur].edge_byte == byte) return cur;
    }
    return null;
}

inline fn encodeState(new_s: u32, dense_count: u32, nclasses: u16, out_head: []const u32) u32 {
    const match_flag: u32 = if (out_head[new_s] != sentinel) match_bit else 0;
    if (new_s < dense_count) {
        return match_flag | (new_s * @as(u32, nclasses));
    }
    return match_flag | sparse_bit | (new_s - dense_count);
}

inline fn divNclasses(row_off: u32, inv_nclasses: u64) usize {
    return @intCast((@as(u64, row_off) * inv_nclasses) >> 32);
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
    return .{ .start = cand.start, .end = cand.end, .pattern_id = cand.id };
}

fn equalAt(pat: []const u8, hay: []const u8, ignore: bool) bool {
    return if (ignore) std.ascii.eqlIgnoreCase(pat, hay) else std.mem.eql(u8, pat, hay);
}

fn buildAnchor(allocator: std.mem.Allocator, patterns: []const []const u8, ignore: bool) !AnchorSet {
    var n: usize = 0;
    for (patterns) |pat| {
        if (pat.len != 0) n += 1;
    }
    // Linear per-anchor verification is only faster than the hybrid dense+sparse automaton on
    // small pattern sets; large sets (>64 patterns) would verify too many candidates per hit.
    if (n == 0 or n > 64) return .{};

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
            if (std.mem.findScalar(u8, member_buf[0..member_n], form) != null) continue;
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

test "anchor prefilter matches dense automaton at the same position" {
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
    return scalarAcCase(hay, start, pats, false, mode);
}

fn scalarAcCase(
    hay: []const u8,
    start: usize,
    pats: []const []const u8,
    ignore_case: bool,
    mode: matcher.MatchMode,
) ?matcher.Match {
    const Pick = struct { start: usize, end: usize, id: u32 };
    var best: ?Pick = null;
    var i = start;
    while (i <= hay.len) : (i += 1) {
        for (pats, 0..) |pat, id_usize| {
            if (i + pat.len > hay.len) continue;
            if (!equalAt(pat, hay[i..][0..pat.len], ignore_case)) continue;
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
    return .{ .start = chosen.start, .end = chosen.end, .pattern_id = chosen.id };
}

test "anchor prefilter skips first stride and matches naive search on second stride" {
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

test "large 500-pattern hybrid dense+sparse automaton: modes, overlaps, ignore_case, and findWatchingNul" {
    const alloc = std.testing.allocator;
    const n_pats = 520;
    var storage = try alloc.alloc([24]u8, n_pats);
    defer alloc.free(storage);
    var pats = try alloc.alloc([]const u8, n_pats);
    defer alloc.free(pats);

    const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-";
    for (0..500) |i| {
        const c0 = alphabet[i % alphabet.len];
        const c1 = alphabet[(i * 7 + 3) % alphabet.len];
        const c2 = alphabet[(i * 13 + 5) % alphabet.len];
        const slice = try std.fmt.bufPrint(&storage[i], "{c}{c}{c}_tok{d:0>4}end", .{ c0, c1, c2, i });
        pats[i] = slice;
    }
    // Overlapping patterns at various depths (testing leftmost_first vs earliest & suffix links)
    pats[500] = "alpha_overlap_long";
    pats[501] = "overlap";
    pats[502] = "alpha_overlap";
    pats[503] = "lap_lo";
    // Shared prefix with >8 branching children in sparse region (triggers binary search in stepSparse)
    for (0..16) |k| {
        const slice = try std.fmt.bufPrint(&storage[504 + k], "shared_deep_pfx_{c}", .{@as(u8, 'a' + @as(u8, @intCast(k)))});
        pats[504 + k] = slice;
    }

    inline for (.{ false, true }) |ignore_case| {
        var ac = try build(alloc, pats, ignore_case);
        defer ac.deinit();
        try std.testing.expect(!ac.use_anchor);
        try std.testing.expect(ac.sparse_states.len > 0);

        // 1. Overlapping match ordering: earliest vs leftmost_first
        const overlap_hay = if (ignore_case)
            "xxxx ALPHA_OVERLAP_LONG yyyy"
        else
            "xxxx alpha_overlap_long yyyy";
        inline for (.{ .earliest, .leftmost_first }) |mode| {
            const got = ac.find(overlap_hay, 0, mode).?;
            const want = scalarAcCase(overlap_hay, 0, pats, ignore_case, mode).?;
            try std.testing.expectEqual(want.start, got.start);
            try std.testing.expectEqual(want.end, got.end);
            try std.testing.expectEqual(want.pattern_id, got.pattern_id);
        }

        // 2. Deep sparse binary-search branch hit (branch index 11 -> 'l')
        const deep_hay = if (ignore_case)
            "noise SHARED_DEEP_PFX_L tail"
        else
            "noise shared_deep_pfx_l tail";
        const deep_hit = ac.find(deep_hay, 0, .earliest).?;
        try std.testing.expectEqual(@as(usize, 6), deep_hit.start);
        try std.testing.expectEqual(@as(?u32, 504 + 11), deep_hit.pattern_id);

        // 3. findWatchingNul: NUL before match vs NUL after match vs NUL inside chunk (> 32 KiB)
        var nul_before: ?usize = null;
        const hay_nul_before = "prefix\x00noise shared_deep_pfx_a tail";
        try std.testing.expect(ac.findWatchingNul(hay_nul_before, 0, .earliest, &nul_before) == null);
        try std.testing.expectEqual(@as(?usize, 6), nul_before);

        var nul_after: ?usize = null;
        const hay_nul_after = "prefix shared_deep_pfx_a\x00tail";
        const after_hit = ac.findWatchingNul(hay_nul_after, 0, .earliest, &nul_after).?;
        try std.testing.expectEqual(@as(usize, 7), after_hit.start);
        try std.testing.expectEqual(@as(?usize, null), nul_after);
    }
}

test "large 2000-pattern hybrid automaton: deep sparse matches, chunk-boundary NUL, and start offset" {
    const alloc = std.testing.allocator;
    const n_pats = 2000;
    var storage = try alloc.alloc([20]u8, n_pats);
    defer alloc.free(storage);
    var pats = try alloc.alloc([]const u8, n_pats);
    defer alloc.free(pats);

    const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_-./:";
    const n_alpha = alphabet.len;
    for (0..n_pats) |i| {
        const c0 = alphabet[i % n_alpha];
        const c1 = alphabet[(i / n_alpha) % n_alpha];
        const c2 = alphabet[(i * 17 + i / n_alpha + 7) % n_alpha];
        const c3 = alphabet[(i * 31 + (i / 13) + 13) % n_alpha];
        const c4 = alphabet[(i * 43 + (i / 29) + 19) % n_alpha];
        const slice = try std.fmt.bufPrint(&storage[i], "{c}{c}{c}{c}_pat_{d:0>4}_{c}", .{ c0, c1, c2, c3, i, c4 });
        pats[i] = slice;
    }

    var ac = try build(alloc, pats, false);
    defer ac.deinit();
    try std.testing.expect(!ac.use_anchor);
    try std.testing.expect(ac.sparse_states.len > 10_000);
    // Dense prefix must stay bounded within L2 budget (~263 KiB).
    try std.testing.expect(ac.dense.len <= dense_budget_cells);

    // Build a >64 KiB haystack spanning multiple nul_chunk_bytes boundaries
    const hay_len = nul_chunk_bytes * 2 + 1024;
    const hay = try alloc.alloc(u8, hay_len);
    defer alloc.free(hay);
    @memset(hay, ' ');
    // Plant a match straddling the 32 KiB chunk boundary and another near the end
    const target_a = pats[1999];
    const pos_a = nul_chunk_bytes - 4;
    @memcpy(hay[pos_a..][0..target_a.len], target_a);
    const target_b = pats[777];
    const pos_b = hay_len - 64;
    @memcpy(hay[pos_b..][0..target_b.len], target_b);

    // 1. Both modes find exact boundary-straddling match and second match from start > pos_a
    inline for (.{ .earliest, .leftmost_first }) |mode| {
        const h1 = ac.find(hay, 0, mode).?;
        try std.testing.expectEqual(pos_a, h1.start);
        try std.testing.expectEqual(pos_a + target_a.len, h1.end);
        try std.testing.expectEqual(@as(?u32, 1999), h1.pattern_id);

        const h2 = ac.find(hay, pos_a + 1, mode).?;
        try std.testing.expectEqual(pos_b, h2.start);
        try std.testing.expectEqual(pos_b + target_b.len, h2.end);
        try std.testing.expectEqual(@as(?u32, 777), h2.pattern_id);
    }

    // 2. NUL placed AFTER pos_a (after boundary-straddling match) must NOT suppress pos_a
    hay[pos_a + target_a.len + 2] = 0;
    var nul_pos: ?usize = null;
    const watched_ok = ac.findWatchingNul(hay, 0, .earliest, &nul_pos).?;
    try std.testing.expectEqual(pos_a, watched_ok.start);
    try std.testing.expectEqual(@as(?usize, null), nul_pos);

    // 3. Starting after pos_a hits the NUL before pos_b
    const watched_nul = ac.findWatchingNul(hay, pos_a + 1, .earliest, &nul_pos);
    try std.testing.expect(watched_nul == null);
    try std.testing.expectEqual(@as(?usize, pos_a + target_a.len + 2), nul_pos);

    // 4. NUL in first chunk suppresses everything after it
    hay[17] = 0;
    nul_pos = null;
    try std.testing.expect(ac.findWatchingNul(hay, 0, .earliest, &nul_pos) == null);
    try std.testing.expectEqual(@as(?usize, 17), nul_pos);
}

test "divNclasses exactness across all nclasses 1..256 and OOM safety" {
    for (1..257) |d_usize| {
        const d: u32 = @intCast(d_usize);
        const inv: u64 = ((@as(u64, 1) << 32) + @as(u64, d) - 1) / @as(u64, d);
        const max_q: u32 = @intCast(dense_budget_cells / d_usize);
        var q: u32 = 0;
        while (q <= max_q) : (q += 1) {
            try std.testing.expectEqual(@as(usize, q), divNclasses(q * d, inv));
        }
    }

    // OOM safety across every allocation point in hybrid dense+sparse build
    var storage: [64][8]u8 = undefined;
    var pats: [64][]const u8 = undefined;
    for (0..64) |i| {
        pats[i] = try std.fmt.bufPrint(&storage[i], "{c}{c}_x{d:0>2}y", .{
            @as(u8, 'a' + @as(u8, @intCast(i % 26))),
            @as(u8, 'A' + @as(u8, @intCast((i * 7) % 26))),
            i,
        });
    }
    var fail_idx: usize = 0;
    while (fail_idx < 32) : (fail_idx += 1) {
        var fa = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = fail_idx });
        if (build(fa.allocator(), &pats, false)) |*built| {
            var mut = built.*;
            mut.deinit();
            break;
        } else |_| {}
    }
}
