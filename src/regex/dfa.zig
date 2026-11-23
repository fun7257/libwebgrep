//! [Module] regex/dfa.zig
//! [Layer] Layer 2 — Bounded Lazy DFA Hybrid Automaton
//! [Role] Implements on-demand subset construction (`BoundedDfa`) over Thompson NFA bytecode (`[]Inst`).
//!        Used as Phase 1 candidate detector in the two-phase DFA + PikeVM hybrid execution engine.
//! [Invariants]
//!   1. State count is strictly bounded by `max_states` (64 for stack, 256 for heap scratch); when full,
//!      the transition cache flushes in O(1) time by resetting `num_states = 2` and incrementing `flushes`.
//!   2. If any single DFA state's NFA epsilon closure exceeds `max_closure_pcs` (64), the transition returns
//!      `bailout_transition` and increments `bailouts`, transparently delegating to linear-time PikeVM.
//!   3. Zero-width assertions and multi-byte Unicode property classes are conservatively over-approximated
//!      in Phase 1 (zero false negatives) and verified exactly by Phase 2 PikeVM.
//! [HotPath] `BoundedDfa.step` (1 table lookup per input byte once determinized).

const std = @import("std");
const matcher = @import("../matcher.zig");
const memchr = @import("../finder/memchr.zig");
const inst_mod = @import("inst.zig");
const Inst = inst_mod.Inst;
const UnicodeRangeList = inst_mod.UnicodeRangeList;
const inRanges = inst_mod.inRanges;

pub const unknown_transition: u16 = 0xFFFF;
pub const bailout_transition: u16 = 0xFFFE;
pub const dead_state: u16 = 0;
pub const start_state: u16 = 1;
pub const max_closure_pcs: usize = 64;

pub const StackDfa = BoundedDfa(64);
pub const HeapDfa = BoundedDfa(256);

/// Returns true when the NFA contains only byte-exact transitions (no zero-width assertions,
/// Unicode multi-byte classes, or wildcards that require CRLF/UTF-8 post-filtering), so a
/// greedy determinized DFA without alternations or lazy quantifiers computes the exact match span.
pub fn isExactInsts(insts: []const Inst) bool {
    for (insts) |inst| {
        switch (inst) {
            .byte, .split, .jmp, .save, .match, .match_id => {},
            .class => |cl| {
                if (cl.utf8_negated) return false;
            },
            .assert, .unicode_class, .any, .any_cont => return false,
        }
    }
    return true;
}

/// Returns true when every NFA transition is exact on pure ASCII slices (`b < 0x80`).
/// Allows `.unicode_class` (whose `< 0x80` transitions are exact in `BoundedDfa`) and its
/// `.any_cont` helpers, while excluding assertions, wildcards, and case-folded unicode classes.
pub fn isExactOnAsciiInsts(insts: []const Inst) bool {
    for (insts) |inst| {
        switch (inst) {
            .byte, .split, .jmp, .save, .match, .match_id, .any_cont => {},
            .class => |cl| {
                if (cl.utf8_negated) return false;
            },
            .unicode_class => |uc| {
                if (uc.ignore_case) return false;
            },
            .assert, .any => return false,
        }
    }
    return true;
}

pub fn BoundedDfa(comptime max_states_cap: u16) type {
    return struct {
        const Self = @This();
        pub const max_states: u16 = max_states_cap;

        pub const StateMeta = struct {
            pcs: [max_closure_pcs]u16 = undefined,
            pc_len: u8 = 0,
        };

        /// Dense 512-byte-stride transition table (`state << 9` indexing without `imul`).
        trans: [max_states_cap][256]u16 = undefined,
        /// Per-state match acceptance flags (fits in <= 4 cache lines).
        is_match: [max_states_cap]bool = @splat(false),
        /// True when `is_match[s]` and every outgoing transition of `s` is `dead_state`.
        is_terminal: [max_states_cap]bool = @splat(false),
        /// Number of contiguous linear single-successor non-match states (`s -> s+1 -> ... -> s+L`) starting at `s`.
        chain_len: [max_states_cap]u8 = @splat(0),
        /// When `chain_uniform_span[s] != 0xFF`, every state in the linear chain starting at `s`
        /// transitions to `s+1` iff `(b -% chain_uniform_lo[s]) <= chain_uniform_span[s]`.
        chain_uniform_lo: [max_states_cap]u8 = @splat(0),
        chain_uniform_span: [max_states_cap]u8 = @splat(0xFF),
        /// Number of exit bytes (1 or 2) where `trans[s][b] != s` for self-loop states (`0` otherwise).
        loop_exit_count: [max_states_cap]u8 = @splat(0),
        /// Exit byte values for self-loop states when `loop_exit_count[s]` is 1 or 2.
        loop_exit_bytes: [max_states_cap][2]u8 = undefined,
        /// Cold NFA closure sets used only during state construction, never touched on hot scan path.
        meta: [max_states_cap]StateMeta = undefined,
        num_states: u16 = 0,
        flushes: u32 = 0,
        bailouts: u32 = 0,
        stops_on_crlf: bool = false,
        compiled_insts_ptr: usize = 0,
        compiled_start_pc: u32 = std.math.maxInt(u32),
        compiled_multiline: bool = false,
        effective_max_states: u16 = max_states_cap,

        pub fn init() Self {
            return .{};
        }

        pub fn reset(self: *Self) void {
            self.num_states = 0;
            self.flushes = 0;
            self.bailouts = 0;
            self.stops_on_crlf = false;
            self.compiled_insts_ptr = 0;
            self.compiled_start_pc = std.math.maxInt(u32);
        }

        pub fn ensureInitialized(
            self: *Self,
            insts: []const Inst,
            start_pc: u32,
            multiline: bool,
            configured_max_states: u16,
        ) bool {
            const cap = @max(@as(u16, 4), @min(max_states_cap, configured_max_states));
            if (self.num_states >= 2 and
                self.compiled_insts_ptr == @intFromPtr(insts.ptr) and
                self.compiled_start_pc == start_pc and
                self.compiled_multiline == multiline and
                self.effective_max_states == cap)
            {
                return true;
            }
            self.compiled_insts_ptr = @intFromPtr(insts.ptr);
            self.compiled_start_pc = start_pc;
            self.compiled_multiline = multiline;
            self.effective_max_states = cap;
            return self.initBaseStates(insts, start_pc);
        }

        /// Determinizes all reachable states ahead-of-time up to `max_states_cap`.
        /// Fails cleanly (returning `false`) if any closure overflows or state table flushes occur.
        pub fn determinize(
            self: *Self,
            insts: []const Inst,
            unicode_ranges: []const UnicodeRangeList,
            start_pc: u32,
            multiline: bool,
        ) bool {
            self.reset();
            if (!self.ensureInitialized(insts, start_pc, multiline, max_states_cap)) return false;
            var crlf_dead = !multiline;
            var q_head: u16 = 1;
            while (q_head < self.num_states) : (q_head += 1) {
                var b: u16 = 0;
                while (b < 256) : (b += 1) {
                    const byte: u8 = @truncate(b);
                    if (!multiline and byte == '\n') {
                        self.trans[q_head]['\n'] = dead_state;
                        continue;
                    }
                    const next = self.step(insts, unicode_ranges, q_head, byte, multiline);
                    if (next == bailout_transition or self.flushes != 0 or self.bailouts != 0) return false;
                }
                if (crlf_dead and (self.trans[q_head]['\r'] != dead_state or self.trans[q_head]['\n'] != dead_state)) {
                    crlf_dead = false;
                }
            }
            self.stops_on_crlf = crlf_dead;
            self.is_terminal = @splat(false);
            self.chain_len = @splat(0);
            self.chain_uniform_lo = @splat(0);
            self.chain_uniform_span = @splat(0xFF);
            self.loop_exit_count = @splat(0);
            if (self.flushes == 0 and self.bailouts == 0 and self.num_states > 1) {
                self.computeLoopExitsForRange(1, self.num_states);
                self.computeChainAndTerminalForRange(1, self.num_states);
            }
            return self.flushes == 0 and self.bailouts == 0;
        }

        fn computeChainAndTerminalForRange(self: *Self, from_state: u16, to_state: u16) void {
            if (to_state <= from_state) return;
            var s_idx: usize = to_state - 1;
            while (s_idx >= from_state) : (s_idx -= 1) {
                const s: u16 = @intCast(s_idx);
                self.chain_len[s] = 0;
                self.chain_uniform_lo[s] = 0;
                self.chain_uniform_span[s] = 0xFF;
                if (self.is_match[s]) {
                    var all_dead = true;
                    for (self.trans[s]) |t| {
                        if (t != dead_state) {
                            all_dead = false;
                            break;
                        }
                    }
                    self.is_terminal[s] = all_dead;
                } else {
                    self.is_terminal[s] = false;
                    if (s + 1 < to_state) {
                        const target: u16 = s + 1;
                        var only_target = true;
                        var has_target = false;
                        var lo: ?u8 = null;
                        var hi: u8 = 0;
                        var count: usize = 0;
                        for (self.trans[s], 0..) |t, b_idx| {
                            if (t == target) {
                                has_target = true;
                                const byte: u8 = @intCast(b_idx);
                                if (lo == null) lo = byte;
                                hi = byte;
                                count += 1;
                            } else if (t != dead_state) {
                                only_target = false;
                                break;
                            }
                        }
                        if (only_target and has_target) {
                            const clen: u8 = @min(@as(u8, 64), 1 +| self.chain_len[target]);
                            self.chain_len[s] = clen;
                            if (lo) |start_b| {
                                const span: usize = @as(usize, hi) - @as(usize, start_b);
                                if (span + 1 == count and span < 128) {
                                    const span_u8: u8 = @intCast(span);
                                    if (clen == 1 or (self.chain_uniform_span[target] == span_u8 and self.chain_uniform_lo[target] == start_b)) {
                                        self.chain_uniform_lo[s] = start_b;
                                        self.chain_uniform_span[s] = span_u8;
                                    }
                                }
                            }
                        }
                    }
                }
                if (s_idx == from_state) break;
            }
        }

        fn computeLoopExitsForRange(self: *Self, from_state: u16, to_state: u16) void {
            var s: u16 = from_state;
            while (s < to_state) : (s += 1) {
                var diff_count: u16 = 0;
                var exits: [2]u8 = .{ 0, 0 };
                for (self.trans[s], 0..) |t, b| {
                    if (t != s) {
                        if (diff_count < 2) exits[diff_count] = @intCast(b);
                        diff_count += 1;
                        if (diff_count > 2) break;
                    }
                }
                if (diff_count == 1 or diff_count == 2) {
                    self.loop_exit_count[s] = @intCast(diff_count);
                    self.loop_exit_bytes[s] = exits;
                } else {
                    self.loop_exit_count[s] = 0;
                }
            }
        }

        /// Adds an additional root state for `suffix_pc` into an already determinized DFA
        /// and determinizes all states reachable from it. Rolls back cleanly and returns `null`
        /// if state capacity (`max_states_cap`) or closure capacity is exceeded.
        pub fn determinizeSuffix(
            self: *Self,
            insts: []const Inst,
            unicode_ranges: []const UnicodeRangeList,
            suffix_pc: u32,
            multiline: bool,
        ) ?u16 {
            if (self.flushes != 0 or self.bailouts != 0 or self.num_states < 2) return null;
            var pcs: [max_closure_pcs]u16 = undefined;
            var pc_len: u8 = 0;
            var match_flag = false;
            if (!computeEpsilonClosure(insts, suffix_pc, &pcs, &pc_len, &match_flag)) return null;
            if (pc_len == 0 and !match_flag) return dead_state;

            for (1..self.num_states) |idx| {
                const st = &self.meta[idx];
                if (st.pc_len == pc_len and self.is_match[idx] == match_flag and
                    std.mem.eql(u16, st.pcs[0..pc_len], pcs[0..pc_len]))
                {
                    return @intCast(idx);
                }
            }

            if (self.num_states >= self.effective_max_states) return null;
            const saved_crlf = self.stops_on_crlf;
            const root_id = self.num_states;
            self.meta[root_id] = .{ .pcs = pcs, .pc_len = pc_len };
            self.is_match[root_id] = match_flag;
            self.trans[root_id] = @splat(unknown_transition);
            self.num_states += 1;

            var crlf_dead = saved_crlf and !multiline;
            var q_head: u16 = root_id;
            while (q_head < self.num_states) : (q_head += 1) {
                var b: u16 = 0;
                while (b < 256) : (b += 1) {
                    const byte: u8 = @truncate(b);
                    if (!multiline and byte == '\n') {
                        self.trans[q_head]['\n'] = dead_state;
                        continue;
                    }
                    const next = self.step(insts, unicode_ranges, q_head, byte, multiline);
                    if (next == bailout_transition or self.flushes != 0 or self.bailouts != 0) {
                        // Re-determinize clean base DFA so caller can still use precomputed_dfa
                        _ = self.determinize(insts, unicode_ranges, self.compiled_start_pc, multiline);
                        return null;
                    }
                }
                if (crlf_dead and (self.trans[q_head]['\r'] != dead_state or self.trans[q_head]['\n'] != dead_state)) {
                    crlf_dead = false;
                }
            }
            self.stops_on_crlf = crlf_dead;
            if (self.flushes == 0 and self.bailouts == 0 and self.num_states > root_id) {
                self.computeLoopExitsForRange(root_id, self.num_states);
                self.computeChainAndTerminalForRange(root_id, self.num_states);
            }
            return root_id;
        }

        /// Fast single-branch prefix matcher on a fully determinized DFA (`determinize() == true`).
        /// When `earliest` is true, returns immediately upon reaching the first accepting state;
        /// otherwise returns the longest greedy match length starting at `slice[0]`, or `null` if no match.
        pub inline fn matchPrefixDeterminized(
            self: *const Self,
            slice: []const u8,
            start_state_id: u16,
            prefix_offset: usize,
            earliest: bool,
        ) ?usize {
            if (prefix_offset > slice.len) return null;
            const rem = slice[prefix_offset..];
            var curr_state: u16 = start_state_id;
            if (earliest and self.is_match[curr_state]) return prefix_offset;
            var last_match: ?usize = if (self.is_match[curr_state]) prefix_offset else null;
            var idx: usize = 0;
            while (idx < rem.len) {
                const lex = self.loop_exit_count[curr_state];
                if (lex != 0) {
                    const eb = self.loop_exit_bytes[curr_state];
                    const next_pos = if (lex == 1)
                        memchr.find(memchr.native_width, rem, idx, eb[0])
                    else
                        memchr.findEither(memchr.native_width, rem, idx, eb[0], eb[1]);
                    if (next_pos) |at| {
                        idx = at;
                        if (self.is_match[curr_state]) {
                            last_match = prefix_offset + idx;
                        }
                        curr_state = self.trans[curr_state][rem[idx]];
                        idx += 1;
                        if (curr_state == dead_state) break;
                        if (self.is_match[curr_state]) {
                            if (earliest) return prefix_offset + idx;
                            last_match = prefix_offset + idx;
                        }
                        continue;
                    } else {
                        if (self.is_match[curr_state]) {
                            last_match = prefix_offset + rem.len;
                        }
                        break;
                    }
                }
                const clen: usize = self.chain_len[curr_state];
                if (clen >= 2) {
                    if (idx + clen > rem.len) break;
                    const p = rem[idx..][0..clen];
                    const base_s: usize = curr_state;
                    const u_span = self.chain_uniform_span[curr_state];
                    if (u_span != 0xFF) {
                        const u_lo = self.chain_uniform_lo[curr_state];
                        if ((p[clen - 1] -% u_lo) > u_span or (p[clen - 2] -% u_lo) > u_span) {
                            break;
                        }
                        var dead = false;
                        for (p[0 .. clen - 2]) |ch| {
                            if ((ch -% u_lo) > u_span) {
                                dead = true;
                                break;
                            }
                        }
                        if (dead) break;
                    } else {
                        if (self.trans[base_s + clen - 1][p[clen - 1]] == dead_state or
                            self.trans[base_s + clen - 2][p[clen - 2]] == dead_state)
                        {
                            break;
                        }
                        var k: usize = 0;
                        const limit4 = (clen - 2) & ~@as(usize, 3);
                        var dead = false;
                        while (k < limit4) : (k += 4) {
                            const t0 = self.trans[base_s + k][p[k]];
                            const t1 = self.trans[base_s + k + 1][p[k + 1]];
                            const t2 = self.trans[base_s + k + 2][p[k + 2]];
                            const t3 = self.trans[base_s + k + 3][p[k + 3]];
                            if ((t0 == dead_state) or (t1 == dead_state) or (t2 == dead_state) or (t3 == dead_state)) {
                                dead = true;
                                break;
                            }
                        }
                        if (dead) break;
                        while (k < clen - 2) : (k += 1) {
                            if (self.trans[base_s + k][p[k]] == dead_state) {
                                dead = true;
                                break;
                            }
                        }
                        if (dead) break;
                    }
                    curr_state = @intCast(base_s + clen);
                    idx += clen;
                    if (self.is_match[curr_state]) {
                        if (earliest or self.is_terminal[curr_state]) return prefix_offset + idx;
                        last_match = prefix_offset + idx;
                    }
                    continue;
                }
                curr_state = self.trans[curr_state][rem[idx]];
                idx += 1;
                if (curr_state == dead_state) break;
                if (self.is_match[curr_state]) {
                    if (earliest) return prefix_offset + idx;
                    last_match = prefix_offset + idx;
                }
            }
            return last_match;
        }

        fn initBaseStates(self: *Self, insts: []const Inst, start_pc: u32) bool {
            // State 0: dead state (all transitions loop to dead_state)
            self.meta[dead_state] = .{ .pc_len = 0 };
            self.is_match[dead_state] = false;
            self.trans[dead_state] = @splat(dead_state);

            // State 1: start state (epsilon closure of start_pc)
            var pcs: [max_closure_pcs]u16 = undefined;
            var pc_len: u8 = 0;
            var match_flag = false;
            if (!computeEpsilonClosure(insts, start_pc, &pcs, &pc_len, &match_flag)) {
                self.bailouts +%= 1;
                self.num_states = 0;
                return false;
            }
            self.meta[start_state] = .{ .pcs = pcs, .pc_len = pc_len };
            self.is_match[start_state] = match_flag;
            self.trans[start_state] = @splat(unknown_transition);
            self.num_states = 2;
            return true;
        }

        /// Advances the lazy DFA from `state_id` on input byte `b`.
        /// Returns the next state ID (`0..effective_max_states-1`), or `bailout_transition` if the NFA closure overflows.
        pub inline fn step(
            self: *Self,
            insts: []const Inst,
            unicode_ranges: []const UnicodeRangeList,
            state_id: u16,
            b: u8,
            multiline: bool,
        ) u16 {
            if (!multiline and b == '\n') return dead_state;
            const cached = self.trans[state_id][b];
            if (cached != unknown_transition) return cached;
            return self.computeTransition(insts, unicode_ranges, state_id, b, multiline);
        }

        noinline fn computeTransition(
            self: *Self,
            insts: []const Inst,
            unicode_ranges: []const UnicodeRangeList,
            state_id: u16,
            b: u8,
            multiline: bool,
        ) u16 {
            var next_pcs: [max_closure_pcs]u16 = undefined;
            var next_len: u8 = 0;
            var next_is_match = false;

            const src_len = self.meta[state_id].pc_len;
            var src_pcs: [max_closure_pcs]u16 = undefined;
            @memcpy(src_pcs[0..src_len], self.meta[state_id].pcs[0..src_len]);

            for (src_pcs[0..src_len]) |pc_u16| {
                const inst = insts[pc_u16];
                switch (inst) {
                    .byte => |by| {
                        const ok = if (by.ignore_case)
                            std.ascii.toLower(b) == std.ascii.toLower(by.b)
                        else
                            b == by.b;
                        if (ok) {
                            if (!computeEpsilonClosure(insts, by.out, &next_pcs, &next_len, &next_is_match)) {
                                self.bailouts +%= 1;
                                self.trans[state_id][b] = bailout_transition;
                                return bailout_transition;
                            }
                        }
                    },
                    .any => |an| {
                        if (!an.allow_nl and b == '\n') continue;
                        const target_pc: u32 = if (b < 0x80)
                            an.out
                        else if (b >= 0xC2 and b <= 0xDF)
                            (if (an.cont1 != 0) an.cont1 else an.out)
                        else if (b >= 0xE0 and b <= 0xEF)
                            (if (an.cont2 != 0) an.cont2 else an.out)
                        else if (b >= 0xF0 and b <= 0xF4)
                            (if (an.cont3 != 0) an.cont3 else an.out)
                        else
                            an.out;
                        if (!computeEpsilonClosure(insts, target_pc, &next_pcs, &next_len, &next_is_match)) {
                            self.bailouts +%= 1;
                            self.trans[state_id][b] = bailout_transition;
                            return bailout_transition;
                        }
                    },
                    .any_cont => |ac| {
                        if ((b & 0xC0) == 0x80) {
                            if (!computeEpsilonClosure(insts, ac.out, &next_pcs, &next_len, &next_is_match)) {
                                self.bailouts +%= 1;
                                self.trans[state_id][b] = bailout_transition;
                                return bailout_transition;
                            }
                        }
                    },
                    .class => |cl| {
                        if (cl.utf8_negated and b >= 0x80) {
                            const target_pc: u32 = if (b >= 0xC2 and b <= 0xDF)
                                (if (cl.cont1 != 0) cl.cont1 else cl.out)
                            else if (b >= 0xE0 and b <= 0xEF)
                                (if (cl.cont2 != 0) cl.cont2 else cl.out)
                            else if (b >= 0xF0 and b <= 0xF4)
                                (if (cl.cont3 != 0) cl.cont3 else cl.out)
                            else
                                cl.out;
                            if (!computeEpsilonClosure(insts, target_pc, &next_pcs, &next_len, &next_is_match)) {
                                self.bailouts +%= 1;
                                self.trans[state_id][b] = bailout_transition;
                                return bailout_transition;
                            }
                            continue;
                        }
                        if (cl.set.contains(b)) {
                            if (!computeEpsilonClosure(insts, cl.out, &next_pcs, &next_len, &next_is_match)) {
                                self.bailouts +%= 1;
                                self.trans[state_id][b] = bailout_transition;
                                return bailout_transition;
                            }
                        }
                    },
                    .unicode_class => |uc| {
                        if (!uc.allow_nl and b == '\n') continue;
                        if (b < 0x80) {
                            const ranges = unicode_ranges[uc.range_idx].ranges;
                            const in_set = (uc.has_ascii_set and uc.ascii_set.contains(b)) or inRanges(b, ranges);
                            const matched = if (uc.negated) !in_set else in_set;
                            if (matched) {
                                if (!computeEpsilonClosure(insts, uc.out, &next_pcs, &next_len, &next_is_match)) {
                                    self.bailouts +%= 1;
                                    self.trans[state_id][b] = bailout_transition;
                                    return bailout_transition;
                                }
                            }
                        } else if (b >= 0xC2 and b <= 0xF4) {
                            const target_pc: u32 = if (b <= 0xDF)
                                (if (uc.cont1 != 0) uc.cont1 else uc.out)
                            else if (b <= 0xEF)
                                (if (uc.cont2 != 0) uc.cont2 else uc.out)
                            else
                                (if (uc.cont3 != 0) uc.cont3 else uc.out);
                            if (!computeEpsilonClosure(insts, target_pc, &next_pcs, &next_len, &next_is_match)) {
                                self.bailouts +%= 1;
                                self.trans[state_id][b] = bailout_transition;
                                return bailout_transition;
                            }
                        }
                    },
                    .match, .match_id, .split, .jmp, .assert, .save => {},
                }
            }

            _ = multiline;
            if (next_len == 0 and !next_is_match) {
                self.trans[state_id][b] = dead_state;
                return dead_state;
            }

            // Deduplicate against existing DFA states
            for (1..self.num_states) |idx| {
                const st = &self.meta[idx];
                if (st.pc_len == next_len and self.is_match[idx] == next_is_match and
                    std.mem.eql(u16, st.pcs[0..next_len], next_pcs[0..next_len]))
                {
                    const found_id: u16 = @intCast(idx);
                    self.trans[state_id][b] = found_id;
                    return found_id;
                }
            }

            // If state cache is full, flush in O(1) by resetting to base states (0 and 1)
            var actual_src = state_id;
            if (self.num_states >= self.effective_max_states) {
                self.flushes +%= 1;
                _ = self.initBaseStates(insts, self.compiled_start_pc);
                if (state_id != start_state) {
                    const reloaded_src = self.num_states;
                    self.meta[reloaded_src] = .{ .pcs = src_pcs, .pc_len = src_len };
                    self.is_match[reloaded_src] = false;
                    self.trans[reloaded_src] = @splat(unknown_transition);
                    self.num_states += 1;
                    actual_src = reloaded_src;
                } else {
                    actual_src = start_state;
                }
            }

            const new_id = self.num_states;
            self.meta[new_id] = .{ .pcs = next_pcs, .pc_len = next_len };
            self.is_match[new_id] = next_is_match;
            self.trans[new_id] = @splat(unknown_transition);
            self.num_states += 1;
            self.trans[actual_src][b] = new_id;
            return new_id;
        }
    };
}

/// Computes the epsilon closure of `start_pc`, treating `.assert` and `.save` as epsilon edges (conservative over-approximation).
/// Returns `false` if the closure exceeds `max_closure_pcs` (64) or `pc` exceeds `u16`.
fn computeEpsilonClosure(
    insts: []const Inst,
    start_pc: u32,
    out_pcs: *[max_closure_pcs]u16,
    out_len: *u8,
    out_is_match: *bool,
) bool {
    var stack: [128]u32 = undefined;
    var sp: usize = 0;
    stack[0] = start_pc;
    sp = 1;

    var visited_pcs: [128]u32 = undefined;
    var visited_len: usize = 0;

    while (sp > 0) {
        sp -= 1;
        const pc = stack[sp];
        if (pc >= insts.len or pc > std.math.maxInt(u16)) return false;

        if (std.mem.findScalar(u32, visited_pcs[0..visited_len], pc) != null) continue;
        if (visited_len >= visited_pcs.len) return false;
        visited_pcs[visited_len] = pc;
        visited_len += 1;

        switch (insts[pc]) {
            .jmp => |target| {
                if (sp >= stack.len) return false;
                stack[sp] = target;
                sp += 1;
            },
            .split => |s| {
                if (sp + 2 > stack.len) return false;
                // Push out2 first so out1 is popped first (preserving NFA priority order)
                stack[sp] = s.out2;
                stack[sp + 1] = s.out1;
                sp += 2;
            },
            .assert => |as| {
                if (sp >= stack.len) return false;
                stack[sp] = as.out;
                sp += 1;
            },
            .save => |sv| {
                if (sp >= stack.len) return false;
                stack[sp] = sv.out;
                sp += 1;
            },
            .match, .match_id => {
                out_is_match.* = true;
            },
            .byte, .any, .any_cont, .class, .unicode_class => {
                const pc16: u16 = @intCast(pc);
                if (std.mem.findScalar(u16, out_pcs[0..out_len.*], pc16) == null) {
                    if (out_len.* >= max_closure_pcs) return false;
                    out_pcs[out_len.*] = pc16;
                    out_len.* += 1;
                }
            },
        }
    }
    return true;
}

fn sortU16(slice: []u16) void {
    var i: usize = 1;
    while (i < slice.len) : (i += 1) {
        const key = slice[i];
        var j: usize = i;
        while (j > 0 and slice[j - 1] > key) : (j -= 1) {
            slice[j] = slice[j - 1];
        }
        slice[j] = key;
    }
}

fn isSubsetU16(sub: []const u16, sup: []const u16) bool {
    for (sub) |x| {
        if (std.mem.findScalar(u16, sup, x) == null) return false;
    }
    return true;
}

pub const ByteRange = struct {
    lo: u8,
    span: u8,
};

pub const StartSkip = union(enum) {
    none,
    byte1: u8,
    byte2: [2]u8,
    byte3: [3]u8,
    range1: ByteRange,
    range2: [2]ByteRange,
    range3: [3]ByteRange,
};

/// Ahead-of-time unanchored Phase-1 search DFA with `u8` state IDs (up to 254 active states).
/// Every state transition implicitly unions `epsilon_closure(start_pc)`, so a single linear pass
/// visits each input byte at most once with zero restarts. States are partitioned so that all
/// non-match states have IDs `< match_start` and all accepting states have IDs `>= match_start`.
pub const UnanchoredDfa = struct {
    pub const start_id: u8 = 1;
    pub const max_states: u16 = 255;

    /// Dense 256-byte-stride transition table (`state << 8` indexing).
    trans: [256][256]u8 = undefined,
    num_states: u16 = 0,
    match_start: u8 = 255,
    /// True if any non-empty NFA move can land back inside `start_state`'s PC set (e.g., `(ab)*c`).
    /// When false, `curr_state == start_id` guarantees no match from an earlier offset survived.
    start_reentrant: bool = false,
    /// Precomputed SIMD skip descriptor for self-looping bytes on `start_id`.
    start_skip: StartSkip = .none,

    pub fn determinize(
        self: *UnanchoredDfa,
        insts: []const Inst,
        unicode_ranges: []const UnicodeRangeList,
        start_pc: u32,
        multiline: bool,
        max_states_cap: u16,
    ) bool {
        const cap: u16 = @min(max_states, max_states_cap);
        if (cap < 4 or insts.len == 0) return false;

        const Meta = struct {
            pcs: [max_closure_pcs]u16 = undefined,
            pc_len: u8 = 0,
        };
        var meta: [256]Meta = undefined;
        var is_match_tmp: [256]bool = @splat(false);

        var start_pcs: [max_closure_pcs]u16 = undefined;
        var start_len: u8 = 0;
        var start_match = false;
        if (!computeEpsilonClosure(insts, start_pc, &start_pcs, &start_len, &start_match)) return false;
        // Zero-length match or unmatchable empty closure stays on PikeVM
        if (start_match or start_len == 0) return false;
        sortU16(start_pcs[0..start_len]);

        meta[start_id] = .{ .pcs = start_pcs, .pc_len = start_len };
        is_match_tmp[start_id] = false;
        self.trans[0] = @splat(start_id);
        var num_states: u16 = 2;
        self.start_reentrant = false;

        var q_head: u16 = start_id;
        while (q_head < num_states) : (q_head += 1) {
            const src_len = meta[q_head].pc_len;
            const src_pcs = meta[q_head].pcs[0..src_len];

            var b_idx: u16 = 0;
            while (b_idx < 256) : (b_idx += 1) {
                const byte: u8 = @truncate(b_idx);
                if (!multiline and byte == '\n') {
                    self.trans[q_head]['\n'] = start_id;
                    continue;
                }

                var next_pcs: [max_closure_pcs]u16 = undefined;
                var next_len: u8 = 0;
                var next_is_match = false;

                for (src_pcs) |pc_u16| {
                    switch (insts[pc_u16]) {
                        .byte => |by| {
                            const ok = if (by.ignore_case)
                                std.ascii.toLower(byte) == std.ascii.toLower(by.b)
                            else
                                byte == by.b;
                            if (ok) {
                                if (!computeEpsilonClosure(insts, by.out, &next_pcs, &next_len, &next_is_match)) return false;
                            }
                        },
                        .any => |an| {
                            if (!an.allow_nl and byte == '\n') continue;
                            const target_pc: u32 = if (byte < 0x80)
                                an.out
                            else if (byte >= 0xC2 and byte <= 0xDF)
                                (if (an.cont1 != 0) an.cont1 else an.out)
                            else if (byte >= 0xE0 and byte <= 0xEF)
                                (if (an.cont2 != 0) an.cont2 else an.out)
                            else if (byte >= 0xF0 and byte <= 0xF4)
                                (if (an.cont3 != 0) an.cont3 else an.out)
                            else
                                an.out;
                            if (!computeEpsilonClosure(insts, target_pc, &next_pcs, &next_len, &next_is_match)) return false;
                        },
                        .any_cont => |ac| {
                            if ((byte & 0xC0) == 0x80) {
                                if (!computeEpsilonClosure(insts, ac.out, &next_pcs, &next_len, &next_is_match)) return false;
                            }
                        },
                        .class => |cl| {
                            if (cl.utf8_negated and byte >= 0x80) {
                                const target_pc: u32 = if (byte >= 0xC2 and byte <= 0xDF)
                                    (if (cl.cont1 != 0) cl.cont1 else cl.out)
                                else if (byte >= 0xE0 and byte <= 0xEF)
                                    (if (cl.cont2 != 0) cl.cont2 else cl.out)
                                else if (byte >= 0xF0 and byte <= 0xF4)
                                    (if (cl.cont3 != 0) cl.cont3 else cl.out)
                                else
                                    cl.out;
                                if (!computeEpsilonClosure(insts, target_pc, &next_pcs, &next_len, &next_is_match)) return false;
                                continue;
                            }
                            if (cl.set.contains(byte)) {
                                if (!computeEpsilonClosure(insts, cl.out, &next_pcs, &next_len, &next_is_match)) return false;
                            }
                        },
                        .unicode_class => |uc| {
                            if (!uc.allow_nl and byte == '\n') continue;
                            if (byte < 0x80) {
                                const ranges = unicode_ranges[uc.range_idx].ranges;
                                const in_set = (uc.has_ascii_set and uc.ascii_set.contains(byte)) or inRanges(byte, ranges);
                                const matched = if (uc.negated) !in_set else in_set;
                                if (matched) {
                                    if (!computeEpsilonClosure(insts, uc.out, &next_pcs, &next_len, &next_is_match)) return false;
                                }
                            } else if (byte >= 0xC2 and byte <= 0xF4) {
                                const target_pc: u32 = if (byte <= 0xDF)
                                    (if (uc.cont1 != 0) uc.cont1 else uc.out)
                                else if (byte <= 0xEF)
                                    (if (uc.cont2 != 0) uc.cont2 else uc.out)
                                else
                                    (if (uc.cont3 != 0) uc.cont3 else uc.out);
                                if (!computeEpsilonClosure(insts, target_pc, &next_pcs, &next_len, &next_is_match)) return false;
                            }
                        },
                        .match, .match_id, .split, .jmp, .assert, .save => {},
                    }
                }

                if (next_len == 0 and !next_is_match) {
                    self.trans[q_head][byte] = start_id;
                    continue;
                }

                if (!next_is_match and !self.start_reentrant) {
                    if (isSubsetU16(next_pcs[0..next_len], start_pcs[0..start_len])) {
                        self.start_reentrant = true;
                    }
                }

                // Union `start_pcs` into `next_pcs` so a new match can begin at every byte offset
                for (start_pcs[0..start_len]) |sp| {
                    if (std.mem.findScalar(u16, next_pcs[0..next_len], sp) == null) {
                        if (next_len >= max_closure_pcs) return false;
                        next_pcs[next_len] = sp;
                        next_len += 1;
                    }
                }
                sortU16(next_pcs[0..next_len]);

                var found_id: ?u8 = null;
                for (1..num_states) |idx| {
                    if (meta[idx].pc_len == next_len and is_match_tmp[idx] == next_is_match and
                        std.mem.eql(u16, meta[idx].pcs[0..next_len], next_pcs[0..next_len]))
                    {
                        found_id = @intCast(idx);
                        break;
                    }
                }
                if (found_id) |fid| {
                    self.trans[q_head][byte] = fid;
                } else {
                    if (num_states >= cap) return false;
                    const new_id: u8 = @intCast(num_states);
                    meta[num_states] = .{ .pcs = next_pcs, .pc_len = next_len };
                    is_match_tmp[num_states] = next_is_match;
                    num_states += 1;
                    self.trans[q_head][byte] = new_id;
                }
            }
        }

        // Partition states `2 .. num_states - 1`: non-match states first, match states `>= match_start`
        var remap: [256]u8 = @splat(0);
        remap[start_id] = start_id;
        var next_id: u16 = 2;
        for (2..num_states) |s| {
            if (!is_match_tmp[s]) {
                remap[s] = @intCast(next_id);
                next_id += 1;
            }
        }
        const match_start_u16 = next_id;
        for (2..num_states) |s| {
            if (is_match_tmp[s]) {
                remap[s] = @intCast(next_id);
                next_id += 1;
            }
        }

        for (1..num_states) |s| {
            for (0..256) |b| {
                self.trans[s][b] = remap[self.trans[s][b]];
            }
        }

        // Permute transition rows in-place via cycle decomposition
        var placed: [256]bool = @splat(false);
        for (1..num_states) |s| {
            if (placed[s] or remap[s] == s) {
                placed[s] = true;
                continue;
            }
            var cur: usize = s;
            var carry: [256]u8 = self.trans[cur];
            while (!placed[cur]) {
                placed[cur] = true;
                const dst: usize = remap[cur];
                const saved: [256]u8 = self.trans[dst];
                self.trans[dst] = carry;
                carry = saved;
                cur = dst;
            }
        }

        // Analyze start_id exit bytes to select optimal SIMD start-state skip strategy
        var exits: [4]u8 = undefined;
        var exit_count: usize = 0;
        var ranges: [4]ByteRange = undefined;
        var num_ranges: usize = 0;
        var in_run = false;
        var run_lo: u8 = 0;

        var b_scan: u16 = 0;
        while (b_scan < 256) : (b_scan += 1) {
            const byte: u8 = @truncate(b_scan);
            const is_exit = self.trans[start_id][byte] != start_id;
            if (is_exit) {
                if (exit_count < 4) exits[exit_count] = byte;
                exit_count += 1;
                if (!in_run) {
                    in_run = true;
                    run_lo = byte;
                }
            } else if (in_run) {
                in_run = false;
                const span: usize = @as(usize, byte - 1) - @as(usize, run_lo);
                if (num_ranges < 4) {
                    ranges[num_ranges] = .{ .lo = run_lo, .span = if (span < 128) @intCast(span) else 255 };
                }
                num_ranges += 1;
            }
        }
        if (in_run) {
            const span: usize = @as(usize, 255) - @as(usize, run_lo);
            if (num_ranges < 4) {
                ranges[num_ranges] = .{ .lo = run_lo, .span = if (span < 128) @intCast(span) else 255 };
            }
            num_ranges += 1;
        }

        if (exit_count == 1) {
            self.start_skip = .{ .byte1 = exits[0] };
        } else if (exit_count == 2) {
            self.start_skip = .{ .byte2 = .{ exits[0], exits[1] } };
        } else if (exit_count == 3) {
            self.start_skip = .{ .byte3 = .{ exits[0], exits[1], exits[2] } };
        } else if (num_ranges == 1 and ranges[0].span < 128) {
            self.start_skip = .{ .range1 = ranges[0] };
        } else if (num_ranges == 2 and ranges[0].span < 128 and ranges[1].span < 128) {
            self.start_skip = .{ .range2 = .{ ranges[0], ranges[1] } };
        } else if (num_ranges == 3 and ranges[0].span < 128 and ranges[1].span < 128 and ranges[2].span < 128) {
            self.start_skip = .{ .range3 = .{ ranges[0], ranges[1], ranges[2] } };
        } else {
            self.start_skip = .none;
        }

        self.num_states = num_states;
        self.match_start = @intCast(match_start_u16);
        return true;
    }

    pub inline fn skipStartBytes(self: *const UnanchoredDfa, haystack: []const u8, from: usize, limit: usize) ?usize {
        const width = memchr.native_width;
        const V = @Vector(width, u8);
        switch (self.start_skip) {
            .none => return from,
            .byte1 => |b0| return memchr.find(width, haystack[0..limit], from, b0),
            .byte2 => |bs| return memchr.findEither(width, haystack[0..limit], from, bs[0], bs[1]),
            .byte3 => |bs| {
                const hit = memchr.findAny(width, haystack[0..limit], from, bs[0], bs[1], bs[2]) orelse return null;
                return hit.index;
            },
            .range1 => |r| {
                const v_lo: V = @splat(r.lo);
                const v_sp: V = @splat(r.span);
                var i = from;
                while (i + width <= limit) : (i += width) {
                    const v: V = haystack[i..][0..width].*;
                    const m = (v -% v_lo) <= v_sp;
                    if (@reduce(.Or, m)) {
                        return i + @as(usize, std.simd.firstTrue(m).?);
                    }
                }
                while (i < limit) : (i += 1) {
                    if ((haystack[i] -% r.lo) <= r.span) return i;
                }
                return null;
            },
            .range2 => |rs| {
                const lo0: V = @splat(rs[0].lo);
                const sp0: V = @splat(rs[0].span);
                const lo1: V = @splat(rs[1].lo);
                const sp1: V = @splat(rs[1].span);
                var i = from;
                while (i + width <= limit) : (i += width) {
                    const v: V = haystack[i..][0..width].*;
                    const m = ((v -% lo0) <= sp0) | ((v -% lo1) <= sp1);
                    if (@reduce(.Or, m)) {
                        return i + @as(usize, std.simd.firstTrue(m).?);
                    }
                }
                while (i < limit) : (i += 1) {
                    const b = haystack[i];
                    if ((b -% rs[0].lo) <= rs[0].span or (b -% rs[1].lo) <= rs[1].span) return i;
                }
                return null;
            },
            .range3 => |rs| {
                const lo0: V = @splat(rs[0].lo);
                const sp0: V = @splat(rs[0].span);
                const lo1: V = @splat(rs[1].lo);
                const sp1: V = @splat(rs[1].span);
                const lo2: V = @splat(rs[2].lo);
                const sp2: V = @splat(rs[2].span);
                var i = from;
                while (i + width <= limit) : (i += width) {
                    const v: V = haystack[i..][0..width].*;
                    const m = ((v -% lo0) <= sp0) | ((v -% lo1) <= sp1) | ((v -% lo2) <= sp2);
                    if (@reduce(.Or, m)) {
                        return i + @as(usize, std.simd.firstTrue(m).?);
                    }
                }
                while (i < limit) : (i += 1) {
                    const b = haystack[i];
                    if ((b -% rs[0].lo) <= rs[0].span or (b -% rs[1].lo) <= rs[1].span or (b -% rs[2].lo) <= rs[2].span) return i;
                }
                return null;
            },
        }
    }
};
