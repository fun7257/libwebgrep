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

const builtin = @import("builtin");
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

/// Returns true when every NFA transition is exact on pure ASCII slices (`b < 0x80`),
/// additionally allowing `\b` and `\B` word-boundary assertions (tracked directly in `UnanchoredDfa`).
pub fn isExactOnAsciiWithWordBoundary(insts: []const Inst) bool {
    for (insts) |inst| {
        switch (inst) {
            .byte, .split, .jmp, .save, .match, .match_id, .any_cont => {},
            .class => {},
            .unicode_class => |uc| {
                if (uc.ignore_case) return false;
            },
            .assert => |as| {
                if (as.kind != .word_boundary and as.kind != .not_word_boundary) return false;
            },
            .any => return false,
        }
    }
    return true;
}

pub inline fn isAsciiWord(b: u8) bool {
    return (b >= 'a' and b <= 'z') or (b >= 'A' and b <= 'Z') or (b >= '0' and b <= '9') or b == '_';
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
        /// True when at least one determinized state has `loop_exit_count[s] != 0`.
        has_loop_exits: bool = false,
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
            self.has_loop_exits = false;
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
            self.has_loop_exits = false;
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
                    self.has_loop_exits = true;
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
                if (self.has_loop_exits) {
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

pub const StartSkipTag = std.meta.Tag(StartSkip);

pub const EoiKind = enum(u2) {
    none = 0,
    verify = 1,
    exact = 2,
};

const WordKind = enum(u2) {
    nonword = 0,
    word = 1,
    maybe = 2,
};

inline fn byteWordKind(b: u8) WordKind {
    if (b >= 0x80) return .maybe;
    if (isAsciiWord(b)) return .word;
    return .nonword;
}

inline fn firstMaskBit(comptime width: comptime_int, m: @Vector(width, bool)) ?usize {
    const MaskInt = @Int(.unsigned, width);
    const mask: MaskInt = @bitCast(m);
    if (mask == 0) return null;
    if (comptime builtin.cpu.arch.endian() == .little) {
        return @as(usize, @ctz(mask));
    } else {
        return @as(usize, @clz(mask));
    }
}

/// Expands epsilon edges (`.jmp`, `.split`, `.save`), stopping at consuming instructions
/// AND stopping at `.assert` instructions so `\b`/`\B` can be evaluated with next-byte look-around.
fn computeClosureStopAtAssert(
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
                stack[sp] = s.out2;
                stack[sp + 1] = s.out1;
                sp += 2;
            },
            .save => |sv| {
                if (sp >= stack.len) return false;
                stack[sp] = sv.out;
                sp += 1;
            },
            .match, .match_id => {
                out_is_match.* = true;
            },
            .assert, .byte, .any, .any_cont, .class, .unicode_class => {
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

const ResolvedBoundary = struct {
    pcs: [max_closure_pcs]u16 = undefined,
    from_ambig: [max_closure_pcs]bool = @splat(false),
    len: u8 = 0,
    delayed_match: bool = false,
    ambiguous_match: bool = false,
};

fn resolveAssertsAtBoundary(
    insts: []const Inst,
    src_pcs: []const u16,
    prev_kind: WordKind,
    next_kind: WordKind,
    out: *ResolvedBoundary,
) bool {
    const boundary_ambig = (prev_kind == .maybe or next_kind == .maybe);

    const StackItem = struct { pc: u32, ambig: bool };
    var stack: [128]StackItem = undefined;
    var sp: usize = 0;

    // Seed consuming PCs directly and push `.assert` PCs onto worklist.
    for (src_pcs) |pc_u16| {
        if (insts[pc_u16] == .assert) {
            if (sp >= stack.len) return false;
            stack[sp] = .{ .pc = pc_u16, .ambig = false };
            sp += 1;
        } else {
            if (out.len >= max_closure_pcs) return false;
            out.pcs[out.len] = pc_u16;
            out.from_ambig[out.len] = false;
            out.len += 1;
        }
    }

    var visited_clean: [128]u32 = undefined;
    var visited_clean_len: usize = 0;
    var visited_ambig: [128]u32 = undefined;
    var visited_ambig_len: usize = 0;

    while (sp > 0) {
        sp -= 1;
        const item = stack[sp];
        const pc = item.pc;
        if (pc >= insts.len or pc > std.math.maxInt(u16)) return false;

        if (item.ambig) {
            if (std.mem.findScalar(u32, visited_ambig[0..visited_ambig_len], pc) != null) continue;
            if (visited_ambig_len >= visited_ambig.len) return false;
            visited_ambig[visited_ambig_len] = pc;
            visited_ambig_len += 1;
        } else {
            if (std.mem.findScalar(u32, visited_clean[0..visited_clean_len], pc) != null) continue;
            if (visited_clean_len >= visited_clean.len) return false;
            visited_clean[visited_clean_len] = pc;
            visited_clean_len += 1;
        }

        switch (insts[pc]) {
            .jmp => |target| {
                if (sp >= stack.len) return false;
                stack[sp] = .{ .pc = target, .ambig = item.ambig };
                sp += 1;
            },
            .split => |s| {
                if (sp + 2 > stack.len) return false;
                stack[sp] = .{ .pc = s.out2, .ambig = item.ambig };
                stack[sp + 1] = .{ .pc = s.out1, .ambig = item.ambig };
                sp += 2;
            },
            .save => |sv| {
                if (sp >= stack.len) return false;
                stack[sp] = .{ .pc = sv.out, .ambig = item.ambig };
                sp += 1;
            },
            .assert => |as| {
                const pass = switch (as.kind) {
                    .word_boundary => boundary_ambig or (prev_kind != next_kind),
                    .not_word_boundary => boundary_ambig or (prev_kind == next_kind),
                    else => return false,
                };
                if (pass) {
                    if (sp >= stack.len) return false;
                    stack[sp] = .{ .pc = as.out, .ambig = item.ambig or boundary_ambig };
                    sp += 1;
                }
            },
            .match, .match_id => {
                out.delayed_match = true;
                if (item.ambig) out.ambiguous_match = true;
            },
            .byte, .any, .any_cont, .class, .unicode_class => {
                const pc16: u16 = @intCast(pc);
                if (std.mem.findScalar(u16, out.pcs[0..out.len], pc16)) |existing| {
                    if (item.ambig) out.from_ambig[existing] = true;
                } else {
                    if (out.len >= max_closure_pcs) return false;
                    out.pcs[out.len] = pc16;
                    out.from_ambig[out.len] = item.ambig;
                    out.len += 1;
                }
            },
        }
    }
    return true;
}

/// Ahead-of-time unanchored search DFA with compact `ByteClasses`, pre-scaled state offsets,
/// exact ASCII `\b`/`\B` look-around tracking, and SIMD start-state skipping.
///
/// State layout (pre-scaled by `stride`):
///   - `0 .. start_max_off`: start-family states (`start_nonword = 0`, optional `start_word`, `start_maybe_word`).
///   - `start_max_off + stride .. match_start_off - stride`: active non-accepting states.
///   - `>= match_start_off`: 4 accepting sink IDs (never indexed into `trans`):
///       * `verify_imm_off = match_start_off + 0`: candidate match ending at `pos` (requires Phase-2 PikeVM)
///       * `verify_del_off = match_start_off + 1`: 1-byte delayed candidate match ending at `pos - 1` (PikeVM)
///       * `exact_imm_off  = match_start_off + 2`: exact match ending at `pos` (0 PikeVM calls in `findEnd`)
///       * `exact_del_off  = match_start_off + 3`: exact 1-byte delayed match ending at `pos - 1` (0 PikeVM calls)
pub const UnanchoredDfa = struct {
    pub const max_non_match_states: u16 = 250;

    /// Byte-to-equivalence-class map (`classes[b] < stride`).
    classes: [256]u8 = @splat(0),
    /// Inline compact transition table when `exact_del_off <= 255` (`use_u8 == true`).
    trans_u8: [256]u8 = @splat(0),
    /// Heap-allocated pre-scaled transition table when `!use_u8` (`len == match_start_off`).
    trans_u16: []u16 = &.{},
    /// End-of-input (EOF / NUL-limit) acceptance status indexed by unscaled non-match state ID.
    eoi_kind: [256]EoiKind = @splat(.none),
    num_states: u16 = 0,
    num_non_match: u16 = 0,
    stride: u16 = 1,
    use_u8: bool = true,
    start_word_off: u16 = 0,
    start_maybe_off: u16 = 0,
    start_max_off: u16 = 0,
    match_start_off: u16 = 255,
    verify_imm_off: u16 = 252,
    verify_del_off: u16 = 253,
    exact_imm_off: u16 = 254,
    exact_del_off: u16 = 255,
    has_word_boundary: bool = false,
    has_exact_match: bool = false,
    /// True if any non-empty NFA move can land back inside `start_state`'s PC set (e.g., `(ab)*c`).
    /// When false, `curr_state <= start_max_off` guarantees no match from an earlier offset survived.
    start_reentrant: bool = false,
    /// Precomputed SIMD skip descriptor for start-family self-looping bytes.
    start_skip: StartSkip = .none,

    pub fn deinit(self: *UnanchoredDfa, allocator: std.mem.Allocator) void {
        if (self.trans_u16.len != 0) {
            allocator.free(self.trans_u16);
            self.trans_u16 = &.{};
        }
    }

    pub inline fn startStateForByte(self: *const UnanchoredDfa, b: u8) u16 {
        if (!self.has_word_boundary) return 0;
        if (b >= 0x80) return self.start_maybe_off;
        if (isAsciiWord(b)) return self.start_word_off;
        return 0;
    }

    pub inline fn startStateAt(self: *const UnanchoredDfa, haystack: []const u8, pos: usize) u16 {
        if (pos == 0 or !self.has_word_boundary) return 0;
        return self.startStateForByte(haystack[pos - 1]);
    }

    pub fn determinize(
        self: *UnanchoredDfa,
        allocator: std.mem.Allocator,
        insts: []const Inst,
        unicode_ranges: []const UnicodeRangeList,
        start_pc: u32,
        multiline: bool,
        max_states_cap: u16,
    ) bool {
        self.deinit(allocator);
        const cap: u16 = @min(max_non_match_states, max_states_cap);
        if (cap < 4 or insts.len == 0) return false;

        // Zero-length match or unmatchable empty closure stays on PikeVM
        var zero_pcs: [max_closure_pcs]u16 = undefined;
        var zero_len: u8 = 0;
        var zero_match = false;
        if (!computeEpsilonClosure(insts, start_pc, &zero_pcs, &zero_len, &zero_match)) return false;
        if (zero_match or zero_len == 0) return false;

        if (!multiline and isExactOnAsciiWithWordBoundary(insts)) {
            if (self.determinizeExact(allocator, insts, unicode_ranges, start_pc, cap)) {
                return true;
            }
            self.deinit(allocator);
        }
        return self.determinizeLegacy(allocator, insts, unicode_ranges, start_pc, multiline, cap);
    }

    const raw_verify_imm: u16 = 0xFFFC;
    const raw_verify_del: u16 = 0xFFFD;
    const raw_exact_imm: u16 = 0xFFFE;
    const raw_exact_del: u16 = 0xFFFF;

    fn determinizeExact(
        self: *UnanchoredDfa,
        allocator: std.mem.Allocator,
        insts: []const Inst,
        unicode_ranges: []const UnicodeRangeList,
        start_pc: u32,
        cap: u16,
    ) bool {
        var has_wb = false;
        for (insts) |inst| {
            if (inst == .assert) {
                has_wb = true;
                break;
            }
        }
        const all_bytes_exact = !has_wb and isExactInsts(insts);

        var start_pcs: [max_closure_pcs]u16 = undefined;
        var start_len: u8 = 0;
        var start_match = false;
        if (!computeClosureStopAtAssert(insts, start_pc, &start_pcs, &start_len, &start_match)) return false;
        if (start_match or start_len == 0) return false;
        sortU16(start_pcs[0..start_len]);

        const Meta = struct {
            pcs: [max_closure_pcs]u16 = undefined,
            pc_len: u8 = 0,
            prev_kind: WordKind = .nonword,
            dirty: bool = false,
        };

        const meta = allocator.alloc(Meta, cap) catch return false;
        defer allocator.free(meta);
        const raw_trans = allocator.alloc([256]u16, cap) catch return false;
        defer allocator.free(raw_trans);

        const num_starts: u16 = if (has_wb) 3 else 1;
        if (num_starts >= cap) return false;

        meta[0] = .{ .pcs = start_pcs, .pc_len = start_len, .prev_kind = .nonword, .dirty = false };
        if (has_wb) {
            meta[1] = .{ .pcs = start_pcs, .pc_len = start_len, .prev_kind = .word, .dirty = false };
            meta[2] = .{ .pcs = start_pcs, .pc_len = start_len, .prev_kind = .maybe, .dirty = false };
        }

        var num_non_match: u16 = num_starts;
        var start_reentrant = false;
        var saw_exact = false;
        var eoi_tmp: [256]EoiKind = @splat(.none);

        var q_head: u16 = 0;
        while (q_head < num_non_match) : (q_head += 1) {
            const src_meta = meta[q_head];
            const src_pcs = src_meta.pcs[0..src_meta.pc_len];

            // Precompute EOI (next_kind = .nonword) acceptance for this non-match state
            var eoi_res = ResolvedBoundary{};
            if (!resolveAssertsAtBoundary(insts, src_pcs, src_meta.prev_kind, .nonword, &eoi_res)) return false;
            if (eoi_res.delayed_match) {
                if (src_meta.dirty or eoi_res.ambiguous_match) {
                    eoi_tmp[q_head] = .verify;
                } else {
                    eoi_tmp[q_head] = .exact;
                    saw_exact = true;
                }
            } else {
                eoi_tmp[q_head] = .none;
            }

            // Pre-resolve boundary assertions for each of the 3 possible next WordKinds (nonword, word, maybe)
            var resolved: [3]ResolvedBoundary = .{ .{}, .{}, .{} };
            for (0..3) |wk_idx| {
                const nk: WordKind = @enumFromInt(wk_idx);
                if (!resolveAssertsAtBoundary(insts, src_pcs, src_meta.prev_kind, nk, &resolved[wk_idx])) return false;
            }

            var b_idx: u16 = 0;
            while (b_idx < 256) : (b_idx += 1) {
                const byte: u8 = @truncate(b_idx);
                const nk = byteWordKind(byte);
                const res = &resolved[@intFromEnum(nk)];

                // Step 1: Delayed match from pending `\b`/`\B` resolved BEFORE consuming `byte`
                if (res.delayed_match) {
                    if (src_meta.dirty or res.ambiguous_match) {
                        raw_trans[q_head][byte] = raw_verify_del;
                    } else {
                        raw_trans[q_head][byte] = raw_exact_del;
                        saw_exact = true;
                    }
                    continue;
                }

                // Step 2: Consume `byte` (in single-line mode, `\n` kills all active consuming threads)
                if (byte == '\n') {
                    raw_trans[q_head]['\n'] = 0; // start_nonword
                    continue;
                }

                var next_pcs: [max_closure_pcs]u16 = undefined;
                var next_len: u8 = 0;
                var next_imm_match = false;
                var next_used_ambig = false;

                for (res.pcs[0..res.len], 0..) |pc_u16, r_idx| {
                    var matched_byte = false;
                    var target_pc: u32 = 0;
                    switch (insts[pc_u16]) {
                        .byte => |by| {
                            matched_byte = if (by.ignore_case)
                                std.ascii.toLower(byte) == std.ascii.toLower(by.b)
                            else
                                byte == by.b;
                            target_pc = by.out;
                        },
                        .any_cont => |ac| {
                            matched_byte = (byte & 0xC0) == 0x80;
                            target_pc = ac.out;
                        },
                        .class => |cl| {
                            if (cl.utf8_negated and byte >= 0x80) {
                                matched_byte = true;
                                target_pc = if (byte >= 0xC2 and byte <= 0xDF)
                                    (if (cl.cont1 != 0) cl.cont1 else cl.out)
                                else if (byte >= 0xE0 and byte <= 0xEF)
                                    (if (cl.cont2 != 0) cl.cont2 else cl.out)
                                else if (byte >= 0xF0 and byte <= 0xF4)
                                    (if (cl.cont3 != 0) cl.cont3 else cl.out)
                                else
                                    cl.out;
                            } else if (cl.set.contains(byte)) {
                                matched_byte = true;
                                target_pc = cl.out;
                            }
                        },
                        .unicode_class => |uc| {
                            if (byte < 0x80) {
                                const ranges = unicode_ranges[uc.range_idx].ranges;
                                const in_set = (uc.has_ascii_set and uc.ascii_set.contains(byte)) or inRanges(byte, ranges);
                                matched_byte = if (uc.negated) !in_set else in_set;
                                target_pc = uc.out;
                            } else if (byte >= 0xC2 and byte <= 0xF4) {
                                matched_byte = true;
                                target_pc = if (byte <= 0xDF)
                                    (if (uc.cont1 != 0) uc.cont1 else uc.out)
                                else if (byte <= 0xEF)
                                    (if (uc.cont2 != 0) uc.cont2 else uc.out)
                                else
                                    (if (uc.cont3 != 0) uc.cont3 else uc.out);
                            }
                        },
                        else => {},
                    }
                    if (matched_byte) {
                        if (res.from_ambig[r_idx]) next_used_ambig = true;
                        if (!computeClosureStopAtAssert(insts, target_pc, &next_pcs, &next_len, &next_imm_match)) return false;
                    }
                }

                const byte_dirty = (!all_bytes_exact and byte >= 0x80);
                if (next_imm_match) {
                    if (src_meta.dirty or next_used_ambig or byte_dirty) {
                        raw_trans[q_head][byte] = raw_verify_imm;
                    } else {
                        raw_trans[q_head][byte] = raw_exact_imm;
                        saw_exact = true;
                    }
                    continue;
                }

                const clean_start_id: u16 = if (!has_wb) 0 else switch (nk) {
                    .nonword => 0,
                    .word => 1,
                    .maybe => 2,
                };
                if (next_len == 0) {
                    raw_trans[q_head][byte] = clean_start_id;
                    continue;
                }

                if (!start_reentrant) {
                    if (isSubsetU16(next_pcs[0..next_len], start_pcs[0..start_len])) {
                        start_reentrant = true;
                    }
                }

                // Union `start_pcs` so a new match can begin at every byte offset
                for (start_pcs[0..start_len]) |sp| {
                    if (std.mem.findScalar(u16, next_pcs[0..next_len], sp) == null) {
                        if (next_len >= max_closure_pcs) return false;
                        next_pcs[next_len] = sp;
                        next_len += 1;
                    }
                }
                sortU16(next_pcs[0..next_len]);

                const next_dirty = src_meta.dirty or next_used_ambig or byte_dirty;
                const next_prev_kind: WordKind = if (has_wb) nk else .nonword;

                var found_id: ?u16 = null;
                for (0..num_non_match) |idx| {
                    if (meta[idx].prev_kind == next_prev_kind and
                        meta[idx].dirty == next_dirty and
                        meta[idx].pc_len == next_len and
                        std.mem.eql(u16, meta[idx].pcs[0..next_len], next_pcs[0..next_len]))
                    {
                        found_id = @intCast(idx);
                        break;
                    }
                }
                if (found_id) |fid| {
                    raw_trans[q_head][byte] = fid;
                } else {
                    if (num_non_match >= cap) return false;
                    const new_id = num_non_match;
                    meta[new_id] = .{
                        .pcs = next_pcs,
                        .pc_len = next_len,
                        .prev_kind = next_prev_kind,
                        .dirty = next_dirty,
                    };
                    num_non_match += 1;
                    raw_trans[q_head][byte] = new_id;
                }
            }
        }

        return self.finalizeTables(allocator, raw_trans[0..num_non_match], &eoi_tmp, num_non_match, num_starts, has_wb, saw_exact, start_reentrant);
    }

    fn determinizeLegacy(
        self: *UnanchoredDfa,
        allocator: std.mem.Allocator,
        insts: []const Inst,
        unicode_ranges: []const UnicodeRangeList,
        start_pc: u32,
        multiline: bool,
        cap: u16,
    ) bool {
        const Meta = struct {
            pcs: [max_closure_pcs]u16 = undefined,
            pc_len: u8 = 0,
        };
        const meta = allocator.alloc(Meta, cap) catch return false;
        defer allocator.free(meta);
        const raw_trans = allocator.alloc([256]u16, cap) catch return false;
        defer allocator.free(raw_trans);

        var start_pcs: [max_closure_pcs]u16 = undefined;
        var start_len: u8 = 0;
        var start_match = false;
        if (!computeEpsilonClosure(insts, start_pc, &start_pcs, &start_len, &start_match)) return false;
        if (start_match or start_len == 0) return false;
        sortU16(start_pcs[0..start_len]);

        meta[0] = .{ .pcs = start_pcs, .pc_len = start_len };
        var num_non_match: u16 = 1;
        var start_reentrant = false;

        var q_head: u16 = 0;
        while (q_head < num_non_match) : (q_head += 1) {
            const src_len = meta[q_head].pc_len;
            const src_pcs = meta[q_head].pcs[0..src_len];

            var b_idx: u16 = 0;
            while (b_idx < 256) : (b_idx += 1) {
                const byte: u8 = @truncate(b_idx);
                if (!multiline and byte == '\n') {
                    raw_trans[q_head]['\n'] = 0;
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

                if (next_is_match) {
                    raw_trans[q_head][byte] = raw_verify_imm;
                    continue;
                }
                if (next_len == 0) {
                    raw_trans[q_head][byte] = 0;
                    continue;
                }
                if (!start_reentrant) {
                    if (isSubsetU16(next_pcs[0..next_len], start_pcs[0..start_len])) {
                        start_reentrant = true;
                    }
                }
                for (start_pcs[0..start_len]) |sp| {
                    if (std.mem.findScalar(u16, next_pcs[0..next_len], sp) == null) {
                        if (next_len >= max_closure_pcs) return false;
                        next_pcs[next_len] = sp;
                        next_len += 1;
                    }
                }
                sortU16(next_pcs[0..next_len]);

                var found_id: ?u16 = null;
                for (0..num_non_match) |idx| {
                    if (meta[idx].pc_len == next_len and
                        std.mem.eql(u16, meta[idx].pcs[0..next_len], next_pcs[0..next_len]))
                    {
                        found_id = @intCast(idx);
                        break;
                    }
                }
                if (found_id) |fid| {
                    raw_trans[q_head][byte] = fid;
                } else {
                    if (num_non_match >= cap) return false;
                    const new_id = num_non_match;
                    meta[new_id] = .{ .pcs = next_pcs, .pc_len = next_len };
                    num_non_match += 1;
                    raw_trans[q_head][byte] = new_id;
                }
            }
        }

        const eoi_none: [256]EoiKind = @splat(.none);
        return self.finalizeTables(allocator, raw_trans[0..num_non_match], &eoi_none, num_non_match, 1, false, false, start_reentrant);
    }

    fn finalizeTables(
        self: *UnanchoredDfa,
        allocator: std.mem.Allocator,
        raw_trans: []const [256]u16,
        eoi_tmp: *const [256]EoiKind,
        num_non_match: u16,
        num_starts: u16,
        has_wb: bool,
        has_exact: bool,
        start_reentrant: bool,
    ) bool {
        // 1. Compute byte equivalence classes across all non-match states
        var classes: [256]u8 = undefined;
        var rep_bytes: [256]u8 = undefined;
        var num_classes: u16 = 0;

        for (0..256) |b_usize| {
            const b: u8 = @intCast(b_usize);
            var found: ?u8 = null;
            for (0..num_classes) |c| {
                const rb = rep_bytes[c];
                var same = true;
                for (0..num_non_match) |s| {
                    if (raw_trans[s][b] != raw_trans[s][rb]) {
                        same = false;
                        break;
                    }
                }
                if (same) {
                    found = @intCast(c);
                    break;
                }
            }
            if (found) |cid| {
                classes[b] = cid;
            } else {
                classes[b] = @intCast(num_classes);
                rep_bytes[num_classes] = b;
                num_classes += 1;
            }
        }

        const stride: u16 = num_classes;
        const total_entries_u32: u32 = @as(u32, num_non_match) * @as(u32, stride);
        if (total_entries_u32 + 4 > std.math.maxInt(u16)) return false;

        const match_start_off: u16 = @intCast(total_entries_u32);
        const verify_imm_off: u16 = match_start_off + 0;
        const verify_del_off: u16 = match_start_off + 1;
        const exact_imm_off: u16 = match_start_off + 2;
        const exact_del_off: u16 = match_start_off + 3;
        const use_u8 = exact_del_off <= 255;

        // 2. Build compact pre-scaled transition table
        if (use_u8) {
            self.trans_u16 = &.{};
            for (0..num_non_match) |s| {
                const row_off = s * stride;
                for (0..num_classes) |c| {
                    const rb = rep_bytes[c];
                    const dst = raw_trans[s][rb];
                    const enc: u16 = switch (dst) {
                        raw_verify_imm => verify_imm_off,
                        raw_verify_del => verify_del_off,
                        raw_exact_imm => exact_imm_off,
                        raw_exact_del => exact_del_off,
                        else => dst * stride,
                    };
                    self.trans_u8[row_off + c] = @intCast(enc);
                }
            }
        } else {
            const tbl = allocator.alloc(u16, match_start_off) catch return false;
            for (0..num_non_match) |s| {
                const row_off = s * stride;
                for (0..num_classes) |c| {
                    const rb = rep_bytes[c];
                    const dst = raw_trans[s][rb];
                    const enc: u16 = switch (dst) {
                        raw_verify_imm => verify_imm_off,
                        raw_verify_del => verify_del_off,
                        raw_exact_imm => exact_imm_off,
                        raw_exact_del => exact_del_off,
                        else => dst * stride,
                    };
                    tbl[row_off + c] = enc;
                }
            }
            self.trans_u16 = tbl;
        }

        // 3. Analyze start-family exit bytes to select optimal SIMD StartSkip strategy
        var exits: [4]u8 = undefined;
        var exit_count: usize = 0;
        var ranges: [4]ByteRange = undefined;
        var num_ranges: usize = 0;
        var in_run = false;
        var run_lo: u8 = 0;

        var b_scan: u16 = 0;
        while (b_scan < 256) : (b_scan += 1) {
            const byte: u8 = @truncate(b_scan);
            var is_exit = false;
            for (0..num_starts) |u| {
                if (raw_trans[u][byte] >= num_starts) {
                    is_exit = true;
                    break;
                }
            }
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

        self.classes = classes;
        self.eoi_kind = eoi_tmp.*;
        self.num_non_match = num_non_match;
        self.num_states = num_non_match + 4;
        self.stride = stride;
        self.use_u8 = use_u8;
        self.has_word_boundary = has_wb;
        self.has_exact_match = has_exact;
        self.start_word_off = if (has_wb) stride else 0;
        self.start_maybe_off = if (has_wb) 2 * stride else 0;
        self.start_max_off = if (has_wb) 2 * stride else 0;
        self.match_start_off = match_start_off;
        self.verify_imm_off = verify_imm_off;
        self.verify_del_off = verify_del_off;
        self.exact_imm_off = exact_imm_off;
        self.exact_del_off = exact_del_off;
        self.start_reentrant = start_reentrant;
        return true;
    }

    pub fn SkipVecs(comptime tag: StartSkipTag) type {
        const width = memchr.native_width;
        const V = @Vector(width, u8);
        return switch (tag) {
            .none => void,
            .byte1 => u8,
            .byte2 => [2]u8,
            .byte3 => [3]u8,
            .range1 => struct { lo: u8, sp: u8, v_lo: V, v_sp: V },
            .range2 => struct { r: [2]ByteRange, lo0: V, sp0: V, lo1: V, sp1: V },
            .range3 => struct { r: [3]ByteRange, lo0: V, sp0: V, lo1: V, sp1: V, lo2: V, sp2: V },
        };
    }

    pub inline fn initSkipVecs(comptime tag: StartSkipTag, skip: StartSkip) SkipVecs(tag) {
        return switch (tag) {
            .none => {},
            .byte1 => skip.byte1,
            .byte2 => skip.byte2,
            .byte3 => skip.byte3,
            .range1 => .{
                .lo = skip.range1.lo,
                .sp = skip.range1.span,
                .v_lo = @splat(skip.range1.lo),
                .v_sp = @splat(skip.range1.span),
            },
            .range2 => .{
                .r = skip.range2,
                .lo0 = @splat(skip.range2[0].lo),
                .sp0 = @splat(skip.range2[0].span),
                .lo1 = @splat(skip.range2[1].lo),
                .sp1 = @splat(skip.range2[1].span),
            },
            .range3 => .{
                .r = skip.range3,
                .lo0 = @splat(skip.range3[0].lo),
                .sp0 = @splat(skip.range3[0].span),
                .lo1 = @splat(skip.range3[1].lo),
                .sp1 = @splat(skip.range3[1].span),
                .lo2 = @splat(skip.range3[2].lo),
                .sp2 = @splat(skip.range3[2].span),
            },
        };
    }

    pub inline fn skipStartVec(
        comptime tag: StartSkipTag,
        vecs: SkipVecs(tag),
        haystack: []const u8,
        from: usize,
        limit: usize,
    ) ?usize {
        const width = memchr.native_width;
        const V = @Vector(width, u8);
        switch (tag) {
            .none => return from,
            .byte1 => return memchr.find(width, haystack[0..limit], from, vecs),
            .byte2 => return memchr.findEither(width, haystack[0..limit], from, vecs[0], vecs[1]),
            .byte3 => {
                const hit = memchr.findAny(width, haystack[0..limit], from, vecs[0], vecs[1], vecs[2]) orelse return null;
                return hit.index;
            },
            .range1 => {
                var i = from;
                while (i + width <= limit) : (i += width) {
                    const v: V = haystack[i..][0..width].*;
                    const m = (v -% vecs.v_lo) <= vecs.v_sp;
                    if (firstMaskBit(width, m)) |rel| return i + rel;
                }
                while (i < limit) : (i += 1) {
                    if ((haystack[i] -% vecs.lo) <= vecs.sp) return i;
                }
                return null;
            },
            .range2 => {
                var i = from;
                while (i + width <= limit) : (i += width) {
                    const v: V = haystack[i..][0..width].*;
                    const m = ((v -% vecs.lo0) <= vecs.sp0) | ((v -% vecs.lo1) <= vecs.sp1);
                    if (firstMaskBit(width, m)) |rel| return i + rel;
                }
                while (i < limit) : (i += 1) {
                    const b = haystack[i];
                    if ((b -% vecs.r[0].lo) <= vecs.r[0].span or (b -% vecs.r[1].lo) <= vecs.r[1].span) return i;
                }
                return null;
            },
            .range3 => {
                var i = from;
                while (i + width <= limit) : (i += width) {
                    const v: V = haystack[i..][0..width].*;
                    const m = ((v -% vecs.lo0) <= vecs.sp0) | ((v -% vecs.lo1) <= vecs.sp1) | ((v -% vecs.lo2) <= vecs.sp2);
                    if (firstMaskBit(width, m)) |rel| return i + rel;
                }
                while (i < limit) : (i += 1) {
                    const b = haystack[i];
                    if ((b -% vecs.r[0].lo) <= vecs.r[0].span or (b -% vecs.r[1].lo) <= vecs.r[1].span or (b -% vecs.r[2].lo) <= vecs.r[2].span) return i;
                }
                return null;
            },
        }
    }

    pub inline fn skipStartBytes(self: *const UnanchoredDfa, haystack: []const u8, from: usize, limit: usize) ?usize {
        return switch (self.start_skip) {
            inline else => |_, tag| skipStartVec(tag, initSkipVecs(tag, self.start_skip), haystack, from, limit),
        };
    }
};
