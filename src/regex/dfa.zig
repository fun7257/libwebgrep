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
        /// Number of contiguous linear single-successor non-match states (`s -> s+1 -> ... -> s+L`) starting at `s`.
        chain_len: [max_states_cap]u8 = @splat(0),
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
            self.chain_len = @splat(0);
            if (self.flushes == 0 and self.bailouts == 0 and self.num_states > 2) {
                var s_idx: usize = self.num_states - 1;
                while (s_idx >= 1) : (s_idx -= 1) {
                    const s: u16 = @intCast(s_idx);
                    if (!self.is_match[s] and s + 1 < self.num_states) {
                        const target: u16 = s + 1;
                        var only_target = true;
                        var has_target = false;
                        for (self.trans[s]) |t| {
                            if (t == target) {
                                has_target = true;
                            } else if (t != dead_state) {
                                only_target = false;
                                break;
                            }
                        }
                        if (only_target and has_target) {
                            self.chain_len[s] = @min(@as(u8, 64), 1 +| self.chain_len[target]);
                        }
                    }
                    if (s_idx == 1) break;
                }
            }
            return self.flushes == 0 and self.bailouts == 0;
        }

        /// Fast single-branch prefix matcher on a fully determinized DFA (`determinize() == true`).
        /// Returns the longest greedy match length starting at `slice[0]`, or `null` if no match.
        pub inline fn matchPrefixDeterminized(
            self: *const Self,
            slice: []const u8,
            start_state_id: u16,
            prefix_offset: usize,
        ) ?usize {
            if (prefix_offset > slice.len) return null;
            const rem = slice[prefix_offset..];
            var curr_state: u16 = start_state_id;
            var last_match: ?usize = if (self.is_match[curr_state]) prefix_offset else null;
            var idx: usize = 0;
            while (idx < rem.len) {
                const clen: usize = self.chain_len[curr_state];
                if (clen >= 2) {
                    if (idx + clen > rem.len) break;
                    const p = rem[idx..][0..clen];
                    const base_s: usize = curr_state;
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
                    curr_state = @intCast(base_s + clen);
                    idx += clen;
                    if (self.is_match[curr_state]) {
                        last_match = prefix_offset + idx;
                    }
                    continue;
                }
                curr_state = self.trans[curr_state][rem[idx]];
                idx += 1;
                if (curr_state == dead_state) break;
                if (self.is_match[curr_state]) {
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

        var seen = false;
        for (visited_pcs[0..visited_len]) |v| {
            if (v == pc) {
                seen = true;
                break;
            }
        }
        if (seen) continue;
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
                var already_in_out = false;
                for (out_pcs[0..out_len.*]) |existing| {
                    if (existing == pc16) {
                        already_in_out = true;
                        break;
                    }
                }
                if (!already_in_out) {
                    if (out_len.* >= max_closure_pcs) return false;
                    out_pcs[out_len.*] = pc16;
                    out_len.* += 1;
                }
            },
        }
    }
    return true;
}
