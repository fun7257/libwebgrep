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

pub fn BoundedDfa(comptime max_states_cap: u16) type {
    return struct {
        const Self = @This();
        pub const max_states: u16 = max_states_cap;

        pub const State = struct {
            pcs: [max_closure_pcs]u16 = undefined,
            pc_len: u8 = 0,
            is_match: bool = false,
            next: [256]u16 = @splat(unknown_transition),
        };

        states: [max_states_cap]State = undefined,
        num_states: u16 = 0,
        flushes: u32 = 0,
        bailouts: u32 = 0,
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

        fn initBaseStates(self: *Self, insts: []const Inst, start_pc: u32) bool {
            // State 0: dead state (all transitions loop to dead_state)
            self.states[dead_state] = .{
                .pc_len = 0,
                .is_match = false,
                .next = @splat(dead_state),
            };

            // State 1: start state (epsilon closure of start_pc)
            var pcs: [max_closure_pcs]u16 = undefined;
            var pc_len: u8 = 0;
            var is_match = false;
            if (!computeEpsilonClosure(insts, start_pc, &pcs, &pc_len, &is_match)) {
                self.bailouts +%= 1;
                self.num_states = 0;
                return false;
            }
            self.states[start_state] = .{
                .pcs = pcs,
                .pc_len = pc_len,
                .is_match = is_match,
                .next = @splat(unknown_transition),
            };
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
            const cached = self.states[state_id].next[b];
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

            const src_len = self.states[state_id].pc_len;
            var src_pcs: [max_closure_pcs]u16 = undefined;
            @memcpy(src_pcs[0..src_len], self.states[state_id].pcs[0..src_len]);

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
                                self.states[state_id].next[b] = bailout_transition;
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
                            self.states[state_id].next[b] = bailout_transition;
                            return bailout_transition;
                        }
                    },
                    .any_cont => |ac| {
                        if ((b & 0xC0) == 0x80) {
                            if (!computeEpsilonClosure(insts, ac.out, &next_pcs, &next_len, &next_is_match)) {
                                self.bailouts +%= 1;
                                self.states[state_id].next[b] = bailout_transition;
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
                                self.states[state_id].next[b] = bailout_transition;
                                return bailout_transition;
                            }
                            continue;
                        }
                        if (cl.set.contains(b)) {
                            if (!computeEpsilonClosure(insts, cl.out, &next_pcs, &next_len, &next_is_match)) {
                                self.bailouts +%= 1;
                                self.states[state_id].next[b] = bailout_transition;
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
                                    self.states[state_id].next[b] = bailout_transition;
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
                                self.states[state_id].next[b] = bailout_transition;
                                return bailout_transition;
                            }
                        }
                    },
                    .match, .match_id, .split, .jmp, .assert, .save => {},
                }
            }

            _ = multiline;
            if (next_len == 0 and !next_is_match) {
                self.states[state_id].next[b] = dead_state;
                return dead_state;
            }

            // Deduplicate against existing DFA states
            for (self.states[1..self.num_states], 1..) |*st, idx| {
                if (st.pc_len == next_len and st.is_match == next_is_match and
                    std.mem.eql(u16, st.pcs[0..next_len], next_pcs[0..next_len]))
                {
                    const found_id: u16 = @intCast(idx);
                    self.states[state_id].next[b] = found_id;
                    return found_id;
                }
            }

            // If state cache is full, flush in O(1) by resetting to base states (0 and 1)
            var actual_src = state_id;
            if (self.num_states >= self.effective_max_states) {
                self.flushes +%= 1;
                _ = self.initBaseStates(insts, self.compiled_start_pc);
                // Re-insert the source state if it was not start_state
                if (state_id != start_state) {
                    const reloaded_src = self.num_states;
                    self.states[reloaded_src] = .{
                        .pcs = src_pcs,
                        .pc_len = src_len,
                        .is_match = false,
                        .next = @splat(unknown_transition),
                    };
                    self.num_states += 1;
                    actual_src = reloaded_src;
                } else {
                    actual_src = start_state;
                }
            }

            const new_id = self.num_states;
            self.states[new_id] = .{
                .pcs = next_pcs,
                .pc_len = next_len,
                .is_match = next_is_match,
                .next = @splat(unknown_transition),
            };
            self.num_states += 1;
            self.states[actual_src].next[b] = new_id;
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
