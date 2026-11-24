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
/// additionally allowing `.any` (caller checks `isAsciiBytes` and, when `!allow_nl`, no `\r`).
pub fn isExactOnAsciiAnyInsts(insts: []const Inst) bool {
    for (insts) |inst| {
        switch (inst) {
            .byte, .split, .jmp, .save, .match, .match_id, .any, .any_cont => {},
            .class => |cl| {
                if (cl.utf8_negated) return false;
            },
            .unicode_class => |uc| {
                if (uc.ignore_case) return false;
            },
            .assert => return false,
        }
    }
    return true;
}

/// Returns true when every NFA transition is exact on pure ASCII slices (`b < 0x80`),
/// additionally allowing `\b` and `\B` (Unicode or ASCII) word-boundary assertions (tracked directly in `UnanchoredDfa`).
pub fn isExactOnAsciiWithWordBoundary(insts: []const Inst) bool {
    for (insts) |inst| {
        switch (inst) {
            .byte, .split, .jmp, .save, .match, .match_id, .any_cont => {},
            .class => {},
            .unicode_class => |uc| {
                if (uc.ignore_case) return false;
            },
            .assert => |as| {
                if (as.kind != .word_boundary and as.kind != .not_word_boundary and
                    as.kind != .ascii_word_boundary and as.kind != .not_ascii_word_boundary)
                {
                    return false;
                }
            },
            .any => return false,
        }
    }
    return true;
}

/// Returns true when every NFA transition is exact for ALL bytes 0..255 (including `>= 0x80`),
/// allowing ASCII word-boundary assertions (where `b >= 0x80` is unconditionally non-word).
fn isExactBytesAllowAsciiWb(insts: []const Inst) bool {
    for (insts) |inst| {
        switch (inst) {
            .byte, .split, .jmp, .save, .match, .match_id => {},
            .class => |cl| {
                if (cl.utf8_negated) return false;
            },
            .assert => |as| {
                if (as.kind != .ascii_word_boundary and as.kind != .not_ascii_word_boundary) return false;
            },
            .unicode_class, .any, .any_cont => return false,
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
            if (!self.has_loop_exits) {
                var idx: usize = 0;
                while (idx < rem.len) {
                    const clen: usize = self.chain_len[curr_state];
                    if (clen >= 2) {
                        if (!self.matchLinearChain(rem, idx, curr_state, clen)) break;
                        curr_state = @intCast(@as(usize, curr_state) + clen);
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
            return self.matchPrefixDeterminizedWithLoopExits(rem, curr_state, prefix_offset, earliest, last_match);
        }

        inline fn matchLinearChain(
            self: *const Self,
            rem: []const u8,
            idx: usize,
            curr_state: u16,
            clen: usize,
        ) bool {
            if (idx + clen > rem.len) return false;
            const p = rem[idx..][0..clen];
            const base_s: usize = curr_state;
            const u_span = self.chain_uniform_span[curr_state];
            if (u_span != 0xFF) {
                const u_lo = self.chain_uniform_lo[curr_state];
                if ((p[clen - 1] -% u_lo) > u_span or (p[clen - 2] -% u_lo) > u_span) {
                    return false;
                }
                for (p[0 .. clen - 2]) |ch| {
                    if ((ch -% u_lo) > u_span) return false;
                }
                return true;
            } else {
                if (self.trans[base_s + clen - 1][p[clen - 1]] == dead_state or
                    self.trans[base_s + clen - 2][p[clen - 2]] == dead_state)
                {
                    return false;
                }
                var k: usize = 0;
                const limit4 = (clen - 2) & ~@as(usize, 3);
                while (k < limit4) : (k += 4) {
                    const t0 = self.trans[base_s + k][p[k]];
                    const t1 = self.trans[base_s + k + 1][p[k + 1]];
                    const t2 = self.trans[base_s + k + 2][p[k + 2]];
                    const t3 = self.trans[base_s + k + 3][p[k + 3]];
                    if ((t0 == dead_state) or (t1 == dead_state) or (t2 == dead_state) or (t3 == dead_state)) {
                        return false;
                    }
                }
                while (k < clen - 2) : (k += 1) {
                    if (self.trans[base_s + k][p[k]] == dead_state) return false;
                }
                return true;
            }
        }

        noinline fn matchPrefixDeterminizedWithLoopExits(
            self: *const Self,
            rem: []const u8,
            start_state_id: u16,
            prefix_offset: usize,
            earliest: bool,
            init_last_match: ?usize,
        ) ?usize {
            var curr_state: u16 = start_state_id;
            var last_match: ?usize = init_last_match;
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
                    if (!self.matchLinearChain(rem, idx, curr_state, clen)) break;
                    curr_state = @intCast(@as(usize, curr_state) + clen);
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
                const res_a: struct { pass: bool, adds_ambig: bool } = switch (as.kind) {
                    .word_boundary => .{
                        .pass = boundary_ambig or (prev_kind != next_kind),
                        .adds_ambig = boundary_ambig,
                    },
                    .not_word_boundary => .{
                        .pass = boundary_ambig or (prev_kind == next_kind),
                        .adds_ambig = boundary_ambig,
                    },
                    .ascii_word_boundary => .{
                        .pass = (prev_kind == .word) != (next_kind == .word),
                        .adds_ambig = false,
                    },
                    .not_ascii_word_boundary => .{
                        .pass = (prev_kind == .word) == (next_kind == .word),
                        .adds_ambig = false,
                    },
                    else => return false,
                };
                if (res_a.pass) {
                    if (sp >= stack.len) return false;
                    stack[sp] = .{ .pc = as.out, .ambig = item.ambig or res_a.adds_ambig };
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
        var has_unicode_wb = false;
        for (insts) |inst| {
            if (inst == .assert) {
                has_wb = true;
                if (inst.assert.kind == .word_boundary or inst.assert.kind == .not_word_boundary) {
                    has_unicode_wb = true;
                }
            }
        }
        const all_bytes_exact = !has_unicode_wb and isExactBytesAllowAsciiWb(insts);

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

        const num_starts: u16 = if (has_unicode_wb) 3 else if (has_wb) 2 else 1;
        if (num_starts >= cap) return false;

        meta[0] = .{ .pcs = start_pcs, .pc_len = start_len, .prev_kind = .nonword, .dirty = false };
        if (num_starts >= 2) {
            meta[1] = .{ .pcs = start_pcs, .pc_len = start_len, .prev_kind = .word, .dirty = false };
        }
        if (num_starts >= 3) {
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

            // Pre-resolve boundary assertions for each possible next WordKind (nonword, word, optional maybe)
            var resolved: [3]ResolvedBoundary = .{ .{}, .{}, .{} };
            const nk_count: usize = if (has_unicode_wb) 3 else 2;
            for (0..nk_count) |wk_idx| {
                const nk: WordKind = @enumFromInt(wk_idx);
                if (!resolveAssertsAtBoundary(insts, src_pcs, src_meta.prev_kind, nk, &resolved[wk_idx])) return false;
            }

            var b_idx: u16 = 0;
            while (b_idx < 256) : (b_idx += 1) {
                const byte: u8 = @truncate(b_idx);
                const nk: WordKind = if (has_unicode_wb)
                    byteWordKind(byte)
                else if (byte < 0x80 and isAsciiWord(byte))
                    .word
                else
                    .nonword;
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
        self.start_word_off = if (num_starts >= 2) stride else 0;
        self.start_maybe_off = if (num_starts >= 3) 2 * stride else 0;
        self.start_max_off = (num_starts - 1) * stride;
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

// ============================================================================
// Multi-Pattern Byte Equivalence Classes & Two-Tier Unanchored Set DFA
// ============================================================================

/// Pre-determinization byte equivalence classes computed in O(`insts.len`) time.
/// Any two bytes assigned the same class ID behave identically across all instructions
/// in `insts` (including `\b`/`\B`/`.ascii_word_boundary`, UTF-8 byte kinds, and `\n`).
pub const ByteClasses = struct {
    map: [256]u8 = @splat(0),
    rep: [256]u8 = @splat(0),
    num_classes: u16 = 1,

    inline fn setBit(bounds: *[4]u64, b: u8) void {
        bounds[b >> 6] |= (@as(u64, 1) << @as(u6, @intCast(b & 63)));
    }

    inline fn markByte(bounds: *[4]u64, b: u8) void {
        if (b > 0) setBit(bounds, b - 1);
        if (b < 255) setBit(bounds, b);
    }

    inline fn markRange(bounds: *[4]u64, lo: u8, hi: u8) void {
        if (lo > 0) setBit(bounds, lo - 1);
        if (hi < 255) setBit(bounds, hi);
    }

    inline fn markByteSet(bounds: *[4]u64, set: inst_mod.ByteSet) void {
        for (0..4) |w| {
            const cur = set.bits[w];
            const next_lo: u64 = if (w < 3) (set.bits[w + 1] & 1) << 63 else 0;
            const shifted_right = (cur >> 1) | next_lo;
            bounds[w] |= (cur ^ shifted_right);
        }
    }

    inline fn markUtf8LeadRanges(bounds: *[4]u64) void {
        markRange(bounds, 0x80, 0xBF);
        markRange(bounds, 0xC0, 0xC1);
        markRange(bounds, 0xC2, 0xDF);
        markRange(bounds, 0xE0, 0xEF);
        markRange(bounds, 0xF0, 0xF4);
        markRange(bounds, 0xF5, 0xFF);
    }

    pub fn compute(
        insts: []const Inst,
        unicode_ranges: []const UnicodeRangeList,
        multiline: bool,
    ) ByteClasses {
        var bounds: [4]u64 = .{ 0, 0, 0, 0 };
        // Always separate ASCII (`0x00..0x7F`) from non-ASCII (`0x80..0xFF`)
        setBit(&bounds, 0x7F);
        if (!multiline) markByte(&bounds, '\n');

        var marked_utf8 = false;
        var marked_word = false;

        for (insts) |inst| {
            switch (inst) {
                .byte => |by| {
                    markByte(&bounds, by.b);
                    if (by.ignore_case) {
                        if (by.b >= 'A' and by.b <= 'Z') markByte(&bounds, by.b + 32);
                        if (by.b >= 'a' and by.b <= 'z') markByte(&bounds, by.b - 32);
                    }
                },
                .class => |cl| {
                    markByteSet(&bounds, cl.set);
                    if (cl.utf8_negated and !marked_utf8) {
                        markUtf8LeadRanges(&bounds);
                        marked_utf8 = true;
                    }
                },
                .any => |an| {
                    if (!an.allow_nl) markByte(&bounds, '\n');
                    if (!marked_utf8) {
                        markUtf8LeadRanges(&bounds);
                        marked_utf8 = true;
                    }
                },
                .any_cont => {
                    markRange(&bounds, 0x80, 0xBF);
                },
                .unicode_class => |uc| {
                    if (!uc.allow_nl) markByte(&bounds, '\n');
                    var ascii_bs = inst_mod.ByteSet{};
                    const ranges = unicode_ranges[uc.range_idx].ranges;
                    var b: u8 = 0;
                    while (b < 0x80) : (b += 1) {
                        const in_set = (uc.has_ascii_set and uc.ascii_set.contains(b)) or inRanges(b, ranges);
                        const matched = if (uc.negated) !in_set else in_set;
                        if (matched) ascii_bs.set(b);
                    }
                    markByteSet(&bounds, ascii_bs);
                    if (!marked_utf8) {
                        markUtf8LeadRanges(&bounds);
                        marked_utf8 = true;
                    }
                },
                .assert => |as| {
                    if ((as.kind == .word_boundary or as.kind == .not_word_boundary or
                        as.kind == .ascii_word_boundary or as.kind == .not_ascii_word_boundary) and !marked_word)
                    {
                        markRange(&bounds, '0', '9');
                        markRange(&bounds, 'A', 'Z');
                        markByte(&bounds, '_');
                        markRange(&bounds, 'a', 'z');
                        marked_word = true;
                    }
                },
                .split, .jmp, .save, .match, .match_id => {},
            }
        }

        var res = ByteClasses{};
        var cid: u16 = 0;
        var seen_first = false;
        for (0..256) |b_usize| {
            const b: u8 = @intCast(b_usize);
            res.map[b] = @intCast(cid);
            if (!seen_first) {
                res.rep[cid] = b;
                seen_first = true;
            }
            if (b < 255) {
                const bit = (bounds[b >> 6] >> @as(u6, @intCast(b & 63))) & 1;
                if (bit != 0) {
                    cid += 1;
                    seen_first = false;
                }
            }
        }
        res.num_classes = cid + 1;
        return res;
    }
};

fn sortAndDedupU32(list: *std.ArrayList(u32)) void {
    const items = list.items;
    if (items.len <= 1) return;
    if (items.len <= 16) {
        var i: usize = 1;
        while (i < items.len) : (i += 1) {
            const key = items[i];
            var j = i;
            while (j > 0 and items[j - 1] > key) : (j -= 1) {
                items[j] = items[j - 1];
            }
            items[j] = key;
        }
    } else {
        std.mem.sort(u32, items, {}, std.sort.asc(u32));
    }
    var write: usize = 1;
    for (items[1..]) |v| {
        if (v != items[write - 1]) {
            items[write] = v;
            write += 1;
        }
    }
    list.items.len = write;
}

fn isSubsetSortedU32(sub: []const u32, sup: []const u32) bool {
    var i: usize = 0;
    var j: usize = 0;
    while (i < sub.len and j < sup.len) {
        if (sub[i] == sup[j]) {
            i += 1;
            j += 1;
        } else if (sub[i] > sup[j]) {
            j += 1;
        } else {
            return false;
        }
    }
    return i == sub.len;
}

const DynStateMeta = struct {
    pc_off: u32,
    pc_len: u32,
    prev_kind: WordKind = .nonword,
    dirty: bool = false,
};

fn hashDynState(prev_kind: WordKind, dirty: bool, pcs: []const u32) u64 {
    var h: u64 = 0xcbf29ce484222325;
    h ^= @as(u64, @intFromEnum(prev_kind)) | (@as(u64, @intFromBool(dirty)) << 2);
    h *%= 0x100000001b3;
    for (pcs) |pc| {
        h ^= pc;
        h *%= 0x100000001b3;
    }
    return h;
}

const DynStateMap = struct {
    const empty_slot: u32 = std.math.maxInt(u32);

    slots: []u32 = &.{},
    count: usize = 0,

    fn init(allocator: std.mem.Allocator, initial_cap: usize) !DynStateMap {
        var cap: usize = 64;
        while (cap < initial_cap * 2) cap <<= 1;
        const slots = try allocator.alloc(u32, cap);
        @memset(slots, empty_slot);
        return .{ .slots = slots, .count = 0 };
    }

    fn deinit(self: *DynStateMap, allocator: std.mem.Allocator) void {
        if (self.slots.len != 0) allocator.free(self.slots);
        self.slots = &.{};
        self.count = 0;
    }

    fn clearRetainingCapacity(self: *DynStateMap) void {
        @memset(self.slots, empty_slot);
        self.count = 0;
    }

    fn find(
        self: *const DynStateMap,
        metas: []const DynStateMeta,
        pc_pool: []const u32,
        prev_kind: WordKind,
        dirty: bool,
        pcs: []const u32,
    ) ?u32 {
        if (self.slots.len == 0) return null;
        const mask = self.slots.len - 1;
        var idx: usize = @truncate(hashDynState(prev_kind, dirty, pcs) & mask);
        while (true) {
            const sid = self.slots[idx];
            if (sid == empty_slot) return null;
            const m = metas[sid];
            if (m.prev_kind == prev_kind and m.dirty == dirty and m.pc_len == pcs.len and
                std.mem.eql(u32, pc_pool[m.pc_off .. m.pc_off + m.pc_len], pcs))
            {
                return sid;
            }
            idx = (idx + 1) & mask;
        }
    }

    fn insert(
        self: *DynStateMap,
        allocator: std.mem.Allocator,
        metas: []const DynStateMeta,
        pc_pool: []const u32,
        sid: u32,
    ) !void {
        if ((self.count + 1) * 2 > self.slots.len) {
            const new_cap = @max(@as(usize, 64), self.slots.len * 2);
            const new_slots = try allocator.alloc(u32, new_cap);
            @memset(new_slots, empty_slot);
            const new_mask = new_cap - 1;
            for (self.slots) |existing| {
                if (existing == empty_slot) continue;
                const em = metas[existing];
                const epcs = pc_pool[em.pc_off .. em.pc_off + em.pc_len];
                var ni: usize = @truncate(hashDynState(em.prev_kind, em.dirty, epcs) & new_mask);
                while (new_slots[ni] != empty_slot) ni = (ni + 1) & new_mask;
                new_slots[ni] = existing;
            }
            if (self.slots.len != 0) allocator.free(self.slots);
            self.slots = new_slots;
        }
        const m = metas[sid];
        const pcs = pc_pool[m.pc_off .. m.pc_off + m.pc_len];
        const mask = self.slots.len - 1;
        var idx: usize = @truncate(hashDynState(m.prev_kind, m.dirty, pcs) & mask);
        while (self.slots[idx] != empty_slot) idx = (idx + 1) & mask;
        self.slots[idx] = sid;
        self.count += 1;
    }
};

const AssertStackItem = struct {
    pc: u32,
    ambig: bool,
};

const DynResolvedBoundary = struct {
    pcs: std.ArrayList(u32) = .empty,
    from_ambig: std.ArrayList(bool) = .empty,
    delayed_match: bool = false,
    clean_delayed_match: bool = false,

    fn clearRetainingCapacity(self: *DynResolvedBoundary) void {
        self.pcs.clearRetainingCapacity();
        self.from_ambig.clearRetainingCapacity();
        self.delayed_match = false;
        self.clean_delayed_match = false;
    }

    fn deinit(self: *DynResolvedBoundary, allocator: std.mem.Allocator) void {
        self.pcs.deinit(allocator);
        self.from_ambig.deinit(allocator);
    }
};

const DynClosureWorkspace = struct {
    stack: std.ArrayList(u32) = .empty,
    assert_stack: std.ArrayList(AssertStackItem) = .empty,
    visited_clean: []u32 = &.{},
    visited_ambig: []u32 = &.{},
    out_slot_gen: []u32 = &.{},
    out_slot_idx: []u32 = &.{},
    gen_clean: u32 = 1,
    gen_ambig: u32 = 1,
    gen_out: u32 = 1,

    fn init(allocator: std.mem.Allocator, n_inst: usize) !DynClosureWorkspace {
        const vc = try allocator.alloc(u32, n_inst);
        errdefer allocator.free(vc);
        @memset(vc, 0);
        const va = try allocator.alloc(u32, n_inst);
        errdefer allocator.free(va);
        @memset(va, 0);
        const og = try allocator.alloc(u32, n_inst);
        errdefer allocator.free(og);
        @memset(og, 0);
        const oi = try allocator.alloc(u32, n_inst);
        errdefer allocator.free(oi);
        return .{
            .visited_clean = vc,
            .visited_ambig = va,
            .out_slot_gen = og,
            .out_slot_idx = oi,
        };
    }

    fn deinit(self: *DynClosureWorkspace, allocator: std.mem.Allocator) void {
        self.stack.deinit(allocator);
        self.assert_stack.deinit(allocator);
        if (self.visited_clean.len != 0) allocator.free(self.visited_clean);
        if (self.visited_ambig.len != 0) allocator.free(self.visited_ambig);
        if (self.out_slot_gen.len != 0) allocator.free(self.out_slot_gen);
        if (self.out_slot_idx.len != 0) allocator.free(self.out_slot_idx);
        self.* = .{};
    }

    inline fn nextGen(table: []u32, g: *u32) u32 {
        g.* +%= 1;
        if (g.* == 0) {
            @memset(table, 0);
            g.* = 1;
        }
        return g.*;
    }

    fn beginOut(self: *DynClosureWorkspace) u32 {
        return nextGen(self.out_slot_gen, &self.gen_out);
    }

    /// Expands epsilon edges (`.jmp`, `.split`, `.save`, `.assert` if `pass_assert == true`),
    /// appending consuming PCs (deduplicated via `out_gen`) into `out_pcs`.
    fn addClosure(
        self: *DynClosureWorkspace,
        allocator: std.mem.Allocator,
        insts: []const Inst,
        start_pc: u32,
        comptime pass_assert: bool,
        out_gen: u32,
        out_pcs: *std.ArrayList(u32),
        out_is_match: *bool,
        max_work: usize,
    ) bool {
        self.stack.clearRetainingCapacity();
        self.stack.append(allocator, start_pc) catch return false;
        const vg = nextGen(self.visited_clean, &self.gen_clean);
        var work: usize = 0;

        while (self.stack.items.len > 0) {
            work += 1;
            if (work > max_work) return false;
            const pc = self.stack.pop().?;
            if (pc >= insts.len) return false;
            if (self.visited_clean[pc] == vg) continue;
            self.visited_clean[pc] = vg;

            switch (insts[pc]) {
                .jmp => |target| {
                    self.stack.append(allocator, target) catch return false;
                },
                .split => |sp| {
                    self.stack.append(allocator, sp.out2) catch return false;
                    self.stack.append(allocator, sp.out1) catch return false;
                },
                .save => |sv| {
                    self.stack.append(allocator, sv.out) catch return false;
                },
                .assert => |as| {
                    if (comptime pass_assert) {
                        self.stack.append(allocator, as.out) catch return false;
                    } else {
                        if (self.out_slot_gen[pc] != out_gen) {
                            self.out_slot_gen[pc] = out_gen;
                            out_pcs.append(allocator, pc) catch return false;
                        }
                    }
                },
                .match, .match_id => {
                    out_is_match.* = true;
                },
                .byte, .any, .any_cont, .class, .unicode_class => {
                    if (self.out_slot_gen[pc] != out_gen) {
                        self.out_slot_gen[pc] = out_gen;
                        out_pcs.append(allocator, pc) catch return false;
                    }
                },
            }
        }
        return true;
    }

    fn resolveAssertsAtBoundary(
        self: *DynClosureWorkspace,
        allocator: std.mem.Allocator,
        insts: []const Inst,
        src_pcs: []const u32,
        prev_kind: WordKind,
        next_kind: WordKind,
        out: *DynResolvedBoundary,
        max_work: usize,
    ) bool {
        out.clearRetainingCapacity();
        self.assert_stack.clearRetainingCapacity();

        const boundary_ambig = (prev_kind == .maybe or next_kind == .maybe);
        const og = nextGen(self.out_slot_gen, &self.gen_out);
        const vg_clean = nextGen(self.visited_clean, &self.gen_clean);
        const vg_ambig = nextGen(self.visited_ambig, &self.gen_ambig);

        for (src_pcs) |pc| {
            if (insts[pc] == .assert) {
                self.assert_stack.append(allocator, .{ .pc = pc, .ambig = false }) catch return false;
            } else {
                if (self.out_slot_gen[pc] != og) {
                    self.out_slot_gen[pc] = og;
                    self.out_slot_idx[pc] = @intCast(out.pcs.items.len);
                    out.pcs.append(allocator, pc) catch return false;
                    out.from_ambig.append(allocator, false) catch return false;
                }
            }
        }

        var work: usize = 0;
        while (self.assert_stack.items.len > 0) {
            work += 1;
            if (work > max_work) return false;
            const item = self.assert_stack.pop().?;
            const pc = item.pc;
            if (pc >= insts.len) return false;

            if (item.ambig) {
                if (self.visited_ambig[pc] == vg_ambig) continue;
                self.visited_ambig[pc] = vg_ambig;
            } else {
                if (self.visited_clean[pc] == vg_clean) continue;
                self.visited_clean[pc] = vg_clean;
            }

            switch (insts[pc]) {
                .jmp => |target| {
                    self.assert_stack.append(allocator, .{ .pc = target, .ambig = item.ambig }) catch return false;
                },
                .split => |sp| {
                    self.assert_stack.append(allocator, .{ .pc = sp.out2, .ambig = item.ambig }) catch return false;
                    self.assert_stack.append(allocator, .{ .pc = sp.out1, .ambig = item.ambig }) catch return false;
                },
                .save => |sv| {
                    self.assert_stack.append(allocator, .{ .pc = sv.out, .ambig = item.ambig }) catch return false;
                },
                .assert => |as| {
                    const res_a: struct { pass: bool, adds_ambig: bool } = switch (as.kind) {
                        .word_boundary => .{
                            .pass = boundary_ambig or (prev_kind != next_kind),
                            .adds_ambig = boundary_ambig,
                        },
                        .not_word_boundary => .{
                            .pass = boundary_ambig or (prev_kind == next_kind),
                            .adds_ambig = boundary_ambig,
                        },
                        .ascii_word_boundary => .{
                            .pass = (prev_kind == .word) != (next_kind == .word),
                            .adds_ambig = false,
                        },
                        .not_ascii_word_boundary => .{
                            .pass = (prev_kind == .word) == (next_kind == .word),
                            .adds_ambig = false,
                        },
                        else => return false,
                    };
                    if (res_a.pass) {
                        self.assert_stack.append(allocator, .{ .pc = as.out, .ambig = item.ambig or res_a.adds_ambig }) catch return false;
                    }
                },
                .match, .match_id => {
                    out.delayed_match = true;
                    if (!item.ambig) out.clean_delayed_match = true;
                },
                .byte, .any, .any_cont, .class, .unicode_class => {
                    if (self.out_slot_gen[pc] == og) {
                        const existing = self.out_slot_idx[pc];
                        if (item.ambig) out.from_ambig.items[existing] = true;
                    } else {
                        self.out_slot_gen[pc] = og;
                        self.out_slot_idx[pc] = @intCast(out.pcs.items.len);
                        out.pcs.append(allocator, pc) catch return false;
                        out.from_ambig.append(allocator, item.ambig) catch return false;
                    }
                },
            }
        }
        return true;
    }
};

inline fn stepInstOnByte(
    inst: Inst,
    unicode_ranges: []const UnicodeRangeList,
    byte: u8,
    comptime allow_any: bool,
) ?u32 {
    switch (inst) {
        .byte => |by| {
            const ok = if (by.ignore_case)
                std.ascii.toLower(byte) == std.ascii.toLower(by.b)
            else
                byte == by.b;
            return if (ok) by.out else null;
        },
        .any => |an| {
            if (comptime !allow_any) return null;
            if (!an.allow_nl and byte == '\n') return null;
            if (byte < 0x80) return an.out;
            if (byte >= 0xC2 and byte <= 0xDF) return if (an.cont1 != 0) an.cont1 else an.out;
            if (byte >= 0xE0 and byte <= 0xEF) return if (an.cont2 != 0) an.cont2 else an.out;
            if (byte >= 0xF0 and byte <= 0xF4) return if (an.cont3 != 0) an.cont3 else an.out;
            return an.out;
        },
        .any_cont => |ac| {
            return if ((byte & 0xC0) == 0x80) ac.out else null;
        },
        .class => |cl| {
            if (cl.utf8_negated and byte >= 0x80) {
                if (byte >= 0xC2 and byte <= 0xDF) return if (cl.cont1 != 0) cl.cont1 else cl.out;
                if (byte >= 0xE0 and byte <= 0xEF) return if (cl.cont2 != 0) cl.cont2 else cl.out;
                if (byte >= 0xF0 and byte <= 0xF4) return if (cl.cont3 != 0) cl.cont3 else cl.out;
                return cl.out;
            }
            return if (cl.set.contains(byte)) cl.out else null;
        },
        .unicode_class => |uc| {
            if (!uc.allow_nl and byte == '\n') return null;
            if (byte < 0x80) {
                const ranges = unicode_ranges[uc.range_idx].ranges;
                const in_set = (uc.has_ascii_set and uc.ascii_set.contains(byte)) or inRanges(byte, ranges);
                const matched = if (uc.negated) !in_set else in_set;
                return if (matched) uc.out else null;
            }
            if (byte >= 0xC2 and byte <= 0xF4) {
                if (byte <= 0xDF) return if (uc.cont1 != 0) uc.cont1 else uc.out;
                if (byte <= 0xEF) return if (uc.cont2 != 0) uc.cont2 else uc.out;
                return if (uc.cont3 != 0) uc.cont3 else uc.out;
            }
            return null;
        },
        else => return null,
    }
}

/// Tier A — Read-only AOT Multi-Pattern Unanchored DFA owned by `*const RegexSet`.
/// Supports arbitrary closure sizes (no 64-PC limit, `u32` PCs), pre-determinization `ByteClasses`,
/// `u8` / `u16` / `u32` pre-scaled transition tables within a strict 512 KiB / 4096-state /
/// 65,536-transition budget, exact `\b`/`\B`/`.ascii_word_boundary` look-around, and SIMD `StartSkip`.
pub const SetUnanchoredDfa = struct {
    pub const max_aot_bytes: usize = 512 * 1024;
    pub const max_aot_states: u32 = 4096;
    pub const max_aot_transitions: u32 = 65_536;
    pub const max_closure_work: usize = 4096;

    pub const TableKind = enum(u2) {
        u8_tbl = 0,
        u16_tbl = 1,
        u32_tbl = 2,
    };

    classes: [256]u8 = @splat(0),
    table_kind: TableKind = .u8_tbl,
    trans_u8: [256]u8 = @splat(0),
    trans_u16: []u16 = &.{},
    trans_u32: []u32 = &.{},
    eoi_kind: []EoiKind = &.{},
    num_states: u32 = 0,
    num_non_match: u32 = 0,
    stride: u32 = 1,
    start_word_off: u32 = 0,
    start_maybe_off: u32 = 0,
    start_max_off: u32 = 0,
    match_start_off: u32 = 255,
    verify_imm_off: u32 = 252,
    verify_del_off: u32 = 253,
    exact_imm_off: u32 = 254,
    exact_del_off: u32 = 255,
    has_word_boundary: bool = false,
    has_unicode_wb: bool = false,
    has_exact_match: bool = false,
    start_reentrant: bool = false,
    start_skip: StartSkip = .none,

    const raw_verify_imm: u32 = 0xFFFF_FFFC;
    const raw_verify_del: u32 = 0xFFFF_FFFD;
    const raw_exact_imm: u32 = 0xFFFF_FFFE;
    const raw_exact_del: u32 = 0xFFFF_FFFF;

    pub fn deinit(self: *SetUnanchoredDfa, allocator: std.mem.Allocator) void {
        if (self.trans_u16.len != 0) {
            allocator.free(self.trans_u16);
            self.trans_u16 = &.{};
        }
        if (self.trans_u32.len != 0) {
            allocator.free(self.trans_u32);
            self.trans_u32 = &.{};
        }
        if (self.eoi_kind.len != 0) {
            allocator.free(self.eoi_kind);
            self.eoi_kind = &.{};
        }
    }

    pub inline fn startStateForByte(self: *const SetUnanchoredDfa, b: u8) u32 {
        if (!self.has_word_boundary) return 0;
        if (b >= 0x80) return self.start_maybe_off;
        if (isAsciiWord(b)) return self.start_word_off;
        return 0;
    }

    pub inline fn startStateAt(self: *const SetUnanchoredDfa, haystack: []const u8, pos: usize) u32 {
        if (pos == 0 or !self.has_word_boundary) return 0;
        return self.startStateForByte(haystack[pos - 1]);
    }

    pub fn determinize(
        self: *SetUnanchoredDfa,
        allocator: std.mem.Allocator,
        insts: []const Inst,
        unicode_ranges: []const UnicodeRangeList,
        bc: *const ByteClasses,
        start_pc: u32,
        multiline: bool,
    ) bool {
        self.deinit(allocator);
        if (insts.len == 0 or bc.num_classes == 0) return false;

        var ws = DynClosureWorkspace.init(allocator, insts.len) catch return false;
        defer ws.deinit(allocator);

        // Zero-length match or empty start closure stays on PikeVM
        var zero_pcs = std.ArrayList(u32).empty;
        defer zero_pcs.deinit(allocator);
        var zero_match = false;
        const og0 = ws.beginOut();
        if (!ws.addClosure(allocator, insts, start_pc, true, og0, &zero_pcs, &zero_match, max_closure_work)) return false;
        if (zero_match or zero_pcs.items.len == 0) return false;

        if (!multiline and isExactOnAsciiWithWordBoundary(insts)) {
            if (self.determinizeExact(allocator, &ws, insts, unicode_ranges, bc, start_pc)) {
                return true;
            }
            self.deinit(allocator);
        }
        return self.determinizeLegacy(allocator, &ws, insts, unicode_ranges, bc, start_pc, multiline);
    }

    fn determinizeExact(
        self: *SetUnanchoredDfa,
        allocator: std.mem.Allocator,
        ws: *DynClosureWorkspace,
        insts: []const Inst,
        unicode_ranges: []const UnicodeRangeList,
        bc: *const ByteClasses,
        start_pc: u32,
    ) bool {
        var has_wb = false;
        var has_unicode_wb = false;
        for (insts) |inst| {
            if (inst == .assert) {
                has_wb = true;
                if (inst.assert.kind == .word_boundary or inst.assert.kind == .not_word_boundary) {
                    has_unicode_wb = true;
                }
            }
        }
        const all_bytes_exact = !has_unicode_wb and isExactBytesAllowAsciiWb(insts);
        const init_classes: usize = bc.num_classes;

        var start_pcs = std.ArrayList(u32).empty;
        defer start_pcs.deinit(allocator);
        var start_match = false;
        const s_og = ws.beginOut();
        if (!ws.addClosure(allocator, insts, start_pc, false, s_og, &start_pcs, &start_match, max_closure_work)) return false;
        if (start_match or start_pcs.items.len == 0) return false;
        sortAndDedupU32(&start_pcs);

        const num_starts: u32 = if (has_unicode_wb) 3 else if (has_wb) 2 else 1;
        if (num_starts >= max_aot_states) return false;

        var pc_pool = std.ArrayList(u32).empty;
        defer pc_pool.deinit(allocator);
        var metas = std.ArrayList(DynStateMeta).empty;
        defer metas.deinit(allocator);
        var raw_trans = std.ArrayList(u32).empty;
        defer raw_trans.deinit(allocator);
        var eoi_list = std.ArrayList(EoiKind).empty;
        defer eoi_list.deinit(allocator);

        var state_map = DynStateMap.init(allocator, 64) catch return false;
        defer state_map.deinit(allocator);

        const start_off: u32 = 0;
        pc_pool.appendSlice(allocator, start_pcs.items) catch return false;
        const start_len: u32 = @intCast(start_pcs.items.len);

        const start_kinds = [_]WordKind{ .nonword, .word, .maybe };
        for (0..num_starts) |si| {
            metas.append(allocator, .{
                .pc_off = start_off,
                .pc_len = start_len,
                .prev_kind = start_kinds[si],
                .dirty = false,
            }) catch return false;
            state_map.insert(allocator, metas.items, pc_pool.items, @intCast(si)) catch return false;
        }

        var resolved: [3]DynResolvedBoundary = .{ .{}, .{}, .{} };
        defer {
            for (&resolved) |*r| r.deinit(allocator);
        }
        var eoi_res = DynResolvedBoundary{};
        defer eoi_res.deinit(allocator);
        var next_pcs = std.ArrayList(u32).empty;
        defer next_pcs.deinit(allocator);

        var start_reentrant = false;
        var saw_exact = false;
        var total_transitions: u32 = 0;

        var q_head: u32 = 0;
        while (q_head < metas.items.len) : (q_head += 1) {
            if (total_transitions + @as(u32, @intCast(init_classes)) > max_aot_transitions) return false;
            total_transitions += @intCast(init_classes);

            const src_meta = metas.items[q_head];
            const src_pcs = pc_pool.items[src_meta.pc_off .. src_meta.pc_off + src_meta.pc_len];

            // EOI check (next_kind = .nonword)
            if (has_wb) {
                if (!ws.resolveAssertsAtBoundary(allocator, insts, src_pcs, src_meta.prev_kind, .nonword, &eoi_res, max_closure_work)) return false;
                if (eoi_res.delayed_match) {
                    if (!src_meta.dirty and eoi_res.clean_delayed_match) {
                        eoi_list.append(allocator, .exact) catch return false;
                        saw_exact = true;
                    } else {
                        eoi_list.append(allocator, .verify) catch return false;
                    }
                } else {
                    eoi_list.append(allocator, .none) catch return false;
                }
            }

            const nk_count: usize = if (has_unicode_wb) 3 else if (has_wb) 2 else 1;
            for (0..nk_count) |wk_idx| {
                const nk: WordKind = @enumFromInt(wk_idx);
                if (!ws.resolveAssertsAtBoundary(allocator, insts, src_pcs, src_meta.prev_kind, nk, &resolved[wk_idx], max_closure_work)) return false;
            }

            const row_start = raw_trans.items.len;
            raw_trans.resize(allocator, row_start + init_classes) catch return false;

            for (0..init_classes) |cls| {
                const byte = bc.rep[cls];
                const nk: WordKind = if (!has_wb)
                    .nonword
                else if (has_unicode_wb)
                    byteWordKind(byte)
                else if (byte < 0x80 and isAsciiWord(byte))
                    .word
                else
                    .nonword;
                const res = &resolved[@intFromEnum(nk)];

                // Step 1: Delayed match from pending word boundary resolved BEFORE consuming `byte`
                if (res.delayed_match) {
                    if (!src_meta.dirty and res.clean_delayed_match) {
                        raw_trans.items[row_start + cls] = raw_exact_del;
                        saw_exact = true;
                    } else {
                        raw_trans.items[row_start + cls] = raw_verify_del;
                    }
                    continue;
                }

                // Step 2: Single-line `\n` kills all active consuming threads
                if (byte == '\n') {
                    raw_trans.items[row_start + cls] = 0; // start_nonword
                    continue;
                }

                next_pcs.clearRetainingCapacity();
                var any_imm_match = false;
                var clean_imm_match = false;
                var next_used_ambig = false;
                const next_og = ws.beginOut();

                for (res.pcs.items, 0..) |pc, r_idx| {
                    if (stepInstOnByte(insts[pc], unicode_ranges, byte, false)) |target_pc| {
                        const from_amb = res.from_ambig.items[r_idx];
                        if (from_amb) next_used_ambig = true;
                        var branch_match = false;
                        if (!ws.addClosure(allocator, insts, target_pc, false, next_og, &next_pcs, &branch_match, max_closure_work)) return false;
                        if (branch_match) {
                            any_imm_match = true;
                            if (!from_amb) clean_imm_match = true;
                        }
                    }
                }

                const byte_dirty = (!all_bytes_exact and byte >= 0x80);
                if (any_imm_match) {
                    if (!src_meta.dirty and !byte_dirty and clean_imm_match) {
                        raw_trans.items[row_start + cls] = raw_exact_imm;
                        saw_exact = true;
                    } else {
                        raw_trans.items[row_start + cls] = raw_verify_imm;
                    }
                    continue;
                }

                const clean_start_id: u32 = if (!has_wb) 0 else @intFromEnum(nk);
                if (next_pcs.items.len == 0) {
                    raw_trans.items[row_start + cls] = clean_start_id;
                    continue;
                }

                if (!start_reentrant) {
                    sortAndDedupU32(&next_pcs);
                    if (isSubsetSortedU32(next_pcs.items, start_pcs.items)) {
                        start_reentrant = true;
                    }
                }

                // Union `start_pcs` so a new match can begin at every byte offset
                next_pcs.appendSlice(allocator, start_pcs.items) catch return false;
                sortAndDedupU32(&next_pcs);

                const next_dirty = src_meta.dirty or next_used_ambig or byte_dirty;
                const next_prev_kind: WordKind = if (has_wb) nk else .nonword;

                if (state_map.find(metas.items, pc_pool.items, next_prev_kind, next_dirty, next_pcs.items)) |fid| {
                    raw_trans.items[row_start + cls] = fid;
                } else {
                    if (metas.items.len >= max_aot_states) return false;
                    const new_id: u32 = @intCast(metas.items.len);
                    const off: u32 = @intCast(pc_pool.items.len);
                    pc_pool.appendSlice(allocator, next_pcs.items) catch return false;
                    metas.append(allocator, .{
                        .pc_off = off,
                        .pc_len = @intCast(next_pcs.items.len),
                        .prev_kind = next_prev_kind,
                        .dirty = next_dirty,
                    }) catch return false;
                    state_map.insert(allocator, metas.items, pc_pool.items, new_id) catch return false;
                    raw_trans.items[row_start + cls] = new_id;
                }
            }
        }

        const num_non_match: u32 = @intCast(metas.items.len);
        const eoi_slice: []const EoiKind = if (has_wb) eoi_list.items else &.{};
        return self.finalizeTables(
            allocator,
            bc,
            raw_trans.items,
            eoi_slice,
            num_non_match,
            num_starts,
            has_wb,
            has_unicode_wb,
            saw_exact,
            start_reentrant,
        );
    }

    fn determinizeLegacy(
        self: *SetUnanchoredDfa,
        allocator: std.mem.Allocator,
        ws: *DynClosureWorkspace,
        insts: []const Inst,
        unicode_ranges: []const UnicodeRangeList,
        bc: *const ByteClasses,
        start_pc: u32,
        multiline: bool,
    ) bool {
        const init_classes: usize = bc.num_classes;

        var start_pcs = std.ArrayList(u32).empty;
        defer start_pcs.deinit(allocator);
        var start_match = false;
        const s_og = ws.beginOut();
        if (!ws.addClosure(allocator, insts, start_pc, true, s_og, &start_pcs, &start_match, max_closure_work)) return false;
        if (start_match or start_pcs.items.len == 0) return false;
        sortAndDedupU32(&start_pcs);

        var pc_pool = std.ArrayList(u32).empty;
        defer pc_pool.deinit(allocator);
        var metas = std.ArrayList(DynStateMeta).empty;
        defer metas.deinit(allocator);
        var raw_trans = std.ArrayList(u32).empty;
        defer raw_trans.deinit(allocator);

        var state_map = DynStateMap.init(allocator, 64) catch return false;
        defer state_map.deinit(allocator);

        pc_pool.appendSlice(allocator, start_pcs.items) catch return false;
        metas.append(allocator, .{
            .pc_off = 0,
            .pc_len = @intCast(start_pcs.items.len),
        }) catch return false;
        state_map.insert(allocator, metas.items, pc_pool.items, 0) catch return false;

        var next_pcs = std.ArrayList(u32).empty;
        defer next_pcs.deinit(allocator);

        var start_reentrant = false;
        var total_transitions: u32 = 0;

        var q_head: u32 = 0;
        while (q_head < metas.items.len) : (q_head += 1) {
            if (total_transitions + @as(u32, @intCast(init_classes)) > max_aot_transitions) return false;
            total_transitions += @intCast(init_classes);

            const src_meta = metas.items[q_head];
            const src_pcs = pc_pool.items[src_meta.pc_off .. src_meta.pc_off + src_meta.pc_len];

            const row_start = raw_trans.items.len;
            raw_trans.resize(allocator, row_start + init_classes) catch return false;

            for (0..init_classes) |cls| {
                const byte = bc.rep[cls];
                if (!multiline and byte == '\n') {
                    raw_trans.items[row_start + cls] = 0;
                    continue;
                }

                next_pcs.clearRetainingCapacity();
                var next_is_match = false;
                const next_og = ws.beginOut();

                for (src_pcs) |pc| {
                    if (stepInstOnByte(insts[pc], unicode_ranges, byte, true)) |target_pc| {
                        if (!ws.addClosure(allocator, insts, target_pc, true, next_og, &next_pcs, &next_is_match, max_closure_work)) return false;
                    }
                }

                if (next_is_match) {
                    raw_trans.items[row_start + cls] = raw_verify_imm;
                    continue;
                }
                if (next_pcs.items.len == 0) {
                    raw_trans.items[row_start + cls] = 0;
                    continue;
                }
                if (!start_reentrant) {
                    sortAndDedupU32(&next_pcs);
                    if (isSubsetSortedU32(next_pcs.items, start_pcs.items)) {
                        start_reentrant = true;
                    }
                }

                next_pcs.appendSlice(allocator, start_pcs.items) catch return false;
                sortAndDedupU32(&next_pcs);

                if (state_map.find(metas.items, pc_pool.items, .nonword, false, next_pcs.items)) |fid| {
                    raw_trans.items[row_start + cls] = fid;
                } else {
                    if (metas.items.len >= max_aot_states) return false;
                    const new_id: u32 = @intCast(metas.items.len);
                    const off: u32 = @intCast(pc_pool.items.len);
                    pc_pool.appendSlice(allocator, next_pcs.items) catch return false;
                    metas.append(allocator, .{
                        .pc_off = off,
                        .pc_len = @intCast(next_pcs.items.len),
                    }) catch return false;
                    state_map.insert(allocator, metas.items, pc_pool.items, new_id) catch return false;
                    raw_trans.items[row_start + cls] = new_id;
                }
            }
        }

        const num_non_match: u32 = @intCast(metas.items.len);
        return self.finalizeTables(
            allocator,
            bc,
            raw_trans.items,
            &.{},
            num_non_match,
            1,
            false,
            false,
            false,
            start_reentrant,
        );
    }

    fn finalizeTables(
        self: *SetUnanchoredDfa,
        allocator: std.mem.Allocator,
        bc: *const ByteClasses,
        raw_trans: []const u32,
        eoi_src: []const EoiKind,
        num_non_match: u32,
        num_starts: u32,
        has_wb: bool,
        has_unicode_wb: bool,
        has_exact: bool,
        start_reentrant: bool,
    ) bool {
        const init_classes: usize = bc.num_classes;

        // 1. Merge identical transition columns across the `init_classes` columns using column hashes
        var col_hashes: [256]u64 = undefined;
        for (0..init_classes) |c| {
            var h: u64 = 0xcbf29ce484222325;
            var s: usize = 0;
            while (s < num_non_match) : (s += 1) {
                h ^= raw_trans[s * init_classes + c];
                h *%= 0x100000001b3;
            }
            col_hashes[c] = h;
        }

        var col_remap: [256]u8 = undefined;
        var rep_cols: [256]u16 = undefined;
        var final_classes: u32 = 0;
        for (0..init_classes) |c| {
            var found: ?u8 = null;
            for (0..final_classes) |fc| {
                const rc = rep_cols[fc];
                if (col_hashes[c] != col_hashes[rc]) continue;
                var same = true;
                var s: usize = 0;
                while (s < num_non_match) : (s += 1) {
                    if (raw_trans[s * init_classes + c] != raw_trans[s * init_classes + rc]) {
                        same = false;
                        break;
                    }
                }
                if (same) {
                    found = @intCast(fc);
                    break;
                }
            }
            if (found) |fc_id| {
                col_remap[c] = fc_id;
            } else {
                col_remap[c] = @intCast(final_classes);
                rep_cols[final_classes] = @intCast(c);
                final_classes += 1;
            }
        }

        var classes: [256]u8 = undefined;
        for (0..256) |b| {
            classes[b] = col_remap[bc.map[b]];
        }

        const stride: u32 = final_classes;
        const total_entries_u64: u64 = @as(u64, num_non_match) * @as(u64, stride);
        if (total_entries_u64 + 4 > std.math.maxInt(u32)) return false;
        const total_entries: u32 = @intCast(total_entries_u64);

        const match_start_off: u32 = total_entries;
        const verify_imm_off: u32 = match_start_off + 0;
        const verify_del_off: u32 = match_start_off + 1;
        const exact_imm_off: u32 = match_start_off + 2;
        const exact_del_off: u32 = match_start_off + 3;

        const kind: TableKind = if (exact_del_off <= 255)
            .u8_tbl
        else if (exact_del_off <= 65535)
            .u16_tbl
        else if (@as(usize, total_entries) * @sizeOf(u32) <= max_aot_bytes)
            .u32_tbl
        else
            return false;

        if (kind == .u16_tbl and @as(usize, total_entries) * @sizeOf(u16) > max_aot_bytes) return false;

        // 2. Build pre-scaled compact transition table
        self.trans_u16 = &.{};
        self.trans_u32 = &.{};
        switch (kind) {
            .u8_tbl => {
                for (0..num_non_match) |s| {
                    const row_off = s * stride;
                    for (0..final_classes) |fc| {
                        const rc = rep_cols[fc];
                        const dst = raw_trans[s * init_classes + rc];
                        const enc: u32 = switch (dst) {
                            raw_verify_imm => verify_imm_off,
                            raw_verify_del => verify_del_off,
                            raw_exact_imm => exact_imm_off,
                            raw_exact_del => exact_del_off,
                            else => dst * stride,
                        };
                        self.trans_u8[row_off + fc] = @intCast(enc);
                    }
                }
            },
            .u16_tbl => {
                const tbl = allocator.alloc(u16, total_entries) catch return false;
                for (0..num_non_match) |s| {
                    const row_off = s * stride;
                    for (0..final_classes) |fc| {
                        const rc = rep_cols[fc];
                        const dst = raw_trans[s * init_classes + rc];
                        const enc: u32 = switch (dst) {
                            raw_verify_imm => verify_imm_off,
                            raw_verify_del => verify_del_off,
                            raw_exact_imm => exact_imm_off,
                            raw_exact_del => exact_del_off,
                            else => dst * stride,
                        };
                        tbl[row_off + fc] = @intCast(enc);
                    }
                }
                self.trans_u16 = tbl;
            },
            .u32_tbl => {
                const tbl = allocator.alloc(u32, total_entries) catch return false;
                for (0..num_non_match) |s| {
                    const row_off = s * stride;
                    for (0..final_classes) |fc| {
                        const rc = rep_cols[fc];
                        const dst = raw_trans[s * init_classes + rc];
                        const enc: u32 = switch (dst) {
                            raw_verify_imm => verify_imm_off,
                            raw_verify_del => verify_del_off,
                            raw_exact_imm => exact_imm_off,
                            raw_exact_del => exact_del_off,
                            else => dst * stride,
                        };
                        tbl[row_off + fc] = enc;
                    }
                }
                self.trans_u32 = tbl;
            },
        }

        // 3. Allocate EOI table (if word boundaries exist)
        var eoi_owned: []EoiKind = &.{};
        if (eoi_src.len != 0) {
            eoi_owned = allocator.dupe(EoiKind, eoi_src) catch {
                self.deinit(allocator);
                return false;
            };
        }

        // 4. Compute SIMD StartSkip over start-family exit bytes
        var exits: [4]u8 = undefined;
        var exit_count: usize = 0;
        var ranges: [4]ByteRange = undefined;
        var num_ranges: usize = 0;
        var in_run = false;
        var run_lo: u8 = 0;

        for (0..256) |b_usize| {
            const byte: u8 = @intCast(b_usize);
            const init_c = bc.map[byte];
            var is_exit = false;
            for (0..num_starts) |u| {
                if (raw_trans[u * init_classes + init_c] >= num_starts) {
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
        self.table_kind = kind;
        self.eoi_kind = eoi_owned;
        self.num_non_match = num_non_match;
        self.num_states = num_non_match + 4;
        self.stride = stride;
        self.has_word_boundary = has_wb;
        self.has_unicode_wb = has_unicode_wb;
        self.has_exact_match = has_exact;
        self.start_word_off = if (num_starts >= 2) stride else 0;
        self.start_maybe_off = if (num_starts >= 3) 2 * stride else 0;
        self.start_max_off = (num_starts - 1) * stride;
        self.match_start_off = match_start_off;
        self.verify_imm_off = verify_imm_off;
        self.verify_del_off = verify_del_off;
        self.exact_imm_off = exact_imm_off;
        self.exact_del_off = exact_del_off;
        self.start_reentrant = start_reentrant;
        return true;
    }
};

/// Tier B — Bounded On-Demand Lazy Multi-Pattern DFA Fallback.
/// Reuses `ByteClasses` computed at `RegexSet` initialization, enforces a strict 256 KiB table budget
/// with O(1) cache flushes (up to `max_flushes = 4`), and bails out cleanly to Thompson PikeVM on
/// thrashing or excessive NFA closure work.
pub const LazySetDfa = struct {
    pub const default_max_bytes: usize = 256 * 1024;
    pub const default_max_flushes: u32 = 4;
    pub const max_closure_work: usize = 4096;

    pub const unknown_trans: u16 = 0xFFFF;
    pub const bailout_trans: u16 = 0xFFFE;
    pub const verify_imm: u16 = 0xFFFD;
    pub const verify_del: u16 = 0xFFFC;
    pub const exact_imm: u16 = 0xFFFB;
    pub const exact_del: u16 = 0xFFFA;
    pub const sentinel_min: u16 = 0xFFFA;

    allocator: std.mem.Allocator,
    insts: []const Inst,
    unicode_ranges: []const UnicodeRangeList,
    classes: [256]u8 = @splat(0),
    trans: []u16 = &.{},
    eoi_cache: []u8 = &.{},
    pc_pool: std.ArrayList(u32) = .empty,
    metas: std.ArrayList(DynStateMeta) = .empty,
    state_map: DynStateMap = .{},
    ws: DynClosureWorkspace = .{},
    start_pcs: []u32 = &.{},
    saved_src_pcs: std.ArrayList(u32) = .empty,
    tmp_next_pcs: std.ArrayList(u32) = .empty,
    tmp_resolved: DynResolvedBoundary = .{},

    stride: u16 = 1,
    max_states: u16 = 0,
    num_states: u16 = 0,
    num_starts: u16 = 1,
    max_flushes: u32 = default_max_flushes,
    flushes: u32 = 0,
    bailed_out: bool = false,
    multiline: bool = false,
    exact_mode: bool = false,
    has_word_boundary: bool = false,
    has_unicode_wb: bool = false,
    all_bytes_exact: bool = false,
    start_reentrant: bool = false,

    pub fn init(
        allocator: std.mem.Allocator,
        insts: []const Inst,
        unicode_ranges: []const UnicodeRangeList,
        bc: *const ByteClasses,
        start_pc: u32,
        multiline: bool,
        max_states_override: ?u16,
        max_flushes: u32,
    ) ?LazySetDfa {
        if (insts.len == 0 or bc.num_classes == 0) return null;
        const stride: u16 = bc.num_classes;
        const budget_states: usize = @min(@as(usize, 2048), (default_max_bytes / @sizeOf(u16)) / stride);
        const cap_u16: u16 = if (max_states_override) |ov|
            @max(@as(u16, 4), @min(ov, @as(u16, 4096)))
        else
            @intCast(@min(@as(usize, 4096), budget_states));
        if (cap_u16 < 4) return null;

        var ws = DynClosureWorkspace.init(allocator, insts.len) catch return null;
        errdefer ws.deinit(allocator);

        // Reject zero-length matches / empty start closure
        var zero_pcs = std.ArrayList(u32).empty;
        defer zero_pcs.deinit(allocator);
        var zero_match = false;
        const og0 = ws.beginOut();
        if (!ws.addClosure(allocator, insts, start_pc, true, og0, &zero_pcs, &zero_match, max_closure_work)) return null;
        if (zero_match or zero_pcs.items.len == 0) return null;

        const exact_mode = !multiline and isExactOnAsciiWithWordBoundary(insts);
        var has_wb = false;
        var has_unicode_wb = false;
        if (exact_mode) {
            for (insts) |inst| {
                if (inst == .assert) {
                    has_wb = true;
                    if (inst.assert.kind == .word_boundary or inst.assert.kind == .not_word_boundary) {
                        has_unicode_wb = true;
                    }
                }
            }
        }
        const all_bytes_exact = exact_mode and !has_unicode_wb and isExactBytesAllowAsciiWb(insts);
        const num_starts: u16 = if (!exact_mode or !has_wb) 1 else if (has_unicode_wb) 3 else 2;
        if (num_starts >= cap_u16) return null;

        var start_list = std.ArrayList(u32).empty;
        defer start_list.deinit(allocator);
        var start_match = false;
        const s_og = ws.beginOut();
        const ok_s = if (exact_mode)
            ws.addClosure(allocator, insts, start_pc, false, s_og, &start_list, &start_match, max_closure_work)
        else
            ws.addClosure(allocator, insts, start_pc, true, s_og, &start_list, &start_match, max_closure_work);
        if (!ok_s or start_match or start_list.items.len == 0) return null;
        sortAndDedupU32(&start_list);

        const start_pcs = allocator.dupe(u32, start_list.items) catch return null;
        errdefer allocator.free(start_pcs);

        const trans = allocator.alloc(u16, @as(usize, cap_u16) * @as(usize, stride)) catch return null;
        errdefer allocator.free(trans);

        const eoi_cache = allocator.alloc(u8, cap_u16) catch return null;
        errdefer allocator.free(eoi_cache);

        const state_map = DynStateMap.init(allocator, @min(@as(usize, cap_u16), 256)) catch return null;

        var self = LazySetDfa{
            .allocator = allocator,
            .insts = insts,
            .unicode_ranges = unicode_ranges,
            .classes = bc.map,
            .trans = trans,
            .eoi_cache = eoi_cache,
            .state_map = state_map,
            .ws = ws,
            .start_pcs = start_pcs,
            .stride = stride,
            .max_states = cap_u16,
            .num_states = 0,
            .num_starts = num_starts,
            .max_flushes = max_flushes,
            .multiline = multiline,
            .exact_mode = exact_mode,
            .has_word_boundary = has_wb,
            .has_unicode_wb = has_unicode_wb,
            .all_bytes_exact = all_bytes_exact,
        };
        if (!self.seedStartStates()) {
            self.deinit();
            return null;
        }
        return self;
    }

    pub fn deinit(self: *LazySetDfa) void {
        self.tmp_resolved.deinit(self.allocator);
        self.tmp_next_pcs.deinit(self.allocator);
        self.saved_src_pcs.deinit(self.allocator);
        self.ws.deinit(self.allocator);
        self.state_map.deinit(self.allocator);
        self.metas.deinit(self.allocator);
        self.pc_pool.deinit(self.allocator);
        if (self.start_pcs.len != 0) self.allocator.free(self.start_pcs);
        if (self.eoi_cache.len != 0) self.allocator.free(self.eoi_cache);
        if (self.trans.len != 0) self.allocator.free(self.trans);
        self.* = undefined;
    }

    fn seedStartStates(self: *LazySetDfa) bool {
        self.pc_pool.clearRetainingCapacity();
        self.metas.clearRetainingCapacity();
        self.state_map.clearRetainingCapacity();
        self.num_states = 0;

        self.pc_pool.appendSlice(self.allocator, self.start_pcs) catch return false;
        const slen: u32 = @intCast(self.start_pcs.len);
        const kinds = [_]WordKind{ .nonword, .word, .maybe };
        for (0..self.num_starts) |si| {
            self.metas.append(self.allocator, .{
                .pc_off = 0,
                .pc_len = slen,
                .prev_kind = kinds[si],
                .dirty = false,
            }) catch return false;
            self.state_map.insert(self.allocator, self.metas.items, self.pc_pool.items, @intCast(si)) catch return false;
            const row = self.trans[si * self.stride ..][0..self.stride];
            @memset(row, unknown_trans);
            self.eoi_cache[si] = 0;
        }
        self.num_states = self.num_starts;
        return true;
    }

    pub inline fn startStateForByte(self: *const LazySetDfa, b: u8) u16 {
        if (!self.has_word_boundary) return 0;
        if (b >= 0x80) return if (self.has_unicode_wb) 2 else 0;
        if (isAsciiWord(b)) return 1;
        return 0;
    }

    pub inline fn startStateAt(self: *const LazySetDfa, haystack: []const u8, pos: usize) u16 {
        if (pos == 0 or !self.has_word_boundary) return 0;
        return self.startStateForByte(haystack[pos - 1]);
    }

    pub inline fn step(self: *LazySetDfa, state_id: u16, b: u8) u16 {
        const cls = self.classes[b];
        const cached = self.trans[@as(usize, state_id) * @as(usize, self.stride) + cls];
        if (cached != unknown_trans) return cached;
        return self.computeTransition(state_id, b, cls);
    }

    pub fn eoiKind(self: *LazySetDfa, state_id: u16) EoiKind {
        if (!self.exact_mode or !self.has_word_boundary or state_id >= self.num_states) return .none;
        const cached = self.eoi_cache[state_id];
        if (cached != 0) return @enumFromInt(cached - 1);

        const m = self.metas.items[state_id];
        const pcs = self.pc_pool.items[m.pc_off .. m.pc_off + m.pc_len];
        if (!self.ws.resolveAssertsAtBoundary(self.allocator, self.insts, pcs, m.prev_kind, .nonword, &self.tmp_resolved, max_closure_work)) {
            self.eoi_cache[state_id] = @intFromEnum(EoiKind.verify) + 1;
            return .verify;
        }
        const kind: EoiKind = if (self.tmp_resolved.delayed_match)
            (if (!m.dirty and self.tmp_resolved.clean_delayed_match) .exact else .verify)
        else
            .none;
        self.eoi_cache[state_id] = @intFromEnum(kind) + 1;
        return kind;
    }

    noinline fn computeTransition(self: *LazySetDfa, state_id: u16, byte: u8, cls: u8) u16 {
        if (self.bailed_out or state_id >= self.num_states) return bailout_trans;

        const src_meta = self.metas.items[state_id];
        const src_pcs = self.pc_pool.items[src_meta.pc_off .. src_meta.pc_off + src_meta.pc_len];

        var next_dirty = false;
        var next_prev_kind: WordKind = .nonword;

        self.tmp_next_pcs.clearRetainingCapacity();

        if (self.exact_mode) {
            const nk: WordKind = if (!self.has_word_boundary)
                .nonword
            else if (self.has_unicode_wb)
                byteWordKind(byte)
            else if (byte < 0x80 and isAsciiWord(byte))
                .word
            else
                .nonword;

            if (!self.ws.resolveAssertsAtBoundary(self.allocator, self.insts, src_pcs, src_meta.prev_kind, nk, &self.tmp_resolved, max_closure_work)) {
                self.bailed_out = true;
                return bailout_trans;
            }
            if (self.tmp_resolved.delayed_match) {
                const res: u16 = if (!src_meta.dirty and self.tmp_resolved.clean_delayed_match) exact_del else verify_del;
                self.trans[@as(usize, state_id) * @as(usize, self.stride) + cls] = res;
                return res;
            }
            if (byte == '\n') {
                self.trans[@as(usize, state_id) * @as(usize, self.stride) + cls] = 0;
                return 0;
            }

            var any_imm_match = false;
            var clean_imm_match = false;
            var next_used_ambig = false;
            const next_og = self.ws.beginOut();

            for (self.tmp_resolved.pcs.items, 0..) |pc, r_idx| {
                if (stepInstOnByte(self.insts[pc], self.unicode_ranges, byte, false)) |target_pc| {
                    const from_amb = self.tmp_resolved.from_ambig.items[r_idx];
                    if (from_amb) next_used_ambig = true;
                    var branch_match = false;
                    if (!self.ws.addClosure(self.allocator, self.insts, target_pc, false, next_og, &self.tmp_next_pcs, &branch_match, max_closure_work)) {
                        self.bailed_out = true;
                        return bailout_trans;
                    }
                    if (branch_match) {
                        any_imm_match = true;
                        if (!from_amb) clean_imm_match = true;
                    }
                }
            }

            const byte_dirty = (!self.all_bytes_exact and byte >= 0x80);
            if (any_imm_match) {
                const res: u16 = if (!src_meta.dirty and !byte_dirty and clean_imm_match) exact_imm else verify_imm;
                self.trans[@as(usize, state_id) * @as(usize, self.stride) + cls] = res;
                return res;
            }

            const clean_start_id: u16 = if (!self.has_word_boundary) 0 else @intFromEnum(nk);
            if (self.tmp_next_pcs.items.len == 0) {
                self.trans[@as(usize, state_id) * @as(usize, self.stride) + cls] = clean_start_id;
                return clean_start_id;
            }

            next_dirty = src_meta.dirty or next_used_ambig or byte_dirty;
            next_prev_kind = if (self.has_word_boundary) nk else .nonword;
        } else {
            if (!self.multiline and byte == '\n') {
                self.trans[@as(usize, state_id) * @as(usize, self.stride) + cls] = 0;
                return 0;
            }

            var next_is_match = false;
            const next_og = self.ws.beginOut();
            for (src_pcs) |pc| {
                if (stepInstOnByte(self.insts[pc], self.unicode_ranges, byte, true)) |target_pc| {
                    if (!self.ws.addClosure(self.allocator, self.insts, target_pc, true, next_og, &self.tmp_next_pcs, &next_is_match, max_closure_work)) {
                        self.bailed_out = true;
                        return bailout_trans;
                    }
                }
            }

            if (next_is_match) {
                self.trans[@as(usize, state_id) * @as(usize, self.stride) + cls] = verify_imm;
                return verify_imm;
            }
            if (self.tmp_next_pcs.items.len == 0) {
                self.trans[@as(usize, state_id) * @as(usize, self.stride) + cls] = 0;
                return 0;
            }
        }

        if (!self.start_reentrant) {
            sortAndDedupU32(&self.tmp_next_pcs);
            if (isSubsetSortedU32(self.tmp_next_pcs.items, self.start_pcs)) {
                self.start_reentrant = true;
            }
        }

        self.tmp_next_pcs.appendSlice(self.allocator, self.start_pcs) catch {
            self.bailed_out = true;
            return bailout_trans;
        };
        sortAndDedupU32(&self.tmp_next_pcs);

        if (self.state_map.find(self.metas.items, self.pc_pool.items, next_prev_kind, next_dirty, self.tmp_next_pcs.items)) |fid| {
            const fid_u16: u16 = @intCast(fid);
            self.trans[@as(usize, state_id) * @as(usize, self.stride) + cls] = fid_u16;
            return fid_u16;
        }

        var flushed = false;
        if (self.num_states >= self.max_states) {
            if (self.flushes >= self.max_flushes) {
                self.bailed_out = true;
                return bailout_trans;
            }
            self.flushes += 1;
            flushed = true;
            if (!self.seedStartStates()) {
                self.bailed_out = true;
                return bailout_trans;
            }
            // Check if the destination happens to match one of the start states after flush
            if (self.state_map.find(self.metas.items, self.pc_pool.items, next_prev_kind, next_dirty, self.tmp_next_pcs.items)) |fid| {
                return @intCast(fid);
            }
        }

        const new_id: u16 = self.num_states;
        const off: u32 = @intCast(self.pc_pool.items.len);
        self.pc_pool.appendSlice(self.allocator, self.tmp_next_pcs.items) catch {
            self.bailed_out = true;
            return bailout_trans;
        };
        self.metas.append(self.allocator, .{
            .pc_off = off,
            .pc_len = @intCast(self.tmp_next_pcs.items.len),
            .prev_kind = next_prev_kind,
            .dirty = next_dirty,
        }) catch {
            self.bailed_out = true;
            return bailout_trans;
        };
        self.state_map.insert(self.allocator, self.metas.items, self.pc_pool.items, new_id) catch {
            self.bailed_out = true;
            return bailout_trans;
        };
        const row = self.trans[@as(usize, new_id) * @as(usize, self.stride) ..][0..self.stride];
        @memset(row, unknown_trans);
        self.eoi_cache[new_id] = 0;
        self.num_states += 1;
        if (!flushed) {
            self.trans[@as(usize, state_id) * @as(usize, self.stride) + cls] = new_id;
        }
        return new_id;
    }
};
