//! [Module] regex/compiler.zig
//! [Layer] Layer 2 — Regex Parser & Thompson NFA Compiler
//! [Role] Compiles regular expression syntax into bounded Thompson NFA bytecode (`[]Inst`).
//! [Invariants]
//!   1. Compilation enforces `max_inst` (`<= max_inst_hard_cap = 4096`) and bounded recursion depth (`<= 64`).
//!   2. Multi-byte UTF-8 character classes and Unicode Simple Case Folding expand into deterministic byte-level NFA states.
//! [HotPath] Compile-time / initialization-only (`Compiler.compile`).

const std = @import("std");
const unicode_fold = @import("../finder/unicode_fold.zig");
const inst_mod = @import("inst.zig");
const Inst = inst_mod.Inst;
const ByteSet = inst_mod.ByteSet;
const AssertKind = inst_mod.AssertKind;
const Error = inst_mod.Error;
const utf8SeqLenAt = inst_mod.utf8SeqLenAt;
const addShorthand = inst_mod.addShorthand;

pub const Frag = struct {
    start: u32,
    end: u32,
};

pub const Compiler = struct {
    allocator: std.mem.Allocator,
    pattern: []const u8,
    pos: usize = 0,
    depth: usize = 0,
    ignore_case: bool,
    unicode_case: bool = true,
    multiline: bool,
    dot_all: bool,
    capture_count: u8 = 0,
    capture_positions: [9]usize = @splat(std.math.maxInt(usize)),
    max_inst: usize,
    insts: std.ArrayList(Inst) = .empty,

    pub fn deinit(self: *Compiler) void {
        self.insts.deinit(self.allocator);
    }

    fn groupForPos(self: *Compiler, paren_pos: usize) u8 {
        for (self.capture_positions[0..self.capture_count], 0..) |p, idx| {
            if (p == paren_pos) return @intCast(idx + 1);
        }
        if (self.capture_count < 9) {
            self.capture_positions[self.capture_count] = paren_pos;
            self.capture_count += 1;
            return self.capture_count;
        }
        return 0;
    }

    fn emit(self: *Compiler, inst: Inst) Error!u32 {
        if (self.insts.items.len >= self.max_inst) return error.RegexTooLarge;
        const idx: u32 = @intCast(self.insts.items.len);
        try self.insts.append(self.allocator, inst);
        return idx;
    }

    fn patch(self: *Compiler, jmp_pc: u32, target: u32) void {
        self.insts.items[jmp_pc] = .{ .jmp = target };
    }

    fn emitByteSeq(self: *Compiler, seq: []const u8, ignore_ascii_case: bool) Error!Frag {
        const end_jmp = try self.emit(.{ .jmp = 0 });
        var next_out: u32 = end_jmp;
        var idx: usize = seq.len;
        while (idx > 0) {
            idx -= 1;
            next_out = try self.emit(.{ .byte = .{
                .b = seq[idx],
                .ignore_case = ignore_ascii_case and seq[idx] < 0x80,
                .out = next_out,
            } });
        }
        return .{ .start = next_out, .end = end_jmp };
    }

    fn emitCodepoint(self: *Compiler, cp: u21, raw_bytes: []const u8) Error!Frag {
        if (self.ignore_case and self.unicode_case) {
            var eq: [4]u21 = undefined;
            const eq_count = unicode_fold.foldEquivalents(cp, &eq);
            if (eq_count > 1) {
                var combined: ?Frag = null;
                for (eq[0..eq_count]) |variant_cp| {
                    var u8buf: [4]u8 = undefined;
                    const ulen = std.unicode.utf8Encode(variant_cp, &u8buf) catch continue;
                    const frag = try self.emitByteSeq(u8buf[0..ulen], false);
                    if (combined) |prev| {
                        const split_pc = try self.emit(.{ .split = .{ .out1 = prev.start, .out2 = frag.start } });
                        const join_jmp = try self.emit(.{ .jmp = 0 });
                        self.patch(prev.end, join_jmp);
                        self.patch(frag.end, join_jmp);
                        combined = .{ .start = split_pc, .end = join_jmp };
                    } else {
                        combined = frag;
                    }
                }
                if (combined) |c| return c;
            }
        }
        return self.emitByteSeq(raw_bytes, self.ignore_case);
    }

    pub fn compile(self: *Compiler) Error!Frag {
        const body = try self.parseAlt();
        if (self.pos != self.pattern.len) return error.RegexSyntax;
        const match_pc = try self.emit(.match);
        self.patch(body.end, match_pc);
        return .{ .start = body.start, .end = match_pc };
    }

    fn parseAlt(self: *Compiler) Error!Frag {
        var left = try self.parseConcat();
        while (self.pos < self.pattern.len and self.pattern[self.pos] == '|') {
            self.pos += 1;
            const right = try self.parseConcat();
            const split_pc = try self.emit(.{ .split = .{ .out1 = left.start, .out2 = right.start } });
            const join_jmp = try self.emit(.{ .jmp = 0 });
            self.patch(left.end, join_jmp);
            self.patch(right.end, join_jmp);
            left = .{ .start = split_pc, .end = join_jmp };
        }
        return left;
    }

    fn parseConcat(self: *Compiler) Error!Frag {
        var first: ?Frag = null;
        while (self.pos < self.pattern.len) {
            const c = self.pattern[self.pos];
            if (c == ')' or c == '|') break;
            const rep = try self.parseRepeat();
            if (first) |prev| {
                self.patch(prev.end, rep.start);
                first = .{ .start = prev.start, .end = rep.end };
            } else {
                first = rep;
            }
        }
        if (first) |f| return f;
        const nop = try self.emit(.{ .jmp = 0 });
        return .{ .start = nop, .end = nop };
    }

    fn parseRepeat(self: *Compiler) Error!Frag {
        const atom_start_pos = self.pos;
        var atom = try self.parseAtom();
        const atom_end_pos = self.pos;

        var had_quantifier = false;
        while (self.pos < self.pattern.len) {
            const c = self.pattern[self.pos];
            switch (c) {
                '*', '+', '?' => {
                    if (had_quantifier) return error.RegexSyntax;
                    had_quantifier = true;
                    self.pos += 1;
                    var lazy = false;
                    if (self.pos < self.pattern.len and self.pattern[self.pos] == '?') {
                        lazy = true;
                        self.pos += 1;
                    }
                    atom = try self.applyQuantifier(atom, c, lazy);
                },
                '{' => {
                    if (had_quantifier) return error.RegexSyntax;
                    had_quantifier = true;
                    const bounds = try self.parseBraces();
                    var lazy = false;
                    if (self.pos < self.pattern.len and self.pattern[self.pos] == '?') {
                        lazy = true;
                        self.pos += 1;
                    }
                    atom = try self.applyBoundedRepeat(atom, atom_start_pos, atom_end_pos, bounds.min, bounds.max, lazy);
                },
                else => break,
            }
        }
        return atom;
    }

    fn applyQuantifier(self: *Compiler, atom: Frag, kind: u8, lazy: bool) Error!Frag {
        const exit_jmp = try self.emit(.{ .jmp = 0 });
        switch (kind) {
            '?' => {
                const split_pc = try self.emit(.{
                    .split = if (lazy)
                        .{ .out1 = exit_jmp, .out2 = atom.start }
                    else
                        .{ .out1 = atom.start, .out2 = exit_jmp },
                });
                self.patch(atom.end, exit_jmp);
                return .{ .start = split_pc, .end = exit_jmp };
            },
            '*' => {
                const split_pc = try self.emit(.{
                    .split = if (lazy)
                        .{ .out1 = exit_jmp, .out2 = atom.start }
                    else
                        .{ .out1 = atom.start, .out2 = exit_jmp },
                });
                self.patch(atom.end, split_pc);
                return .{ .start = split_pc, .end = exit_jmp };
            },
            '+' => {
                const split_pc = try self.emit(.{
                    .split = if (lazy)
                        .{ .out1 = exit_jmp, .out2 = atom.start }
                    else
                        .{ .out1 = atom.start, .out2 = exit_jmp },
                });
                self.patch(atom.end, split_pc);
                return .{ .start = atom.start, .end = exit_jmp };
            },
            else => unreachable,
        }
    }

    const Bounds = struct { min: usize, max: ?usize };

    fn parseBraces(self: *Compiler) Error!Bounds {
        self.pos += 1; // skip '{'
        const min = try self.parseNumber();
        if (self.pos >= self.pattern.len) return error.RegexSyntax;
        if (self.pattern[self.pos] == '}') {
            self.pos += 1;
            return .{ .min = min, .max = min };
        }
        if (self.pattern[self.pos] != ',') return error.RegexSyntax;
        self.pos += 1;
        if (self.pos >= self.pattern.len) return error.RegexSyntax;
        if (self.pattern[self.pos] == '}') {
            self.pos += 1;
            return .{ .min = min, .max = null };
        }
        const max = try self.parseNumber();
        if (self.pos >= self.pattern.len or self.pattern[self.pos] != '}' or max < min) {
            return error.RegexSyntax;
        }
        self.pos += 1;
        return .{ .min = min, .max = max };
    }

    fn parseNumber(self: *Compiler) Error!usize {
        const start = self.pos;
        var val: usize = 0;
        while (self.pos < self.pattern.len and self.pattern[self.pos] >= '0' and self.pattern[self.pos] <= '9') : (self.pos += 1) {
            val = std.math.mul(usize, val, 10) catch return error.RegexTooLarge;
            val = std.math.add(usize, val, self.pattern[self.pos] - '0') catch return error.RegexTooLarge;
            if (val > self.max_inst) return error.RegexTooLarge;
        }
        if (self.pos == start) return error.RegexSyntax;
        return val;
    }

    fn applyBoundedRepeat(
        self: *Compiler,
        first_atom: Frag,
        atom_start_pos: usize,
        atom_end_pos: usize,
        min: usize,
        max: ?usize,
        lazy: bool,
    ) Error!Frag {
        const saved_pos = self.pos;
        defer self.pos = saved_pos;

        var current: ?Frag = null;
        if (min == 0) {
            // first_atom is treated as optional or discarded; rebuild from 0
            self.insts.shrinkRetainingCapacity(first_atom.start);
        } else {
            current = first_atom;
            var k: usize = 1;
            while (k < min) : (k += 1) {
                self.pos = atom_start_pos;
                const next_copy = try self.parseAtom();
                std.debug.assert(self.pos == atom_end_pos);
                self.patch(current.?.end, next_copy.start);
                current = .{ .start = current.?.start, .end = next_copy.end };
            }
        }

        if (max) |m| {
            var k: usize = min;
            while (k < m) : (k += 1) {
                self.pos = atom_start_pos;
                const opt_copy = try self.parseAtom();
                const q = try self.applyQuantifier(opt_copy, '?', lazy);
                if (current) |prev| {
                    self.patch(prev.end, q.start);
                    current = .{ .start = prev.start, .end = q.end };
                } else {
                    current = q;
                }
            }
        } else {
            self.pos = atom_start_pos;
            const star_copy = try self.parseAtom();
            const q = try self.applyQuantifier(star_copy, '*', lazy);
            if (current) |prev| {
                self.patch(prev.end, q.start);
                current = .{ .start = prev.start, .end = q.end };
            } else {
                current = q;
            }
        }

        if (current) |c| return c;
        const nop = try self.emit(.{ .jmp = 0 });
        return .{ .start = nop, .end = nop };
    }

    fn parseAtom(self: *Compiler) Error!Frag {
        if (self.pos >= self.pattern.len) return error.RegexSyntax;
        const c = self.pattern[self.pos];
        switch (c) {
            '(' => {
                const paren_pos = self.pos;
                self.pos += 1;
                if (self.pos < self.pattern.len and self.pattern[self.pos] == '?') {
                    self.pos += 1;
                    var new_i = self.ignore_case;
                    var new_m = self.multiline;
                    var new_s = self.dot_all;
                    var neg = false;
                    var saw_flag = false;
                    while (self.pos < self.pattern.len) {
                        switch (self.pattern[self.pos]) {
                            '-' => {
                                neg = true;
                                saw_flag = true;
                                self.pos += 1;
                            },
                            'i' => {
                                new_i = !neg;
                                saw_flag = true;
                                self.pos += 1;
                            },
                            'm' => {
                                new_m = !neg;
                                saw_flag = true;
                                self.pos += 1;
                            },
                            's' => {
                                new_s = !neg;
                                saw_flag = true;
                                self.pos += 1;
                            },
                            else => break,
                        }
                    }
                    if (self.pos < self.pattern.len and self.pattern[self.pos] == ')' and saw_flag) {
                        self.pos += 1;
                        self.ignore_case = new_i;
                        self.multiline = new_m;
                        self.dot_all = new_s;
                        const nop = try self.emit(.{ .jmp = 0 });
                        return .{ .start = nop, .end = nop };
                    }
                    if (self.pos < self.pattern.len and self.pattern[self.pos] == ':') {
                        self.pos += 1;
                        const saved_i = self.ignore_case;
                        const saved_m = self.multiline;
                        const saved_s = self.dot_all;
                        self.ignore_case = new_i;
                        self.multiline = new_m;
                        self.dot_all = new_s;
                        self.depth += 1;
                        defer {
                            self.depth -= 1;
                            self.ignore_case = saved_i;
                            self.multiline = saved_m;
                            self.dot_all = saved_s;
                        }
                        const inner = try self.parseAlt();
                        if (self.pos >= self.pattern.len or self.pattern[self.pos] != ')') return error.RegexSyntax;
                        self.pos += 1;
                        return inner;
                    }
                    return error.RegexSyntax;
                }
                const group_id = self.groupForPos(paren_pos);
                const saved_i = self.ignore_case;
                const saved_m = self.multiline;
                const saved_s = self.dot_all;
                self.depth += 1;
                const inner = blk: {
                    errdefer self.depth -= 1;
                    break :blk try self.parseAlt();
                };
                self.depth -= 1;
                self.ignore_case = saved_i;
                self.multiline = saved_m;
                self.dot_all = saved_s;
                if (self.pos >= self.pattern.len or self.pattern[self.pos] != ')') return error.RegexSyntax;
                self.pos += 1;
                if (group_id >= 1 and group_id <= 9) {
                    const slot_start: u8 = (group_id - 1) * 2;
                    const slot_end: u8 = slot_start + 1;
                    const end_jmp = try self.emit(.{ .jmp = 0 });
                    const save_end = try self.emit(.{ .save = .{ .slot = slot_end, .out = end_jmp } });
                    self.patch(inner.end, save_end);
                    const save_start = try self.emit(.{ .save = .{ .slot = slot_start, .out = inner.start } });
                    return .{ .start = save_start, .end = end_jmp };
                }
                return inner;
            },
            '.' => {
                self.pos += 1;
                const end_jmp = try self.emit(.{ .jmp = 0 });
                const cont1 = try self.emit(.{ .any_cont = .{ .out = end_jmp } });
                const cont2 = try self.emit(.{ .any_cont = .{ .out = cont1 } });
                const cont3 = try self.emit(.{ .any_cont = .{ .out = cont2 } });
                const pc = try self.emit(.{ .any = .{
                    .allow_nl = self.dot_all and self.multiline,
                    .out = end_jmp,
                    .cont1 = cont1,
                    .cont2 = cont2,
                    .cont3 = cont3,
                } });
                return .{ .start = pc, .end = end_jmp };
            },
            '^' => {
                self.pos += 1;
                const end_jmp = try self.emit(.{ .jmp = 0 });
                const pc = try self.emit(.{ .assert = .{ .kind = .start_line, .out = end_jmp } });
                return .{ .start = pc, .end = end_jmp };
            },
            '$' => {
                self.pos += 1;
                const end_jmp = try self.emit(.{ .jmp = 0 });
                const pc = try self.emit(.{ .assert = .{ .kind = .end_line, .out = end_jmp } });
                return .{ .start = pc, .end = end_jmp };
            },
            '[' => return self.parseClass(),
            '\\' => return self.parseEscape(),
            '*', '+', '?', ')', '|', '{', '}' => return error.RegexSyntax,
            else => {
                if (c >= 0x80) {
                    const seq_len = utf8SeqLenAt(self.pattern, self.pos, self.pattern.len);
                    if (seq_len > 1) {
                        const raw = self.pattern[self.pos .. self.pos + seq_len];
                        const cp = std.unicode.utf8Decode(raw) catch unreachable;
                        self.pos += seq_len;
                        return self.emitCodepoint(cp, raw);
                    }
                }
                self.pos += 1;
                const end_jmp = try self.emit(.{ .jmp = 0 });
                const pc = try self.emit(.{ .byte = .{ .b = c, .ignore_case = self.ignore_case, .out = end_jmp } });
                return .{ .start = pc, .end = end_jmp };
            },
        }
    }

    fn parseEscape(self: *Compiler) Error!Frag {
        self.pos += 1; // skip '\'
        if (self.pos >= self.pattern.len) return error.RegexSyntax;
        const c = self.pattern[self.pos];
        if (c >= 0x80) {
            const seq_len = utf8SeqLenAt(self.pattern, self.pos, self.pattern.len);
            if (seq_len > 1) {
                const raw = self.pattern[self.pos .. self.pos + seq_len];
                const cp = std.unicode.utf8Decode(raw) catch unreachable;
                self.pos += seq_len;
                return self.emitCodepoint(cp, raw);
            }
        }
        self.pos += 1;
        switch (c) {
            'A' => {
                const end_jmp = try self.emit(.{ .jmp = 0 });
                const pc = try self.emit(.{ .assert = .{ .kind = .start_input, .out = end_jmp } });
                return .{ .start = pc, .end = end_jmp };
            },
            'z' => {
                const end_jmp = try self.emit(.{ .jmp = 0 });
                const pc = try self.emit(.{ .assert = .{ .kind = .end_input, .out = end_jmp } });
                return .{ .start = pc, .end = end_jmp };
            },
            'b' => {
                const end_jmp = try self.emit(.{ .jmp = 0 });
                const pc = try self.emit(.{ .assert = .{ .kind = .word_boundary, .out = end_jmp } });
                return .{ .start = pc, .end = end_jmp };
            },
            'B' => {
                const end_jmp = try self.emit(.{ .jmp = 0 });
                const pc = try self.emit(.{ .assert = .{ .kind = .not_word_boundary, .out = end_jmp } });
                return .{ .start = pc, .end = end_jmp };
            },
            'd', 'D', 'w', 'W', 's', 'S' => {
                var set = ByteSet{};
                addShorthand(&set, c);
                if (!self.multiline) set.clear('\n');
                const is_neg = (c == 'D' or c == 'W' or c == 'S');
                const end_jmp = try self.emit(.{ .jmp = 0 });
                var cont1: u32 = 0;
                var cont2: u32 = 0;
                var cont3: u32 = 0;
                if (is_neg) {
                    cont1 = try self.emit(.{ .any_cont = .{ .out = end_jmp } });
                    cont2 = try self.emit(.{ .any_cont = .{ .out = cont1 } });
                    cont3 = try self.emit(.{ .any_cont = .{ .out = cont2 } });
                }
                const pc = try self.emit(.{ .class = .{
                    .set = set,
                    .out = end_jmp,
                    .utf8_negated = is_neg,
                    .cont1 = cont1,
                    .cont2 = cont2,
                    .cont3 = cont3,
                } });
                return .{ .start = pc, .end = end_jmp };
            },
            else => {
                const b: u8 = switch (c) {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    '0' => 0,
                    else => c,
                };
                const end_jmp = try self.emit(.{ .jmp = 0 });
                const pc = try self.emit(.{ .byte = .{ .b = b, .ignore_case = self.ignore_case, .out = end_jmp } });
                return .{ .start = pc, .end = end_jmp };
            },
        }
    }

    fn parseClass(self: *Compiler) Error!Frag {
        self.pos += 1; // skip '['
        if (self.pos >= self.pattern.len) return error.RegexSyntax;
        var negated = false;
        if (self.pattern[self.pos] == '^' or self.pattern[self.pos] == '!') {
            negated = true;
            self.pos += 1;
        }
        var set = ByteSet{};
        var has_byte_set = false;
        var utf8_alt: ?Frag = null;
        var first = true;
        while (self.pos < self.pattern.len) {
            const c = self.pattern[self.pos];
            if (c == ']' and !first) {
                self.pos += 1;
                if (negated) {
                    set.invert();
                    if (!self.multiline) set.clear('\n');
                    const end_jmp = try self.emit(.{ .jmp = 0 });
                    const cont1 = try self.emit(.{ .any_cont = .{ .out = end_jmp } });
                    const cont2 = try self.emit(.{ .any_cont = .{ .out = cont1 } });
                    const cont3 = try self.emit(.{ .any_cont = .{ .out = cont2 } });
                    const pc = try self.emit(.{ .class = .{
                        .set = set,
                        .out = end_jmp,
                        .utf8_negated = true,
                        .cont1 = cont1,
                        .cont2 = cont2,
                        .cont3 = cont3,
                    } });
                    return .{ .start = pc, .end = end_jmp };
                }
                if (utf8_alt) |ufrag| {
                    if (!has_byte_set) return ufrag;
                    const end_jmp = try self.emit(.{ .jmp = 0 });
                    const class_pc = try self.emit(.{ .class = .{ .set = set, .out = end_jmp } });
                    const split_pc = try self.emit(.{ .split = .{ .out1 = class_pc, .out2 = ufrag.start } });
                    const join_jmp = try self.emit(.{ .jmp = 0 });
                    self.patch(end_jmp, join_jmp);
                    self.patch(ufrag.end, join_jmp);
                    return .{ .start = split_pc, .end = join_jmp };
                }
                const end_jmp = try self.emit(.{ .jmp = 0 });
                const pc = try self.emit(.{ .class = .{ .set = set, .out = end_jmp } });
                return .{ .start = pc, .end = end_jmp };
            }
            first = false;
            if (!negated and c >= 0x80) {
                const seq_len = utf8SeqLenAt(self.pattern, self.pos, self.pattern.len);
                if (seq_len > 1) {
                    const lo_raw = self.pattern[self.pos .. self.pos + seq_len];
                    const lo_cp = std.unicode.utf8Decode(lo_raw) catch unreachable;
                    self.pos += seq_len;
                    if (self.pos + 1 < self.pattern.len and self.pattern[self.pos] == '-' and self.pattern[self.pos + 1] != ']') {
                        self.pos += 1; // skip '-'
                        const hi_len = utf8SeqLenAt(self.pattern, self.pos, self.pattern.len);
                        if (hi_len <= 1) return error.RegexSyntax;
                        const hi_raw = self.pattern[self.pos .. self.pos + hi_len];
                        const hi_cp = std.unicode.utf8Decode(hi_raw) catch return error.RegexSyntax;
                        self.pos += hi_len;
                        if (hi_cp < lo_cp) return error.RegexSyntax;
                        if (hi_cp - lo_cp > self.max_inst) return error.RegexTooLarge;
                        var cp: u21 = lo_cp;
                        while (cp <= hi_cp) : (cp += 1) {
                            var u8buf: [4]u8 = undefined;
                            const ulen = std.unicode.utf8Encode(cp, &u8buf) catch continue;
                            const cp_frag = try self.emitCodepoint(cp, u8buf[0..ulen]);
                            if (utf8_alt) |prev| {
                                const split_pc = try self.emit(.{ .split = .{ .out1 = prev.start, .out2 = cp_frag.start } });
                                const join_jmp = try self.emit(.{ .jmp = 0 });
                                self.patch(prev.end, join_jmp);
                                self.patch(cp_frag.end, join_jmp);
                                utf8_alt = .{ .start = split_pc, .end = join_jmp };
                            } else {
                                utf8_alt = cp_frag;
                            }
                        }
                    } else {
                        const cp_frag = try self.emitCodepoint(lo_cp, lo_raw);
                        if (utf8_alt) |prev| {
                            const split_pc = try self.emit(.{ .split = .{ .out1 = prev.start, .out2 = cp_frag.start } });
                            const join_jmp = try self.emit(.{ .jmp = 0 });
                            self.patch(prev.end, join_jmp);
                            self.patch(cp_frag.end, join_jmp);
                            utf8_alt = .{ .start = split_pc, .end = join_jmp };
                        } else {
                            utf8_alt = cp_frag;
                        }
                    }
                    continue;
                }
            }
            const lo = try self.parseClassChar(&set);
            has_byte_set = true;
            if (lo) |start_ch| {
                if (self.pos + 1 < self.pattern.len and self.pattern[self.pos] == '-' and self.pattern[self.pos + 1] != ']') {
                    self.pos += 1; // skip '-'
                    const hi = (try self.parseClassChar(&set)) orelse return error.RegexSyntax;
                    if (hi < start_ch) return error.RegexSyntax;
                    set.setRange(start_ch, hi, self.ignore_case);
                } else {
                    set.setWithCase(start_ch, self.ignore_case);
                }
            }
        }
        return error.RegexSyntax;
    }

    fn parseClassChar(self: *Compiler, set: *ByteSet) Error!?u8 {
        if (self.pos >= self.pattern.len) return error.RegexSyntax;
        const c = self.pattern[self.pos];
        self.pos += 1;
        if (c != '\\') return c;
        if (self.pos >= self.pattern.len) return error.RegexSyntax;
        const esc = self.pattern[self.pos];
        self.pos += 1;
        switch (esc) {
            'd', 'D', 'w', 'W', 's', 'S' => {
                addShorthand(set, esc);
                return null;
            },
            'n' => return '\n',
            'r' => return '\r',
            't' => return '\t',
            '0' => return 0,
            else => return esc,
        }
    }
};

