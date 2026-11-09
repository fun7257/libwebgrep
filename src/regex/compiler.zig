//! [Module] regex/compiler.zig
//! [Layer] Layer 2 — Regex Parser & Thompson NFA Compiler
//! [Role] Compiles regular expression syntax into bounded Thompson NFA bytecode (`[]Inst`)
//!        with structured `CompileDiagnostic` reporting and O(1) Unicode property/range classes.
//! [Invariants]
//!   1. Compilation enforces `max_inst` (`<= max_inst_hard_cap`) and bounded recursion depth (`<= 64`).
//!   2. Unicode properties (`\p{...}`, `\P{...}`) and codepoint ranges (`[一-龥]`) compile to compact `.unicode_class` states.
//!   3. Any syntax or limit error populates `diag: ?*CompileDiagnostic` with exact 0-based `offset` and 1-based `line`/`column`.
//! [HotPath] Compile-time / initialization-only (`Compiler.compile`).

const std = @import("std");
const unicode_fold = @import("../finder/unicode_fold.zig");
const prop_table = @import("../tables/unicode_prop_table.zig");
const inst_mod = @import("inst.zig");
const Inst = inst_mod.Inst;
const ByteSet = inst_mod.ByteSet;
const AssertKind = inst_mod.AssertKind;
const Error = inst_mod.Error;
const DiagnosticCode = inst_mod.DiagnosticCode;
const CompileDiagnostic = inst_mod.CompileDiagnostic;
const CodepointRange = inst_mod.CodepointRange;
const UnicodeRangeList = inst_mod.UnicodeRangeList;
const populateDiagnostic = inst_mod.populateDiagnostic;
const findInvalidUtf8Offset = inst_mod.findInvalidUtf8Offset;
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
    unicode_ranges: std.ArrayList(UnicodeRangeList) = .empty,
    diag: ?*CompileDiagnostic = null,
    pattern_index: ?usize = null,
    match_inst: Inst = .match,

    pub fn deinit(self: *Compiler) void {
        for (self.unicode_ranges.items) |item| {
            if (item.owned) self.allocator.free(item.ranges);
        }
        self.unicode_ranges.deinit(self.allocator);
        self.insts.deinit(self.allocator);
    }

    pub fn fail(self: *Compiler, err: Error, code: DiagnosticCode, pos: usize, msg: []const u8) Error {
        if (self.diag) |d| {
            if (d.code == .none) {
                populateDiagnostic(d, self.pattern, err, code, pos, msg, self.pattern_index);
            }
        }
        return err;
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

    pub fn emit(self: *Compiler, inst: Inst) Error!u32 {
        if (self.insts.items.len >= self.max_inst) {
            return self.fail(error.RegexTooLarge, .instruction_limit_exceeded, self.pos, "compiled instruction count exceeds maximum limit");
        }
        const idx: u32 = @intCast(self.insts.items.len);
        try self.insts.append(self.allocator, inst);
        return idx;
    }

    fn addUnicodeRangeList(self: *Compiler, ranges: []const CodepointRange, owned: bool) Error!u32 {
        if (!owned) {
            for (self.unicode_ranges.items, 0..) |existing, idx| {
                if (!existing.owned and existing.ranges.ptr == ranges.ptr and existing.ranges.len == ranges.len) {
                    return @intCast(idx);
                }
            }
        }
        const idx: u32 = @intCast(self.unicode_ranges.items.len);
        try self.unicode_ranges.append(self.allocator, .{ .ranges = ranges, .owned = owned });
        return idx;
    }

    pub fn patch(self: *Compiler, jmp_pc: u32, target: u32) void {
        switch (self.insts.items[jmp_pc]) {
            .jmp => self.insts.items[jmp_pc] = .{ .jmp = target },
            .byte => |*by| by.out = target,
            .class => |*cl| cl.out = target,
            .assert => |*as| as.out = target,
            .save => |*sv| sv.out = target,
            else => {},
        }
    }

    fn emitByteSeq(self: *Compiler, seq: []const u8, ignore_ascii_case: bool) Error!Frag {
        std.debug.assert(seq.len > 0);
        const last_pc = try self.emit(.{ .byte = .{
            .b = seq[seq.len - 1],
            .ignore_case = ignore_ascii_case and seq[seq.len - 1] < 0x80,
            .out = 0,
        } });
        var next_out: u32 = last_pc;
        var idx: usize = seq.len - 1;
        while (idx > 0) {
            idx -= 1;
            next_out = try self.emit(.{ .byte = .{
                .b = seq[idx],
                .ignore_case = ignore_ascii_case and seq[idx] < 0x80,
                .out = next_out,
            } });
        }
        return .{ .start = next_out, .end = last_pc };
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

    fn emitUnicodeClassInst(
        self: *Compiler,
        range_idx: u32,
        negated: bool,
        ascii_set: ByteSet,
        has_ascii_set: bool,
    ) Error!Frag {
        const end_jmp = try self.emit(.{ .jmp = 0 });
        const cont1 = try self.emit(.{ .any_cont = .{ .out = end_jmp } });
        const cont2 = try self.emit(.{ .any_cont = .{ .out = cont1 } });
        const cont3 = try self.emit(.{ .any_cont = .{ .out = cont2 } });
        const pc = try self.emit(.{ .unicode_class = .{
            .range_idx = range_idx,
            .negated = negated,
            .ascii_set = ascii_set,
            .has_ascii_set = has_ascii_set,
            .ignore_case = self.ignore_case and self.unicode_case,
            .allow_nl = self.multiline,
            .out = end_jmp,
            .cont1 = cont1,
            .cont2 = cont2,
            .cont3 = cont3,
        } });
        return .{ .start = pc, .end = end_jmp };
    }

    pub fn compile(self: *Compiler) Error!Frag {
        if (findInvalidUtf8Offset(self.pattern)) |bad_pos| {
            return self.fail(error.RegexSyntax, .invalid_utf8, bad_pos, "pattern contains invalid UTF-8 byte sequence");
        }
        const body = try self.parseAlt();
        if (self.pos != self.pattern.len) {
            if (self.pattern[self.pos] == ')') {
                return self.fail(error.RegexSyntax, .unmatched_close_paren, self.pos, "unmatched closing parenthesis ')'");
            }
            return self.fail(error.RegexSyntax, .invalid_escape, self.pos, "unexpected token in pattern");
        }
        const match_pc = try self.emit(self.match_inst);
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
                    if (had_quantifier) {
                        return self.fail(error.RegexSyntax, .dangling_quantifier, self.pos, "multiple repeat quantifiers on single atom");
                    }
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
                    if (had_quantifier) {
                        return self.fail(error.RegexSyntax, .dangling_quantifier, self.pos, "multiple repeat quantifiers on single atom");
                    }
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
        const brace_pos = self.pos;
        self.pos += 1; // skip '{'
        // If there is no closing '}' anywhere after '{', report unclosed_repeat_braces
        if (std.mem.indexOfScalarPos(u8, self.pattern, self.pos, '}') == null) {
            return self.fail(error.RegexSyntax, .unclosed_repeat_braces, brace_pos, "unclosed repeat braces '{'");
        }
        if (self.pos < self.pattern.len and self.pattern[self.pos] == '}') {
            return self.fail(error.RegexSyntax, .invalid_repeat_bounds, brace_pos, "empty repeat braces '{}'");
        }
        const min = try self.parseNumber(brace_pos);
        if (self.pos >= self.pattern.len) {
            return self.fail(error.RegexSyntax, .unclosed_repeat_braces, brace_pos, "unclosed repeat braces '{'");
        }
        if (self.pattern[self.pos] == '}') {
            self.pos += 1;
            return .{ .min = min, .max = min };
        }
        if (self.pattern[self.pos] != ',') {
            return self.fail(error.RegexSyntax, .invalid_repeat_bounds, brace_pos, "invalid character in repeat braces");
        }
        self.pos += 1;
        if (self.pos >= self.pattern.len) {
            return self.fail(error.RegexSyntax, .unclosed_repeat_braces, brace_pos, "unclosed repeat braces '{'");
        }
        if (self.pattern[self.pos] == '}') {
            self.pos += 1;
            return .{ .min = min, .max = null };
        }
        const max = try self.parseNumber(brace_pos);
        if (self.pos >= self.pattern.len or self.pattern[self.pos] != '}') {
            return self.fail(error.RegexSyntax, .invalid_repeat_bounds, brace_pos, "invalid repeat bounds");
        }
        if (max < min) {
            return self.fail(error.RegexSyntax, .invalid_repeat_bounds, brace_pos, "repeat max is less than min");
        }
        self.pos += 1;
        return .{ .min = min, .max = max };
    }

    fn parseNumber(self: *Compiler, brace_pos: usize) Error!usize {
        const start = self.pos;
        var val: usize = 0;
        while (self.pos < self.pattern.len and self.pattern[self.pos] >= '0' and self.pattern[self.pos] <= '9') : (self.pos += 1) {
            val = std.math.mul(usize, val, 10) catch {
                return self.fail(error.RegexTooLarge, .instruction_limit_exceeded, brace_pos, "repeat count overflow");
            };
            val = std.math.add(usize, val, self.pattern[self.pos] - '0') catch {
                return self.fail(error.RegexTooLarge, .instruction_limit_exceeded, brace_pos, "repeat count overflow");
            };
            if (val > inst_mod.max_repeat_hard_cap or val > self.max_inst) {
                return self.fail(error.RegexTooLarge, .instruction_limit_exceeded, brace_pos, "repeat count exceeds maximum limit");
            }
        }
        if (self.pos == start) {
            return self.fail(error.RegexSyntax, .invalid_repeat_bounds, brace_pos, "expected number in repeat braces");
        }
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
        if (self.pos >= self.pattern.len) {
            return self.fail(error.RegexSyntax, .empty_pattern, self.pos, "unexpected end of pattern");
        }
        const c = self.pattern[self.pos];
        switch (c) {
            '(' => {
                const paren_pos = self.pos;
                if (self.depth >= inst_mod.max_recursion_depth) {
                    return self.fail(error.RegexTooLarge, .recursion_depth_exceeded, paren_pos, "group nesting depth exceeds maximum (64)");
                }
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
                        if (self.pos >= self.pattern.len or self.pattern[self.pos] != ')') {
                            return self.fail(error.RegexSyntax, .unclosed_group, paren_pos, "unclosed non-capturing group '(?:'");
                        }
                        self.pos += 1;
                        return inner;
                    }
                    if (self.pos >= self.pattern.len) {
                        return self.fail(error.RegexSyntax, .unclosed_group, paren_pos, "unclosed group '('");
                    }
                    return self.fail(error.RegexSyntax, .invalid_inline_flags, paren_pos, "invalid inline flags in '(?...)'");
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
                if (self.pos >= self.pattern.len or self.pattern[self.pos] != ')') {
                    return self.fail(error.RegexSyntax, .unclosed_group, paren_pos, "unclosed group parenthesis '('");
                }
                self.pos += 1;
                if (group_id >= 1 and group_id <= 9) {
                    const slot_start: u8 = (group_id - 1) * 2;
                    const slot_end: u8 = slot_start + 1;
                    const save_end = try self.emit(.{ .save = .{ .slot = slot_end, .out = 0 } });
                    self.patch(inner.end, save_end);
                    const save_start = try self.emit(.{ .save = .{ .slot = slot_start, .out = inner.start } });
                    return .{ .start = save_start, .end = save_end };
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
                const pc = try self.emit(.{ .assert = .{ .kind = .start_line, .out = 0 } });
                return .{ .start = pc, .end = pc };
            },
            '$' => {
                self.pos += 1;
                const pc = try self.emit(.{ .assert = .{ .kind = .end_line, .out = 0 } });
                return .{ .start = pc, .end = pc };
            },
            '[' => return self.parseClass(),
            '\\' => return self.parseEscape(),
            '*', '+', '?', '{' => {
                return self.fail(error.RegexSyntax, .dangling_quantifier, self.pos, "quantifier has no preceding atom");
            },
            ')' => {
                return self.fail(error.RegexSyntax, .unmatched_close_paren, self.pos, "unmatched closing parenthesis ')'");
            },
            '|', '}' => {
                return self.fail(error.RegexSyntax, .invalid_escape, self.pos, "unexpected token in atom");
            },
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
                const pc = try self.emit(.{ .byte = .{ .b = c, .ignore_case = self.ignore_case, .out = 0 } });
                return .{ .start = pc, .end = pc };
            },
        }
    }

    const ParsedUnicodeProp = struct {
        ranges: []const CodepointRange,
        negated: bool,
    };

    fn parseUnicodePropertySpec(self: *Compiler, esc_char: u8, prop_start_pos: usize) Error!ParsedUnicodeProp {
        var is_neg = (esc_char == 'P');
        if (self.pos >= self.pattern.len) {
            return self.fail(error.RegexSyntax, .unknown_unicode_property, prop_start_pos, "missing Unicode property name after \\p");
        }
        var raw_name: []const u8 = undefined;
        if (self.pattern[self.pos] == '{') {
            self.pos += 1; // skip '{'
            const close_idx = std.mem.indexOfScalarPos(u8, self.pattern, self.pos, '}') orelse {
                return self.fail(error.RegexSyntax, .unclosed_unicode_property, prop_start_pos, "unclosed Unicode property '{'");
            };
            raw_name = self.pattern[self.pos..close_idx];
            self.pos = close_idx + 1;
            // Trim leading ASCII whitespace to check for '^' negation prefix
            var trimmed = std.mem.trim(u8, raw_name, " \t\r\n");
            if (trimmed.len > 0 and trimmed[0] == '^') {
                is_neg = !is_neg;
                raw_name = trimmed[1..];
            }
        } else {
            // Single-letter shorthand property \pL, \pN, \pP, \pS, \pZ, \pM, \pC
            const ch = self.pattern[self.pos];
            if (ch >= 0x80) {
                return self.fail(error.RegexSyntax, .unknown_unicode_property, prop_start_pos, "invalid shorthand Unicode property");
            }
            raw_name = self.pattern[self.pos .. self.pos + 1];
            self.pos += 1;
        }

        const spec = prop_table.lookupProperty(raw_name) orelse {
            return self.fail(error.RegexSyntax, .unknown_unicode_property, prop_start_pos, "unknown Unicode property or script name");
        };
        const ranges = if (self.ignore_case and self.unicode_case and spec.is_cased_subcat)
            &prop_table.gc_LC
        else
            spec.ranges;
        return .{ .ranges = ranges, .negated = is_neg };
    }

    fn parseEscape(self: *Compiler) Error!Frag {
        const slash_pos = self.pos;
        self.pos += 1; // skip '\'
        if (self.pos >= self.pattern.len) {
            return self.fail(error.RegexSyntax, .trailing_backslash, slash_pos, "trailing backslash at end of pattern");
        }
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
            'p', 'P' => {
                const parsed = try self.parseUnicodePropertySpec(c, slash_pos);
                const range_idx = try self.addUnicodeRangeList(parsed.ranges, false);
                return self.emitUnicodeClassInst(range_idx, parsed.negated, .{}, false);
            },
            'A' => {
                const pc = try self.emit(.{ .assert = .{ .kind = .start_input, .out = 0 } });
                return .{ .start = pc, .end = pc };
            },
            'z' => {
                const pc = try self.emit(.{ .assert = .{ .kind = .end_input, .out = 0 } });
                return .{ .start = pc, .end = pc };
            },
            'b' => {
                const pc = try self.emit(.{ .assert = .{ .kind = .word_boundary, .out = 0 } });
                return .{ .start = pc, .end = pc };
            },
            'B' => {
                const pc = try self.emit(.{ .assert = .{ .kind = .not_word_boundary, .out = 0 } });
                return .{ .start = pc, .end = pc };
            },
            'd', 'D', 'w', 'W', 's', 'S' => {
                var set = ByteSet{};
                addShorthand(&set, c);
                if (!self.multiline) set.clear('\n');
                const is_neg = (c == 'D' or c == 'W' or c == 'S');
                if (is_neg) {
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
                const pc = try self.emit(.{ .class = .{ .set = set, .out = 0 } });
                return .{ .start = pc, .end = pc };
            },
            else => {
                const b: u8 = switch (c) {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    '0' => 0,
                    else => c,
                };
                const pc = try self.emit(.{ .byte = .{ .b = b, .ignore_case = self.ignore_case, .out = 0 } });
                return .{ .start = pc, .end = pc };
            },
        }
    }

    fn appendComplementRanges(allocator: std.mem.Allocator, list: *std.ArrayList(CodepointRange), ranges: []const CodepointRange) !void {
        var cur: u21 = 0;
        for (ranges) |r| {
            if (r.start > cur) {
                try list.append(allocator, .{ .start = cur, .end = r.start - 1 });
            }
            if (r.end == 0x10FFFF) {
                cur = 0x10FFFF;
                return;
            }
            cur = r.end + 1;
        }
        if (cur <= 0x10FFFF) {
            try list.append(allocator, .{ .start = cur, .end = 0x10FFFF });
        }
    }

    fn sortAndMergeRanges(allocator: std.mem.Allocator, list: *std.ArrayList(CodepointRange)) ![]const CodepointRange {
        if (list.items.len <= 1) return list.toOwnedSlice(allocator);
        std.mem.sort(CodepointRange, list.items, {}, struct {
            fn lessThan(_: void, a: CodepointRange, b: CodepointRange) bool {
                return a.start < b.start or (a.start == b.start and a.end < b.end);
            }
        }.lessThan);
        var write_idx: usize = 0;
        for (list.items[1..]) |r| {
            if (r.start <= list.items[write_idx].end +| 1) {
                if (r.end > list.items[write_idx].end) {
                    list.items[write_idx].end = r.end;
                }
            } else {
                write_idx += 1;
                list.items[write_idx] = r;
            }
        }
        list.shrinkRetainingCapacity(write_idx + 1);
        return list.toOwnedSlice(allocator);
    }

    fn parseClass(self: *Compiler) Error!Frag {
        const class_start_pos = self.pos;
        self.pos += 1; // skip '['
        if (self.pos >= self.pattern.len) {
            return self.fail(error.RegexSyntax, .unclosed_char_class, class_start_pos, "unclosed character class '['");
        }
        var negated = false;
        if (self.pattern[self.pos] == '^' or self.pattern[self.pos] == '!') {
            negated = true;
            self.pos += 1;
        }
        var set = ByteSet{};
        var has_byte_set = false;
        var unicode_list = std.ArrayList(CodepointRange).empty;
        defer unicode_list.deinit(self.allocator);
        var has_unicode_ranges = false;

        var first = true;
        while (self.pos < self.pattern.len) {
            const c = self.pattern[self.pos];
            if (c == ']' and !first) {
                self.pos += 1;
                if (has_unicode_ranges) {
                    const owned_ranges = try sortAndMergeRanges(self.allocator, &unicode_list);
                    errdefer self.allocator.free(owned_ranges);
                    const range_idx = try self.addUnicodeRangeList(owned_ranges, true);
                    return self.emitUnicodeClassInst(range_idx, negated, set, has_byte_set);
                }
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
                const pc = try self.emit(.{ .class = .{ .set = set, .out = 0 } });
                return .{ .start = pc, .end = pc };
            }
            first = false;

            // Check for \p{...} or \P{...} inside [...]
            if (c == '\\' and self.pos + 1 < self.pattern.len and (self.pattern[self.pos + 1] == 'p' or self.pattern[self.pos + 1] == 'P')) {
                const prop_pos = self.pos;
                const esc_c = self.pattern[self.pos + 1];
                self.pos += 2;
                const parsed = try self.parseUnicodePropertySpec(esc_c, prop_pos);
                if (self.pos + 1 < self.pattern.len and self.pattern[self.pos] == '-' and self.pattern[self.pos + 1] != ']') {
                    return self.fail(error.RegexSyntax, .invalid_char_range, self.pos, "cannot use Unicode property as character range bound");
                }
                has_unicode_ranges = true;
                if (parsed.negated) {
                    try appendComplementRanges(self.allocator, &unicode_list, parsed.ranges);
                } else {
                    try unicode_list.appendSlice(self.allocator, parsed.ranges);
                }
                continue;
            }

            if (c >= 0x80) {
                const seq_len = utf8SeqLenAt(self.pattern, self.pos, self.pattern.len);
                if (seq_len > 1) {
                    const lo_raw = self.pattern[self.pos .. self.pos + seq_len];
                    const lo_cp = std.unicode.utf8Decode(lo_raw) catch unreachable;
                    self.pos += seq_len;
                    has_unicode_ranges = true;
                    if (self.pos + 1 < self.pattern.len and self.pattern[self.pos] == '-' and self.pattern[self.pos + 1] != ']') {
                        const dash_pos = self.pos;
                        self.pos += 1; // skip '-'
                        if (self.pos < self.pattern.len and self.pattern[self.pos] == '\\') {
                            return self.fail(error.RegexSyntax, .invalid_char_range, dash_pos, "invalid character class range");
                        }
                        const hi_len = utf8SeqLenAt(self.pattern, self.pos, self.pattern.len);
                        if (hi_len <= 1) {
                            return self.fail(error.RegexSyntax, .invalid_char_range, dash_pos, "invalid UTF-8 upper bound in character range");
                        }
                        const hi_raw = self.pattern[self.pos .. self.pos + hi_len];
                        const hi_cp = std.unicode.utf8Decode(hi_raw) catch {
                            return self.fail(error.RegexSyntax, .invalid_char_range, dash_pos, "invalid UTF-8 in character range");
                        };
                        self.pos += hi_len;
                        if (hi_cp < lo_cp) {
                            return self.fail(error.RegexSyntax, .invalid_char_range, dash_pos, "character range start is greater than end");
                        }
                        try unicode_list.append(self.allocator, .{ .start = lo_cp, .end = hi_cp });
                        if (self.ignore_case and self.unicode_case and (hi_cp - lo_cp <= 256)) {
                            var cp: u21 = lo_cp;
                            while (cp <= hi_cp) : (cp += 1) {
                                var eq: [4]u21 = undefined;
                                const n_eq = unicode_fold.foldEquivalents(cp, &eq);
                                for (eq[0..n_eq]) |alt_cp| {
                                    try unicode_list.append(self.allocator, .{ .start = alt_cp, .end = alt_cp });
                                }
                            }
                        }
                    } else {
                        try unicode_list.append(self.allocator, .{ .start = lo_cp, .end = lo_cp });
                        if (self.ignore_case and self.unicode_case) {
                            var eq: [4]u21 = undefined;
                            const n_eq = unicode_fold.foldEquivalents(lo_cp, &eq);
                            for (eq[0..n_eq]) |alt_cp| {
                                try unicode_list.append(self.allocator, .{ .start = alt_cp, .end = alt_cp });
                            }
                        }
                    }
                    continue;
                }
            }

            const item_pos = self.pos;
            const lo = try self.parseClassChar(&set);
            has_byte_set = true;
            if (lo) |start_ch| {
                if (self.pos + 1 < self.pattern.len and self.pattern[self.pos] == '-' and self.pattern[self.pos + 1] != ']') {
                    const dash_pos = self.pos;
                    self.pos += 1; // skip '-'
                    // Check if upper bound is a multi-byte UTF-8 codepoint (e.g. [\x00-\u{10FFFF}])
                    if (self.pos < self.pattern.len and self.pattern[self.pos] >= 0x80) {
                        const hi_len = utf8SeqLenAt(self.pattern, self.pos, self.pattern.len);
                        if (hi_len > 1) {
                            const hi_cp = std.unicode.utf8Decode(self.pattern[self.pos .. self.pos + hi_len]) catch {
                                return self.fail(error.RegexSyntax, .invalid_char_range, dash_pos, "invalid UTF-8 in character range");
                            };
                            self.pos += hi_len;
                            has_unicode_ranges = true;
                            try unicode_list.append(self.allocator, .{ .start = start_ch, .end = hi_cp });
                            continue;
                        }
                    }
                    const hi = (try self.parseClassChar(&set)) orelse {
                        return self.fail(error.RegexSyntax, .invalid_char_range, dash_pos, "invalid shorthand in character class range");
                    };
                    if (hi < start_ch) {
                        return self.fail(error.RegexSyntax, .invalid_char_range, dash_pos, "character range start is greater than end");
                    }
                    set.setRange(start_ch, hi, self.ignore_case);
                } else {
                    set.setWithCase(start_ch, self.ignore_case);
                }
            } else {
                // Shorthand (\d, \w, \s) cannot be the start of a range like [\d-z]
                if (self.pos + 1 < self.pattern.len and self.pattern[self.pos] == '-' and self.pattern[self.pos + 1] != ']') {
                    return self.fail(error.RegexSyntax, .invalid_char_range, item_pos, "shorthand class cannot be range bound");
                }
            }
        }
        return self.fail(error.RegexSyntax, .unclosed_char_class, class_start_pos, "unclosed character class '['");
    }

    fn parseClassChar(self: *Compiler, set: *ByteSet) Error!?u8 {
        if (self.pos >= self.pattern.len) {
            return self.fail(error.RegexSyntax, .unclosed_char_class, self.pos, "unclosed character class '['");
        }
        const c = self.pattern[self.pos];
        const slash_pos = self.pos;
        self.pos += 1;
        if (c != '\\') return c;
        if (self.pos >= self.pattern.len) {
            return self.fail(error.RegexSyntax, .trailing_backslash, slash_pos, "trailing backslash in character class");
        }
        const esc = self.pattern[self.pos];
        self.pos += 1;
        switch (esc) {
            'd', 'D', 'w', 'W', 's', 'S' => {
                addShorthand(set, esc);
                return null;
            },
            'p', 'P' => {
                return self.fail(error.RegexSyntax, .invalid_char_range, slash_pos, "cannot use Unicode property as character range bound");
            },
            'n' => return '\n',
            'r' => return '\r',
            't' => return '\t',
            '0' => return 0,
            else => return esc,
        }
    }
};
