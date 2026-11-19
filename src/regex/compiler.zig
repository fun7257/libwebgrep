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
    unicode_classes: bool = false,
    multiline: bool,
    dot_all: bool,
    capture_count: u8 = 0,
    capture_positions: [inst_mod.max_capture_groups]usize = @splat(std.math.maxInt(usize)),
    capture_names: [inst_mod.max_capture_groups][]const u8 = @splat(""),
    max_inst: usize,
    max_repeat: usize = inst_mod.default_max_repeat,
    max_recursion_depth: usize = inst_mod.default_max_recursion_depth,
    insts: std.ArrayList(Inst) = .empty,
    unicode_ranges: std.ArrayList(UnicodeRangeList) = .empty,
    has_lazy: bool = false,
    has_alt: bool = false,
    saw_scoped_m: bool = false,
    saw_ignore_case: bool = false,
    explicit_neg_m: bool = false,
    extended: bool = false,
    ungreedy: bool = false,
    saw_extended: bool = false,
    saw_ungreedy: bool = false,
    saw_literal_nl_pos: ?usize = null,
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

    fn recordLiteralNewline(self: *Compiler, pos: usize) void {
        if (!self.multiline and self.saw_literal_nl_pos == null) {
            self.saw_literal_nl_pos = pos;
        }
    }

    fn skipExtended(self: *Compiler) void {
        if (!self.extended) return;
        while (self.pos < self.pattern.len) {
            const b = self.pattern[self.pos];
            if (b == ' ' or b == '\t' or b == '\n' or b == '\r' or b == 0x0B or b == 0x0C) {
                self.pos += 1;
                continue;
            }
            if (b == '#') {
                self.pos += 1;
                while (self.pos < self.pattern.len and self.pattern[self.pos] != '\n') {
                    self.pos += 1;
                }
                if (self.pos < self.pattern.len and self.pattern[self.pos] == '\n') {
                    self.pos += 1;
                }
                continue;
            }
            break;
        }
    }

    fn groupForPos(self: *Compiler, paren_pos: usize) u8 {
        for (self.capture_positions[0..self.capture_count], 0..) |p, idx| {
            if (p == paren_pos) return @intCast(idx + 1);
        }
        if (self.capture_count < inst_mod.max_capture_groups) {
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
        const base_idx = self.insts.items.len;
        if (self.ignore_case) self.saw_ignore_case = true;
        if (findInvalidUtf8Offset(self.pattern)) |bad_pos| {
            return self.fail(error.RegexSyntax, .invalid_utf8, bad_pos, "pattern contains invalid UTF-8 byte sequence");
        }
        const body = try self.parseAlt();
        self.skipExtended();
        if (self.pos != self.pattern.len) {
            if (self.pattern[self.pos] == ')') {
                return self.fail(error.RegexSyntax, .unmatched_close_paren, self.pos, "unmatched closing parenthesis ')'");
            }
            return self.fail(error.RegexSyntax, .invalid_escape, self.pos, "unexpected token in pattern");
        }
        const match_pc = try self.emit(self.match_inst);
        self.patch(body.end, match_pc);
        self.optimizeByteExactLoops(base_idx);
        return .{ .start = body.start, .end = match_pc };
    }

    fn requiresAsciiFollow(items: []const Inst, start_pc: u32) bool {
        var stack: [64]u32 = undefined;
        var visited: [64]u32 = undefined;
        var sp: usize = 0;
        var visited_len: usize = 0;
        var saw_consumer = false;

        stack[0] = start_pc;
        sp = 1;
        while (sp > 0) {
            sp -= 1;
            const pc = stack[sp];
            if (pc >= items.len) return false;
            var already = false;
            for (visited[0..visited_len]) |v| {
                if (v == pc) {
                    already = true;
                    break;
                }
            }
            if (already) continue;
            if (visited_len >= visited.len) return false;
            visited[visited_len] = pc;
            visited_len += 1;

            switch (items[pc]) {
                .jmp => |t| {
                    if (sp >= stack.len) return false;
                    stack[sp] = t;
                    sp += 1;
                },
                .split => |s| {
                    if (sp + 2 > stack.len) return false;
                    stack[sp] = s.out1;
                    stack[sp + 1] = s.out2;
                    sp += 2;
                },
                .save => |sv| {
                    if (sp >= stack.len) return false;
                    stack[sp] = sv.out;
                    sp += 1;
                },
                .byte => |by| {
                    if (by.b >= 0x80) return false;
                    saw_consumer = true;
                },
                .class => |cl| {
                    if (cl.utf8_negated or cl.set.bits[2] != 0 or cl.set.bits[3] != 0) return false;
                    saw_consumer = true;
                },
                .any, .any_cont, .unicode_class, .assert, .match, .match_id => return false,
            }
        }
        return saw_consumer;
    }

    fn optimizeByteExactLoops(self: *Compiler, base_idx: usize) void {
        const effective_ml = self.multiline or self.saw_scoped_m;
        const items = self.insts.items;
        if (items.len < base_idx + 7) return;
        var pc: usize = items.len - 3;
        while (pc >= base_idx + 4) : (pc -= 1) {
            const end_jmp_pc: u32 = @intCast(pc - 4);
            const cont1_pc: u32 = @intCast(pc - 3);
            const cont2_pc: u32 = @intCast(pc - 2);
            const cont3_pc: u32 = @intCast(pc - 1);
            const atom_pc: u32 = @intCast(pc);
            const exit_jmp_pc: u32 = @intCast(pc + 1);
            const split_pc: u32 = @intCast(pc + 2);

            const end_target = switch (items[pc - 4]) {
                .jmp => |t| t,
                else => {
                    if (pc == base_idx + 4) break;
                    continue;
                },
            };
            if (end_target != split_pc) {
                if (pc == base_idx + 4) break;
                continue;
            }
            const ok_cont = blk: {
                switch (items[pc - 3]) {
                    .any_cont => |ac| if (ac.out != end_jmp_pc) break :blk false,
                    else => break :blk false,
                }
                switch (items[pc - 2]) {
                    .any_cont => |ac| if (ac.out != cont1_pc) break :blk false,
                    else => break :blk false,
                }
                switch (items[pc - 1]) {
                    .any_cont => |ac| if (ac.out != cont2_pc) break :blk false,
                    else => break :blk false,
                }
                break :blk true;
            };
            if (!ok_cont) {
                if (pc == base_idx + 4) break;
                continue;
            }
            const exit_target = switch (items[pc + 1]) {
                .jmp => |t| t,
                else => {
                    if (pc == base_idx + 4) break;
                    continue;
                },
            };
            const is_greedy_loop = switch (items[pc + 2]) {
                .split => |sp| sp.out1 == atom_pc and sp.out2 == exit_jmp_pc,
                else => false,
            };
            if (!is_greedy_loop) {
                if (pc == base_idx + 4) break;
                continue;
            }

            var collapsed_set: ByteSet = undefined;
            const can_collapse_atom = switch (items[pc]) {
                .class => |cl| blk: {
                    if (!cl.utf8_negated) break :blk false;
                    if (cl.out != end_jmp_pc or cl.cont1 != cont1_pc or cl.cont2 != cont2_pc or cl.cont3 != cont3_pc) break :blk false;
                    collapsed_set = cl.set;
                    if (!effective_ml) collapsed_set.clear('\n');
                    break :blk true;
                },
                .any => |an| blk: {
                    if (!effective_ml) break :blk false;
                    if (an.out != end_jmp_pc or an.cont1 != cont1_pc or an.cont2 != cont2_pc or an.cont3 != cont3_pc) break :blk false;
                    collapsed_set = ByteSet{};
                    collapsed_set.invert();
                    if (!an.allow_nl) collapsed_set.clear('\n');
                    break :blk true;
                },
                else => false,
            };
            if (can_collapse_atom and requiresAsciiFollow(items, exit_target)) {
                items[pc] = .{ .class = .{ .set = collapsed_set, .out = split_pc } };
                items[pc - 4] = .{ .jmp = 0 };
                items[pc - 3] = .{ .jmp = 0 };
                items[pc - 2] = .{ .jmp = 0 };
                items[pc - 1] = .{ .jmp = 0 };
            }
            if (pc == base_idx + 4) break;
        }
    }

    fn parseAlt(self: *Compiler) Error!Frag {
        var left = try self.parseConcat();
        self.skipExtended();
        while (self.pos < self.pattern.len and self.pattern[self.pos] == '|') {
            self.has_alt = true;
            self.pos += 1;
            const right = try self.parseConcat();
            const split_pc = try self.emit(.{ .split = .{ .out1 = left.start, .out2 = right.start } });
            const join_jmp = try self.emit(.{ .jmp = 0 });
            self.patch(left.end, join_jmp);
            self.patch(right.end, join_jmp);
            left = .{ .start = split_pc, .end = join_jmp };
            self.skipExtended();
        }
        return left;
    }

    fn parseConcat(self: *Compiler) Error!Frag {
        var first: ?Frag = null;
        while (true) {
            self.skipExtended();
            if (self.pos >= self.pattern.len) break;
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
        self.skipExtended();
        const atom_start_pos = self.pos;
        var atom = try self.parseAtom();
        const atom_end_pos = self.pos;

        var had_quantifier = false;
        while (true) {
            self.skipExtended();
            if (self.pos >= self.pattern.len) break;
            const c = self.pattern[self.pos];
            switch (c) {
                '*', '+', '?' => {
                    if (had_quantifier) {
                        return self.fail(error.RegexSyntax, .dangling_quantifier, self.pos, "multiple repeat quantifiers on single atom");
                    }
                    had_quantifier = true;
                    self.pos += 1;
                    self.skipExtended();
                    var lazy = false;
                    if (self.pos < self.pattern.len and self.pattern[self.pos] == '?') {
                        lazy = true;
                        self.pos += 1;
                    }
                    if (self.ungreedy) lazy = !lazy;
                    if (lazy) self.has_lazy = true;
                    atom = try self.applyQuantifier(atom, c, lazy);
                },
                '{' => {
                    if (had_quantifier) {
                        return self.fail(error.RegexSyntax, .dangling_quantifier, self.pos, "multiple repeat quantifiers on single atom");
                    }
                    had_quantifier = true;
                    const bounds = try self.parseBraces();
                    self.skipExtended();
                    var lazy = false;
                    if (self.pos < self.pattern.len and self.pattern[self.pos] == '?') {
                        lazy = true;
                        self.pos += 1;
                    }
                    if (self.ungreedy) lazy = !lazy;
                    if (lazy) self.has_lazy = true;
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
            if (val > self.max_repeat or val > self.max_inst) {
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
                if (self.depth >= self.max_recursion_depth) {
                    return self.fail(error.RegexTooLarge, .recursion_depth_exceeded, paren_pos, "group nesting depth exceeds maximum");
                }
                self.pos += 1;
                if (self.pos < self.pattern.len and self.pattern[self.pos] == '?') {
                    self.pos += 1;
                    const is_py_named = (self.pos + 1 < self.pattern.len and self.pattern[self.pos] == 'P' and self.pattern[self.pos + 1] == '<');
                    const is_pl_named = (!is_py_named and self.pos < self.pattern.len and self.pattern[self.pos] == '<');
                    if (is_py_named or is_pl_named) {
                        self.pos += if (is_py_named) @as(usize, 2) else @as(usize, 1);
                        const name_start = self.pos;
                        const close_gt = std.mem.indexOfScalarPos(u8, self.pattern, name_start, '>') orelse {
                            return self.fail(error.RegexSyntax, .invalid_group_name, paren_pos, "unclosed named capture group name");
                        };
                        const name = self.pattern[name_start..close_gt];
                        if (name.len == 0 or !((name[0] >= 'a' and name[0] <= 'z') or (name[0] >= 'A' and name[0] <= 'Z') or name[0] == '_')) {
                            return self.fail(error.RegexSyntax, .invalid_group_name, paren_pos, "invalid capture group name");
                        }
                        for (name[1..]) |ch| {
                            if (!((ch >= 'a' and ch <= 'z') or (ch >= 'A' and ch <= 'Z') or (ch >= '0' and ch <= '9') or ch == '_')) {
                                return self.fail(error.RegexSyntax, .invalid_group_name, paren_pos, "invalid character in capture group name");
                            }
                        }
                        for (self.capture_names[0..self.capture_count], 0..) |existing, idx| {
                            if (existing.len > 0 and self.capture_positions[idx] != paren_pos and std.mem.eql(u8, existing, name)) {
                                return self.fail(error.RegexSyntax, .duplicate_group_name, paren_pos, "duplicate capture group name");
                            }
                        }
                        self.pos = close_gt + 1;
                        if (self.multiline) self.saw_scoped_m = true;
                        const group_id = self.groupForPos(paren_pos);
                        if (group_id >= 1 and group_id <= inst_mod.max_capture_groups) {
                            self.capture_names[group_id - 1] = name;
                        }
                        const saved_i = self.ignore_case;
                        const saved_m = self.multiline;
                        const saved_neg_m = self.explicit_neg_m;
                        const saved_s = self.dot_all;
                        const saved_x = self.extended;
                        const saved_u = self.ungreedy;
                        const saved_uc = self.unicode_classes;
                        self.depth += 1;
                        const inner = blk: {
                            errdefer self.depth -= 1;
                            break :blk try self.parseAlt();
                        };
                        self.depth -= 1;
                        self.ignore_case = saved_i;
                        self.multiline = saved_m;
                        self.explicit_neg_m = saved_neg_m;
                        self.dot_all = saved_s;
                        self.extended = saved_x;
                        self.ungreedy = saved_u;
                        self.unicode_classes = saved_uc;
                        if (self.pos >= self.pattern.len or self.pattern[self.pos] != ')') {
                            return self.fail(error.RegexSyntax, .unclosed_group, paren_pos, "unclosed named capture group '('");
                        }
                        self.pos += 1;
                        if (group_id >= 1 and group_id <= inst_mod.max_capture_groups) {
                            const slot_start: u8 = (group_id - 1) * 2;
                            const slot_end: u8 = slot_start + 1;
                            const save_end = try self.emit(.{ .save = .{ .slot = slot_end, .out = 0 } });
                            self.patch(inner.end, save_end);
                            const save_start = try self.emit(.{ .save = .{ .slot = slot_start, .out = inner.start } });
                            return .{ .start = save_start, .end = save_end };
                        }
                        return inner;
                    }
                    var new_i = self.ignore_case;
                    var new_m = self.multiline;
                    var new_neg_m = self.explicit_neg_m;
                    var new_s = self.dot_all;
                    var new_x = self.extended;
                    var new_u = self.ungreedy;
                    var new_uc = self.unicode_classes;
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
                                new_neg_m = neg;
                                saw_flag = true;
                                self.pos += 1;
                            },
                            's' => {
                                new_s = !neg;
                                saw_flag = true;
                                self.pos += 1;
                            },
                            'x' => {
                                new_x = !neg;
                                saw_flag = true;
                                self.pos += 1;
                            },
                            'U' => {
                                new_u = !neg;
                                saw_flag = true;
                                self.pos += 1;
                            },
                            'u' => {
                                new_uc = !neg;
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
                        self.explicit_neg_m = new_neg_m;
                        self.dot_all = new_s;
                        self.extended = new_x;
                        self.ungreedy = new_u;
                        self.unicode_classes = new_uc;
                        if (new_i) self.saw_ignore_case = true;
                        if (new_m) self.saw_scoped_m = true;
                        if (new_x) self.saw_extended = true;
                        if (new_u) self.saw_ungreedy = true;
                        const nop = try self.emit(.{ .jmp = 0 });
                        return .{ .start = nop, .end = nop };
                    }
                    if (self.pos < self.pattern.len and self.pattern[self.pos] == ':') {
                        self.pos += 1;
                        const saved_i = self.ignore_case;
                        const saved_m = self.multiline;
                        const saved_neg_m = self.explicit_neg_m;
                        const saved_s = self.dot_all;
                        const saved_x = self.extended;
                        const saved_u = self.ungreedy;
                        const saved_uc = self.unicode_classes;
                        self.ignore_case = new_i;
                        self.multiline = new_m;
                        self.explicit_neg_m = new_neg_m;
                        self.dot_all = new_s;
                        self.extended = new_x;
                        self.ungreedy = new_u;
                        self.unicode_classes = new_uc;
                        if (new_i) self.saw_ignore_case = true;
                        if (new_m) self.saw_scoped_m = true;
                        if (new_x) self.saw_extended = true;
                        if (new_u) self.saw_ungreedy = true;
                        self.depth += 1;
                        defer {
                            self.depth -= 1;
                            self.ignore_case = saved_i;
                            self.multiline = saved_m;
                            self.explicit_neg_m = saved_neg_m;
                            self.dot_all = saved_s;
                            self.extended = saved_x;
                            self.ungreedy = saved_u;
                            self.unicode_classes = saved_uc;
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
                if (self.multiline) self.saw_scoped_m = true;
                const group_id = self.groupForPos(paren_pos);
                const saved_i = self.ignore_case;
                const saved_m = self.multiline;
                const saved_neg_m = self.explicit_neg_m;
                const saved_s = self.dot_all;
                const saved_x = self.extended;
                const saved_u = self.ungreedy;
                const saved_uc = self.unicode_classes;
                self.depth += 1;
                const inner = blk: {
                    errdefer self.depth -= 1;
                    break :blk try self.parseAlt();
                };
                self.depth -= 1;
                self.ignore_case = saved_i;
                self.multiline = saved_m;
                self.explicit_neg_m = saved_neg_m;
                self.dot_all = saved_s;
                self.extended = saved_x;
                self.ungreedy = saved_u;
                self.unicode_classes = saved_uc;
                if (self.pos >= self.pattern.len or self.pattern[self.pos] != ')') {
                    return self.fail(error.RegexSyntax, .unclosed_group, paren_pos, "unclosed group parenthesis '('");
                }
                self.pos += 1;
                if (group_id >= 1 and group_id <= inst_mod.max_capture_groups) {
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
                const kind: AssertKind = if (self.explicit_neg_m) .start_input else .start_line;
                const pc = try self.emit(.{ .assert = .{ .kind = kind, .out = 0 } });
                return .{ .start = pc, .end = pc };
            },
            '$' => {
                self.pos += 1;
                const kind: AssertKind = if (self.explicit_neg_m) .end_input else .end_line;
                const pc = try self.emit(.{ .assert = .{ .kind = kind, .out = 0 } });
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
                if (self.multiline) self.saw_scoped_m = true;
                if (c == '\n') self.recordLiteralNewline(self.pos);
                if (c >= 0x80) {
                    const seq_len = utf8SeqLenAt(self.pattern, self.pos, self.pattern.len);
                    if (seq_len > 1) {
                        const raw = self.pattern[self.pos .. self.pos + seq_len];
                        const cp = std.unicode.utf8Decode(raw) catch unreachable;
                        self.pos += seq_len;
                        return self.emitCodepoint(cp, raw);
                    }
                }
                if (self.ignore_case and self.unicode_case and (c == 'k' or c == 'K' or c == 's' or c == 'S')) {
                    const raw = self.pattern[self.pos .. self.pos + 1];
                    self.pos += 1;
                    return self.emitCodepoint(c, raw);
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

    fn parseHexScalar(self: *Compiler, kind: u8, slash_pos: usize) Error!u21 {
        if (self.pos < self.pattern.len and self.pattern[self.pos] == '{') {
            self.pos += 1; // skip '{'
            const hex_start = self.pos;
            var val: u32 = 0;
            var digits: usize = 0;
            while (self.pos < self.pattern.len and self.pattern[self.pos] != '}') : (self.pos += 1) {
                const d = std.fmt.charToDigit(self.pattern[self.pos], 16) catch {
                    return self.fail(error.RegexSyntax, .invalid_escape, slash_pos, "invalid hex digit in escape sequence");
                };
                digits += 1;
                if (digits > 6) {
                    return self.fail(error.RegexSyntax, .invalid_escape, slash_pos, "hex escape exceeds 6 digits");
                }
                val = (val << 4) | d;
            }
            if (self.pos >= self.pattern.len or self.pattern[self.pos] != '}' or self.pos == hex_start) {
                return self.fail(error.RegexSyntax, .invalid_escape, slash_pos, "invalid or unclosed braced hex escape");
            }
            self.pos += 1; // skip '}'
            if (val > 0x10FFFF or (val >= 0xD800 and val <= 0xDFFF)) {
                return self.fail(error.RegexSyntax, .invalid_escape, slash_pos, "hex escape is not a valid Unicode scalar value");
            }
            return @intCast(val);
        }

        const expected: usize = if (kind == 'x') 2 else 4;
        if (self.pos + expected > self.pattern.len) {
            return self.fail(error.RegexSyntax, .invalid_escape, slash_pos, "incomplete hex escape sequence");
        }
        var val: u32 = 0;
        for (self.pattern[self.pos .. self.pos + expected]) |ch| {
            const d = std.fmt.charToDigit(ch, 16) catch {
                return self.fail(error.RegexSyntax, .invalid_escape, slash_pos, "invalid hex digit in escape sequence");
            };
            val = (val << 4) | d;
        }
        self.pos += expected;
        if (val >= 0xD800 and val <= 0xDFFF) {
            return self.fail(error.RegexSyntax, .invalid_escape, slash_pos, "hex escape is a surrogate code point");
        }
        return @intCast(val);
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
            'Z' => {
                const pc = try self.emit(.{ .assert = .{ .kind = .end_input_before_nl, .out = 0 } });
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
            'Q' => {
                if (self.multiline) self.saw_scoped_m = true;
                const lit_start = self.pos;
                var end_pos = self.pattern.len;
                if (std.mem.indexOfPos(u8, self.pattern, lit_start, "\\E")) |e_pos| {
                    end_pos = e_pos;
                    self.pos = e_pos + 2;
                } else {
                    self.pos = self.pattern.len;
                }
                const verbatim = self.pattern[lit_start..end_pos];
                if (verbatim.len == 0) {
                    const nop = try self.emit(.{ .jmp = 0 });
                    return .{ .start = nop, .end = nop };
                }
                var idx: usize = 0;
                var combined: ?Frag = null;
                while (idx < verbatim.len) {
                    const ch = verbatim[idx];
                    if (ch == '\n') self.recordLiteralNewline(lit_start + idx);
                    const seq_len: usize = if (ch >= 0x80) utf8SeqLenAt(verbatim, idx, verbatim.len) else 1;
                    const raw = verbatim[idx .. idx + seq_len];
                    const piece: Frag = if (seq_len > 1) blk: {
                        const cp = std.unicode.utf8Decode(raw) catch unreachable;
                        break :blk try self.emitCodepoint(cp, raw);
                    } else if (self.ignore_case and self.unicode_case and (ch == 'k' or ch == 'K' or ch == 's' or ch == 'S')) blk: {
                        break :blk try self.emitCodepoint(ch, raw);
                    } else blk: {
                        const pc = try self.emit(.{ .byte = .{ .b = ch, .ignore_case = self.ignore_case, .out = 0 } });
                        break :blk Frag{ .start = pc, .end = pc };
                    };
                    if (combined) |prev| {
                        self.patch(prev.end, piece.start);
                        combined = .{ .start = prev.start, .end = piece.end };
                    } else {
                        combined = piece;
                    }
                    idx += seq_len;
                }
                return combined.?;
            },
            'x', 'u' => {
                if (self.multiline) self.saw_scoped_m = true;
                const cp = try self.parseHexScalar(c, slash_pos);
                var enc: [4]u8 = undefined;
                const ulen = std.unicode.utf8Encode(cp, &enc) catch {
                    return self.fail(error.RegexSyntax, .invalid_escape, slash_pos, "invalid Unicode scalar in escape sequence");
                };
                if (cp < 0x80) {
                    const b: u8 = @intCast(cp);
                    if (self.ignore_case and self.unicode_case and (b == 'k' or b == 'K' or b == 's' or b == 'S')) {
                        return self.emitCodepoint(cp, enc[0..1]);
                    }
                    const pc = try self.emit(.{ .byte = .{ .b = b, .ignore_case = self.ignore_case, .out = 0 } });
                    return .{ .start = pc, .end = pc };
                }
                return self.emitCodepoint(cp, enc[0..ulen]);
            },
            'd', 'D', 'w', 'W', 's', 'S' => {
                const is_neg = (c == 'D' or c == 'W' or c == 'S');
                if (self.unicode_classes) {
                    return self.emitUnicodeShorthand(c, is_neg);
                }
                var set = ByteSet{};
                addShorthand(&set, c);
                if (!self.multiline) set.clear('\n');
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
                    'a' => 0x07,
                    'f' => 0x0C,
                    'v' => 0x0B,
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    '0' => 0,
                    else => c,
                };
                if (self.ignore_case and self.unicode_case and (b == 'k' or b == 'K' or b == 's' or b == 'S')) {
                    const raw = &[1]u8{b};
                    return self.emitCodepoint(b, raw);
                }
                const pc = try self.emit(.{ .byte = .{ .b = b, .ignore_case = self.ignore_case, .out = 0 } });
                return .{ .start = pc, .end = pc };
            },
        }
    }

    fn buildUnicodeWordRanges(allocator: std.mem.Allocator) error{OutOfMemory}![]const CodepointRange {
        var list = std.ArrayList(CodepointRange).empty;
        errdefer list.deinit(allocator);
        try list.appendSlice(allocator, &prop_table.gc_L);
        try list.appendSlice(allocator, &prop_table.gc_M);
        try list.appendSlice(allocator, &prop_table.gc_N);
        try list.appendSlice(allocator, &prop_table.gc_Pc);
        try list.append(allocator, .{ .start = 0x200C, .end = 0x200D });
        return sortAndMergeRanges(allocator, &list);
    }

    fn emitUnicodeShorthand(self: *Compiler, kind: u8, is_neg: bool) Error!Frag {
        const range_idx: u32 = switch (kind) {
            'd', 'D' => try self.addUnicodeRangeList(&prop_table.gc_Nd, false),
            's', 'S' => try self.addUnicodeRangeList(&prop_table.prop_Whitespace, false),
            'w', 'W' => blk: {
                const owned = try buildUnicodeWordRanges(self.allocator);
                errdefer self.allocator.free(owned);
                break :blk try self.addUnicodeRangeList(owned, true);
            },
            else => unreachable,
        };
        return self.emitUnicodeClassInst(range_idx, is_neg, .{}, false);
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
                if (self.ignore_case and self.unicode_case and has_byte_set and set.bits[2] == 0 and set.bits[3] == 0) {
                    if (set.contains('k') or set.contains('K')) {
                        try unicode_list.append(self.allocator, .{ .start = 0x212A, .end = 0x212A });
                        has_unicode_ranges = true;
                    }
                    if (set.contains('s') or set.contains('S')) {
                        try unicode_list.append(self.allocator, .{ .start = 0x017F, .end = 0x017F });
                        has_unicode_ranges = true;
                    }
                }
                if (has_unicode_ranges) {
                    const owned_ranges = try sortAndMergeRanges(self.allocator, &unicode_list);
                    errdefer self.allocator.free(owned_ranges);
                    const range_idx = try self.addUnicodeRangeList(owned_ranges, true);
                    return self.emitUnicodeClassInst(range_idx, negated, set, has_byte_set);
                }
                if (negated) {
                    set.invert();
                    if (!self.multiline) set.clear('\n');
                    const utf8_neg = (set.bits[2] == std.math.maxInt(u64) and set.bits[3] == std.math.maxInt(u64));
                    if (utf8_neg) {
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
                    if (self.ignore_case and self.unicode_case and set.bits[2] == 0 and set.bits[3] == 0) {
                        var added_fold = false;
                        if (set.contains('k') or set.contains('K')) {
                            try unicode_list.append(self.allocator, .{ .start = 0x212A, .end = 0x212A });
                            added_fold = true;
                        }
                        if (set.contains('s') or set.contains('S')) {
                            try unicode_list.append(self.allocator, .{ .start = 0x017F, .end = 0x017F });
                            added_fold = true;
                        }
                        if (added_fold) {
                            const owned_ranges = try sortAndMergeRanges(self.allocator, &unicode_list);
                            errdefer self.allocator.free(owned_ranges);
                            const range_idx = try self.addUnicodeRangeList(owned_ranges, true);
                            return self.emitUnicodeClassInst(range_idx, false, set, true);
                        }
                    }
                }
                const pc = try self.emit(.{ .class = .{ .set = set, .out = 0 } });
                return .{ .start = pc, .end = pc };
            }
            first = false;

            // Check for POSIX class [:name:] / [:^name:] inside [...]
            if (c == '[' and self.pos + 1 < self.pattern.len and self.pattern[self.pos + 1] == ':') {
                const posix_pos = self.pos;
                const close_idx = std.mem.indexOfPos(u8, self.pattern, self.pos + 2, ":]") orelse {
                    return self.fail(error.RegexSyntax, .invalid_posix_class, posix_pos, "unclosed POSIX character class '[:'");
                };
                var raw_name = self.pattern[self.pos + 2 .. close_idx];
                var pneg = false;
                if (raw_name.len > 0 and raw_name[0] == '^') {
                    pneg = true;
                    raw_name = raw_name[1..];
                }
                if (!addPosixClass(&set, raw_name, pneg, self.ignore_case)) {
                    return self.fail(error.RegexSyntax, .invalid_posix_class, posix_pos, "unknown POSIX character class");
                }
                has_byte_set = true;
                if (pneg) {
                    try unicode_list.append(self.allocator, .{ .start = 0x80, .end = 0x10FFFF });
                    has_unicode_ranges = true;
                }
                self.pos = close_idx + 2;
                if (self.pos + 1 < self.pattern.len and self.pattern[self.pos] == '-' and self.pattern[self.pos + 1] != ']') {
                    return self.fail(error.RegexSyntax, .invalid_char_range, self.pos, "POSIX class cannot be range bound");
                }
                continue;
            }

            // Check for \Q...\E inside [...]
            if (c == '\\' and self.pos + 1 < self.pattern.len and self.pattern[self.pos + 1] == 'Q') {
                const lit_start = self.pos + 2;
                var end_pos = self.pattern.len;
                if (std.mem.indexOfPos(u8, self.pattern, lit_start, "\\E")) |e_pos| {
                    end_pos = e_pos;
                    self.pos = e_pos + 2;
                } else {
                    self.pos = self.pattern.len;
                }
                const verbatim = self.pattern[lit_start..end_pos];
                var idx: usize = 0;
                while (idx < verbatim.len) {
                    const ch = verbatim[idx];
                    if (ch == '\n') self.recordLiteralNewline(lit_start + idx);
                    const seq_len: usize = if (ch >= 0x80) utf8SeqLenAt(verbatim, idx, verbatim.len) else 1;
                    if (seq_len > 1) {
                        const lo_cp = std.unicode.utf8Decode(verbatim[idx .. idx + seq_len]) catch unreachable;
                        has_unicode_ranges = true;
                        try unicode_list.append(self.allocator, .{ .start = lo_cp, .end = lo_cp });
                        if (self.ignore_case and self.unicode_case) {
                            try self.appendFoldVariants(&set, &has_byte_set, &unicode_list, lo_cp);
                        }
                    } else {
                        set.setWithCase(ch, self.ignore_case);
                        has_byte_set = true;
                    }
                    idx += seq_len;
                }
                if (self.pos + 1 < self.pattern.len and self.pattern[self.pos] == '-' and self.pattern[self.pos + 1] != ']') {
                    return self.fail(error.RegexSyntax, .invalid_char_range, self.pos, "\\Q...\\E cannot be range bound");
                }
                continue;
            }

            // Check for Unicode \d/\D/\w/\W/\s/\S inside [...] when unicode_classes is active
            if (self.unicode_classes and c == '\\' and self.pos + 1 < self.pattern.len) {
                const esc_c = self.pattern[self.pos + 1];
                if (esc_c == 'd' or esc_c == 'D' or esc_c == 'w' or esc_c == 'W' or esc_c == 's' or esc_c == 'S') {
                    const sh_pos = self.pos;
                    self.pos += 2;
                    if (self.pos + 1 < self.pattern.len and self.pattern[self.pos] == '-' and self.pattern[self.pos + 1] != ']') {
                        return self.fail(error.RegexSyntax, .invalid_char_range, sh_pos, "shorthand class cannot be range bound");
                    }
                    has_unicode_ranges = true;
                    const is_neg = (esc_c == 'D' or esc_c == 'W' or esc_c == 'S');
                    switch (esc_c) {
                        'd', 'D' => {
                            if (is_neg) {
                                try appendComplementRanges(self.allocator, &unicode_list, &prop_table.gc_Nd);
                            } else {
                                try unicode_list.appendSlice(self.allocator, &prop_table.gc_Nd);
                            }
                        },
                        's', 'S' => {
                            if (is_neg) {
                                try appendComplementRanges(self.allocator, &unicode_list, &prop_table.prop_Whitespace);
                            } else {
                                try unicode_list.appendSlice(self.allocator, &prop_table.prop_Whitespace);
                            }
                        },
                        'w', 'W' => {
                            const word_ranges = try buildUnicodeWordRanges(self.allocator);
                            defer self.allocator.free(word_ranges);
                            if (is_neg) {
                                try appendComplementRanges(self.allocator, &unicode_list, word_ranges);
                            } else {
                                try unicode_list.appendSlice(self.allocator, word_ranges);
                            }
                        },
                        else => unreachable,
                    }
                    continue;
                }
            }

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

            const item_pos = self.pos;
            const lo_atom = try self.parseClassAtom(&set);
            switch (lo_atom) {
                .shorthand => {
                    has_byte_set = true;
                    if (self.pos + 1 < self.pattern.len and self.pattern[self.pos] == '-' and self.pattern[self.pos + 1] != ']') {
                        return self.fail(error.RegexSyntax, .invalid_char_range, item_pos, "shorthand class cannot be range bound");
                    }
                },
                .cp => |lo_cp| {
                    if (self.pos + 1 < self.pattern.len and self.pattern[self.pos] == '-' and self.pattern[self.pos + 1] != ']') {
                        const dash_pos = self.pos;
                        self.pos += 1; // skip '-'
                        if (self.pos + 1 < self.pattern.len and self.pattern[self.pos] == '[' and self.pattern[self.pos + 1] == ':') {
                            return self.fail(error.RegexSyntax, .invalid_char_range, dash_pos, "POSIX class cannot be range bound");
                        }
                        if (self.pos + 1 < self.pattern.len and self.pattern[self.pos] == '\\' and self.pattern[self.pos + 1] == 'Q') {
                            return self.fail(error.RegexSyntax, .invalid_char_range, dash_pos, "\\Q...\\E cannot be range bound");
                        }
                        const hi_atom = try self.parseClassAtom(&set);
                        const hi_cp: u21 = switch (hi_atom) {
                            .shorthand => return self.fail(error.RegexSyntax, .invalid_char_range, dash_pos, "invalid shorthand in character class range"),
                            .cp => |v| v,
                        };
                        if (hi_cp < lo_cp) {
                            return self.fail(error.RegexSyntax, .invalid_char_range, dash_pos, "character range start is greater than end");
                        }
                        if (hi_cp < 0x80) {
                            set.setRange(@intCast(lo_cp), @intCast(hi_cp), self.ignore_case);
                            has_byte_set = true;
                        } else {
                            has_unicode_ranges = true;
                            if (lo_cp < 0x80) {
                                set.setRange(@intCast(lo_cp), 0x7F, self.ignore_case);
                                has_byte_set = true;
                                try unicode_list.append(self.allocator, .{ .start = 0x80, .end = hi_cp });
                            } else {
                                try unicode_list.append(self.allocator, .{ .start = lo_cp, .end = hi_cp });
                                if (self.ignore_case and self.unicode_case and (hi_cp - lo_cp <= 256)) {
                                    var cp: u21 = lo_cp;
                                    while (cp <= hi_cp) : (cp += 1) {
                                        try self.appendFoldVariants(&set, &has_byte_set, &unicode_list, cp);
                                    }
                                }
                            }
                        }
                    } else if (lo_cp < 0x80) {
                        set.setWithCase(@intCast(lo_cp), self.ignore_case);
                        has_byte_set = true;
                    } else {
                        has_unicode_ranges = true;
                        try unicode_list.append(self.allocator, .{ .start = lo_cp, .end = lo_cp });
                        if (self.ignore_case and self.unicode_case) {
                            try self.appendFoldVariants(&set, &has_byte_set, &unicode_list, lo_cp);
                        }
                    }
                },
            }
        }
        return self.fail(error.RegexSyntax, .unclosed_char_class, class_start_pos, "unclosed character class '['");
    }

    fn appendFoldVariants(
        self: *Compiler,
        set: *ByteSet,
        has_byte_set: *bool,
        unicode_list: *std.ArrayList(CodepointRange),
        cp: u21,
    ) !void {
        var eq: [4]u21 = undefined;
        const n_eq = unicode_fold.foldEquivalents(cp, &eq);
        for (eq[0..n_eq]) |alt_cp| {
            if (alt_cp < 0x80) {
                set.setWithCase(@intCast(alt_cp), true);
                has_byte_set.* = true;
            } else {
                try unicode_list.append(self.allocator, .{ .start = alt_cp, .end = alt_cp });
            }
        }
    }

    fn addPosixClass(set: *ByteSet, name: []const u8, negated: bool, ignore_case: bool) bool {
        var tmp = ByteSet{};
        if (std.mem.eql(u8, name, "alnum")) {
            tmp.setRange('0', '9', false);
            tmp.setRange('A', 'Z', false);
            tmp.setRange('a', 'z', false);
        } else if (std.mem.eql(u8, name, "alpha")) {
            tmp.setRange('A', 'Z', false);
            tmp.setRange('a', 'z', false);
        } else if (std.mem.eql(u8, name, "ascii")) {
            tmp.setRange(0x00, 0x7F, false);
        } else if (std.mem.eql(u8, name, "blank")) {
            tmp.set(' ');
            tmp.set('\t');
        } else if (std.mem.eql(u8, name, "cntrl")) {
            tmp.setRange(0x00, 0x1F, false);
            tmp.set(0x7F);
        } else if (std.mem.eql(u8, name, "digit")) {
            tmp.setRange('0', '9', false);
        } else if (std.mem.eql(u8, name, "graph")) {
            tmp.setRange(0x21, 0x7E, false);
        } else if (std.mem.eql(u8, name, "lower")) {
            tmp.setRange('a', 'z', ignore_case);
        } else if (std.mem.eql(u8, name, "print")) {
            tmp.setRange(0x20, 0x7E, false);
        } else if (std.mem.eql(u8, name, "punct")) {
            tmp.setRange('!', '/', false);
            tmp.setRange(':', '@', false);
            tmp.setRange('[', '`', false);
            tmp.setRange('{', '~', false);
        } else if (std.mem.eql(u8, name, "space")) {
            tmp.set(' ');
            tmp.set('\t');
            tmp.set('\n');
            tmp.set('\r');
            tmp.set(0x0B);
            tmp.set(0x0C);
        } else if (std.mem.eql(u8, name, "upper")) {
            tmp.setRange('A', 'Z', ignore_case);
        } else if (std.mem.eql(u8, name, "word")) {
            tmp.setRange('0', '9', false);
            tmp.setRange('A', 'Z', false);
            tmp.setRange('a', 'z', false);
            tmp.set('_');
        } else if (std.mem.eql(u8, name, "xdigit")) {
            tmp.setRange('0', '9', false);
            tmp.setRange('A', 'F', false);
            tmp.setRange('a', 'f', false);
        } else {
            return false;
        }
        if (negated) tmp.invert();
        for (0..4) |i| set.bits[i] |= tmp.bits[i];
        return true;
    }

    const ClassAtom = union(enum) {
        cp: u21,
        shorthand,
    };

    fn parseClassAtom(self: *Compiler, set: *ByteSet) Error!ClassAtom {
        if (self.pos >= self.pattern.len) {
            return self.fail(error.RegexSyntax, .unclosed_char_class, self.pos, "unclosed character class '['");
        }
        const item_pos = self.pos;
        const c = self.pattern[self.pos];
        if (c >= 0x80) {
            const seq_len = utf8SeqLenAt(self.pattern, self.pos, self.pattern.len);
            if (seq_len > 1) {
                const raw = self.pattern[self.pos .. self.pos + seq_len];
                const cp = std.unicode.utf8Decode(raw) catch {
                    return self.fail(error.RegexSyntax, .invalid_utf8, item_pos, "invalid UTF-8 in character class");
                };
                self.pos += seq_len;
                return .{ .cp = cp };
            }
        }
        self.pos += 1;
        if (c != '\\') {
            if (c == '\n') self.recordLiteralNewline(item_pos);
            return .{ .cp = c };
        }
        if (self.pos >= self.pattern.len) {
            return self.fail(error.RegexSyntax, .trailing_backslash, item_pos, "trailing backslash in character class");
        }
        const esc = self.pattern[self.pos];
        if (esc >= 0x80) {
            const seq_len = utf8SeqLenAt(self.pattern, self.pos, self.pattern.len);
            if (seq_len > 1) {
                const raw = self.pattern[self.pos .. self.pos + seq_len];
                const cp = std.unicode.utf8Decode(raw) catch {
                    return self.fail(error.RegexSyntax, .invalid_utf8, self.pos, "invalid UTF-8 in character class");
                };
                self.pos += seq_len;
                return .{ .cp = cp };
            }
        }
        self.pos += 1;
        switch (esc) {
            'd', 'D', 'w', 'W', 's', 'S' => {
                addShorthand(set, esc);
                return .shorthand;
            },
            'p', 'P' => {
                return self.fail(error.RegexSyntax, .invalid_char_range, item_pos, "cannot use Unicode property as character range bound");
            },
            'x', 'u' => {
                const cp = try self.parseHexScalar(esc, item_pos);
                return .{ .cp = cp };
            },
            'a' => return .{ .cp = 0x07 },
            'f' => return .{ .cp = 0x0C },
            'v' => return .{ .cp = 0x0B },
            'n' => return .{ .cp = '\n' },
            'r' => return .{ .cp = '\r' },
            't' => return .{ .cp = '\t' },
            '0' => return .{ .cp = 0 },
            else => return .{ .cp = esc },
        }
    }
};
