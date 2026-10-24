//! 线性时间正则表达式引擎（Thompson NFA / PikeVM + SIMD 必需字面量预过滤 + 有界跨行窗口）。
//!
//! 设计铁律：
//! 1. 绝不使用指数级回溯（无回溯栈），每个输入字节上每条 NFA 指令最多激活一次，最坏时间复杂度严格为 O(N * M)。
//! 2. 编译期强制校验指令数硬顶（`max_inst_hard_cap`），超限在扫描开始前返回 `error.RegexTooLarge`。
//! 3. 自动从正则语法树提取必需字面量（`RequiredLiteral`）并挂载 SIMD `Finder` 预过滤，带字面量锚点的正则保持 20+ GB/s 吞吐。
//! 4. 跨行匹配（`multiline`）严格受有界窗口（`max_multiline_window`）约束，窗口耗尽仍未闭合即判定失配。

const std = @import("std");
const matcher = @import("matcher.zig");
const Finder = @import("finder/finder.zig").Finder;
const memchr = @import("finder/memchr.zig");

pub const Match = matcher.Match;
pub const MatchMode = matcher.MatchMode;
pub const CaseMode = matcher.CaseMode;
pub const RequiredLiteral = matcher.RequiredLiteral;

/// 编译后 NFA 指令数服务端硬顶。
pub const max_inst_hard_cap: usize = 4096;
/// 有界跨行匹配窗口服务端硬顶（8 MiB）。
pub const max_multiline_window_hard_cap: usize = 8 * 1024 * 1024;
/// 默认有界跨行匹配窗口（64 KiB）。
pub const default_multiline_window: usize = 64 * 1024;

pub const Error = error{
    RegexSyntax,
    RegexTooLarge,
    PatternHasNewline,
    PatternCountExceeded,
    PatternBytesExceeded,
    OutOfMemory,
};

pub const RegexOptions = struct {
    case: CaseMode = .sensitive,
    /// 允许匹配跨越多行（包含 `\n`），且 `^` / `$` 匹配行首与行尾。
    multiline: bool = false,
    /// 允许 `.` 匹配 `\n`（需配合 `multiline = true` 跨行）。
    dot_all: bool = false,
    /// 编译指令数上限。null 使用 `max_inst_hard_cap`；大于硬顶时返回 `RegexTooLarge`。
    max_inst: ?usize = null,
    /// 跨行匹配的最大字节跨度窗口。超过硬顶返回 `RegexTooLarge`。
    max_multiline_window: usize = default_multiline_window,
};

pub const ByteSet = struct {
    bits: [4]u64 = .{ 0, 0, 0, 0 },

    pub fn set(self: *ByteSet, b: u8) void {
        self.bits[b >> 6] |= (@as(u64, 1) << @as(u6, @intCast(b & 63)));
    }

    pub fn setWithCase(self: *ByteSet, b: u8, ignore_case: bool) void {
        self.set(b);
        if (ignore_case) {
            if (b >= 'A' and b <= 'Z') self.set(b + 32);
            if (b >= 'a' and b <= 'z') self.set(b - 32);
        }
    }

    pub fn setRange(self: *ByteSet, lo: u8, hi: u8, ignore_case: bool) void {
        if (lo > hi) return;
        var c: u16 = lo;
        while (c <= hi) : (c += 1) {
            self.setWithCase(@intCast(c), ignore_case);
        }
    }

    pub fn invert(self: *ByteSet) void {
        for (&self.bits) |*w| w.* = ~w.*;
    }

    pub fn clear(self: *ByteSet, b: u8) void {
        self.bits[b >> 6] &= ~(@as(u64, 1) << @as(u6, @intCast(b & 63)));
    }

    pub inline fn contains(self: *const ByteSet, b: u8) bool {
        return (self.bits[b >> 6] & (@as(u64, 1) << @as(u6, @intCast(b & 63)))) != 0;
    }
};

pub const Inst = union(enum) {
    /// 匹配单个字节（`ignore_case` 时忽略 ASCII 大小写）。
    byte: struct { b: u8, ignore_case: bool, out: u32 },
    /// 匹配任意字节（`allow_nl` 为假时不匹配 `\n`）。
    any: struct { allow_nl: bool, out: u32 },
    /// 匹配 256 位字符集。
    class: struct { set: ByteSet, out: u32 },
    /// 零宽分支：优先走 `out1`，次选 `out2`。
    split: struct { out1: u32, out2: u32 },
    /// 无条件跳转。
    jmp: u32,
    /// 零宽锚点。
    assert: struct { kind: AssertKind, out: u32 },
    /// 匹配成功终点。
    match,
};

pub const AssertKind = enum {
    start_line,
    end_line,
    start_input,
    end_input,
    word_boundary,
    not_word_boundary,
};

const Thread = struct {
    pc: u32,
    start: usize,
};

pub const Regex = struct {
    allocator: std.mem.Allocator,
    insts: []Inst,
    start_pc: u32,
    ignore_case: bool,
    multiline: bool,
    dot_all: bool,
    anchored_start: bool = false,
    max_multiline_window: usize,
    /// 提取出的必需字面量（指向内部分配的字节）。
    req_literal_bytes: []u8 = &.{},
    req_literal_offset: usize = 0,
    req_is_prefix: bool = false,
    req_is_exact: bool = false,
    prefilter: ?Finder = null,
    /// 尾随必需字面量（如 `ERROR.*timeout` 中的 `"timeout"`），用于在预过滤命中后二次快速过滤。
    tail_literal_bytes: []u8 = &.{},
    tail_finder: ?Finder = null,
    /// 统计 NFA 状态转移步数，用于测试断言线性时间复杂度。
    steps: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, pattern: []const u8, options: RegexOptions) Error!Regex {
        const inst_cap = options.max_inst orelse max_inst_hard_cap;
        if (inst_cap > max_inst_hard_cap or inst_cap == 0) return error.RegexTooLarge;
        if (options.max_multiline_window > max_multiline_window_hard_cap or options.max_multiline_window == 0) {
            return error.RegexTooLarge;
        }
        try matcher.checkPatternLimits(&.{pattern}, .{});
        if (!options.multiline) {
            if (std.mem.indexOfScalar(u8, pattern, '\n') != null) return error.PatternHasNewline;
        }

        const ignore_case = switch (options.case) {
            .sensitive => false,
            .insensitive => true,
            .smart => !hasLiteralUpper(pattern),
        };

        var compiler = Compiler{
            .allocator = allocator,
            .pattern = pattern,
            .ignore_case = ignore_case,
            .multiline = options.multiline,
            .dot_all = options.dot_all,
            .max_inst = inst_cap,
        };
        defer compiler.deinit();

        const root_frag = try compiler.compile();
        if (compiler.insts.items.len > inst_cap) return error.RegexTooLarge;

        const insts = try compiler.insts.toOwnedSlice(allocator);
        errdefer allocator.free(insts);

        var self = Regex{
            .allocator = allocator,
            .insts = insts,
            .start_pc = root_frag.start,
            .ignore_case = ignore_case,
            .multiline = options.multiline,
            .dot_all = options.dot_all,
            .anchored_start = std.mem.startsWith(u8, pattern, "\\A") or (!options.multiline and std.mem.startsWith(u8, pattern, "^") and std.mem.indexOfScalar(u8, pattern, '|') == null),
            .max_multiline_window = options.max_multiline_window,
        };
        errdefer self.deinit();

        try self.extractLiterals(pattern, options.case);
        return self;
    }

    pub fn deinit(self: *Regex) void {
        if (self.req_literal_bytes.len != 0) self.allocator.free(self.req_literal_bytes);
        if (self.tail_literal_bytes.len != 0) self.allocator.free(self.tail_literal_bytes);
        self.allocator.free(self.insts);
        self.* = undefined;
    }

    pub fn resetStats(self: *Regex) void {
        self.steps = 0;
        if (self.prefilter) |*pf| pf.resetStats();
        if (self.tail_finder) |*tf| tf.resetStats();
    }

    pub fn requiredLiteral(self: *const Regex) ?RequiredLiteral {
        if (self.req_literal_bytes.len == 0) return null;
        return .{
            .bytes = self.req_literal_bytes,
            .offset_in_match = self.req_literal_offset,
        };
    }

    pub fn isMultiline(self: *const Regex) bool {
        return self.multiline;
    }

    pub fn isStartAnchored(self: *const Regex) bool {
        return self.anchored_start;
    }

    pub fn multilineWindow(self: *const Regex) usize {
        return self.max_multiline_window;
    }

    pub fn find(self: *Regex, haystack: []const u8, start: usize, mode: MatchMode) ?Match {
        if (start > haystack.len) return null;
        if (self.anchored_start and start > 0) return null;

        // 快路径 1：整条正则就是纯字面量
        if (self.req_is_exact) {
            if (self.prefilter) |*pf| {
                return pf.find(haystack, start, mode);
            }
        }

        // 快路径 2：带前缀必需字面量（如 `ERROR.*timeout` 或 `WARN_[0-9]+`）
        if (self.req_is_prefix) {
            if (self.prefilter) |*pf| {
                var pos = start;
                while (pos <= haystack.len) {
                    const hit = pf.find(haystack, pos, .earliest) orelse return null;
                    const win_end = self.windowLimit(haystack, hit.start);
                    if (self.tail_finder) |*tf| {
                        // 若还有尾随必需字面量，先检查候选窗口内是否存在该尾随字面量
                        const tail_hit = tf.find(haystack[0..win_end], hit.end, .earliest) orelse {
                            if (!self.multiline) {
                                // 单行模式下尾随字面量在当前行都不存在，直接跳到行尾后继续
                                pos = @min(haystack.len + 1, win_end + 1);
                            } else {
                                pos = hit.start + 1;
                            }
                            continue;
                        };
                        _ = tail_hit;
                    }
                    if (self.runAnchored(haystack, hit.start, win_end, mode)) |m| {
                        return m;
                    }
                    pos = hit.start + 1;
                }
                return null;
            }
        }

        // 快路径 3：带内部必需字面量（如 `[0-9]+ERROR`）
        if (self.prefilter) |*pf| {
            var pos = start;
            while (pos <= haystack.len) {
                const hit = pf.find(haystack, pos, .earliest) orelse return null;
                const search_from = if (!self.multiline)
                    @max(start, lineStartAt(haystack, hit.start))
                else
                    @max(start, hit.start -| self.max_multiline_window);
                const win_end = self.windowLimit(haystack, hit.start);
                if (self.runWindow(haystack, search_from, hit.start, win_end, mode)) |m| {
                    return m;
                }
                pos = hit.start + 1;
            }
            return null;
        }

        // 通用路径：无固定字面量时运行线性时间 PikeVM
        return self.runUnanchored(haystack, start, haystack.len, mode);
    }

    pub fn findWatched(self: *Regex, haystack: []const u8, start: usize, nul: *?usize) ?Match {
        const hit = self.find(haystack, start, .earliest);
        const limit = if (hit) |m| m.start else haystack.len;
        if (start < limit) {
            if (memchr.find(memchr.native_width, haystack, start, 0)) |at| {
                if (at < limit) {
                    nul.* = at;
                    return null;
                }
            }
        }
        return hit;
    }

    pub fn findAllowed(
        self: *Regex,
        haystack: []const u8,
        start: usize,
        mode: MatchMode,
        comptime allow: fn ([]const u8, usize, usize) bool,
    ) ?Match {
        var pos = start;
        while (pos <= haystack.len) {
            const hit = self.find(haystack, pos, mode) orelse return null;
            if (allow(haystack, hit.start, hit.end)) return hit;
            pos = hit.start + 1;
        }
        return null;
    }

    pub fn acceptsSpan(self: *Regex, haystack: []const u8, start: usize, end: usize) bool {
        if (end < start or end > haystack.len) return false;
        const slice = haystack[start..end];
        if (self.runAnchored(slice, 0, slice.len, .leftmost_first)) |m| {
            return m.start == 0 and m.end == slice.len;
        }
        return false;
    }

    fn windowLimit(self: *const Regex, haystack: []const u8, from: usize) usize {
        if (!self.multiline) {
            if (memchr.find(memchr.native_width, haystack, from, '\n')) |nl| {
                if (nl > from and haystack[nl - 1] == '\r') return nl - 1;
                return nl;
            }
            return haystack.len;
        }
        return @min(haystack.len, from +| self.max_multiline_window);
    }

    /// 锚定在 `anchor_pos` 起点运行 Thompson NFA，扫描范围不超过 `limit`。
    fn runAnchored(self: *Regex, haystack: []const u8, anchor_pos: usize, limit: usize, mode: MatchMode) ?Match {
        return self.runRange(haystack, anchor_pos, anchor_pos, limit, mode);
    }

    /// 在 `[from .. max_start]` 范围内寻找起点，扫描终点不超过 `limit`。
    fn runWindow(self: *Regex, haystack: []const u8, from: usize, max_start: usize, limit: usize, mode: MatchMode) ?Match {
        return self.runRange(haystack, from, max_start, limit, mode);
    }

    fn runUnanchored(self: *Regex, haystack: []const u8, start: usize, limit: usize, mode: MatchMode) ?Match {
        return self.runRange(haystack, start, limit, limit, mode);
    }

    fn runRange(
        self: *Regex,
        haystack: []const u8,
        start_lo: usize,
        start_hi: usize,
        limit: usize,
        mode: MatchMode,
    ) ?Match {
        const n_inst = self.insts.len;
        if (n_inst == 0 or start_lo > limit) return null;

        var stack_curr: [256]Thread = undefined;
        var stack_next: [256]Thread = undefined;
        var stack_gen: [256]u32 = undefined;

        var heap_curr: []Thread = &.{};
        defer if (heap_curr.len != 0) self.allocator.free(heap_curr);
        var heap_next: []Thread = &.{};
        defer if (heap_next.len != 0) self.allocator.free(heap_next);
        var heap_gen: []u32 = &.{};
        defer if (heap_gen.len != 0) self.allocator.free(heap_gen);

        var curr: []Thread = if (n_inst <= 256) stack_curr[0..n_inst] else blk: {
            heap_curr = self.allocator.alloc(Thread, n_inst) catch return null;
            break :blk heap_curr;
        };
        var next: []Thread = if (n_inst <= 256) stack_next[0..n_inst] else blk: {
            heap_next = self.allocator.alloc(Thread, n_inst) catch return null;
            break :blk heap_next;
        };
        const gen_table: []u32 = if (n_inst <= 256) stack_gen[0..n_inst] else blk: {
            heap_gen = self.allocator.alloc(u32, n_inst) catch return null;
            break :blk heap_gen;
        };
        @memset(gen_table, 0);
        var gen: u32 = 1;

        var curr_len: usize = 0;
        var best: ?Match = null;

        var pos = start_lo;
        while (true) {
            if (gen == std.math.maxInt(u32)) {
                @memset(gen_table, 0);
                gen = 1;
            }

            // 若还没有找到匹配，且当前位置仍在允许的新起点范围内，注入新起点线程
            if (best == null and pos <= start_hi and (!self.anchored_start or pos == 0)) {
                self.addThread(curr, &curr_len, gen_table, gen, self.start_pc, pos, haystack, pos);
            }

            if (curr_len == 0) {
                if (best != null or pos >= start_hi or pos >= limit or (self.anchored_start and pos > 0)) break;
                pos += 1;
                continue;
            }

            var next_len: usize = 0;
            gen +%= 1;
            if (gen == 0) {
                @memset(gen_table, 0);
                gen = 1;
            }

            const has_byte = pos < limit;
            const b: u8 = if (has_byte) haystack[pos] else 0;
            const is_nl = has_byte and b == '\n';

            for (curr[0..curr_len]) |th| {
                // 有界跨行窗口检查：若该线程距离其起点已超出窗口上限，立即丢弃
                if (pos - th.start > self.max_multiline_window) continue;

                const inst = self.insts[th.pc];
                switch (inst) {
                    .match => {
                        if (best == null or th.start < best.?.start or (th.start == best.?.start and pos > best.?.end)) {
                            best = .{ .start = th.start, .end = pos };
                        }
                        if (mode == .earliest and next_len == 0) return best;
                        // 同一优先级的后续备选被当前 match 截断
                        break;
                    },
                    .byte => |by| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        const ok = if (by.ignore_case)
                            std.ascii.toLower(b) == std.ascii.toLower(by.b)
                        else
                            b == by.b;
                        if (ok and (pos + 1 - th.start <= self.max_multiline_window)) {
                            self.addThread(next, &next_len, gen_table, gen, by.out, th.start, haystack, pos + 1);
                        }
                    },
                    .any => |an| {
                        if (!has_byte) continue;
                        if ((!an.allow_nl or !self.multiline) and (is_nl or (!self.multiline and b == '\r' and pos + 1 < haystack.len and haystack[pos + 1] == '\n'))) {
                            continue;
                        }
                        if (pos + 1 - th.start <= self.max_multiline_window) {
                            self.addThread(next, &next_len, gen_table, gen, an.out, th.start, haystack, pos + 1);
                        }
                    },
                    .class => |cl| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        if (cl.set.contains(b) and (pos + 1 - th.start <= self.max_multiline_window)) {
                            self.addThread(next, &next_len, gen_table, gen, cl.out, th.start, haystack, pos + 1);
                        }
                    },
                    .split, .jmp, .assert => {},
                }
            }

            if (pos >= limit) break;
            // 单行模式下遇到换行符且当前没有找到匹配，清空跨行残留状态
            if (!self.multiline and is_nl) {
                if (best != null) break;
                curr_len = 0;
            } else {
                const tmp = curr;
                curr = next;
                next = tmp;
                curr_len = next_len;
            }
            pos += 1;
            gen +%= 1;
        }

        return best;
    }

    fn addThread(
        self: *Regex,
        list: []Thread,
        list_len: *usize,
        gen_table: []u32,
        gen: u32,
        pc: u32,
        start: usize,
        haystack: []const u8,
        pos: usize,
    ) void {
        if (gen_table[pc] == gen) return;
        gen_table[pc] = gen;
        self.steps += 1;

        switch (self.insts[pc]) {
            .jmp => |target| {
                self.addThread(list, list_len, gen_table, gen, target, start, haystack, pos);
            },
            .split => |sp| {
                self.addThread(list, list_len, gen_table, gen, sp.out1, start, haystack, pos);
                self.addThread(list, list_len, gen_table, gen, sp.out2, start, haystack, pos);
            },
            .assert => |as| {
                if (checkAssert(as.kind, haystack, pos)) {
                    self.addThread(list, list_len, gen_table, gen, as.out, start, haystack, pos);
                }
            },
            else => {
                list[list_len.*] = .{ .pc = pc, .start = start };
                list_len.* += 1;
            },
        }
    }

    fn extractLiterals(self: *Regex, pattern: []const u8, case_mode: CaseMode) !void {
        // 分析主干上的必需字面量片段：不在分支 `(a|b)`、`*`、`?`、`{0,...}` 内的顶层连续字面量
        var first_lit = std.ArrayList(u8).empty;
        defer first_lit.deinit(self.allocator);
        var best_lit = std.ArrayList(u8).empty;
        defer best_lit.deinit(self.allocator);
        var curr_lit = std.ArrayList(u8).empty;
        defer curr_lit.deinit(self.allocator);

        var depth: usize = 0;
        var has_top_alt = false;
        var prefix_active = true;
        var exact_only = true;
        var curr_offset: usize = 0;
        var best_offset: usize = 0;
        var fixed_offset: ?usize = 0;

        var i: usize = 0;
        while (i < pattern.len) {
            const c = pattern[i];
            switch (c) {
                '(' => {
                    if (curr_lit.items.len > best_lit.items.len) {
                        best_lit.clearRetainingCapacity();
                        try best_lit.appendSlice(self.allocator, curr_lit.items);
                        best_offset = curr_offset;
                    }
                    curr_lit.clearRetainingCapacity();
                    depth += 1;
                    prefix_active = false;
                    exact_only = false;
                    fixed_offset = null;
                    i += 1;
                },
                ')' => {
                    if (depth > 0) depth -= 1;
                    i += 1;
                },
                '|' => {
                    if (depth == 0) has_top_alt = true;
                    prefix_active = false;
                    exact_only = false;
                    fixed_offset = null;
                    curr_lit.clearRetainingCapacity();
                    i += 1;
                },
                '*', '?', '{' => {
                    // 量词作用于前一个原子：若 curr_lit 非空，需要回退最后一个字节（因為 `*`/`?`/`{0,}` 可选，或 `+`/`{m,}` 重复）
                    if (curr_lit.items.len > 0) {
                        _ = curr_lit.pop();
                        if (prefix_active and first_lit.items.len > 0) {
                            _ = first_lit.pop();
                        }
                    }
                    if (curr_lit.items.len > best_lit.items.len) {
                        best_lit.clearRetainingCapacity();
                        try best_lit.appendSlice(self.allocator, curr_lit.items);
                        best_offset = curr_offset;
                    }
                    curr_lit.clearRetainingCapacity();
                    prefix_active = false;
                    exact_only = false;
                    fixed_offset = null;
                    if (c == '{') {
                        while (i < pattern.len and pattern[i] != '}') i += 1;
                    }
                    if (i < pattern.len) i += 1;
                },
                '+' => {
                    // `a+` 至少出现一次，最后一个字符仍然属于必需前缀！但后续偏移不再固定
                    if (curr_lit.items.len > best_lit.items.len) {
                        best_lit.clearRetainingCapacity();
                        try best_lit.appendSlice(self.allocator, curr_lit.items);
                        best_offset = curr_offset;
                    }
                    curr_lit.clearRetainingCapacity();
                    prefix_active = false;
                    exact_only = false;
                    fixed_offset = null;
                    i += 1;
                },
                '.', '^', '$' => {
                    if (curr_lit.items.len > best_lit.items.len) {
                        best_lit.clearRetainingCapacity();
                        try best_lit.appendSlice(self.allocator, curr_lit.items);
                        best_offset = curr_offset;
                    }
                    curr_lit.clearRetainingCapacity();
                    prefix_active = false;
                    exact_only = false;
                    if (c == '.' and fixed_offset != null) {
                        fixed_offset.? += 1;
                    } else {
                        fixed_offset = null;
                    }
                    i += 1;
                },
                '[' => {
                    if (curr_lit.items.len > best_lit.items.len) {
                        best_lit.clearRetainingCapacity();
                        try best_lit.appendSlice(self.allocator, curr_lit.items);
                        best_offset = curr_offset;
                    }
                    curr_lit.clearRetainingCapacity();
                    prefix_active = false;
                    exact_only = false;
                    if (fixed_offset != null) fixed_offset.? += 1;
                    i += 1;
                    if (i < pattern.len and (pattern[i] == '^' or pattern[i] == '!')) i += 1;
                    if (i < pattern.len and pattern[i] == ']') i += 1;
                    while (i < pattern.len and pattern[i] != ']') {
                        if (pattern[i] == '\\' and i + 1 < pattern.len) i += 2 else i += 1;
                    }
                    if (i < pattern.len) i += 1;
                },
                '\\' => {
                    if (i + 1 >= pattern.len) break;
                    const next_c = pattern[i + 1];
                    const decoded: ?u8 = switch (next_c) {
                        'n' => if (self.multiline) null else '\n',
                        'r' => '\r',
                        't' => '\t',
                        'A', 'z', 'd', 'D', 'w', 'W', 's', 'S', 'b', 'B', '0' => null,
                        else => next_c,
                    };
                    if (decoded) |lit_b| {
                        if (depth == 0) {
                            if (curr_lit.items.len == 0) curr_offset = fixed_offset orelse 0;
                            try curr_lit.append(self.allocator, lit_b);
                            if (prefix_active) try first_lit.append(self.allocator, lit_b);
                            if (fixed_offset != null) fixed_offset.? += 1;
                        }
                    } else {
                        if (curr_lit.items.len > best_lit.items.len) {
                            best_lit.clearRetainingCapacity();
                            try best_lit.appendSlice(self.allocator, curr_lit.items);
                            best_offset = curr_offset;
                        }
                        curr_lit.clearRetainingCapacity();
                        prefix_active = false;
                        exact_only = false;
                        fixed_offset = null;
                    }
                    i += 2;
                },
                else => {
                    if (depth == 0 and c != '\n') {
                        if (curr_lit.items.len == 0) curr_offset = fixed_offset orelse 0;
                        try curr_lit.append(self.allocator, c);
                        if (prefix_active) try first_lit.append(self.allocator, c);
                        if (fixed_offset != null) fixed_offset.? += 1;
                    } else {
                        prefix_active = false;
                        exact_only = false;
                        fixed_offset = null;
                    }
                    i += 1;
                },
            }
        }
        if (curr_lit.items.len > best_lit.items.len) {
            best_lit.clearRetainingCapacity();
            try best_lit.appendSlice(self.allocator, curr_lit.items);
            best_offset = curr_offset;
        }

        if (has_top_alt) return;

        const find_opts = matcher.FindOptions{
            .case = if (self.ignore_case) .insensitive else case_mode,
        };

        if (first_lit.items.len >= 2 or (first_lit.items.len >= 1 and exact_only)) {
            self.req_literal_bytes = try self.allocator.dupe(u8, first_lit.items);
            self.req_literal_offset = 0;
            self.req_is_prefix = true;
            self.req_is_exact = exact_only and !self.multiline;
            self.prefilter = Finder.init(self.req_literal_bytes, find_opts) catch null;

            // 若除前缀字面量外，末尾或中间还有另一段长必需字面量（如 `ERROR.*timeout`），保存为 tail_finder
            if (!exact_only and curr_lit.items.len >= 2 and !std.mem.eql(u8, curr_lit.items, first_lit.items)) {
                self.tail_literal_bytes = try self.allocator.dupe(u8, curr_lit.items);
                self.tail_finder = Finder.init(self.tail_literal_bytes, find_opts) catch null;
            }
        } else if (best_lit.items.len >= 2) {
            self.req_literal_bytes = try self.allocator.dupe(u8, best_lit.items);
            self.req_literal_offset = best_offset;
            self.req_is_prefix = false;
            self.req_is_exact = false;
            self.prefilter = Finder.init(self.req_literal_bytes, find_opts) catch null;
        }
    }
};

fn lineStartAt(haystack: []const u8, pos: usize) usize {
    if (pos == 0) return 0;
    if (memchr.findLast(memchr.native_width, haystack, 0, pos, '\n')) |nl| return nl + 1;
    return 0;
}

fn isWordChar(b: u8) bool {
    return switch (b) {
        '0'...'9', 'A'...'Z', 'a'...'z', '_' => true,
        else => false,
    };
}

fn checkAssert(kind: AssertKind, haystack: []const u8, pos: usize) bool {
    return switch (kind) {
        .start_line => pos == 0 or (pos <= haystack.len and haystack[pos - 1] == '\n'),
        .end_line => pos == haystack.len or haystack[pos] == '\n' or (pos + 1 < haystack.len and haystack[pos] == '\r' and haystack[pos + 1] == '\n'),
        .start_input => pos == 0,
        .end_input => pos == haystack.len,
        .word_boundary => blk: {
            const left = pos > 0 and isWordChar(haystack[pos - 1]);
            const right = pos < haystack.len and isWordChar(haystack[pos]);
            break :blk left != right;
        },
        .not_word_boundary => blk: {
            const left = pos > 0 and isWordChar(haystack[pos - 1]);
            const right = pos < haystack.len and isWordChar(haystack[pos]);
            break :blk left == right;
        },
    };
}

fn hasLiteralUpper(pattern: []const u8) bool {
    var i: usize = 0;
    while (i < pattern.len) : (i += 1) {
        if (pattern[i] == '\\') {
            i += 1;
            continue;
        }
        if (pattern[i] >= 'A' and pattern[i] <= 'Z') return true;
    }
    return false;
}

const Frag = struct {
    start: u32,
    end: u32,
};

const Compiler = struct {
    allocator: std.mem.Allocator,
    pattern: []const u8,
    pos: usize = 0,
    ignore_case: bool,
    multiline: bool,
    dot_all: bool,
    max_inst: usize,
    insts: std.ArrayList(Inst) = .empty,

    fn deinit(self: *Compiler) void {
        self.insts.deinit(self.allocator);
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

    fn compile(self: *Compiler) Error!Frag {
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

        while (self.pos < self.pattern.len) {
            const c = self.pattern[self.pos];
            switch (c) {
                '*', '+', '?' => {
                    self.pos += 1;
                    var lazy = false;
                    if (self.pos < self.pattern.len and self.pattern[self.pos] == '?') {
                        lazy = true;
                        self.pos += 1;
                    }
                    atom = try self.applyQuantifier(atom, c, lazy);
                },
                '{' => {
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
            // first_atom 被当作可选分支或丢弃，重新从 0 构建
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
                self.pos += 1;
                if (self.pos + 1 < self.pattern.len and self.pattern[self.pos] == '?' and self.pattern[self.pos + 1] == ':') {
                    self.pos += 2;
                }
                const inner = try self.parseAlt();
                if (self.pos >= self.pattern.len or self.pattern[self.pos] != ')') return error.RegexSyntax;
                self.pos += 1;
                return inner;
            },
            '.' => {
                self.pos += 1;
                const end_jmp = try self.emit(.{ .jmp = 0 });
                const pc = try self.emit(.{ .any = .{ .allow_nl = self.dot_all and self.multiline, .out = end_jmp } });
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
                const end_jmp = try self.emit(.{ .jmp = 0 });
                const pc = try self.emit(.{ .class = .{ .set = set, .out = end_jmp } });
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
        if (self.pattern[self.pos] == '^') {
            negated = true;
            self.pos += 1;
        }
        var set = ByteSet{};
        var first = true;
        while (self.pos < self.pattern.len) {
            const c = self.pattern[self.pos];
            if (c == ']' and !first) {
                self.pos += 1;
                if (negated) {
                    set.invert();
                    if (!self.multiline) set.clear('\n');
                }
                const end_jmp = try self.emit(.{ .jmp = 0 });
                const pc = try self.emit(.{ .class = .{ .set = set, .out = end_jmp } });
                return .{ .start = pc, .end = end_jmp };
            }
            first = false;
            const lo = try self.parseClassChar(&set);
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

fn addShorthand(set: *ByteSet, kind: u8) void {
    var tmp = ByteSet{};
    switch (kind) {
        'd', 'D' => tmp.setRange('0', '9', false),
        'w', 'W' => {
            tmp.setRange('0', '9', false);
            tmp.setRange('A', 'Z', false);
            tmp.setRange('a', 'z', false);
            tmp.set('_');
        },
        's', 'S' => {
            tmp.set(' ');
            tmp.set('\t');
            tmp.set('\n');
            tmp.set('\r');
            tmp.set(0x0B);
            tmp.set(0x0C);
        },
        else => unreachable,
    }
    if (kind == 'D' or kind == 'W' or kind == 'S') tmp.invert();
    for (0..4) |i| set.bits[i] |= tmp.bits[i];
}

test "B16 正则编译大小超过硬顶时拒绝" {
    try std.testing.expectError(
        error.RegexTooLarge,
        Regex.init(std.testing.allocator, "a{5000}", .{}),
    );
    try std.testing.expectError(
        error.RegexTooLarge,
        Regex.init(std.testing.allocator, "abcdefghij", .{ .max_inst = 5 }),
    );
}

test "B16 病态模式步数随输入长度线性增长" {
    // 传统回溯引擎在 `(a+)+b` 面对全 `a` 串时会发生 O(2^n) 指数爆炸，
    // Thompson NFA 在任意长度输入下每个字节每条指令最多访问一次。
    var re = try Regex.init(std.testing.allocator, "(a+)+b", .{});
    defer re.deinit();

    const small_input: [64]u8 = @splat('a');
    re.resetStats();
    try std.testing.expect(re.find(&small_input, 0, .earliest) == null);
    const steps_64 = re.steps;

    const large_input: [256]u8 = @splat('a');
    re.resetStats();
    try std.testing.expect(re.find(&large_input, 0, .earliest) == null);
    const steps_256 = re.steps;

    // 256 字节的步数应当约为 64 字节的 4 倍（允许常数误差，绝不可能指数增长）
    try std.testing.expect(steps_256 <= steps_64 * 5);
    try std.testing.expect(steps_256 <= 256 * re.insts.len * 2);
}

test "B16 RequiredLiteral 提取与 SIMD 预过滤命中" {
    var re = try Regex.init(std.testing.allocator, "ERROR_[0-9]+:.*timeout", .{});
    defer re.deinit();

    const req = re.requiredLiteral().?;
    try std.testing.expectEqualStrings("ERROR_", req.bytes);
    try std.testing.expectEqual(@as(usize, 0), req.offset_in_match);

    const hay = "INFO ok\nWARN retry\nERROR_404: gateway timeout after 30s\n";
    const hit = re.find(hay, 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("ERROR_404: gateway timeout", hay[hit.start..hit.end]);
}

test "B17 有界跨行窗口内命中且超窗立即失配" {
    var re = try Regex.init(std.testing.allocator, "BEGIN.*END", .{
        .multiline = true,
        .dot_all = true,
        .max_multiline_window = 32,
    });
    defer re.deinit();

    const short_hay = "header\nBEGIN\nmid\nEND\nfooter\n";
    const hit = re.find(short_hay, 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("BEGIN\nmid\nEND", short_hay[hit.start..hit.end]);

    // 跨度超过 32 字节窗口时，立即判定该跨行匹配不成立
    const filler: [40]u8 = @splat('x');
    const long_hay = "BEGIN\n" ++ filler ++ "\nEND\n";
    try std.testing.expect(re.find(long_hay, 0, .leftmost_first) == null);
}
