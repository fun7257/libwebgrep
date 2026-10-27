//! Linear-time regular expression engine (Thompson NFA / PikeVM + SIMD required literal prefiltering + bounded multiline window).
//!
//! Design invariants:
//! 1. Never use exponential backtracking (no backtracking stack); each NFA instruction activates at most once per input byte, guaranteeing O(N * M) worst-case time complexity.
//! 2. Enforce a hard cap on compiled instruction count (`max_inst_hard_cap`) at compile time, returning `error.RegexTooLarge` before scanning begins if exceeded.
//! 3. Automatically extract a required literal (`RequiredLiteral`) from the regex syntax tree and attach a SIMD `Finder` prefilter so regexes with literal anchors sustain 20+ GB/s throughput.
//! 4. Multiline matching (`multiline`) is strictly constrained by a bounded window (`max_multiline_window`); if the window is exhausted before closing the match, it immediately fails.

const builtin = @import("builtin");
const std = @import("std");
const matcher = @import("matcher.zig");
const Finder = @import("finder/finder.zig").Finder;
const memchr = @import("finder/memchr.zig");

pub const Match = matcher.Match;
pub const MatchMode = matcher.MatchMode;
pub const CaseMode = matcher.CaseMode;
pub const RequiredLiteral = matcher.RequiredLiteral;

/// Server hard cap on compiled NFA instruction count.
pub const max_inst_hard_cap: usize = 4096;
/// Server hard cap on bounded multiline match window (8 MiB).
pub const max_multiline_window_hard_cap: usize = 8 * 1024 * 1024;
/// Default bounded multiline match window (64 KiB).
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
    /// Allow matches to span multiple lines (including `\n`), with `^` and `$` matching line boundaries.
    multiline: bool = false,
    /// Allow `.` to match `\n` (requires `multiline = true` to cross lines).
    dot_all: bool = false,
    /// Maximum compiled instruction count. Null uses `max_inst_hard_cap`; values above the hard cap return `RegexTooLarge`.
    max_inst: ?usize = null,
    /// Maximum byte span window for multiline matching. Values exceeding the hard cap return `RegexTooLarge`.
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
    /// Match a single byte (ignoring ASCII case when `ignore_case` is true).
    byte: struct { b: u8, ignore_case: bool, out: u32 },
    /// Match any byte (excluding `\n` when `allow_nl` is false).
    any: struct { allow_nl: bool, out: u32 },
    /// Match a 256-bit byte class.
    class: struct { set: ByteSet, out: u32 },
    /// Zero-width branch: prefers `out1`, then `out2`.
    split: struct { out1: u32, out2: u32 },
    /// Unconditional jump.
    jmp: u32,
    /// Zero-width assertion anchor.
    assert: struct { kind: AssertKind, out: u32 },
    /// Accepting match state.
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
    /// Extracted required literal (points to internally allocated bytes).
    req_literal_bytes: []u8 = &.{},
    req_literal_offset: usize = 0,
    req_is_prefix: bool = false,
    req_is_exact: bool = false,
    prefilter: ?Finder = null,
    /// Trailing required literal (such as `"timeout"` in `ERROR.*timeout`), used for a fast secondary check after a prefilter hit.
    tail_literal_bytes: []u8 = &.{},
    tail_finder: ?Finder = null,
    /// Counts NFA state transition steps for unit tests asserting linear time complexity.
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
            .anchored_start = std.mem.startsWith(u8, pattern, "\\A") and !hasTopLevelAlt(pattern),
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
        const steps: ?*u64 = if (comptime builtin.is_test) &self.steps else null;
        return self.findInternal(haystack, start, mode, steps);
    }

    /// Read-only search over `haystack` that accepts `*const Regex` without copying or mutating state.
    pub fn findReadOnly(self: *const Regex, haystack: []const u8, start: usize, mode: MatchMode) ?Match {
        return self.findInternal(haystack, start, mode, null);
    }

    fn findInternal(self: *const Regex, haystack: []const u8, start: usize, mode: MatchMode, steps: ?*u64) ?Match {
        if (start > haystack.len) return null;
        if (self.anchored_start and start > 0) return null;

        // Fast path 1: the entire regex is a pure literal
        if (self.req_is_exact) {
            if (self.prefilter) |*pf| {
                return pf.findReadOnly(haystack, start, mode);
            }
        }

        // Fast path 2: has a required literal prefix (e.g., `ERROR.*timeout` or `WARN_[0-9]+`)
        if (self.req_is_prefix) {
            if (self.prefilter) |*pf| {
                var pos = start;
                var cached_win_end: usize = std.math.maxInt(usize);
                while (pos <= haystack.len) {
                    const hit = pf.findReadOnly(haystack, pos, .earliest) orelse return null;
                    const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                        cached_win_end
                    else blk: {
                        const w = self.windowLimit(haystack, hit.start);
                        cached_win_end = w;
                        break :blk w;
                    };
                    if (self.tail_finder) |*tf| {
                        // If a trailing required literal exists, verify it appears within the candidate window first
                        const tail_hit = tf.findReadOnly(haystack[0..win_end], hit.end, .earliest) orelse {
                            if (!self.multiline) {
                                // In single-line mode, if the trailing literal is absent on this line, skip past the end of the line
                                pos = @min(haystack.len + 1, win_end + 1);
                            } else {
                                pos = hit.start + 1;
                            }
                            continue;
                        };
                        _ = tail_hit;
                    }
                    if (self.runWindow(haystack, hit.start, win_end, win_end, mode, steps)) |m| {
                        return m;
                    }
                    if (!self.multiline) {
                        pos = @min(haystack.len + 1, win_end + 1);
                    } else {
                        pos = hit.start + 1;
                    }
                }
                return null;
            }
        }

        // Fast path 3: has an interior required literal (e.g., `[0-9]+ERROR`)
        if (self.prefilter) |*pf| {
            var pos = start;
            var min_start = start;
            var cached_win_end: usize = std.math.maxInt(usize);
            while (pos <= haystack.len) {
                const hit = pf.findReadOnly(haystack, pos, .earliest) orelse return null;
                const search_from = if (!self.multiline)
                    @max(min_start, lineStartAt(haystack, hit.start))
                else
                    @max(min_start, hit.start -| self.max_multiline_window);
                const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                    cached_win_end
                else blk: {
                    const w = self.windowLimit(haystack, hit.start);
                    cached_win_end = w;
                    break :blk w;
                };
                if (self.runWindow(haystack, search_from, win_end, win_end, mode, steps)) |m| {
                    return m;
                }
                if (!self.multiline) {
                    pos = @min(haystack.len + 1, win_end + 1);
                    min_start = pos;
                } else {
                    pos = hit.start + 1;
                    min_start = hit.start + 1;
                }
            }
            return null;
        }

        // General path: run linear-time PikeVM when no fixed literal is available
        return self.runUnanchored(haystack, start, haystack.len, mode, steps);
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
        const steps: ?*u64 = if (comptime builtin.is_test) &self.steps else null;
        return self.findAllowedInternal(haystack, start, mode, allow, steps);
    }

    /// Read-only variant of `findAllowed` that accepts `*const Regex` without copying or mutating state.
    pub fn findAllowedReadOnly(
        self: *const Regex,
        haystack: []const u8,
        start: usize,
        mode: MatchMode,
        comptime allow: fn ([]const u8, usize, usize) bool,
    ) ?Match {
        return self.findAllowedInternal(haystack, start, mode, allow, null);
    }

    fn findAllowedInternal(
        self: *const Regex,
        haystack: []const u8,
        start: usize,
        mode: MatchMode,
        comptime allow: fn ([]const u8, usize, usize) bool,
        steps: ?*u64,
    ) ?Match {
        var pos = start;
        while (pos <= haystack.len) {
            const hit = self.findInternal(haystack, pos, mode, steps) orelse return null;
            if (allow(haystack, hit.start, hit.end)) return hit;
            const win_end = self.windowLimit(haystack, hit.start);
            if (self.runRangeAllowed(haystack, hit.start, hit.start, win_end, mode, allow, steps)) |alt| {
                return alt;
            }
            pos = hit.start + 1;
        }
        return null;
    }

    pub fn acceptsSpan(self: *const Regex, haystack: []const u8, start: usize, end: usize) bool {
        if (end < start or end > haystack.len) return false;
        const slice = haystack[start..end];
        if (self.runRangeAllowed(slice, 0, 0, slice.len, .leftmost_first, allowExactLen, null)) |m| {
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

    /// Run Thompson NFA anchored at `anchor_pos`, scanning no further than `limit`.
    fn runAnchored(self: *const Regex, haystack: []const u8, anchor_pos: usize, limit: usize, mode: MatchMode, steps: ?*u64) ?Match {
        return self.runRange(haystack, anchor_pos, anchor_pos, limit, mode, steps);
    }

    /// Search for a match start in `[from .. max_start]`, scanning no further than `limit`.
    fn runWindow(self: *const Regex, haystack: []const u8, from: usize, max_start: usize, limit: usize, mode: MatchMode, steps: ?*u64) ?Match {
        return self.runRange(haystack, from, max_start, limit, mode, steps);
    }

    fn runUnanchored(self: *const Regex, haystack: []const u8, start: usize, limit: usize, mode: MatchMode, steps: ?*u64) ?Match {
        return self.runRange(haystack, start, limit, limit, mode, steps);
    }

    fn runRange(
        self: *const Regex,
        haystack: []const u8,
        start_lo: usize,
        start_hi: usize,
        limit: usize,
        mode: MatchMode,
        steps: ?*u64,
    ) ?Match {
        return self.runRangeAllowed(haystack, start_lo, start_hi, limit, mode, allowAnySpan, steps);
    }

    fn runRangeAllowed(
        self: *const Regex,
        haystack: []const u8,
        start_lo: usize,
        start_hi: usize,
        limit: usize,
        mode: MatchMode,
        comptime allow: fn ([]const u8, usize, usize) bool,
        steps: ?*u64,
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

            if (curr_len == 0 and best == null and pos > start_lo and pos <= start_hi and self.req_is_prefix) {
                if (self.prefilter) |*pf| {
                    const next_hit = pf.findReadOnly(haystack[0..limit], pos, .earliest) orelse break;
                    if (next_hit.start > start_hi) break;
                    pos = next_hit.start;
                }
            }

            // If no match has been found yet and the current position is still within the allowed start range, spawn a new start thread
            if (best == null and pos <= start_hi and (!self.anchored_start or pos == 0)) {
                const can_start = if (self.req_is_prefix and self.req_literal_bytes.len > 0)
                    (pos < limit and (if (self.ignore_case)
                        std.ascii.toLower(haystack[pos]) == std.ascii.toLower(self.req_literal_bytes[0])
                    else
                        haystack[pos] == self.req_literal_bytes[0]))
                else
                    true;
                if (can_start) {
                    self.addThread(curr, &curr_len, gen_table, gen, self.start_pc, pos, haystack, pos, steps);
                }
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
                // Bounded multiline window check: drop this thread immediately if its distance from start exceeds the window limit
                if (self.multiline and (pos - th.start > self.max_multiline_window)) continue;

                const inst = self.insts[th.pc];
                switch (inst) {
                    .match => {
                        if (!allow(haystack, th.start, pos)) continue;
                        if (best == null or th.start < best.?.start or (th.start == best.?.start and pos > best.?.end)) {
                            best = .{ .start = th.start, .end = pos };
                        }
                        if (mode == .earliest and next_len == 0) return best;
                        // Lower-priority alternatives are cut off by the current match
                        break;
                    },
                    .byte => |by| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        const ok = if (by.ignore_case)
                            std.ascii.toLower(b) == std.ascii.toLower(by.b)
                        else
                            b == by.b;
                        if (ok and (!self.multiline or pos + 1 - th.start <= self.max_multiline_window)) {
                            self.addThread(next, &next_len, gen_table, gen, by.out, th.start, haystack, pos + 1, steps);
                        }
                    },
                    .any => |an| {
                        if (!has_byte) continue;
                        if ((!an.allow_nl or !self.multiline) and (is_nl or (!self.multiline and b == '\r' and pos + 1 < haystack.len and haystack[pos + 1] == '\n'))) {
                            continue;
                        }
                        if (!self.multiline or pos + 1 - th.start <= self.max_multiline_window) {
                            self.addThread(next, &next_len, gen_table, gen, an.out, th.start, haystack, pos + 1, steps);
                        }
                    },
                    .class => |cl| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        if (cl.set.contains(b) and (!self.multiline or pos + 1 - th.start <= self.max_multiline_window)) {
                            self.addThread(next, &next_len, gen_table, gen, cl.out, th.start, haystack, pos + 1, steps);
                        }
                    },
                    .split, .jmp, .assert => {},
                }
            }

            if (pos >= limit) break;
            // In single-line mode, clear residual states upon hitting a newline if no match was found
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
        }

        return best;
    }

    fn addThread(
        self: *const Regex,
        list: []Thread,
        list_len: *usize,
        gen_table: []u32,
        gen: u32,
        pc: u32,
        start: usize,
        haystack: []const u8,
        pos: usize,
        steps: ?*u64,
    ) void {
        if (gen_table[pc] == gen) return;
        gen_table[pc] = gen;
        if (comptime builtin.is_test) {
            if (steps) |s| s.* += 1;
        }

        switch (self.insts[pc]) {
            .jmp => |target| {
                self.addThread(list, list_len, gen_table, gen, target, start, haystack, pos, steps);
            },
            .split => |sp| {
                self.addThread(list, list_len, gen_table, gen, sp.out1, start, haystack, pos, steps);
                self.addThread(list, list_len, gen_table, gen, sp.out2, start, haystack, pos, steps);
            },
            .assert => |as| {
                if (checkAssert(as.kind, haystack, pos)) {
                    self.addThread(list, list_len, gen_table, gen, as.out, start, haystack, pos, steps);
                }
            },
            else => {
                list[list_len.*] = .{ .pc = pc, .start = start };
                list_len.* += 1;
            },
        }
    }

    fn extractLiterals(self: *Regex, pattern: []const u8, case_mode: CaseMode) !void {
        // Analyze required literal runs on the main spine: top-level contiguous literals outside `(a|b)`, `*`, `?`, or `{0,...}`
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
                    // Quantifier applies to the preceding atom: pop the last byte from curr_lit if non-empty (since `*`/`?`/`{0,}` is optional or `{m,}` repeats)
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
                    // `a+` occurs at least once, so the last character remains part of the required prefix, though subsequent offsets are no longer fixed
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

        if (first_lit.items.len >= 2 or (first_lit.items.len == 1 and best_lit.items.len < 2)) {
            self.req_literal_bytes = try self.allocator.dupe(u8, first_lit.items);
            self.req_literal_offset = 0;
            self.req_is_prefix = true;
            self.req_is_exact = exact_only and !self.multiline;
            self.prefilter = Finder.init(self.req_literal_bytes, find_opts) catch null;

            // If another required literal of length >= 2 exists beyond the prefix literal (e.g., `ERROR.*timeout`), save it as tail_finder
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

fn allowAnySpan(haystack: []const u8, start: usize, end: usize) bool {
    _ = haystack;
    _ = start;
    _ = end;
    return true;
}

fn allowExactLen(haystack: []const u8, start: usize, end: usize) bool {
    return start == 0 and end == haystack.len;
}

fn hasTopLevelAlt(pattern: []const u8) bool {
    var depth: usize = 0;
    var in_class = false;
    var i: usize = 0;
    while (i < pattern.len) : (i += 1) {
        const c = pattern[i];
        if (c == '\\') {
            i += 1;
            continue;
        }
        if (in_class) {
            if (c == ']') in_class = false;
            continue;
        }
        switch (c) {
            '[' => in_class = true,
            '(' => depth += 1,
            ')' => if (depth > 0) {
                depth -= 1;
            },
            '|' => if (depth == 0) return true,
            else => {},
        }
    }
    return false;
}

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

test "regex compilation size exceeding hard cap is rejected" {
    try std.testing.expectError(
        error.RegexTooLarge,
        Regex.init(std.testing.allocator, "a{5000}", .{}),
    );
    try std.testing.expectError(
        error.RegexTooLarge,
        Regex.init(std.testing.allocator, "abcdefghij", .{ .max_inst = 5 }),
    );
}

test "pathological pattern steps scale linearly with input length" {
    // Traditional backtracking engines suffer O(2^n) exponential blowup on `(a+)+b` against all-'a' strings;
    // Thompson NFA visits each instruction at most once per input byte regardless of input length.
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

    // Steps for 256 bytes should be roughly 4x those for 64 bytes (allowing a small constant factor, never exponential)
    try std.testing.expect(steps_256 <= steps_64 * 5);
    try std.testing.expect(steps_256 <= 256 * re.insts.len * 2);
}

test "RequiredLiteral extraction and SIMD prefilter hit" {
    var re = try Regex.init(std.testing.allocator, "ERROR_[0-9]+:.*timeout", .{});
    defer re.deinit();

    const req = re.requiredLiteral().?;
    try std.testing.expectEqualStrings("ERROR_", req.bytes);
    try std.testing.expectEqual(@as(usize, 0), req.offset_in_match);

    const hay = "INFO ok\nWARN retry\nERROR_404: gateway timeout after 30s\n";
    const hit = re.find(hay, 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("ERROR_404: gateway timeout", hay[hit.start..hit.end]);
}

test "bounded multiline window matches within limit and fails immediately when exceeded" {
    var re = try Regex.init(std.testing.allocator, "BEGIN.*END", .{
        .multiline = true,
        .dot_all = true,
        .max_multiline_window = 32,
    });
    defer re.deinit();

    const short_hay = "header\nBEGIN\nmid\nEND\nfooter\n";
    const hit = re.find(short_hay, 0, .leftmost_first).?;
    try std.testing.expectEqualStrings("BEGIN\nmid\nEND", short_hay[hit.start..hit.end]);

    // When the span exceeds the 32-byte window, the multiline match immediately fails
    const filler: [40]u8 = @splat('x');
    const long_hay = "BEGIN\n" ++ filler ++ "\nEND\n";
    try std.testing.expect(re.find(long_hay, 0, .leftmost_first) == null);
}

test "caret start-of-line anchor matches on subsequent lines and with start > 0" {
    var re = try Regex.init(std.testing.allocator, "^ERROR", .{});
    defer re.deinit();

    const hay = "INFO ok\nERROR failed\n";
    const hit1 = re.find(hay, 0, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 8), hit1.start);
    try std.testing.expectEqual(@as(usize, 13), hit1.end);

    const hit2 = re.find(hay, 4, .leftmost_first).?;
    try std.testing.expectEqual(@as(usize, 8), hit2.start);
    try std.testing.expectEqual(@as(usize, 13), hit2.end);
}

test "acceptsSpan and findAllowed respect lower-priority alternation branches" {
    var re_whole = try Regex.init(std.testing.allocator, "a|ab", .{});
    defer re_whole.deinit();
    try std.testing.expect(re_whole.acceptsSpan("ab", 0, 2));
    try std.testing.expect(re_whole.acceptsSpan("a", 0, 1));
    try std.testing.expect(!re_whole.acceptsSpan("abc", 0, 3));

    var re_word = try Regex.init(std.testing.allocator, "foo|foobar", .{});
    defer re_word.deinit();
    const WordCheck = struct {
        fn allow(h: []const u8, s: usize, e: usize) bool {
            const left = s > 0 and isWordChar(h[s - 1]);
            const right = e < h.len and isWordChar(h[e]);
            return !left and !right;
        }
    };
    const hit = re_word.findAllowed("foobar", 0, .leftmost_first, WordCheck.allow).?;
    try std.testing.expectEqual(@as(usize, 0), hit.start);
    try std.testing.expectEqual(@as(usize, 6), hit.end);
}

