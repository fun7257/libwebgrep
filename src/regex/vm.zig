//! [Module] regex/vm.zig
//! [Layer] Layer 2 — Hybrid Lazy DFA & Thompson NFA / PikeVM Execution Engine
//! [Role] Executes compiled regex bytecode (`[]Inst`) in guaranteed O(N * M) time with SIMD literal prefiltering,
//!        bounded Lazy DFA (`StackDfa` / `HeapDfa`), thread-safe `*const Regex` search, reusable `RegexScratch`,
//!        bounded multiline windows, Unicode property classes (`\p{...}`), and submatch capture extraction (`Captures`).
//! [Invariants]
//!   1. All search methods (`find`, `isMatch`, `findCaptures`, `acceptsSpan`, `findAllowed`) take `*const Regex`
//!      and are 100% thread-safe and lock-free across concurrent worker threads.
//!   2. Lockstep Thompson NFA activates each instruction PC at most once per byte position (sparse-set deduplication).
//!   3. Multiline matches never scan or match beyond `max_multiline_window` bytes from the candidate start offset.
//! [HotPath] `findInternal` -> `prefilter` / `alt_prefilter` / `runWithDfa` -> `runRangeAllowed`.

const builtin = @import("builtin");
const std = @import("std");
const matcher = @import("../matcher.zig");
const Finder = @import("../finder/finder.zig").Finder;
const Multi = @import("../finder/multi.zig").Multi;
const memchr = @import("../finder/memchr.zig");
const unicode_fold = @import("../finder/unicode_fold.zig");
const inst_mod = @import("inst.zig");
const compiler_mod = @import("compiler.zig");
const prefilter_mod = @import("prefilter.zig");
const dfa_mod = @import("dfa.zig");

pub const Match = inst_mod.Match;
pub const MatchMode = inst_mod.MatchMode;
pub const CaseMode = inst_mod.CaseMode;
pub const RequiredLiteral = inst_mod.RequiredLiteral;
pub const Captures = inst_mod.Captures;
pub const max_inst_hard_cap = inst_mod.max_inst_hard_cap;
pub const max_multiline_window_hard_cap = inst_mod.max_multiline_window_hard_cap;
pub const default_multiline_window = inst_mod.default_multiline_window;
pub const Error = inst_mod.Error;
pub const DiagnosticCode = inst_mod.DiagnosticCode;
pub const CompileDiagnostic = inst_mod.CompileDiagnostic;
pub const RegexOptions = inst_mod.RegexOptions;
pub const ByteSet = inst_mod.ByteSet;
pub const Inst = inst_mod.Inst;
pub const AssertKind = inst_mod.AssertKind;
pub const UnicodeRangeList = inst_mod.UnicodeRangeList;
pub const StackDfa = dfa_mod.StackDfa;
pub const HeapDfa = dfa_mod.HeapDfa;

const Thread = inst_mod.Thread;
const Compiler = compiler_mod.Compiler;
const hasLiteralUpper = inst_mod.hasLiteralUpper;
const hasTopLevelAlt = inst_mod.hasTopLevelAlt;
const lineStartAt = inst_mod.lineStartAt;
const allowAnySpan = inst_mod.allowAnySpan;
const allowExactLen = inst_mod.allowExactLen;
const checkAssert = inst_mod.checkAssert;
const utf8SeqLenAt = inst_mod.utf8SeqLenAt;
const decodeValidUtf8At = inst_mod.decodeValidUtf8At;
const inRanges = inst_mod.inRanges;
const populateDiagnostic = inst_mod.populateDiagnostic;

/// Per-thread reusable scratch buffers for `Regex.findWithScratch`, `isMatchWithScratch`, and `findCapturesWithScratch`.
/// Eliminates per-search heap allocations for large NFAs (`insts.len > 256`) and caches the 256-state `HeapDfa` across searches.
pub const RegexScratch = struct {
    allocator: std.mem.Allocator,
    curr: []Thread = &.{},
    next: []Thread = &.{},
    gen_table: []u32 = &.{},
    dfa: ?*HeapDfa = null,
    dfa_scratch: ?*HeapDfa = null,

    pub fn init(allocator: std.mem.Allocator) RegexScratch {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *RegexScratch) void {
        if (self.curr.len != 0) self.allocator.free(self.curr);
        if (self.next.len != 0) self.allocator.free(self.next);
        if (self.gen_table.len != 0) self.allocator.free(self.gen_table);
        if (self.dfa) |d| self.allocator.destroy(d);
        self.* = undefined;
    }

    pub fn reset(self: *RegexScratch) void {
        if (self.dfa) |d| d.reset();
    }

    pub fn ensureCapacity(self: *RegexScratch, n_inst: usize) !void {
        if (self.curr.len < n_inst) {
            const new_curr = try self.allocator.alloc(Thread, n_inst);
            if (self.curr.len != 0) self.allocator.free(self.curr);
            self.curr = new_curr;
        }
        if (self.next.len < n_inst) {
            const new_next = try self.allocator.alloc(Thread, n_inst);
            if (self.next.len != 0) self.allocator.free(self.next);
            self.next = new_next;
        }
        if (self.gen_table.len < n_inst) {
            const new_gen = try self.allocator.alloc(u32, n_inst);
            if (self.gen_table.len != 0) self.allocator.free(self.gen_table);
            self.gen_table = new_gen;
        }
    }

    pub fn ensureDfa(self: *RegexScratch) !*HeapDfa {
        if (self.dfa) |d| return d;
        const d = try self.allocator.create(HeapDfa);
        d.* = HeapDfa.init();
        self.dfa = d;
        self.dfa_scratch = d;
        return d;
    }
};

pub const Regex = struct {
    allocator: std.mem.Allocator,
    insts: []Inst,
    unicode_ranges: []UnicodeRangeList = &.{},
    start_pc: u32,
    ignore_case: bool,
    unicode_case: bool = true,
    multiline: bool,
    dot_all: bool,
    num_captures: u8 = 0,
    group_count: u8 = 0,
    group_names: [9][]const u8 = @splat(""),
    anchored_start: bool = false,
    max_multiline_window: usize,
    max_dfa_states: u16 = 256,
    /// Extracted required literal (points to internally allocated bytes).
    req_literal_bytes: []u8 = &.{},
    req_literal_offset: usize = 0,
    req_is_prefix: bool = false,
    req_is_exact: bool = false,
    prefilter: ?Finder = null,
    /// Trailing required literal (such as `"timeout"` in `ERROR.*timeout`), used for a fast secondary check after a prefilter hit.
    tail_literal_bytes: []u8 = &.{},
    tail_finder: ?Finder = null,
    /// Multi-pattern SIMD prefilter for top-level alternations where every branch has a literal prefix.
    alt_literal_slices: [][]const u8 = &.{},
    alt_prefilter: ?Multi = null,
    /// Counts NFA state transition steps for unit tests asserting linear time complexity.
    steps: u64 = 0,

    pub fn init(allocator: std.mem.Allocator, pattern: []const u8, options: RegexOptions) Error!Regex {
        return initDiagnostic(allocator, pattern, options, null);
    }

    pub fn initDiagnostic(
        allocator: std.mem.Allocator,
        pattern: []const u8,
        options: RegexOptions,
        diag: ?*CompileDiagnostic,
    ) Error!Regex {
        if (diag) |d| d.* = .{};

        const inst_cap = options.effectiveMaxInst() orelse max_inst_hard_cap;
        if (inst_cap > max_inst_hard_cap or inst_cap == 0) {
            populateDiagnostic(diag, pattern, error.RegexTooLarge, .instruction_limit_exceeded, 0, "max_inst exceeds hard cap or is zero", null);
            return error.RegexTooLarge;
        }
        if (options.max_multiline_window > max_multiline_window_hard_cap or options.max_multiline_window == 0) {
            populateDiagnostic(diag, pattern, error.RegexTooLarge, .multiline_window_exceeded, 0, "max_multiline_window exceeds hard cap or is zero", null);
            return error.RegexTooLarge;
        }
        matcher.checkPatternLimits(&.{pattern}, .{}) catch |err| {
            const code: DiagnosticCode = switch (err) {
                error.PatternCountExceeded => .pattern_count_exceeded,
                error.PatternBytesExceeded => .pattern_bytes_exceeded,
            };
            populateDiagnostic(diag, pattern, err, code, 0, "pattern exceeds size limit", null);
            return err;
        };

        if (inst_mod.findInvalidUtf8Offset(pattern)) |bad_pos| {
            populateDiagnostic(diag, pattern, error.RegexSyntax, .invalid_utf8, bad_pos, "pattern contains invalid UTF-8 byte sequence", null);
            return error.RegexSyntax;
        }

        const ignore_case = switch (options.case) {
            .sensitive => false,
            .insensitive => true,
            .smart => !hasLiteralUpper(pattern, options.unicode_case),
        };

        var compiler = Compiler{
            .allocator = allocator,
            .pattern = pattern,
            .ignore_case = ignore_case,
            .unicode_case = options.unicode_case,
            .multiline = options.multiline,
            .dot_all = options.dot_all,
            .max_inst = inst_cap,
            .diag = diag,
        };
        defer compiler.deinit();

        const root_frag = try compiler.compile();
        if (!compiler.multiline) {
            if (std.mem.indexOfScalar(u8, pattern, '\n')) |nl_pos| {
                populateDiagnostic(diag, pattern, error.PatternHasNewline, .pattern_has_newline, nl_pos, "pattern contains literal newline in single-line mode", null);
                return error.PatternHasNewline;
            }
        }
        if (compiler.insts.items.len > inst_cap) {
            populateDiagnostic(diag, pattern, error.RegexTooLarge, .instruction_limit_exceeded, pattern.len, "compiled instruction count exceeds limit", null);
            return error.RegexTooLarge;
        }

        const insts = try compiler.insts.toOwnedSlice(allocator);
        errdefer allocator.free(insts);

        const unicode_ranges = try compiler.unicode_ranges.toOwnedSlice(allocator);
        errdefer {
            for (unicode_ranges) |item| {
                if (item.owned) allocator.free(item.ranges);
            }
            allocator.free(unicode_ranges);
        }

        var self = Regex{
            .allocator = allocator,
            .insts = insts,
            .unicode_ranges = unicode_ranges,
            .start_pc = root_frag.start,
            .ignore_case = compiler.ignore_case,
            .unicode_case = options.unicode_case,
            .multiline = compiler.multiline,
            .dot_all = compiler.dot_all,
            .num_captures = compiler.capture_count,
            .group_count = compiler.capture_count,
            .anchored_start = std.mem.startsWith(u8, pattern, "\\A") and !hasTopLevelAlt(pattern),
            .max_multiline_window = options.max_multiline_window,
            .max_dfa_states = options.max_dfa_states,
        };
        errdefer self.deinit();

        try prefilter_mod.extractLiterals(&self, pattern, options.case);
        return self;
    }

    pub fn deinit(self: *Regex) void {
        if (self.req_literal_bytes.len != 0) self.allocator.free(self.req_literal_bytes);
        if (self.tail_literal_bytes.len != 0) self.allocator.free(self.tail_literal_bytes);
        if (self.alt_prefilter) |*ap| ap.deinit();
        if (self.alt_literal_slices.len != 0) {
            for (self.alt_literal_slices) |s| self.allocator.free(s);
            self.allocator.free(self.alt_literal_slices);
        }
        if (self.unicode_ranges.len != 0) {
            for (self.unicode_ranges) |item| {
                if (item.owned) self.allocator.free(item.ranges);
            }
            self.allocator.free(self.unicode_ranges);
        }
        self.allocator.free(self.insts);
        self.* = undefined;
    }

    pub fn groupIndexByName(self: *const Regex, name: []const u8) ?usize {
        if (name.len == 0) return null;
        for (self.group_names[0..self.group_count], 0..) |gname, idx| {
            if (gname.len > 0 and std.mem.eql(u8, gname, name)) return idx + 1;
        }
        return null;
    }

    pub fn resetStats(self: *const Regex) void {
        @atomicStore(u64, @constCast(&self.steps), 0, .monotonic);
        if (self.prefilter) |*pf| @constCast(pf).resetStats();
        if (self.tail_finder) |*tf| @constCast(tf).resetStats();
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

    /// Thread-safe, lock-free search over `haystack`. Accepts `*const Regex` (and `*Regex` via auto-coercion).
    pub fn find(self: *const Regex, haystack: []const u8, start: usize, mode: MatchMode) ?Match {
        const steps: ?*u64 = if (comptime builtin.is_test) @constCast(&self.steps) else null;
        return self.findInternal(haystack, start, mode, steps, null);
    }

    /// Alias for `find` on `*const Regex`.
    pub fn findReadOnly(self: *const Regex, haystack: []const u8, start: usize, mode: MatchMode) ?Match {
        return self.findInternal(haystack, start, mode, null, null);
    }

    /// Searches `haystack` using caller-supplied `RegexScratch` to reuse heap NFA buffers and the 256-state `HeapDfa`.
    pub fn findWithScratch(
        self: *const Regex,
        haystack: []const u8,
        start: usize,
        mode: MatchMode,
        scratch: *RegexScratch,
    ) ?Match {
        _ = scratch.ensureDfa() catch {};
        const steps: ?*u64 = if (comptime builtin.is_test) @constCast(&self.steps) else null;
        return self.findInternal(haystack, start, mode, steps, scratch);
    }

    /// Returns true if `haystack` matches anywhere.
    pub fn isMatch(self: *const Regex, haystack: []const u8) bool {
        return self.find(haystack, 0, .earliest) != null;
    }

    /// Returns true if `haystack` matches anywhere, reusing `scratch`.
    pub fn isMatchWithScratch(self: *const Regex, haystack: []const u8, scratch: *RegexScratch) bool {
        return self.findWithScratch(haystack, 0, .earliest, scratch) != null;
    }

    /// Finds the next match along with submatch capture groups `$1`..`$9`.
    pub fn findCaptures(self: *const Regex, haystack: []const u8, start: usize, mode: MatchMode) ?Captures {
        const m = self.findInternal(haystack, start, mode, null, null) orelse return null;
        return self.extractCaptures(haystack, m);
    }

    /// Finds the next match along with submatch capture groups `$1`..`$9`, reusing `scratch`.
    pub fn findCapturesWithScratch(
        self: *const Regex,
        haystack: []const u8,
        start: usize,
        mode: MatchMode,
        scratch: *RegexScratch,
    ) ?Captures {
        const m = self.findInternal(haystack, start, mode, null, scratch) orelse return null;
        return self.extractCaptures(haystack, m);
    }

    fn findInternal(
        self: *const Regex,
        haystack: []const u8,
        start: usize,
        mode: MatchMode,
        steps: ?*u64,
        scratch: ?*RegexScratch,
    ) ?Match {
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
                        const tail_hit = tf.findReadOnly(haystack[0..win_end], hit.end, .earliest) orelse {
                            if (!self.multiline) {
                                pos = @min(haystack.len + 1, win_end + 1);
                            } else {
                                pos = hit.start + 1;
                            }
                            continue;
                        };
                        _ = tail_hit;
                    }
                    if (self.runRangeAllowed(haystack, hit.start, win_end, win_end, mode, allowAnySpan, steps, scratch)) |m| {
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
                if (self.runRangeAllowed(haystack, search_from, win_end, win_end, mode, allowAnySpan, steps, scratch)) |m| {
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

        // Fast path 4: top-level alternation where every branch starts with a literal prefix
        if (self.alt_prefilter) |*ap| {
            var pos = start;
            var min_start = start;
            var cached_win_end: usize = std.math.maxInt(usize);
            while (pos <= haystack.len) {
                const hit = ap.find(haystack, pos, .leftmost_first) orelse return null;
                const search_from = if (!self.multiline)
                    @max(min_start, lineStartAt(haystack, hit.start))
                else
                    @max(min_start, hit.start);
                const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                    cached_win_end
                else blk: {
                    const w = self.windowLimit(haystack, hit.start);
                    cached_win_end = w;
                    break :blk w;
                };
                if (self.runRangeAllowed(haystack, search_from, win_end, win_end, mode, allowAnySpan, steps, scratch)) |m| {
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

        // General path: run two-phase Lazy DFA + PikeVM hybrid engine
        return self.runWithDfa(haystack, start, haystack.len, mode, steps, scratch);
    }

    fn runWithDfa(
        self: *const Regex,
        haystack: []const u8,
        start: usize,
        limit: usize,
        mode: MatchMode,
        steps: ?*u64,
        scratch: ?*RegexScratch,
    ) ?Match {
        if (self.insts.len == 0 or start > limit) return null;
        if (scratch) |sc| {
            if (sc.ensureDfa()) |heap_dfa| {
                return self.runWithDfaGeneric(HeapDfa, heap_dfa, haystack, start, limit, mode, steps, scratch);
            } else |_| {}
        }
        var stack_dfa = StackDfa.init();
        return self.runWithDfaGeneric(StackDfa, &stack_dfa, haystack, start, limit, mode, steps, scratch);
    }

    fn runWithDfaGeneric(
        self: *const Regex,
        comptime DfaType: type,
        dfa: *DfaType,
        haystack: []const u8,
        start: usize,
        limit: usize,
        mode: MatchMode,
        steps: ?*u64,
        scratch: ?*RegexScratch,
    ) ?Match {
        if (!dfa.ensureInitialized(self.insts, self.start_pc, self.multiline, self.max_dfa_states)) {
            return self.runRangeAllowed(haystack, start, limit, limit, mode, allowAnySpan, steps, scratch);
        }

        // If the start state itself can accept zero bytes (e.g., `a*`, `^`, `$`, `\b`), delegate to PikeVM
        if (dfa.states[dfa_mod.start_state].is_match) {
            return self.runRangeAllowed(haystack, start, limit, limit, mode, allowAnySpan, steps, scratch);
        }

        var curr_state: u16 = dfa_mod.start_state;
        var active_since: usize = start;
        var pos: usize = start;
        var restarts: usize = 0;
        var local_steps: u64 = 0;
        defer if (comptime builtin.is_test) {
            if (steps) |s| {
                if (local_steps > 0) _ = @atomicRmw(u64, s, .Add, local_steps, .monotonic);
            }
        };

        while (pos < limit) {
            if (self.anchored_start and active_since > 0) break;

            if (self.multiline and curr_state != dfa_mod.start_state and (pos - active_since >= self.max_multiline_window)) {
                const win_end = @min(limit, active_since +| self.max_multiline_window);
                if (self.runRangeAllowed(haystack, active_since, active_since, win_end, mode, allowAnySpan, steps, scratch)) |m| {
                    return m;
                }
                pos = active_since + 1;
                active_since = pos;
                curr_state = dfa_mod.start_state;
                continue;
            }

            const b = haystack[pos];
            if (!self.multiline and b == '\n') {
                curr_state = dfa_mod.start_state;
                pos += 1;
                active_since = pos;
                continue;
            }

            const next_state = dfa.step(self.insts, self.unicode_ranges, curr_state, b, self.multiline);
            if (comptime builtin.is_test) local_steps += 1;

            if (next_state == dfa_mod.bailout_transition) {
                return self.runRangeAllowed(haystack, active_since, limit, limit, mode, allowAnySpan, steps, scratch);
            }

            if (next_state == dfa_mod.dead_state) {
                if (curr_state == dfa_mod.start_state) {
                    pos += 1;
                    active_since = pos;
                } else {
                    restarts += 1;
                    if (restarts >= 8 and pos > active_since + 1) {
                        const win_end = @min(limit, self.windowLimit(haystack, active_since));
                        if (self.runRangeAllowed(haystack, active_since, pos, win_end, mode, allowAnySpan, steps, scratch)) |m| {
                            return m;
                        }
                        pos += 1;
                        active_since = pos;
                        curr_state = dfa_mod.start_state;
                    } else {
                        pos = active_since + 1;
                        active_since = pos;
                        curr_state = dfa_mod.start_state;
                    }
                }
                continue;
            }

            if (curr_state == dfa_mod.start_state) {
                active_since = pos;
            }
            curr_state = next_state;
            pos += 1;

            if (dfa.states[curr_state].is_match) {
                const win_end = @min(limit, self.windowLimit(haystack, active_since));
                if (self.runRangeAllowed(haystack, active_since, active_since, win_end, mode, allowAnySpan, steps, scratch)) |m| {
                    return m;
                }
                pos = active_since + 1;
                active_since = pos;
                curr_state = dfa_mod.start_state;
            }
        }

        return null;
    }

    pub fn findWatched(self: *const Regex, haystack: []const u8, start: usize, nul: *?usize) ?Match {
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
        self: *const Regex,
        haystack: []const u8,
        start: usize,
        mode: MatchMode,
        allow_arg: anytype,
    ) ?Match {
        const steps: ?*u64 = if (comptime builtin.is_test) @constCast(&self.steps) else null;
        return self.findAllowedInternal(haystack, start, mode, allow_arg, steps);
    }

    pub fn findAllowedReadOnly(
        self: *const Regex,
        haystack: []const u8,
        start: usize,
        mode: MatchMode,
        allow_arg: anytype,
    ) ?Match {
        return self.findAllowedInternal(haystack, start, mode, allow_arg, null);
    }

    fn findAllowedInternal(
        self: *const Regex,
        haystack: []const u8,
        start: usize,
        mode: MatchMode,
        allow_arg: anytype,
        steps: ?*u64,
    ) ?Match {
        var pos = start;
        while (pos <= haystack.len) {
            const hit = self.findInternal(haystack, pos, mode, steps, null) orelse return null;
            if (inst_mod.invokeAllow(allow_arg, haystack, hit.start, hit.end)) return hit;
            const win_end = self.windowLimit(haystack, hit.start);
            if (self.runRangeAllowed(haystack, hit.start, hit.start, win_end, mode, allow_arg, steps, null)) |alt| {
                return alt;
            }
            pos = hit.start + 1;
        }
        return null;
    }

    pub fn acceptsSpan(self: *const Regex, span: []const u8, mode: MatchMode) bool {
        if (self.runRangeAllowed(span, 0, 0, span.len, mode, allowExactLen, null, null)) |m| {
            return m.start == 0 and m.end == span.len;
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

    fn runRangeAllowed(
        self: *const Regex,
        haystack: []const u8,
        start_lo: usize,
        start_hi: usize,
        limit: usize,
        mode: MatchMode,
        allow_arg: anytype,
        steps: ?*u64,
        scratch: ?*RegexScratch,
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

        var curr: []Thread = undefined;
        var next: []Thread = undefined;
        var gen_table: []u32 = undefined;

        if (n_inst <= 256) {
            curr = stack_curr[0..n_inst];
            next = stack_next[0..n_inst];
            gen_table = stack_gen[0..n_inst];
        } else if (scratch) |sc| {
            sc.ensureCapacity(n_inst) catch return null;
            curr = sc.curr[0..n_inst];
            next = sc.next[0..n_inst];
            gen_table = sc.gen_table[0..n_inst];
        } else {
            heap_curr = self.allocator.alloc(Thread, n_inst) catch return null;
            heap_next = self.allocator.alloc(Thread, n_inst) catch return null;
            heap_gen = self.allocator.alloc(u32, n_inst) catch return null;
            curr = heap_curr;
            next = heap_next;
            gen_table = heap_gen;
        }

        @memset(gen_table, 0);
        var gen: u32 = 1;

        var curr_len: usize = 0;
        var best: ?Match = null;
        var local_steps: u64 = 0;
        defer if (comptime builtin.is_test) {
            if (steps) |s| {
                if (local_steps > 0) _ = @atomicRmw(u64, s, .Add, local_steps, .monotonic);
            }
        };
        const local_steps_ptr: ?*u64 = if (comptime builtin.is_test) &local_steps else null;

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
                        (if (self.unicode_case and self.req_literal_bytes[0] >= 0x80)
                            true
                        else
                            std.ascii.toLower(haystack[pos]) == std.ascii.toLower(self.req_literal_bytes[0]))
                    else
                        haystack[pos] == self.req_literal_bytes[0]))
                else
                    true;
                if (can_start) {
                    self.addThread(curr, &curr_len, gen_table, gen, self.start_pc, pos, haystack, pos, local_steps_ptr);
                }
            }

            if (curr_len == 0) {
                if (best != null or pos >= start_hi or pos >= limit or (self.anchored_start and pos > 0)) break;
                gen +%= 1;
                if (gen == 0) {
                    @memset(gen_table, 0);
                    gen = 1;
                }
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
                    .match, .match_id => {
                        if (!inst_mod.invokeAllow(allow_arg, haystack, th.start, pos)) continue;
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
                            self.addThread(next, &next_len, gen_table, gen, by.out, th.start, haystack, pos + 1, local_steps_ptr);
                        }
                    },
                    .any => |an| {
                        if (!has_byte) continue;
                        if ((!an.allow_nl or !self.multiline) and (is_nl or (!self.multiline and b == '\r' and pos + 1 < haystack.len and haystack[pos + 1] == '\n'))) {
                            continue;
                        }
                        const seq_len = utf8SeqLenAt(haystack, pos, limit);
                        if (!self.multiline or pos + seq_len - th.start <= self.max_multiline_window) {
                            const target_pc: u32 = switch (seq_len) {
                                2 => if (an.cont1 != 0) an.cont1 else an.out,
                                3 => if (an.cont2 != 0) an.cont2 else an.out,
                                4 => if (an.cont3 != 0) an.cont3 else an.out,
                                else => an.out,
                            };
                            self.addThread(next, &next_len, gen_table, gen, target_pc, th.start, haystack, pos + 1, local_steps_ptr);
                        }
                    },
                    .any_cont => |ac| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        if ((b & 0xC0) == 0x80 and (!self.multiline or pos + 1 - th.start <= self.max_multiline_window)) {
                            self.addThread(next, &next_len, gen_table, gen, ac.out, th.start, haystack, pos + 1, local_steps_ptr);
                        }
                    },
                    .class => |cl| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        if (cl.utf8_negated and b >= 0x80) {
                            const seq_len = utf8SeqLenAt(haystack, pos, limit);
                            if (seq_len > 1) {
                                if (!self.multiline or pos + seq_len - th.start <= self.max_multiline_window) {
                                    const target_pc: u32 = switch (seq_len) {
                                        2 => if (cl.cont1 != 0) cl.cont1 else cl.out,
                                        3 => if (cl.cont2 != 0) cl.cont2 else cl.out,
                                        4 => if (cl.cont3 != 0) cl.cont3 else cl.out,
                                        else => cl.out,
                                    };
                                    self.addThread(next, &next_len, gen_table, gen, target_pc, th.start, haystack, pos + 1, local_steps_ptr);
                                }
                                continue;
                            }
                        }
                        if (cl.set.contains(b) and (!self.multiline or pos + 1 - th.start <= self.max_multiline_window)) {
                            self.addThread(next, &next_len, gen_table, gen, cl.out, th.start, haystack, pos + 1, local_steps_ptr);
                        }
                    },
                    .unicode_class => |uc| {
                        if (!has_byte) continue;
                        if (!uc.allow_nl and is_nl) continue;
                        const dec = decodeValidUtf8At(haystack, pos, limit) orelse continue;
                        const ranges = self.unicode_ranges[uc.range_idx].ranges;
                        var in_set = (dec.cp < 0x80 and uc.has_ascii_set and uc.ascii_set.contains(@intCast(dec.cp))) or inRanges(dec.cp, ranges);
                        if (!in_set and uc.ignore_case and dec.cp >= 0x80) {
                            var eq: [4]u21 = undefined;
                            const n_eq = unicode_fold.foldEquivalents(dec.cp, &eq);
                            for (eq[0..n_eq]) |alt_cp| {
                                if (inRanges(alt_cp, ranges)) {
                                    in_set = true;
                                    break;
                                }
                            }
                        }
                        const matched = if (uc.negated) !in_set else in_set;
                        if (matched and (!self.multiline or pos + dec.len - th.start <= self.max_multiline_window)) {
                            const target_pc: u32 = switch (dec.len) {
                                2 => if (uc.cont1 != 0) uc.cont1 else uc.out,
                                3 => if (uc.cont2 != 0) uc.cont2 else uc.out,
                                4 => if (uc.cont3 != 0) uc.cont3 else uc.out,
                                else => uc.out,
                            };
                            self.addThread(next, &next_len, gen_table, gen, target_pc, th.start, haystack, pos + 1, local_steps_ptr);
                        }
                    },
                    .split, .jmp, .assert, .save => {},
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
            .save => |sv| {
                self.addThread(list, list_len, gen_table, gen, sv.out, start, haystack, pos, steps);
            },
            else => {
                list[list_len.*] = .{ .pc = pc, .start = start };
                list_len.* += 1;
            },
        }
    }

    const CapThread = struct {
        pc: u32,
        slots: [18]?usize = @splat(null),
    };

    pub fn extractCaptures(self: *const Regex, haystack: []const u8, m: Match) Captures {
        var res = Captures{ .match = m };
        if (self.num_captures == 0 or m.start > m.end or m.end > haystack.len) return res;
        const n_inst = self.insts.len;
        if (n_inst == 0) return res;

        var stack_curr: [64]CapThread = undefined;
        var stack_next: [64]CapThread = undefined;
        var stack_gen: [256]u32 = undefined;

        var heap_curr: []CapThread = &.{};
        defer if (heap_curr.len != 0) self.allocator.free(heap_curr);
        var heap_next: []CapThread = &.{};
        defer if (heap_next.len != 0) self.allocator.free(heap_next);
        var heap_gen: []u32 = &.{};
        defer if (heap_gen.len != 0) self.allocator.free(heap_gen);

        var curr: []CapThread = if (n_inst <= 64) stack_curr[0..n_inst] else blk: {
            heap_curr = self.allocator.alloc(CapThread, n_inst) catch return res;
            break :blk heap_curr;
        };
        var next: []CapThread = if (n_inst <= 64) stack_next[0..n_inst] else blk: {
            heap_next = self.allocator.alloc(CapThread, n_inst) catch return res;
            break :blk heap_next;
        };
        const gen_table: []u32 = if (n_inst <= 256) stack_gen[0..n_inst] else blk: {
            heap_gen = self.allocator.alloc(u32, n_inst) catch return res;
            break :blk heap_gen;
        };
        @memset(gen_table, 0);
        var gen: u32 = 1;
        var curr_len: usize = 0;

        self.addCapThread(curr, &curr_len, gen_table, gen, self.start_pc, @splat(null), haystack, m.start);

        var pos = m.start;
        while (pos <= m.end and curr_len > 0) : (pos += 1) {
            var next_len: usize = 0;
            gen +%= 1;
            if (gen == 0) {
                @memset(gen_table, 0);
                gen = 1;
            }
            const has_byte = pos < m.end;
            const b: u8 = if (has_byte) haystack[pos] else 0;
            const is_nl = has_byte and b == '\n';

            for (curr[0..curr_len]) |th| {
                const inst = self.insts[th.pc];
                switch (inst) {
                    .match, .match_id => {
                        if (pos == m.end) {
                            for (0..9) |g| {
                                if (th.slots[g * 2]) |s| {
                                    if (th.slots[g * 2 + 1]) |e| {
                                        if (s <= e) res.groups[g] = .{ .start = s, .end = e };
                                    }
                                }
                            }
                            return res;
                        }
                    },
                    .byte => |by| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        const ok = if (by.ignore_case)
                            std.ascii.toLower(b) == std.ascii.toLower(by.b)
                        else
                            b == by.b;
                        if (ok) self.addCapThread(next, &next_len, gen_table, gen, by.out, th.slots, haystack, pos + 1);
                    },
                    .any => |an| {
                        if (!has_byte) continue;
                        if ((!an.allow_nl or !self.multiline) and (is_nl or (!self.multiline and b == '\r' and pos + 1 < haystack.len and haystack[pos + 1] == '\n'))) {
                            continue;
                        }
                        const seq_len = utf8SeqLenAt(haystack, pos, m.end);
                        const target_pc: u32 = switch (seq_len) {
                            2 => if (an.cont1 != 0) an.cont1 else an.out,
                            3 => if (an.cont2 != 0) an.cont2 else an.out,
                            4 => if (an.cont3 != 0) an.cont3 else an.out,
                            else => an.out,
                        };
                        self.addCapThread(next, &next_len, gen_table, gen, target_pc, th.slots, haystack, pos + 1);
                    },
                    .any_cont => |ac| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        if ((b & 0xC0) == 0x80) {
                            self.addCapThread(next, &next_len, gen_table, gen, ac.out, th.slots, haystack, pos + 1);
                        }
                    },
                    .class => |cl| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        if (cl.utf8_negated and b >= 0x80) {
                            const seq_len = utf8SeqLenAt(haystack, pos, m.end);
                            if (seq_len > 1) {
                                const target_pc: u32 = switch (seq_len) {
                                    2 => if (cl.cont1 != 0) cl.cont1 else cl.out,
                                    3 => if (cl.cont2 != 0) cl.cont2 else cl.out,
                                    4 => if (cl.cont3 != 0) cl.cont3 else cl.out,
                                    else => cl.out,
                                };
                                self.addCapThread(next, &next_len, gen_table, gen, target_pc, th.slots, haystack, pos + 1);
                                continue;
                            }
                        }
                        if (cl.set.contains(b)) {
                            self.addCapThread(next, &next_len, gen_table, gen, cl.out, th.slots, haystack, pos + 1);
                        }
                    },
                    .unicode_class => |uc| {
                        if (!has_byte) continue;
                        if (!uc.allow_nl and is_nl) continue;
                        const dec = decodeValidUtf8At(haystack, pos, m.end) orelse continue;
                        const ranges = self.unicode_ranges[uc.range_idx].ranges;
                        var in_set = (dec.cp < 0x80 and uc.has_ascii_set and uc.ascii_set.contains(@intCast(dec.cp))) or inRanges(dec.cp, ranges);
                        if (!in_set and uc.ignore_case and dec.cp >= 0x80) {
                            var eq: [4]u21 = undefined;
                            const n_eq = unicode_fold.foldEquivalents(dec.cp, &eq);
                            for (eq[0..n_eq]) |alt_cp| {
                                if (inRanges(alt_cp, ranges)) {
                                    in_set = true;
                                    break;
                                }
                            }
                        }
                        const matched = if (uc.negated) !in_set else in_set;
                        if (matched) {
                            const target_pc: u32 = switch (dec.len) {
                                2 => if (uc.cont1 != 0) uc.cont1 else uc.out,
                                3 => if (uc.cont2 != 0) uc.cont2 else uc.out,
                                4 => if (uc.cont3 != 0) uc.cont3 else uc.out,
                                else => uc.out,
                            };
                            self.addCapThread(next, &next_len, gen_table, gen, target_pc, th.slots, haystack, pos + 1);
                        }
                    },
                    .split, .jmp, .assert, .save => {},
                }
            }
            if (!has_byte) break;
            const tmp = curr;
            curr = next;
            next = tmp;
            curr_len = next_len;
        }
        return res;
    }

    fn addCapThread(
        self: *const Regex,
        list: []CapThread,
        list_len: *usize,
        gen_table: []u32,
        gen: u32,
        pc: u32,
        slots: [18]?usize,
        haystack: []const u8,
        pos: usize,
    ) void {
        if (gen_table[pc] == gen) return;
        gen_table[pc] = gen;

        switch (self.insts[pc]) {
            .jmp => |target| {
                self.addCapThread(list, list_len, gen_table, gen, target, slots, haystack, pos);
            },
            .split => |sp| {
                self.addCapThread(list, list_len, gen_table, gen, sp.out1, slots, haystack, pos);
                self.addCapThread(list, list_len, gen_table, gen, sp.out2, slots, haystack, pos);
            },
            .assert => |as| {
                if (checkAssert(as.kind, haystack, pos)) {
                    self.addCapThread(list, list_len, gen_table, gen, as.out, slots, haystack, pos);
                }
            },
            .save => |sv| {
                var next_slots = slots;
                if (sv.slot < 18) next_slots[sv.slot] = pos;
                self.addCapThread(list, list_len, gen_table, gen, sv.out, next_slots, haystack, pos);
            },
            else => {
                list[list_len.*] = .{ .pc = pc, .slots = slots };
                list_len.* += 1;
            },
        }
    }
};
