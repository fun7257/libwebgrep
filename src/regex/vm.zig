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
const multi_mod = @import("../finder/multi.zig");
const Multi = multi_mod.Multi;
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
pub const UnanchoredDfa = dfa_mod.UnanchoredDfa;

const Thread = inst_mod.Thread;
const Compiler = compiler_mod.Compiler;
const hasLiteralUpper = inst_mod.hasLiteralUpper;
const hasTopLevelAlt = inst_mod.hasTopLevelAlt;
const lineStartAt = inst_mod.lineStartAt;
const allowExactLen = inst_mod.allowExactLen;
const checkAssert = inst_mod.checkAssert;

const AllowAny = struct {
    pub inline fn allow(_: @This(), _: []const u8, _: usize, _: usize) bool {
        return true;
    }
};
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
    group_names: [inst_mod.max_capture_groups][]const u8 = @splat(""),
    anchored_start: bool = false,
    max_multiline_window: usize,
    max_dfa_states: u16 = 256,
    /// Extracted required literal (points to internally allocated bytes).
    req_literal_bytes: []u8 = &.{},
    req_literal_offset: usize = 0,
    req_prefix_shift: usize = 1,
    req_is_prefix: bool = false,
    req_is_exact: bool = false,
    /// True when the entire pattern is strictly `\b<req_literal_bytes>\b` (verified via O(1) boundary checks).
    req_word_bounded: bool = false,
    /// True when `req_word_bounded` uses ASCII `\b` (`.ascii_word_boundary`) rather than Unicode `\b`.
    req_word_bounded_ascii: bool = false,
    /// Minimum bytes required before `req_literal_bytes` (derived from compiled NFA graph).
    req_min_before: usize = 0,
    /// Bounded maximum bytes before `req_literal_bytes`, or `null` when a prefix cycle exists.
    req_max_before: ?usize = null,
    /// When true, `haystack[hit.start - 1]` (and up to 3 bytes before `hit.start`) must match `req_prev_masks`.
    req_has_prev_mask: bool = false,
    req_prev_mask: ByteSet = .{},
    req_prev_mask_len: u8 = 0,
    req_prev_masks: [3]ByteSet = .{ .{}, .{}, .{} },
    /// Optional k-byte suffix prefilter (`[prev_bytes..., req_literal_bytes[0]]`, k = 1..3)
    /// when a 1-byte interior/trailing literal has a small Cartesian product of predecessor bytes
    /// (e.g., `(a|b){15}c` -> 8 4-byte patterns `aaac..bbbc` dispatched to AVX2 Teddy).
    pair_prefilter_slices: [][]const u8 = &.{},
    pair_prefilter: ?Multi = null,
    pair_prefilter_prefix_len: u8 = 0,
    /// Optional SIMD single-byte literal + contiguous predecessor/successor byte-range prefilter
    /// (e.g. `\p{Han}+_[0-9]{4}` -> `[0x80..0xBF]_[0-9]`, `[a-z]{4,7}=[0-9]{3,4}ms` -> `[a-z]=[0-9]`).
    byte_ctx_prefilter: ?ByteContextPrefilter = null,
    /// When non-sentinel, the prefix before `req_literal_bytes` is strictly a repeated single `.unicode_class`
    /// (`+` if `req_prefix_uclass_min == 1`, `*` if `0`), disjoint from `req_literal_bytes[0]`, with an exact suffix DFA.
    req_prefix_uclass_pc: u32 = std.math.maxInt(u32),
    req_prefix_uclass_min: u8 = 0,
    dfa_suffix_is_exact: bool = false,
    /// When true, every byte in `[match.start .. hit.start)` must belong to `req_prefix_bytes_mask`.
    req_has_prefix_bytes_mask: bool = false,
    req_prefix_bytes_mask: ByteSet = .{},
    prefilter: ?Finder = null,
    /// Trailing required literal (such as `"timeout"` in `ERROR.*timeout`), used for a fast secondary check after a prefilter hit.
    tail_literal_bytes: []u8 = &.{},
    tail_finder: ?Finder = null,
    /// Multi-pattern SIMD prefilter for top-level alternations where every branch has a literal prefix.
    alt_literal_slices: [][]const u8 = &.{},
    alt_prefilter: ?Multi = null,
    alt_is_exact: bool = false,
    alt_is_prefix: bool = false,
    /// Optional longest-common-prefix `Finder` across all alternation branches (e.g., `ALT_TOKEN_` for 32 branches).
    alt_lcp_bytes: []u8 = &.{},
    alt_lcp_finder: ?Finder = null,
    alt_max_branch_len: usize = 0,
    /// Pre-determinized anchored DFA if full ahead-of-time determinization succeeded.
    precomputed_dfa: ?*HeapDfa = null,
    /// Pre-determinized unanchored Phase-1 DFA for zero-literal patterns (`prefilter == null and alt_prefilter == null`).
    unanchored_dfa: ?*UnanchoredDfa = null,
    has_lazy: bool = false,
    has_alt: bool = false,
    saw_extended: bool = false,
    dfa_is_exact: bool = false,
    /// True when `precomputed_dfa` produces exact match spans whenever the matched slice is pure ASCII.
    dfa_exact_on_ascii: bool = false,
    /// True when `precomputed_dfa` (including `.any`) produces exact match spans on pure ASCII slices
    /// (also verifying no `\r` when `dfa_any_needs_no_cr` is true).
    dfa_exact_on_ascii_any: bool = false,
    dfa_any_needs_no_cr: bool = false,
    dfa_has_unicode_class: bool = false,
    /// Specialized fast path for `<prefix_lit>.{min,max}<tail_lit>` / `<prefix_lit>.*<tail_lit>` patterns.
    prefix_any_tail: ?PrefixAnyTail = null,
    /// Optional compiled linear capture plan for zero-PikeVM submatch extraction (`extractCaptures`).
    cap_plan: ?*CapPlan = null,
    dfa_prefix_state: u16 = dfa_mod.start_state,
    dfa_prefix_len: usize = 0,
    dfa_suffix_state: u16 = 0,
    alt_dfa_prefix_state: [32]u16 = @splat(dfa_mod.start_state),
    alt_dfa_prefix_len: [32]u8 = @splat(0),
    max_newlines: ?u32 = null,
    /// Counts NFA state transition steps for unit tests asserting linear time complexity.
    steps: usize = 0,

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
        if (inst_cap == 0 or inst_cap > std.math.maxInt(u32)) {
            populateDiagnostic(diag, pattern, error.RegexTooLarge, .instruction_limit_exceeded, 0, "max_inst is zero or exceeds u32 max", null);
            return error.RegexTooLarge;
        }
        if (options.max_multiline_window == 0) {
            populateDiagnostic(diag, pattern, error.RegexTooLarge, .multiline_window_exceeded, 0, "max_multiline_window is zero", null);
            return error.RegexTooLarge;
        }
        matcher.checkPatternLimits(&.{pattern}, .{
            .max_pattern_count = options.max_pattern_count,
            .max_pattern_bytes = options.max_pattern_bytes,
            .max_unicode_variants = options.max_unicode_variants,
        }) catch |err| {
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
            .unicode_classes = options.unicode_classes,
            .unicode_word_boundary = options.unicode_word_boundary,
            .multiline = options.multiline,
            .dot_all = options.dot_all,
            .max_inst = inst_cap,
            .max_repeat = options.max_repeat,
            .max_recursion_depth = options.max_recursion_depth,
            .diag = diag,
        };
        defer compiler.deinit();

        const root_frag = try compiler.compile();
        const effective_ml = compiler.multiline or compiler.saw_scoped_m;
        if (!effective_ml) {
            if (compiler.saw_literal_nl_pos) |nl_pos| {
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
            .ignore_case = compiler.ignore_case or compiler.saw_ignore_case,
            .unicode_case = options.unicode_case,
            .multiline = effective_ml,
            .dot_all = compiler.dot_all,
            .num_captures = compiler.capture_count,
            .group_count = compiler.capture_count,
            .anchored_start = std.mem.startsWith(u8, pattern, "\\A") and !hasTopLevelAlt(pattern),
            .max_multiline_window = options.max_multiline_window,
            .max_dfa_states = options.max_dfa_states,
            .has_lazy = compiler.has_lazy,
            .has_alt = compiler.has_alt,
            .saw_extended = compiler.saw_extended,
            .max_newlines = computeMaxNewlines(insts, unicode_ranges, root_frag.start, effective_ml),
        };
        errdefer self.deinit();

        for (compiler.capture_names[0..compiler.capture_count], 0..) |name, idx| {
            if (name.len > 0) {
                self.group_names[idx] = try allocator.dupe(u8, name);
            }
        }

        try prefilter_mod.extractLiterals(&self, pattern, options);
        if (self.req_literal_bytes.len > 1 and (!self.ignore_case or !self.unicode_case)) {
            const lit = self.req_literal_bytes;
            var shift: usize = lit.len;
            var k: usize = 1;
            while (k < lit.len) : (k += 1) {
                const rem = lit.len - k;
                const ok_overlap = if (self.ignore_case)
                    std.ascii.eqlIgnoreCase(lit[0..rem], lit[k..])
                else
                    std.mem.eql(u8, lit[0..rem], lit[k..]);
                if (ok_overlap) {
                    shift = k;
                    break;
                }
            }
            self.req_prefix_shift = shift;
        }
        self.prefix_any_tail = detectPrefixAnyTail(&self);
        if (compileCapPlan(&self)) |plan| {
            if (allocator.create(CapPlan)) |cp| {
                cp.* = plan;
                self.cap_plan = cp;
            } else |_| {}
        }
        if (options.max_dfa_states > 0 and self.insts.len <= options.aot_dfa_max_insts) {
            if (self.prefilter == null and self.alt_prefilter == null and !self.anchored_start) {
                if (allocator.create(UnanchoredDfa)) |udfa| {
                    udfa.* = .{};
                    if (udfa.determinize(allocator, self.insts, self.unicode_ranges, self.start_pc, self.multiline, options.max_dfa_states)) {
                        self.unanchored_dfa = udfa;
                    } else {
                        udfa.deinit(allocator);
                        allocator.destroy(udfa);
                    }
                } else |_| {}
            } else if (allocator.create(HeapDfa)) |heap_dfa| {
                heap_dfa.* = HeapDfa.init();
                if (heap_dfa.determinize(self.insts, self.unicode_ranges, self.start_pc, self.multiline)) {
                    self.precomputed_dfa = heap_dfa;
                    self.dfa_is_exact = !self.has_lazy and dfa_mod.isExactInsts(self.insts);
                    self.dfa_exact_on_ascii = !self.has_lazy and dfa_mod.isExactOnAsciiInsts(self.insts);
                    self.dfa_exact_on_ascii_any = !self.has_lazy and dfa_mod.isExactOnAsciiAnyInsts(self.insts);
                    if (self.dfa_exact_on_ascii_any) {
                        var needs_no_cr = false;
                        var has_uc = false;
                        for (self.insts) |inst| {
                            switch (inst) {
                                .any => |an| {
                                    if (!an.allow_nl) needs_no_cr = true;
                                },
                                .unicode_class => has_uc = true,
                                else => {},
                            }
                        }
                        self.dfa_any_needs_no_cr = needs_no_cr;
                        self.dfa_has_unicode_class = has_uc;
                    }
                    if (self.req_is_prefix and self.req_literal_bytes.len > 0) {
                        var s: u16 = dfa_mod.start_state;
                        var ok = true;
                        var any_prefix_match = heap_dfa.is_match[s];
                        for (self.req_literal_bytes, 0..) |b, idx| {
                            const n = heap_dfa.trans[s][b];
                            if (n == dfa_mod.unknown_transition or n == dfa_mod.bailout_transition or n == dfa_mod.dead_state) {
                                ok = false;
                                break;
                            }
                            s = n;
                            if (idx + 1 < self.req_literal_bytes.len and heap_dfa.is_match[s]) {
                                any_prefix_match = true;
                            }
                        }
                        if (ok and !any_prefix_match and s != dfa_mod.dead_state) {
                            self.dfa_prefix_state = s;
                            self.dfa_prefix_len = self.req_literal_bytes.len;
                        }
                    } else if (!self.req_is_prefix and self.req_literal_bytes.len >= 1 and (!self.ignore_case or !self.unicode_case)) {
                        if (findUniqueLiteralSpanPc(self.insts, self.req_literal_bytes)) |span_pc| {
                            if (heap_dfa.determinizeSuffix(self.insts, self.unicode_ranges, span_pc.end_pc, self.multiline)) |s_id| {
                                self.dfa_suffix_state = s_id;
                            }
                        }
                    }
                    if (self.alt_is_prefix and self.alt_literal_slices.len > 0 and self.alt_literal_slices.len <= 32 and (!self.ignore_case or !self.unicode_case)) {
                        for (self.alt_literal_slices, 0..) |lit, id| {
                            if (lit.len == 0 or lit.len > std.math.maxInt(u8)) continue;
                            var s: u16 = dfa_mod.start_state;
                            var ok = true;
                            var any_prefix_match = heap_dfa.is_match[s];
                            for (lit, 0..) |b, idx| {
                                const n = heap_dfa.trans[s][b];
                                if (n == dfa_mod.unknown_transition or n == dfa_mod.bailout_transition or n == dfa_mod.dead_state) {
                                    ok = false;
                                    break;
                                }
                                s = n;
                                if (idx + 1 < lit.len and heap_dfa.is_match[s]) {
                                    any_prefix_match = true;
                                }
                            }
                            if (ok and !any_prefix_match and s != dfa_mod.dead_state) {
                                self.alt_dfa_prefix_state[id] = s;
                                self.alt_dfa_prefix_len[id] = @intCast(lit.len);
                            }
                        }
                    }
                } else {
                    allocator.destroy(heap_dfa);
                }
            } else |_| {}
        }
        if (!self.req_is_exact and !self.req_is_prefix and self.req_literal_bytes.len >= 1 and (!self.ignore_case or !self.unicode_case)) {
            analyzeRequiredLiteralContext(&self);
        }
        return self;
    }

    pub fn deinit(self: *Regex) void {
        for (self.group_names[0..self.group_count]) |name| {
            if (name.len != 0) self.allocator.free(name);
        }
        if (self.cap_plan) |cp| self.allocator.destroy(cp);
        if (self.unanchored_dfa) |ud| {
            ud.deinit(self.allocator);
            self.allocator.destroy(ud);
        }
        if (self.precomputed_dfa) |d| self.allocator.destroy(d);
        if (self.req_literal_bytes.len != 0) self.allocator.free(self.req_literal_bytes);
        if (self.tail_literal_bytes.len != 0) self.allocator.free(self.tail_literal_bytes);
        if (self.pair_prefilter) |*pp| pp.deinit();
        if (self.pair_prefilter_slices.len != 0) {
            for (self.pair_prefilter_slices) |s| self.allocator.free(s);
            self.allocator.free(self.pair_prefilter_slices);
        }
        if (self.alt_lcp_bytes.len != 0) self.allocator.free(self.alt_lcp_bytes);
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
        if (comptime builtin.is_test) {
            @atomicStore(usize, @constCast(&self.steps), 0, .monotonic);
        }
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

    pub fn maxNewlines(self: *const Regex) ?u32 {
        return self.max_newlines;
    }

    pub fn earliestPendingStart(self: *const Regex, chunk: []const u8, from: usize) usize {
        if (from >= chunk.len) return chunk.len;
        if (self.req_is_exact or self.req_is_prefix) {
            if (self.prefilter) |*pf| {
                const max_lit_bytes = if (self.ignore_case and self.unicode_case)
                    self.req_literal_bytes.len *| 3
                else
                    self.req_literal_bytes.len;
                const tail_keep = max_lit_bytes -| 1;
                const tail_start = chunk.len -| tail_keep;
                if (pf.findReadOnly(chunk, from, .earliest)) |hit| {
                    return @min(hit.start, tail_start);
                }
                return tail_start;
            }
        }
        return from;
    }

    pub inline fn watchedIsExact(self: *const Regex) bool {
        if (self.anchored_start) return false;
        if (self.req_is_exact or self.req_word_bounded) return true;
        if (self.req_is_prefix and self.precomputed_dfa != null and self.dfa_is_exact and !self.has_alt) return true;
        return false;
    }

    pub inline fn watchedHasExactStart(self: *const Regex) bool {
        if (self.anchored_start) return false;
        return self.req_is_exact or self.req_word_bounded or self.req_is_prefix;
    }

    inline fn isAsciiExactMatch(self: *const Regex, matched: []const u8) bool {
        if (self.dfa_exact_on_ascii) return isAsciiBytes(matched);
        if (self.dfa_exact_on_ascii_any) {
            if (self.dfa_any_needs_no_cr and std.mem.findScalar(u8, matched, '\r') != null) return false;
            if (isAsciiBytes(matched)) return true;
            if (!self.dfa_has_unicode_class and std.unicode.utf8ValidateSlice(matched)) return true;
            return false;
        }
        return false;
    }

    /// Thread-safe, lock-free search over `haystack`. Accepts `*const Regex` (and `*Regex` via auto-coercion).
    pub fn find(self: *const Regex, haystack: []const u8, start: usize, mode: MatchMode) ?Match {
        const steps: ?*usize = if (comptime builtin.is_test) @constCast(&self.steps) else null;
        return self.findInternal(haystack, start, mode, steps, null);
    }

    /// Alias for `find` on `*const Regex`.
    pub fn findReadOnly(self: *const Regex, haystack: []const u8, start: usize, mode: MatchMode) ?Match {
        return self.findInternal(haystack, start, mode, null, null);
    }

    /// Half-match fast path returning the exact match end offset (`?usize`) without recovering `start`.
    /// When `unanchored_dfa` reaches an exact accepting state (`exact_imm`, 1-byte delayed `exact_del`, or `eoi_exact`),
    /// returns immediately with 0 PikeVM calls, 0 `windowLimit`, and 0 `lineStartAt`.
    pub fn findEnd(self: *const Regex, haystack: []const u8, start: usize, mode: MatchMode) ?usize {
        if (start > haystack.len) return null;
        if (self.anchored_start and start > 0) return null;
        if (self.unanchored_dfa) |udfa| {
            if (mode == .earliest and !self.multiline and udfa.has_exact_match) {
                const steps: ?*usize = if (comptime builtin.is_test) @constCast(&self.steps) else null;
                var unused_nul: ?usize = null;
                return self.runUnanchoredDfaEnd(udfa, haystack, start, haystack.len, steps, false, &unused_nul);
            }
        }
        const m = self.find(haystack, start, mode) orelse return null;
        return m.end;
    }

    /// NUL-watched half-match fast path returning the exact match end offset (`?usize`).
    /// Sets `nul.*` and returns `null` if a NUL byte occurs strictly before the match ends.
    pub fn findEndWatched(self: *const Regex, haystack: []const u8, start: usize, mode: MatchMode, nul: *?usize) ?usize {
        if (start > haystack.len) return null;
        if (!self.anchored_start) {
            if (self.unanchored_dfa) |udfa| {
                if (mode == .earliest and !self.multiline and udfa.has_exact_match) {
                    const steps: ?*usize = if (comptime builtin.is_test) @constCast(&self.steps) else null;
                    return self.runUnanchoredDfaEnd(udfa, haystack, start, haystack.len, steps, true, nul);
                }
            }
        }
        const m = self.findWatched(haystack, start, nul) orelse return null;
        return m.end;
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
        const steps: ?*usize = if (comptime builtin.is_test) @constCast(&self.steps) else null;
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

    /// Finds the next match along with submatch capture groups `$1`..`$32`.
    pub fn findCaptures(self: *const Regex, haystack: []const u8, start: usize, mode: MatchMode) ?Captures {
        const m = self.findInternal(haystack, start, mode, null, null) orelse return null;
        return self.extractCaptures(haystack, m);
    }

    /// Finds the next match along with submatch capture groups `$1`..`$32`, reusing `scratch`.
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
        steps: ?*usize,
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

        // Fast path 1b: the entire regex is strictly `\b<literal>\b` (Unicode or ASCII)
        if (self.req_word_bounded) {
            if (self.prefilter) |*pf| {
                const wb_kind: AssertKind = if (self.req_word_bounded_ascii) .ascii_word_boundary else .word_boundary;
                var pos = start;
                while (pos <= haystack.len) {
                    const hit = pf.findReadOnly(haystack, pos, .earliest) orelse return null;
                    if (checkAssert(wb_kind, haystack, hit.start) and checkAssert(wb_kind, haystack, hit.end)) {
                        return hit;
                    }
                    pos = hit.start + self.req_prefix_shift;
                }
                return null;
            }
        }

        // Fast path 2: has a required literal prefix (e.g., `ERROR.*timeout` or `WARN_[0-9]+`)
        if (self.req_is_prefix) {
            if (self.prefilter) |*pf| {
                if (self.prefix_any_tail) |pat| {
                    if (self.tail_finder) |*tf| {
                        var unused_nul: ?usize = null;
                        return self.findPrefixAnyTail(pat, pf, tf, haystack, start, mode, false, &unused_nul);
                    }
                }
                var pos = start;
                const exact_for_mode = self.dfa_is_exact and !self.has_alt;
                const ascii_exact_for_mode = (self.dfa_exact_on_ascii or self.dfa_exact_on_ascii_any) and !self.has_alt;
                const can_jump_tail = !self.ignore_case or !self.unicode_case;
                if (self.precomputed_dfa) |dfa| {
                    if (exact_for_mode and dfa.stops_on_crlf) {
                        const fixed_prefix = self.dfa_prefix_len > 0 and self.dfa_prefix_len == self.req_literal_bytes.len and (!self.ignore_case or !self.unicode_case);
                        if (fixed_prefix) {
                            const s0 = self.dfa_prefix_state;
                            const p0 = self.dfa_prefix_len;
                            const shift = self.req_prefix_shift;
                            const clen: usize = dfa.chain_len[s0];
                            if (clen >= 2 and dfa.chain_uniform_span[s0] != 0xFF and dfa.is_terminal[s0 + clen]) {
                                const u_lo = dfa.chain_uniform_lo[s0];
                                const u_sp = dfa.chain_uniform_span[s0];
                                while (pos <= haystack.len) {
                                    const hit = pf.findReadOnly(haystack, pos, .earliest) orelse return null;
                                    const rem_start = hit.start + p0;
                                    if (rem_start + clen <= haystack.len) {
                                        const p = haystack[rem_start..][0..clen];
                                        if ((p[clen - 1] -% u_lo) <= u_sp) {
                                            var ok = true;
                                            for (p[0 .. clen - 1]) |ch| {
                                                if ((ch -% u_lo) > u_sp) {
                                                    ok = false;
                                                    break;
                                                }
                                            }
                                            if (ok) {
                                                return Match{
                                                    .start = hit.start,
                                                    .end = rem_start + clen,
                                                    .pattern_id = null,
                                                };
                                            }
                                        }
                                    }
                                    pos = hit.start + shift;
                                }
                                return null;
                            }
                            while (pos <= haystack.len) {
                                const hit = pf.findReadOnly(haystack, pos, .earliest) orelse return null;
                                if (dfa.matchPrefixDeterminized(haystack[hit.start..], s0, p0, false)) |match_len| {
                                    return Match{
                                        .start = hit.start,
                                        .end = hit.start + match_len,
                                        .pattern_id = null,
                                    };
                                }
                                pos = hit.start + shift;
                            }
                            return null;
                        }
                        while (pos <= haystack.len) {
                            const hit = pf.findReadOnly(haystack, pos, .earliest) orelse return null;
                            const can_skip_prefix = (hit.end - hit.start == self.dfa_prefix_len);
                            const s0: u16 = if (can_skip_prefix) self.dfa_prefix_state else dfa_mod.start_state;
                            const p0: usize = if (can_skip_prefix) self.dfa_prefix_len else 0;
                            if (dfa.matchPrefixDeterminized(haystack[hit.start..], s0, p0, false)) |match_len| {
                                return Match{
                                    .start = hit.start,
                                    .end = hit.start + match_len,
                                    .pattern_id = null,
                                };
                            }
                            pos = hit.start + self.req_prefix_shift;
                        }
                        return null;
                    }
                    var cached_win_end: usize = std.math.maxInt(usize);
                    var next_tail: ?Match = null;
                    while (pos <= haystack.len) {
                        const hit = pf.findReadOnly(haystack, pos, .earliest) orelse return null;
                        const can_skip_prefix = (hit.end - hit.start == self.dfa_prefix_len);
                        const s0: u16 = if (can_skip_prefix) self.dfa_prefix_state else dfa_mod.start_state;
                        const p0: usize = if (can_skip_prefix) self.dfa_prefix_len else 0;
                        const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                            cached_win_end
                        else blk: {
                            const w = self.windowLimit(haystack, hit.start);
                            cached_win_end = w;
                            break :blk w;
                        };
                        if (self.tail_finder) |*tf| {
                            if (next_tail == null or next_tail.?.start < hit.end) {
                                next_tail = tf.findReadOnly(haystack, hit.end, .earliest) orelse return null;
                            }
                            if (next_tail.?.end > win_end) {
                                if (!self.multiline) {
                                    const nl_next = @min(haystack.len + 1, win_end + 1);
                                    pos = if (can_jump_tail) @max(nl_next, lineStartAt(haystack, next_tail.?.start)) else nl_next;
                                } else {
                                    pos = if (can_jump_tail)
                                        @max(hit.start + self.req_prefix_shift, next_tail.?.end -| self.max_multiline_window)
                                    else
                                        hit.start + self.req_prefix_shift;
                                }
                                continue;
                            }
                        }
                        if (dfa.matchPrefixDeterminized(haystack[hit.start..win_end], s0, p0, !exact_for_mode and !ascii_exact_for_mode)) |match_len| {
                            if (exact_for_mode or (ascii_exact_for_mode and self.isAsciiExactMatch(haystack[hit.start .. hit.start + match_len]))) {
                                return Match{
                                    .start = hit.start,
                                    .end = hit.start + match_len,
                                    .pattern_id = null,
                                };
                            }
                            if (self.runRangeAllowed(haystack, hit.start, hit.start, win_end, mode, AllowAny{}, steps, scratch)) |m| {
                                return m;
                            }
                        }
                        pos = hit.start + self.req_prefix_shift;
                    }
                    return null;
                }
                var cached_win_end: usize = std.math.maxInt(usize);
                var next_tail: ?Match = null;
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
                        if (next_tail == null or next_tail.?.start < hit.end) {
                            next_tail = tf.findReadOnly(haystack, hit.end, .earliest) orelse return null;
                        }
                        if (next_tail.?.end > win_end) {
                            if (!self.multiline) {
                                const nl_next = @min(haystack.len + 1, win_end + 1);
                                pos = if (can_jump_tail) @max(nl_next, lineStartAt(haystack, next_tail.?.start)) else nl_next;
                            } else {
                                pos = if (can_jump_tail)
                                    @max(hit.start + self.req_prefix_shift, next_tail.?.end -| self.max_multiline_window)
                                else
                                    hit.start + 1;
                            }
                            continue;
                        }
                    }
                    const p_hi = if (self.multiline) hit.start else win_end;
                    if (self.runRangeAllowed(haystack, hit.start, p_hi, win_end, mode, AllowAny{}, steps, scratch)) |m| {
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
            const exact_for_mode = self.dfa_is_exact and !self.has_alt;
            const ascii_exact_for_mode = (self.dfa_exact_on_ascii or self.dfa_exact_on_ascii_any) and !self.has_alt;
            while (pos <= haystack.len) {
                const hit = if (self.pair_prefilter) |*pp| blk: {
                    const pf_pre: usize = self.pair_prefilter_prefix_len;
                    const pair_search_from = @max(pos, min_start + self.req_min_before) -| pf_pre;
                    if (pair_search_from > haystack.len) return null;
                    const ph = pp.find(haystack, pair_search_from, .earliest) orelse return null;
                    break :blk Match{ .start = ph.start + pf_pre, .end = ph.end, .pattern_id = null };
                } else if (self.byte_ctx_prefilter) |bcp| blk: {
                    const at = bcp.find(haystack, pos, min_start + self.req_min_before) orelse return null;
                    break :blk Match{ .start = at, .end = at + 1, .pattern_id = null };
                } else (pf.findReadOnly(haystack, pos, .earliest) orelse return null);
                if (self.multiline and hit.end - hit.start > self.max_multiline_window) {
                    pos = hit.start + 1;
                    min_start = pos;
                    continue;
                }
                if (hit.start < min_start + self.req_min_before) {
                    pos = hit.start + self.req_prefix_shift;
                    continue;
                }
                if (self.req_has_prev_mask) {
                    if (!self.req_prev_masks[0].contains(haystack[hit.start - 1])) {
                        pos = hit.start + self.req_prefix_shift;
                        continue;
                    }
                    if (self.req_prev_mask_len >= 2 and !self.req_prev_masks[1].contains(haystack[hit.start - 2])) {
                        pos = hit.start + self.req_prefix_shift;
                        continue;
                    }
                    if (self.req_prev_mask_len >= 3 and !self.req_prev_masks[2].contains(haystack[hit.start - 3])) {
                        pos = hit.start + self.req_prefix_shift;
                        continue;
                    }
                }
                if (self.req_prefix_uclass_pc != std.math.maxInt(u32) and self.dfa_suffix_is_exact) {
                    if (self.precomputed_dfa) |dfa| {
                        if (dfa.matchPrefixDeterminized(haystack[hit.end..], self.dfa_suffix_state, 0, false)) |suf_len| {
                            const uc = self.insts[self.req_prefix_uclass_pc].unicode_class;
                            const ranges = self.unicode_ranges[uc.range_idx].ranges;
                            if (matchPrefixUclassReverse(haystack, min_start, hit.start, uc, ranges, self.req_prefix_uclass_min)) |run_start| {
                                return Match{ .start = run_start, .end = hit.end + suf_len, .pattern_id = null };
                            }
                        }
                        pos = hit.start + self.req_prefix_shift;
                        continue;
                    }
                }
                if (self.dfa_suffix_state != 0 and !self.multiline) {
                    if (self.precomputed_dfa) |dfa| {
                        if (dfa.matchPrefixDeterminized(haystack[hit.end..], self.dfa_suffix_state, 0, true) == null) {
                            pos = hit.start + self.req_prefix_shift;
                            continue;
                        }
                    }
                }
                const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                    cached_win_end
                else blk: {
                    const w = self.windowLimit(haystack, hit.start);
                    cached_win_end = w;
                    break :blk w;
                };
                if (self.tail_finder) |*tf| {
                    if (hit.end > win_end or tf.findReadOnly(haystack[0..win_end], hit.end, .earliest) == null) {
                        if (!self.multiline) {
                            pos = @min(haystack.len + 1, win_end + 1);
                            min_start = pos;
                        } else {
                            pos = hit.start + 1;
                            min_start = hit.start + 1;
                        }
                        continue;
                    }
                }
                const narrowed_local = !self.multiline and (self.req_max_before != null or self.req_has_prefix_bytes_mask);
                const search_from = blk: {
                    if (self.multiline) {
                        break :blk @max(min_start, hit.end -| self.max_multiline_window);
                    }
                    var lo = min_start;
                    if (self.req_max_before) |max_b| {
                        lo = @max(lo, hit.start -| max_b);
                    }
                    if (self.req_has_prefix_bytes_mask) {
                        var cur = hit.start;
                        while (cur > lo and self.req_prefix_bytes_mask.contains(haystack[cur - 1])) {
                            cur -= 1;
                        }
                        lo = cur;
                    }
                    if (self.req_max_before != null or self.req_has_prefix_bytes_mask) {
                        if (lo < hit.start and (!self.req_has_prefix_bytes_mask or self.req_prefix_bytes_mask.contains('\n'))) {
                            if (memchr.findLast(memchr.native_width, haystack, lo, hit.start, '\n')) |nl| {
                                lo = nl + 1;
                            }
                        }
                        break :blk lo;
                    }
                    break :blk @max(min_start, lineStartAt(haystack, hit.start));
                };
                const p_hi = if (self.multiline)
                    hit.start -| self.req_min_before
                else if (narrowed_local)
                    hit.start -| self.req_min_before
                else
                    win_end;
                if (self.precomputed_dfa) |dfa| {
                    if (!self.anchored_start) {
                        var p = search_from;
                        while (p <= p_hi) : (p += 1) {
                            if (p < win_end and dfa.trans[dfa_mod.start_state][haystack[p]] == dfa_mod.dead_state) continue;
                            const p_win = if (self.multiline) self.windowLimit(haystack, p) else win_end;
                            if (dfa.matchPrefixDeterminized(haystack[p..p_win], dfa_mod.start_state, 0, !exact_for_mode and !ascii_exact_for_mode)) |match_len| {
                                if (exact_for_mode or (ascii_exact_for_mode and self.isAsciiExactMatch(haystack[p .. p + match_len]))) {
                                    return Match{ .start = p, .end = p + match_len, .pattern_id = null };
                                }
                                if (self.runRangeAllowed(haystack, p, p, p_win, mode, AllowAny{}, steps, scratch)) |m| {
                                    return m;
                                }
                            }
                        }
                        if (narrowed_local) {
                            pos = hit.start + self.req_prefix_shift;
                        } else if (!self.multiline) {
                            pos = @min(haystack.len + 1, win_end + 1);
                            min_start = pos;
                        } else {
                            pos = hit.start + 1;
                            min_start = hit.start + 1;
                        }
                        continue;
                    }
                }
                if (search_from <= p_hi) {
                    if (self.runRangeAllowed(haystack, search_from, p_hi, win_end, mode, AllowAny{}, steps, scratch)) |m| {
                        return m;
                    }
                }
                if (narrowed_local) {
                    pos = hit.start + self.req_prefix_shift;
                } else if (!self.multiline) {
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
            if (self.alt_is_exact) {
                if (self.alt_lcp_finder) |*lcp_f| {
                    var pos = start;
                    while (pos <= haystack.len) {
                        const hit = lcp_f.findReadOnly(haystack, pos, .earliest) orelse return null;
                        const slice_end = @min(haystack.len, hit.start +| self.alt_max_branch_len);
                        if (ap.find(haystack[hit.start..slice_end], 0, mode)) |m| {
                            if (m.start == 0) {
                                return Match{ .start = hit.start, .end = hit.start + m.end, .pattern_id = null };
                            }
                        }
                        pos = hit.start + 1;
                    }
                    return null;
                }
                if (ap.find(haystack, start, mode)) |m| {
                    return Match{ .start = m.start, .end = m.end, .pattern_id = null };
                }
                return null;
            }
            var pos = start;
            var min_start = start;
            var cached_win_end: usize = std.math.maxInt(usize);
            if (self.alt_is_prefix) {
                if (self.precomputed_dfa) |dfa| {
                    if (dfa.stops_on_crlf) {
                        var verifier = AltDfaVerifier(true, false, false){
                            .regex = self,
                            .dfa = dfa,
                            .full_haystack = haystack,
                            .mode = mode,
                            .steps = steps,
                            .scratch = scratch,
                        };
                        return switch (ap.findVerified(haystack, pos, .leftmost_first, &verifier)) {
                            .match => |vm| Match{ .start = vm.start, .end = vm.end, .pattern_id = null },
                            .none, .aborted => null,
                        };
                    }
                    var verifier = AltDfaVerifier(false, false, false){
                        .regex = self,
                        .dfa = dfa,
                        .full_haystack = haystack,
                        .mode = mode,
                        .steps = steps,
                        .scratch = scratch,
                    };
                    return switch (ap.findVerified(haystack, pos, .leftmost_first, &verifier)) {
                        .match => |vm| Match{ .start = vm.start, .end = vm.end, .pattern_id = null },
                        .none, .aborted => null,
                    };
                }
            }
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
                const p_hi = if (self.multiline) hit.start else win_end;
                if (search_from <= p_hi) {
                    if (self.runRangeAllowed(haystack, search_from, p_hi, win_end, mode, AllowAny{}, steps, scratch)) |m| {
                        return m;
                    }
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

        // General path: run two-phase Unanchored AOT DFA or Lazy DFA + PikeVM hybrid engine
        return self.runWithDfa(haystack, start, haystack.len, mode, steps, scratch);
    }

    fn runWithDfa(
        self: *const Regex,
        haystack: []const u8,
        start: usize,
        limit: usize,
        mode: MatchMode,
        steps: ?*usize,
        scratch: ?*RegexScratch,
    ) ?Match {
        if (self.insts.len == 0 or start > limit) return null;
        if (self.unanchored_dfa) |udfa| {
            var unused_nul: ?usize = null;
            return self.runUnanchoredDfa(udfa, haystack, start, limit, mode, steps, scratch, false, &unused_nul);
        }
        if (scratch) |sc| {
            if (sc.ensureDfa()) |heap_dfa| {
                return self.runWithDfaGeneric(HeapDfa, heap_dfa, haystack, start, limit, mode, steps, scratch);
            } else |_| {}
        }
        var stack_dfa = StackDfa.init();
        return self.runWithDfaGeneric(StackDfa, &stack_dfa, haystack, start, limit, mode, steps, scratch);
    }

    fn AltDfaVerifier(comptime stops_on_crlf: bool, comptime watch_abort: bool, comptime bounded_cand: bool) type {
        return struct {
            regex: *const Regex,
            dfa: *const HeapDfa,
            full_haystack: []const u8,
            mode: MatchMode,
            steps: ?*usize,
            scratch: ?*RegexScratch,
            cached_win_start: usize = std.math.maxInt(usize),
            cached_win_end: usize = std.math.maxInt(usize),
            cand_limit: usize = std.math.maxInt(usize),
            orig_start: usize = 0,
            rejects: usize = 0,

            pub inline fn verify(self: *@This(), _: []const u8, pat_start: usize, pat_end: usize, pat_id: usize) multi_mod.VerifyResult {
                if (comptime bounded_cand) {
                    if (pat_start >= self.cand_limit) return .reject;
                }
                const haystack = self.full_haystack;
                const can_skip = pat_id < 32 and self.regex.alt_dfa_prefix_len[pat_id] != 0 and (pat_end - pat_start) == self.regex.alt_dfa_prefix_len[pat_id];
                const s0: u16 = if (can_skip) self.regex.alt_dfa_prefix_state[pat_id] else dfa_mod.start_state;
                const p0: usize = if (can_skip) self.regex.alt_dfa_prefix_len[pat_id] else 0;
                if (comptime stops_on_crlf) {
                    if (self.dfa.matchPrefixDeterminized(haystack[pat_start..], s0, p0, true) != null) {
                        const win_end = if (!self.regex.multiline and self.cached_win_end != std.math.maxInt(usize) and
                            pat_start >= self.cached_win_start and pat_start <= self.cached_win_end)
                            self.cached_win_end
                        else blk: {
                            const w = self.regex.windowLimit(haystack, pat_start);
                            self.cached_win_start = pat_start;
                            self.cached_win_end = w;
                            break :blk w;
                        };
                        if (self.regex.runRangeAllowed(haystack, pat_start, pat_start, win_end, self.mode, AllowAny{}, self.steps, self.scratch)) |m| {
                            return .{ .accept = m.end };
                        }
                    }
                } else {
                    const win_end = if (!self.regex.multiline and self.cached_win_end != std.math.maxInt(usize) and
                        pat_start >= self.cached_win_start and pat_start <= self.cached_win_end)
                        self.cached_win_end
                    else blk: {
                        const w = self.regex.windowLimit(haystack, pat_start);
                        self.cached_win_start = pat_start;
                        self.cached_win_end = w;
                        break :blk w;
                    };
                    if (self.dfa.matchPrefixDeterminized(haystack[pat_start..win_end], s0, p0, true) != null) {
                        if (self.regex.runRangeAllowed(haystack, pat_start, pat_start, win_end, self.mode, AllowAny{}, self.steps, self.scratch)) |m| {
                            return .{ .accept = m.end };
                        }
                    }
                }
                if (comptime watch_abort) {
                    self.rejects += 1;
                    if (self.rejects >= 16 and pat_start <= self.orig_start + 32 * 1024 and haystack.len - pat_start >= 64 * 1024) {
                        return .abort;
                    }
                }
                return .reject;
            }
        };
    }

    fn scanUnanchoredChunk(
        comptime TableT: type,
        comptime skip_tag: dfa_mod.StartSkipTag,
        comptime track_active: bool,
        dfa: *const UnanchoredDfa,
        trans: [*]const TableT,
        haystack: []const u8,
        pos_ptr: *usize,
        chunk_limit: usize,
        state_ptr: *u16,
        active_since_ptr: *usize,
        local_steps: *usize,
    ) void {
        const classes = &dfa.classes;
        const start_max = dfa.start_max_off;
        const match_start = dfa.match_start_off;
        const vecs = UnanchoredDfa.initSkipVecs(skip_tag, dfa.start_skip);

        var pos = pos_ptr.*;
        var s = state_ptr.*;
        var active_since = active_since_ptr.*;

        while (pos < chunk_limit) {
            if (s <= start_max) {
                var sc: usize = 0;
                while (sc < 4 and pos < chunk_limit) : (sc += 1) {
                    const ns: u16 = trans[s + classes[haystack[pos]]];
                    if (comptime builtin.is_test) local_steps.* += 1;
                    if (ns > start_max) {
                        if (comptime track_active) active_since = pos;
                        s = ns;
                        pos += 1;
                        break;
                    }
                    s = ns;
                    pos += 1;
                }
                if (s >= match_start) break;
                if (s <= start_max) {
                    if (pos >= chunk_limit) break;
                    if (comptime skip_tag != .none) {
                        if (chunk_limit - pos >= memchr.native_width) {
                            if (UnanchoredDfa.skipStartVec(skip_tag, vecs, haystack, pos, chunk_limit)) |next_pos| {
                                if (comptime builtin.is_test) local_steps.* += next_pos - pos;
                                if (next_pos > pos) {
                                    s = dfa.startStateForByte(haystack[next_pos - 1]);
                                    pos = next_pos;
                                }
                                const ns: u16 = trans[s + classes[haystack[pos]]];
                                if (comptime builtin.is_test) local_steps.* += 1;
                                if (ns > start_max) {
                                    if (comptime track_active) active_since = pos;
                                }
                                s = ns;
                                pos += 1;
                                if (s >= match_start) break;
                                if (s <= start_max) continue;
                            } else {
                                if (comptime builtin.is_test) local_steps.* += chunk_limit - pos;
                                if (chunk_limit > pos) {
                                    s = dfa.startStateForByte(haystack[chunk_limit - 1]);
                                    pos = chunk_limit;
                                }
                                break;
                            }
                        } else {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
            }

            // Active non-start state: 4x unrolled compact ByteClasses + pre-scaled table DFA loop
            while (pos + 4 <= chunk_limit) {
                const s1: u16 = trans[s + classes[haystack[pos]]];
                if (s1 >= match_start) {
                    if (comptime builtin.is_test) local_steps.* += 1;
                    s = s1;
                    pos += 1;
                    break;
                }
                if (comptime track_active) {
                    if (s1 <= start_max) active_since = pos + 1;
                }
                const s2: u16 = trans[s1 + classes[haystack[pos + 1]]];
                if (s2 >= match_start) {
                    if (comptime builtin.is_test) local_steps.* += 2;
                    s = s2;
                    pos += 2;
                    break;
                }
                if (comptime track_active) {
                    if (s2 <= start_max) active_since = pos + 2;
                }
                const s3: u16 = trans[s2 + classes[haystack[pos + 2]]];
                if (s3 >= match_start) {
                    if (comptime builtin.is_test) local_steps.* += 3;
                    s = s3;
                    pos += 3;
                    break;
                }
                if (comptime track_active) {
                    if (s3 <= start_max) active_since = pos + 3;
                }
                const s4: u16 = trans[s3 + classes[haystack[pos + 3]]];
                if (comptime builtin.is_test) local_steps.* += 4;
                s = s4;
                pos += 4;
                if (comptime track_active) {
                    if (s <= start_max) active_since = pos;
                }
                if (s >= match_start or s <= start_max) break;
            }
            if (s >= match_start) break;
            if (s <= start_max) continue;

            while (pos < chunk_limit) {
                s = trans[s + classes[haystack[pos]]];
                if (comptime builtin.is_test) local_steps.* += 1;
                pos += 1;
                if (s >= match_start) break;
                if (s <= start_max) {
                    if (comptime track_active) active_since = pos;
                    break;
                }
            }
            if (s >= match_start) break;
        }

        pos_ptr.* = pos;
        state_ptr.* = s;
        active_since_ptr.* = active_since;
    }

    inline fn dispatchScanUnanchored(
        comptime track_active: bool,
        dfa: *const UnanchoredDfa,
        haystack: []const u8,
        pos_ptr: *usize,
        chunk_limit: usize,
        state_ptr: *u16,
        active_since_ptr: *usize,
        local_steps: *usize,
    ) void {
        if (dfa.use_u8) {
            const trans: [*]const u8 = &dfa.trans_u8;
            switch (dfa.start_skip) {
                inline else => |_, tag| scanUnanchoredChunk(u8, tag, track_active, dfa, trans, haystack, pos_ptr, chunk_limit, state_ptr, active_since_ptr, local_steps),
            }
        } else {
            const trans: [*]const u16 = dfa.trans_u16.ptr;
            switch (dfa.start_skip) {
                inline else => |_, tag| scanUnanchoredChunk(u16, tag, track_active, dfa, trans, haystack, pos_ptr, chunk_limit, state_ptr, active_since_ptr, local_steps),
            }
        }
    }

    fn runUnanchoredDfaEnd(
        self: *const Regex,
        dfa: *const UnanchoredDfa,
        haystack: []const u8,
        start: usize,
        limit: usize,
        steps: ?*usize,
        comptime watch_nul: bool,
        nul: *?usize,
    ) ?usize {
        if (start > limit) return null;
        const match_start = dfa.match_start_off;

        var scan_limit: usize = limit;
        var nul_checked_to: usize = start;
        var nul_found: ?usize = null;

        var pos: usize = start;
        var search_floor: usize = start;
        var unused_active: usize = start;
        var s: u16 = dfa.startStateAt(haystack, start);
        var cached_win_end: usize = std.math.maxInt(usize);
        var cached_line_start: usize = start;

        var local_steps: usize = 0;
        defer if (comptime builtin.is_test) {
            if (steps) |st| {
                if (local_steps > 0) _ = @atomicRmw(usize, st, .Add, local_steps, .monotonic);
            }
        };

        while (pos < scan_limit) {
            if (watch_nul and pos >= nul_checked_to) {
                const check_end = @min(scan_limit, pos + 32768);
                if (memchr.find(memchr.native_width, haystack[0..check_end], pos, 0)) |z| {
                    nul_found = z;
                    scan_limit = z;
                    nul_checked_to = z;
                    if (pos >= scan_limit) break;
                } else {
                    nul_checked_to = check_end;
                }
            }
            const chunk_limit = if (watch_nul) @min(scan_limit, nul_checked_to) else scan_limit;

            dispatchScanUnanchored(false, dfa, haystack, &pos, chunk_limit, &s, &unused_active, &local_steps);

            if (s < match_start) continue;

            // Exact match fast path: 0 PikeVM calls, 0 windowLimit, 0 lineStartAt!
            if (s == dfa.exact_del_off) return pos - 1;
            if (s == dfa.exact_imm_off) return pos;

            // Rare verify_match fallback (non-ASCII / ambiguous `\b` candidate)
            const cand_end: usize = if (s == dfa.verify_del_off) pos - 1 else pos;
            const probe_pos: usize = if (cand_end > 0) cand_end - 1 else 0;
            if (cached_win_end == std.math.maxInt(usize) or probe_pos > cached_win_end) {
                cached_win_end = self.windowLimit(haystack, probe_pos);
                cached_line_start = @max(search_floor, lineStartAt(haystack, probe_pos));
            }
            var win_end = @min(scan_limit, cached_win_end);
            if (watch_nul and win_end > nul_checked_to) {
                if (memchr.find(memchr.native_width, haystack[0..win_end], nul_checked_to, 0)) |z| {
                    nul_found = z;
                    scan_limit = z;
                    win_end = z;
                    nul_checked_to = z;
                } else {
                    nul_checked_to = win_end;
                }
            }
            const line_start = @max(search_floor, cached_line_start);
            const start_hi = if (cand_end > 0) cand_end - 1 else 0;
            if (cand_end > 0 and line_start <= start_hi) {
                if (self.runRangeAllowed(haystack, line_start, start_hi, win_end, .earliest, AllowAny{}, steps, null)) |m| {
                    return m.end;
                }
            }
            search_floor = cand_end;
            pos = cand_end;
            s = dfa.startStateAt(haystack, cand_end);
        }

        // End-of-input (EOF / NUL-limit) pending `\b`/`\B` check
        if (s < match_start and pos > search_floor) {
            const eoi = dfa.eoi_kind[@intCast(s / dfa.stride)];
            if (eoi == .exact) return pos;
            if (eoi == .verify) {
                const probe_pos = pos - 1;
                const line_start = @max(search_floor, lineStartAt(haystack, probe_pos));
                if (line_start <= probe_pos) {
                    if (self.runRangeAllowed(haystack, line_start, probe_pos, pos, .earliest, AllowAny{}, steps, null)) |m| {
                        return m.end;
                    }
                }
            }
        }

        if (watch_nul) {
            if (nul_found) |z| {
                nul.* = z;
            }
        }
        return null;
    }

    fn runUnanchoredDfa(
        self: *const Regex,
        dfa: *const UnanchoredDfa,
        haystack: []const u8,
        start: usize,
        limit: usize,
        mode: MatchMode,
        steps: ?*usize,
        scratch: ?*RegexScratch,
        comptime watch_nul: bool,
        nul: *?usize,
    ) ?Match {
        if (start > limit) return null;
        const match_start = dfa.match_start_off;

        var scan_limit: usize = limit;
        var nul_checked_to: usize = start;
        var nul_found: ?usize = null;

        var pos: usize = start;
        var search_floor: usize = start;
        var active_since: usize = start;
        var s: u16 = dfa.startStateAt(haystack, start);
        var cached_win_end: usize = std.math.maxInt(usize);
        var cached_line_start: usize = start;

        var local_steps: usize = 0;
        defer if (comptime builtin.is_test) {
            if (steps) |st| {
                if (local_steps > 0) _ = @atomicRmw(usize, st, .Add, local_steps, .monotonic);
            }
        };

        while (pos < scan_limit) {
            if (watch_nul and pos >= nul_checked_to) {
                const check_end = @min(scan_limit, pos + 32768);
                if (memchr.find(memchr.native_width, haystack[0..check_end], pos, 0)) |z| {
                    nul_found = z;
                    scan_limit = z;
                    nul_checked_to = z;
                    if (pos >= scan_limit) break;
                } else {
                    nul_checked_to = check_end;
                }
            }
            const chunk_limit = if (watch_nul) @min(scan_limit, nul_checked_to) else scan_limit;

            dispatchScanUnanchored(true, dfa, haystack, &pos, chunk_limit, &s, &active_since, &local_steps);

            if (s < match_start) continue;

            const is_delayed = (s == dfa.verify_del_off or s == dfa.exact_del_off);
            const cand_end: usize = if (is_delayed) pos - 1 else pos;
            const probe_pos: usize = if (cand_end > 0) cand_end - 1 else 0;

            // Phase-2 exact PikeVM start/end recovery on candidate ending at `cand_end`
            if (!self.multiline) {
                if (cached_win_end == std.math.maxInt(usize) or probe_pos > cached_win_end) {
                    cached_win_end = self.windowLimit(haystack, probe_pos);
                    cached_line_start = @max(search_floor, lineStartAt(haystack, probe_pos));
                }
                var win_end = @min(scan_limit, cached_win_end);
                if (watch_nul and win_end > nul_checked_to) {
                    if (memchr.find(memchr.native_width, haystack[0..win_end], nul_checked_to, 0)) |z| {
                        nul_found = z;
                        scan_limit = z;
                        win_end = z;
                        nul_checked_to = z;
                    } else {
                        nul_checked_to = win_end;
                    }
                }
                const line_start = @max(search_floor, cached_line_start);

                if (dfa.start_reentrant) {
                    if (self.runRangeAllowed(haystack, line_start, win_end, win_end, mode, AllowAny{}, steps, scratch)) |m| {
                        return m;
                    }
                    if (win_end >= scan_limit) {
                        pos = scan_limit;
                        break;
                    }
                    pos = win_end + 1;
                    if (watch_nul and pos > nul_checked_to) nul_checked_to = pos;
                    search_floor = pos;
                    active_since = pos;
                    s = dfa.startStateAt(haystack, pos);
                    continue;
                }

                const search_lo = @max(line_start, active_since);
                const start_hi = probe_pos;
                if (cand_end > 0 and search_lo <= start_hi) {
                    if (self.runRangeAllowed(haystack, search_lo, start_hi, win_end, mode, AllowAny{}, steps, scratch)) |m| {
                        if (mode == .earliest and m.end > cand_end + 1) {
                            const earlier_lim = @min(m.end, win_end);
                            if (cand_end < earlier_lim) {
                                if (self.runRangeAllowed(haystack, cand_end, earlier_lim, earlier_lim, .earliest, AllowAny{}, steps, scratch)) |m2| {
                                    if (m2.end < m.end or (m2.end == m.end and m2.start < m.start)) {
                                        return m2;
                                    }
                                }
                            }
                        }
                        return m;
                    }
                }
                search_floor = cand_end;
                active_since = cand_end;
                pos = cand_end;
                s = dfa.startStateAt(haystack, cand_end);
            } else {
                const search_lo = blk: {
                    var lo = @max(search_floor, cand_end -| self.max_multiline_window);
                    if (!dfa.start_reentrant) lo = @max(lo, active_since);
                    break :blk lo;
                };
                const raw_verify_limit = @min(scan_limit, probe_pos +| self.max_multiline_window);
                if (watch_nul and raw_verify_limit > nul_checked_to) {
                    if (memchr.find(memchr.native_width, haystack[0..raw_verify_limit], nul_checked_to, 0)) |z| {
                        nul_found = z;
                        scan_limit = z;
                        nul_checked_to = z;
                    } else {
                        nul_checked_to = raw_verify_limit;
                    }
                }
                const eff_verify_limit = @min(raw_verify_limit, scan_limit);
                const start_hi = probe_pos;
                if (cand_end > 0 and search_lo <= start_hi) {
                    if (self.runRangeAllowed(haystack, search_lo, start_hi, eff_verify_limit, mode, AllowAny{}, steps, scratch)) |m| {
                        if (mode == .earliest and m.end > cand_end + 1) {
                            const earlier_lim = @min(m.end, eff_verify_limit);
                            if (cand_end < earlier_lim) {
                                if (self.runRangeAllowed(haystack, cand_end, earlier_lim, earlier_lim, .earliest, AllowAny{}, steps, scratch)) |m2| {
                                    if (m2.end < m.end or (m2.end == m.end and m2.start < m.start)) {
                                        return m2;
                                    }
                                }
                            }
                        }
                        return m;
                    }
                }
                search_floor = cand_end;
                active_since = cand_end;
                pos = cand_end;
                s = dfa.startStateAt(haystack, cand_end);
            }
        }

        // End-of-input (EOF / NUL-limit) pending `\b`/`\B` check
        if (s < match_start and pos > search_floor) {
            const eoi = dfa.eoi_kind[@intCast(s / dfa.stride)];
            if (eoi != .none) {
                const probe_pos = pos - 1;
                const line_start = @max(search_floor, lineStartAt(haystack, probe_pos));
                const search_lo = if (dfa.start_reentrant) line_start else @max(line_start, active_since);
                if (search_lo <= probe_pos) {
                    if (self.runRangeAllowed(haystack, search_lo, probe_pos, pos, mode, AllowAny{}, steps, scratch)) |m| {
                        return m;
                    }
                }
            }
        }

        if (watch_nul) {
            if (nul_found) |z| {
                nul.* = z;
            }
        }
        return null;
    }

    fn runWithDfaGeneric(
        self: *const Regex,
        comptime DfaType: type,
        dfa: *DfaType,
        haystack: []const u8,
        start: usize,
        limit: usize,
        mode: MatchMode,
        steps: ?*usize,
        scratch: ?*RegexScratch,
    ) ?Match {
        if (!dfa.ensureInitialized(self.insts, self.start_pc, self.multiline, self.max_dfa_states)) {
            return self.runRangeAllowed(haystack, start, limit, limit, mode, AllowAny{}, steps, scratch);
        }

        // If the start state itself can accept zero bytes (e.g., `a*`, `^`, `$`, `\b`), delegate to PikeVM
        if (dfa.is_match[dfa_mod.start_state]) {
            return self.runRangeAllowed(haystack, start, limit, limit, mode, AllowAny{}, steps, scratch);
        }

        var curr_state: u16 = dfa_mod.start_state;
        var active_since: usize = start;
        var pos: usize = start;
        var restarts: usize = 0;
        var local_steps: usize = 0;
        defer if (comptime builtin.is_test) {
            if (steps) |s| {
                if (local_steps > 0) _ = @atomicRmw(usize, s, .Add, local_steps, .monotonic);
            }
        };

        while (pos < limit) {
            if (self.anchored_start and active_since > 0) break;

            if (self.multiline and curr_state != dfa_mod.start_state and (pos - active_since >= self.max_multiline_window)) {
                const win_end = @min(limit, active_since +| self.max_multiline_window);
                if (self.runRangeAllowed(haystack, active_since, active_since, win_end, mode, AllowAny{}, steps, scratch)) |m| {
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
                return self.runRangeAllowed(haystack, active_since, limit, limit, mode, AllowAny{}, steps, scratch);
            }

            if (next_state == dfa_mod.dead_state) {
                if (curr_state == dfa_mod.start_state) {
                    pos += 1;
                    active_since = pos;
                } else {
                    restarts += 1;
                    if (restarts >= 8 and pos > active_since + 1) {
                        const win_end = @min(limit, self.windowLimit(haystack, pos));
                        if (self.runRangeAllowed(haystack, active_since, pos, win_end, mode, AllowAny{}, steps, scratch)) |m| {
                            return m;
                        }
                        pos += 1;
                        active_since = pos;
                        curr_state = dfa_mod.start_state;
                        restarts = 0;
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

            if (dfa.is_match[curr_state]) {
                const win_end = @min(limit, self.windowLimit(haystack, active_since));
                if (self.runRangeAllowed(haystack, active_since, active_since, win_end, mode, AllowAny{}, steps, scratch)) |m| {
                    return m;
                }
                pos = active_since + 1;
                active_since = pos;
                curr_state = dfa_mod.start_state;
            }
        }

        return null;
    }

    inline fn checkWatchedMatch(haystack: []const u8, checked_to: usize, m: Match, nul: *?usize) ?Match {
        const end_check = @min(haystack.len, @max(checked_to, m.end));
        if (checked_to < end_check) {
            if (memchr.find(memchr.native_width, haystack[0..end_check], checked_to, 0)) |at| {
                nul.* = at;
                return null;
            }
        }
        return m;
    }

    fn findWatchedWordBoundedChunked(
        self: *const Regex,
        pf: *const Finder,
        haystack: []const u8,
        start_pos: usize,
        nul: *?usize,
    ) ?Match {
        var scan_pos = start_pos;
        var chunk_size: usize = 64 * 1024;
        const max_chunk_size: usize = 256 * 1024;
        const max_lit_len = if (self.ignore_case and self.unicode_case) self.req_literal_bytes.len *| 3 else self.req_literal_bytes.len;
        const overlap = max_lit_len -| 1;

        while (scan_pos <= haystack.len) {
            const chunk_end = @min(haystack.len, scan_pos +| chunk_size);
            const nul_in_chunk = memchr.find(memchr.native_width, haystack[0..chunk_end], scan_pos, 0);
            const has_nul = nul_in_chunk != null;
            const eff_end = nul_in_chunk orelse chunk_end;
            const prefilter_end = if (has_nul) eff_end else @min(haystack.len, eff_end +| overlap);
            const pf_slice = haystack[0..prefilter_end];

            var pos = scan_pos;
            const wb_kind: AssertKind = if (self.req_word_bounded_ascii) .ascii_word_boundary else .word_boundary;
            while (pos < eff_end) {
                const hit = pf.findReadOnly(pf_slice, pos, .earliest) orelse break;
                if (hit.start >= eff_end) break;
                if (checkAssert(wb_kind, haystack, hit.start) and checkAssert(wb_kind, haystack, hit.end)) {
                    if (has_nul) {
                        if (hit.end <= eff_end) return hit;
                        nul.* = eff_end;
                        return null;
                    }
                    return checkWatchedMatch(haystack, eff_end, hit, nul);
                }
                pos = hit.start + self.req_prefix_shift;
            }
            if (has_nul) {
                nul.* = eff_end;
                return null;
            }
            if (eff_end >= haystack.len) return null;
            scan_pos = eff_end;
            chunk_size = @min(max_chunk_size, chunk_size * 2);
        }
        return null;
    }

    fn findWatchedPrefixChainChunked(
        pf: *const Finder,
        haystack: []const u8,
        start_pos: usize,
        p0: usize,
        clen: usize,
        u_lo: u8,
        u_sp: u8,
        shift: usize,
        nul: *?usize,
    ) ?Match {
        var scan_pos = start_pos;
        var chunk_size: usize = 64 * 1024;
        const max_chunk_size: usize = 256 * 1024;
        const overlap = p0 -| 1;

        while (scan_pos <= haystack.len) {
            const chunk_end = @min(haystack.len, scan_pos +| chunk_size);
            const nul_in_chunk = memchr.find(memchr.native_width, haystack[0..chunk_end], scan_pos, 0);
            const has_nul = nul_in_chunk != null;
            const eff_end = nul_in_chunk orelse chunk_end;
            const prefilter_end = if (has_nul) eff_end else @min(haystack.len, eff_end +| overlap);
            const pf_slice = haystack[0..prefilter_end];

            var pos = scan_pos;
            while (pos < eff_end) {
                const hit = pf.findReadOnly(pf_slice, pos, .earliest) orelse break;
                if (hit.start >= eff_end) break;
                const rem_start = hit.start + p0;
                if (rem_start + clen <= haystack.len) {
                    const p = haystack[rem_start..][0..clen];
                    if ((p[clen - 1] -% u_lo) <= u_sp) {
                        var ok = true;
                        for (p[0 .. clen - 1]) |ch| {
                            if ((ch -% u_lo) > u_sp) {
                                ok = false;
                                break;
                            }
                        }
                        if (ok) {
                            const m = Match{ .start = hit.start, .end = rem_start + clen, .pattern_id = null };
                            if (has_nul) {
                                if (m.end <= eff_end) return m;
                                nul.* = eff_end;
                                return null;
                            }
                            return checkWatchedMatch(haystack, eff_end, m, nul);
                        }
                    }
                }
                pos = hit.start + shift;
            }
            if (has_nul) {
                nul.* = eff_end;
                return null;
            }
            if (eff_end >= haystack.len) return null;
            scan_pos = eff_end;
            chunk_size = @min(max_chunk_size, chunk_size * 2);
        }
        return null;
    }

    fn findWatchedPrefixChunked(
        self: *const Regex,
        pf: *const Finder,
        haystack: []const u8,
        start_pos: usize,
        nul: *?usize,
    ) ?Match {
        var scan_pos = start_pos;
        var chunk_size: usize = 64 * 1024;
        const max_chunk_size: usize = 256 * 1024;
        const max_lit_len = if (self.ignore_case and self.unicode_case) self.req_literal_bytes.len *| 3 else self.req_literal_bytes.len;
        const overlap = max_lit_len -| 1;
        const exact_for_mode = self.dfa_is_exact and !self.has_alt;
        const ascii_exact_for_mode = (self.dfa_exact_on_ascii or self.dfa_exact_on_ascii_any) and !self.has_alt;
        const can_jump_tail = !self.ignore_case or !self.unicode_case;
        var cached_win_end: usize = std.math.maxInt(usize);
        var next_tail: ?Match = null;

        while (scan_pos <= haystack.len) {
            const chunk_end = @min(haystack.len, scan_pos +| chunk_size);
            const nul_in_chunk = memchr.find(memchr.native_width, haystack[0..chunk_end], scan_pos, 0);
            const has_nul = nul_in_chunk != null;
            const eff_end = nul_in_chunk orelse chunk_end;
            const prefilter_end = if (has_nul) eff_end else @min(haystack.len, eff_end +| overlap);
            const pf_slice = haystack[0..prefilter_end];

            var pos = scan_pos;
            if (self.precomputed_dfa) |dfa| {
                if (exact_for_mode and dfa.stops_on_crlf) {
                    const fixed_prefix = self.dfa_prefix_len > 0 and self.dfa_prefix_len == self.req_literal_bytes.len and (!self.ignore_case or !self.unicode_case);
                    while (pos < eff_end) {
                        const hit = pf.findReadOnly(pf_slice, pos, .earliest) orelse break;
                        if (hit.start >= eff_end) break;
                        const can_skip = fixed_prefix or (hit.end - hit.start == self.dfa_prefix_len);
                        const s0: u16 = if (can_skip) self.dfa_prefix_state else dfa_mod.start_state;
                        const p0: usize = if (can_skip) self.dfa_prefix_len else 0;
                        if (dfa.matchPrefixDeterminized(haystack[hit.start..], s0, p0, false)) |match_len| {
                            const m = Match{ .start = hit.start, .end = hit.start + match_len, .pattern_id = null };
                            if (has_nul) {
                                if (m.end <= eff_end) return m;
                                nul.* = eff_end;
                                return null;
                            }
                            return checkWatchedMatch(haystack, eff_end, m, nul);
                        }
                        pos = hit.start + self.req_prefix_shift;
                    }
                } else {
                    while (pos < eff_end) {
                        const hit = pf.findReadOnly(pf_slice, pos, .earliest) orelse break;
                        if (hit.start >= eff_end) break;
                        const can_skip = (hit.end - hit.start == self.dfa_prefix_len);
                        const s0: u16 = if (can_skip) self.dfa_prefix_state else dfa_mod.start_state;
                        const p0: usize = if (can_skip) self.dfa_prefix_len else 0;
                        const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                            cached_win_end
                        else blk: {
                            const w = self.windowLimit(haystack, hit.start);
                            cached_win_end = w;
                            break :blk w;
                        };
                        if (self.tail_finder) |*tf| {
                            if (next_tail == null or next_tail.?.start < hit.end) {
                                next_tail = tf.findReadOnly(haystack, hit.end, .earliest) orelse {
                                    if (has_nul) {
                                        nul.* = eff_end;
                                        return null;
                                    }
                                    if (eff_end < haystack.len) {
                                        if (memchr.find(memchr.native_width, haystack, eff_end, 0)) |z| nul.* = z;
                                    }
                                    return null;
                                };
                            }
                            if (next_tail.?.end > win_end) {
                                if (!self.multiline) {
                                    const nl_next = @min(haystack.len + 1, win_end + 1);
                                    pos = if (can_jump_tail) @max(nl_next, lineStartAt(haystack, next_tail.?.start)) else nl_next;
                                } else {
                                    pos = if (can_jump_tail)
                                        @max(hit.start + self.req_prefix_shift, next_tail.?.end -| self.max_multiline_window)
                                    else
                                        hit.start + self.req_prefix_shift;
                                }
                                continue;
                            }
                        }
                        if (dfa.matchPrefixDeterminized(haystack[hit.start..win_end], s0, p0, !exact_for_mode and !ascii_exact_for_mode)) |match_len| {
                            const m_opt = if (exact_for_mode or (ascii_exact_for_mode and self.isAsciiExactMatch(haystack[hit.start .. hit.start + match_len])))
                                Match{ .start = hit.start, .end = hit.start + match_len, .pattern_id = null }
                            else
                                self.runRangeAllowed(haystack, hit.start, hit.start, win_end, .earliest, AllowAny{}, null, null);
                            if (m_opt) |m| {
                                if (has_nul) {
                                    if (m.end <= eff_end) return m;
                                    nul.* = eff_end;
                                    return null;
                                }
                                return checkWatchedMatch(haystack, eff_end, m, nul);
                            }
                        }
                        pos = hit.start + self.req_prefix_shift;
                    }
                }
            } else {
                while (pos < eff_end) {
                    const hit = pf.findReadOnly(pf_slice, pos, .earliest) orelse break;
                    if (hit.start >= eff_end) break;
                    const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                        cached_win_end
                    else blk: {
                        const w = self.windowLimit(haystack, hit.start);
                        cached_win_end = w;
                        break :blk w;
                    };
                    if (self.tail_finder) |*tf| {
                        if (next_tail == null or next_tail.?.start < hit.end) {
                            next_tail = tf.findReadOnly(haystack, hit.end, .earliest) orelse {
                                if (has_nul) {
                                    nul.* = eff_end;
                                    return null;
                                }
                                if (eff_end < haystack.len) {
                                    if (memchr.find(memchr.native_width, haystack, eff_end, 0)) |z| nul.* = z;
                                }
                                return null;
                            };
                        }
                        if (next_tail.?.end > win_end) {
                            if (!self.multiline) {
                                const nl_next = @min(haystack.len + 1, win_end + 1);
                                pos = if (can_jump_tail) @max(nl_next, lineStartAt(haystack, next_tail.?.start)) else nl_next;
                            } else {
                                pos = if (can_jump_tail)
                                    @max(hit.start + self.req_prefix_shift, next_tail.?.end -| self.max_multiline_window)
                                else
                                    hit.start + 1;
                            }
                            continue;
                        }
                    }
                    const p_hi = if (self.multiline) hit.start else win_end;
                    if (self.runRangeAllowed(haystack, hit.start, p_hi, win_end, .earliest, AllowAny{}, null, null)) |m| {
                        if (has_nul) {
                            if (m.end <= eff_end) return m;
                            nul.* = eff_end;
                            return null;
                        }
                        return checkWatchedMatch(haystack, eff_end, m, nul);
                    }
                    pos = if (!self.multiline) @min(haystack.len + 1, win_end + 1) else hit.start + 1;
                }
            }
            if (has_nul) {
                nul.* = eff_end;
                return null;
            }
            if (eff_end >= haystack.len) return null;
            scan_pos = eff_end;
            chunk_size = @min(max_chunk_size, chunk_size * 2);
        }
        return null;
    }

    fn findWatchedInteriorChunked(
        self: *const Regex,
        pf: *const Finder,
        haystack: []const u8,
        start_pos: usize,
        start_min_start: usize,
        nul: *?usize,
    ) ?Match {
        var scan_pos = start_pos;
        var min_start = start_min_start;
        var chunk_size: usize = 64 * 1024;
        const max_chunk_size: usize = 256 * 1024;
        const max_lit_len = if (self.ignore_case and self.unicode_case) self.req_literal_bytes.len *| 3 else self.req_literal_bytes.len;
        const overlap = (max_lit_len -| 1) + @as(usize, if (self.byte_ctx_prefilter != null) 1 else 0);
        const exact_for_mode = self.dfa_is_exact and !self.has_alt;
        const ascii_exact_for_mode = (self.dfa_exact_on_ascii or self.dfa_exact_on_ascii_any) and !self.has_alt;
        var cached_win_end: usize = std.math.maxInt(usize);

        while (scan_pos <= haystack.len) {
            const chunk_end = @min(haystack.len, scan_pos +| chunk_size);
            const nul_in_chunk = memchr.find(memchr.native_width, haystack[0..chunk_end], scan_pos, 0);
            const has_nul = nul_in_chunk != null;
            const eff_end = nul_in_chunk orelse chunk_end;
            const prefilter_end = if (has_nul) eff_end else @min(haystack.len, eff_end +| overlap);
            const pf_slice = haystack[0..prefilter_end];

            var pos = scan_pos;
            while (pos < eff_end) {
                const hit_opt: ?Match = if (self.pair_prefilter) |*pp| blk: {
                    const pf_pre: usize = self.pair_prefilter_prefix_len;
                    const pair_search_from = @max(pos, min_start + self.req_min_before) -| pf_pre;
                    if (pair_search_from >= prefilter_end) break :blk null;
                    const ph = pp.find(pf_slice, pair_search_from, .earliest) orelse break :blk null;
                    break :blk Match{ .start = ph.start + pf_pre, .end = ph.end, .pattern_id = null };
                } else if (self.byte_ctx_prefilter) |bcp| blk: {
                    const at = bcp.find(pf_slice, pos, min_start + self.req_min_before) orelse break :blk null;
                    break :blk Match{ .start = at, .end = at + 1, .pattern_id = null };
                } else pf.findReadOnly(pf_slice, pos, .earliest);
                const hit = hit_opt orelse break;

                if (hit.start >= eff_end) break;
                if (self.multiline and hit.end - hit.start > self.max_multiline_window) {
                    pos = hit.start + 1;
                    min_start = pos;
                    continue;
                }
                if (hit.start < min_start + self.req_min_before) {
                    pos = hit.start + self.req_prefix_shift;
                    continue;
                }
                if (self.req_has_prev_mask) {
                    if (!self.req_prev_masks[0].contains(haystack[hit.start - 1]) or
                        (self.req_prev_mask_len >= 2 and !self.req_prev_masks[1].contains(haystack[hit.start - 2])) or
                        (self.req_prev_mask_len >= 3 and !self.req_prev_masks[2].contains(haystack[hit.start - 3])))
                    {
                        pos = hit.start + self.req_prefix_shift;
                        continue;
                    }
                }
                if (self.req_prefix_uclass_pc != std.math.maxInt(u32) and self.dfa_suffix_is_exact) {
                    if (self.precomputed_dfa) |dfa| {
                        if (dfa.matchPrefixDeterminized(haystack[hit.end..], self.dfa_suffix_state, 0, false)) |suf_len| {
                            const uc = self.insts[self.req_prefix_uclass_pc].unicode_class;
                            const ranges = self.unicode_ranges[uc.range_idx].ranges;
                            if (matchPrefixUclassReverse(haystack, min_start, hit.start, uc, ranges, self.req_prefix_uclass_min)) |run_start| {
                                const m = Match{ .start = run_start, .end = hit.end + suf_len, .pattern_id = null };
                                if (has_nul) {
                                    if (m.end <= eff_end) return m;
                                    nul.* = eff_end;
                                    return null;
                                }
                                return checkWatchedMatch(haystack, eff_end, m, nul);
                            }
                        }
                        pos = hit.start + self.req_prefix_shift;
                        continue;
                    }
                }
                if (self.dfa_suffix_state != 0 and !self.multiline) {
                    if (self.precomputed_dfa) |dfa| {
                        if (dfa.matchPrefixDeterminized(haystack[hit.end..], self.dfa_suffix_state, 0, true) == null) {
                            pos = hit.start + self.req_prefix_shift;
                            continue;
                        }
                    }
                }
                const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                    cached_win_end
                else blk: {
                    const w = self.windowLimit(haystack, hit.start);
                    cached_win_end = w;
                    break :blk w;
                };
                if (self.tail_finder) |*tf| {
                    if (hit.end > win_end or tf.findReadOnly(haystack[0..win_end], hit.end, .earliest) == null) {
                        pos = if (!self.multiline) @min(haystack.len + 1, win_end + 1) else hit.start + 1;
                        min_start = pos;
                        continue;
                    }
                }
                const narrowed_local = !self.multiline and (self.req_max_before != null or self.req_has_prefix_bytes_mask);
                const search_from = blk: {
                    if (self.multiline) break :blk @max(min_start, hit.end -| self.max_multiline_window);
                    var lo = min_start;
                    if (self.req_max_before) |max_b| lo = @max(lo, hit.start -| max_b);
                    if (self.req_has_prefix_bytes_mask) {
                        var cur = hit.start;
                        while (cur > lo and self.req_prefix_bytes_mask.contains(haystack[cur - 1])) cur -= 1;
                        lo = cur;
                    }
                    if (self.req_max_before != null or self.req_has_prefix_bytes_mask) {
                        if (lo < hit.start and (!self.req_has_prefix_bytes_mask or self.req_prefix_bytes_mask.contains('\n'))) {
                            if (memchr.findLast(memchr.native_width, haystack, lo, hit.start, '\n')) |nl| lo = nl + 1;
                        }
                        break :blk lo;
                    }
                    break :blk @max(min_start, lineStartAt(haystack, hit.start));
                };
                const p_hi = if (self.multiline or narrowed_local) hit.start -| self.req_min_before else win_end;
                if (self.precomputed_dfa) |dfa| {
                    var p = search_from;
                    while (p <= p_hi) : (p += 1) {
                        if (p < win_end and dfa.trans[dfa_mod.start_state][haystack[p]] == dfa_mod.dead_state) continue;
                        const p_win = if (self.multiline) self.windowLimit(haystack, p) else win_end;
                        if (dfa.matchPrefixDeterminized(haystack[p..p_win], dfa_mod.start_state, 0, !exact_for_mode and !ascii_exact_for_mode)) |match_len| {
                            const m_opt = if (exact_for_mode or (ascii_exact_for_mode and self.isAsciiExactMatch(haystack[p .. p + match_len])))
                                Match{ .start = p, .end = p + match_len, .pattern_id = null }
                            else
                                self.runRangeAllowed(haystack, p, p, p_win, .earliest, AllowAny{}, null, null);
                            if (m_opt) |m| {
                                if (has_nul) {
                                    if (m.end <= eff_end) return m;
                                    nul.* = eff_end;
                                    return null;
                                }
                                return checkWatchedMatch(haystack, eff_end, m, nul);
                            }
                        }
                    }
                } else if (search_from <= p_hi) {
                    if (self.runRangeAllowed(haystack, search_from, p_hi, win_end, .earliest, AllowAny{}, null, null)) |m| {
                        if (has_nul) {
                            if (m.end <= eff_end) return m;
                            nul.* = eff_end;
                            return null;
                        }
                        return checkWatchedMatch(haystack, eff_end, m, nul);
                    }
                }
                pos = if (narrowed_local)
                    hit.start + self.req_prefix_shift
                else if (!self.multiline)
                    @min(haystack.len + 1, win_end + 1)
                else
                    hit.start + 1;
                if (!narrowed_local) min_start = @min(pos, eff_end);
            }
            if (has_nul) {
                nul.* = eff_end;
                return null;
            }
            if (eff_end >= haystack.len) return null;
            scan_pos = eff_end;
            chunk_size = @min(max_chunk_size, chunk_size * 2);
        }
        return null;
    }

    fn findWatchedAltDfaChunked(
        self: *const Regex,
        ap: *const Multi,
        dfa: *const HeapDfa,
        haystack: []const u8,
        start_pos: usize,
        max_ap_len: usize,
        nul: *?usize,
    ) ?Match {
        var scan_pos = start_pos;
        var chunk_size: usize = 64 * 1024;
        const max_chunk_size: usize = 256 * 1024;
        const overlap = max_ap_len -| 1;

        while (scan_pos <= haystack.len) {
            const chunk_end = @min(haystack.len, scan_pos +| chunk_size);
            const nul_in_chunk = memchr.find(memchr.native_width, haystack[0..chunk_end], scan_pos, 0);
            const has_nul = nul_in_chunk != null;
            const eff_end = nul_in_chunk orelse chunk_end;
            const prefilter_end = if (has_nul) eff_end else @min(haystack.len, eff_end +| overlap);

            const step = if (dfa.stops_on_crlf) blk: {
                var verifier = AltDfaVerifier(true, false, true){
                    .regex = self,
                    .dfa = dfa,
                    .full_haystack = haystack,
                    .mode = .earliest,
                    .steps = null,
                    .scratch = null,
                    .cand_limit = eff_end,
                };
                break :blk ap.findVerified(haystack[0..prefilter_end], scan_pos, .leftmost_first, &verifier);
            } else blk: {
                var verifier = AltDfaVerifier(false, false, true){
                    .regex = self,
                    .dfa = dfa,
                    .full_haystack = haystack,
                    .mode = .earliest,
                    .steps = null,
                    .scratch = null,
                    .cand_limit = eff_end,
                };
                break :blk ap.findVerified(haystack[0..prefilter_end], scan_pos, .leftmost_first, &verifier);
            };

            switch (step) {
                .match => |vm| {
                    const m = Match{ .start = vm.start, .end = vm.end, .pattern_id = null };
                    if (has_nul) {
                        if (m.end <= eff_end) return m;
                        nul.* = eff_end;
                        return null;
                    }
                    return checkWatchedMatch(haystack, eff_end, m, nul);
                },
                .none, .aborted => {
                    if (has_nul) {
                        nul.* = eff_end;
                        return null;
                    }
                    if (eff_end >= haystack.len) return null;
                    scan_pos = eff_end;
                    chunk_size = @min(max_chunk_size, chunk_size * 2);
                },
            }
        }
        return null;
    }

    fn findWatchedAltGeneralChunked(
        self: *const Regex,
        ap: *const Multi,
        haystack: []const u8,
        start_pos: usize,
        start_min_start: usize,
        max_ap_len: usize,
        nul: *?usize,
    ) ?Match {
        var scan_pos = start_pos;
        var min_start = start_min_start;
        var chunk_size: usize = 64 * 1024;
        const max_chunk_size: usize = 256 * 1024;
        const overlap = max_ap_len -| 1;
        var cached_win_end: usize = std.math.maxInt(usize);

        while (scan_pos <= haystack.len) {
            const chunk_end = @min(haystack.len, scan_pos +| chunk_size);
            const nul_in_chunk = memchr.find(memchr.native_width, haystack[0..chunk_end], scan_pos, 0);
            const has_nul = nul_in_chunk != null;
            const eff_end = nul_in_chunk orelse chunk_end;
            const prefilter_end = if (has_nul) eff_end else @min(haystack.len, eff_end +| overlap);
            const pf_slice = haystack[0..prefilter_end];

            var pos = scan_pos;
            while (pos < eff_end) {
                const hit = ap.find(pf_slice, pos, .leftmost_first) orelse break;
                if (hit.start >= eff_end) break;
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
                const p_hi = if (self.multiline) hit.start else win_end;
                if (search_from <= p_hi) {
                    if (self.runRangeAllowed(haystack, search_from, p_hi, win_end, .earliest, AllowAny{}, null, null)) |m| {
                        if (has_nul) {
                            if (m.end <= eff_end) return m;
                            nul.* = eff_end;
                            return null;
                        }
                        return checkWatchedMatch(haystack, eff_end, m, nul);
                    }
                }
                pos = if (!self.multiline) @min(haystack.len + 1, win_end + 1) else hit.start + 1;
                min_start = @min(pos, eff_end);
            }
            if (has_nul) {
                nul.* = eff_end;
                return null;
            }
            if (eff_end >= haystack.len) return null;
            scan_pos = eff_end;
            chunk_size = @min(max_chunk_size, chunk_size * 2);
        }
        return null;
    }

    pub fn findWatched(self: *const Regex, haystack: []const u8, start: usize, nul: *?usize) ?Match {
        if (start > haystack.len) return null;
        if (!self.anchored_start) {
            if (self.req_is_exact) {
                if (self.prefilter) |*pf| {
                    return pf.findWatched(haystack, start, nul);
                }
            }
            if (self.req_word_bounded) {
                if (self.prefilter) |*pf| {
                    const wb_kind: AssertKind = if (self.req_word_bounded_ascii) .ascii_word_boundary else .word_boundary;
                    var pos = start;
                    var rejects: usize = 0;
                    while (pos <= haystack.len) {
                        const hit = pf.findWatched(haystack, pos, nul) orelse return null;
                        if (checkAssert(wb_kind, haystack, hit.start) and checkAssert(wb_kind, haystack, hit.end)) {
                            return hit;
                        }
                        const next_pos = hit.start + self.req_prefix_shift;
                        const check_to = @min(next_pos, haystack.len);
                        if (check_to > hit.end) {
                            if (memchr.find(memchr.native_width, haystack[0..check_to], hit.end, 0)) |at| {
                                nul.* = at;
                                return null;
                            }
                        }
                        pos = next_pos;
                        rejects += 1;
                        if (rejects >= 16 and pos <= start + 32 * 1024 and haystack.len -| pos >= 64 * 1024) {
                            return self.findWatchedWordBoundedChunked(pf, haystack, pos, nul);
                        }
                    }
                    return null;
                }
            }
            if (self.alt_is_exact) {
                if (self.alt_lcp_finder) |*lcp_f| {
                    if (self.alt_prefilter) |*ap| {
                        var pos = start;
                        while (pos <= haystack.len) {
                            const hit = lcp_f.findWatched(haystack, pos, nul) orelse return null;
                            const slice_end = @min(haystack.len, hit.start +| self.alt_max_branch_len);
                            if (ap.find(haystack[hit.start..slice_end], 0, .leftmost_first)) |m| {
                                if (m.start == 0) {
                                    return checkWatchedMatch(haystack, hit.end, Match{
                                        .start = hit.start,
                                        .end = hit.start + m.end,
                                        .pattern_id = null,
                                    }, nul);
                                }
                            }
                            pos = hit.start + 1;
                        }
                        return null;
                    }
                }
                if (self.alt_prefilter) |*ap| {
                    if (ap.findWatched(haystack, start, nul)) |m| {
                        return Match{ .start = m.start, .end = m.end, .pattern_id = null };
                    }
                    return null;
                }
            }
            if (self.req_is_prefix) {
                if (self.prefilter) |*pf| {
                    if (self.prefix_any_tail) |pat| {
                        if (self.tail_finder) |*tf| {
                            return self.findPrefixAnyTail(pat, pf, tf, haystack, start, .earliest, true, nul);
                        }
                    }
                    var pos = start;
                    var rejects: usize = 0;
                    const exact_for_mode = self.dfa_is_exact and !self.has_alt;
                    const ascii_exact_for_mode = (self.dfa_exact_on_ascii or self.dfa_exact_on_ascii_any) and !self.has_alt;
                    const can_jump_tail = !self.ignore_case or !self.unicode_case;
                    if (self.precomputed_dfa) |dfa| {
                        if (exact_for_mode and dfa.stops_on_crlf) {
                            const fixed_prefix = self.dfa_prefix_len > 0 and self.dfa_prefix_len == self.req_literal_bytes.len and (!self.ignore_case or !self.unicode_case);
                            if (fixed_prefix) {
                                const s0 = self.dfa_prefix_state;
                                const p0 = self.dfa_prefix_len;
                                const shift = self.req_prefix_shift;
                                const clen: usize = dfa.chain_len[s0];
                                if (clen >= 2 and dfa.chain_uniform_span[s0] != 0xFF and dfa.is_terminal[s0 + clen]) {
                                    const u_lo = dfa.chain_uniform_lo[s0];
                                    const u_sp = dfa.chain_uniform_span[s0];
                                    while (pos <= haystack.len) {
                                        const hit = pf.findWatched(haystack, pos, nul) orelse return null;
                                        const rem_start = hit.start + p0;
                                        if (rem_start + clen <= haystack.len) {
                                            const p = haystack[rem_start..][0..clen];
                                            if ((p[clen - 1] -% u_lo) <= u_sp) {
                                                var ok = true;
                                                for (p[0 .. clen - 1]) |ch| {
                                                    if ((ch -% u_lo) > u_sp) {
                                                        ok = false;
                                                        break;
                                                    }
                                                }
                                                if (ok) {
                                                    return checkWatchedMatch(haystack, hit.end, Match{
                                                        .start = hit.start,
                                                        .end = rem_start + clen,
                                                        .pattern_id = null,
                                                    }, nul);
                                                }
                                            }
                                        }
                                        pos = hit.start + shift;
                                        rejects += 1;
                                        if (rejects >= 16 and pos <= start + 32 * 1024 and haystack.len -| pos >= 64 * 1024) {
                                            return findWatchedPrefixChainChunked(pf, haystack, pos, p0, clen, u_lo, u_sp, shift, nul);
                                        }
                                    }
                                    return null;
                                }
                                while (pos <= haystack.len) {
                                    const hit = pf.findWatched(haystack, pos, nul) orelse return null;
                                    if (dfa.matchPrefixDeterminized(haystack[hit.start..], s0, p0, false)) |match_len| {
                                        return checkWatchedMatch(haystack, hit.end, Match{
                                            .start = hit.start,
                                            .end = hit.start + match_len,
                                            .pattern_id = null,
                                        }, nul);
                                    }
                                    pos = hit.start + shift;
                                    rejects += 1;
                                    if (rejects >= 16 and pos <= start + 32 * 1024 and haystack.len -| pos >= 64 * 1024) {
                                        return self.findWatchedPrefixChunked(pf, haystack, pos, nul);
                                    }
                                }
                                return null;
                            }
                            while (pos <= haystack.len) {
                                const hit = pf.findWatched(haystack, pos, nul) orelse return null;
                                const can_skip_prefix = (hit.end - hit.start == self.dfa_prefix_len);
                                const s0: u16 = if (can_skip_prefix) self.dfa_prefix_state else dfa_mod.start_state;
                                const p0: usize = if (can_skip_prefix) self.dfa_prefix_len else 0;
                                if (dfa.matchPrefixDeterminized(haystack[hit.start..], s0, p0, false)) |match_len| {
                                    return checkWatchedMatch(haystack, hit.end, Match{
                                        .start = hit.start,
                                        .end = hit.start + match_len,
                                        .pattern_id = null,
                                    }, nul);
                                }
                                const next_pos = hit.start + self.req_prefix_shift;
                                const check_to = @min(next_pos, haystack.len);
                                if (check_to > hit.end) {
                                    if (memchr.find(memchr.native_width, haystack[0..check_to], hit.end, 0)) |at| {
                                        nul.* = at;
                                        return null;
                                    }
                                }
                                pos = next_pos;
                                rejects += 1;
                                if (rejects >= 16 and pos <= start + 32 * 1024 and haystack.len -| pos >= 64 * 1024) {
                                    return self.findWatchedPrefixChunked(pf, haystack, pos, nul);
                                }
                            }
                            return null;
                        }
                        var cached_win_end: usize = std.math.maxInt(usize);
                        var next_tail: ?Match = null;
                        var nul_checked_to: usize = start;
                        while (pos <= haystack.len) {
                            const hit = pf.findWatched(haystack, pos, nul) orelse return null;
                            nul_checked_to = @max(nul_checked_to, hit.end);
                            const can_skip_prefix = (hit.end - hit.start == self.dfa_prefix_len);
                            const s0: u16 = if (can_skip_prefix) self.dfa_prefix_state else dfa_mod.start_state;
                            const p0: usize = if (can_skip_prefix) self.dfa_prefix_len else 0;
                            const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                                cached_win_end
                            else blk: {
                                const w = self.windowLimit(haystack, hit.start);
                                cached_win_end = w;
                                break :blk w;
                            };
                            if (self.tail_finder) |*tf| {
                                if (next_tail == null or next_tail.?.start < hit.end) {
                                    var t_nul: ?usize = null;
                                    const found_t = tf.findWatched(haystack, hit.end, &t_nul);
                                    if (t_nul) |z| {
                                        nul.* = z;
                                        return null;
                                    }
                                    next_tail = found_t orelse return null;
                                    nul_checked_to = @max(nul_checked_to, next_tail.?.end);
                                }
                                if (next_tail.?.end > win_end) {
                                    const next_pos = if (!self.multiline) blk: {
                                        const nl_next = @min(haystack.len + 1, win_end + 1);
                                        break :blk if (can_jump_tail) @max(nl_next, lineStartAt(haystack, next_tail.?.start)) else nl_next;
                                    } else if (can_jump_tail)
                                        @max(hit.start + self.req_prefix_shift, next_tail.?.end -| self.max_multiline_window)
                                    else
                                        hit.start + self.req_prefix_shift;
                                    const check_to = @min(next_pos, haystack.len);
                                    if (check_to > nul_checked_to) {
                                        if (memchr.find(memchr.native_width, haystack[0..check_to], nul_checked_to, 0)) |at| {
                                            nul.* = at;
                                            return null;
                                        }
                                        nul_checked_to = check_to;
                                    }
                                    pos = next_pos;
                                    rejects += 1;
                                    if (rejects >= 16 and pos <= start + 32 * 1024 and haystack.len -| pos >= 64 * 1024) {
                                        return self.findWatchedPrefixChunked(pf, haystack, pos, nul);
                                    }
                                    continue;
                                }
                            }
                            if (dfa.matchPrefixDeterminized(haystack[hit.start..win_end], s0, p0, !exact_for_mode and !ascii_exact_for_mode)) |match_len| {
                                if (exact_for_mode or (ascii_exact_for_mode and self.isAsciiExactMatch(haystack[hit.start .. hit.start + match_len]))) {
                                    return checkWatchedMatch(haystack, nul_checked_to, Match{
                                        .start = hit.start,
                                        .end = hit.start + match_len,
                                        .pattern_id = null,
                                    }, nul);
                                }
                                if (self.runRangeAllowed(haystack, hit.start, hit.start, win_end, .earliest, AllowAny{}, null, null)) |m| {
                                    return checkWatchedMatch(haystack, nul_checked_to, m, nul);
                                }
                            }
                            const next_pos = hit.start + self.req_prefix_shift;
                            const check_to = @min(next_pos, haystack.len);
                            if (check_to > nul_checked_to) {
                                if (memchr.find(memchr.native_width, haystack[0..check_to], nul_checked_to, 0)) |at| {
                                    nul.* = at;
                                    return null;
                                }
                                nul_checked_to = check_to;
                            }
                            pos = next_pos;
                            rejects += 1;
                            if (rejects >= 16 and pos <= start + 32 * 1024 and haystack.len -| pos >= 64 * 1024) {
                                return self.findWatchedPrefixChunked(pf, haystack, pos, nul);
                            }
                        }
                        return null;
                    }
                    var cached_win_end: usize = std.math.maxInt(usize);
                    var next_tail: ?Match = null;
                    var nul_checked_to: usize = start;
                    while (pos <= haystack.len) {
                        const hit = pf.findWatched(haystack, pos, nul) orelse return null;
                        nul_checked_to = @max(nul_checked_to, hit.end);
                        const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                            cached_win_end
                        else blk: {
                            const w = self.windowLimit(haystack, hit.start);
                            cached_win_end = w;
                            break :blk w;
                        };
                        if (self.tail_finder) |*tf| {
                            if (next_tail == null or next_tail.?.start < hit.end) {
                                var t_nul: ?usize = null;
                                const found_t = tf.findWatched(haystack, hit.end, &t_nul);
                                if (t_nul) |z| {
                                    nul.* = z;
                                    return null;
                                }
                                next_tail = found_t orelse return null;
                                nul_checked_to = @max(nul_checked_to, next_tail.?.end);
                            }
                            if (next_tail.?.end > win_end) {
                                const next_pos = if (!self.multiline) blk: {
                                    const nl_next = @min(haystack.len + 1, win_end + 1);
                                    break :blk if (can_jump_tail) @max(nl_next, lineStartAt(haystack, next_tail.?.start)) else nl_next;
                                } else if (can_jump_tail)
                                    @max(hit.start + self.req_prefix_shift, next_tail.?.end -| self.max_multiline_window)
                                else
                                    hit.start + 1;
                                const check_to = @min(next_pos, haystack.len);
                                if (check_to > nul_checked_to) {
                                    if (memchr.find(memchr.native_width, haystack[0..check_to], nul_checked_to, 0)) |at| {
                                        nul.* = at;
                                        return null;
                                    }
                                    nul_checked_to = check_to;
                                }
                                pos = next_pos;
                                rejects += 1;
                                if (rejects >= 16 and pos <= start + 32 * 1024 and haystack.len -| pos >= 64 * 1024) {
                                    return self.findWatchedPrefixChunked(pf, haystack, pos, nul);
                                }
                                continue;
                            }
                        }
                        const p_hi = if (self.multiline) hit.start else win_end;
                        if (self.runRangeAllowed(haystack, hit.start, p_hi, win_end, .earliest, AllowAny{}, null, null)) |m| {
                            return checkWatchedMatch(haystack, nul_checked_to, m, nul);
                        }
                        const next_pos = if (!self.multiline) @min(haystack.len + 1, win_end + 1) else hit.start + 1;
                        const check_to = @min(next_pos, haystack.len);
                        if (check_to > nul_checked_to) {
                            if (memchr.find(memchr.native_width, haystack[0..check_to], nul_checked_to, 0)) |at| {
                                nul.* = at;
                                return null;
                            }
                            nul_checked_to = check_to;
                        }
                        pos = next_pos;
                        rejects += 1;
                        if (rejects >= 16 and pos <= start + 32 * 1024 and haystack.len -| pos >= 64 * 1024) {
                            return self.findWatchedPrefixChunked(pf, haystack, pos, nul);
                        }
                    }
                    return null;
                }
            }
            if (self.prefilter) |*pf| {
                var pos = start;
                var min_start = start;
                var rejects: usize = 0;
                var cached_win_end: usize = std.math.maxInt(usize);
                const exact_for_mode = self.dfa_is_exact and !self.has_alt;
                const ascii_exact_for_mode = (self.dfa_exact_on_ascii or self.dfa_exact_on_ascii_any) and !self.has_alt;
                while (pos <= haystack.len) {
                    const hit = if (self.pair_prefilter) |*pp| blk: {
                        const pf_pre: usize = self.pair_prefilter_prefix_len;
                        const pair_search_from = @max(pos, min_start + self.req_min_before) -| pf_pre;
                        if (pair_search_from > haystack.len) return null;
                        if (pair_search_from > pos) {
                            if (memchr.find(memchr.native_width, haystack[0..pair_search_from], pos, 0)) |at| {
                                nul.* = at;
                                return null;
                            }
                        }
                        const ph = pp.findWatched(haystack, pair_search_from, nul) orelse return null;
                        break :blk Match{ .start = ph.start + pf_pre, .end = ph.end, .pattern_id = null };
                    } else if (self.byte_ctx_prefilter) |bcp| blk: {
                        const at = bcp.findWatched(haystack, pos, min_start + self.req_min_before, nul) orelse return null;
                        break :blk Match{ .start = at, .end = at + 1, .pattern_id = null };
                    } else (pf.findWatched(haystack, pos, nul) orelse return null);
                    if (self.multiline and hit.end - hit.start > self.max_multiline_window) {
                        pos = hit.start + 1;
                        min_start = pos;
                        rejects += 1;
                        if (rejects >= 16 and pos <= start + 32 * 1024 and haystack.len -| pos >= 64 * 1024) {
                            return self.findWatchedInteriorChunked(pf, haystack, pos, min_start, nul);
                        }
                        continue;
                    }
                    const prev_fail = hit.start < min_start + self.req_min_before or
                        (self.req_has_prev_mask and (!self.req_prev_masks[0].contains(haystack[hit.start - 1]) or
                            (self.req_prev_mask_len >= 2 and !self.req_prev_masks[1].contains(haystack[hit.start - 2])) or
                            (self.req_prev_mask_len >= 3 and !self.req_prev_masks[2].contains(haystack[hit.start - 3]))));
                    if (prev_fail) {
                        const next_pos = hit.start + self.req_prefix_shift;
                        const check_to = @min(next_pos, haystack.len);
                        if (check_to > hit.end) {
                            if (memchr.find(memchr.native_width, haystack[0..check_to], hit.end, 0)) |at| {
                                nul.* = at;
                                return null;
                            }
                        }
                        pos = next_pos;
                        rejects += 1;
                        if (rejects >= 16 and pos <= start + 32 * 1024 and haystack.len -| pos >= 64 * 1024) {
                            return self.findWatchedInteriorChunked(pf, haystack, pos, min_start, nul);
                        }
                        continue;
                    }
                    if (self.req_prefix_uclass_pc != std.math.maxInt(u32) and self.dfa_suffix_is_exact) {
                        if (self.precomputed_dfa) |dfa| {
                            if (dfa.matchPrefixDeterminized(haystack[hit.end..], self.dfa_suffix_state, 0, false)) |suf_len| {
                                const uc = self.insts[self.req_prefix_uclass_pc].unicode_class;
                                const ranges = self.unicode_ranges[uc.range_idx].ranges;
                                if (matchPrefixUclassReverse(haystack, min_start, hit.start, uc, ranges, self.req_prefix_uclass_min)) |run_start| {
                                    return checkWatchedMatch(haystack, hit.end, Match{
                                        .start = run_start,
                                        .end = hit.end + suf_len,
                                        .pattern_id = null,
                                    }, nul);
                                }
                            }
                            const next_pos = hit.start + self.req_prefix_shift;
                            const check_to = @min(next_pos, haystack.len);
                            if (check_to > hit.end) {
                                if (memchr.find(memchr.native_width, haystack[0..check_to], hit.end, 0)) |at| {
                                    nul.* = at;
                                    return null;
                                }
                            }
                            pos = next_pos;
                            rejects += 1;
                            if (rejects >= 16 and pos <= start + 32 * 1024 and haystack.len -| pos >= 64 * 1024) {
                                return self.findWatchedInteriorChunked(pf, haystack, pos, min_start, nul);
                            }
                            continue;
                        }
                    }
                    if (self.dfa_suffix_state != 0 and !self.multiline) {
                        if (self.precomputed_dfa) |dfa| {
                            if (dfa.matchPrefixDeterminized(haystack[hit.end..], self.dfa_suffix_state, 0, true) == null) {
                                const next_pos = hit.start + self.req_prefix_shift;
                                const check_to = @min(next_pos, haystack.len);
                                if (check_to > hit.end) {
                                    if (memchr.find(memchr.native_width, haystack[0..check_to], hit.end, 0)) |at| {
                                        nul.* = at;
                                        return null;
                                    }
                                }
                                pos = next_pos;
                                rejects += 1;
                                if (rejects >= 16 and pos <= start + 32 * 1024 and haystack.len -| pos >= 64 * 1024) {
                                    return self.findWatchedInteriorChunked(pf, haystack, pos, min_start, nul);
                                }
                                continue;
                            }
                        }
                    }
                    const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                        cached_win_end
                    else blk: {
                        const w = self.windowLimit(haystack, hit.start);
                        cached_win_end = w;
                        break :blk w;
                    };
                    if (self.tail_finder) |*tf| {
                        if (hit.end > win_end or tf.findReadOnly(haystack[0..win_end], hit.end, .earliest) == null) {
                            const next_pos = if (!self.multiline) @min(haystack.len + 1, win_end + 1) else hit.start + 1;
                            const check_to = @min(next_pos, haystack.len);
                            if (check_to > hit.end) {
                                if (memchr.find(memchr.native_width, haystack[0..check_to], hit.end, 0)) |at| {
                                    nul.* = at;
                                    return null;
                                }
                            }
                            pos = next_pos;
                            min_start = pos;
                            rejects += 1;
                            if (rejects >= 16 and pos <= start + 32 * 1024 and haystack.len -| pos >= 64 * 1024) {
                                return self.findWatchedInteriorChunked(pf, haystack, pos, min_start, nul);
                            }
                            continue;
                        }
                    }
                    const narrowed_local = !self.multiline and (self.req_max_before != null or self.req_has_prefix_bytes_mask);
                    const search_from = blk: {
                        if (self.multiline) {
                            break :blk @max(min_start, hit.end -| self.max_multiline_window);
                        }
                        var lo = min_start;
                        if (self.req_max_before) |max_b| {
                            lo = @max(lo, hit.start -| max_b);
                        }
                        if (self.req_has_prefix_bytes_mask) {
                            var cur = hit.start;
                            while (cur > lo and self.req_prefix_bytes_mask.contains(haystack[cur - 1])) {
                                cur -= 1;
                            }
                            lo = cur;
                        }
                        if (self.req_max_before != null or self.req_has_prefix_bytes_mask) {
                            if (lo < hit.start and (!self.req_has_prefix_bytes_mask or self.req_prefix_bytes_mask.contains('\n'))) {
                                if (memchr.findLast(memchr.native_width, haystack, lo, hit.start, '\n')) |nl| {
                                    lo = nl + 1;
                                }
                            }
                            break :blk lo;
                        }
                        break :blk @max(min_start, lineStartAt(haystack, hit.start));
                    };
                    const p_hi = if (self.multiline)
                        hit.start -| self.req_min_before
                    else if (narrowed_local)
                        hit.start -| self.req_min_before
                    else
                        win_end;
                    if (self.precomputed_dfa) |dfa| {
                        var p = search_from;
                        while (p <= p_hi) : (p += 1) {
                            if (p < win_end and dfa.trans[dfa_mod.start_state][haystack[p]] == dfa_mod.dead_state) continue;
                            const p_win = if (self.multiline) self.windowLimit(haystack, p) else win_end;
                            if (dfa.matchPrefixDeterminized(haystack[p..p_win], dfa_mod.start_state, 0, !exact_for_mode and !ascii_exact_for_mode)) |match_len| {
                                const m = if (exact_for_mode or (ascii_exact_for_mode and self.isAsciiExactMatch(haystack[p .. p + match_len])))
                                    Match{ .start = p, .end = p + match_len, .pattern_id = null }
                                else
                                    self.runRangeAllowed(haystack, p, p, p_win, .earliest, AllowAny{}, null, null);
                                if (m) |found_m| {
                                    return checkWatchedMatch(haystack, hit.end, found_m, nul);
                                }
                            }
                        }
                    } else if (search_from <= p_hi) {
                        if (self.runRangeAllowed(haystack, search_from, p_hi, win_end, .earliest, AllowAny{}, null, null)) |m| {
                            return checkWatchedMatch(haystack, hit.end, m, nul);
                        }
                    }
                    const next_pos = if (narrowed_local)
                        hit.start + self.req_prefix_shift
                    else if (!self.multiline)
                        @min(haystack.len + 1, win_end + 1)
                    else
                        hit.start + 1;
                    const check_to = @min(next_pos, haystack.len);
                    if (check_to > hit.end) {
                        if (memchr.find(memchr.native_width, haystack[0..check_to], hit.end, 0)) |at| {
                            nul.* = at;
                            return null;
                        }
                    }
                    pos = next_pos;
                    if (!narrowed_local) min_start = pos;
                    rejects += 1;
                    if (rejects >= 16 and pos <= start + 32 * 1024 and haystack.len -| pos >= 64 * 1024) {
                        return self.findWatchedInteriorChunked(pf, haystack, pos, min_start, nul);
                    }
                }
                return null;
            }
            if (self.alt_prefilter) |*ap| {
                var max_ap_len: usize = 0;
                for (self.alt_literal_slices) |s| {
                    if (s.len > max_ap_len) max_ap_len = s.len;
                }
                if (self.ignore_case and self.unicode_case) max_ap_len *|= 3;

                var pos = start;
                var min_start = start;
                var rejects: usize = 0;
                var cached_win_end: usize = std.math.maxInt(usize);
                if (self.alt_is_prefix) {
                    if (self.precomputed_dfa) |dfa| {
                        const step = if (dfa.stops_on_crlf) blk: {
                            var verifier = AltDfaVerifier(true, true, false){
                                .regex = self,
                                .dfa = dfa,
                                .full_haystack = haystack,
                                .mode = .earliest,
                                .steps = null,
                                .scratch = null,
                                .orig_start = start,
                            };
                            break :blk ap.findVerifiedWatched(haystack, pos, .leftmost_first, nul, &verifier);
                        } else blk: {
                            var verifier = AltDfaVerifier(false, true, false){
                                .regex = self,
                                .dfa = dfa,
                                .full_haystack = haystack,
                                .mode = .earliest,
                                .steps = null,
                                .scratch = null,
                                .orig_start = start,
                            };
                            break :blk ap.findVerifiedWatched(haystack, pos, .leftmost_first, nul, &verifier);
                        };
                        return switch (step) {
                            .match => |vm| checkWatchedMatch(haystack, vm.start, Match{
                                .start = vm.start,
                                .end = vm.end,
                                .pattern_id = null,
                            }, nul),
                            .none => null,
                            .aborted => |resume_pos| self.findWatchedAltDfaChunked(ap, dfa, haystack, resume_pos, max_ap_len, nul),
                        };
                    }
                }
                while (pos <= haystack.len) {
                    const raw_hit = ap.findWatched(haystack, pos, nul) orelse return null;
                    const lo = @max(pos, raw_hit.end -| max_ap_len);
                    const hi_slice = @min(haystack.len, raw_hit.start +| max_ap_len);
                    const hit = if (lo < raw_hit.start)
                        (ap.find(haystack[0..hi_slice], lo, .leftmost_first) orelse raw_hit)
                    else
                        raw_hit;
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
                    const p_hi = if (self.multiline) hit.start else win_end;
                    if (search_from <= p_hi) {
                        if (self.runRangeAllowed(haystack, search_from, p_hi, win_end, .earliest, AllowAny{}, null, null)) |m| {
                            return checkWatchedMatch(haystack, raw_hit.end, m, nul);
                        }
                    }
                    const next_pos = if (!self.multiline) @min(haystack.len + 1, win_end + 1) else hit.start + 1;
                    const check_to = @min(next_pos, haystack.len);
                    if (check_to > raw_hit.end) {
                        if (memchr.find(memchr.native_width, haystack[0..check_to], raw_hit.end, 0)) |at| {
                            nul.* = at;
                            return null;
                        }
                    }
                    pos = next_pos;
                    min_start = pos;
                    rejects += 1;
                    if (rejects >= 16 and pos <= start + 32 * 1024 and haystack.len -| pos >= 64 * 1024) {
                        return self.findWatchedAltGeneralChunked(ap, haystack, pos, min_start, max_ap_len, nul);
                    }
                }
                return null;
            }
            if (self.unanchored_dfa) |udfa| {
                return self.runUnanchoredDfa(udfa, haystack, start, haystack.len, .earliest, null, null, true, nul);
            }
        }
        const hit = self.find(haystack, start, .earliest);
        const limit = if (hit) |m| @min(haystack.len, @max(start, m.end)) else haystack.len;
        if (start < limit) {
            if (memchr.find(memchr.native_width, haystack[0..limit], start, 0)) |at| {
                nul.* = at;
                return null;
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
        const steps: ?*usize = if (comptime builtin.is_test) @constCast(&self.steps) else null;
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
        steps: ?*usize,
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
            return memchr.find(memchr.native_width, haystack, from, '\n') orelse haystack.len;
        }
        const max_end = @min(haystack.len, from +| self.max_multiline_window);
        if (self.max_newlines) |max_nl| {
            if (max_nl <= 4) {
                var cur = from;
                var rem: u32 = max_nl + 1;
                while (rem > 0 and cur < max_end) : (rem -= 1) {
                    if (memchr.find(memchr.native_width, haystack[0..max_end], cur, '\n')) |nl| {
                        cur = nl + 1;
                    } else {
                        return max_end;
                    }
                }
                return cur;
            }
        }
        return max_end;
    }

    fn runRangeAllowed(
        self: *const Regex,
        haystack: []const u8,
        start_lo: usize,
        start_hi: usize,
        limit: usize,
        mode: MatchMode,
        allow_arg: anytype,
        steps: ?*usize,
        scratch: ?*RegexScratch,
    ) ?Match {
        var window_clipped = false;
        const best = self.runRangeAllowedOnce(haystack, start_lo, start_hi, limit, mode, allow_arg, steps, scratch, &window_clipped);
        if (!window_clipped or start_lo >= start_hi) return best;
        if (mode == .leftmost_first and best != null and best.?.start <= start_lo) return best;

        var lo_p = start_lo + 1;
        var max_p = @min(start_hi, limit);
        if (best) |bm| {
            if (mode == .leftmost_first) {
                max_p = @min(max_p, bm.start - 1);
            } else {
                max_p = @min(max_p, bm.end);
            }
        }
        if (lo_p > max_p) return best;

        if (max_p - lo_p > 64) {
            const probe_limit = if (mode == .earliest and best != null) @min(limit, best.?.end) else limit;
            const first_end = self.firstWindowEndFrom(haystack, lo_p, max_p, probe_limit, steps, scratch) orelse return best;
            if (comptime @TypeOf(allow_arg) == AllowAny) {
                lo_p = @max(lo_p, first_end -| self.max_multiline_window);
                if (mode == .earliest) max_p = @min(max_p, first_end);
            }
        }

        var overall = best;
        var p = lo_p;
        while (p <= max_p) : (p += 1) {
            if (self.anchored_start and p > 0) break;
            if (self.req_is_prefix) {
                if (self.prefilter) |*pf| {
                    const nh = pf.findReadOnly(haystack[0..limit], p, .earliest) orelse break;
                    if (nh.start > max_p) break;
                    p = nh.start;
                }
            }
            var dummy_clip = false;
            const p_lim = @min(limit, self.windowLimit(haystack, p));
            if (self.runRangeAllowedOnce(haystack, p, p, p_lim, mode, allow_arg, steps, scratch, &dummy_clip)) |m| {
                if (mode == .leftmost_first) return m;
                if (overall == null or m.end < overall.?.end or (m.end == overall.?.end and m.start < overall.?.start)) {
                    overall = m;
                    max_p = @min(max_p, m.end);
                }
            }
        }
        return overall;
    }

    fn firstWindowEndFrom(
        self: *const Regex,
        haystack: []const u8,
        from_start: usize,
        max_start: usize,
        limit: usize,
        steps: ?*usize,
        scratch: ?*RegexScratch,
    ) ?usize {
        const n_inst = self.insts.len;
        if (n_inst == 0 or from_start > limit) return null;

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
        var local_steps: usize = 0;
        defer if (comptime builtin.is_test) {
            if (steps) |s| {
                if (local_steps > 0) _ = @atomicRmw(usize, s, .Add, local_steps, .monotonic);
            }
        };
        const local_steps_ptr: ?*usize = if (comptime builtin.is_test) &local_steps else null;

        var pos = from_start;
        while (true) {
            if (gen == std.math.maxInt(u32)) {
                @memset(gen_table, 0);
                gen = 1;
            }

            if (curr_len == 0 and pos > from_start and pos <= max_start and self.req_is_prefix) {
                if (self.prefilter) |*pf| {
                    const next_hit = pf.findReadOnly(haystack[0..limit], pos, .earliest) orelse break;
                    if (next_hit.start > max_start) break;
                    pos = next_hit.start;
                }
            }

            if (pos <= max_start and (!self.anchored_start or pos == 0)) {
                if (curr_len == 0) {
                    self.addThread(curr, &curr_len, gen_table, gen, self.start_pc, pos, haystack, pos, local_steps_ptr);
                } else {
                    gen +%= 1;
                    if (gen == 0) {
                        @memset(gen_table, 0);
                        gen = 1;
                    }
                    var merged_len: usize = 0;
                    self.addThread(next, &merged_len, gen_table, gen, self.start_pc, pos, haystack, pos, local_steps_ptr);
                    for (curr[0..curr_len]) |th| {
                        if (gen_table[th.pc] != gen) {
                            gen_table[th.pc] = gen;
                            next[merged_len] = th;
                            merged_len += 1;
                        }
                    }
                    const tmp_m = curr;
                    curr = next;
                    next = tmp_m;
                    curr_len = merged_len;
                }
            }

            if (curr_len == 0) {
                if (pos >= max_start or pos >= limit or (self.anchored_start and pos > 0)) break;
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
                if (self.multiline and (pos - th.start > self.max_multiline_window)) continue;
                const inst = self.insts[th.pc];
                switch (inst) {
                    .match, .match_id => return pos,
                    .byte => |by| {
                        if (!has_byte or (!self.multiline and is_nl)) continue;
                        const ok = if (by.ignore_case) std.ascii.toLower(b) == std.ascii.toLower(by.b) else b == by.b;
                        if (ok and (!self.multiline or pos + 1 - th.start <= self.max_multiline_window)) {
                            self.addThread(next, &next_len, gen_table, gen, by.out, th.start, haystack, pos + 1, local_steps_ptr);
                        }
                    },
                    .any => |an| {
                        if (!has_byte) continue;
                        if ((!an.allow_nl or !self.multiline) and (is_nl or (!self.multiline and b == '\r' and pos + 1 < haystack.len and haystack[pos + 1] == '\n'))) continue;
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
                        if (!has_byte or (!self.multiline and is_nl)) continue;
                        if ((b & 0xC0) == 0x80 and (!self.multiline or pos + 1 - th.start <= self.max_multiline_window)) {
                            self.addThread(next, &next_len, gen_table, gen, ac.out, th.start, haystack, pos + 1, local_steps_ptr);
                        }
                    },
                    .class => |cl| {
                        if (!has_byte or (!self.multiline and is_nl)) continue;
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
                        if (!has_byte or (!uc.allow_nl and is_nl)) continue;
                        const dec = decodeValidUtf8At(haystack, pos, limit) orelse continue;
                        const ranges = self.unicode_ranges[uc.range_idx].ranges;
                        var in_set = (dec.cp < 0x80 and uc.has_ascii_set and uc.ascii_set.contains(@intCast(dec.cp))) or inRanges(dec.cp, ranges);
                        if (!in_set and uc.ignore_case and dec.cp >= 0x80) {
                            var eq: [4]u21 = undefined;
                            const n_eq = unicode_fold.foldEquivalents(dec.cp, &eq);
                            for (eq[0..n_eq]) |alt_cp| {
                                if ((alt_cp < 0x80 and uc.has_ascii_set and uc.ascii_set.contains(@intCast(alt_cp))) or inRanges(alt_cp, ranges)) {
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
            const tmp = curr;
            curr = next;
            next = tmp;
            curr_len = next_len;
            pos += 1;
        }
        return null;
    }

    fn runRangeAllowedOnce(
        self: *const Regex,
        haystack: []const u8,
        start_lo: usize,
        start_hi: usize,
        limit: usize,
        mode: MatchMode,
        allow_arg: anytype,
        steps: ?*usize,
        scratch: ?*RegexScratch,
        window_clipped: *bool,
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
        var local_steps: usize = 0;
        defer if (comptime builtin.is_test) {
            if (steps) |s| {
                if (local_steps > 0) _ = @atomicRmw(usize, s, .Add, local_steps, .monotonic);
            }
        };
        const local_steps_ptr: ?*usize = if (comptime builtin.is_test) &local_steps else null;

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
                        (if (self.unicode_case and (self.req_literal_bytes[0] >= 0x80 or self.req_literal_bytes[0] == 'k' or self.req_literal_bytes[0] == 'K' or self.req_literal_bytes[0] == 's' or self.req_literal_bytes[0] == 'S'))
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
                if (self.multiline and (pos - th.start > self.max_multiline_window)) {
                    window_clipped.* = true;
                    continue;
                }

                const inst = self.insts[th.pc];
                switch (inst) {
                    .match, .match_id => {
                        if (!inst_mod.invokeAllow(allow_arg, haystack, th.start, pos)) continue;
                        if (best == null or th.start < best.?.start or (th.start == best.?.start and pos > best.?.end)) {
                            best = .{ .start = th.start, .end = pos };
                        }
                        if (mode == .earliest and next_len == 0 and !window_clipped.*) return best;
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
                        if (ok) {
                            if (!self.multiline or pos + 1 - th.start <= self.max_multiline_window) {
                                self.addThread(next, &next_len, gen_table, gen, by.out, th.start, haystack, pos + 1, local_steps_ptr);
                            } else {
                                window_clipped.* = true;
                            }
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
                        } else {
                            window_clipped.* = true;
                        }
                    },
                    .any_cont => |ac| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        if ((b & 0xC0) == 0x80) {
                            if (!self.multiline or pos + 1 - th.start <= self.max_multiline_window) {
                                self.addThread(next, &next_len, gen_table, gen, ac.out, th.start, haystack, pos + 1, local_steps_ptr);
                            } else {
                                window_clipped.* = true;
                            }
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
                                } else {
                                    window_clipped.* = true;
                                }
                                continue;
                            }
                        }
                        if (cl.set.contains(b)) {
                            if (!self.multiline or pos + 1 - th.start <= self.max_multiline_window) {
                                self.addThread(next, &next_len, gen_table, gen, cl.out, th.start, haystack, pos + 1, local_steps_ptr);
                            } else {
                                window_clipped.* = true;
                            }
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
                                if ((alt_cp < 0x80 and uc.has_ascii_set and uc.ascii_set.contains(@intCast(alt_cp))) or inRanges(alt_cp, ranges)) {
                                    in_set = true;
                                    break;
                                }
                            }
                        }
                        const matched = if (uc.negated) !in_set else in_set;
                        if (matched) {
                            if (!self.multiline or pos + dec.len - th.start <= self.max_multiline_window) {
                                const target_pc: u32 = switch (dec.len) {
                                    2 => if (uc.cont1 != 0) uc.cont1 else uc.out,
                                    3 => if (uc.cont2 != 0) uc.cont2 else uc.out,
                                    4 => if (uc.cont3 != 0) uc.cont3 else uc.out,
                                    else => uc.out,
                                };
                                self.addThread(next, &next_len, gen_table, gen, target_pc, th.start, haystack, pos + 1, local_steps_ptr);
                            } else {
                                window_clipped.* = true;
                            }
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
        steps: ?*usize,
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

    fn findPrefixAnyTail(
        self: *const Regex,
        pat: PrefixAnyTail,
        pf: *const Finder,
        tf: *const Finder,
        haystack: []const u8,
        start: usize,
        mode: MatchMode,
        comptime watch_nul: bool,
        nul: *?usize,
    ) ?Match {
        const eff_allow_nl = pat.allow_nl and self.multiline;
        const reject_crlf = !self.multiline;
        const shift = self.req_prefix_shift;
        const pref_len = self.req_literal_bytes.len;
        const tail_len = self.tail_literal_bytes.len;

        var pos = start;
        var nul_checked_to = start;
        var next_tail: ?Match = null;
        var cached_win_end: usize = std.math.maxInt(usize);

        while (pos <= haystack.len) {
            const hit = if (watch_nul)
                (pf.findWatched(haystack, pos, nul) orelse return null)
            else
                (pf.findReadOnly(haystack, pos, .earliest) orelse return null);
            if (watch_nul) nul_checked_to = @max(nul_checked_to, hit.end);

            const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                cached_win_end
            else blk: {
                const w = if (!self.multiline)
                    (memchr.find(memchr.native_width, haystack, hit.start, '\n') orelse haystack.len)
                else
                    @min(haystack.len, hit.start +| self.max_multiline_window);
                cached_win_end = w;
                break :blk w;
            };

            const min_tail_start = hit.end +| pat.min_any;
            if (min_tail_start +| tail_len > win_end) {
                if (self.multiline and min_tail_start +| tail_len > haystack.len) {
                    if (watch_nul and nul_checked_to < haystack.len) {
                        if (memchr.find(memchr.native_width, haystack, nul_checked_to, 0)) |z| nul.* = z;
                    }
                    return null;
                }
                const next_pos = if (!self.multiline) @min(haystack.len + 1, win_end + 1) else hit.start + shift;
                if (watch_nul) {
                    const check_to = @min(next_pos, haystack.len);
                    if (check_to > nul_checked_to) {
                        if (memchr.find(memchr.native_width, haystack[0..check_to], nul_checked_to, 0)) |at| {
                            nul.* = at;
                            return null;
                        }
                        nul_checked_to = check_to;
                    }
                }
                pos = next_pos;
                continue;
            }

            if (next_tail == null or next_tail.?.start < min_tail_start) {
                if (watch_nul) {
                    if (min_tail_start > nul_checked_to) {
                        if (memchr.find(memchr.native_width, haystack[0..min_tail_start], nul_checked_to, 0)) |at| {
                            nul.* = at;
                            return null;
                        }
                        nul_checked_to = min_tail_start;
                    }
                    var t_nul: ?usize = null;
                    const found_t = tf.findWatched(haystack, min_tail_start, &t_nul);
                    if (t_nul) |z| {
                        nul.* = z;
                        return null;
                    }
                    next_tail = found_t orelse return null;
                    nul_checked_to = @max(nul_checked_to, next_tail.?.end);
                } else {
                    next_tail = tf.findReadOnly(haystack, min_tail_start, .earliest) orelse return null;
                }
            }

            const t0 = next_tail.?;
            if (t0.end > win_end) {
                const next_pos = if (!self.multiline)
                    @max(@min(haystack.len + 1, win_end + 1), lineStartAt(haystack, t0.start))
                else blk: {
                    var jump = @max(hit.start + shift, t0.end -| self.max_multiline_window);
                    if (pat.max_any) |max_a| {
                        jump = @max(jump, t0.start -| (pref_len +| @as(usize, max_a) *| 4));
                    }
                    break :blk jump;
                };
                if (watch_nul) {
                    const check_to = @min(next_pos, haystack.len);
                    if (check_to > nul_checked_to) {
                        if (memchr.find(memchr.native_width, haystack[0..check_to], nul_checked_to, 0)) |at| {
                            nul.* = at;
                            return null;
                        }
                        nul_checked_to = check_to;
                    }
                }
                pos = next_pos;
                continue;
            }

            var gap_limit = win_end;
            if (!eff_allow_nl) {
                if (self.multiline) {
                    if (memchr.find(memchr.native_width, haystack[0..win_end], hit.end, '\n')) |nl| {
                        gap_limit = nl;
                    }
                }
                if (reject_crlf and gap_limit > hit.end and gap_limit < haystack.len and haystack[gap_limit - 1] == '\r' and haystack[gap_limit] == '\n') {
                    gap_limit -= 1;
                }
            }

            if (t0.start > gap_limit) {
                const next_pos = @max(hit.start + shift, gap_limit + 1);
                if (watch_nul) {
                    const check_to = @min(next_pos, haystack.len);
                    if (check_to > nul_checked_to) {
                        if (memchr.find(memchr.native_width, haystack[0..check_to], nul_checked_to, 0)) |at| {
                            nul.* = at;
                            return null;
                        }
                        nul_checked_to = check_to;
                    }
                }
                pos = next_pos;
                continue;
            }

            var max_tail_start = gap_limit;
            var gap_is_ascii = false;
            if (pat.max_any) |max_a| {
                const max_bytes = @as(usize, max_a) *| 4;
                if (t0.start > hit.end +| max_bytes) {
                    const next_pos = @max(hit.start + shift, t0.start -| (pref_len +| max_bytes));
                    if (watch_nul) {
                        const check_to = @min(next_pos, haystack.len);
                        if (check_to > nul_checked_to) {
                            if (memchr.find(memchr.native_width, haystack[0..check_to], nul_checked_to, 0)) |at| {
                                nul.* = at;
                                return null;
                            }
                            nul_checked_to = check_to;
                        }
                    }
                    pos = next_pos;
                    continue;
                }
                const ascii_cap = @min(gap_limit, hit.end +| @as(usize, max_a));
                if (isAsciiBytes(haystack[hit.end..ascii_cap])) {
                    max_tail_start = ascii_cap;
                    gap_is_ascii = true;
                } else {
                    var p = hit.end;
                    var cps: usize = 0;
                    while (p < gap_limit and cps < max_a) : (cps += 1) {
                        const sl = utf8SeqLenAt(haystack, p, win_end);
                        if (p + sl > gap_limit) break;
                        p += sl;
                    }
                    max_tail_start = p;
                }
            }

            if (t0.start > max_tail_start) {
                const next_pos = hit.start + shift;
                if (watch_nul) {
                    const check_to = @min(next_pos, haystack.len);
                    if (check_to > nul_checked_to) {
                        if (memchr.find(memchr.native_width, haystack[0..check_to], nul_checked_to, 0)) |at| {
                            nul.* = at;
                            return null;
                        }
                        nul_checked_to = check_to;
                    }
                }
                pos = next_pos;
                continue;
            }

            const search_end = @min(win_end, max_tail_start +| tail_len);
            const want_first = (mode == .earliest or pat.is_lazy);
            var cur_t: Match = t0;
            var best_end: ?usize = null;
            while (true) {
                if (cur_t.start <= max_tail_start and cur_t.end <= win_end) {
                    const valid = if (gap_is_ascii)
                        true
                    else if (isAsciiBytes(haystack[hit.end..cur_t.start]))
                        (pat.max_any == null or (cur_t.start - hit.end) <= pat.max_any.?)
                    else blk: {
                        var p = hit.end;
                        var cps: usize = 0;
                        while (p < cur_t.start) {
                            const sl = utf8SeqLenAt(haystack, p, win_end);
                            p += sl;
                            cps += 1;
                        }
                        break :blk p == cur_t.start and cps >= pat.min_any and (pat.max_any == null or cps <= pat.max_any.?);
                    };
                    if (valid) {
                        best_end = cur_t.end;
                        if (want_first) break;
                    }
                }
                if (cur_t.start + 1 >= search_end) break;
                cur_t = tf.findReadOnly(haystack[0..search_end], cur_t.start + 1, .earliest) orelse break;
            }

            if (best_end) |be| {
                const m = Match{ .start = hit.start, .end = be, .pattern_id = null };
                if (watch_nul) return checkWatchedMatch(haystack, nul_checked_to, m, nul);
                return m;
            }

            const next_pos = hit.start + shift;
            if (watch_nul) {
                const check_to = @min(next_pos, haystack.len);
                if (check_to > nul_checked_to) {
                    if (memchr.find(memchr.native_width, haystack[0..check_to], nul_checked_to, 0)) |at| {
                        nul.* = at;
                        return null;
                    }
                    nul_checked_to = check_to;
                }
            }
            pos = next_pos;
        }
        return null;
    }

    pub fn extractCaptures(self: *const Regex, haystack: []const u8, m: Match) Captures {
        if (self.num_captures == 0 or m.start > m.end or m.end > haystack.len or self.insts.len == 0) {
            return Captures{ .match = m };
        }
        if (self.cap_plan) |cp| {
            if (self.execCapPlan(cp, haystack, m)) |fast_res| return fast_res;
        }
        if (self.num_captures <= 4) return self.extractCapturesImpl(8, 128, haystack, m);
        if (self.num_captures <= 8) return self.extractCapturesImpl(16, 64, haystack, m);
        return self.extractCapturesImpl(inst_mod.max_capture_slots, 16, haystack, m);
    }

    const CapExecStatus = enum { matched, no_match, bailout };

    fn execCapPlan(self: *const Regex, cp: *const CapPlan, haystack: []const u8, m: Match) ?Captures {
        const unset: usize = std.math.maxInt(usize);
        var slots: [16]usize = @splat(unset);
        var budget: u32 = 128;
        if (self.execCapOp(cp, 0, haystack, m.start, m.end, &slots, &budget) != .matched) {
            return null;
        }
        var res = Captures{ .match = m };
        const n_groups: usize = @min(@as(usize, self.num_captures), 8);
        for (0..n_groups) |g| {
            const s = slots[g * 2];
            const e = slots[g * 2 + 1];
            if (s != unset and e != unset and s <= e) {
                res.groups[g] = .{ .start = s, .end = e };
            }
        }
        return res;
    }

    fn execCapOp(
        self: *const Regex,
        cp: *const CapPlan,
        op_idx: usize,
        haystack: []const u8,
        pos: usize,
        end: usize,
        slots: *[16]usize,
        budget: *u32,
    ) CapExecStatus {
        if (op_idx >= cp.len) return if (pos == end) .matched else .no_match;
        if (budget.* == 0) return .bailout;
        budget.* -= 1;

        const unset: usize = std.math.maxInt(usize);
        switch (cp.ops[op_idx]) {
            .save => |slot| {
                const saved = if (slot < 16) slots[slot] else unset;
                if (slot < 16) slots[slot] = pos;
                const st = self.execCapOp(cp, op_idx + 1, haystack, pos, end, slots, budget);
                if (st == .matched) return .matched;
                if (slot < 16) slots[slot] = saved;
                return st;
            },
            .lit => |lit| {
                const lbytes = cp.lit_buf[lit.off .. lit.off + lit.len];
                if (pos + lbytes.len > end) return .no_match;
                const ok = if (lit.ignore_case)
                    std.ascii.eqlIgnoreCase(haystack[pos .. pos + lbytes.len], lbytes)
                else
                    std.mem.eql(u8, haystack[pos .. pos + lbytes.len], lbytes);
                if (!ok) return .no_match;
                return self.execCapOp(cp, op_idx + 1, haystack, pos + lbytes.len, end, slots, budget);
            },
            .class_rep => |cr| {
                const hi_cap = if (cr.max) |mx| @min(end, pos +| mx) else end;
                var hi = pos;
                while (hi < hi_cap and cr.set.contains(haystack[hi]) and (self.multiline or haystack[hi] != '\n')) : (hi += 1) {}
                if (hi - pos < cr.min) return .no_match;
                const lo = pos + cr.min;
                if (!cr.lazy) {
                    var k = hi;
                    while (true) {
                        const st = self.execCapOp(cp, op_idx + 1, haystack, k, end, slots, budget);
                        if (st != .no_match) return st;
                        if (k == lo) break;
                        k -= 1;
                    }
                } else {
                    var k = lo;
                    while (k <= hi) : (k += 1) {
                        const st = self.execCapOp(cp, op_idx + 1, haystack, k, end, slots, budget);
                        if (st != .no_match) return st;
                    }
                }
                return .no_match;
            },
            .any_rep => |ar| {
                const eff_allow_nl = ar.allow_nl and self.multiline;
                const reject_crlf = !self.multiline;
                const lit_idx = cp.next_lit_op[op_idx];
                if (lit_idx != 0xFF and !ar.lazy and ar.min == 0 and ar.max == null) {
                    const lit = cp.ops[lit_idx].lit;
                    const lbytes = cp.lit_buf[lit.off .. lit.off + lit.len];
                    if (lbytes.len > 0 and lbytes[0] < 0x80 and !lit.ignore_case) {
                        var gap_lim = end -| lbytes.len;
                        if (!eff_allow_nl and self.multiline) {
                            if (memchr.find(memchr.native_width, haystack[0..end], pos, '\n')) |nl| {
                                gap_lim = @min(gap_lim, nl);
                            }
                        }
                        if (pos <= gap_lim) {
                            const b0 = lbytes[0];
                            var search_end = gap_lim + 1;
                            while (search_end > pos) {
                                const cand = memchr.findLast(memchr.native_width, haystack, pos, search_end, b0) orelse break;
                                if (std.mem.eql(u8, haystack[cand .. cand + lbytes.len], lbytes)) {
                                    if (!(reject_crlf and cand > pos and cand < haystack.len and haystack[cand - 1] == '\r' and haystack[cand] == '\n')) {
                                        const st = self.execCapOp(cp, op_idx + 1, haystack, cand, end, slots, budget);
                                        if (st != .no_match) return st;
                                    }
                                }
                                search_end = cand;
                            }
                        }
                        return .no_match;
                    }
                }
                var cp_ends: [65]usize = undefined;
                var n_cps: usize = 0;
                cp_ends[0] = pos;
                var p = pos;
                while (p < end) {
                    if (ar.max) |mx| {
                        if (n_cps >= mx) break;
                    }
                    if (!eff_allow_nl and (haystack[p] == '\n' or (reject_crlf and haystack[p] == '\r' and p + 1 < haystack.len and haystack[p + 1] == '\n'))) {
                        break;
                    }
                    const sl = utf8SeqLenAt(haystack, p, end);
                    p += sl;
                    n_cps += 1;
                    if (n_cps >= cp_ends.len) return .bailout;
                    cp_ends[n_cps] = p;
                }
                if (n_cps < ar.min) return .no_match;
                if (!ar.lazy) {
                    var k = n_cps;
                    while (true) {
                        const st = self.execCapOp(cp, op_idx + 1, haystack, cp_ends[k], end, slots, budget);
                        if (st != .no_match) return st;
                        if (k == ar.min) break;
                        k -= 1;
                    }
                } else {
                    var k = ar.min;
                    while (k <= n_cps) : (k += 1) {
                        const st = self.execCapOp(cp, op_idx + 1, haystack, cp_ends[k], end, slots, budget);
                        if (st != .no_match) return st;
                    }
                }
                return .no_match;
            },
        }
    }

    fn extractCapturesImpl(
        self: *const Regex,
        comptime cap_slots: usize,
        comptime stack_cap: usize,
        haystack: []const u8,
        m: Match,
    ) Captures {
        const unset: usize = std.math.maxInt(usize);
        const CapTh = struct {
            pc: u32,
            slots: [cap_slots]usize,
        };

        var res = Captures{ .match = m };
        const n_inst = self.insts.len;

        var stack_curr: [stack_cap]CapTh = undefined;
        var stack_next: [stack_cap]CapTh = undefined;
        var stack_gen: [256]u32 = undefined;

        var heap_curr: []CapTh = &.{};
        defer if (heap_curr.len != 0) self.allocator.free(heap_curr);
        var heap_next: []CapTh = &.{};
        defer if (heap_next.len != 0) self.allocator.free(heap_next);
        var heap_gen: []u32 = &.{};
        defer if (heap_gen.len != 0) self.allocator.free(heap_gen);

        var curr: []CapTh = if (n_inst <= stack_cap) stack_curr[0..n_inst] else blk: {
            heap_curr = self.allocator.alloc(CapTh, n_inst) catch return res;
            break :blk heap_curr;
        };
        var next: []CapTh = if (n_inst <= stack_cap) stack_next[0..n_inst] else blk: {
            heap_next = self.allocator.alloc(CapTh, n_inst) catch return res;
            break :blk heap_next;
        };
        const gen_table: []u32 = if (n_inst <= 256) stack_gen[0..n_inst] else blk: {
            heap_gen = self.allocator.alloc(u32, n_inst) catch return res;
            break :blk heap_gen;
        };
        @memset(gen_table, 0);
        var gen: u32 = 1;
        var curr_len: usize = 0;

        const init_slots: [cap_slots]usize = @splat(unset);
        self.addCapThreadImpl(cap_slots, CapTh, curr, &curr_len, gen_table, gen, self.start_pc, &init_slots, haystack, m.start);

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

            for (curr[0..curr_len]) |*th| {
                const inst = self.insts[th.pc];
                switch (inst) {
                    .match, .match_id => {
                        if (pos == m.end) {
                            const max_g = @min(cap_slots / 2, inst_mod.max_capture_groups);
                            for (0..max_g) |g| {
                                const s = th.slots[g * 2];
                                const e = th.slots[g * 2 + 1];
                                if (s != unset and e != unset and s <= e) {
                                    res.groups[g] = .{ .start = s, .end = e };
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
                        if (ok) self.addCapThreadImpl(cap_slots, CapTh, next, &next_len, gen_table, gen, by.out, &th.slots, haystack, pos + 1);
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
                        self.addCapThreadImpl(cap_slots, CapTh, next, &next_len, gen_table, gen, target_pc, &th.slots, haystack, pos + 1);
                    },
                    .any_cont => |ac| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        if ((b & 0xC0) == 0x80) {
                            self.addCapThreadImpl(cap_slots, CapTh, next, &next_len, gen_table, gen, ac.out, &th.slots, haystack, pos + 1);
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
                                self.addCapThreadImpl(cap_slots, CapTh, next, &next_len, gen_table, gen, target_pc, &th.slots, haystack, pos + 1);
                                continue;
                            }
                        }
                        if (cl.set.contains(b)) {
                            self.addCapThreadImpl(cap_slots, CapTh, next, &next_len, gen_table, gen, cl.out, &th.slots, haystack, pos + 1);
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
                                if ((alt_cp < 0x80 and uc.has_ascii_set and uc.ascii_set.contains(@intCast(alt_cp))) or inRanges(alt_cp, ranges)) {
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
                            self.addCapThreadImpl(cap_slots, CapTh, next, &next_len, gen_table, gen, target_pc, &th.slots, haystack, pos + 1);
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

    fn addCapThreadImpl(
        self: *const Regex,
        comptime cap_slots: usize,
        comptime CapTh: type,
        list: []CapTh,
        list_len: *usize,
        gen_table: []u32,
        gen: u32,
        pc: u32,
        slots: *const [cap_slots]usize,
        haystack: []const u8,
        pos: usize,
    ) void {
        if (gen_table[pc] == gen) return;
        gen_table[pc] = gen;

        switch (self.insts[pc]) {
            .jmp => |target| {
                self.addCapThreadImpl(cap_slots, CapTh, list, list_len, gen_table, gen, target, slots, haystack, pos);
            },
            .split => |sp| {
                self.addCapThreadImpl(cap_slots, CapTh, list, list_len, gen_table, gen, sp.out1, slots, haystack, pos);
                self.addCapThreadImpl(cap_slots, CapTh, list, list_len, gen_table, gen, sp.out2, slots, haystack, pos);
            },
            .assert => |as| {
                if (checkAssert(as.kind, haystack, pos)) {
                    self.addCapThreadImpl(cap_slots, CapTh, list, list_len, gen_table, gen, as.out, slots, haystack, pos);
                }
            },
            .save => |sv| {
                var next_slots = slots.*;
                if (sv.slot < cap_slots) next_slots[sv.slot] = pos;
                self.addCapThreadImpl(cap_slots, CapTh, list, list_len, gen_table, gen, sv.out, &next_slots, haystack, pos);
            },
            else => {
                list[list_len.*] = .{ .pc = pc, .slots = slots.* };
                list_len.* += 1;
            },
        }
    }
};

const PrefixAnyTail = struct {
    min_any: u32,
    max_any: ?u32,
    allow_nl: bool,
    is_lazy: bool,
};

const CapOp = union(enum) {
    save: u8,
    lit: struct { off: u8, len: u8, ignore_case: bool },
    class_rep: struct { set: ByteSet, min: u16, max: ?u16, lazy: bool },
    any_rep: struct { min: u16, max: ?u16, allow_nl: bool, lazy: bool },
};

const CapPlan = struct {
    ops: [16]CapOp = undefined,
    len: u8 = 0,
    lit_buf: [64]u8 = undefined,
    lit_len: u8 = 0,
    next_lit_op: [16]u8 = @splat(0xFF),
};

fn skipJmpOnly(insts: []const Inst, start_pc: u32) ?u32 {
    var cur = start_pc;
    var steps: usize = 0;
    while (steps < insts.len + 1) : (steps += 1) {
        if (cur >= insts.len) return null;
        switch (insts[cur]) {
            .jmp => |t| cur = t,
            else => return cur,
        }
    }
    return null;
}

fn byteSetEql(a: ByteSet, b: ByteSet) bool {
    return a.bits[0] == b.bits[0] and a.bits[1] == b.bits[1] and a.bits[2] == b.bits[2] and a.bits[3] == b.bits[3];
}

fn compileCapPlan(self: *const Regex) ?CapPlan {
    if (self.num_captures == 0 or self.num_captures > 8) return null;
    if (self.has_alt) return null;
    if (self.ignore_case and self.unicode_case) return null;
    const insts = self.insts;
    if (insts.len == 0) return null;

    var plan = CapPlan{};
    var cur: u32 = self.start_pc;
    var guard: usize = 0;
    while (guard <= insts.len) : (guard += 1) {
        cur = skipJmpOnly(insts, cur) orelse return null;
        switch (insts[cur]) {
            .match => break,
            .save => |sv| {
                if (plan.len >= plan.ops.len) return null;
                plan.ops[plan.len] = .{ .save = sv.slot };
                plan.len += 1;
                cur = sv.out;
            },
            .byte => |by| {
                // Check for `a+` / `a+?` loop
                const after = skipJmpOnly(insts, by.out) orelse return null;
                if (insts[after] == .split) {
                    const sp = insts[after].split;
                    const o1 = skipJmpOnly(insts, sp.out1) orelse return null;
                    const o2 = skipJmpOnly(insts, sp.out2) orelse return null;
                    if (o1 == cur or o2 == cur) {
                        var bs = ByteSet{};
                        bs.setWithCase(by.b, by.ignore_case);
                        if (plan.len >= plan.ops.len) return null;
                        plan.ops[plan.len] = .{ .class_rep = .{
                            .set = bs,
                            .min = 1,
                            .max = null,
                            .lazy = (o2 == cur),
                        } };
                        plan.len += 1;
                        cur = if (o1 == cur) o2 else o1;
                        continue;
                    }
                }
                // Coalesce into previous `.lit` op if matching ignore_case
                if (plan.len > 0 and plan.ops[plan.len - 1] == .lit and plan.ops[plan.len - 1].lit.ignore_case == by.ignore_case) {
                    if (plan.lit_len >= plan.lit_buf.len) return null;
                    plan.lit_buf[plan.lit_len] = by.b;
                    plan.lit_len += 1;
                    plan.ops[plan.len - 1].lit.len += 1;
                } else {
                    if (plan.len >= plan.ops.len or plan.lit_len >= plan.lit_buf.len) return null;
                    const off = plan.lit_len;
                    plan.lit_buf[plan.lit_len] = by.b;
                    plan.lit_len += 1;
                    plan.ops[plan.len] = .{ .lit = .{ .off = off, .len = 1, .ignore_case = by.ignore_case } };
                    plan.len += 1;
                }
                cur = by.out;
            },
            .class => |cl| {
                if (cl.utf8_negated) return null;
                const after = skipJmpOnly(insts, cl.out) orelse return null;
                if (insts[after] == .split) {
                    const sp = insts[after].split;
                    const o1 = skipJmpOnly(insts, sp.out1) orelse return null;
                    const o2 = skipJmpOnly(insts, sp.out2) orelse return null;
                    if (o1 == cur or o2 == cur) {
                        if (plan.len >= plan.ops.len) return null;
                        plan.ops[plan.len] = .{ .class_rep = .{
                            .set = cl.set,
                            .min = 1,
                            .max = null,
                            .lazy = (o2 == cur),
                        } };
                        plan.len += 1;
                        cur = if (o1 == cur) o2 else o1;
                        continue;
                    }
                }
                // Coalesce consecutive identical required classes into a single class_rep
                if (plan.len > 0 and plan.ops[plan.len - 1] == .class_rep and
                    plan.ops[plan.len - 1].class_rep.max != null and
                    plan.ops[plan.len - 1].class_rep.min == plan.ops[plan.len - 1].class_rep.max.? and
                    byteSetEql(plan.ops[plan.len - 1].class_rep.set, cl.set))
                {
                    plan.ops[plan.len - 1].class_rep.min +|= 1;
                    plan.ops[plan.len - 1].class_rep.max = plan.ops[plan.len - 1].class_rep.min;
                } else {
                    if (plan.len >= plan.ops.len) return null;
                    plan.ops[plan.len] = .{ .class_rep = .{
                        .set = cl.set,
                        .min = 1,
                        .max = 1,
                        .lazy = false,
                    } };
                    plan.len += 1;
                }
                cur = cl.out;
            },
            .any => |an| {
                if (!isStandardAnyContChain(insts, an)) return null;
                const after = skipJmpOnly(insts, an.out) orelse return null;
                if (insts[after] == .split) {
                    const sp = insts[after].split;
                    const o1 = skipJmpOnly(insts, sp.out1) orelse return null;
                    const o2 = skipJmpOnly(insts, sp.out2) orelse return null;
                    if (o1 == cur or o2 == cur) {
                        if (plan.len >= plan.ops.len) return null;
                        plan.ops[plan.len] = .{ .any_rep = .{
                            .min = 1,
                            .max = null,
                            .allow_nl = an.allow_nl,
                            .lazy = (o2 == cur),
                        } };
                        plan.len += 1;
                        cur = if (o1 == cur) o2 else o1;
                        continue;
                    }
                }
                if (plan.len >= plan.ops.len) return null;
                plan.ops[plan.len] = .{ .any_rep = .{
                    .min = 1,
                    .max = 1,
                    .allow_nl = an.allow_nl,
                    .lazy = false,
                } };
                plan.len += 1;
                cur = an.out;
            },
            .split => |sp| {
                const o1 = skipJmpOnly(insts, sp.out1) orelse return null;
                const o2 = skipJmpOnly(insts, sp.out2) orelse return null;
                // Check for `.any` loop (`.*`, `.*?`) or optional (`.?`, `.??`)
                var any_pc: ?u32 = null;
                var exit_pc: u32 = 0;
                var is_lazy = false;
                if (insts[o1] == .any) {
                    any_pc = o1;
                    exit_pc = o2;
                    is_lazy = false;
                } else if (insts[o2] == .any) {
                    any_pc = o2;
                    exit_pc = o1;
                    is_lazy = true;
                }
                if (any_pc) |apc| {
                    const an = insts[apc].any;
                    if (!isStandardAnyContChain(insts, an)) return null;
                    const an_next = skipJmpOnly(insts, an.out) orelse return null;
                    if (an_next == cur) {
                        if (plan.len >= plan.ops.len) return null;
                        plan.ops[plan.len] = .{ .any_rep = .{
                            .min = 0,
                            .max = null,
                            .allow_nl = an.allow_nl,
                            .lazy = is_lazy,
                        } };
                        plan.len += 1;
                        cur = exit_pc;
                        continue;
                    } else if (an_next == exit_pc) {
                        if (plan.len >= plan.ops.len) return null;
                        plan.ops[plan.len] = .{ .any_rep = .{
                            .min = 0,
                            .max = 1,
                            .allow_nl = an.allow_nl,
                            .lazy = is_lazy,
                        } };
                        plan.len += 1;
                        cur = exit_pc;
                        continue;
                    }
                    return null;
                }
                // Check for `.class` loop (`[a-z]*`) or optional (`[a-z]?`)
                var cl_pc: ?u32 = null;
                if (insts[o1] == .class and !insts[o1].class.utf8_negated) {
                    cl_pc = o1;
                    exit_pc = o2;
                    is_lazy = false;
                } else if (insts[o2] == .class and !insts[o2].class.utf8_negated) {
                    cl_pc = o2;
                    exit_pc = o1;
                    is_lazy = true;
                }
                if (cl_pc) |cpc| {
                    const cl = insts[cpc].class;
                    const cl_next = skipJmpOnly(insts, cl.out) orelse return null;
                    if (cl_next == cur) {
                        if (plan.len >= plan.ops.len) return null;
                        plan.ops[plan.len] = .{ .class_rep = .{
                            .set = cl.set,
                            .min = 0,
                            .max = null,
                            .lazy = is_lazy,
                        } };
                        plan.len += 1;
                        cur = exit_pc;
                        continue;
                    } else if (cl_next == exit_pc) {
                        // Coalesce into previous identical bounded class_rep if possible
                        if (plan.len > 0 and plan.ops[plan.len - 1] == .class_rep and
                            plan.ops[plan.len - 1].class_rep.max != null and
                            plan.ops[plan.len - 1].class_rep.lazy == is_lazy and
                            byteSetEql(plan.ops[plan.len - 1].class_rep.set, cl.set))
                        {
                            plan.ops[plan.len - 1].class_rep.max = plan.ops[plan.len - 1].class_rep.max.? +| 1;
                        } else {
                            if (plan.len >= plan.ops.len) return null;
                            plan.ops[plan.len] = .{ .class_rep = .{
                                .set = cl.set,
                                .min = 0,
                                .max = 1,
                                .lazy = is_lazy,
                            } };
                            plan.len += 1;
                        }
                        cur = exit_pc;
                        continue;
                    }
                    return null;
                }
                return null;
            },
            else => return null,
        }
    }
    if (plan.len == 0) return null;
    for (0..plan.len) |i| {
        if (plan.ops[i] == .any_rep) {
            var j = i + 1;
            while (j < plan.len and plan.ops[j] == .save) : (j += 1) {}
            if (j < plan.len and plan.ops[j] == .lit and plan.ops[j].lit.len > 0) {
                plan.next_lit_op[i] = @intCast(j);
            }
        }
    }
    return plan;
}

fn skipZeroWidthJmpSave(insts: []const Inst, start_pc: u32) ?u32 {
    var cur = start_pc;
    var steps: usize = 0;
    while (steps < insts.len + 1) : (steps += 1) {
        if (cur >= insts.len) return null;
        switch (insts[cur]) {
            .jmp => |t| cur = t,
            .save => |sv| cur = sv.out,
            else => return cur,
        }
    }
    return null;
}

fn isStandardAnyContChain(insts: []const Inst, an: anytype) bool {
    if (an.cont1 != 0) {
        if (an.cont1 >= insts.len) return false;
        switch (insts[an.cont1]) {
            .any_cont => |ac| if (ac.out != an.out) return false,
            else => return false,
        }
    }
    if (an.cont2 != 0) {
        if (an.cont2 >= insts.len) return false;
        switch (insts[an.cont2]) {
            .any_cont => |ac| if (ac.out != an.cont1) return false,
            else => return false,
        }
    }
    if (an.cont3 != 0) {
        if (an.cont3 >= insts.len) return false;
        switch (insts[an.cont3]) {
            .any_cont => |ac| if (ac.out != an.cont2) return false,
            else => return false,
        }
    }
    return true;
}

fn matchLiteralByteChain(insts: []const Inst, start_pc: u32, lit: []const u8, ignore_case: bool) ?u32 {
    var cur = start_pc;
    for (lit) |expected| {
        cur = skipZeroWidthJmpSave(insts, cur) orelse return null;
        switch (insts[cur]) {
            .byte => |by| {
                if (ignore_case) {
                    if (std.ascii.toLower(by.b) != std.ascii.toLower(expected)) return null;
                    if (!by.ignore_case and std.ascii.isAlphabetic(expected)) return null;
                } else {
                    if (by.ignore_case or by.b != expected) return null;
                }
                cur = by.out;
            },
            else => return null,
        }
    }
    return cur;
}

fn detectPrefixAnyTail(self: *const Regex) ?PrefixAnyTail {
    if (!self.req_is_prefix or self.prefilter == null or self.tail_finder == null) return null;
    if (self.anchored_start or self.has_alt) return null;
    if (self.req_literal_bytes.len == 0 or self.tail_literal_bytes.len == 0) return null;
    if (self.ignore_case and self.unicode_case) return null;

    const insts = self.insts;
    if (insts.len == 0) return null;

    // 1. Match prefix literal chain
    var cur = matchLiteralByteChain(insts, self.start_pc, self.req_literal_bytes, self.ignore_case) orelse return null;

    // 2. Match `.{min_any, max_any}` / `.*` / `.+` (greedy or lazy)
    var min_any: u32 = 0;
    var opt_any: u32 = 0;
    var unbounded = false;
    var is_lazy = false;
    var saw_opt_mode = false;
    var allow_nl: ?bool = null;

    // Required `.` copies
    while (true) {
        cur = skipZeroWidthJmpSave(insts, cur) orelse return null;
        switch (insts[cur]) {
            .any => |an| {
                if (!isStandardAnyContChain(insts, an)) return null;
                if (allow_nl) |prev| {
                    if (prev != an.allow_nl) return null;
                } else {
                    allow_nl = an.allow_nl;
                }
                min_any +|= 1;
                cur = an.out;
            },
            else => break,
        }
    }

    // Optional `.?` chain or unbounded `.*` loop
    var guard_steps: usize = 0;
    while (guard_steps < insts.len) : (guard_steps += 1) {
        cur = skipZeroWidthJmpSave(insts, cur) orelse return null;
        if (insts[cur] != .split) break;
        const sp = insts[cur].split;
        const o1 = skipZeroWidthJmpSave(insts, sp.out1) orelse return null;
        const o2 = skipZeroWidthJmpSave(insts, sp.out2) orelse return null;

        var any_pc: u32 = 0;
        var exit_pc: u32 = 0;
        var step_lazy = false;
        if (insts[o1] == .any) {
            any_pc = o1;
            exit_pc = o2;
            step_lazy = false;
        } else if (insts[o2] == .any) {
            any_pc = o2;
            exit_pc = o1;
            step_lazy = true;
        } else {
            return null;
        }
        const an = insts[any_pc].any;
        if (!isStandardAnyContChain(insts, an)) return null;
        if (allow_nl) |prev| {
            if (prev != an.allow_nl) return null;
        } else {
            allow_nl = an.allow_nl;
        }
        const any_next = skipZeroWidthJmpSave(insts, an.out) orelse return null;
        if (any_next == cur) {
            // Unbounded `.*` or `.*?`
            if (saw_opt_mode and is_lazy != step_lazy) return null;
            is_lazy = step_lazy;
            unbounded = true;
            cur = exit_pc;
            break;
        } else if (any_next == exit_pc) {
            // Bounded optional `.?` or `.??`
            if (saw_opt_mode and is_lazy != step_lazy) return null;
            saw_opt_mode = true;
            is_lazy = step_lazy;
            opt_any +|= 1;
            cur = exit_pc;
        } else {
            return null;
        }
    }

    const eff_allow = allow_nl orelse return null;
    if (min_any == 0 and opt_any == 0 and !unbounded) return null;

    // 3. Match tail literal chain ending directly at `.match`
    cur = matchLiteralByteChain(insts, cur, self.tail_literal_bytes, self.ignore_case) orelse return null;
    cur = skipZeroWidthJmpSave(insts, cur) orelse return null;
    if (insts[cur] != .match) return null;

    return .{
        .min_any = min_any,
        .max_any = if (unbounded) null else min_any +| opt_any,
        .allow_nl = eff_allow,
        .is_lazy = is_lazy,
    };
}

/// Vectorized single-byte literal prefilter fused with contiguous predecessor/successor byte-range checks.
/// Eliminates high-frequency single-byte false hits (e.g., `[0x80..0xBF]_[0-9]` or `[a-z]=[0-9]`) directly in SIMD.
const ByteContextPrefilter = struct {
    lit: u8,
    has_prev: bool,
    prev_lo: u8,
    prev_span: u8,
    has_next: bool,
    next_lo: u8,
    next_span: u8,

    pub fn find(self: ByteContextPrefilter, haystack: []const u8, pos: usize, min_lit_pos: usize) ?usize {
        var unused: ?usize = null;
        return self.findInner(haystack, pos, min_lit_pos, false, &unused);
    }

    pub fn findWatched(self: ByteContextPrefilter, haystack: []const u8, pos: usize, min_lit_pos: usize, nul: *?usize) ?usize {
        return self.findInner(haystack, pos, min_lit_pos, true, nul);
    }

    fn findInner(
        self: ByteContextPrefilter,
        haystack: []const u8,
        pos: usize,
        min_lit_pos: usize,
        comptime watch_nul: bool,
        nul: *?usize,
    ) ?usize {
        var start_i = @max(pos, min_lit_pos);
        if (self.has_prev and start_i < 1) start_i = 1;
        const end_excl = if (self.has_next) haystack.len -| 1 else haystack.len;
        if (watch_nul and start_i > pos) {
            const pre_lim = @min(start_i, haystack.len);
            if (pos < pre_lim) {
                if (memchr.find(memchr.native_width, haystack[0..pre_lim], pos, 0)) |z| {
                    nul.* = z;
                    return null;
                }
            }
        }
        if (start_i >= end_excl) {
            if (watch_nul and start_i < haystack.len) {
                if (memchr.find(memchr.native_width, haystack, start_i, 0)) |z| nul.* = z;
            }
            return null;
        }
        if (self.has_prev) {
            if (self.has_next) {
                return self.scanLoop(haystack, start_i, end_excl, true, true, watch_nul, nul);
            }
            return self.scanLoop(haystack, start_i, end_excl, true, false, watch_nul, nul);
        }
        return self.scanLoop(haystack, start_i, end_excl, false, true, watch_nul, nul);
    }

    inline fn vecHitMask(
        self: ByteContextPrefilter,
        comptime width: comptime_int,
        haystack: []const u8,
        at: usize,
        comptime has_p: bool,
        comptime has_n: bool,
    ) @Vector(width, bool) {
        const V = @Vector(width, u8);
        const v_cur: V = haystack[at..][0..width].*;
        var m = v_cur == @as(V, @splat(self.lit));
        if (has_p) {
            const v_prev: V = haystack[at - 1 ..][0..width].*;
            m = m & ((v_prev -% @as(V, @splat(self.prev_lo))) <= @as(V, @splat(self.prev_span)));
        }
        if (has_n) {
            const v_next: V = haystack[at + 1 ..][0..width].*;
            m = m & ((v_next -% @as(V, @splat(self.next_lo))) <= @as(V, @splat(self.next_span)));
        }
        return m;
    }

    fn scanLoop(
        self: ByteContextPrefilter,
        haystack: []const u8,
        start_i: usize,
        end_excl: usize,
        comptime has_p: bool,
        comptime has_n: bool,
        comptime watch_nul: bool,
        nul: *?usize,
    ) ?usize {
        const width = memchr.native_width;
        const V = @Vector(width, u8);
        const zero_v: V = @splat(0);
        const stride = width * 4;
        var i = start_i;

        while (i + stride <= end_excl) {
            var masks: [4]@Vector(width, bool) = undefined;
            inline for (0..4) |k| {
                const at = i + k * width;
                var m = self.vecHitMask(width, haystack, at, has_p, has_n);
                if (watch_nul) {
                    const v_cur: V = haystack[at..][0..width].*;
                    m = m | (v_cur == zero_v);
                }
                masks[k] = m;
            }
            if (@reduce(.Or, (masks[0] | masks[1]) | (masks[2] | masks[3]))) {
                @branchHint(.unlikely);
                inline for (0..4) |k| {
                    if (@reduce(.Or, masks[k])) {
                        const at = i + k * width;
                        const h_mask = self.vecHitMask(width, haystack, at, has_p, has_n);
                        if (comptime builtin.cpu.arch.endian() == .little) {
                            const MaskInt = @Int(.unsigned, width);
                            const hbits: MaskInt = @bitCast(h_mask);
                            if (watch_nul) {
                                const v_cur: V = haystack[at..][0..width].*;
                                const zbits: MaskInt = @bitCast(v_cur == zero_v);
                                if (zbits != 0) {
                                    const zrel: usize = @ctz(zbits);
                                    if (hbits == 0 or zrel < @as(usize, @ctz(hbits))) {
                                        nul.* = at + zrel;
                                        return null;
                                    }
                                }
                            }
                            if (hbits != 0) return at + @as(usize, @ctz(hbits));
                        } else {
                            if (watch_nul) {
                                const v_cur: V = haystack[at..][0..width].*;
                                if (std.simd.firstTrue(v_cur == zero_v)) |zrel| {
                                    if (std.simd.firstTrue(h_mask)) |hrel| {
                                        if (hrel < zrel) return at + @as(usize, hrel);
                                    }
                                    nul.* = at + @as(usize, zrel);
                                    return null;
                                }
                            }
                            if (std.simd.firstTrue(h_mask)) |hrel| return at + @as(usize, hrel);
                        }
                    }
                }
            }
            i += stride;
        }

        while (i + width <= end_excl) {
            const h_mask = self.vecHitMask(width, haystack, i, has_p, has_n);
            const v_cur: V = haystack[i..][0..width].*;
            const comb = if (watch_nul) h_mask | (v_cur == zero_v) else h_mask;
            if (@reduce(.Or, comb)) {
                @branchHint(.unlikely);
                if (comptime builtin.cpu.arch.endian() == .little) {
                    const MaskInt = @Int(.unsigned, width);
                    const hbits: MaskInt = @bitCast(h_mask);
                    if (watch_nul) {
                        const zbits: MaskInt = @bitCast(v_cur == zero_v);
                        if (zbits != 0) {
                            const zrel: usize = @ctz(zbits);
                            if (hbits == 0 or zrel < @as(usize, @ctz(hbits))) {
                                nul.* = i + zrel;
                                return null;
                            }
                        }
                    }
                    if (hbits != 0) return i + @as(usize, @ctz(hbits));
                } else {
                    if (watch_nul) {
                        if (std.simd.firstTrue(v_cur == zero_v)) |zrel| {
                            if (std.simd.firstTrue(h_mask)) |hrel| {
                                if (hrel < zrel) return i + @as(usize, hrel);
                            }
                            nul.* = i + @as(usize, zrel);
                            return null;
                        }
                    }
                    if (std.simd.firstTrue(h_mask)) |hrel| return i + @as(usize, hrel);
                }
            }
            i += width;
        }

        while (i < end_excl) : (i += 1) {
            const b = haystack[i];
            if (watch_nul and b == 0) {
                nul.* = i;
                return null;
            }
            if (b == self.lit and
                (!has_p or (haystack[i - 1] -% self.prev_lo) <= self.prev_span) and
                (!has_n or (haystack[i + 1] -% self.next_lo) <= self.next_span))
            {
                return i;
            }
        }
        if (watch_nul and end_excl < haystack.len) {
            if (memchr.find(width, haystack, end_excl, 0)) |z| nul.* = z;
        }
        return null;
    }
};

inline fn matchPrefixUclassReverse(
    haystack: []const u8,
    min_start: usize,
    hit_start: usize,
    uc: anytype,
    ranges: []const inst_mod.CodepointRange,
    min_reps: u8,
) ?usize {
    var cur = hit_start;
    var reps: usize = 0;
    while (cur > min_start) {
        const b_last = haystack[cur - 1];
        if (b_last < 0x80) {
            if (!uc.allow_nl and b_last == '\n') break;
            const in_set = (uc.has_ascii_set and uc.ascii_set.contains(b_last)) or inRanges(b_last, ranges);
            if (if (uc.negated) in_set else !in_set) break;
            cur -= 1;
            reps += 1;
            continue;
        }
        if ((b_last & 0xC0) != 0x80) break;
        if (cur >= min_start + 3 and (haystack[cur - 3] & 0xF0) == 0xE0 and (haystack[cur - 2] & 0xC0) == 0x80) {
            const cp = std.unicode.utf8Decode3(haystack[cur - 3 ..][0..3].*) catch break;
            const in_set = inRanges(cp, ranges);
            if (if (uc.negated) in_set else !in_set) break;
            cur -= 3;
            reps += 1;
            continue;
        }
        if (cur >= min_start + 2 and (haystack[cur - 2] & 0xE0) == 0xC0) {
            const cp = std.unicode.utf8Decode2(haystack[cur - 2 ..][0..2].*) catch break;
            const in_set = inRanges(cp, ranges);
            if (if (uc.negated) in_set else !in_set) break;
            cur -= 2;
            reps += 1;
            continue;
        }
        if (cur >= min_start + 4 and (haystack[cur - 4] & 0xF8) == 0xF0 and
            (haystack[cur - 3] & 0xC0) == 0x80 and (haystack[cur - 2] & 0xC0) == 0x80)
        {
            const cp = std.unicode.utf8Decode4(haystack[cur - 4 ..][0..4].*) catch break;
            const in_set = inRanges(cp, ranges);
            if (if (uc.negated) in_set else !in_set) break;
            cur -= 4;
            reps += 1;
            continue;
        }
        break;
    }
    if (reps >= min_reps) return cur;
    return null;
}

const ContiguousByteRange = struct { lo: u8, span: u8 };

fn extractContiguousByteRange(set: ByteSet) ?ContiguousByteRange {
    var lo: ?u8 = null;
    var hi: u8 = 0;
    var count: usize = 0;
    var b: u16 = 0;
    while (b < 256) : (b += 1) {
        const byte: u8 = @truncate(b);
        if (set.contains(byte)) {
            if (lo == null) lo = byte;
            hi = byte;
            count += 1;
        }
    }
    const start_b = lo orelse return null;
    const span: usize = @as(usize, hi) - @as(usize, start_b);
    if (span + 1 != count or span >= 128) return null;
    return .{ .lo = start_b, .span = @intCast(span) };
}

fn isSuffixSubgraphExact(insts: []const Inst, start_pc: u32) bool {
    const n = insts.len;
    if (n == 0 or n > 256 or start_pc >= n) return false;
    var vis: [256]bool = @splat(false);
    var q: [256]u32 = undefined;
    var head: usize = 0;
    var tail: usize = 0;
    vis[start_pc] = true;
    q[tail] = start_pc;
    tail += 1;
    while (head < tail) {
        const pc = q[head];
        head += 1;
        switch (insts[pc]) {
            .byte => |by| {
                if (by.out < n and !vis[by.out]) {
                    vis[by.out] = true;
                    q[tail] = by.out;
                    tail += 1;
                }
            },
            .class => |cl| {
                if (cl.utf8_negated) return false;
                if (cl.out < n and !vis[cl.out]) {
                    vis[cl.out] = true;
                    q[tail] = cl.out;
                    tail += 1;
                }
            },
            .jmp => |t| {
                if (t < n and !vis[t]) {
                    vis[t] = true;
                    q[tail] = t;
                    tail += 1;
                }
            },
            .split => |s| {
                if (s.out1 < n and !vis[s.out1]) {
                    vis[s.out1] = true;
                    q[tail] = s.out1;
                    tail += 1;
                }
                if (s.out2 < n and !vis[s.out2]) {
                    vis[s.out2] = true;
                    q[tail] = s.out2;
                    tail += 1;
                }
            },
            .save => |sv| {
                if (sv.out < n and !vis[sv.out]) {
                    vis[sv.out] = true;
                    q[tail] = sv.out;
                    tail += 1;
                }
            },
            .match, .match_id => {},
            .assert, .unicode_class, .any, .any_cont => return false,
        }
    }
    return true;
}

fn zeroWidthReaches(insts: []const Inst, from_pc: u32, target_pc: u32) bool {
    const n = insts.len;
    if (n == 0 or n > 256 or from_pc >= n) return false;
    var vis: [256]bool = @splat(false);
    var q: [256]u32 = undefined;
    var head: usize = 0;
    var tail: usize = 0;
    vis[from_pc] = true;
    q[tail] = from_pc;
    tail += 1;
    while (head < tail) {
        const pc = q[head];
        head += 1;
        if (pc == target_pc) return true;
        switch (insts[pc]) {
            .jmp => |t| if (t < n and !vis[t]) {
                vis[t] = true;
                q[tail] = t;
                tail += 1;
            },
            .split => |s| {
                if (s.out1 < n and !vis[s.out1]) {
                    vis[s.out1] = true;
                    q[tail] = s.out1;
                    tail += 1;
                }
                if (s.out2 < n and !vis[s.out2]) {
                    vis[s.out2] = true;
                    q[tail] = s.out2;
                    tail += 1;
                }
            },
            .save => |sv| if (sv.out < n and !vis[sv.out]) {
                vis[sv.out] = true;
                q[tail] = sv.out;
                tail += 1;
            },
            else => {},
        }
    }
    return false;
}

inline fn isAsciiBytes(bytes: []const u8) bool {
    const V = @Vector(memchr.native_width, u8);
    const msb: V = @splat(0x80);
    var i: usize = 0;
    while (i + memchr.native_width <= bytes.len) : (i += memchr.native_width) {
        const v: V = bytes[i..][0..memchr.native_width].*;
        if (@reduce(.Or, (v & msb) != @as(V, @splat(0)))) return false;
    }
    while (i < bytes.len) : (i += 1) {
        if (bytes[i] >= 0x80) return false;
    }
    return true;
}

const LiteralSpanPc = struct {
    start_pc: u32,
    end_pc: u32,
};

fn findUniqueLiteralSpanPc(insts: []const Inst, lit: []const u8) ?LiteralSpanPc {
    if (lit.len == 0 or insts.len < lit.len) return null;
    var found: ?LiteralSpanPc = null;
    var start_idx: usize = 0;
    while (start_idx < insts.len) : (start_idx += 1) {
        var cur: u32 = @intCast(start_idx);
        var k: usize = 0;
        var matched = true;
        while (k < lit.len) : (k += 1) {
            if (cur >= insts.len) {
                matched = false;
                break;
            }
            switch (insts[cur]) {
                .byte => |by| {
                    const ok = if (by.ignore_case)
                        std.ascii.toLower(by.b) == std.ascii.toLower(lit[k])
                    else
                        by.b == lit[k];
                    if (!ok) {
                        matched = false;
                        break;
                    }
                    cur = by.out;
                },
                else => {
                    matched = false;
                    break;
                },
            }
        }
        if (matched) {
            const cand = LiteralSpanPc{ .start_pc = @intCast(start_idx), .end_pc = cur };
            if (found) |prev| {
                if (prev.start_pc != cand.start_pc or prev.end_pc != cand.end_pc) return null;
            }
            found = cand;
        }
    }
    return found;
}

fn isLinearWordBoundaryChain(insts: []const Inst, from_pc: u32, target_pc: ?u32, want_match: bool, wanted_kind: AssertKind) bool {
    var cur = from_pc;
    var saw_wb = false;
    var steps: usize = 0;
    while (steps < insts.len + 1) : (steps += 1) {
        if (target_pc) |tp| {
            if (cur == tp) return saw_wb;
        }
        if (cur >= insts.len) return false;
        switch (insts[cur]) {
            .jmp => |t| cur = t,
            .save => |sv| cur = sv.out,
            .assert => |as| {
                if (as.kind != wanted_kind) return false;
                saw_wb = true;
                cur = as.out;
            },
            .match => return want_match and saw_wb,
            else => return false,
        }
    }
    return false;
}

fn unionByteSet(dst: *ByteSet, src: ByteSet) void {
    for (0..4) |i| dst.bits[i] |= src.bits[i];
}

fn byteSetIsAll(s: ByteSet) bool {
    return (s.bits[0] & s.bits[1] & s.bits[2] & s.bits[3]) == std.math.maxInt(u64);
}

fn byteSetForInst(inst: Inst, unicode_ranges: []const UnicodeRangeList, multiline: bool) struct {
    out_set: ByteSet,
    has_out: bool,
    cont1_set: ByteSet,
    cont2_set: ByteSet,
    cont3_set: ByteSet,
} {
    var out_set = ByteSet{};
    var has_out = false;
    var cont1_set = ByteSet{};
    var cont2_set = ByteSet{};
    var cont3_set = ByteSet{};
    switch (inst) {
        .byte => |by| {
            out_set.setWithCase(by.b, by.ignore_case);
            has_out = true;
        },
        .class => |cl| {
            out_set = cl.set;
            has_out = true;
            if (cl.utf8_negated) {
                cont1_set.setRange(0xC2, 0xDF, false);
                cont2_set.setRange(0xE0, 0xEF, false);
                cont3_set.setRange(0xF0, 0xF4, false);
            }
        },
        .any_cont => {
            out_set.setRange(0x80, 0xBF, false);
            has_out = true;
        },
        .any => |an| {
            out_set.setRange(0x00, 0x7F, false);
            if (!an.allow_nl or !multiline) out_set.clear('\n');
            has_out = true;
            cont1_set.setRange(0xC2, 0xDF, false);
            cont2_set.setRange(0xE0, 0xEF, false);
            cont3_set.setRange(0xF0, 0xF4, false);
        },
        .unicode_class => |uc| {
            if (uc.ignore_case) {
                out_set.setRange(0x00, 0x7F, false);
                if (!uc.allow_nl or !multiline) out_set.clear('\n');
                has_out = true;
            } else {
                const ranges = unicode_ranges[uc.range_idx].ranges;
                var b: u8 = 0;
                while (b < 0x80) : (b += 1) {
                    if ((!uc.allow_nl or !multiline) and b == '\n') continue;
                    const in_set = (uc.has_ascii_set and uc.ascii_set.contains(b)) or inRanges(b, ranges);
                    if (if (uc.negated) !in_set else in_set) {
                        out_set.set(b);
                        has_out = true;
                    }
                }
            }
            cont1_set.setRange(0xC2, 0xDF, false);
            cont2_set.setRange(0xE0, 0xEF, false);
            cont3_set.setRange(0xF0, 0xF4, false);
        },
        else => {},
    }
    return .{
        .out_set = out_set,
        .has_out = has_out,
        .cont1_set = cont1_set,
        .cont2_set = cont2_set,
        .cont3_set = cont3_set,
    };
}

/// Analyzes the compiled NFA subgraph preceding a unique required literal (`lit_start_pc..lit_end_pc`)
/// to derive exact `\b<lit>\b` recognition, bounded `[req_min_before, req_max_before]` windows,
/// 1-byte predecessor rejection (`req_prev_mask`), and backward-scan byte closure (`req_prefix_bytes_mask`).
fn analyzeRequiredLiteralContext(self: *Regex) void {
    const insts = self.insts;
    if (insts.len == 0 or insts.len > 256) return;
    const span_pc = findUniqueLiteralSpanPc(insts, self.req_literal_bytes) orelse return;
    const lit_start = span_pc.start_pc;
    const lit_end = span_pc.end_pc;

    // 1. Exact `\b<literal>\b` (Unicode or ASCII) detection (zero consuming instructions before/after the unique literal chain).
    if (!self.anchored_start) {
        const is_uni_wb = isLinearWordBoundaryChain(insts, self.start_pc, lit_start, false, .word_boundary) and
            isLinearWordBoundaryChain(insts, lit_end, null, true, .word_boundary);
        const is_ascii_wb = !is_uni_wb and
            isLinearWordBoundaryChain(insts, self.start_pc, lit_start, false, .ascii_word_boundary) and
            isLinearWordBoundaryChain(insts, lit_end, null, true, .ascii_word_boundary);
        if (is_uni_wb or is_ascii_wb) {
            const max_len = if (self.ignore_case and self.unicode_case) self.req_literal_bytes.len *| 3 else self.req_literal_bytes.len;
            if (!self.multiline or max_len <= self.max_multiline_window) {
                self.req_word_bounded = true;
                self.req_word_bounded_ascii = is_ascii_wb;
                return;
            }
        }
    }

    const n = insts.len;
    // 2. Compute nodes reachable from `start_pc` without crossing `lit_start`, and nodes that can reach `lit_start`.
    var fwd: [256]bool = @splat(false);
    var queue: [256]u32 = undefined;
    var q_head: usize = 0;
    var q_tail: usize = 0;
    fwd[self.start_pc] = true;
    queue[q_tail] = self.start_pc;
    q_tail += 1;

    while (q_head < q_tail) {
        const pc = queue[q_head];
        q_head += 1;
        if (pc == lit_start) continue;
        const add = struct {
            fn push(target: u32, lim: usize, vis: *[256]bool, q: *[256]u32, tail: *usize) void {
                if (target < lim and !vis[target]) {
                    vis[target] = true;
                    q[tail.*] = target;
                    tail.* += 1;
                }
            }
        }.push;
        switch (insts[pc]) {
            .jmp => |t| add(t, n, &fwd, &queue, &q_tail),
            .split => |s| {
                add(s.out1, n, &fwd, &queue, &q_tail);
                add(s.out2, n, &fwd, &queue, &q_tail);
            },
            .save => |sv| add(sv.out, n, &fwd, &queue, &q_tail),
            .assert => |as| add(as.out, n, &fwd, &queue, &q_tail),
            .byte => |by| add(by.out, n, &fwd, &queue, &q_tail),
            .any_cont => |ac| add(ac.out, n, &fwd, &queue, &q_tail),
            .class => |cl| {
                add(cl.out, n, &fwd, &queue, &q_tail);
                if (cl.utf8_negated) {
                    if (cl.cont1 != 0) add(cl.cont1, n, &fwd, &queue, &q_tail);
                    if (cl.cont2 != 0) add(cl.cont2, n, &fwd, &queue, &q_tail);
                    if (cl.cont3 != 0) add(cl.cont3, n, &fwd, &queue, &q_tail);
                }
            },
            .any => |an| {
                add(an.out, n, &fwd, &queue, &q_tail);
                if (an.cont1 != 0) add(an.cont1, n, &fwd, &queue, &q_tail);
                if (an.cont2 != 0) add(an.cont2, n, &fwd, &queue, &q_tail);
                if (an.cont3 != 0) add(an.cont3, n, &fwd, &queue, &q_tail);
            },
            .unicode_class => |uc| {
                const bs = byteSetForInst(insts[pc], self.unicode_ranges, self.multiline);
                if (bs.has_out) add(uc.out, n, &fwd, &queue, &q_tail);
                if (uc.cont1 != 0) add(uc.cont1, n, &fwd, &queue, &q_tail);
                if (uc.cont2 != 0) add(uc.cont2, n, &fwd, &queue, &q_tail);
                if (uc.cont3 != 0) add(uc.cont3, n, &fwd, &queue, &q_tail);
            },
            .match, .match_id => {},
        }
    }
    if (!fwd[lit_start]) return;

    // Reverse reachability to `lit_start` (all nodes that can reach `lit_start` without crossing `lit_start` first),
    // plus zero-width reverse reachability to `lit_start` (to identify immediate predecessor consuming instructions).
    var can_reach: [256]bool = @splat(false);
    var zero_to_lit: [256]bool = @splat(false);
    can_reach[lit_start] = true;
    zero_to_lit[lit_start] = true;

    var changed = true;
    while (changed) {
        changed = false;
        for (0..n) |idx| {
            if (!fwd[idx] or idx == lit_start) continue;
            switch (insts[idx]) {
                .jmp => |t| {
                    if (t < n and can_reach[t] and !can_reach[idx]) {
                        can_reach[idx] = true;
                        changed = true;
                    }
                    if (t < n and zero_to_lit[t] and !zero_to_lit[idx]) {
                        zero_to_lit[idx] = true;
                        changed = true;
                    }
                },
                .split => |s| {
                    if (((s.out1 < n and can_reach[s.out1]) or (s.out2 < n and can_reach[s.out2])) and !can_reach[idx]) {
                        can_reach[idx] = true;
                        changed = true;
                    }
                    if (((s.out1 < n and zero_to_lit[s.out1]) or (s.out2 < n and zero_to_lit[s.out2])) and !zero_to_lit[idx]) {
                        zero_to_lit[idx] = true;
                        changed = true;
                    }
                },
                .save => |sv| {
                    if (sv.out < n and can_reach[sv.out] and !can_reach[idx]) {
                        can_reach[idx] = true;
                        changed = true;
                    }
                    if (sv.out < n and zero_to_lit[sv.out] and !zero_to_lit[idx]) {
                        zero_to_lit[idx] = true;
                        changed = true;
                    }
                },
                .assert => |as| {
                    if (as.out < n and can_reach[as.out] and !can_reach[idx]) {
                        can_reach[idx] = true;
                        changed = true;
                    }
                    if (as.out < n and zero_to_lit[as.out] and !zero_to_lit[idx]) {
                        zero_to_lit[idx] = true;
                        changed = true;
                    }
                },
                .byte => |by| {
                    if (by.out < n and can_reach[by.out] and !can_reach[idx]) {
                        can_reach[idx] = true;
                        changed = true;
                    }
                },
                .any_cont => |ac| {
                    if (ac.out < n and can_reach[ac.out] and !can_reach[idx]) {
                        can_reach[idx] = true;
                        changed = true;
                    }
                },
                .class => |cl| {
                    const hit_out = (cl.out < n and can_reach[cl.out]) or
                        (cl.utf8_negated and ((cl.cont1 != 0 and cl.cont1 < n and can_reach[cl.cont1]) or
                            (cl.cont2 != 0 and cl.cont2 < n and can_reach[cl.cont2]) or
                            (cl.cont3 != 0 and cl.cont3 < n and can_reach[cl.cont3])));
                    if (hit_out and !can_reach[idx]) {
                        can_reach[idx] = true;
                        changed = true;
                    }
                },
                .any => |an| {
                    const hit_out = (an.out < n and can_reach[an.out]) or
                        (an.cont1 != 0 and an.cont1 < n and can_reach[an.cont1]) or
                        (an.cont2 != 0 and an.cont2 < n and can_reach[an.cont2]) or
                        (an.cont3 != 0 and an.cont3 < n and can_reach[an.cont3]);
                    if (hit_out and !can_reach[idx]) {
                        can_reach[idx] = true;
                        changed = true;
                    }
                },
                .unicode_class => |uc| {
                    const bs = byteSetForInst(insts[idx], self.unicode_ranges, self.multiline);
                    const hit_out = (bs.has_out and uc.out < n and can_reach[uc.out]) or
                        (uc.cont1 != 0 and uc.cont1 < n and can_reach[uc.cont1]) or
                        (uc.cont2 != 0 and uc.cont2 < n and can_reach[uc.cont2]) or
                        (uc.cont3 != 0 and uc.cont3 < n and can_reach[uc.cont3]);
                    if (hit_out and !can_reach[idx]) {
                        can_reach[idx] = true;
                        changed = true;
                    }
                },
                .match, .match_id => {},
            }
        }
    }

    // 3. Bellman-Ford for exact shortest (`min_dist`) and longest (`max_dist`) byte length from `start_pc` to `lit_start`.
    const inf: u32 = std.math.maxInt(u32);
    var min_dist: [256]u32 = @splat(inf);
    var max_dist: [256]i32 = @splat(-1);
    min_dist[self.start_pc] = 0;
    max_dist[self.start_pc] = 0;

    var max_unbounded = false;
    var iter: usize = 0;
    while (iter < n + 1) : (iter += 1) {
        var any_update = false;
        for (0..n) |idx| {
            if (!can_reach[idx] or idx == lit_start) continue;
            const d_min = min_dist[idx];
            const d_max = max_dist[idx];
            if (d_min == inf and d_max < 0) continue;

            const relax = struct {
                fn edge(target: u32, cost: u32, lim: usize, reach: *const [256]bool, dm: u32, dx: i32, mins: *[256]u32, maxs: *[256]i32, is_last: bool, unb: *bool, upd: *bool) void {
                    if (target >= lim or !reach[target]) return;
                    if (dm != std.math.maxInt(u32)) {
                        const cand = dm +| cost;
                        if (cand < mins[target]) {
                            mins[target] = cand;
                            upd.* = true;
                        }
                    }
                    if (dx >= 0) {
                        const cand_max = dx + @as(i32, @intCast(cost));
                        if (cand_max > maxs[target]) {
                            if (is_last and cost > 0) {
                                unb.* = true;
                            } else {
                                maxs[target] = cand_max;
                                upd.* = true;
                            }
                        }
                    }
                }
            }.edge;

            const is_last = (iter == n);
            switch (insts[idx]) {
                .jmp => |t| relax(t, 0, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update),
                .split => |s| {
                    relax(s.out1, 0, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update);
                    relax(s.out2, 0, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update);
                },
                .save => |sv| relax(sv.out, 0, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update),
                .assert => |as| relax(as.out, 0, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update),
                .byte => |by| relax(by.out, 1, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update),
                .any_cont => |ac| relax(ac.out, 1, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update),
                .class => |cl| {
                    relax(cl.out, 1, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update);
                    if (cl.utf8_negated) {
                        if (cl.cont1 != 0) relax(cl.cont1, 1, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update);
                        if (cl.cont2 != 0) relax(cl.cont2, 1, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update);
                        if (cl.cont3 != 0) relax(cl.cont3, 1, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update);
                    }
                },
                .any => |an| {
                    relax(an.out, 1, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update);
                    if (an.cont1 != 0) relax(an.cont1, 1, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update);
                    if (an.cont2 != 0) relax(an.cont2, 1, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update);
                    if (an.cont3 != 0) relax(an.cont3, 1, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update);
                },
                .unicode_class => |uc| {
                    const bs = byteSetForInst(insts[idx], self.unicode_ranges, self.multiline);
                    if (bs.has_out) relax(uc.out, 1, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update);
                    if (uc.cont1 != 0) relax(uc.cont1, 1, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update);
                    if (uc.cont2 != 0) relax(uc.cont2, 1, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update);
                    if (uc.cont3 != 0) relax(uc.cont3, 1, n, &can_reach, d_min, d_max, &min_dist, &max_dist, is_last, &max_unbounded, &any_update);
                },
                .match, .match_id => {},
            }
        }
        if (!any_update) break;
    }

    if (min_dist[lit_start] != inf) {
        self.req_min_before = min_dist[lit_start];
    }
    if (!max_unbounded and max_dist[lit_start] >= 0) {
        self.req_max_before = @intCast(max_dist[lit_start]);
    }

    // 4. Collect `req_prev_mask` (immediate predecessor bytes when empty prefix is impossible) and
    //    `req_prefix_bytes_mask` (union of all bytes consumable on paths from `start_pc` to `lit_start`).
    var prev_mask = ByteSet{};
    var prefix_bytes = ByteSet{};
    var any_prev = false;
    var any_prefix_bytes = false;

    for (0..n) |idx| {
        if (!can_reach[idx] or idx == lit_start) continue;
        const bs = byteSetForInst(insts[idx], self.unicode_ranges, self.multiline);
        switch (insts[idx]) {
            .byte => |by| {
                if (by.out < n and can_reach[by.out]) {
                    unionByteSet(&prefix_bytes, bs.out_set);
                    any_prefix_bytes = true;
                    if (zero_to_lit[by.out]) {
                        unionByteSet(&prev_mask, bs.out_set);
                        any_prev = true;
                    }
                }
            },
            .any_cont => |ac| {
                if (ac.out < n and can_reach[ac.out]) {
                    unionByteSet(&prefix_bytes, bs.out_set);
                    any_prefix_bytes = true;
                    if (zero_to_lit[ac.out]) {
                        unionByteSet(&prev_mask, bs.out_set);
                        any_prev = true;
                    }
                }
            },
            .class => |cl| {
                if (cl.out < n and can_reach[cl.out]) {
                    unionByteSet(&prefix_bytes, bs.out_set);
                    any_prefix_bytes = true;
                    if (zero_to_lit[cl.out]) {
                        unionByteSet(&prev_mask, bs.out_set);
                        any_prev = true;
                    }
                }
                if (cl.utf8_negated) {
                    if (cl.cont1 != 0 and cl.cont1 < n and can_reach[cl.cont1]) {
                        unionByteSet(&prefix_bytes, bs.cont1_set);
                        any_prefix_bytes = true;
                    }
                    if (cl.cont2 != 0 and cl.cont2 < n and can_reach[cl.cont2]) {
                        unionByteSet(&prefix_bytes, bs.cont2_set);
                        any_prefix_bytes = true;
                    }
                    if (cl.cont3 != 0 and cl.cont3 < n and can_reach[cl.cont3]) {
                        unionByteSet(&prefix_bytes, bs.cont3_set);
                        any_prefix_bytes = true;
                    }
                }
            },
            .any => |an| {
                if (an.out < n and can_reach[an.out]) {
                    unionByteSet(&prefix_bytes, bs.out_set);
                    any_prefix_bytes = true;
                    if (zero_to_lit[an.out]) {
                        unionByteSet(&prev_mask, bs.out_set);
                        any_prev = true;
                    }
                }
                if (an.cont1 != 0 and an.cont1 < n and can_reach[an.cont1]) {
                    unionByteSet(&prefix_bytes, bs.cont1_set);
                    any_prefix_bytes = true;
                }
                if (an.cont2 != 0 and an.cont2 < n and can_reach[an.cont2]) {
                    unionByteSet(&prefix_bytes, bs.cont2_set);
                    any_prefix_bytes = true;
                }
                if (an.cont3 != 0 and an.cont3 < n and can_reach[an.cont3]) {
                    unionByteSet(&prefix_bytes, bs.cont3_set);
                    any_prefix_bytes = true;
                }
            },
            .unicode_class => |uc| {
                if (bs.has_out and uc.out < n and can_reach[uc.out]) {
                    unionByteSet(&prefix_bytes, bs.out_set);
                    any_prefix_bytes = true;
                    if (zero_to_lit[uc.out]) {
                        unionByteSet(&prev_mask, bs.out_set);
                        any_prev = true;
                    }
                }
                if (uc.cont1 != 0 and uc.cont1 < n and can_reach[uc.cont1]) {
                    unionByteSet(&prefix_bytes, bs.cont1_set);
                    any_prefix_bytes = true;
                }
                if (uc.cont2 != 0 and uc.cont2 < n and can_reach[uc.cont2]) {
                    unionByteSet(&prefix_bytes, bs.cont2_set);
                    any_prefix_bytes = true;
                }
                if (uc.cont3 != 0 and uc.cont3 < n and can_reach[uc.cont3]) {
                    unionByteSet(&prefix_bytes, bs.cont3_set);
                    any_prefix_bytes = true;
                }
            },
            else => {},
        }
    }

    if (!zero_to_lit[self.start_pc] and any_prev and !byteSetIsAll(prev_mask) and self.req_min_before >= 1) {
        self.req_has_prev_mask = true;
        self.req_prev_mask = prev_mask;
        self.req_prev_masks[0] = prev_mask;
        self.req_prev_mask_len = 1;

        // Extend reverse predecessor masks to distances d=2 and d=3 (strictly within `req_min_before`).
        var reach_d: [256]bool = zero_to_lit;
        var d: usize = 1;
        while (d < 3 and d + 1 <= self.req_min_before) : (d += 1) {
            var next_reach: [256]bool = @splat(false);
            // Step backward across 1 consuming edge from `reach_d`
            for (0..n) |idx| {
                if (!can_reach[idx] or idx == lit_start) continue;
                switch (insts[idx]) {
                    .byte => |by| if (by.out < n and reach_d[by.out]) {
                        next_reach[idx] = true;
                    },
                    .any_cont => |ac| if (ac.out < n and reach_d[ac.out]) {
                        next_reach[idx] = true;
                    },
                    .class => |cl| {
                        const hit_c = (cl.out < n and reach_d[cl.out]) or
                            (cl.utf8_negated and ((cl.cont1 != 0 and cl.cont1 < n and reach_d[cl.cont1]) or
                                (cl.cont2 != 0 and cl.cont2 < n and reach_d[cl.cont2]) or
                                (cl.cont3 != 0 and cl.cont3 < n and reach_d[cl.cont3])));
                        if (hit_c) next_reach[idx] = true;
                    },
                    .any => |an| {
                        const hit_a = (an.out < n and reach_d[an.out]) or
                            (an.cont1 != 0 and an.cont1 < n and reach_d[an.cont1]) or
                            (an.cont2 != 0 and an.cont2 < n and reach_d[an.cont2]) or
                            (an.cont3 != 0 and an.cont3 < n and reach_d[an.cont3]);
                        if (hit_a) next_reach[idx] = true;
                    },
                    .unicode_class => |uc| {
                        const bs = byteSetForInst(insts[idx], self.unicode_ranges, self.multiline);
                        const hit_u = (bs.has_out and uc.out < n and reach_d[uc.out]) or
                            (uc.cont1 != 0 and uc.cont1 < n and reach_d[uc.cont1]) or
                            (uc.cont2 != 0 and uc.cont2 < n and reach_d[uc.cont2]) or
                            (uc.cont3 != 0 and uc.cont3 < n and reach_d[uc.cont3]);
                        if (hit_u) next_reach[idx] = true;
                    },
                    else => {},
                }
            }
            // Propagate backward across zero-width edges
            var z_changed = true;
            while (z_changed) {
                z_changed = false;
                for (0..n) |idx| {
                    if (!can_reach[idx] or idx == lit_start or next_reach[idx]) continue;
                    switch (insts[idx]) {
                        .jmp => |t| if (t < n and next_reach[t]) {
                            next_reach[idx] = true;
                            z_changed = true;
                        },
                        .split => |s| if ((s.out1 < n and next_reach[s.out1]) or (s.out2 < n and next_reach[s.out2])) {
                            next_reach[idx] = true;
                            z_changed = true;
                        },
                        .save => |sv| if (sv.out < n and next_reach[sv.out]) {
                            next_reach[idx] = true;
                            z_changed = true;
                        },
                        .assert => |as| if (as.out < n and next_reach[as.out]) {
                            next_reach[idx] = true;
                            z_changed = true;
                        },
                        else => {},
                    }
                }
            }
            if (next_reach[self.start_pc]) break;
            var mask_d = ByteSet{};
            var any_d = false;
            for (0..n) |idx| {
                if (!can_reach[idx] or idx == lit_start) continue;
                const bs = byteSetForInst(insts[idx], self.unicode_ranges, self.multiline);
                switch (insts[idx]) {
                    .byte => |by| if (by.out < n and next_reach[by.out]) {
                        unionByteSet(&mask_d, bs.out_set);
                        any_d = true;
                    },
                    .any_cont => |ac| if (ac.out < n and next_reach[ac.out]) {
                        unionByteSet(&mask_d, bs.out_set);
                        any_d = true;
                    },
                    .class => |cl| {
                        if (cl.out < n and next_reach[cl.out]) {
                            unionByteSet(&mask_d, bs.out_set);
                            any_d = true;
                        }
                        if (cl.utf8_negated) {
                            if (cl.cont1 != 0 and cl.cont1 < n and next_reach[cl.cont1]) {
                                unionByteSet(&mask_d, bs.cont1_set);
                                any_d = true;
                            }
                            if (cl.cont2 != 0 and cl.cont2 < n and next_reach[cl.cont2]) {
                                unionByteSet(&mask_d, bs.cont2_set);
                                any_d = true;
                            }
                            if (cl.cont3 != 0 and cl.cont3 < n and next_reach[cl.cont3]) {
                                unionByteSet(&mask_d, bs.cont3_set);
                                any_d = true;
                            }
                        }
                    },
                    .any => |an| {
                        if (an.out < n and next_reach[an.out]) {
                            unionByteSet(&mask_d, bs.out_set);
                            any_d = true;
                        }
                        if (an.cont1 != 0 and an.cont1 < n and next_reach[an.cont1]) {
                            unionByteSet(&mask_d, bs.cont1_set);
                            any_d = true;
                        }
                        if (an.cont2 != 0 and an.cont2 < n and next_reach[an.cont2]) {
                            unionByteSet(&mask_d, bs.cont2_set);
                            any_d = true;
                        }
                        if (an.cont3 != 0 and an.cont3 < n and next_reach[an.cont3]) {
                            unionByteSet(&mask_d, bs.cont3_set);
                            any_d = true;
                        }
                    },
                    .unicode_class => |uc| {
                        if (bs.has_out and uc.out < n and next_reach[uc.out]) {
                            unionByteSet(&mask_d, bs.out_set);
                            any_d = true;
                        }
                        if (uc.cont1 != 0 and uc.cont1 < n and next_reach[uc.cont1]) {
                            unionByteSet(&mask_d, bs.cont1_set);
                            any_d = true;
                        }
                        if (uc.cont2 != 0 and uc.cont2 < n and next_reach[uc.cont2]) {
                            unionByteSet(&mask_d, bs.cont2_set);
                            any_d = true;
                        }
                        if (uc.cont3 != 0 and uc.cont3 < n and next_reach[uc.cont3]) {
                            unionByteSet(&mask_d, bs.cont3_set);
                            any_d = true;
                        }
                    },
                    else => {},
                }
            }
            if (!any_d or byteSetIsAll(mask_d)) break;
            self.req_prev_masks[d] = mask_d;
            self.req_prev_mask_len = @intCast(d + 1);
            reach_d = next_reach;
        }

        // If `req_literal_bytes` is a single byte and preceding byte masks have small cardinality (e.g. `(a|b){15}c`),
        // promote up to 3 preceding bytes into a 2..4-byte `Multi` prefilter (up to 16 patterns -> AVX2 Teddy for >4).
        if (self.req_literal_bytes.len == 1 and !self.ignore_case and !self.multiline) {
            var prev_lists: [3][8]u8 = undefined;
            var prev_counts: [3]usize = .{ 0, 0, 0 };
            var prefix_len: usize = 0;
            var product: usize = 1;
            const max_d: usize = @min(@as(usize, self.req_prev_mask_len), 3);
            var d_idx: usize = 0;
            while (d_idx < max_d) : (d_idx += 1) {
                var cnt: usize = 0;
                var ok_d = true;
                var b: u16 = 0;
                while (b < 256) : (b += 1) {
                    const byte: u8 = @truncate(b);
                    if (self.req_prev_masks[d_idx].contains(byte)) {
                        if (byte == '\n' or cnt >= 8) {
                            ok_d = false;
                            break;
                        }
                        prev_lists[d_idx][cnt] = byte;
                        cnt += 1;
                    }
                }
                if (!ok_d or cnt == 0) break;
                const next_prod = product * cnt;
                if (next_prod > 16) break;
                prev_counts[d_idx] = cnt;
                product = next_prod;
                prefix_len = d_idx + 1;
            }
            if (prefix_len >= 1) {
                if (self.allocator.alloc([]const u8, product)) |slices| {
                    var built: usize = 0;
                    var alloc_ok = true;
                    const pat_len = prefix_len + 1;
                    for (0..product) |idx| {
                        if (self.allocator.alloc(u8, pat_len)) |pat_buf| {
                            var rem = idx;
                            for (0..prefix_len) |di| {
                                const c = prev_counts[di];
                                pat_buf[prefix_len - 1 - di] = prev_lists[di][rem % c];
                                rem /= c;
                            }
                            pat_buf[prefix_len] = self.req_literal_bytes[0];
                            slices[idx] = pat_buf;
                            built += 1;
                        } else |_| {
                            alloc_ok = false;
                            break;
                        }
                    }
                    if (alloc_ok) {
                        if (Multi.init(self.allocator, slices, .{ .case = .sensitive, .multiline = false })) |m| {
                            self.pair_prefilter_slices = slices;
                            self.pair_prefilter = m;
                            self.pair_prefilter_prefix_len = @intCast(prefix_len);
                        } else |_| {
                            for (slices) |s| self.allocator.free(s);
                            self.allocator.free(slices);
                        }
                    } else {
                        for (slices[0..built]) |s| self.allocator.free(s);
                        self.allocator.free(slices);
                    }
                } else |_| {}
            }
        }
    }
    if (any_prefix_bytes and !byteSetIsAll(prefix_bytes)) {
        self.req_has_prefix_bytes_mask = true;
        self.req_prefix_bytes_mask = prefix_bytes;
    }

    // 5. Check whether the suffix DFA after `lit_end` is byte-exact, and whether the prefix before `lit_start`
    //    is strictly a repeated single `.unicode_class` (`+` or `*`) disjoint from `req_literal_bytes[0]`.
    if (self.dfa_suffix_state != 0 and !self.has_lazy and !self.has_alt and !self.anchored_start and !self.multiline) {
        self.dfa_suffix_is_exact = isSuffixSubgraphExact(insts, lit_end);
        if (self.dfa_suffix_is_exact and self.precomputed_dfa != null and self.req_literal_bytes[0] < 0x80) {
            var uc_pc: u32 = std.math.maxInt(u32);
            var uc_count: usize = 0;
            var pure_uclass = true;
            for (0..n) |idx| {
                if (!can_reach[idx] or idx == lit_start) continue;
                switch (insts[idx]) {
                    .jmp, .split, .save, .any_cont => {},
                    .unicode_class => {
                        uc_pc = @intCast(idx);
                        uc_count += 1;
                    },
                    else => {
                        pure_uclass = false;
                        break;
                    },
                }
            }
            if (pure_uclass and uc_count == 1) {
                const uc = insts[uc_pc].unicode_class;
                // Ensure every reachable `.any_cont` belongs exclusively to this `uc_pc`.
                for (0..n) |idx| {
                    if (!can_reach[idx] or idx == lit_start) continue;
                    if (insts[idx] == .any_cont) {
                        const ipc: u32 = @intCast(idx);
                        if (ipc != uc.cont1 and ipc != uc.cont2 and ipc != uc.cont3) {
                            pure_uclass = false;
                            break;
                        }
                    }
                }
                if (pure_uclass and !uc.ignore_case and
                    zeroWidthReaches(insts, self.start_pc, uc_pc) and
                    zeroWidthReaches(insts, uc.out, uc_pc) and
                    zeroWidthReaches(insts, uc.out, lit_start))
                {
                    const lit0 = self.req_literal_bytes[0];
                    const ranges = self.unicode_ranges[uc.range_idx].ranges;
                    const in_set = (uc.has_ascii_set and uc.ascii_set.contains(lit0)) or inRanges(lit0, ranges);
                    const uc_matches_lit0 = if (uc.negated) !in_set else in_set;
                    if (!uc_matches_lit0) {
                        self.req_prefix_uclass_pc = uc_pc;
                        self.req_prefix_uclass_min = if (zero_to_lit[self.start_pc]) 0 else 1;
                    }
                }
            }
        }
    }

    // 6. Build SIMD single-byte + contiguous prev/next byte-range prefilter when `pair_prefilter` was not built.
    if (self.pair_prefilter == null and self.req_literal_bytes.len == 1 and !self.ignore_case and !self.multiline) {
        const prev_rng = if (self.req_has_prev_mask) extractContiguousByteRange(self.req_prev_masks[0]) else null;
        var next_rng: ?ContiguousByteRange = null;
        if (self.dfa_suffix_state != 0) {
            if (self.precomputed_dfa) |dfa| {
                if (!dfa.is_match[self.dfa_suffix_state]) {
                    var next_set = ByteSet{};
                    var b: u16 = 0;
                    while (b < 256) : (b += 1) {
                        const byte: u8 = @truncate(b);
                        if (dfa.trans[self.dfa_suffix_state][byte] != dfa_mod.dead_state) {
                            next_set.set(byte);
                        }
                    }
                    next_rng = extractContiguousByteRange(next_set);
                }
            }
        }
        if (prev_rng != null or next_rng != null) {
            self.byte_ctx_prefilter = .{
                .lit = self.req_literal_bytes[0],
                .has_prev = prev_rng != null,
                .prev_lo = if (prev_rng) |r| r.lo else 0,
                .prev_span = if (prev_rng) |r| r.span else 0,
                .has_next = next_rng != null,
                .next_lo = if (next_rng) |r| r.lo else 0,
                .next_span = if (next_rng) |r| r.span else 0,
            };
        }
    }
}

fn instCanMatchNewline(inst: Inst, unicode_ranges: []const UnicodeRangeList, multiline: bool) bool {
    return switch (inst) {
        .byte => |by| by.b == '\n',
        .class => |cl| multiline and cl.set.contains('\n'),
        .any => |an| multiline and an.allow_nl,
        .unicode_class => |uc| blk: {
            if (!uc.allow_nl) break :blk false;
            const ranges = unicode_ranges[uc.range_idx].ranges;
            const in_set = (uc.has_ascii_set and uc.ascii_set.contains('\n')) or inst_mod.inRanges('\n', ranges);
            break :blk if (uc.negated) !in_set else in_set;
        },
        else => false,
    };
}

fn computeMaxNewlines(
    insts: []const Inst,
    unicode_ranges: []const UnicodeRangeList,
    start_pc: u32,
    multiline: bool,
) ?u32 {
    if (!multiline) return 0;
    const n = insts.len;
    if (n == 0 or n > 512 or start_pc >= n) return null;
    const unreached: i32 = -1;
    var dist: [512]i32 = @splat(unreached);
    dist[start_pc] = 0;

    var iter: usize = 0;
    var changed = true;
    while (iter <= n and changed) : (iter += 1) {
        changed = false;
        for (insts[0..n], 0..) |inst, u| {
            const d = dist[u];
            if (d < 0) continue;
            const w: i32 = if (instCanMatchNewline(inst, unicode_ranges, multiline)) 1 else 0;
            const nd = d + w;
            switch (inst) {
                .byte => |by| {
                    if (by.out < n and nd > dist[by.out]) {
                        dist[by.out] = nd;
                        changed = true;
                    }
                },
                .any => |an| {
                    if (an.out < n and nd > dist[an.out]) {
                        dist[an.out] = nd;
                        changed = true;
                    }
                    if (an.cont1 != 0 and an.cont1 < n and nd > dist[an.cont1]) {
                        dist[an.cont1] = nd;
                        changed = true;
                    }
                    if (an.cont2 != 0 and an.cont2 < n and nd > dist[an.cont2]) {
                        dist[an.cont2] = nd;
                        changed = true;
                    }
                    if (an.cont3 != 0 and an.cont3 < n and nd > dist[an.cont3]) {
                        dist[an.cont3] = nd;
                        changed = true;
                    }
                },
                .any_cont => |ac| {
                    if (ac.out < n and nd > dist[ac.out]) {
                        dist[ac.out] = nd;
                        changed = true;
                    }
                },
                .class => |cl| {
                    if (cl.out < n and nd > dist[cl.out]) {
                        dist[cl.out] = nd;
                        changed = true;
                    }
                    if (cl.cont1 != 0 and cl.cont1 < n and nd > dist[cl.cont1]) {
                        dist[cl.cont1] = nd;
                        changed = true;
                    }
                    if (cl.cont2 != 0 and cl.cont2 < n and nd > dist[cl.cont2]) {
                        dist[cl.cont2] = nd;
                        changed = true;
                    }
                    if (cl.cont3 != 0 and cl.cont3 < n and nd > dist[cl.cont3]) {
                        dist[cl.cont3] = nd;
                        changed = true;
                    }
                },
                .unicode_class => |uc| {
                    if (uc.out < n and nd > dist[uc.out]) {
                        dist[uc.out] = nd;
                        changed = true;
                    }
                    if (uc.cont1 != 0 and uc.cont1 < n and nd > dist[uc.cont1]) {
                        dist[uc.cont1] = nd;
                        changed = true;
                    }
                    if (uc.cont2 != 0 and uc.cont2 < n and nd > dist[uc.cont2]) {
                        dist[uc.cont2] = nd;
                        changed = true;
                    }
                    if (uc.cont3 != 0 and uc.cont3 < n and nd > dist[uc.cont3]) {
                        dist[uc.cont3] = nd;
                        changed = true;
                    }
                },
                .jmp => |target| {
                    if (target < n and nd > dist[target]) {
                        dist[target] = nd;
                        changed = true;
                    }
                },
                .split => |s| {
                    if (s.out1 < n and nd > dist[s.out1]) {
                        dist[s.out1] = nd;
                        changed = true;
                    }
                    if (s.out2 < n and nd > dist[s.out2]) {
                        dist[s.out2] = nd;
                        changed = true;
                    }
                },
                .assert => |a| {
                    if (a.out < n and nd > dist[a.out]) {
                        dist[a.out] = nd;
                        changed = true;
                    }
                },
                .save => |sv| {
                    if (sv.out < n and nd > dist[sv.out]) {
                        dist[sv.out] = nd;
                        changed = true;
                    }
                },
                .match, .match_id => {},
            }
        }
    }
    if (changed) return null; // Positive-weight cycle (unbounded newlines)

    var max_nl: i32 = 0;
    var found_match = false;
    for (insts[0..n], 0..) |inst, u| {
        switch (inst) {
            .match, .match_id => {
                if (dist[u] >= 0) {
                    found_match = true;
                    if (dist[u] > max_nl) max_nl = dist[u];
                }
            },
            else => {},
        }
    }
    if (!found_match) return 0;
    return @intCast(max_nl);
}

test "precomputed DFA fast path preserves exact semantics on repeated prefixes, assertions, and alternations" {
    const alloc = std.testing.allocator;

    // 1. Repeated prefix on the same line where the first candidate fails
    {
        var re = try Regex.init(alloc, "ERROR \\[http\\] req=[0-9a-f]{4}", .{});
        defer re.deinit();
        const line = "ERROR [http] req=ZZZZ and ERROR [http] req=09af done\n";
        const m = re.find(line, 0, .earliest) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqualStrings("ERROR [http] req=09af", line[m.start..m.end]);
    }

    // 2. End-of-line assertion `$` must not over-match via DFA epsilon closure
    {
        var re = try Regex.init(alloc, "ERROR_foo$", .{});
        defer re.deinit();
        try std.testing.expect(re.find("ERROR_foobar\n", 0, .earliest) == null);
        const m = re.find("ERROR_foo\n", 0, .earliest) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(usize, 0), m.start);
        try std.testing.expectEqual(@as(usize, 9), m.end);
    }

    // 3. Word boundary `\b` must not falsely match inside identifier
    {
        var re = try Regex.init(alloc, "ERROR_foo\\b", .{});
        defer re.deinit();
        try std.testing.expect(re.find("ERROR_foobar", 0, .earliest) == null);
        const m = re.find("ERROR_foo bar", 0, .earliest) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(usize, 0), m.start);
        try std.testing.expectEqual(@as(usize, 9), m.end);
    }

    // 4. Leftmost-first alternation priority (`a|ab` on `ab` -> `a`)
    {
        var re = try Regex.init(alloc, "prefix(a|ab)", .{});
        defer re.deinit();
        const m = re.find("prefixab", 0, .leftmost_first) orelse return error.TestUnexpectedResult;
        try std.testing.expectEqual(@as(usize, 0), m.start);
        try std.testing.expectEqual(@as(usize, 7), m.end);
    }
}
