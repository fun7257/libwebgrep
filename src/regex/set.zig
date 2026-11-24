//! [Module] regex/set.zig
//! [Layer] Layer 2 — Multi-Pattern Regular Expression Set (`RegexSet`)
//! [Role] Compiles up to `pattern_count_hard_cap` (1,024) regular expressions into a combined
//!        Thompson NFA accelerated by unified multi-pattern SIMD prefiltering (FP0/FP1/FP2),
//!        per-pattern stack-buffered NFA verification, and a two-tier Unanchored Set DFA
//!        (`SetUnanchoredDfa` Tier A + `LazySetDfa` Tier B, FP3).
//! [Invariants]
//!   1. Guaranteed O(N * M) linear-time worst-case evaluation across all patterns simultaneously.
//!   2. All search methods take `*const RegexSet` and are 100% thread-safe and lock-free.
//!   3. Strict enforcement of instruction caps, pattern count/byte caps, UTF-8 validity, and single-line newline rejection.
//! [HotPath] `RegexSet.find` / `findWatched` / `findEnd` / `findEndWatched` / `matches`.

const std = @import("std");
const matcher = @import("../matcher.zig");
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
pub const Error = inst_mod.Error;
pub const DiagnosticCode = inst_mod.DiagnosticCode;
pub const CompileDiagnostic = inst_mod.CompileDiagnostic;
pub const RegexOptions = inst_mod.RegexOptions;
pub const Inst = inst_mod.Inst;
pub const Thread = inst_mod.Thread;
pub const UnicodeRangeList = inst_mod.UnicodeRangeList;
pub const SetLitKind = prefilter_mod.SetLitKind;
pub const max_inst_hard_cap = inst_mod.max_inst_hard_cap;
pub const max_multiline_window_hard_cap = inst_mod.max_multiline_window_hard_cap;

const Compiler = compiler_mod.Compiler;
const UnanchoredDfa = dfa_mod.UnanchoredDfa;
const SetUnanchoredDfa = dfa_mod.SetUnanchoredDfa;
const LazySetDfa = dfa_mod.LazySetDfa;
const ByteClasses = dfa_mod.ByteClasses;
const hasLiteralUpper = inst_mod.hasLiteralUpper;
const hasTopLevelAlt = inst_mod.hasTopLevelAlt;
const checkAssert = inst_mod.checkAssert;
const lineStartAt = inst_mod.lineStartAt;
const utf8SeqLenAt = inst_mod.utf8SeqLenAt;
const decodeValidUtf8At = inst_mod.decodeValidUtf8At;
const inRanges = inst_mod.inRanges;
const populateDiagnostic = inst_mod.populateDiagnostic;

const AllowAny = struct {
    pub inline fn allow(_: @This(), _: []const u8, _: usize, _: usize) bool {
        return true;
    }
};

pub const PatternMeta = struct {
    start_pc: u32,
    inst_start: u32,
    inst_end: u32,
    min_before: u32 = 0,
    is_exact: bool = false,
};

pub const RegexSet = struct {
    allocator: std.mem.Allocator,
    insts: []Inst = &.{},
    unicode_ranges: []UnicodeRangeList = &.{},
    pat_meta: []PatternMeta = &.{},
    start_pc: u32 = 0,
    pattern_count: usize = 0,
    multiline: bool = false,
    anchored_start: bool = false,
    any_ignore_case: bool = false,
    unicode_case: bool = true,
    max_multiline_window: usize = inst_mod.default_multiline_window,
    max_dfa_states: u16 = 256,
    prefix_slices: [][]u8 = &.{},
    prefilter: ?Multi = null,
    pf_pat_offsets: []u32 = &.{},
    pf_pat_ids: []u32 = &.{},
    pf_lit_kind: []SetLitKind = &.{},
    pf_min_before: []u32 = &.{},
    pf_next_mask: []inst_mod.ByteSet = &.{},
    pf_has_next_mask: []bool = &.{},
    pf_min_len: usize = 0,
    pf_max_len: usize = 0,
    all_exact: bool = false,
    all_prefix: bool = false,
    has_prefix_overlap: bool = false,
    byte_classes: ByteClasses = .{},
    has_byte_classes: bool = false,
    set_unanchored_dfa: ?*SetUnanchoredDfa = null,

    pub fn init(
        allocator: std.mem.Allocator,
        patterns: []const []const u8,
        options: RegexOptions,
    ) Error!RegexSet {
        return initDiagnostic(allocator, patterns, options, null);
    }

    pub fn initDiagnostic(
        allocator: std.mem.Allocator,
        patterns: []const []const u8,
        options: RegexOptions,
        diag: ?*CompileDiagnostic,
    ) Error!RegexSet {
        if (diag) |d| d.* = .{};

        const inst_cap = options.effectiveMaxInst() orelse
            @min(@as(usize, 262_144), @max(max_inst_hard_cap, patterns.len *| 512));
        if (inst_cap == 0 or inst_cap > std.math.maxInt(u32)) {
            populateDiagnostic(diag, "", error.RegexTooLarge, .instruction_limit_exceeded, 0, "max_inst is zero or exceeds u32 max", null);
            return error.RegexTooLarge;
        }
        if (options.max_multiline_window == 0) {
            populateDiagnostic(diag, "", error.RegexTooLarge, .multiline_window_exceeded, 0, "max_multiline_window is zero", null);
            return error.RegexTooLarge;
        }
        matcher.checkPatternLimits(patterns, .{
            .max_pattern_count = options.max_pattern_count,
            .max_pattern_bytes = options.max_pattern_bytes,
            .max_unicode_variants = options.max_unicode_variants,
        }) catch |err| {
            const code: DiagnosticCode = switch (err) {
                error.PatternCountExceeded => .pattern_count_exceeded,
                error.PatternBytesExceeded => .pattern_bytes_exceeded,
            };
            populateDiagnostic(diag, "", err, code, 0, "pattern set exceeds count or byte limit", null);
            return err;
        };

        if (patterns.len == 0) {
            return .{
                .allocator = allocator,
                .pattern_count = 0,
                .multiline = options.multiline,
                .unicode_case = options.unicode_case,
                .max_multiline_window = options.max_multiline_window,
                .max_dfa_states = options.max_dfa_states,
            };
        }

        var compiler = Compiler{
            .allocator = allocator,
            .pattern = "",
            .ignore_case = false,
            .unicode_case = options.unicode_case,
            .unicode_classes = options.unicode_classes,
            .multiline = options.multiline,
            .dot_all = options.dot_all,
            .max_inst = inst_cap,
            .max_repeat = options.max_repeat,
            .max_recursion_depth = options.max_recursion_depth,
            .diag = diag,
        };
        defer compiler.deinit();

        var frag_starts = try allocator.alloc(u32, patterns.len);
        defer allocator.free(frag_starts);

        var transferred = false;

        const pat_meta = try allocator.alloc(PatternMeta, patterns.len);
        errdefer if (!transferred) allocator.free(pat_meta);

        var any_multiline = options.multiline;
        var all_anchored = true;
        var any_ignore_case = false;
        var all_ignore_case = true;
        var any_saw_extended = false;
        var any_inline_case_change = false;

        for (patterns, 0..) |pat, idx| {
            if (inst_mod.findInvalidUtf8Offset(pat)) |bad_pos| {
                populateDiagnostic(diag, pat, error.RegexSyntax, .invalid_utf8, bad_pos, "pattern contains invalid UTF-8 byte sequence", idx);
                return error.RegexSyntax;
            }

            const pat_ignore_case = switch (options.case) {
                .sensitive => false,
                .insensitive => true,
                .smart => !hasLiteralUpper(pat, options.unicode_case),
            };

            compiler.pattern = pat;
            compiler.pos = 0;
            compiler.depth = 0;
            compiler.ignore_case = pat_ignore_case;
            compiler.unicode_case = options.unicode_case;
            compiler.unicode_classes = options.unicode_classes;
            if (@hasField(Compiler, "unicode_word_boundary")) {
                compiler.unicode_word_boundary = options.unicode_word_boundary;
            }
            compiler.multiline = options.multiline;
            compiler.dot_all = options.dot_all;
            compiler.saw_scoped_m = false;
            compiler.saw_ignore_case = pat_ignore_case;
            compiler.explicit_neg_m = false;
            compiler.extended = false;
            compiler.ungreedy = false;
            compiler.saw_extended = false;
            compiler.saw_ungreedy = false;
            compiler.saw_literal_nl_pos = null;
            compiler.capture_count = 0;
            compiler.capture_positions = @splat(std.math.maxInt(usize));
            compiler.capture_names = @splat("");
            compiler.pattern_index = idx;
            compiler.match_inst = .{ .match_id = @intCast(idx) };

            const inst_start: u32 = @intCast(compiler.insts.items.len);
            const frag = try compiler.compile();
            const inst_end: u32 = @intCast(compiler.insts.items.len);
            const pat_ml = compiler.multiline or compiler.saw_scoped_m;
            if (!pat_ml) {
                if (compiler.saw_literal_nl_pos) |nl_pos| {
                    populateDiagnostic(diag, pat, error.PatternHasNewline, .pattern_has_newline, nl_pos, "pattern contains literal newline in single-line mode", idx);
                    return error.PatternHasNewline;
                }
            }
            frag_starts[idx] = frag.start;
            pat_meta[idx] = .{
                .start_pc = frag.start,
                .inst_start = inst_start,
                .inst_end = inst_end,
            };
            if (pat_ml) any_multiline = true;
            if (compiler.saw_extended) any_saw_extended = true;

            const eff_ic = compiler.ignore_case or compiler.saw_ignore_case;
            if (eff_ic != pat_ignore_case or compiler.ignore_case != eff_ic) {
                any_inline_case_change = true;
            }
            if (eff_ic) {
                any_ignore_case = true;
            } else {
                all_ignore_case = false;
            }
            if (!(std.mem.startsWith(u8, pat, "\\A") and !hasTopLevelAlt(pat))) {
                all_anchored = false;
            }
        }

        // Build priority-ordered split tree from pattern 0..N-1
        var root_start: u32 = frag_starts[patterns.len - 1];
        var rev_idx: usize = patterns.len - 1;
        while (rev_idx > 0) {
            rev_idx -= 1;
            root_start = try compiler.emit(.{
                .split = .{
                    .out1 = frag_starts[rev_idx],
                    .out2 = root_start,
                },
            });
        }

        if (compiler.insts.items.len > inst_cap) {
            populateDiagnostic(diag, patterns[patterns.len - 1], error.RegexTooLarge, .instruction_limit_exceeded, 0, "compiled instruction count exceeds limit", patterns.len - 1);
            return error.RegexTooLarge;
        }

        const insts = try compiler.insts.toOwnedSlice(allocator);
        errdefer if (!transferred) allocator.free(insts);

        const unicode_ranges = try compiler.unicode_ranges.toOwnedSlice(allocator);
        errdefer {
            if (!transferred) {
                for (unicode_ranges) |item| {
                    if (item.owned) allocator.free(item.ranges);
                }
                allocator.free(unicode_ranges);
            }
        }

        const all_same_case = !any_inline_case_change and (any_ignore_case == all_ignore_case);

        var self = RegexSet{
            .allocator = allocator,
            .insts = insts,
            .unicode_ranges = unicode_ranges,
            .pat_meta = pat_meta,
            .start_pc = root_start,
            .pattern_count = patterns.len,
            .multiline = any_multiline,
            .anchored_start = all_anchored,
            .any_ignore_case = any_ignore_case,
            .unicode_case = options.unicode_case,
            .max_multiline_window = options.max_multiline_window,
            .max_dfa_states = options.max_dfa_states,
        };
        transferred = true;
        errdefer self.deinit();

        try self.tryBuildMultiPrefilter(patterns, any_ignore_case, all_same_case, any_saw_extended, options);

        if (self.prefilter == null and !self.anchored_start and options.max_dfa_states > 0) {
            self.byte_classes = ByteClasses.compute(self.insts, self.unicode_ranges, self.multiline);
            self.has_byte_classes = true;

            if (allocator.create(SetUnanchoredDfa)) |udfa| {
                udfa.* = .{};
                if (udfa.determinize(allocator, self.insts, self.unicode_ranges, &self.byte_classes, self.start_pc, self.multiline)) {
                    self.set_unanchored_dfa = udfa;
                } else {
                    udfa.deinit(allocator);
                    allocator.destroy(udfa);
                }
            } else |_| {}
        }

        return self;
    }

    fn literalsEqual(a: []const u8, b: []const u8, ignore_case: bool, unicode_case: bool) bool {
        if (!ignore_case) return std.mem.eql(u8, a, b);
        if (unicode_case) return unicode_fold.eqlFolded(a, b);
        if (a.len != b.len) return false;
        for (a, b) |ca, cb| {
            if (std.ascii.toLower(ca) != std.ascii.toLower(cb)) return false;
        }
        return true;
    }

    fn literalStartsWith(hay: []const u8, prefix: []const u8, ignore_case: bool, unicode_case: bool) bool {
        if (!ignore_case) return std.mem.startsWith(u8, hay, prefix);
        if (unicode_case) return unicode_fold.matchFoldedPrefix(prefix, hay) != null;
        if (hay.len < prefix.len) return false;
        for (prefix, hay[0..prefix.len]) |cp, ch| {
            if (std.ascii.toLower(cp) != std.ascii.toLower(ch)) return false;
        }
        return true;
    }

    fn tryBuildMultiPrefilter(
        self: *RegexSet,
        patterns: []const []const u8,
        any_ignore_case: bool,
        all_same_case: bool,
        any_saw_extended: bool,
        options: RegexOptions,
    ) !void {
        if (any_saw_extended) return;

        var extracted = (try prefilter_mod.extractSetLiterals(self.allocator, patterns, self.multiline, 512)) orelse return;
        defer extracted.deinit(self.allocator);

        const UniqueEntry = struct {
            bytes: []u8,
            kind: SetLitKind,
            min_before: u32,
            owners: std.ArrayList(u32) = .empty,
        };

        var uniques = std.ArrayList(UniqueEntry).empty;
        defer {
            for (uniques.items) |*u| {
                u.owners.deinit(self.allocator);
            }
            uniques.deinit(self.allocator);
        }
        errdefer {
            for (uniques.items) |u| {
                if (u.bytes.len != 0) self.allocator.free(u.bytes);
            }
        }

        // Deduplicate extracted literals (case-folding aware when `any_ignore_case`)
        for (extracted.items) |item| {
            var found_idx: ?usize = null;
            for (uniques.items, 0..) |u, u_idx| {
                if (literalsEqual(u.bytes, item.bytes, any_ignore_case, options.unicode_case)) {
                    found_idx = u_idx;
                    break;
                }
            }
            if (found_idx) |fi| {
                var u = &uniques.items[fi];
                if (@intFromEnum(item.kind) > @intFromEnum(u.kind)) u.kind = item.kind;
                if (item.min_before < u.min_before) u.min_before = item.min_before;
                // Keep owner list sorted ascending and deduplicated
                if (u.owners.items.len == 0 or u.owners.items[u.owners.items.len - 1] != item.pat_id) {
                    var already = false;
                    for (u.owners.items) |oid| {
                        if (oid == item.pat_id) {
                            already = true;
                            break;
                        }
                    }
                    if (!already) {
                        try u.owners.append(self.allocator, item.pat_id);
                    }
                }
            } else {
                const duped = try self.allocator.dupe(u8, item.bytes);
                errdefer self.allocator.free(duped);
                var entry = UniqueEntry{
                    .bytes = duped,
                    .kind = item.kind,
                    .min_before = item.min_before,
                };
                errdefer entry.owners.deinit(self.allocator);
                try entry.owners.append(self.allocator, item.pat_id);
                try uniques.append(self.allocator, entry);
            }

            // Record per-pattern metadata hints
            if (item.pat_id < self.pat_meta.len) {
                if (item.kind == .interior) {
                    if (self.pat_meta[item.pat_id].min_before == 0 or item.min_before < self.pat_meta[item.pat_id].min_before) {
                        self.pat_meta[item.pat_id].min_before = item.min_before;
                    }
                }
            }
        }

        const m_count = uniques.items.len;
        if (m_count == 0) return;

        // Sort each unique entry's owner IDs ascending
        var total_owners: usize = 0;
        for (uniques.items) |*u| {
            if (u.owners.items.len > 1) {
                std.mem.sort(u32, u.owners.items, {}, std.sort.asc(u32));
            }
            total_owners += u.owners.items.len;
        }

        const owned_prefixes = try self.allocator.alloc([]u8, m_count);
        var built_count: usize = 0;
        errdefer {
            for (owned_prefixes[0..built_count]) |s| self.allocator.free(s);
            self.allocator.free(owned_prefixes);
        }

        const offsets = try self.allocator.alloc(u32, m_count + 1);
        errdefer self.allocator.free(offsets);
        const pat_ids = try self.allocator.alloc(u32, total_owners);
        errdefer self.allocator.free(pat_ids);
        const lit_kinds = try self.allocator.alloc(SetLitKind, m_count);
        errdefer self.allocator.free(lit_kinds);
        const min_befores = try self.allocator.alloc(u32, m_count);
        errdefer self.allocator.free(min_befores);

        var all_exact = all_same_case and !self.anchored_start;
        var all_prefix = true;
        var min_len: usize = std.math.maxInt(usize);
        var max_len: usize = 0;

        var owner_cursor: usize = 0;
        for (uniques.items, 0..) |*u, idx| {
            owned_prefixes[idx] = u.bytes;
            u.bytes = &.{}; // ownership transferred
            built_count += 1;

            offsets[idx] = @intCast(owner_cursor);
            for (u.owners.items) |pid| {
                pat_ids[owner_cursor] = pid;
                owner_cursor += 1;
            }
            lit_kinds[idx] = u.kind;
            min_befores[idx] = u.min_before;

            if (u.kind != .exact) all_exact = false;
            if (u.kind == .interior) all_prefix = false;
            if (owned_prefixes[idx].len < min_len) min_len = owned_prefixes[idx].len;
            if (owned_prefixes[idx].len > max_len) max_len = owned_prefixes[idx].len;
        }
        offsets[m_count] = @intCast(owner_cursor);

        const eff_max_len = if (any_ignore_case and options.unicode_case) max_len *| 3 else max_len;
        if (self.multiline and eff_max_len > self.max_multiline_window) {
            all_exact = false;
        }

        // Check whether any two distinct unique literals overlap as prefixes of each other
        var has_overlap = false;
        outer_ov: for (0..m_count) |a_idx| {
            for (a_idx + 1..m_count) |b_idx| {
                const sa = owned_prefixes[a_idx];
                const sb = owned_prefixes[b_idx];
                if (literalStartsWith(sa, sb, any_ignore_case, options.unicode_case) or
                    literalStartsWith(sb, sa, any_ignore_case, options.unicode_case))
                {
                    has_overlap = true;
                    break :outer_ov;
                }
            }
        }

        const const_slices: []const []const u8 = @ptrCast(owned_prefixes);
        // Always pass uniform case (`.insensitive` if any pattern ignores case, else `.sensitive`)
        // to avoid `Multi.Kind.mixed` scalar fallback!
        const find_opts = matcher.FindOptions{
            .case = if (any_ignore_case) .insensitive else .sensitive,
            .unicode_case = options.unicode_case,
            .max_pattern_count = options.max_pattern_count,
            .max_pattern_bytes = options.max_pattern_bytes,
            .max_unicode_variants = options.max_unicode_variants,
            .multiline = self.multiline,
            .max_multiline_window = self.max_multiline_window,
        };
        if (Multi.init(self.allocator, const_slices, find_opts)) |m| {
            const next_masks = self.allocator.alloc(inst_mod.ByteSet, m_count) catch null;
            const has_next_masks = if (next_masks != null) (self.allocator.alloc(bool, m_count) catch null) else null;
            if (next_masks != null and has_next_masks == null) {
                self.allocator.free(next_masks.?);
            }

            self.prefix_slices = owned_prefixes;
            self.prefilter = m;
            self.pf_pat_offsets = offsets;
            self.pf_pat_ids = pat_ids;
            self.pf_lit_kind = lit_kinds;
            self.pf_min_before = min_befores;
            self.pf_min_len = if (any_ignore_case and options.unicode_case) 1 else min_len;
            self.pf_max_len = eff_max_len;
            self.all_exact = all_exact;
            self.all_prefix = all_prefix;
            self.has_prefix_overlap = has_overlap;

            if (next_masks != null and has_next_masks != null) {
                const nm = next_masks.?;
                const hnm = has_next_masks.?;
                @memset(nm, .{});
                @memset(hnm, false);
                for (0..m_count) |lid| {
                    if (lit_kinds[lid] == .prefix and owned_prefixes[lid].len > 0) {
                        if (self.computePostPrefixMask(owned_prefixes[lid], pat_ids[offsets[lid]..offsets[lid + 1]])) |mask| {
                            nm[lid] = mask;
                            hnm[lid] = true;
                        }
                    }
                }
                self.pf_next_mask = nm;
                self.pf_has_next_mask = hnm;
            }

            if (all_exact) {
                for (self.pat_meta) |*pm| pm.is_exact = true;
            }
        } else |_| {
            for (owned_prefixes) |s| self.allocator.free(s);
            self.allocator.free(owned_prefixes);
            self.allocator.free(offsets);
            self.allocator.free(pat_ids);
            self.allocator.free(lit_kinds);
            self.allocator.free(min_befores);
        }
    }

    fn closureSinglePatIgnoreAssert(
        self: *const RegexSet,
        inst_base: u32,
        start_pc: u32,
        out_pcs: []u32,
        out_len: *usize,
        gen_table: []u32,
        gen: u32,
        reached_match: *bool,
    ) bool {
        var stack: [256]u32 = undefined;
        var sp: usize = 0;
        stack[0] = start_pc;
        sp = 1;

        while (sp > 0) {
            sp -= 1;
            const pc = stack[sp];
            if (pc < inst_base) return false;
            const rel = pc - inst_base;
            if (rel >= gen_table.len) return false;
            if (gen_table[rel] == gen) continue;
            gen_table[rel] = gen;

            switch (self.insts[pc]) {
                .jmp => |t| {
                    if (sp >= stack.len) return false;
                    stack[sp] = t;
                    sp += 1;
                },
                .split => |s| {
                    if (sp + 2 > stack.len) return false;
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
                    reached_match.* = true;
                },
                .byte, .any, .any_cont, .class, .unicode_class => {
                    if (out_len.* >= out_pcs.len) return false;
                    out_pcs[out_len.*] = pc;
                    out_len.* += 1;
                },
            }
        }
        return true;
    }

    /// Computes a conservative `ByteSet` of all bytes that can validly appear immediately after
    /// matching prefix literal `lit` across every owning pattern in `owners`.
    /// Returns `null` if any owner can accept immediately after `lit` (0 trailing bytes), exceeds
    /// 256 instructions, or allows all 256 byte values.
    fn computePostPrefixMask(self: *const RegexSet, lit: []const u8, owners: []const u32) ?inst_mod.ByteSet {
        if (lit.len == 0 or owners.len == 0) return null;
        var combined = inst_mod.ByteSet{};

        for (owners) |pid| {
            if (pid >= self.pat_meta.len) return null;
            const meta = self.pat_meta[pid];
            const n_inst: usize = meta.inst_end - meta.inst_start;
            if (n_inst == 0 or n_inst > 256) return null;

            var curr_buf: [256]u32 = undefined;
            var next_buf: [256]u32 = undefined;
            var gen_table: [256]u32 = @splat(0);
            var gen: u32 = 1;

            var curr: []u32 = curr_buf[0..n_inst];
            var next: []u32 = next_buf[0..n_inst];
            var curr_len: usize = 0;
            var reached_match = false;
            if (!self.closureSinglePatIgnoreAssert(meta.inst_start, meta.start_pc, curr, &curr_len, gen_table[0..n_inst], gen, &reached_match)) {
                return null;
            }

            for (lit) |b| {
                gen +%= 1;
                if (gen == 0) {
                    @memset(gen_table[0..n_inst], 0);
                    gen = 1;
                }
                var next_len: usize = 0;
                reached_match = false;
                const alt_b: ?u8 = if (self.any_ignore_case and std.ascii.isAlphabetic(b)) (b ^ 32) else null;

                for (curr[0..curr_len]) |pc| {
                    const inst = self.insts[pc];
                    switch (inst) {
                        .byte => |by| {
                            const ok = if (by.ignore_case or self.any_ignore_case)
                                std.ascii.toLower(by.b) == std.ascii.toLower(b)
                            else
                                by.b == b;
                            if (ok) {
                                if (!self.closureSinglePatIgnoreAssert(meta.inst_start, by.out, next, &next_len, gen_table[0..n_inst], gen, &reached_match)) return null;
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
                                if (!self.closureSinglePatIgnoreAssert(meta.inst_start, target_pc, next, &next_len, gen_table[0..n_inst], gen, &reached_match)) return null;
                                continue;
                            }
                            if (cl.set.contains(b) or (alt_b != null and cl.set.contains(alt_b.?))) {
                                if (!self.closureSinglePatIgnoreAssert(meta.inst_start, cl.out, next, &next_len, gen_table[0..n_inst], gen, &reached_match)) return null;
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
                            if (!self.closureSinglePatIgnoreAssert(meta.inst_start, target_pc, next, &next_len, gen_table[0..n_inst], gen, &reached_match)) return null;
                        },
                        .any_cont => |ac| {
                            if ((b & 0xC0) == 0x80) {
                                if (!self.closureSinglePatIgnoreAssert(meta.inst_start, ac.out, next, &next_len, gen_table[0..n_inst], gen, &reached_match)) return null;
                            }
                        },
                        .unicode_class => |uc| {
                            if (!uc.allow_nl and b == '\n') continue;
                            if (b < 0x80) {
                                const ranges = self.unicode_ranges[uc.range_idx].ranges;
                                const in1 = (uc.has_ascii_set and uc.ascii_set.contains(b)) or inRanges(b, ranges);
                                const m1 = if (uc.negated) !in1 else in1;
                                const m2 = if (alt_b) |ab| blk: {
                                    const in2 = (uc.has_ascii_set and uc.ascii_set.contains(ab)) or inRanges(ab, ranges);
                                    break :blk if (uc.negated) !in2 else in2;
                                } else false;
                                if (m1 or m2) {
                                    if (!self.closureSinglePatIgnoreAssert(meta.inst_start, uc.out, next, &next_len, gen_table[0..n_inst], gen, &reached_match)) return null;
                                }
                            } else if (b >= 0xC2 and b <= 0xF4) {
                                const target_pc: u32 = if (b <= 0xDF)
                                    (if (uc.cont1 != 0) uc.cont1 else uc.out)
                                else if (b <= 0xEF)
                                    (if (uc.cont2 != 0) uc.cont2 else uc.out)
                                else
                                    (if (uc.cont3 != 0) uc.cont3 else uc.out);
                                if (!self.closureSinglePatIgnoreAssert(meta.inst_start, target_pc, next, &next_len, gen_table[0..n_inst], gen, &reached_match)) return null;
                            }
                        },
                        else => {},
                    }
                }
                const tmp = curr;
                curr = next;
                next = tmp;
                curr_len = next_len;
            }

            // If this owner can accept with 0 additional bytes (or had empty closure), cannot reject on next byte
            if (reached_match or curr_len == 0) return null;

            for (curr[0..curr_len]) |pc| {
                switch (self.insts[pc]) {
                    .byte => |by| {
                        combined.setWithCase(by.b, by.ignore_case);
                        if (by.ignore_case and self.unicode_case and
                            (by.b == 's' or by.b == 'S' or by.b == 'k' or by.b == 'K'))
                        {
                            combined.bits[2] = std.math.maxInt(u64);
                            combined.bits[3] = std.math.maxInt(u64);
                        }
                    },
                    .class => |cl| {
                        for (0..4) |w| combined.bits[w] |= cl.set.bits[w];
                        if (cl.utf8_negated) {
                            combined.bits[2] = std.math.maxInt(u64);
                            combined.bits[3] = std.math.maxInt(u64);
                        }
                    },
                    .any => |an| {
                        combined.bits = .{
                            std.math.maxInt(u64),
                            std.math.maxInt(u64),
                            std.math.maxInt(u64),
                            std.math.maxInt(u64),
                        };
                        if (!an.allow_nl) combined.clear('\n');
                    },
                    .any_cont => {
                        combined.bits[2] = std.math.maxInt(u64);
                    },
                    .unicode_class => |uc| {
                        const ranges = self.unicode_ranges[uc.range_idx].ranges;
                        var ch: u8 = 0;
                        while (ch < 0x80) : (ch += 1) {
                            if (!uc.allow_nl and ch == '\n') continue;
                            const in_set = (uc.has_ascii_set and uc.ascii_set.contains(ch)) or inRanges(ch, ranges);
                            if (if (uc.negated) !in_set else in_set) combined.set(ch);
                        }
                        combined.bits[2] = std.math.maxInt(u64);
                        combined.bits[3] = std.math.maxInt(u64);
                    },
                    else => return null,
                }
            }
        }

        if (!self.multiline) combined.clear('\n');
        if (combined.bits[0] == std.math.maxInt(u64) and
            combined.bits[1] == std.math.maxInt(u64) and
            combined.bits[2] == std.math.maxInt(u64) and
            combined.bits[3] == std.math.maxInt(u64))
        {
            return null;
        }
        return combined;
    }

    pub fn deinit(self: *RegexSet) void {
        if (self.set_unanchored_dfa) |udfa| {
            udfa.deinit(self.allocator);
            self.allocator.destroy(udfa);
        }
        if (self.prefilter) |*pf| pf.deinit();
        if (self.prefix_slices.len != 0) {
            for (self.prefix_slices) |s| self.allocator.free(s);
            self.allocator.free(self.prefix_slices);
        }
        if (self.pf_pat_offsets.len != 0) self.allocator.free(self.pf_pat_offsets);
        if (self.pf_pat_ids.len != 0) self.allocator.free(self.pf_pat_ids);
        if (self.pf_lit_kind.len != 0) self.allocator.free(self.pf_lit_kind);
        if (self.pf_min_before.len != 0) self.allocator.free(self.pf_min_before);
        if (self.pf_next_mask.len != 0) self.allocator.free(self.pf_next_mask);
        if (self.pf_has_next_mask.len != 0) self.allocator.free(self.pf_has_next_mask);
        if (self.pat_meta.len != 0) self.allocator.free(self.pat_meta);
        if (self.unicode_ranges.len != 0) {
            for (self.unicode_ranges) |item| {
                if (item.owned) self.allocator.free(item.ranges);
            }
            self.allocator.free(self.unicode_ranges);
        }
        if (self.insts.len != 0) self.allocator.free(self.insts);
        self.* = undefined;
    }

    pub fn len(self: *const RegexSet) usize {
        return self.pattern_count;
    }

    pub fn isEmpty(self: *const RegexSet) bool {
        return self.pattern_count == 0;
    }

    pub fn isMultiline(self: *const RegexSet) bool {
        return self.multiline;
    }

    pub fn isStartAnchored(self: *const RegexSet) bool {
        return self.anchored_start;
    }

    pub fn multilineWindow(self: *const RegexSet) usize {
        return self.max_multiline_window;
    }

    pub fn maxNewlines(self: *const RegexSet) ?u32 {
        return if (!self.multiline) 0 else null;
    }

    pub fn earliestPendingStart(self: *const RegexSet, chunk: []const u8, from: usize) usize {
        if (from >= chunk.len) return chunk.len;
        if (self.all_exact or self.all_prefix) {
            if (self.prefilter) |*pf| {
                const tail_keep = self.pf_max_len -| 1;
                const tail_start = chunk.len -| tail_keep;
                if (pf.find(chunk, from, .leftmost_first)) |hit| {
                    return @min(hit.start, tail_start);
                }
                return tail_start;
            }
        }
        return from;
    }

    pub inline fn watchedIsExact(self: *const RegexSet) bool {
        if (self.anchored_start) return false;
        return self.all_exact and self.prefix_slices.len <= 1;
    }

    pub inline fn watchedHasExactStart(self: *const RegexSet) bool {
        if (self.anchored_start) return false;
        return self.all_exact and self.prefix_slices.len <= 1;
    }

    pub fn resetStats(self: *const RegexSet) void {
        _ = self;
    }

    pub fn isMatch(self: *const RegexSet, haystack: []const u8) bool {
        return self.findEnd(haystack, 0, .earliest) != null;
    }

    pub fn findReadOnly(self: *const RegexSet, haystack: []const u8, start: usize, mode: MatchMode) ?Match {
        return self.find(haystack, start, mode);
    }

    pub fn matchSpan(self: *const RegexSet, span: []const u8, mode: MatchMode) ?Match {
        if (self.pattern_count == 0 or self.insts.len == 0) return null;
        return self.runFindRangeSpan(span, 0, 0, span.len, mode, true, AllowAny{});
    }

    pub fn acceptsSpan(self: *const RegexSet, span: []const u8, mode: MatchMode) bool {
        return self.matchSpan(span, mode) != null;
    }

    inline fn litOwners(self: *const RegexSet, lit_id: usize) []const u32 {
        return self.pf_pat_ids[self.pf_pat_offsets[lit_id]..self.pf_pat_offsets[lit_id + 1]];
    }

    inline fn preferMatch(a: Match, b: Match, mode: MatchMode) bool {
        const a_pid = a.pattern_id orelse std.math.maxInt(u32);
        const b_pid = b.pattern_id orelse std.math.maxInt(u32);
        if (mode == .earliest) {
            if (a.end != b.end) return a.end < b.end;
            if (a.start != b.start) return a.start < b.start;
            return a_pid < b_pid;
        }
        if (a.start != b.start) return a.start < b.start;
        if (a_pid != b_pid) return a_pid < b_pid;
        return a.end > b.end;
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

    inline fn failsNextMask(self: *const RegexSet, haystack: []const u8, pat_start: usize, pat_end: usize, lit_id: usize) bool {
        if (lit_id < self.pf_has_next_mask.len and self.pf_has_next_mask[lit_id]) {
            if (pat_end - pat_start == self.prefix_slices[lit_id].len) {
                if (pat_end >= haystack.len or !self.pf_next_mask[lit_id].contains(haystack[pat_end])) {
                    return true;
                }
            }
        }
        return false;
    }

    fn SetPrefixVerifier(comptime watch_abort: bool, comptime bounded_cand: bool) type {
        return struct {
            set: *const RegexSet,
            full_haystack: []const u8,
            mode: MatchMode,
            cached_win_start: usize = std.math.maxInt(usize),
            cached_win_end: usize = std.math.maxInt(usize),
            cand_limit: usize = std.math.maxInt(usize),
            orig_start: usize = 0,
            rejects: usize = 0,
            matched_pid: u32 = 0,
            best_match: ?Match = null,

            pub inline fn verify(self: *@This(), _: []const u8, pat_start: usize, pat_end: usize, lit_id: usize) multi_mod.VerifyResult {
                if (comptime bounded_cand) {
                    if (pat_start >= self.cand_limit) return .reject;
                }
                const haystack = self.full_haystack;
                if (self.set.failsNextMask(haystack, pat_start, pat_end, lit_id)) {
                    if (comptime watch_abort) {
                        if (self.best_match == null) {
                            self.rejects += 1;
                            if (self.rejects >= 16 and pat_start <= self.orig_start + 32 * 1024 and haystack.len - pat_start >= 64 * 1024) {
                                return .abort;
                            }
                        }
                    }
                    return .reject;
                }
                const win_end = if (!self.set.multiline and self.cached_win_end != std.math.maxInt(usize) and
                    pat_start >= self.cached_win_start and pat_start <= self.cached_win_end)
                    self.cached_win_end
                else blk: {
                    const w = self.set.windowLimit(haystack, pat_start);
                    self.cached_win_start = pat_start;
                    self.cached_win_end = w;
                    break :blk w;
                };
                const owners = self.set.litOwners(lit_id);
                if (self.mode == .leftmost_first) {
                    for (owners) |pid| {
                        if (self.set.runSinglePattern(pid, haystack, pat_start, pat_start, win_end, .leftmost_first, AllowAny{})) |m| {
                            self.matched_pid = pid;
                            self.best_match = m;
                            return .{ .accept = m.end };
                        }
                    }
                } else {
                    var best: ?Match = null;
                    for (owners) |pid| {
                        if (self.set.runSinglePattern(pid, haystack, pat_start, pat_start, win_end, .earliest, AllowAny{})) |m| {
                            if (best == null or preferMatch(m, best.?, .earliest)) best = m;
                        }
                    }
                    if (best) |bm| {
                        if (self.best_match == null or preferMatch(bm, self.best_match.?, .earliest)) {
                            self.best_match = bm;
                            self.matched_pid = bm.pattern_id orelse owners[0];
                        }
                        return .{ .accept = bm.end };
                    }
                }
                if (comptime watch_abort) {
                    if (self.best_match == null) {
                        self.rejects += 1;
                        if (self.rejects >= 16 and pat_start <= self.orig_start + 32 * 1024 and haystack.len - pat_start >= 64 * 1024) {
                            return .abort;
                        }
                    }
                }
                return .reject;
            }
        };
    }

    pub fn find(self: *const RegexSet, haystack: []const u8, start: usize, mode: MatchMode) ?Match {
        if (self.pattern_count == 0 or self.insts.len == 0 or start > haystack.len) return null;
        if (self.anchored_start and start > 0) return null;

        // FP0: all patterns are exact literals -> zero NFA!
        if (self.all_exact) {
            if (self.prefilter) |*pf| {
                const hit = pf.find(haystack, start, mode) orelse return null;
                const lit_id: usize = hit.pattern_id orelse 0;
                return Match{
                    .start = hit.start,
                    .end = hit.end,
                    .pattern_id = self.litOwners(lit_id)[0],
                };
            }
        }

        // FP1: all patterns have required literal prefixes
        if (self.all_prefix) {
            if (self.prefilter) |*pf| {
                return self.findPrefix(pf, haystack, start, mode);
            }
        }

        // FP2: interior or mixed literals
        if (self.prefilter) |*pf| {
            return self.findInterior(pf, haystack, start, mode);
        }

        // FP3 Tier A: AOT SetUnanchoredDfa
        if (self.set_unanchored_dfa) |udfa| {
            var unused_nul: ?usize = null;
            return self.runSetUnanchoredDfa(udfa, haystack, start, haystack.len, mode, false, &unused_nul);
        }

        // FP3 Tier B: On-demand bounded LazySetDfa for buffers >= 16 KiB
        if (self.has_byte_classes and !self.anchored_start and self.max_dfa_states > 0 and haystack.len - start >= 16_384) {
            var unused_nul: ?usize = null;
            return self.runLazySetDfa(haystack, start, haystack.len, mode, false, &unused_nul);
        }

        // Fallback: guaranteed O(N * M) Thompson PikeVM
        return self.runFindRange(haystack, start, haystack.len, haystack.len, mode);
    }

    fn findPrefix(
        self: *const RegexSet,
        pf: *const Multi,
        haystack: []const u8,
        start: usize,
        mode: MatchMode,
    ) ?Match {
        // Teddy fused findVerified when prefixes do not overlap (both `.leftmost_first` and `.earliest`)
        if (!self.has_prefix_overlap and std.mem.eql(u8, pf.engineName(), "teddy")) {
            var verifier = SetPrefixVerifier(false, false){
                .set = self,
                .full_haystack = haystack,
                .mode = mode,
            };
            return switch (pf.findVerified(haystack, start, mode, &verifier)) {
                .match => |vm| Match{ .start = vm.start, .end = vm.end, .pattern_id = verifier.matched_pid },
                .none, .aborted => null,
            };
        }

        var pos = start;
        var cached_win_end: usize = std.math.maxInt(usize);

        if (mode == .leftmost_first) {
            while (pos <= haystack.len) {
                const hit = pf.find(haystack, pos, .leftmost_first) orelse return null;
                if (!self.has_prefix_overlap) {
                    const lit_id: usize = hit.pattern_id orelse 0;
                    if (self.failsNextMask(haystack, hit.start, hit.end, lit_id)) {
                        if (hit.start >= haystack.len) return null;
                        pos = hit.start + 1;
                        continue;
                    }
                    const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                        cached_win_end
                    else blk: {
                        const w = self.windowLimit(haystack, hit.start);
                        cached_win_end = w;
                        break :blk w;
                    };
                    for (self.litOwners(lit_id)) |pid| {
                        if (self.runSinglePattern(pid, haystack, hit.start, hit.start, win_end, .leftmost_first, AllowAny{})) |m| {
                            return m;
                        }
                    }
                } else {
                    const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                        cached_win_end
                    else blk: {
                        const w = self.windowLimit(haystack, hit.start);
                        cached_win_end = w;
                        break :blk w;
                    };
                    if (self.runFindRange(haystack, hit.start, hit.start, win_end, .leftmost_first)) |m| {
                        return m;
                    }
                }
                if (hit.start >= haystack.len) return null;
                pos = hit.start + 1;
            }
            return null;
        }

        // `.earliest` mode: once `best` is found, stop probing when `next_start + pf_min_len >= best.end`
        var best: ?Match = null;
        while (pos <= haystack.len) {
            if (best) |cur| {
                if (pos +| self.pf_min_len >= cur.end) break;
            }
            const hit = pf.find(haystack, pos, .leftmost_first) orelse break;
            if (best) |cur| {
                if (hit.start +| self.pf_min_len >= cur.end) break;
            }
            if (!self.has_prefix_overlap) {
                const lit_id: usize = hit.pattern_id orelse 0;
                if (self.failsNextMask(haystack, hit.start, hit.end, lit_id)) {
                    if (hit.start >= haystack.len) break;
                    pos = hit.start + 1;
                    continue;
                }
                const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                    cached_win_end
                else blk: {
                    const w = self.windowLimit(haystack, hit.start);
                    cached_win_end = w;
                    break :blk w;
                };
                for (self.litOwners(lit_id)) |pid| {
                    if (self.runSinglePattern(pid, haystack, hit.start, hit.start, win_end, .earliest, AllowAny{})) |m| {
                        if (best == null or preferMatch(m, best.?, .earliest)) best = m;
                    }
                }
            } else {
                const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                    cached_win_end
                else blk: {
                    const w = self.windowLimit(haystack, hit.start);
                    cached_win_end = w;
                    break :blk w;
                };
                if (self.runFindRange(haystack, hit.start, hit.start, win_end, .earliest)) |m| {
                    if (best == null or preferMatch(m, best.?, .earliest)) best = m;
                }
            }
            if (hit.start >= haystack.len) break;
            pos = hit.start + 1;
        }
        return best;
    }

    fn verifySingleHitLine(
        self: *const RegexSet,
        haystack: []const u8,
        line_start: usize,
        win_end: usize,
        hit_start: usize,
        lit_id: usize,
        mode: MatchMode,
    ) ?Match {
        const owners = self.litOwners(lit_id);
        const lit_kind = self.pf_lit_kind[lit_id];
        const min_b = self.pf_min_before[lit_id];

        if (lit_kind == .prefix or lit_kind == .exact) {
            if (owners.len == 1) {
                return self.runSinglePattern(owners[0], haystack, hit_start, hit_start, win_end, mode, AllowAny{});
            }
            var best: ?Match = null;
            for (owners) |pid| {
                if (self.runSinglePattern(pid, haystack, hit_start, hit_start, win_end, mode, AllowAny{})) |m| {
                    if (mode == .leftmost_first) return m;
                    if (best == null or preferMatch(m, best.?, mode)) best = m;
                }
            }
            return best;
        }

        // Interior literal: any match of an owning pattern starts in `[line_start .. hit_start - min_b]`
        if (hit_start < line_start + min_b) return null;
        const start_hi = hit_start - min_b;
        if (owners.len == 1) {
            return self.runSinglePattern(owners[0], haystack, line_start, start_hi, win_end, mode, AllowAny{});
        }
        var best: ?Match = null;
        for (owners) |pid| {
            if (self.runSinglePattern(pid, haystack, line_start, start_hi, win_end, mode, AllowAny{})) |m| {
                if (best == null or preferMatch(m, best.?, mode)) best = m;
            }
        }
        return best;
    }

    fn findInterior(
        self: *const RegexSet,
        pf: *const Multi,
        haystack: []const u8,
        start: usize,
        mode: MatchMode,
    ) ?Match {
        var pos = start;
        var min_start = start;

        if (!self.multiline) {
            while (pos <= haystack.len) {
                const hit = pf.find(haystack, pos, .leftmost_first) orelse return null;
                const win_end = self.windowLimit(haystack, hit.start);
                const line_start = @max(min_start, lineStartAt(haystack, hit.start));

                const has_second_hit = (hit.start + 1 < win_end) and
                    (pf.find(haystack[0..win_end], hit.start + 1, .leftmost_first) != null);

                if (!has_second_hit and !self.has_prefix_overlap) {
                    const lit_id: usize = hit.pattern_id orelse 0;
                    if (self.verifySingleHitLine(haystack, line_start, win_end, hit.start, lit_id, mode)) |m| {
                        return m;
                    }
                } else {
                    if (self.runFindRange(haystack, line_start, win_end, win_end, mode)) |m| {
                        return m;
                    }
                }

                pos = @min(haystack.len + 1, win_end + 1);
                min_start = pos;
            }
            return null;
        }

        // Multiline interior literal search
        while (pos <= haystack.len) {
            const hit = pf.find(haystack, pos, .leftmost_first) orelse return null;
            const search_from = @max(min_start, hit.end -| self.max_multiline_window);
            const win_end = @min(haystack.len, hit.start +| self.max_multiline_window);
            if (search_from <= hit.start) {
                if (self.runFindRange(haystack, search_from, hit.start, win_end, mode)) |m| {
                    return m;
                }
            }
            if (hit.start >= haystack.len) return null;
            pos = hit.start + 1;
        }
        return null;
    }

    /// Half-match fast path returning the exact match end offset (`?usize`) without recovering `start`
    /// when `SetUnanchoredDfa` or `LazySetDfa` reaches an exact accepting state.
    pub fn findEnd(self: *const RegexSet, haystack: []const u8, start: usize, mode: MatchMode) ?usize {
        if (self.pattern_count == 0 or self.insts.len == 0 or start > haystack.len) return null;
        if (self.anchored_start and start > 0) return null;

        if (self.all_exact) {
            if (self.prefilter) |*pf| {
                const hit = pf.find(haystack, start, mode) orelse return null;
                return hit.end;
            }
        }
        if (self.prefilter == null and mode == .earliest and !self.multiline) {
            if (self.set_unanchored_dfa) |udfa| {
                if (udfa.has_exact_match) {
                    var unused_nul: ?usize = null;
                    return self.runSetUnanchoredDfaEnd(udfa, haystack, start, haystack.len, false, &unused_nul);
                }
            } else if (self.has_byte_classes and !self.anchored_start and self.max_dfa_states > 0 and haystack.len - start >= 16_384) {
                var unused_nul: ?usize = null;
                return self.runLazySetDfaEnd(haystack, start, haystack.len, false, &unused_nul);
            }
        }

        const m = self.find(haystack, start, mode) orelse return null;
        return m.end;
    }

    /// NUL-watched half-match fast path returning the exact match end offset (`?usize`).
    /// Sets `nul.*` and returns `null` if a NUL byte occurs strictly before the match ends.
    pub fn findEndWatched(self: *const RegexSet, haystack: []const u8, start: usize, mode: MatchMode, nul: *?usize) ?usize {
        if (self.pattern_count == 0 or self.insts.len == 0 or start > haystack.len) return null;
        if (!self.anchored_start) {
            if (self.all_exact) {
                if (self.prefilter) |*pf| {
                    const hit = pf.findWatched(haystack, start, nul) orelse return null;
                    return hit.end;
                }
            }
            if (self.prefilter == null and mode == .earliest and !self.multiline) {
                if (self.set_unanchored_dfa) |udfa| {
                    if (udfa.has_exact_match) {
                        return self.runSetUnanchoredDfaEnd(udfa, haystack, start, haystack.len, true, nul);
                    }
                } else if (self.has_byte_classes and self.max_dfa_states > 0 and haystack.len - start >= 16_384) {
                    return self.runLazySetDfaEnd(haystack, start, haystack.len, true, nul);
                }
            }
        }
        const m = self.findWatched(haystack, start, nul) orelse return null;
        return m.end;
    }

    pub fn findWatched(self: *const RegexSet, haystack: []const u8, start: usize, nul: *?usize) ?Match {
        if (self.pattern_count == 0 or self.insts.len == 0 or start > haystack.len) return null;

        if (!self.anchored_start) {
            // FP0: exact literals
            if (self.all_exact) {
                if (self.prefilter) |*pf| {
                    const hit = pf.findWatched(haystack, start, nul) orelse return null;
                    const lit_id: usize = hit.pattern_id orelse 0;
                    return Match{
                        .start = hit.start,
                        .end = hit.end,
                        .pattern_id = self.litOwners(lit_id)[0],
                    };
                }
            }

            // FP1: all prefix literals
            if (self.all_prefix) {
                if (self.prefilter) |*pf| {
                    return self.findWatchedPrefix(pf, haystack, start, nul);
                }
            }

            // FP2: interior / mixed literals
            if (self.prefilter) |*pf| {
                return self.findWatchedInterior(pf, haystack, start, nul);
            }

            // FP3 Tier A: AOT SetUnanchoredDfa
            if (self.set_unanchored_dfa) |udfa| {
                return self.runSetUnanchoredDfa(udfa, haystack, start, haystack.len, .earliest, true, nul);
            }

            // FP3 Tier B: LazySetDfa for >= 16 KiB
            if (self.has_byte_classes and self.max_dfa_states > 0 and haystack.len - start >= 16_384) {
                return self.runLazySetDfa(haystack, start, haystack.len, .earliest, true, nul);
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

    fn findWatchedPrefix(
        self: *const RegexSet,
        pf: *const Multi,
        haystack: []const u8,
        start: usize,
        nul: *?usize,
    ) ?Match {
        // Teddy fused findVerifiedWatched when prefixes do not overlap
        if (!self.has_prefix_overlap and std.mem.eql(u8, pf.engineName(), "teddy")) {
            var verifier = SetPrefixVerifier(true, false){
                .set = self,
                .full_haystack = haystack,
                .mode = .earliest,
                .orig_start = start,
            };
            return switch (pf.findVerifiedWatched(haystack, start, .earliest, nul, &verifier)) {
                .match => |vm| checkWatchedMatch(haystack, vm.start, Match{
                    .start = vm.start,
                    .end = vm.end,
                    .pattern_id = verifier.matched_pid,
                }, nul),
                .none => null,
                .aborted => |resume_pos| self.findWatchedPrefixChunked(pf, haystack, resume_pos, nul),
            };
        }

        var pos = start;
        var rejects: usize = 0;
        var cached_win_end: usize = std.math.maxInt(usize);

        while (pos <= haystack.len) {
            const raw_hit = pf.findWatched(haystack, pos, nul) orelse return null;
            const lo = @max(pos, raw_hit.end -| self.pf_max_len);
            const hi_slice = @min(haystack.len, raw_hit.start +| self.pf_max_len);
            const hit = if (lo < raw_hit.start)
                (pf.find(haystack[0..hi_slice], lo, .leftmost_first) orelse raw_hit)
            else
                raw_hit;

            var best: ?Match = null;
            if (!self.has_prefix_overlap) {
                const lit_id: usize = hit.pattern_id orelse 0;
                if (!self.failsNextMask(haystack, hit.start, hit.end, lit_id)) {
                    const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                        cached_win_end
                    else blk: {
                        const w = self.windowLimit(haystack, hit.start);
                        cached_win_end = w;
                        break :blk w;
                    };
                    for (self.litOwners(lit_id)) |pid| {
                        if (self.runSinglePattern(pid, haystack, hit.start, hit.start, win_end, .earliest, AllowAny{})) |m| {
                            if (best == null or preferMatch(m, best.?, .earliest)) best = m;
                        }
                    }
                }
            } else {
                const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                    cached_win_end
                else blk: {
                    const w = self.windowLimit(haystack, hit.start);
                    cached_win_end = w;
                    break :blk w;
                };
                best = self.runFindRange(haystack, hit.start, hit.start, win_end, .earliest);
            }

            if (best) |cur0| {
                var cur = cur0;
                // Check if any later prefix hit before `cur.end` yields an earlier-ending match
                if (hit.start + 1 +| self.pf_min_len < cur.end) {
                    var probe = hit.start + 1;
                    while (probe +| self.pf_min_len < cur.end) {
                        const nh = pf.find(haystack[0..cur.end], probe, .leftmost_first) orelse break;
                        if (nh.start +| self.pf_min_len >= cur.end) break;
                        if (!self.has_prefix_overlap) {
                            const nl_id: usize = nh.pattern_id orelse 0;
                            if (!self.failsNextMask(haystack, nh.start, nh.end, nl_id)) {
                                const p_win = @min(self.windowLimit(haystack, nh.start), cur.end);
                                for (self.litOwners(nl_id)) |pid| {
                                    if (self.runSinglePattern(pid, haystack, nh.start, nh.start, p_win, .earliest, AllowAny{})) |m2| {
                                        if (preferMatch(m2, cur, .earliest)) cur = m2;
                                    }
                                }
                            }
                        } else {
                            const p_win = @min(self.windowLimit(haystack, nh.start), cur.end);
                            if (self.runFindRange(haystack, nh.start, nh.start, p_win, .earliest)) |m2| {
                                if (preferMatch(m2, cur, .earliest)) cur = m2;
                            }
                        }
                        probe = nh.start + 1;
                    }
                }
                return checkWatchedMatch(haystack, raw_hit.end, cur, nul);
            }

            if (hit.start >= haystack.len) return null;
            const next_pos = hit.start + 1;
            const check_to = @min(next_pos, haystack.len);
            if (check_to > raw_hit.end) {
                if (memchr.find(memchr.native_width, haystack[0..check_to], raw_hit.end, 0)) |at| {
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

    fn findWatchedPrefixChunked(
        self: *const RegexSet,
        pf: *const Multi,
        haystack: []const u8,
        start_pos: usize,
        nul: *?usize,
    ) ?Match {
        var scan_pos = start_pos;
        var chunk_size: usize = 64 * 1024;
        const max_chunk_size: usize = 256 * 1024;
        const overlap = self.pf_max_len -| 1;
        const use_teddy_verified = !self.has_prefix_overlap and std.mem.eql(u8, pf.engineName(), "teddy");
        var cached_win_end: usize = std.math.maxInt(usize);

        while (scan_pos <= haystack.len) {
            const chunk_end = @min(haystack.len, scan_pos +| chunk_size);
            const nul_in_chunk = memchr.find(memchr.native_width, haystack[0..chunk_end], scan_pos, 0);
            const has_nul = nul_in_chunk != null;
            const eff_end = nul_in_chunk orelse chunk_end;
            const prefilter_end = if (has_nul) eff_end else @min(haystack.len, eff_end +| overlap);
            const pf_slice = haystack[0..prefilter_end];

            if (use_teddy_verified) {
                var verifier = SetPrefixVerifier(false, true){
                    .set = self,
                    .full_haystack = haystack,
                    .mode = .earliest,
                    .cand_limit = eff_end,
                };
                switch (pf.findVerified(pf_slice, scan_pos, .earliest, &verifier)) {
                    .match => |vm| {
                        var m = Match{ .start = vm.start, .end = vm.end, .pattern_id = verifier.matched_pid };
                        if (!has_nul and eff_end +| self.pf_min_len < m.end) {
                            var v2 = SetPrefixVerifier(false, false){
                                .set = self,
                                .full_haystack = haystack,
                                .mode = .earliest,
                            };
                            switch (pf.findVerified(haystack[0..m.end], eff_end, .earliest, &v2)) {
                                .match => |vm2| {
                                    const m2 = Match{ .start = vm2.start, .end = vm2.end, .pattern_id = v2.matched_pid };
                                    if (preferMatch(m2, m, .earliest)) m = m2;
                                },
                                .none, .aborted => {},
                            }
                        }
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
                        continue;
                    },
                }
            }

            var pos = scan_pos;
            var best: ?Match = null;
            while (pos < eff_end) {
                if (best) |cur| {
                    if (pos +| self.pf_min_len >= cur.end) break;
                }
                const hit = pf.find(pf_slice, pos, .leftmost_first) orelse break;
                if (hit.start >= eff_end) break;
                if (best) |cur| {
                    if (hit.start +| self.pf_min_len >= cur.end) break;
                }
                if (!self.has_prefix_overlap) {
                    const lit_id: usize = hit.pattern_id orelse 0;
                    if (self.failsNextMask(haystack, hit.start, hit.end, lit_id)) {
                        pos = hit.start + 1;
                        continue;
                    }
                    const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                        cached_win_end
                    else blk: {
                        const w = self.windowLimit(haystack, hit.start);
                        cached_win_end = w;
                        break :blk w;
                    };
                    for (self.litOwners(lit_id)) |pid| {
                        if (self.runSinglePattern(pid, haystack, hit.start, hit.start, win_end, .earliest, AllowAny{})) |m| {
                            if (best == null or preferMatch(m, best.?, .earliest)) best = m;
                        }
                    }
                } else {
                    const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                        cached_win_end
                    else blk: {
                        const w = self.windowLimit(haystack, hit.start);
                        cached_win_end = w;
                        break :blk w;
                    };
                    if (self.runFindRange(haystack, hit.start, hit.start, win_end, .earliest)) |m| {
                        if (best == null or preferMatch(m, best.?, .earliest)) best = m;
                    }
                }
                pos = hit.start + 1;
            }
            if (best) |m0| {
                var m = m0;
                // If `m.end` extended past `eff_end` in a non-NUL chunk, check if a hit in `[eff_end..m.end)` beats `m`
                if (!has_nul and eff_end +| self.pf_min_len < m.end) {
                    var probe = eff_end;
                    while (probe +| self.pf_min_len < m.end) {
                        const nh = pf.find(haystack[0..m.end], probe, .leftmost_first) orelse break;
                        if (nh.start +| self.pf_min_len >= m.end) break;
                        if (!self.has_prefix_overlap) {
                            const nl_id: usize = nh.pattern_id orelse 0;
                            if (!self.failsNextMask(haystack, nh.start, nh.end, nl_id)) {
                                const p_win = @min(self.windowLimit(haystack, nh.start), m.end);
                                for (self.litOwners(nl_id)) |pid| {
                                    if (self.runSinglePattern(pid, haystack, nh.start, nh.start, p_win, .earliest, AllowAny{})) |m2| {
                                        if (preferMatch(m2, m, .earliest)) m = m2;
                                    }
                                }
                            }
                        } else {
                            const p_win = @min(self.windowLimit(haystack, nh.start), m.end);
                            if (self.runFindRange(haystack, nh.start, nh.start, p_win, .earliest)) |m2| {
                                if (preferMatch(m2, m, .earliest)) m = m2;
                            }
                        }
                        probe = nh.start + 1;
                    }
                }
                if (has_nul) {
                    if (m.end <= eff_end) return m;
                    nul.* = eff_end;
                    return null;
                }
                return checkWatchedMatch(haystack, eff_end, m, nul);
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

    fn findWatchedInterior(
        self: *const RegexSet,
        pf: *const Multi,
        haystack: []const u8,
        start: usize,
        nul: *?usize,
    ) ?Match {
        var pos = start;
        var min_start = start;
        var rejects: usize = 0;

        while (pos <= haystack.len) {
            const raw_hit = pf.findWatched(haystack, pos, nul) orelse return null;
            const lo = @max(pos, raw_hit.end -| self.pf_max_len);
            const hi_slice = @min(haystack.len, raw_hit.start +| self.pf_max_len);
            const hit = if (lo < raw_hit.start)
                (pf.find(haystack[0..hi_slice], lo, .leftmost_first) orelse raw_hit)
            else
                raw_hit;

            if (!self.multiline) {
                const win_end = self.windowLimit(haystack, hit.start);
                const line_start = @max(min_start, lineStartAt(haystack, hit.start));
                const has_second_hit = (hit.start + 1 < win_end) and
                    (pf.find(haystack[0..win_end], hit.start + 1, .leftmost_first) != null);

                const found: ?Match = if (!has_second_hit and !self.has_prefix_overlap)
                    self.verifySingleHitLine(haystack, line_start, win_end, hit.start, hit.pattern_id orelse 0, .earliest)
                else
                    self.runFindRange(haystack, line_start, win_end, win_end, .earliest);

                if (found) |m| {
                    return checkWatchedMatch(haystack, raw_hit.end, m, nul);
                }

                const next_pos = @min(haystack.len + 1, win_end + 1);
                const check_to = @min(next_pos, haystack.len);
                if (check_to > raw_hit.end) {
                    if (memchr.find(memchr.native_width, haystack[0..check_to], raw_hit.end, 0)) |at| {
                        nul.* = at;
                        return null;
                    }
                }
                pos = next_pos;
                min_start = pos;
            } else {
                const search_from = @max(min_start, hit.end -| self.max_multiline_window);
                const win_end = @min(haystack.len, hit.start +| self.max_multiline_window);
                if (search_from <= hit.start) {
                    if (self.runFindRange(haystack, search_from, hit.start, win_end, .earliest)) |m| {
                        return checkWatchedMatch(haystack, raw_hit.end, m, nul);
                    }
                }
                if (hit.start >= haystack.len) return null;
                const next_pos = hit.start + 1;
                const check_to = @min(next_pos, haystack.len);
                if (check_to > raw_hit.end) {
                    if (memchr.find(memchr.native_width, haystack[0..check_to], raw_hit.end, 0)) |at| {
                        nul.* = at;
                        return null;
                    }
                }
                pos = next_pos;
            }

            rejects += 1;
            if (rejects >= 16 and pos <= start + 32 * 1024 and haystack.len -| pos >= 64 * 1024) {
                return self.findWatchedInteriorChunked(pf, haystack, pos, min_start, nul);
            }
        }
        return null;
    }

    fn findWatchedInteriorChunked(
        self: *const RegexSet,
        pf: *const Multi,
        haystack: []const u8,
        start_pos: usize,
        start_min_start: usize,
        nul: *?usize,
    ) ?Match {
        var scan_pos = start_pos;
        var min_start = start_min_start;
        var chunk_size: usize = 64 * 1024;
        const max_chunk_size: usize = 256 * 1024;
        const overlap = self.pf_max_len -| 1;

        while (scan_pos <= haystack.len) {
            const chunk_end = @min(haystack.len, scan_pos +| chunk_size);
            const nul_in_chunk = memchr.find(memchr.native_width, haystack[0..chunk_end], scan_pos, 0);
            const has_nul = nul_in_chunk != null;
            const eff_end = nul_in_chunk orelse chunk_end;
            const prefilter_end = if (has_nul) eff_end else @min(haystack.len, eff_end +| overlap);
            const pf_slice = haystack[0..prefilter_end];

            var pos = scan_pos;
            while (pos < eff_end) {
                const hit = pf.find(pf_slice, pos, .leftmost_first) orelse break;
                if (hit.start >= eff_end) break;

                if (!self.multiline) {
                    const win_end = self.windowLimit(haystack, hit.start);
                    const line_start = @max(min_start, lineStartAt(haystack, hit.start));
                    const has_second_hit = (hit.start + 1 < win_end) and
                        (pf.find(haystack[0..win_end], hit.start + 1, .leftmost_first) != null);

                    const found: ?Match = if (!has_second_hit and !self.has_prefix_overlap)
                        self.verifySingleHitLine(haystack, line_start, win_end, hit.start, hit.pattern_id orelse 0, .earliest)
                    else
                        self.runFindRange(haystack, line_start, win_end, win_end, .earliest);

                    if (found) |m| {
                        if (has_nul) {
                            if (m.end <= eff_end) return m;
                            nul.* = eff_end;
                            return null;
                        }
                        return checkWatchedMatch(haystack, eff_end, m, nul);
                    }

                    pos = @min(haystack.len + 1, win_end + 1);
                    min_start = pos;
                } else {
                    const search_from = @max(min_start, hit.end -| self.max_multiline_window);
                    const win_end = @min(haystack.len, hit.start +| self.max_multiline_window);
                    if (search_from <= hit.start) {
                        if (self.runFindRange(haystack, search_from, hit.start, win_end, .earliest)) |m| {
                            if (has_nul) {
                                if (m.end <= eff_end) return m;
                                nul.* = eff_end;
                                return null;
                            }
                            return checkWatchedMatch(haystack, eff_end, m, nul);
                        }
                    }
                    pos = hit.start + 1;
                }
            }
            if (has_nul) {
                nul.* = eff_end;
                return null;
            }
            if (eff_end >= haystack.len) return null;
            // Advance scan_pos without clobbering `min_start` mid-line so a line straddling `eff_end`
            // whose interior literal lies in the next chunk still recovers its full `line_start`.
            scan_pos = @max(eff_end, pos);
            chunk_size = @min(max_chunk_size, chunk_size * 2);
        }
        return null;
    }

    // ========================================================================
    // FP3 Tier A: SetUnanchoredDfa 4x-Unrolled ByteClasses + SIMD StartSkip
    // ========================================================================

    fn scanSetUnanchoredChunk(
        comptime TableT: type,
        comptime skip_tag: dfa_mod.StartSkipTag,
        comptime track_active: bool,
        dfa: *const SetUnanchoredDfa,
        trans: [*]const TableT,
        haystack: []const u8,
        pos_ptr: *usize,
        chunk_limit: usize,
        state_ptr: *u32,
        active_since_ptr: *usize,
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
                    const ns: u32 = trans[s + classes[haystack[pos]]];
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
                                if (next_pos > pos) {
                                    s = dfa.startStateForByte(haystack[next_pos - 1]);
                                    pos = next_pos;
                                }
                                const ns: u32 = trans[s + classes[haystack[pos]]];
                                if (ns > start_max) {
                                    if (comptime track_active) active_since = pos;
                                }
                                s = ns;
                                pos += 1;
                                if (s >= match_start) break;
                                if (s <= start_max) continue;
                            } else {
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

            // Active non-start state: 4x unrolled compact ByteClasses + pre-scaled table loop
            while (pos + 4 <= chunk_limit) {
                const s1: u32 = trans[s + classes[haystack[pos]]];
                if (s1 >= match_start) {
                    s = s1;
                    pos += 1;
                    break;
                }
                if (comptime track_active) {
                    if (s1 <= start_max) active_since = pos + 1;
                }
                const s2: u32 = trans[s1 + classes[haystack[pos + 1]]];
                if (s2 >= match_start) {
                    s = s2;
                    pos += 2;
                    break;
                }
                if (comptime track_active) {
                    if (s2 <= start_max) active_since = pos + 2;
                }
                const s3: u32 = trans[s2 + classes[haystack[pos + 2]]];
                if (s3 >= match_start) {
                    s = s3;
                    pos += 3;
                    break;
                }
                if (comptime track_active) {
                    if (s3 <= start_max) active_since = pos + 3;
                }
                const s4: u32 = trans[s3 + classes[haystack[pos + 3]]];
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

    inline fn dispatchScanSetUnanchored(
        comptime track_active: bool,
        dfa: *const SetUnanchoredDfa,
        haystack: []const u8,
        pos_ptr: *usize,
        chunk_limit: usize,
        state_ptr: *u32,
        active_since_ptr: *usize,
    ) void {
        switch (dfa.table_kind) {
            .u8_tbl => {
                const trans: [*]const u8 = &dfa.trans_u8;
                switch (dfa.start_skip) {
                    inline else => |_, tag| scanSetUnanchoredChunk(u8, tag, track_active, dfa, trans, haystack, pos_ptr, chunk_limit, state_ptr, active_since_ptr),
                }
            },
            .u16_tbl => {
                const trans: [*]const u16 = dfa.trans_u16.ptr;
                switch (dfa.start_skip) {
                    inline else => |_, tag| scanSetUnanchoredChunk(u16, tag, track_active, dfa, trans, haystack, pos_ptr, chunk_limit, state_ptr, active_since_ptr),
                }
            },
            .u32_tbl => {
                const trans: [*]const u32 = dfa.trans_u32.ptr;
                switch (dfa.start_skip) {
                    inline else => |_, tag| scanSetUnanchoredChunk(u32, tag, track_active, dfa, trans, haystack, pos_ptr, chunk_limit, state_ptr, active_since_ptr),
                }
            },
        }
    }

    fn runSetUnanchoredDfaEnd(
        self: *const RegexSet,
        dfa: *const SetUnanchoredDfa,
        haystack: []const u8,
        start: usize,
        limit: usize,
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
        var s: u32 = dfa.startStateAt(haystack, start);
        var cached_win_end: usize = std.math.maxInt(usize);
        var cached_line_start: usize = start;

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

            dispatchScanSetUnanchored(false, dfa, haystack, &pos, chunk_limit, &s, &unused_active);

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
                if (self.runFindRange(haystack, line_start, start_hi, win_end, .earliest)) |m| {
                    return m.end;
                }
            }
            search_floor = cand_end;
            pos = cand_end;
            s = dfa.startStateAt(haystack, cand_end);
        }

        if (s < match_start and pos > search_floor and dfa.eoi_kind.len != 0) {
            const eoi = dfa.eoi_kind[@intCast(s / dfa.stride)];
            if (eoi == .exact) return pos;
            if (eoi == .verify) {
                const probe_pos = pos - 1;
                const line_start = @max(search_floor, lineStartAt(haystack, probe_pos));
                if (line_start <= probe_pos) {
                    if (self.runFindRange(haystack, line_start, probe_pos, pos, .earliest)) |m| {
                        return m.end;
                    }
                }
            }
        }

        if (watch_nul) {
            if (nul_found) |z| nul.* = z;
        }
        return null;
    }

    fn runSetUnanchoredDfa(
        self: *const RegexSet,
        dfa: *const SetUnanchoredDfa,
        haystack: []const u8,
        start: usize,
        limit: usize,
        mode: MatchMode,
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
        var s: u32 = dfa.startStateAt(haystack, start);
        var cached_win_end: usize = std.math.maxInt(usize);
        var cached_line_start: usize = start;

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

            dispatchScanSetUnanchored(true, dfa, haystack, &pos, chunk_limit, &s, &active_since);

            if (s < match_start) continue;

            const is_delayed = (s == dfa.verify_del_off or s == dfa.exact_del_off);
            const cand_end: usize = if (is_delayed) pos - 1 else pos;
            const probe_pos: usize = if (cand_end > 0) cand_end - 1 else 0;

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
                    if (self.runFindRange(haystack, line_start, win_end, win_end, mode)) |m| {
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
                    if (self.runFindRange(haystack, search_lo, start_hi, win_end, mode)) |m| {
                        if (mode == .earliest and m.end > cand_end + 1) {
                            const earlier_lim = @min(m.end, win_end);
                            if (cand_end < earlier_lim) {
                                if (self.runFindRange(haystack, cand_end, earlier_lim, earlier_lim, .earliest)) |m2| {
                                    if (preferMatch(m2, m, .earliest)) return m2;
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
                    if (self.runFindRange(haystack, search_lo, start_hi, eff_verify_limit, mode)) |m| {
                        if (mode == .earliest and m.end > cand_end + 1) {
                            const earlier_lim = @min(m.end, eff_verify_limit);
                            if (cand_end < earlier_lim) {
                                if (self.runFindRange(haystack, cand_end, earlier_lim, earlier_lim, .earliest)) |m2| {
                                    if (preferMatch(m2, m, .earliest)) return m2;
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

        if (s < match_start and pos > search_floor and dfa.eoi_kind.len != 0) {
            const eoi = dfa.eoi_kind[@intCast(s / dfa.stride)];
            if (eoi != .none) {
                const probe_pos = pos - 1;
                const line_start = @max(search_floor, lineStartAt(haystack, probe_pos));
                const search_lo = if (dfa.start_reentrant) line_start else @max(line_start, active_since);
                if (search_lo <= probe_pos) {
                    if (self.runFindRange(haystack, search_lo, probe_pos, pos, mode)) |m| {
                        return m;
                    }
                }
            }
        }

        if (watch_nul) {
            if (nul_found) |z| nul.* = z;
        }
        return null;
    }

    // ========================================================================
    // FP3 Tier B: Bounded On-Demand LazySetDfa Fallback (256 KiB, max 4 flushes)
    // ========================================================================

    fn runLazySetDfaEnd(
        self: *const RegexSet,
        haystack: []const u8,
        start: usize,
        limit: usize,
        comptime watch_nul: bool,
        nul: *?usize,
    ) ?usize {
        var lazy = LazySetDfa.init(
            self.allocator,
            self.insts,
            self.unicode_ranges,
            &self.byte_classes,
            self.start_pc,
            self.multiline,
            null,
            LazySetDfa.default_max_flushes,
        ) orelse {
            if (watch_nul) {
                const m = self.findWatchedFallback(haystack, start, limit, nul) orelse return null;
                return m.end;
            }
            const m = self.runFindRange(haystack, start, limit, limit, .earliest) orelse return null;
            return m.end;
        };
        defer lazy.deinit();

        var scan_limit: usize = limit;
        var nul_checked_to: usize = start;
        var nul_found: ?usize = null;

        var pos: usize = start;
        var search_floor: usize = start;
        var s: u16 = lazy.startStateAt(haystack, start);
        var cached_win_end: usize = std.math.maxInt(usize);
        var cached_line_start: usize = start;

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
            const stride: usize = lazy.stride;
            const classes = &lazy.classes;
            const trans = lazy.trans;

            while (pos < chunk_limit) {
                const ns = trans[@as(usize, s) * stride + classes[haystack[pos]]];
                if (ns < LazySetDfa.sentinel_min) {
                    s = ns;
                    pos += 1;
                    continue;
                }
                const stepped = if (ns == LazySetDfa.unknown_trans) lazy.step(s, haystack[pos]) else ns;
                if (stepped < LazySetDfa.sentinel_min) {
                    s = stepped;
                    pos += 1;
                    continue;
                }
                s = stepped;
                pos += 1;
                break;
            }

            if (s < LazySetDfa.sentinel_min) continue;

            if (s == LazySetDfa.bailout_trans) {
                const resume_from = if (!self.multiline)
                    @max(search_floor, lineStartAt(haystack, if (pos > 0) pos - 1 else 0))
                else
                    @max(search_floor, pos -| self.max_multiline_window);
                if (watch_nul) {
                    const m = self.findWatchedFallback(haystack, resume_from, scan_limit, nul);
                    if (m) |mm| return mm.end;
                    if (nul.* == null) {
                        if (nul_found) |z| nul.* = z;
                    }
                    return null;
                }
                const m = self.runFindRange(haystack, resume_from, scan_limit, scan_limit, .earliest) orelse return null;
                return m.end;
            }

            if (s == LazySetDfa.exact_del) return pos - 1;
            if (s == LazySetDfa.exact_imm) return pos;

            const cand_end: usize = if (s == LazySetDfa.verify_del) pos - 1 else pos;
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
                if (self.runFindRange(haystack, line_start, start_hi, win_end, .earliest)) |m| {
                    return m.end;
                }
            }
            search_floor = cand_end;
            pos = cand_end;
            s = lazy.startStateAt(haystack, cand_end);
        }

        if (s < LazySetDfa.sentinel_min and pos > search_floor) {
            const eoi = lazy.eoiKind(s);
            if (eoi == .exact) return pos;
            if (eoi == .verify) {
                const probe_pos = pos - 1;
                const line_start = @max(search_floor, lineStartAt(haystack, probe_pos));
                if (line_start <= probe_pos) {
                    if (self.runFindRange(haystack, line_start, probe_pos, pos, .earliest)) |m| {
                        return m.end;
                    }
                }
            }
        }

        if (watch_nul) {
            if (nul_found) |z| nul.* = z;
        }
        return null;
    }

    fn runLazySetDfa(
        self: *const RegexSet,
        haystack: []const u8,
        start: usize,
        limit: usize,
        mode: MatchMode,
        comptime watch_nul: bool,
        nul: *?usize,
    ) ?Match {
        var lazy = LazySetDfa.init(
            self.allocator,
            self.insts,
            self.unicode_ranges,
            &self.byte_classes,
            self.start_pc,
            self.multiline,
            null,
            LazySetDfa.default_max_flushes,
        ) orelse {
            if (watch_nul) return self.findWatchedFallback(haystack, start, limit, nul);
            return self.runFindRange(haystack, start, limit, limit, mode);
        };
        defer lazy.deinit();

        var scan_limit: usize = limit;
        var nul_checked_to: usize = start;
        var nul_found: ?usize = null;

        var pos: usize = start;
        var search_floor: usize = start;
        var active_since: usize = start;
        var s: u16 = lazy.startStateAt(haystack, start);
        var cached_win_end: usize = std.math.maxInt(usize);
        var cached_line_start: usize = start;

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
            const stride: usize = lazy.stride;
            const num_starts: u16 = lazy.num_starts;
            const classes = &lazy.classes;
            const trans = lazy.trans;

            while (pos < chunk_limit) {
                const ns = trans[@as(usize, s) * stride + classes[haystack[pos]]];
                if (ns < LazySetDfa.sentinel_min) {
                    if (s < num_starts and ns >= num_starts) {
                        active_since = pos;
                    } else if (ns < num_starts) {
                        active_since = pos + 1;
                    }
                    s = ns;
                    pos += 1;
                    continue;
                }
                const stepped = if (ns == LazySetDfa.unknown_trans) lazy.step(s, haystack[pos]) else ns;
                if (stepped < LazySetDfa.sentinel_min) {
                    if (s < num_starts and stepped >= num_starts) {
                        active_since = pos;
                    } else if (stepped < num_starts) {
                        active_since = pos + 1;
                    }
                    s = stepped;
                    pos += 1;
                    continue;
                }
                s = stepped;
                pos += 1;
                break;
            }

            if (s < LazySetDfa.sentinel_min) continue;

            if (s == LazySetDfa.bailout_trans) {
                const resume_from = if (!self.multiline)
                    @max(search_floor, lineStartAt(haystack, if (pos > 0) pos - 1 else 0))
                else
                    @max(search_floor, pos -| self.max_multiline_window);
                if (watch_nul) {
                    const m = self.findWatchedFallback(haystack, resume_from, scan_limit, nul);
                    if (m == null and nul.* == null) {
                        if (nul_found) |z| nul.* = z;
                    }
                    return m;
                }
                return self.runFindRange(haystack, resume_from, scan_limit, scan_limit, mode);
            }

            const is_delayed = (s == LazySetDfa.verify_del or s == LazySetDfa.exact_del);
            const cand_end: usize = if (is_delayed) pos - 1 else pos;
            const probe_pos: usize = if (cand_end > 0) cand_end - 1 else 0;

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

                if (lazy.start_reentrant) {
                    if (self.runFindRange(haystack, line_start, win_end, win_end, mode)) |m| return m;
                    if (win_end >= scan_limit) {
                        pos = scan_limit;
                        break;
                    }
                    pos = win_end + 1;
                    if (watch_nul and pos > nul_checked_to) nul_checked_to = pos;
                    search_floor = pos;
                    active_since = pos;
                    s = lazy.startStateAt(haystack, pos);
                    continue;
                }

                const search_lo = @max(line_start, active_since);
                const start_hi = probe_pos;
                if (cand_end > 0 and search_lo <= start_hi) {
                    if (self.runFindRange(haystack, search_lo, start_hi, win_end, mode)) |m| {
                        if (mode == .earliest and m.end > cand_end + 1) {
                            const earlier_lim = @min(m.end, win_end);
                            if (cand_end < earlier_lim) {
                                if (self.runFindRange(haystack, cand_end, earlier_lim, earlier_lim, .earliest)) |m2| {
                                    if (preferMatch(m2, m, .earliest)) return m2;
                                }
                            }
                        }
                        return m;
                    }
                }
                search_floor = cand_end;
                active_since = cand_end;
                pos = cand_end;
                s = lazy.startStateAt(haystack, cand_end);
            } else {
                const search_lo = blk: {
                    var lo = @max(search_floor, cand_end -| self.max_multiline_window);
                    if (!lazy.start_reentrant) lo = @max(lo, active_since);
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
                    if (self.runFindRange(haystack, search_lo, start_hi, eff_verify_limit, mode)) |m| {
                        if (mode == .earliest and m.end > cand_end + 1) {
                            const earlier_lim = @min(m.end, eff_verify_limit);
                            if (cand_end < earlier_lim) {
                                if (self.runFindRange(haystack, cand_end, earlier_lim, earlier_lim, .earliest)) |m2| {
                                    if (preferMatch(m2, m, .earliest)) return m2;
                                }
                            }
                        }
                        return m;
                    }
                }
                search_floor = cand_end;
                active_since = cand_end;
                pos = cand_end;
                s = lazy.startStateAt(haystack, cand_end);
            }
        }

        if (s < LazySetDfa.sentinel_min and pos > search_floor) {
            const eoi = lazy.eoiKind(s);
            if (eoi != .none) {
                const probe_pos = pos - 1;
                const line_start = @max(search_floor, lineStartAt(haystack, probe_pos));
                const search_lo = if (lazy.start_reentrant) line_start else @max(line_start, active_since);
                if (search_lo <= probe_pos) {
                    if (self.runFindRange(haystack, search_lo, probe_pos, pos, mode)) |m| return m;
                }
            }
        }

        if (watch_nul) {
            if (nul_found) |z| nul.* = z;
        }
        return null;
    }

    fn findWatchedFallback(
        self: *const RegexSet,
        haystack: []const u8,
        start: usize,
        limit: usize,
        nul: *?usize,
    ) ?Match {
        const hit = self.runFindRange(haystack, start, limit, limit, .earliest);
        const check_lim = if (hit) |m| @min(limit, @max(start, m.end)) else limit;
        if (start < check_lim) {
            if (memchr.find(memchr.native_width, haystack[0..check_lim], start, 0)) |at| {
                nul.* = at;
                return null;
            }
        }
        return hit;
    }

    pub fn findAllowed(
        self: *const RegexSet,
        haystack: []const u8,
        start: usize,
        mode: MatchMode,
        allow_arg: anytype,
    ) ?Match {
        var pos = start;
        while (pos <= haystack.len) {
            const hit = self.find(haystack, pos, mode) orelse return null;
            if (inst_mod.invokeAllow(allow_arg, haystack, hit.start, hit.end)) return hit;
            const win_end = self.windowLimit(haystack, hit.start);
            if (self.runFindRangeSpan(haystack, hit.start, hit.start, win_end, mode, false, allow_arg)) |alt| {
                return alt;
            }
            pos = hit.start + 1;
        }
        return null;
    }

    pub fn findAllowedReadOnly(
        self: *const RegexSet,
        haystack: []const u8,
        start: usize,
        mode: MatchMode,
        allow_arg: anytype,
    ) ?Match {
        return self.findAllowed(haystack, start, mode, allow_arg);
    }

    /// Evaluates all compiled patterns against `haystack` and writes the matching
    /// 0-based pattern indices (in ascending order) into `out_ids`. Returns the number of IDs written.
    pub fn matches(self: *const RegexSet, haystack: []const u8, out_ids: []u32) usize {
        if (self.pattern_count == 0 or self.insts.len == 0) return 0;

        const n_pats = self.pattern_count;
        var stack_matched: [1024]bool = undefined;
        var heap_matched: []bool = &.{};
        defer if (heap_matched.len != 0) self.allocator.free(heap_matched);

        const matched_flags: []bool = if (n_pats <= 1024) stack_matched[0..n_pats] else blk: {
            heap_matched = self.allocator.alloc(bool, n_pats) catch return 0;
            break :blk heap_matched;
        };
        @memset(matched_flags, false);
        var matched_count: usize = 0;

        if (self.all_exact) {
            if (self.prefilter) |*pf| {
                var pos: usize = 0;
                while (pos <= haystack.len and matched_count < n_pats) {
                    const hit = pf.find(haystack, pos, .leftmost_first) orelse break;
                    if (!self.has_prefix_overlap) {
                        const lit_id: usize = hit.pattern_id orelse 0;
                        for (self.litOwners(lit_id)) |pid| {
                            if (pid < n_pats and !matched_flags[pid]) {
                                matched_flags[pid] = true;
                                matched_count += 1;
                            }
                        }
                    } else {
                        for (self.prefix_slices, 0..) |lit, lid| {
                            const owners = self.litOwners(lid);
                            var need = false;
                            for (owners) |pid| {
                                if (pid < n_pats and !matched_flags[pid]) {
                                    need = true;
                                    break;
                                }
                            }
                            if (!need) continue;
                            if (literalStartsWith(haystack[hit.start..], lit, self.any_ignore_case, self.unicode_case)) {
                                for (owners) |pid| {
                                    if (pid < n_pats and !matched_flags[pid]) {
                                        matched_flags[pid] = true;
                                        matched_count += 1;
                                    }
                                }
                            }
                        }
                    }
                    if (hit.start >= haystack.len) break;
                    pos = hit.start + 1;
                }
                return writeMatchedIds(matched_flags, out_ids);
            }
        }

        if (self.prefilter) |*pf| {
            if (!self.multiline) {
                var pos: usize = 0;
                while (pos <= haystack.len and matched_count < n_pats) {
                    const hit = pf.find(haystack, pos, .leftmost_first) orelse break;
                    const win_end = self.windowLimit(haystack, hit.start);
                    const line_start = lineStartAt(haystack, hit.start);

                    if (self.all_prefix and !self.has_prefix_overlap) {
                        const lit_id: usize = hit.pattern_id orelse 0;
                        for (self.litOwners(lit_id)) |pid| {
                            if (pid < n_pats and !matched_flags[pid]) {
                                if (self.runSinglePattern(pid, haystack, hit.start, hit.start, win_end, .earliest, AllowAny{}) != null) {
                                    matched_flags[pid] = true;
                                    matched_count += 1;
                                }
                            }
                        }
                        if (hit.start >= haystack.len) break;
                        pos = hit.start + 1;
                    } else {
                        const has_second_hit = (hit.start + 1 < win_end) and
                            (pf.find(haystack[0..win_end], hit.start + 1, .leftmost_first) != null);
                        if (!has_second_hit and !self.has_prefix_overlap) {
                            const lit_id: usize = hit.pattern_id orelse 0;
                            const lit_kind = self.pf_lit_kind[lit_id];
                            const min_b = self.pf_min_before[lit_id];
                            for (self.litOwners(lit_id)) |pid| {
                                if (pid < n_pats and !matched_flags[pid]) {
                                    const matched_one = if (lit_kind == .prefix or lit_kind == .exact)
                                        self.runSinglePattern(pid, haystack, hit.start, hit.start, win_end, .earliest, AllowAny{}) != null
                                    else if (hit.start >= line_start + min_b)
                                        self.runSinglePattern(pid, haystack, line_start, hit.start - min_b, win_end, .earliest, AllowAny{}) != null
                                    else
                                        false;
                                    if (matched_one) {
                                        matched_flags[pid] = true;
                                        matched_count += 1;
                                    }
                                }
                            }
                        } else {
                            self.matchesPikeVmRange(haystack, line_start, win_end, matched_flags, &matched_count);
                        }
                        pos = @min(haystack.len + 1, win_end + 1);
                    }
                }
                return writeMatchedIds(matched_flags, out_ids);
            }
        } else if (!self.multiline) {
            if (self.set_unanchored_dfa) |udfa| {
                var pos: usize = 0;
                var unused_nul: ?usize = null;
                while (pos <= haystack.len and matched_count < n_pats) {
                    const cand_end = if (udfa.has_exact_match)
                        self.runSetUnanchoredDfaEnd(udfa, haystack, pos, haystack.len, false, &unused_nul) orelse break
                    else
                        (self.runSetUnanchoredDfa(udfa, haystack, pos, haystack.len, .earliest, false, &unused_nul) orelse break).end;
                    const probe = if (cand_end > pos) cand_end - 1 else cand_end;
                    const line_start = @max(pos, lineStartAt(haystack, probe));
                    const win_end = self.windowLimit(haystack, probe);
                    self.matchesPikeVmRange(haystack, line_start, win_end, matched_flags, &matched_count);
                    if (win_end >= haystack.len) break;
                    pos = win_end + 1;
                }
                return writeMatchedIds(matched_flags, out_ids);
            }
        }

        self.matchesPikeVmRange(haystack, 0, haystack.len, matched_flags, &matched_count);
        return writeMatchedIds(matched_flags, out_ids);
    }

    fn writeMatchedIds(matched_flags: []const bool, out_ids: []u32) usize {
        var written: usize = 0;
        for (matched_flags, 0..) |flag, id| {
            if (flag) {
                if (written < out_ids.len) {
                    out_ids[written] = @intCast(id);
                    written += 1;
                }
            }
        }
        return written;
    }

    fn matchesPikeVmRange(
        self: *const RegexSet,
        haystack: []const u8,
        start_pos: usize,
        limit: usize,
        matched_flags: []bool,
        matched_count: *usize,
    ) void {
        const n_inst = self.insts.len;
        const n_pats = self.pattern_count;
        if (n_inst == 0 or start_pos > limit or matched_count.* >= n_pats) return;

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
            heap_curr = self.allocator.alloc(Thread, n_inst) catch return;
            break :blk heap_curr;
        };
        var next: []Thread = if (n_inst <= 256) stack_next[0..n_inst] else blk: {
            heap_next = self.allocator.alloc(Thread, n_inst) catch return;
            break :blk heap_next;
        };
        const gen_table: []u32 = if (n_inst <= 256) stack_gen[0..n_inst] else blk: {
            heap_gen = self.allocator.alloc(u32, n_inst) catch return;
            break :blk heap_gen;
        };

        @memset(gen_table, 0);
        var gen: u32 = 1;
        var curr_len: usize = 0;

        var pos: usize = start_pos;
        while (true) {
            if (gen == std.math.maxInt(u32)) {
                @memset(gen_table, 0);
                gen = 1;
            }

            if (curr_len == 0 and (self.all_prefix or self.all_exact) and pos <= limit) {
                if (self.prefilter) |*pf| {
                    const next_hit = pf.find(haystack[0..limit], pos, .leftmost_first) orelse break;
                    pos = next_hit.start;
                }
            }

            if (pos <= limit and (!self.anchored_start or pos == 0)) {
                if (curr_len == 0 or !self.multiline) {
                    self.addThread(curr, &curr_len, gen_table, gen, self.start_pc, pos, haystack, pos);
                } else {
                    gen +%= 1;
                    if (gen == 0) {
                        @memset(gen_table, 0);
                        gen = 1;
                    }
                    var merged_len: usize = 0;
                    self.addThread(next, &merged_len, gen_table, gen, self.start_pc, pos, haystack, pos);
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
                if (pos >= limit or (self.anchored_start and pos > 0)) break;
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
                    .match_id => |pat_id| {
                        if (pat_id < n_pats and !matched_flags[pat_id]) {
                            matched_flags[pat_id] = true;
                            matched_count.* += 1;
                            if (matched_count.* == n_pats) break;
                        }
                    },
                    .match => {},
                    .byte => |by| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        const ok = if (by.ignore_case)
                            std.ascii.toLower(b) == std.ascii.toLower(by.b)
                        else
                            b == by.b;
                        if (ok and (!self.multiline or pos + 1 - th.start <= self.max_multiline_window)) {
                            self.addThread(next, &next_len, gen_table, gen, by.out, th.start, haystack, pos + 1);
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
                            self.addThread(next, &next_len, gen_table, gen, target_pc, th.start, haystack, pos + 1);
                        }
                    },
                    .any_cont => |ac| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        if ((b & 0xC0) == 0x80 and (!self.multiline or pos + 1 - th.start <= self.max_multiline_window)) {
                            self.addThread(next, &next_len, gen_table, gen, ac.out, th.start, haystack, pos + 1);
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
                                    self.addThread(next, &next_len, gen_table, gen, target_pc, th.start, haystack, pos + 1);
                                }
                                continue;
                            }
                        }
                        if (cl.set.contains(b) and (!self.multiline or pos + 1 - th.start <= self.max_multiline_window)) {
                            self.addThread(next, &next_len, gen_table, gen, cl.out, th.start, haystack, pos + 1);
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
                        if (matched and (!self.multiline or pos + dec.len - th.start <= self.max_multiline_window)) {
                            const target_pc: u32 = switch (dec.len) {
                                2 => if (uc.cont1 != 0) uc.cont1 else uc.out,
                                3 => if (uc.cont2 != 0) uc.cont2 else uc.out,
                                4 => if (uc.cont3 != 0) uc.cont3 else uc.out,
                                else => uc.out,
                            };
                            self.addThread(next, &next_len, gen_table, gen, target_pc, th.start, haystack, pos + 1);
                        }
                    },
                    .split, .jmp, .assert, .save => {},
                }
            }

            if (matched_count.* == n_pats or pos >= limit) break;
            if (!self.multiline and is_nl) {
                curr_len = 0;
            } else {
                const tmp = curr;
                curr = next;
                next = tmp;
                curr_len = next_len;
            }
            pos += 1;
        }
    }

    // ========================================================================
    // Per-Pattern Stack-Buffered Verification (`runSinglePattern`)
    // ========================================================================

    fn runSinglePattern(
        self: *const RegexSet,
        pat_id: u32,
        haystack: []const u8,
        start_lo: usize,
        start_hi: usize,
        limit: usize,
        mode: MatchMode,
        allow_arg: anytype,
    ) ?Match {
        if (pat_id >= self.pat_meta.len or start_lo > limit) return null;
        var window_clipped = false;
        const best = self.runSinglePatternOnce(pat_id, haystack, start_lo, start_hi, limit, mode, allow_arg, &window_clipped);
        if (!window_clipped or start_lo >= start_hi) return best;
        if (mode == .leftmost_first and best != null and best.?.start <= start_lo) return best;

        const lo_p = start_lo + 1;
        var max_p = @min(start_hi, limit);
        if (best) |bm| {
            if (mode == .leftmost_first) {
                max_p = @min(max_p, bm.start - 1);
            } else {
                max_p = @min(max_p, bm.end);
            }
        }
        var overall = best;
        var p = lo_p;
        while (p <= max_p) : (p += 1) {
            if (self.anchored_start and p > 0) break;
            var dummy_clip = false;
            const p_lim = @min(limit, self.windowLimit(haystack, p));
            if (self.runSinglePatternOnce(pat_id, haystack, p, p, p_lim, mode, allow_arg, &dummy_clip)) |m| {
                if (mode == .leftmost_first) return m;
                if (overall == null or preferMatch(m, overall.?, .earliest)) {
                    overall = m;
                    max_p = @min(max_p, m.end);
                }
            }
        }
        return overall;
    }

    fn runSinglePatternOnce(
        self: *const RegexSet,
        pat_id: u32,
        haystack: []const u8,
        start_lo: usize,
        start_hi: usize,
        limit: usize,
        mode: MatchMode,
        allow_arg: anytype,
        window_clipped: *bool,
    ) ?Match {
        const meta = self.pat_meta[pat_id];
        const inst_base = meta.inst_start;
        const n_inst: usize = meta.inst_end - meta.inst_start;
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

            if (best == null and pos <= start_hi and (!self.anchored_start or pos == 0)) {
                self.addThreadOffset(curr, &curr_len, gen_table, gen, inst_base, meta.start_pc, pos, haystack, pos);
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
                if (self.multiline and (pos - th.start > self.max_multiline_window)) {
                    window_clipped.* = true;
                    continue;
                }

                const inst = self.insts[th.pc];
                switch (inst) {
                    .match_id => |matched_pid| {
                        if (!inst_mod.invokeAllow(allow_arg, haystack, th.start, pos)) continue;
                        if (mode == .earliest) {
                            const cand = Match{ .start = th.start, .end = pos, .pattern_id = matched_pid };
                            if (best == null or preferMatch(cand, best.?, .earliest)) best = cand;
                            if (!window_clipped.*) return best;
                            break;
                        } else {
                            const cand = Match{ .start = th.start, .end = pos, .pattern_id = matched_pid };
                            if (best == null or preferMatch(cand, best.?, .leftmost_first)) best = cand;
                            break;
                        }
                    },
                    .match => {},
                    .byte => |by| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        const ok = if (by.ignore_case)
                            std.ascii.toLower(b) == std.ascii.toLower(by.b)
                        else
                            b == by.b;
                        if (ok) {
                            if (!self.multiline or pos + 1 - th.start <= self.max_multiline_window) {
                                self.addThreadOffset(next, &next_len, gen_table, gen, inst_base, by.out, th.start, haystack, pos + 1);
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
                            self.addThreadOffset(next, &next_len, gen_table, gen, inst_base, target_pc, th.start, haystack, pos + 1);
                        } else {
                            window_clipped.* = true;
                        }
                    },
                    .any_cont => |ac| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        if ((b & 0xC0) == 0x80) {
                            if (!self.multiline or pos + 1 - th.start <= self.max_multiline_window) {
                                self.addThreadOffset(next, &next_len, gen_table, gen, inst_base, ac.out, th.start, haystack, pos + 1);
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
                                    self.addThreadOffset(next, &next_len, gen_table, gen, inst_base, target_pc, th.start, haystack, pos + 1);
                                } else {
                                    window_clipped.* = true;
                                }
                                continue;
                            }
                        }
                        if (cl.set.contains(b)) {
                            if (!self.multiline or pos + 1 - th.start <= self.max_multiline_window) {
                                self.addThreadOffset(next, &next_len, gen_table, gen, inst_base, cl.out, th.start, haystack, pos + 1);
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
                                self.addThreadOffset(next, &next_len, gen_table, gen, inst_base, target_pc, th.start, haystack, pos + 1);
                            } else {
                                window_clipped.* = true;
                            }
                        }
                    },
                    .split, .jmp, .assert, .save => {},
                }
            }

            if (pos >= limit) break;
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

    fn addThreadOffset(
        self: *const RegexSet,
        list: []Thread,
        list_len: *usize,
        gen_table: []u32,
        gen: u32,
        inst_base: u32,
        pc: u32,
        start: usize,
        haystack: []const u8,
        pos: usize,
    ) void {
        const rel = pc - inst_base;
        if (gen_table[rel] == gen) return;
        gen_table[rel] = gen;

        switch (self.insts[pc]) {
            .jmp => |target| {
                self.addThreadOffset(list, list_len, gen_table, gen, inst_base, target, start, haystack, pos);
            },
            .split => |sp| {
                self.addThreadOffset(list, list_len, gen_table, gen, inst_base, sp.out1, start, haystack, pos);
                self.addThreadOffset(list, list_len, gen_table, gen, inst_base, sp.out2, start, haystack, pos);
            },
            .assert => |as| {
                if (checkAssert(as.kind, haystack, pos)) {
                    self.addThreadOffset(list, list_len, gen_table, gen, inst_base, as.out, start, haystack, pos);
                }
            },
            .save => |sv| {
                self.addThreadOffset(list, list_len, gen_table, gen, inst_base, sv.out, start, haystack, pos);
            },
            else => {
                list[list_len.*] = .{ .pc = pc, .start = start };
                list_len.* += 1;
            },
        }
    }

    fn windowLimit(self: *const RegexSet, haystack: []const u8, from: usize) usize {
        if (!self.multiline) {
            return memchr.find(memchr.native_width, haystack, from, '\n') orelse haystack.len;
        }
        return @min(haystack.len, from +| self.max_multiline_window);
    }

    fn runFindRange(
        self: *const RegexSet,
        haystack: []const u8,
        start_lo: usize,
        start_hi: usize,
        limit: usize,
        mode: MatchMode,
    ) ?Match {
        return self.runFindRangeSpan(haystack, start_lo, start_hi, limit, mode, false, AllowAny{});
    }

    fn runFindRangeSpan(
        self: *const RegexSet,
        haystack: []const u8,
        start_lo: usize,
        start_hi: usize,
        limit: usize,
        mode: MatchMode,
        require_full_span: bool,
        allow_arg: anytype,
    ) ?Match {
        var window_clipped = false;
        const best = self.runFindRangeOnce(haystack, start_lo, start_hi, limit, mode, require_full_span, allow_arg, &window_clipped);
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

        if (max_p - lo_p > 64 and !require_full_span) {
            const probe_limit = if (mode == .earliest and best != null) @min(limit, best.?.end) else limit;
            const first_end = self.firstWindowEndFrom(haystack, lo_p, max_p, probe_limit) orelse return best;
            if (comptime @TypeOf(allow_arg) == AllowAny) {
                lo_p = @max(lo_p, first_end -| self.max_multiline_window);
                if (mode == .earliest) max_p = @min(max_p, first_end);
            }
        }

        var overall = best;
        var p = lo_p;
        while (p <= max_p) : (p += 1) {
            if (self.anchored_start and p > 0) break;
            if (self.all_prefix or self.all_exact) {
                if (self.prefilter) |*pf| {
                    const nh = pf.find(haystack[0..limit], p, .leftmost_first) orelse break;
                    if (nh.start > max_p) break;
                    p = nh.start;
                }
            }
            var dummy_clip = false;
            const p_lim = if (require_full_span) limit else @min(limit, self.windowLimit(haystack, p));
            if (self.runFindRangeOnce(haystack, p, p, p_lim, mode, require_full_span, allow_arg, &dummy_clip)) |m| {
                if (mode == .leftmost_first) return m;
                const m_pid = m.pattern_id orelse std.math.maxInt(u32);
                const o_pid = if (overall) |om| (om.pattern_id orelse std.math.maxInt(u32)) else std.math.maxInt(u32);
                if (overall == null or
                    m.end < overall.?.end or
                    (m.end == overall.?.end and m.start < overall.?.start) or
                    (m.end == overall.?.end and m.start == overall.?.start and m_pid < o_pid))
                {
                    overall = m;
                    max_p = @min(max_p, m.end);
                }
            }
        }
        return overall;
    }

    fn firstWindowEndFrom(
        self: *const RegexSet,
        haystack: []const u8,
        from_start: usize,
        max_start: usize,
        limit: usize,
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

        var pos = from_start;
        while (true) {
            if (gen == std.math.maxInt(u32)) {
                @memset(gen_table, 0);
                gen = 1;
            }

            if (curr_len == 0 and pos > from_start and pos <= max_start and (self.all_prefix or self.all_exact)) {
                if (self.prefilter) |*pf| {
                    const next_hit = pf.find(haystack[0..limit], pos, .leftmost_first) orelse break;
                    if (next_hit.start > max_start) break;
                    pos = next_hit.start;
                }
            }

            if (pos <= max_start and (!self.anchored_start or pos == 0)) {
                if (curr_len == 0) {
                    self.addThread(curr, &curr_len, gen_table, gen, self.start_pc, pos, haystack, pos);
                } else {
                    gen +%= 1;
                    if (gen == 0) {
                        @memset(gen_table, 0);
                        gen = 1;
                    }
                    var merged_len: usize = 0;
                    self.addThread(next, &merged_len, gen_table, gen, self.start_pc, pos, haystack, pos);
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
                    .match_id => return pos,
                    .match => {},
                    .byte => |by| {
                        if (!has_byte or (!self.multiline and is_nl)) continue;
                        const ok = if (by.ignore_case) std.ascii.toLower(b) == std.ascii.toLower(by.b) else b == by.b;
                        if (ok and (!self.multiline or pos + 1 - th.start <= self.max_multiline_window)) {
                            self.addThread(next, &next_len, gen_table, gen, by.out, th.start, haystack, pos + 1);
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
                            self.addThread(next, &next_len, gen_table, gen, target_pc, th.start, haystack, pos + 1);
                        }
                    },
                    .any_cont => |ac| {
                        if (!has_byte or (!self.multiline and is_nl)) continue;
                        if ((b & 0xC0) == 0x80 and (!self.multiline or pos + 1 - th.start <= self.max_multiline_window)) {
                            self.addThread(next, &next_len, gen_table, gen, ac.out, th.start, haystack, pos + 1);
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
                                    self.addThread(next, &next_len, gen_table, gen, target_pc, th.start, haystack, pos + 1);
                                }
                                continue;
                            }
                        }
                        if (cl.set.contains(b) and (!self.multiline or pos + 1 - th.start <= self.max_multiline_window)) {
                            self.addThread(next, &next_len, gen_table, gen, cl.out, th.start, haystack, pos + 1);
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
                            self.addThread(next, &next_len, gen_table, gen, target_pc, th.start, haystack, pos + 1);
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

    fn runFindRangeOnce(
        self: *const RegexSet,
        haystack: []const u8,
        start_lo: usize,
        start_hi: usize,
        limit: usize,
        mode: MatchMode,
        require_full_span: bool,
        allow_arg: anytype,
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

            if (curr_len == 0 and best == null and pos > start_lo and pos <= start_hi and (self.all_prefix or self.all_exact)) {
                if (self.prefilter) |*pf| {
                    const next_hit = pf.find(haystack[0..limit], pos, .leftmost_first) orelse break;
                    if (next_hit.start > start_hi) break;
                    pos = next_hit.start;
                }
            }

            if (best == null and pos <= start_hi and (!self.anchored_start or pos == 0)) {
                self.addThread(curr, &curr_len, gen_table, gen, self.start_pc, pos, haystack, pos);
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
                if (self.multiline and (pos - th.start > self.max_multiline_window)) {
                    window_clipped.* = true;
                    continue;
                }

                const inst = self.insts[th.pc];
                switch (inst) {
                    .match_id => |pat_id| {
                        if (require_full_span and pos != limit) continue;
                        if (!inst_mod.invokeAllow(allow_arg, haystack, th.start, pos)) continue;
                        if (mode == .earliest) {
                            if (best == null or
                                pos < best.?.end or
                                (pos == best.?.end and th.start < best.?.start) or
                                (pos == best.?.end and th.start == best.?.start and pat_id < (best.?.pattern_id orelse std.math.maxInt(u32))))
                            {
                                best = .{ .start = th.start, .end = pos, .pattern_id = pat_id };
                            }
                            if (!window_clipped.*) return best;
                            break;
                        } else {
                            if (best == null or
                                th.start < best.?.start or
                                (th.start == best.?.start and pat_id < (best.?.pattern_id orelse std.math.maxInt(u32))) or
                                (th.start == best.?.start and pat_id == (best.?.pattern_id orelse std.math.maxInt(u32)) and pos > best.?.end))
                            {
                                best = .{ .start = th.start, .end = pos, .pattern_id = pat_id };
                            }
                            break;
                        }
                    },
                    .match => {},
                    .byte => |by| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        const ok = if (by.ignore_case)
                            std.ascii.toLower(b) == std.ascii.toLower(by.b)
                        else
                            b == by.b;
                        if (ok) {
                            if (!self.multiline or pos + 1 - th.start <= self.max_multiline_window) {
                                self.addThread(next, &next_len, gen_table, gen, by.out, th.start, haystack, pos + 1);
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
                            self.addThread(next, &next_len, gen_table, gen, target_pc, th.start, haystack, pos + 1);
                        } else {
                            window_clipped.* = true;
                        }
                    },
                    .any_cont => |ac| {
                        if (!has_byte) continue;
                        if (!self.multiline and is_nl) continue;
                        if ((b & 0xC0) == 0x80) {
                            if (!self.multiline or pos + 1 - th.start <= self.max_multiline_window) {
                                self.addThread(next, &next_len, gen_table, gen, ac.out, th.start, haystack, pos + 1);
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
                                    self.addThread(next, &next_len, gen_table, gen, target_pc, th.start, haystack, pos + 1);
                                } else {
                                    window_clipped.* = true;
                                }
                                continue;
                            }
                        }
                        if (cl.set.contains(b)) {
                            if (!self.multiline or pos + 1 - th.start <= self.max_multiline_window) {
                                self.addThread(next, &next_len, gen_table, gen, cl.out, th.start, haystack, pos + 1);
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
                                self.addThread(next, &next_len, gen_table, gen, target_pc, th.start, haystack, pos + 1);
                            } else {
                                window_clipped.* = true;
                            }
                        }
                    },
                    .split, .jmp, .assert, .save => {},
                }
            }

            if (pos >= limit) break;
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
        self: *const RegexSet,
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
            .save => |sv| {
                self.addThread(list, list_len, gen_table, gen, sv.out, start, haystack, pos);
            },
            else => {
                list[list_len.*] = .{ .pc = pc, .start = start };
                list_len.* += 1;
            },
        }
    }
};
