//! [Module] regex/set.zig
//! [Layer] Layer 2 — Multi-Pattern Regular Expression Set (`RegexSet`)
//! [Role] Compiles up to `pattern_count_hard_cap` (1,024) regular expressions into a single combined
//!        lockstep Thompson NFA with `match_id` accepting states and optional `Multi` SIMD prefix prefiltering.
//! [Invariants]
//!   1. Single-pass O(N * M) evaluation across all patterns simultaneously (`isMatch`, `find`, `matches`).
//!   2. All search methods take `*const RegexSet` and are 100% thread-safe and lock-free.
//!   3. Strict enforcement of instruction caps, pattern count/byte caps, UTF-8 validity, and single-line newline rejection.
//! [HotPath] `RegexSet.find` / `RegexSet.matches` -> `prefilter` (`Multi`) -> `runSet`.

const std = @import("std");
const matcher = @import("../matcher.zig");
const Multi = @import("../finder/multi.zig").Multi;
const memchr = @import("../finder/memchr.zig");
const unicode_fold = @import("../finder/unicode_fold.zig");
const inst_mod = @import("inst.zig");
const compiler_mod = @import("compiler.zig");
const prefilter_mod = @import("prefilter.zig");

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
pub const max_inst_hard_cap = inst_mod.max_inst_hard_cap;
pub const max_multiline_window_hard_cap = inst_mod.max_multiline_window_hard_cap;

const Compiler = compiler_mod.Compiler;
const Frag = compiler_mod.Frag;
const hasLiteralUpper = inst_mod.hasLiteralUpper;
const hasTopLevelAlt = inst_mod.hasTopLevelAlt;
const checkAssert = inst_mod.checkAssert;
const utf8SeqLenAt = inst_mod.utf8SeqLenAt;
const decodeValidUtf8At = inst_mod.decodeValidUtf8At;
const inRanges = inst_mod.inRanges;
const populateDiagnostic = inst_mod.populateDiagnostic;

pub const RegexSet = struct {
    allocator: std.mem.Allocator,
    insts: []Inst = &.{},
    unicode_ranges: []UnicodeRangeList = &.{},
    start_pc: u32 = 0,
    pattern_count: usize = 0,
    multiline: bool = false,
    anchored_start: bool = false,
    max_multiline_window: usize = inst_mod.default_multiline_window,
    prefix_slices: [][]u8 = &.{},
    prefilter: ?Multi = null,

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

        const inst_cap = options.effectiveMaxInst() orelse max_inst_hard_cap;
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
                .max_multiline_window = options.max_multiline_window,
            };
        }

        var compiler = Compiler{
            .allocator = allocator,
            .pattern = "",
            .ignore_case = false,
            .unicode_case = options.unicode_case,
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

        var any_multiline = options.multiline;
        var all_anchored = true;
        var any_ignore_case = false;

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
            compiler.multiline = options.multiline;
            compiler.dot_all = options.dot_all;
            compiler.capture_count = 0;
            compiler.capture_positions = @splat(std.math.maxInt(usize));
            compiler.pattern_index = idx;
            compiler.match_inst = .{ .match_id = @intCast(idx) };

            const frag = try compiler.compile();
            if (!compiler.multiline) {
                if (std.mem.indexOfScalar(u8, pat, '\n')) |nl_pos| {
                    populateDiagnostic(diag, pat, error.PatternHasNewline, .pattern_has_newline, nl_pos, "pattern contains literal newline in single-line mode", idx);
                    return error.PatternHasNewline;
                }
            }
            frag_starts[idx] = frag.start;
            if (compiler.multiline) any_multiline = true;
            if (compiler.ignore_case) any_ignore_case = true;
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
        errdefer allocator.free(insts);

        const unicode_ranges = try compiler.unicode_ranges.toOwnedSlice(allocator);
        errdefer {
            for (unicode_ranges) |item| {
                if (item.owned) allocator.free(item.ranges);
            }
            allocator.free(unicode_ranges);
        }

        var self = RegexSet{
            .allocator = allocator,
            .insts = insts,
            .unicode_ranges = unicode_ranges,
            .start_pc = root_start,
            .pattern_count = patterns.len,
            .multiline = any_multiline,
            .anchored_start = all_anchored,
            .max_multiline_window = options.max_multiline_window,
        };
        errdefer self.deinit();

        try self.tryBuildMultiPrefilter(patterns, any_ignore_case, options);
        return self;
    }

    fn tryBuildMultiPrefilter(
        self: *RegexSet,
        patterns: []const []const u8,
        any_ignore_case: bool,
        options: RegexOptions,
    ) !void {
        var prefixes = std.ArrayList([]u8).empty;
        errdefer {
            for (prefixes.items) |p| self.allocator.free(p);
            prefixes.deinit(self.allocator);
        }

        for (patterns) |pat| {
            const p = (try prefilter_mod.extractRequiredPrefix(self.allocator, pat, self.multiline)) orelse {
                for (prefixes.items) |s| self.allocator.free(s);
                prefixes.deinit(self.allocator);
                return;
            };
            errdefer self.allocator.free(p);
            try prefixes.append(self.allocator, p);
        }

        const owned_prefixes = try prefixes.toOwnedSlice(self.allocator);
        const const_slices: []const []const u8 = @ptrCast(owned_prefixes);
        const find_opts = matcher.FindOptions{
            .case = if (any_ignore_case) .insensitive else .sensitive,
            .unicode_case = options.unicode_case,
            .max_pattern_count = options.max_pattern_count,
            .max_pattern_bytes = options.max_pattern_bytes,
            .max_unicode_variants = options.max_unicode_variants,
        };
        if (Multi.init(self.allocator, const_slices, find_opts)) |m| {
            self.prefix_slices = owned_prefixes;
            self.prefilter = m;
        } else |_| {
            for (owned_prefixes) |s| self.allocator.free(s);
            self.allocator.free(owned_prefixes);
        }
    }

    pub fn deinit(self: *RegexSet) void {
        if (self.prefilter) |*pf| pf.deinit();
        if (self.prefix_slices.len != 0) {
            for (self.prefix_slices) |s| self.allocator.free(s);
            self.allocator.free(self.prefix_slices);
        }
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

    pub fn resetStats(self: *const RegexSet) void {
        _ = self;
    }

    pub fn isMatch(self: *const RegexSet, haystack: []const u8) bool {
        return self.find(haystack, 0, .earliest) != null;
    }

    pub fn find(self: *const RegexSet, haystack: []const u8, start: usize, mode: MatchMode) ?Match {
        if (self.pattern_count == 0 or self.insts.len == 0 or start > haystack.len) return null;
        if (self.anchored_start and start > 0) return null;

        if (self.prefilter) |*pf| {
            var pos = start;
            var cached_win_end: usize = std.math.maxInt(usize);
            while (pos <= haystack.len) {
                const hit = pf.find(haystack, pos, .leftmost_first) orelse return null;
                const win_end = if (!self.multiline and cached_win_end != std.math.maxInt(usize) and hit.start <= cached_win_end)
                    cached_win_end
                else blk: {
                    const w = self.windowLimit(haystack, hit.start);
                    cached_win_end = w;
                    break :blk w;
                };
                if (self.runFindRange(haystack, hit.start, win_end, win_end, mode)) |m| {
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

        return self.runFindRange(haystack, start, haystack.len, haystack.len, mode);
    }

    /// Evaluates all compiled patterns against `haystack` in a single pass and writes the matching
    /// 0-based pattern indices (in ascending order) into `out_ids`. Returns the number of IDs written.
    pub fn matches(self: *const RegexSet, haystack: []const u8, out_ids: []u32) usize {
        if (self.pattern_count == 0 or self.insts.len == 0) return 0;

        const n_inst = self.insts.len;
        const n_pats = self.pattern_count;

        var stack_curr: [256]Thread = undefined;
        var stack_next: [256]Thread = undefined;
        var stack_gen: [256]u32 = undefined;
        var stack_matched: [1024]bool = undefined;

        var heap_curr: []Thread = &.{};
        defer if (heap_curr.len != 0) self.allocator.free(heap_curr);
        var heap_next: []Thread = &.{};
        defer if (heap_next.len != 0) self.allocator.free(heap_next);
        var heap_gen: []u32 = &.{};
        defer if (heap_gen.len != 0) self.allocator.free(heap_gen);
        var heap_matched: []bool = &.{};
        defer if (heap_matched.len != 0) self.allocator.free(heap_matched);

        var curr: []Thread = if (n_inst <= 256) stack_curr[0..n_inst] else blk: {
            heap_curr = self.allocator.alloc(Thread, n_inst) catch return 0;
            break :blk heap_curr;
        };
        var next: []Thread = if (n_inst <= 256) stack_next[0..n_inst] else blk: {
            heap_next = self.allocator.alloc(Thread, n_inst) catch return 0;
            break :blk heap_next;
        };
        const gen_table: []u32 = if (n_inst <= 256) stack_gen[0..n_inst] else blk: {
            heap_gen = self.allocator.alloc(u32, n_inst) catch return 0;
            break :blk heap_gen;
        };
        const matched_flags: []bool = if (n_pats <= 1024) stack_matched[0..n_pats] else blk: {
            heap_matched = self.allocator.alloc(bool, n_pats) catch return 0;
            break :blk heap_matched;
        };

        @memset(gen_table, 0);
        @memset(matched_flags, false);
        var gen: u32 = 1;
        var curr_len: usize = 0;
        var matched_count: usize = 0;

        var pos: usize = 0;
        while (true) {
            if (gen == std.math.maxInt(u32)) {
                @memset(gen_table, 0);
                gen = 1;
            }

            if (curr_len == 0 and pos > 0 and pos <= haystack.len) {
                if (self.prefilter) |*pf| {
                    const next_hit = pf.find(haystack, pos, .leftmost_first) orelse break;
                    pos = next_hit.start;
                }
            }

            if (pos <= haystack.len and (!self.anchored_start or pos == 0)) {
                self.addThread(curr, &curr_len, gen_table, gen, self.start_pc, pos, haystack, pos);
            }

            if (curr_len == 0) {
                if (pos >= haystack.len or (self.anchored_start and pos > 0)) break;
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

            const has_byte = pos < haystack.len;
            const b: u8 = if (has_byte) haystack[pos] else 0;
            const is_nl = has_byte and b == '\n';

            for (curr[0..curr_len]) |th| {
                if (self.multiline and (pos - th.start > self.max_multiline_window)) continue;

                const inst = self.insts[th.pc];
                switch (inst) {
                    .match_id => |pat_id| {
                        if (pat_id < n_pats and !matched_flags[pat_id]) {
                            matched_flags[pat_id] = true;
                            matched_count += 1;
                            if (matched_count == n_pats) break;
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
                        const seq_len = utf8SeqLenAt(haystack, pos, haystack.len);
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
                            const seq_len = utf8SeqLenAt(haystack, pos, haystack.len);
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
                        const dec = decodeValidUtf8At(haystack, pos, haystack.len) orelse continue;
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
                            self.addThread(next, &next_len, gen_table, gen, target_pc, th.start, haystack, pos + 1);
                        }
                    },
                    .split, .jmp, .assert, .save => {},
                }
            }

            if (matched_count == n_pats or pos >= haystack.len) break;
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

    fn windowLimit(self: *const RegexSet, haystack: []const u8, from: usize) usize {
        if (!self.multiline) {
            if (memchr.find(memchr.native_width, haystack, from, '\n')) |nl| {
                if (nl > from and haystack[nl - 1] == '\r') return nl - 1;
                return nl;
            }
            return haystack.len;
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

            if (curr_len == 0 and best == null and pos > start_lo and pos <= start_hi) {
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
                if (self.multiline and (pos - th.start > self.max_multiline_window)) continue;

                const inst = self.insts[th.pc];
                switch (inst) {
                    .match_id => |pat_id| {
                        if (mode == .earliest) {
                            if (best == null or
                                pos < best.?.end or
                                (pos == best.?.end and th.start < best.?.start) or
                                (pos == best.?.end and th.start == best.?.start and pat_id < (best.?.pattern_id orelse std.math.maxInt(u32))))
                            {
                                best = .{ .start = th.start, .end = pos, .pattern_id = pat_id };
                            }
                            return best;
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
                            self.addThread(next, &next_len, gen_table, gen, target_pc, th.start, haystack, pos + 1);
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
