//! [Module] regex/prefilter.zig
//! [Layer] Layer 2 — Regex Required Literal & Alternation Prefilter Extractor
//! [Role] Analyzes regex syntax to extract required prefix/interior/trailing literals (`Finder`)
//!        or top-level alternation branch prefixes (`Multi`) for 14-29 GB/s SIMD prefiltering.
//! [Invariants]
//!   1. Prefilters are strictly conservative: every valid regex match must contain the prefilter candidate,
//!      ensuring zero false negatives before NFA verification.
//! [HotPath] Initialization-only (`extractLiterals` / `tryExtractAltLiterals` / `extractSetLiterals`).

const std = @import("std");
const matcher = @import("../matcher.zig");
const Finder = @import("../finder/finder.zig").Finder;
const Multi = @import("../finder/multi.zig").Multi;
const inst_mod = @import("inst.zig");
const CaseMode = inst_mod.CaseMode;
const popLastUtf8Codepoint = inst_mod.popLastUtf8Codepoint;
const utf8SeqLenAt = inst_mod.utf8SeqLenAt;

pub fn extractLiterals(self: anytype, pattern: []const u8, options: inst_mod.RegexOptions) !void {
    if (self.saw_extended) return;
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
                // Check for standalone inline flag group `(?i)`, `(?m)`, `(?s)`, `(?U)`, `(?-i)` or named group `(?P<name>...)` / `(?<name>...)`
                if (i + 2 < pattern.len and pattern[i + 1] == '?') {
                    if (i + 3 < pattern.len and pattern[i + 2] == 'P' and pattern[i + 3] == '<') {
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
                        if (std.mem.findScalarPos(u8, pattern, i + 4, '>')) |gt| {
                            i = gt + 1;
                        } else {
                            return;
                        }
                        continue;
                    }
                    if (pattern[i + 2] == '<') {
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
                        if (std.mem.findScalarPos(u8, pattern, i + 3, '>')) |gt| {
                            i = gt + 1;
                        } else {
                            return;
                        }
                        continue;
                    }
                    var j = i + 2;
                    var only_flags = false;
                    var has_neg_or_scoped = false;
                    while (j < pattern.len and (pattern[j] == 'i' or pattern[j] == 'm' or pattern[j] == 's' or pattern[j] == 'U' or pattern[j] == 'u' or pattern[j] == 'x' or pattern[j] == '-')) : (j += 1) {
                        only_flags = true;
                        if (pattern[j] == 'x') return;
                        if (pattern[j] == '-') has_neg_or_scoped = true;
                    }
                    if (j < pattern.len and pattern[j] == ')' and only_flags and !has_neg_or_scoped and i == 0) {
                        i = j + 1;
                        continue;
                    }
                    if (j < pattern.len and (pattern[j] == ')' or pattern[j] == ':') and only_flags) {
                        return;
                    }
                }
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
                // Quantifier applies to the preceding atom: pop the last UTF-8 codepoint from curr_lit if non-empty
                popLastUtf8Codepoint(&curr_lit);
                if (prefix_active) popLastUtf8Codepoint(&first_lit);
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
                if (i < pattern.len and pattern[i] == '?') i += 1;
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
                if (i < pattern.len and pattern[i] == '?') i += 1;
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
                fixed_offset = null;
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
                var class_fixed_one = !(self.ignore_case and self.unicode_case);
                i += 1;
                if (i < pattern.len and (pattern[i] == '^' or pattern[i] == '!')) {
                    class_fixed_one = false;
                    i += 1;
                }
                if (i < pattern.len and pattern[i] == ']') i += 1;
                while (i < pattern.len and pattern[i] != ']') {
                    if (pattern[i] == '[' and i + 1 < pattern.len and pattern[i + 1] == ':') {
                        if (std.mem.findPos(u8, pattern, i + 2, ":]")) |end_posix| {
                            if (pattern[i + 2] == '^') class_fixed_one = false;
                            i = end_posix + 2;
                            continue;
                        }
                    }
                    if (pattern[i] >= 0x80) class_fixed_one = false;
                    if (pattern[i] == '\\' and i + 1 < pattern.len) {
                        const esc = pattern[i + 1];
                        if (esc == 'Q') {
                            class_fixed_one = false;
                            i += 2;
                            if (std.mem.findPos(u8, pattern, i, "\\E")) |e_pos| {
                                i = e_pos + 2;
                            } else {
                                i = pattern.len;
                            }
                            continue;
                        }
                        if (esc == 'x' or esc == 'u') {
                            class_fixed_one = false;
                            i += 2;
                            if (i < pattern.len and pattern[i] == '{') {
                                while (i < pattern.len and pattern[i] != '}') i += 1;
                                if (i < pattern.len) i += 1;
                            } else {
                                i = @min(pattern.len, i + (if (esc == 'x') @as(usize, 2) else @as(usize, 4)));
                            }
                            continue;
                        }
                        if (esc == 'D' or esc == 'W' or esc == 'S' or esc == 'p' or esc == 'P' or esc >= 0x80) {
                            class_fixed_one = false;
                        }
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if (i < pattern.len) i += 1;
                if (class_fixed_one and fixed_offset != null) {
                    fixed_offset.? += 1;
                } else {
                    fixed_offset = null;
                }
            },
            '\\' => {
                if (i + 1 >= pattern.len) break;
                const next_c = pattern[i + 1];
                if (next_c == 'Q') {
                    if (curr_lit.items.len > best_lit.items.len) {
                        best_lit.clearRetainingCapacity();
                        try best_lit.appendSlice(self.allocator, curr_lit.items);
                        best_offset = curr_offset;
                    }
                    curr_lit.clearRetainingCapacity();
                    prefix_active = false;
                    exact_only = false;
                    fixed_offset = null;
                    i += 2;
                    if (std.mem.findPos(u8, pattern, i, "\\E")) |e_pos| {
                        i = e_pos + 2;
                    } else {
                        i = pattern.len;
                    }
                    continue;
                }
                if (next_c == 'x' or next_c == 'u') {
                    if (curr_lit.items.len > best_lit.items.len) {
                        best_lit.clearRetainingCapacity();
                        try best_lit.appendSlice(self.allocator, curr_lit.items);
                        best_offset = curr_offset;
                    }
                    curr_lit.clearRetainingCapacity();
                    prefix_active = false;
                    exact_only = false;
                    fixed_offset = null;
                    i += 2;
                    if (i < pattern.len and pattern[i] == '{') {
                        while (i < pattern.len and pattern[i] != '}') i += 1;
                        if (i < pattern.len) i += 1;
                    } else {
                        i = @min(pattern.len, i + (if (next_c == 'x') @as(usize, 2) else @as(usize, 4)));
                    }
                    continue;
                }
                if (next_c == 'p' or next_c == 'P') {
                    if (curr_lit.items.len > best_lit.items.len) {
                        best_lit.clearRetainingCapacity();
                        try best_lit.appendSlice(self.allocator, curr_lit.items);
                        best_offset = curr_offset;
                    }
                    curr_lit.clearRetainingCapacity();
                    prefix_active = false;
                    exact_only = false;
                    fixed_offset = null;
                    i += 2;
                    if (i < pattern.len and pattern[i] == '{') {
                        while (i < pattern.len and pattern[i] != '}') i += 1;
                        if (i < pattern.len) i += 1;
                    } else if (i < pattern.len) {
                        i += 1;
                    }
                    continue;
                }
                const decoded: ?u8 = switch (next_c) {
                    'a' => 0x07,
                    'f' => 0x0C,
                    'v' => 0x0B,
                    'n' => if (self.multiline) '\n' else null,
                    'r' => '\r',
                    't' => '\t',
                    'A', 'z', 'Z', 'd', 'D', 'w', 'W', 's', 'S', 'b', 'B', '0' => null,
                    else => next_c,
                };
                if (decoded) |lit_b| {
                    if (depth == 0) {
                        if (curr_lit.items.len == 0) curr_offset = fixed_offset orelse 0;
                        try curr_lit.append(self.allocator, lit_b);
                        if (prefix_active) try first_lit.append(self.allocator, lit_b);
                        if (fixed_offset != null) {
                            if (self.ignore_case and self.unicode_case and (lit_b >= 0x80 or lit_b == 'k' or lit_b == 'K' or lit_b == 's' or lit_b == 'S')) {
                                fixed_offset = null;
                            } else {
                                fixed_offset.? += 1;
                            }
                        }
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
                if (depth == 0 and (c != '\n' or self.multiline)) {
                    const seq_len = utf8SeqLenAt(pattern, i, pattern.len);
                    if (curr_lit.items.len == 0) curr_offset = fixed_offset orelse 0;
                    try curr_lit.appendSlice(self.allocator, pattern[i .. i + seq_len]);
                    if (prefix_active) try first_lit.appendSlice(self.allocator, pattern[i .. i + seq_len]);
                    if (fixed_offset != null) {
                        if (self.ignore_case and self.unicode_case and (seq_len > 1 or c == 'k' or c == 'K' or c == 's' or c == 'S')) {
                            fixed_offset = null;
                        } else {
                            fixed_offset.? += seq_len;
                        }
                    }
                    i += seq_len;
                    continue;
                } else {
                    prefix_active = false;
                    exact_only = false;
                    fixed_offset = null;
                }
                i += 1;
            },
        }
    }
    var best_is_trailing = false;
    if (curr_lit.items.len > best_lit.items.len) {
        best_lit.clearRetainingCapacity();
        try best_lit.appendSlice(self.allocator, curr_lit.items);
        best_offset = curr_offset;
        best_is_trailing = true;
    }

    const find_opts = matcher.FindOptions{
        .case = if (self.ignore_case) .insensitive else options.case,
        .unicode_case = self.unicode_case,
        .max_pattern_count = options.max_pattern_count,
        .max_pattern_bytes = options.max_pattern_bytes,
        .max_unicode_variants = options.max_unicode_variants,
        .multiline = self.multiline,
        .max_multiline_window = self.max_multiline_window,
    };

    if (has_top_alt) {
        try tryExtractAltLiterals(self, pattern, find_opts);
        return;
    }

    if (first_lit.items.len >= 2 or (first_lit.items.len == 1 and best_lit.items.len < 2)) {
        self.req_literal_bytes = try self.allocator.dupe(u8, first_lit.items);
        self.req_literal_offset = 0;
        self.req_is_prefix = true;
        const max_first_exact = if (self.ignore_case and self.unicode_case) first_lit.items.len *| 3 else first_lit.items.len;
        self.req_is_exact = exact_only and (!self.multiline or max_first_exact <= self.max_multiline_window);
        self.prefilter = Finder.init(self.req_literal_bytes, find_opts) catch null;

        // If another required literal of length >= 2 exists beyond the prefix literal (e.g., `ERROR.*timeout`), save it as tail_finder
        if (!exact_only and curr_lit.items.len >= 2 and !std.mem.eql(u8, curr_lit.items, first_lit.items)) {
            self.tail_literal_bytes = try self.allocator.dupe(u8, curr_lit.items);
            self.tail_finder = Finder.init(self.tail_literal_bytes, find_opts) catch null;
        }
    } else if (best_lit.items.len >= 1) {
        if (best_lit.items.len <= 2) {
            try tryExtractLeadingAltPrefixes(self, pattern, find_opts);
            if (self.alt_prefilter != null) return;
        }
        self.req_literal_bytes = try self.allocator.dupe(u8, best_lit.items);
        self.req_literal_offset = best_offset;
        self.req_is_prefix = false;
        self.req_is_exact = false;
        self.prefilter = Finder.init(self.req_literal_bytes, find_opts) catch null;

        if (!best_is_trailing and depth == 0 and curr_lit.items.len >= 2) {
            self.tail_literal_bytes = try self.allocator.dupe(u8, curr_lit.items);
            self.tail_finder = Finder.init(self.tail_literal_bytes, find_opts) catch null;
        }
    } else {
        try tryExtractAltLiterals(self, pattern, find_opts);
        if (self.alt_prefilter == null) {
            try tryExtractLeadingAltPrefixes(self, pattern, find_opts);
        }
    }
}

pub fn tryExtractAltLiterals(self: anytype, pattern: []const u8, find_opts: matcher.FindOptions) !void {
    if (self.saw_extended) return;
    var inner = pattern;
    if (inner.len >= 3 and inner[0] == '(' and inner[inner.len - 1] == ')') {
        // Check whether the opening '(' at index 0 matches the closing ')' at inner.len - 1
        var depth: usize = 0;
        var in_class = false;
        var j: usize = 0;
        var wraps_entire = true;
        while (j < inner.len) : (j += 1) {
            const ch = inner[j];
            if (ch == '\\' and j + 1 < inner.len) {
                if (inner[j + 1] == 'Q') {
                    j += 2;
                    while (j + 1 < inner.len and !(inner[j] == '\\' and inner[j + 1] == 'E')) : (j += 1) {}
                    if (j + 1 < inner.len) j += 1;
                    continue;
                }
                j += 1;
                continue;
            }
            if (in_class) {
                if (ch == '[' and j + 1 < inner.len and inner[j + 1] == ':') {
                    if (std.mem.findPos(u8, inner, j + 2, ":]")) |end_posix| {
                        j = end_posix + 1;
                        continue;
                    }
                }
                if (ch == ']') in_class = false;
                continue;
            }
            if (ch == '[') {
                in_class = true;
                if (j + 1 < inner.len and (inner[j + 1] == '^' or inner[j + 1] == '!')) j += 1;
                if (j + 1 < inner.len and inner[j + 1] == ']') j += 1;
            } else if (ch == '(') {
                depth += 1;
            } else if (ch == ')') {
                depth -= 1;
                if (depth == 0 and j + 1 < inner.len) {
                    wraps_entire = false;
                    break;
                }
            }
        }
        if (wraps_entire and depth == 0) {
            if (std.mem.startsWith(u8, inner, "(?:")) {
                inner = inner[3 .. inner.len - 1];
            } else if (std.mem.startsWith(u8, inner, "(?P<")) {
                if (std.mem.findScalarPos(u8, inner, 4, '>')) |gt| {
                    inner = inner[gt + 1 .. inner.len - 1];
                }
            } else if (std.mem.startsWith(u8, inner, "(?<")) {
                if (std.mem.findScalarPos(u8, inner, 3, '>')) |gt| {
                    inner = inner[gt + 1 .. inner.len - 1];
                }
            } else if (inner[1] != '?') {
                inner = inner[1 .. inner.len - 1];
            }
        }
    }

    const max_alt_branches: usize = 256;
    var branches = std.ArrayList([]const u8).empty;
    defer branches.deinit(self.allocator);
    var branch_start: usize = 0;
    var depth: usize = 0;
    var in_class = false;
    var i: usize = 0;
    while (i < inner.len) : (i += 1) {
        const ch = inner[i];
        if (ch == '\\' and i + 1 < inner.len) {
            if (inner[i + 1] == 'Q') {
                i += 2;
                while (i + 1 < inner.len and !(inner[i] == '\\' and inner[i + 1] == 'E')) : (i += 1) {}
                if (i + 1 < inner.len) i += 1;
                continue;
            }
            i += 1;
            continue;
        }
        if (in_class) {
            if (ch == '[' and i + 1 < inner.len and inner[i + 1] == ':') {
                if (std.mem.findPos(u8, inner, i + 2, ":]")) |end_posix| {
                    i = end_posix + 1;
                    continue;
                }
            }
            if (ch == ']') in_class = false;
            continue;
        }
        if (ch == '[') {
            in_class = true;
            if (i + 1 < inner.len and (inner[i + 1] == '^' or inner[i + 1] == '!')) i += 1;
            if (i + 1 < inner.len and inner[i + 1] == ']') i += 1;
        } else if (ch == '(') {
            depth += 1;
        } else if (ch == ')') {
            if (depth > 0) depth -= 1;
        } else if (ch == '|' and depth == 0) {
            if (branches.items.len + 1 >= max_alt_branches) return;
            try branches.append(self.allocator, inner[branch_start..i]);
            branch_start = i + 1;
        }
    }
    try branches.append(self.allocator, inner[branch_start..]);
    if (branches.items.len < 2) return;

    var prefixes = std.ArrayList([]const u8).empty;
    errdefer {
        for (prefixes.items) |s| self.allocator.free(s);
        prefixes.deinit(self.allocator);
    }

    var prefix_buf = std.ArrayList(u8).empty;
    defer prefix_buf.deinit(self.allocator);

    var all_exact = true;
    for (branches.items) |br| {
        prefix_buf.clearRetainingCapacity();
        var k: usize = 0;
        var br_exact = true;
        while (k < br.len) {
            const c = br[k];
            switch (c) {
                '.', '^', '$', '[', '(', ')' => {
                    br_exact = false;
                    break;
                },
                '*', '?', '{' => {
                    popLastUtf8Codepoint(&prefix_buf);
                    br_exact = false;
                    break;
                },
                '+' => {
                    br_exact = false;
                    break;
                },
                '\\' => {
                    if (k + 1 >= br.len) {
                        br_exact = false;
                        break;
                    }
                    const next_c = br[k + 1];
                    if (next_c == 'p' or next_c == 'P' or next_c == 'A' or next_c == 'z' or next_c == 'Z' or
                        next_c == 'x' or next_c == 'u' or next_c == 'Q' or
                        next_c == 'd' or next_c == 'D' or next_c == 'w' or next_c == 'W' or
                        next_c == 's' or next_c == 'S' or next_c == 'b' or next_c == 'B' or next_c == '0')
                    {
                        br_exact = false;
                        break;
                    }
                    const lit_b: u8 = switch (next_c) {
                        'a' => 0x07,
                        'f' => 0x0C,
                        'v' => 0x0B,
                        'n' => if (!self.multiline) {
                            br_exact = false;
                            break;
                        } else '\n',
                        'r' => '\r',
                        't' => '\t',
                        else => next_c,
                    };
                    try prefix_buf.append(self.allocator, lit_b);
                    k += 2;
                },
                else => {
                    if (c == '\n' and !self.multiline) {
                        br_exact = false;
                        break;
                    }
                    const seq_len = utf8SeqLenAt(br, k, br.len);
                    try prefix_buf.appendSlice(self.allocator, br[k .. k + seq_len]);
                    k += seq_len;
                },
            }
        }
        if (!br_exact or k != br.len) all_exact = false;
        if (prefix_buf.items.len < 2) {
            for (prefixes.items) |s| self.allocator.free(s);
            prefixes.deinit(self.allocator);
            return;
        }
        const duped = try self.allocator.dupe(u8, prefix_buf.items);
        errdefer self.allocator.free(duped);
        try prefixes.append(self.allocator, duped);
    }

    const owned_slices = try prefixes.toOwnedSlice(self.allocator);
    if (Multi.init(self.allocator, owned_slices, find_opts)) |m| {
        self.alt_literal_slices = owned_slices;
        self.alt_prefilter = m;
        self.alt_is_prefix = true;
        var max_br_len: usize = 0;
        for (owned_slices) |s| {
            if (s.len > max_br_len) max_br_len = s.len;
        }
        const max_alt_exact = if (self.ignore_case and self.unicode_case) max_br_len *| 3 else max_br_len;
        self.alt_is_exact = all_exact and (!self.multiline or max_alt_exact <= self.max_multiline_window);

        // When >= 4 alternation branches share a long common prefix (e.g., `ALT_TOKEN_00|...|ALT_TOKEN_31`),
        // attach a single-literal `PackedPair` Finder on the LCP so rare-hit scans run at 23 GB/s instead of Teddy/AC.
        if (owned_slices.len >= 4 and (!self.ignore_case or !self.unicode_case)) {
            var lcp_len = owned_slices[0].len;
            for (owned_slices[1..]) |s| {
                const lim = @min(lcp_len, s.len);
                var k: usize = 0;
                while (k < lim) : (k += 1) {
                    const a = if (self.ignore_case) std.ascii.toLower(owned_slices[0][k]) else owned_slices[0][k];
                    const b = if (self.ignore_case) std.ascii.toLower(s[k]) else s[k];
                    if (a != b) break;
                }
                lcp_len = k;
                if (lcp_len < 3) break;
            }
            // Trim trailing UTF-8 continuation bytes so LCP ends on a valid codepoint boundary.
            while (lcp_len > 0 and (owned_slices[0][lcp_len - 1] & 0xC0) == 0x80) : (lcp_len -= 1) {}
            if (lcp_len >= 3) {
                if (self.allocator.dupe(u8, owned_slices[0][0..lcp_len])) |lcp_owned| {
                    if (Finder.init(lcp_owned, find_opts)) |lcp_f| {
                        self.alt_lcp_bytes = lcp_owned;
                        self.alt_lcp_finder = lcp_f;
                        self.alt_max_branch_len = max_br_len;
                    } else |_| {
                        self.allocator.free(lcp_owned);
                    }
                } else |_| {}
            }
        }
    } else |_| {
        for (owned_slices) |s| self.allocator.free(s);
        self.allocator.free(owned_slices);
    }
}

/// Extracts branch prefix literals from a leading alternation group `(?:b1|b2|...|bk)...`
/// (up to 32 branches, non-empty required literal prefix per branch, no top-level `|` outside the group,
/// and optional fixed literal suffix immediately after `)` appended to exact branches).
/// Populates `alt_prefilter` (`Multi` -> AVX2 Teddy) with `alt_is_exact = false` and `alt_is_prefix = true`.
pub fn tryExtractLeadingAltPrefixes(self: anytype, pattern: []const u8, find_opts: matcher.FindOptions) !void {
    if (self.saw_extended) return;
    if (inst_mod.hasTopLevelAlt(pattern)) return;

    var start_idx: usize = 0;
    // Allow optional leading standalone inline flags `(?i)` / `(?m)` / `(?s)` / `(?U)` / `(?u)` (without `-` or `x`)
    if (pattern.len >= 4 and pattern[0] == '(' and pattern[1] == '?') {
        var j: usize = 2;
        var only_flags = false;
        var has_neg = false;
        while (j < pattern.len and (pattern[j] == 'i' or pattern[j] == 'm' or pattern[j] == 's' or pattern[j] == 'U' or pattern[j] == 'u' or pattern[j] == 'x' or pattern[j] == '-')) : (j += 1) {
            only_flags = true;
            if (pattern[j] == 'x') return;
            if (pattern[j] == '-') has_neg = true;
        }
        if (j < pattern.len and pattern[j] == ')' and only_flags and !has_neg) {
            start_idx = j + 1;
        }
    }

    if (start_idx + 3 >= pattern.len or pattern[start_idx] != '(') return;

    // Locate the matching ')' for the opening '(' at `start_idx`
    var close_idx: ?usize = null;
    {
        var depth: usize = 0;
        var in_class = false;
        var j: usize = start_idx;
        while (j < pattern.len) : (j += 1) {
            const ch = pattern[j];
            if (ch == '\\' and j + 1 < pattern.len) {
                if (pattern[j + 1] == 'Q') {
                    j += 2;
                    while (j + 1 < pattern.len and !(pattern[j] == '\\' and pattern[j + 1] == 'E')) : (j += 1) {}
                    if (j + 1 < pattern.len) j += 1;
                    continue;
                }
                j += 1;
                continue;
            }
            if (in_class) {
                if (ch == '[' and j + 1 < pattern.len and pattern[j + 1] == ':') {
                    if (std.mem.findPos(u8, pattern, j + 2, ":]")) |end_posix| {
                        j = end_posix + 1;
                        continue;
                    }
                }
                if (ch == ']') in_class = false;
                continue;
            }
            if (ch == '[') {
                in_class = true;
                if (j + 1 < pattern.len and (pattern[j + 1] == '^' or pattern[j + 1] == '!')) j += 1;
                if (j + 1 < pattern.len and pattern[j + 1] == ']') j += 1;
            } else if (ch == '(') {
                depth += 1;
            } else if (ch == ')') {
                depth -= 1;
                if (depth == 0) {
                    close_idx = j;
                    break;
                }
            }
        }
    }
    const c_idx = close_idx orelse return;
    if (c_idx <= start_idx + 1) return;

    const group_slice = pattern[start_idx .. c_idx + 1];
    const inner: []const u8 = if (std.mem.startsWith(u8, group_slice, "(?:"))
        group_slice[3 .. group_slice.len - 1]
    else if (std.mem.startsWith(u8, group_slice, "(?P<")) blk: {
        const gt = std.mem.findScalarPos(u8, group_slice, 4, '>') orelse return;
        break :blk group_slice[gt + 1 .. group_slice.len - 1];
    } else if (std.mem.startsWith(u8, group_slice, "(?<")) blk: {
        const gt = std.mem.findScalarPos(u8, group_slice, 3, '>') orelse return;
        break :blk group_slice[gt + 1 .. group_slice.len - 1];
    } else if (group_slice[1] != '?')
        group_slice[1 .. group_slice.len - 1]
    else
        return;

    // Check quantifier immediately after closing ')'
    const after = c_idx + 1;
    var allow_suffix = true;
    if (after < pattern.len) {
        switch (pattern[after]) {
            '*', '?' => return, // Leading group is optional
            '+' => allow_suffix = false,
            '{' => {
                var j = after + 1;
                var min_val: usize = 0;
                var has_digit = false;
                while (j < pattern.len and std.ascii.isDigit(pattern[j])) : (j += 1) {
                    has_digit = true;
                    min_val = min_val *| 10 +| (pattern[j] - '0');
                }
                if (!has_digit or min_val == 0) return; // Leading group is optional
                allow_suffix = false;
            },
            else => {},
        }
    } else {
        allow_suffix = false;
    }

    // Split `inner` on top-level `|` (up to 32 branches)
    const max_leading_branches: usize = 32;
    var branches = std.ArrayList([]const u8).empty;
    defer branches.deinit(self.allocator);
    {
        var branch_start: usize = 0;
        var depth: usize = 0;
        var in_class = false;
        var i: usize = 0;
        while (i < inner.len) : (i += 1) {
            const ch = inner[i];
            if (ch == '\\' and i + 1 < inner.len) {
                if (inner[i + 1] == 'Q') {
                    i += 2;
                    while (i + 1 < inner.len and !(inner[i] == '\\' and inner[i + 1] == 'E')) : (i += 1) {}
                    if (i + 1 < inner.len) i += 1;
                    continue;
                }
                i += 1;
                continue;
            }
            if (in_class) {
                if (ch == '[' and i + 1 < inner.len and inner[i + 1] == ':') {
                    if (std.mem.findPos(u8, inner, i + 2, ":]")) |end_posix| {
                        i = end_posix + 1;
                        continue;
                    }
                }
                if (ch == ']') in_class = false;
                continue;
            }
            if (ch == '[') {
                in_class = true;
                if (i + 1 < inner.len and (inner[i + 1] == '^' or inner[i + 1] == '!')) i += 1;
                if (i + 1 < inner.len and inner[i + 1] == ']') i += 1;
            } else if (ch == '(') {
                depth += 1;
            } else if (ch == ')') {
                if (depth > 0) depth -= 1;
            } else if (ch == '|' and depth == 0) {
                if (branches.items.len + 1 >= max_leading_branches) return;
                try branches.append(self.allocator, inner[branch_start..i]);
                branch_start = i + 1;
            }
        }
        try branches.append(self.allocator, inner[branch_start..]);
    }
    if (branches.items.len < 2 or branches.items.len > max_leading_branches) return;

    // Extract optional fixed literal suffix immediately after ')' (e.g. `_` in `(?:err|warn)_[a-z]+`)
    var suffix_buf = std.ArrayList(u8).empty;
    defer suffix_buf.deinit(self.allocator);
    if (allow_suffix and after < pattern.len) {
        const tail = pattern[after..];
        var t: usize = 0;
        while (t < tail.len) {
            const c = tail[t];
            switch (c) {
                '.', '^', '$', '[', '(', ')', '|' => break,
                '*', '?' => {
                    popLastUtf8Codepoint(&suffix_buf);
                    break;
                },
                '{' => {
                    var j = t + 1;
                    var min_val: usize = 0;
                    var has_digit = false;
                    while (j < tail.len and std.ascii.isDigit(tail[j])) : (j += 1) {
                        has_digit = true;
                        min_val = min_val *| 10 +| (tail[j] - '0');
                    }
                    if (!has_digit or min_val == 0) {
                        popLastUtf8Codepoint(&suffix_buf);
                    }
                    break;
                },
                '+' => break,
                '\\' => {
                    if (t + 1 >= tail.len) break;
                    const next_c = tail[t + 1];
                    if (next_c == 'p' or next_c == 'P' or next_c == 'A' or next_c == 'z' or next_c == 'Z' or
                        next_c == 'x' or next_c == 'u' or next_c == 'Q' or
                        next_c == 'd' or next_c == 'D' or next_c == 'w' or next_c == 'W' or
                        next_c == 's' or next_c == 'S' or next_c == 'b' or next_c == 'B' or next_c == '0')
                    {
                        break;
                    }
                    const lit_b: u8 = switch (next_c) {
                        'a' => 0x07,
                        'f' => 0x0C,
                        'v' => 0x0B,
                        'n' => if (!self.multiline) break else '\n',
                        'r' => '\r',
                        't' => '\t',
                        else => next_c,
                    };
                    try suffix_buf.append(self.allocator, lit_b);
                    t += 2;
                },
                else => {
                    if (c == '\n' and !self.multiline) break;
                    const seq_len = utf8SeqLenAt(tail, t, tail.len);
                    try suffix_buf.appendSlice(self.allocator, tail[t .. t + seq_len]);
                    t += seq_len;
                },
            }
        }
    }

    var prefixes = std.ArrayList([]const u8).empty;
    errdefer {
        for (prefixes.items) |s| self.allocator.free(s);
        prefixes.deinit(self.allocator);
    }

    var prefix_buf = std.ArrayList(u8).empty;
    defer prefix_buf.deinit(self.allocator);

    for (branches.items) |br| {
        prefix_buf.clearRetainingCapacity();
        var k: usize = 0;
        var br_exact = true;
        while (k < br.len) {
            const c = br[k];
            switch (c) {
                '.', '^', '$', '[', '(', ')' => {
                    br_exact = false;
                    break;
                },
                '*', '?', '{' => {
                    popLastUtf8Codepoint(&prefix_buf);
                    br_exact = false;
                    break;
                },
                '+' => {
                    br_exact = false;
                    break;
                },
                '\\' => {
                    if (k + 1 >= br.len) {
                        br_exact = false;
                        break;
                    }
                    const next_c = br[k + 1];
                    if (next_c == 'p' or next_c == 'P' or next_c == 'A' or next_c == 'z' or next_c == 'Z' or
                        next_c == 'x' or next_c == 'u' or next_c == 'Q' or
                        next_c == 'd' or next_c == 'D' or next_c == 'w' or next_c == 'W' or
                        next_c == 's' or next_c == 'S' or next_c == 'b' or next_c == 'B' or next_c == '0')
                    {
                        br_exact = false;
                        break;
                    }
                    const lit_b: u8 = switch (next_c) {
                        'a' => 0x07,
                        'f' => 0x0C,
                        'v' => 0x0B,
                        'n' => if (!self.multiline) {
                            br_exact = false;
                            break;
                        } else '\n',
                        'r' => '\r',
                        't' => '\t',
                        else => next_c,
                    };
                    try prefix_buf.append(self.allocator, lit_b);
                    k += 2;
                },
                else => {
                    if (c == '\n' and !self.multiline) {
                        br_exact = false;
                        break;
                    }
                    const seq_len = utf8SeqLenAt(br, k, br.len);
                    try prefix_buf.appendSlice(self.allocator, br[k .. k + seq_len]);
                    k += seq_len;
                },
            }
        }
        if (prefix_buf.items.len == 0) {
            for (prefixes.items) |s| self.allocator.free(s);
            prefixes.deinit(self.allocator);
            return;
        }
        if (br_exact and k == br.len and suffix_buf.items.len > 0) {
            try prefix_buf.appendSlice(self.allocator, suffix_buf.items);
        }
        if (prefix_buf.items.len < 2) {
            for (prefixes.items) |s| self.allocator.free(s);
            prefixes.deinit(self.allocator);
            return;
        }
        const duped = try self.allocator.dupe(u8, prefix_buf.items);
        errdefer self.allocator.free(duped);
        try prefixes.append(self.allocator, duped);
    }

    const owned_slices = try prefixes.toOwnedSlice(self.allocator);
    if (Multi.init(self.allocator, owned_slices, find_opts)) |m| {
        self.alt_literal_slices = owned_slices;
        self.alt_prefilter = m;
        self.alt_is_exact = false;
        self.alt_is_prefix = true;
    } else |_| {
        for (owned_slices) |s| self.allocator.free(s);
        self.allocator.free(owned_slices);
    }
}

pub const SetLitKind = enum(u2) {
    exact = 0,
    prefix = 1,
    interior = 2,
};

pub const SetExtractItem = struct {
    bytes: []u8,
    pat_id: u32,
    kind: SetLitKind,
    min_before: u32 = 0,
};

pub const SetExtractResult = struct {
    items: []SetExtractItem,

    pub fn deinit(self: *SetExtractResult, allocator: std.mem.Allocator) void {
        for (self.items) |it| allocator.free(it.bytes);
        allocator.free(self.items);
        self.* = undefined;
    }
};

/// Extracts conservative required literals across every pattern in a `RegexSet` (up to `max_total_literals`).
/// Supports leading standalone inline flags (`(?i)`, `(?m)`, `(?s)`, `(?u)`, `(?U)`), top-level `|` (including
/// outer `(...)` / `(?:...)` wrappers), leading zero-width anchors (`^`, `\A`, `\b`, `\B`), longest interior/trailing
/// literal with conservative `min_before`, and leading alternation groups `(?:b1|b2|...)`.
/// Returns `null` if any pattern has no extractable required literal or exceeds literal caps (routing the set to DFA).
pub fn extractSetLiterals(
    allocator: std.mem.Allocator,
    patterns: []const []const u8,
    multiline: bool,
    max_total_literals: usize,
) !?SetExtractResult {
    if (patterns.len == 0 or max_total_literals == 0) return null;

    var items = std.ArrayList(SetExtractItem).empty;
    errdefer {
        for (items.items) |it| allocator.free(it.bytes);
        items.deinit(allocator);
    }

    for (patterns, 0..) |raw_pat, idx| {
        if (!try extractSetPatternLiterals(allocator, raw_pat, @intCast(idx), multiline, max_total_literals, &items)) {
            for (items.items) |it| allocator.free(it.bytes);
            items.deinit(allocator);
            return null;
        }
    }

    if (items.items.len == 0) {
        items.deinit(allocator);
        return null;
    }

    return .{
        .items = try items.toOwnedSlice(allocator),
    };
}

fn stripLeadingSetFlags(pattern: []const u8, had_flags: *bool) ?[]const u8 {
    var s = pattern;
    while (s.len >= 4 and s[0] == '(' and s[1] == '?') {
        var j: usize = 2;
        var only_flags = false;
        while (j < s.len and (s[j] == 'i' or s[j] == 'm' or s[j] == 's' or s[j] == 'U' or s[j] == 'u' or s[j] == 'x' or s[j] == '-')) : (j += 1) {
            only_flags = true;
            if (s[j] == 'x' or s[j] == '-') return null;
        }
        if (only_flags and j < s.len and s[j] == ')') {
            had_flags.* = true;
            s = s[j + 1 ..];
            continue;
        }
        break;
    }
    return s;
}

fn unwrapOuterGroup(pattern: []const u8, unwrapped: *bool) []const u8 {
    var inner = pattern;
    while (inner.len >= 3 and inner[0] == '(' and inner[inner.len - 1] == ')') {
        var depth: usize = 0;
        var in_class = false;
        var j: usize = 0;
        var wraps_entire = true;
        while (j < inner.len) : (j += 1) {
            const ch = inner[j];
            if (ch == '\\' and j + 1 < inner.len) {
                if (inner[j + 1] == 'Q') {
                    j += 2;
                    while (j + 1 < inner.len and !(inner[j] == '\\' and inner[j + 1] == 'E')) : (j += 1) {}
                    if (j + 1 < inner.len) j += 1;
                    continue;
                }
                j += 1;
                continue;
            }
            if (in_class) {
                if (ch == '[' and j + 1 < inner.len and inner[j + 1] == ':') {
                    if (std.mem.findPos(u8, inner, j + 2, ":]")) |end_posix| {
                        j = end_posix + 1;
                        continue;
                    }
                }
                if (ch == ']') in_class = false;
                continue;
            }
            if (ch == '[') {
                in_class = true;
                if (j + 1 < inner.len and (inner[j + 1] == '^' or inner[j + 1] == '!')) j += 1;
                if (j + 1 < inner.len and inner[j + 1] == ']') j += 1;
            } else if (ch == '(') {
                depth += 1;
            } else if (ch == ')') {
                depth -= 1;
                if (depth == 0 and j + 1 < inner.len) {
                    wraps_entire = false;
                    break;
                }
            }
        }
        if (!wraps_entire or depth != 0) break;

        if (std.mem.startsWith(u8, inner, "(?:")) {
            inner = inner[3 .. inner.len - 1];
            unwrapped.* = true;
        } else if (std.mem.startsWith(u8, inner, "(?P<")) {
            const gt = std.mem.findScalarPos(u8, inner, 4, '>') orelse break;
            inner = inner[gt + 1 .. inner.len - 1];
            unwrapped.* = true;
        } else if (std.mem.startsWith(u8, inner, "(?<")) {
            const gt = std.mem.findScalarPos(u8, inner, 3, '>') orelse break;
            inner = inner[gt + 1 .. inner.len - 1];
            unwrapped.* = true;
        } else if (inner[1] != '?') {
            inner = inner[1 .. inner.len - 1];
            unwrapped.* = true;
        } else {
            break;
        }
    }
    return inner;
}

fn splitTopLevelBranches(
    allocator: std.mem.Allocator,
    pattern: []const u8,
    max_branches: usize,
    out: *std.ArrayList([]const u8),
) !bool {
    var branch_start: usize = 0;
    var depth: usize = 0;
    var in_class = false;
    var i: usize = 0;
    while (i < pattern.len) : (i += 1) {
        const ch = pattern[i];
        if (ch == '\\' and i + 1 < pattern.len) {
            if (pattern[i + 1] == 'Q') {
                i += 2;
                while (i + 1 < pattern.len and !(pattern[i] == '\\' and pattern[i + 1] == 'E')) : (i += 1) {}
                if (i + 1 < pattern.len) i += 1;
                continue;
            }
            i += 1;
            continue;
        }
        if (in_class) {
            if (ch == '[' and i + 1 < pattern.len and pattern[i + 1] == ':') {
                if (std.mem.findPos(u8, pattern, i + 2, ":]")) |end_posix| {
                    i = end_posix + 1;
                    continue;
                }
            }
            if (ch == ']') in_class = false;
            continue;
        }
        if (ch == '[') {
            in_class = true;
            if (i + 1 < pattern.len and (pattern[i + 1] == '^' or pattern[i + 1] == '!')) i += 1;
            if (i + 1 < pattern.len and pattern[i + 1] == ']') i += 1;
        } else if (ch == '(') {
            depth += 1;
        } else if (ch == ')') {
            if (depth > 0) depth -= 1;
        } else if (ch == '|' and depth == 0) {
            if (out.items.len + 1 >= max_branches) return false;
            try out.append(allocator, pattern[branch_start..i]);
            branch_start = i + 1;
        }
    }
    try out.append(allocator, pattern[branch_start..]);
    return true;
}

fn extractSetPatternLiterals(
    allocator: std.mem.Allocator,
    raw_pat: []const u8,
    pat_id: u32,
    multiline: bool,
    max_total_literals: usize,
    out_items: *std.ArrayList(SetExtractItem),
) !bool {
    var had_flags = false;
    const stripped = stripLeadingSetFlags(raw_pat, &had_flags) orelse return false;
    if (stripped.len == 0) return false;

    var unwrapped = false;
    const inner = unwrapOuterGroup(stripped, &unwrapped);
    if (inner.len == 0) return false;

    const max_pat_branches: usize = 16;
    var branches = std.ArrayList([]const u8).empty;
    defer branches.deinit(allocator);
    if (!try splitTopLevelBranches(allocator, inner, max_pat_branches, &branches)) return false;

    if (branches.items.len >= 2) {
        if (out_items.items.len + branches.items.len > max_total_literals) return false;
        for (branches.items) |br| {
            var br_flags = had_flags;
            const br_s = stripLeadingSetFlags(br, &br_flags) orelse return false;
            var br_unw = false;
            const br_in = unwrapOuterGroup(br_s, &br_unw);
            if (br_in.len == 0 or inst_mod.hasTopLevelAlt(br_in)) return false;
            if (!try extractSetSpineLiterals(allocator, br_in, pat_id, multiline, br_flags, max_total_literals, out_items)) {
                return false;
            }
        }
        return true;
    }

    return extractSetSpineLiterals(allocator, inner, pat_id, multiline, had_flags, max_total_literals, out_items);
}

fn extractSetSpineLiterals(
    allocator: std.mem.Allocator,
    pattern: []const u8,
    pat_id: u32,
    multiline: bool,
    had_inline_flags: bool,
    max_total_literals: usize,
    out_items: *std.ArrayList(SetExtractItem),
) !bool {
    var first_lit = std.ArrayList(u8).empty;
    defer first_lit.deinit(allocator);
    var best_lit = std.ArrayList(u8).empty;
    defer best_lit.deinit(allocator);
    var curr_lit = std.ArrayList(u8).empty;
    defer curr_lit.deinit(allocator);

    var depth: usize = 0;
    var prefix_active = true;
    var exact_only = !had_inline_flags;
    var min_len_so_far: usize = 0;
    var last_atom_min_bytes: usize = 0;
    var curr_min_before: usize = 0;
    var best_min_before: usize = 0;

    var i: usize = 0;
    while (i < pattern.len) {
        const c = pattern[i];
        switch (c) {
            '(' => {
                if (i + 2 < pattern.len and pattern[i + 1] == '?') {
                    if (i + 3 < pattern.len and pattern[i + 2] == 'P' and pattern[i + 3] == '<') {
                        if (depth == 0 and curr_lit.items.len > best_lit.items.len) {
                            best_lit.clearRetainingCapacity();
                            try best_lit.appendSlice(allocator, curr_lit.items);
                            best_min_before = curr_min_before;
                        }
                        curr_lit.clearRetainingCapacity();
                        depth += 1;
                        prefix_active = false;
                        exact_only = false;
                        last_atom_min_bytes = 0;
                        if (std.mem.findScalarPos(u8, pattern, i + 4, '>')) |gt| {
                            i = gt + 1;
                            continue;
                        }
                        return false;
                    }
                    if (pattern[i + 2] == '<') {
                        if (depth == 0 and curr_lit.items.len > best_lit.items.len) {
                            best_lit.clearRetainingCapacity();
                            try best_lit.appendSlice(allocator, curr_lit.items);
                            best_min_before = curr_min_before;
                        }
                        curr_lit.clearRetainingCapacity();
                        depth += 1;
                        prefix_active = false;
                        exact_only = false;
                        last_atom_min_bytes = 0;
                        if (std.mem.findScalarPos(u8, pattern, i + 3, '>')) |gt| {
                            i = gt + 1;
                            continue;
                        }
                        return false;
                    }
                    var j = i + 2;
                    var only_flags = false;
                    while (j < pattern.len and (pattern[j] == 'i' or pattern[j] == 'm' or pattern[j] == 's' or pattern[j] == 'U' or pattern[j] == 'u' or pattern[j] == 'x' or pattern[j] == '-')) : (j += 1) {
                        only_flags = true;
                        if (pattern[j] == 'x' or pattern[j] == '-') return false;
                    }
                    if (only_flags and j < pattern.len and pattern[j] == ')') {
                        // Standalone inline flag mid-pattern
                        exact_only = false;
                        if (depth == 0 and curr_lit.items.len > best_lit.items.len) {
                            best_lit.clearRetainingCapacity();
                            try best_lit.appendSlice(allocator, curr_lit.items);
                            best_min_before = curr_min_before;
                        }
                        curr_lit.clearRetainingCapacity();
                        if (first_lit.items.len > 0 or min_len_so_far > 0) prefix_active = false;
                        last_atom_min_bytes = 0;
                        i = j + 1;
                        continue;
                    }
                    if (only_flags and j < pattern.len and pattern[j] == ':') {
                        if (depth == 0 and curr_lit.items.len > best_lit.items.len) {
                            best_lit.clearRetainingCapacity();
                            try best_lit.appendSlice(allocator, curr_lit.items);
                            best_min_before = curr_min_before;
                        }
                        curr_lit.clearRetainingCapacity();
                        depth += 1;
                        prefix_active = false;
                        exact_only = false;
                        last_atom_min_bytes = 0;
                        i = j + 1;
                        continue;
                    }
                }
                if (depth == 0 and curr_lit.items.len > best_lit.items.len) {
                    best_lit.clearRetainingCapacity();
                    try best_lit.appendSlice(allocator, curr_lit.items);
                    best_min_before = curr_min_before;
                }
                curr_lit.clearRetainingCapacity();
                depth += 1;
                prefix_active = false;
                exact_only = false;
                last_atom_min_bytes = 0;
                i += 1;
            },
            ')' => {
                if (depth > 0) depth -= 1;
                last_atom_min_bytes = 0;
                i += 1;
            },
            '|' => {
                if (depth == 0) return false;
                i += 1;
            },
            '*', '?' => {
                if (depth == 0) {
                    popLastUtf8Codepoint(&curr_lit);
                    if (prefix_active) popLastUtf8Codepoint(&first_lit);
                    if (curr_lit.items.len > best_lit.items.len) {
                        best_lit.clearRetainingCapacity();
                        try best_lit.appendSlice(allocator, curr_lit.items);
                        best_min_before = curr_min_before;
                    }
                    curr_lit.clearRetainingCapacity();
                    min_len_so_far -|= last_atom_min_bytes;
                    last_atom_min_bytes = 0;
                    prefix_active = false;
                    exact_only = false;
                }
                i += 1;
                if (i < pattern.len and pattern[i] == '?') i += 1;
            },
            '{' => {
                var j = i + 1;
                var min_val: usize = 0;
                var has_digit = false;
                while (j < pattern.len and std.ascii.isDigit(pattern[j])) : (j += 1) {
                    has_digit = true;
                    min_val = min_val *| 10 +| (pattern[j] - '0');
                }
                var valid_brace = false;
                if (has_digit and j < pattern.len) {
                    if (pattern[j] == '}') {
                        valid_brace = true;
                    } else if (pattern[j] == ',') {
                        j += 1;
                        while (j < pattern.len and std.ascii.isDigit(pattern[j])) : (j += 1) {}
                        if (j < pattern.len and pattern[j] == '}') valid_brace = true;
                    }
                }
                if (depth == 0) {
                    if (!valid_brace or min_val == 0) {
                        popLastUtf8Codepoint(&curr_lit);
                        if (prefix_active) popLastUtf8Codepoint(&first_lit);
                        min_len_so_far -|= last_atom_min_bytes;
                    } else if (min_val > 1) {
                        min_len_so_far +|= (min_val - 1) *| last_atom_min_bytes;
                    }
                    if (curr_lit.items.len > best_lit.items.len) {
                        best_lit.clearRetainingCapacity();
                        try best_lit.appendSlice(allocator, curr_lit.items);
                        best_min_before = curr_min_before;
                    }
                    curr_lit.clearRetainingCapacity();
                    last_atom_min_bytes = 0;
                    prefix_active = false;
                    exact_only = false;
                }
                if (valid_brace) {
                    i = j + 1;
                } else {
                    while (i < pattern.len and pattern[i] != '}') i += 1;
                    if (i < pattern.len) i += 1;
                }
                if (i < pattern.len and pattern[i] == '?') i += 1;
            },
            '+' => {
                if (depth == 0) {
                    if (curr_lit.items.len > best_lit.items.len) {
                        best_lit.clearRetainingCapacity();
                        try best_lit.appendSlice(allocator, curr_lit.items);
                        best_min_before = curr_min_before;
                    }
                    curr_lit.clearRetainingCapacity();
                    last_atom_min_bytes = 0;
                    prefix_active = false;
                    exact_only = false;
                }
                i += 1;
                if (i < pattern.len and pattern[i] == '?') i += 1;
            },
            '^' => {
                if (depth == 0) {
                    exact_only = false;
                    if (curr_lit.items.len > 0 or first_lit.items.len > 0 or min_len_so_far > 0) {
                        if (curr_lit.items.len > best_lit.items.len) {
                            best_lit.clearRetainingCapacity();
                            try best_lit.appendSlice(allocator, curr_lit.items);
                            best_min_before = curr_min_before;
                        }
                        curr_lit.clearRetainingCapacity();
                        prefix_active = false;
                    }
                    last_atom_min_bytes = 0;
                }
                i += 1;
            },
            '$' => {
                if (depth == 0) {
                    if (curr_lit.items.len > best_lit.items.len) {
                        best_lit.clearRetainingCapacity();
                        try best_lit.appendSlice(allocator, curr_lit.items);
                        best_min_before = curr_min_before;
                    }
                    curr_lit.clearRetainingCapacity();
                    prefix_active = false;
                    exact_only = false;
                    last_atom_min_bytes = 0;
                }
                i += 1;
            },
            '.' => {
                if (depth == 0) {
                    if (curr_lit.items.len > best_lit.items.len) {
                        best_lit.clearRetainingCapacity();
                        try best_lit.appendSlice(allocator, curr_lit.items);
                        best_min_before = curr_min_before;
                    }
                    curr_lit.clearRetainingCapacity();
                    prefix_active = false;
                    exact_only = false;
                    last_atom_min_bytes = 1;
                    min_len_so_far +|= 1;
                }
                i += 1;
            },
            '[' => {
                if (depth == 0) {
                    if (curr_lit.items.len > best_lit.items.len) {
                        best_lit.clearRetainingCapacity();
                        try best_lit.appendSlice(allocator, curr_lit.items);
                        best_min_before = curr_min_before;
                    }
                    curr_lit.clearRetainingCapacity();
                    prefix_active = false;
                    exact_only = false;
                }
                i += 1;
                if (i < pattern.len and (pattern[i] == '^' or pattern[i] == '!')) i += 1;
                if (i < pattern.len and pattern[i] == ']') i += 1;
                while (i < pattern.len and pattern[i] != ']') {
                    if (pattern[i] == '[' and i + 1 < pattern.len and pattern[i + 1] == ':') {
                        if (std.mem.findPos(u8, pattern, i + 2, ":]")) |end_posix| {
                            i = end_posix + 2;
                            continue;
                        }
                    }
                    if (pattern[i] == '\\' and i + 1 < pattern.len) {
                        const esc = pattern[i + 1];
                        if (esc == 'Q') {
                            i += 2;
                            if (std.mem.findPos(u8, pattern, i, "\\E")) |e_pos| {
                                i = e_pos + 2;
                            } else {
                                i = pattern.len;
                            }
                            continue;
                        }
                        if (esc == 'x' or esc == 'u') {
                            i += 2;
                            if (i < pattern.len and pattern[i] == '{') {
                                while (i < pattern.len and pattern[i] != '}') i += 1;
                                if (i < pattern.len) i += 1;
                            } else {
                                i = @min(pattern.len, i + (if (esc == 'x') @as(usize, 2) else @as(usize, 4)));
                            }
                            continue;
                        }
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if (i < pattern.len) i += 1;
                if (depth == 0) {
                    last_atom_min_bytes = 1;
                    min_len_so_far +|= 1;
                }
            },
            '\\' => {
                if (i + 1 >= pattern.len) break;
                const next_c = pattern[i + 1];
                if (next_c == 'Q') {
                    if (depth == 0) {
                        if (curr_lit.items.len > best_lit.items.len) {
                            best_lit.clearRetainingCapacity();
                            try best_lit.appendSlice(allocator, curr_lit.items);
                            best_min_before = curr_min_before;
                        }
                        curr_lit.clearRetainingCapacity();
                        prefix_active = false;
                        exact_only = false;
                        last_atom_min_bytes = 0;
                    }
                    i += 2;
                    if (std.mem.findPos(u8, pattern, i, "\\E")) |e_pos| {
                        i = e_pos + 2;
                    } else {
                        i = pattern.len;
                    }
                    continue;
                }
                if (next_c == 'x' or next_c == 'u') {
                    if (depth == 0) {
                        if (curr_lit.items.len > best_lit.items.len) {
                            best_lit.clearRetainingCapacity();
                            try best_lit.appendSlice(allocator, curr_lit.items);
                            best_min_before = curr_min_before;
                        }
                        curr_lit.clearRetainingCapacity();
                        prefix_active = false;
                        exact_only = false;
                        last_atom_min_bytes = 1;
                        min_len_so_far +|= 1;
                    }
                    i += 2;
                    if (i < pattern.len and pattern[i] == '{') {
                        while (i < pattern.len and pattern[i] != '}') i += 1;
                        if (i < pattern.len) i += 1;
                    } else {
                        i = @min(pattern.len, i + (if (next_c == 'x') @as(usize, 2) else @as(usize, 4)));
                    }
                    continue;
                }
                if (next_c == 'p' or next_c == 'P') {
                    if (depth == 0) {
                        if (curr_lit.items.len > best_lit.items.len) {
                            best_lit.clearRetainingCapacity();
                            try best_lit.appendSlice(allocator, curr_lit.items);
                            best_min_before = curr_min_before;
                        }
                        curr_lit.clearRetainingCapacity();
                        prefix_active = false;
                        exact_only = false;
                        last_atom_min_bytes = 1;
                        min_len_so_far +|= 1;
                    }
                    i += 2;
                    if (i < pattern.len and pattern[i] == '{') {
                        while (i < pattern.len and pattern[i] != '}') i += 1;
                        if (i < pattern.len) i += 1;
                    } else if (i < pattern.len) {
                        i += 1;
                    }
                    continue;
                }
                if (next_c == 'A' or next_c == 'b' or next_c == 'B') {
                    if (depth == 0) {
                        exact_only = false;
                        if (curr_lit.items.len > 0 or first_lit.items.len > 0 or min_len_so_far > 0) {
                            if (curr_lit.items.len > best_lit.items.len) {
                                best_lit.clearRetainingCapacity();
                                try best_lit.appendSlice(allocator, curr_lit.items);
                                best_min_before = curr_min_before;
                            }
                            curr_lit.clearRetainingCapacity();
                            prefix_active = false;
                        }
                        last_atom_min_bytes = 0;
                    }
                    i += 2;
                    continue;
                }
                if (next_c == 'z' or next_c == 'Z' or next_c == '0') {
                    if (depth == 0) {
                        if (curr_lit.items.len > best_lit.items.len) {
                            best_lit.clearRetainingCapacity();
                            try best_lit.appendSlice(allocator, curr_lit.items);
                            best_min_before = curr_min_before;
                        }
                        curr_lit.clearRetainingCapacity();
                        prefix_active = false;
                        exact_only = false;
                        last_atom_min_bytes = 0;
                    }
                    i += 2;
                    continue;
                }
                if (next_c == 'd' or next_c == 'D' or next_c == 'w' or next_c == 'W' or next_c == 's' or next_c == 'S') {
                    if (depth == 0) {
                        if (curr_lit.items.len > best_lit.items.len) {
                            best_lit.clearRetainingCapacity();
                            try best_lit.appendSlice(allocator, curr_lit.items);
                            best_min_before = curr_min_before;
                        }
                        curr_lit.clearRetainingCapacity();
                        prefix_active = false;
                        exact_only = false;
                        last_atom_min_bytes = 1;
                        min_len_so_far +|= 1;
                    }
                    i += 2;
                    continue;
                }
                const decoded: ?u8 = switch (next_c) {
                    'a' => 0x07,
                    'f' => 0x0C,
                    'v' => 0x0B,
                    'n' => if (multiline) '\n' else null,
                    'r' => '\r',
                    't' => '\t',
                    else => next_c,
                };
                if (decoded) |lit_b| {
                    if (depth == 0) {
                        if (curr_lit.items.len == 0) curr_min_before = min_len_so_far;
                        try curr_lit.append(allocator, lit_b);
                        if (prefix_active) try first_lit.append(allocator, lit_b);
                        last_atom_min_bytes = 1;
                        min_len_so_far +|= 1;
                    }
                } else {
                    if (depth == 0) {
                        if (curr_lit.items.len > best_lit.items.len) {
                            best_lit.clearRetainingCapacity();
                            try best_lit.appendSlice(allocator, curr_lit.items);
                            best_min_before = curr_min_before;
                        }
                        curr_lit.clearRetainingCapacity();
                        prefix_active = false;
                        exact_only = false;
                        last_atom_min_bytes = 0;
                    }
                }
                i += 2;
            },
            else => {
                if (depth == 0 and (c != '\n' or multiline)) {
                    const seq_len = utf8SeqLenAt(pattern, i, pattern.len);
                    if (curr_lit.items.len == 0) curr_min_before = min_len_so_far;
                    try curr_lit.appendSlice(allocator, pattern[i .. i + seq_len]);
                    if (prefix_active) try first_lit.appendSlice(allocator, pattern[i .. i + seq_len]);
                    last_atom_min_bytes = 1;
                    min_len_so_far +|= 1;
                    i += seq_len;
                    continue;
                } else if (depth == 0) {
                    if (curr_lit.items.len > best_lit.items.len) {
                        best_lit.clearRetainingCapacity();
                        try best_lit.appendSlice(allocator, curr_lit.items);
                        best_min_before = curr_min_before;
                    }
                    curr_lit.clearRetainingCapacity();
                    prefix_active = false;
                    exact_only = false;
                    last_atom_min_bytes = 0;
                }
                i += 1;
            },
        }
    }

    if (curr_lit.items.len > best_lit.items.len) {
        best_lit.clearRetainingCapacity();
        try best_lit.appendSlice(allocator, curr_lit.items);
        best_min_before = curr_min_before;
    }

    // If no leading literal, try leading alternation group `(?:b1|b2|...)` when its branch prefixes
    // are at least as informative as `best_lit` (promoting e.g. `(?:FATAL|PANIC)_OOM_[0-9]+` to `.prefix`).
    if (first_lit.items.len == 0) {
        if (try tryExtractSetLeadingAltGroup(allocator, pattern, pat_id, multiline, best_lit.items.len, max_total_literals, out_items)) {
            return true;
        }
    }

    if (exact_only and first_lit.items.len > 0) {
        if (out_items.items.len >= max_total_literals) return false;
        const duped = try allocator.dupe(u8, first_lit.items);
        errdefer allocator.free(duped);
        try out_items.append(allocator, .{
            .bytes = duped,
            .pat_id = pat_id,
            .kind = .exact,
            .min_before = 0,
        });
        return true;
    }

    const pick_first = first_lit.items.len >= 3 or
        (first_lit.items.len >= 2 and first_lit.items.len >= best_lit.items.len) or
        (first_lit.items.len == 1 and best_lit.items.len <= 1);

    if (pick_first) {
        if (out_items.items.len >= max_total_literals) return false;
        const duped = try allocator.dupe(u8, first_lit.items);
        errdefer allocator.free(duped);
        try out_items.append(allocator, .{
            .bytes = duped,
            .pat_id = pat_id,
            .kind = .prefix,
            .min_before = 0,
        });
        return true;
    }

    if (best_lit.items.len >= 1) {
        if (out_items.items.len >= max_total_literals) return false;
        const duped = try allocator.dupe(u8, best_lit.items);
        errdefer allocator.free(duped);
        try out_items.append(allocator, .{
            .bytes = duped,
            .pat_id = pat_id,
            .kind = .interior,
            .min_before = @intCast(@min(best_min_before, std.math.maxInt(u32))),
        });
        return true;
    }

    return false;
}

fn tryExtractSetLeadingAltGroup(
    allocator: std.mem.Allocator,
    pattern: []const u8,
    pat_id: u32,
    multiline: bool,
    best_lit_len: usize,
    max_total_literals: usize,
    out_items: *std.ArrayList(SetExtractItem),
) !bool {
    var start_idx: usize = 0;
    // Allow leading zero-width anchors `^`, `\A`, `\b`, `\B` before the leading alt group
    while (start_idx < pattern.len) {
        if (pattern[start_idx] == '^') {
            start_idx += 1;
        } else if (pattern[start_idx] == '\\' and start_idx + 1 < pattern.len and
            (pattern[start_idx + 1] == 'A' or pattern[start_idx + 1] == 'b' or pattern[start_idx + 1] == 'B'))
        {
            start_idx += 2;
        } else {
            break;
        }
    }
    if (start_idx + 3 >= pattern.len or pattern[start_idx] != '(') return false;

    var close_idx: ?usize = null;
    {
        var depth: usize = 0;
        var in_class = false;
        var j: usize = start_idx;
        while (j < pattern.len) : (j += 1) {
            const ch = pattern[j];
            if (ch == '\\' and j + 1 < pattern.len) {
                if (pattern[j + 1] == 'Q') {
                    j += 2;
                    while (j + 1 < pattern.len and !(pattern[j] == '\\' and pattern[j + 1] == 'E')) : (j += 1) {}
                    if (j + 1 < pattern.len) j += 1;
                    continue;
                }
                j += 1;
                continue;
            }
            if (in_class) {
                if (ch == '[' and j + 1 < pattern.len and pattern[j + 1] == ':') {
                    if (std.mem.findPos(u8, pattern, j + 2, ":]")) |end_posix| {
                        j = end_posix + 1;
                        continue;
                    }
                }
                if (ch == ']') in_class = false;
                continue;
            }
            if (ch == '[') {
                in_class = true;
                if (j + 1 < pattern.len and (pattern[j + 1] == '^' or pattern[j + 1] == '!')) j += 1;
                if (j + 1 < pattern.len and pattern[j + 1] == ']') j += 1;
            } else if (ch == '(') {
                depth += 1;
            } else if (ch == ')') {
                depth -= 1;
                if (depth == 0) {
                    close_idx = j;
                    break;
                }
            }
        }
    }
    const c_idx = close_idx orelse return false;
    if (c_idx <= start_idx + 1) return false;

    const group_slice = pattern[start_idx .. c_idx + 1];
    const inner: []const u8 = if (std.mem.startsWith(u8, group_slice, "(?:"))
        group_slice[3 .. group_slice.len - 1]
    else if (std.mem.startsWith(u8, group_slice, "(?P<")) blk: {
        const gt = std.mem.findScalarPos(u8, group_slice, 4, '>') orelse return false;
        break :blk group_slice[gt + 1 .. group_slice.len - 1];
    } else if (std.mem.startsWith(u8, group_slice, "(?<")) blk: {
        const gt = std.mem.findScalarPos(u8, group_slice, 3, '>') orelse return false;
        break :blk group_slice[gt + 1 .. group_slice.len - 1];
    } else if (group_slice[1] != '?')
        group_slice[1 .. group_slice.len - 1]
    else
        return false;

    const after = c_idx + 1;
    var allow_suffix = true;
    if (after < pattern.len) {
        switch (pattern[after]) {
            '*', '?' => return false,
            '+' => allow_suffix = false,
            '{' => {
                var j = after + 1;
                var min_val: usize = 0;
                var has_digit = false;
                while (j < pattern.len and std.ascii.isDigit(pattern[j])) : (j += 1) {
                    has_digit = true;
                    min_val = min_val *| 10 +| (pattern[j] - '0');
                }
                if (!has_digit or min_val == 0) return false;
                allow_suffix = false;
            },
            else => {},
        }
    } else {
        allow_suffix = false;
    }

    const max_leading_branches: usize = 16;
    var branches = std.ArrayList([]const u8).empty;
    defer branches.deinit(allocator);
    if (!try splitTopLevelBranches(allocator, inner, max_leading_branches, &branches)) return false;
    if (branches.items.len < 2 or out_items.items.len + branches.items.len > max_total_literals) return false;

    var suffix_buf = std.ArrayList(u8).empty;
    defer suffix_buf.deinit(allocator);
    if (allow_suffix and after < pattern.len) {
        const tail = pattern[after..];
        var t: usize = 0;
        while (t < tail.len) {
            const ch = tail[t];
            switch (ch) {
                '.', '^', '$', '[', '(', ')', '|' => break,
                '*', '?' => {
                    popLastUtf8Codepoint(&suffix_buf);
                    break;
                },
                '{' => {
                    var j = t + 1;
                    var min_val: usize = 0;
                    var has_digit = false;
                    while (j < tail.len and std.ascii.isDigit(tail[j])) : (j += 1) {
                        has_digit = true;
                        min_val = min_val *| 10 +| (tail[j] - '0');
                    }
                    if (!has_digit or min_val == 0) popLastUtf8Codepoint(&suffix_buf);
                    break;
                },
                '+' => break,
                '\\' => {
                    if (t + 1 >= tail.len) break;
                    const nc = tail[t + 1];
                    if (nc == 'p' or nc == 'P' or nc == 'A' or nc == 'z' or nc == 'Z' or
                        nc == 'x' or nc == 'u' or nc == 'Q' or
                        nc == 'd' or nc == 'D' or nc == 'w' or nc == 'W' or
                        nc == 's' or nc == 'S' or nc == 'b' or nc == 'B' or nc == '0')
                    {
                        break;
                    }
                    const lit_b: u8 = switch (nc) {
                        'a' => 0x07,
                        'f' => 0x0C,
                        'v' => 0x0B,
                        'n' => if (!multiline) break else '\n',
                        'r' => '\r',
                        't' => '\t',
                        else => nc,
                    };
                    try suffix_buf.append(allocator, lit_b);
                    t += 2;
                },
                else => {
                    if (ch == '\n' and !multiline) break;
                    const seq_len = utf8SeqLenAt(tail, t, tail.len);
                    try suffix_buf.appendSlice(allocator, tail[t .. t + seq_len]);
                    t += seq_len;
                },
            }
        }
    }

    var local = std.ArrayList([]u8).empty;
    errdefer {
        for (local.items) |s| allocator.free(s);
        local.deinit(allocator);
    }

    var prefix_buf = std.ArrayList(u8).empty;
    defer prefix_buf.deinit(allocator);

    for (branches.items) |br| {
        prefix_buf.clearRetainingCapacity();
        var k: usize = 0;
        var br_exact = true;
        while (k < br.len) {
            const ch = br[k];
            switch (ch) {
                '.', '^', '$', '[', '(', ')' => {
                    br_exact = false;
                    break;
                },
                '*', '?', '{' => {
                    popLastUtf8Codepoint(&prefix_buf);
                    br_exact = false;
                    break;
                },
                '+' => {
                    br_exact = false;
                    break;
                },
                '\\' => {
                    if (k + 1 >= br.len) {
                        br_exact = false;
                        break;
                    }
                    const nc = br[k + 1];
                    if (nc == 'p' or nc == 'P' or nc == 'A' or nc == 'z' or nc == 'Z' or
                        nc == 'x' or nc == 'u' or nc == 'Q' or
                        nc == 'd' or nc == 'D' or nc == 'w' or nc == 'W' or
                        nc == 's' or nc == 'S' or nc == 'b' or nc == 'B' or nc == '0')
                    {
                        br_exact = false;
                        break;
                    }
                    const lit_b: u8 = switch (nc) {
                        'a' => 0x07,
                        'f' => 0x0C,
                        'v' => 0x0B,
                        'n' => if (!multiline) {
                            br_exact = false;
                            break;
                        } else '\n',
                        'r' => '\r',
                        't' => '\t',
                        else => nc,
                    };
                    try prefix_buf.append(allocator, lit_b);
                    k += 2;
                },
                else => {
                    if (ch == '\n' and !multiline) {
                        br_exact = false;
                        break;
                    }
                    const seq_len = utf8SeqLenAt(br, k, br.len);
                    try prefix_buf.appendSlice(allocator, br[k .. k + seq_len]);
                    k += seq_len;
                },
            }
        }
        if (prefix_buf.items.len == 0) {
            for (local.items) |s| allocator.free(s);
            local.deinit(allocator);
            return false;
        }
        if (br_exact and k == br.len and suffix_buf.items.len > 0) {
            try prefix_buf.appendSlice(allocator, suffix_buf.items);
        }
        const duped = try allocator.dupe(u8, prefix_buf.items);
        errdefer allocator.free(duped);
        try local.append(allocator, duped);
    }

    var min_branch_len: usize = std.math.maxInt(usize);
    for (local.items) |s| {
        if (s.len < min_branch_len) min_branch_len = s.len;
    }
    if (best_lit_len > 2 and min_branch_len < 3 and min_branch_len < best_lit_len) {
        for (local.items) |s| allocator.free(s);
        local.deinit(allocator);
        return false;
    }

    for (local.items) |s| {
        try out_items.append(allocator, .{
            .bytes = s,
            .pat_id = pat_id,
            .kind = .prefix,
            .min_before = 0,
        });
    }
    local.deinit(allocator);
    return true;
}
