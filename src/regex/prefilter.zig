//! [Module] regex/prefilter.zig
//! [Layer] Layer 2 — Regex Required Literal & Alternation Prefilter Extractor
//! [Role] Analyzes regex syntax to extract required prefix/interior/trailing literals (`Finder`)
//!        or top-level alternation branch prefixes (`Multi`) for 14-29 GB/s SIMD prefiltering.
//! [Invariants]
//!   1. Prefilters are strictly conservative: every valid regex match must contain the prefilter candidate,
//!      ensuring zero false negatives before NFA verification.
//! [HotPath] Initialization-only (`extractLiterals` / `tryExtractAltLiterals` / `extractRequiredPrefix`).

const std = @import("std");
const matcher = @import("../matcher.zig");
const Finder = @import("../finder/finder.zig").Finder;
const Multi = @import("../finder/multi.zig").Multi;
const inst_mod = @import("inst.zig");
const CaseMode = inst_mod.CaseMode;
const popLastUtf8Codepoint = inst_mod.popLastUtf8Codepoint;
const utf8SeqLenAt = inst_mod.utf8SeqLenAt;

pub fn extractLiterals(self: anytype, pattern: []const u8, options: inst_mod.RegexOptions) !void {
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
                // Check for standalone inline flag group `(?i)`, `(?m)`, `(?s)`, `(?-i)` at the start of the pattern
                if (i + 2 < pattern.len and pattern[i + 1] == '?') {
                    var j = i + 2;
                    var only_flags = false;
                    var has_neg_or_scoped = false;
                    while (j < pattern.len and (pattern[j] == 'i' or pattern[j] == 'm' or pattern[j] == 's' or pattern[j] == '-')) : (j += 1) {
                        only_flags = true;
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
                    const seq_len = utf8SeqLenAt(pattern, i, pattern.len);
                    if (curr_lit.items.len == 0) curr_offset = fixed_offset orelse 0;
                    try curr_lit.appendSlice(self.allocator, pattern[i .. i + seq_len]);
                    if (prefix_active) try first_lit.appendSlice(self.allocator, pattern[i .. i + seq_len]);
                    if (fixed_offset != null) fixed_offset.? += seq_len;
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
    };

    if (has_top_alt) {
        try tryExtractAltLiterals(self, pattern, find_opts);
        return;
    }

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
    } else if (best_lit.items.len >= 1) {
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
    }
}

/// Extracts a required literal prefix (starting at offset 0 of any match) if the pattern has no top-level alternation
/// and begins with at least 1 required literal byte. Used by `RegexSet` to build a shared `Multi` SIMD prefilter.
pub fn extractRequiredPrefix(allocator: std.mem.Allocator, pattern: []const u8, multiline: bool) !?[]u8 {
    if (inst_mod.hasTopLevelAlt(pattern)) return null;
    var prefix = std.ArrayList(u8).empty;
    defer prefix.deinit(allocator);

    var i: usize = 0;
    // Allow leading `(?i)` / `(?m)` / `(?s)` standalone flag group
    if (pattern.len >= 4 and pattern[0] == '(' and pattern[1] == '?') {
        var j: usize = 2;
        var only_flags = false;
        var has_neg = false;
        while (j < pattern.len and (pattern[j] == 'i' or pattern[j] == 'm' or pattern[j] == 's' or pattern[j] == '-')) : (j += 1) {
            only_flags = true;
            if (pattern[j] == '-') has_neg = true;
        }
        if (j < pattern.len and pattern[j] == ')' and only_flags and !has_neg) {
            i = j + 1;
        }
    }

    while (i < pattern.len) {
        const c = pattern[i];
        switch (c) {
            '.', '^', '$', '[', '(', ')', '|' => break,
            '*', '?' => {
                popLastUtf8Codepoint(&prefix);
                break;
            },
            '{' => {
                // Check if `{0,...}` (optional) vs `{1,...}` (required at least once)
                var j = i + 1;
                var min_val: usize = 0;
                var has_digit = false;
                while (j < pattern.len and pattern[j] >= '0' and pattern[j] <= '9') : (j += 1) {
                    has_digit = true;
                    min_val = min_val *| 10 +| (pattern[j] - '0');
                }
                if (!has_digit or min_val == 0) {
                    popLastUtf8Codepoint(&prefix);
                }
                break;
            },
            '+' => break,
            '\\' => {
                if (i + 1 >= pattern.len) break;
                const next_c = pattern[i + 1];
                if (next_c == 'p' or next_c == 'P' or next_c == 'A' or next_c == 'z' or
                    next_c == 'd' or next_c == 'D' or next_c == 'w' or next_c == 'W' or
                    next_c == 's' or next_c == 'S' or next_c == 'b' or next_c == 'B' or next_c == '0')
                {
                    break;
                }
                const lit_b: u8 = switch (next_c) {
                    'n' => if (multiline) break else '\n',
                    'r' => '\r',
                    't' => '\t',
                    else => next_c,
                };
                try prefix.append(allocator, lit_b);
                i += 2;
            },
            else => {
                if (c == '\n') break;
                const seq_len = utf8SeqLenAt(pattern, i, pattern.len);
                try prefix.appendSlice(allocator, pattern[i .. i + seq_len]);
                i += seq_len;
            },
        }
    }
    if (prefix.items.len == 0) return null;
    return try allocator.dupe(u8, prefix.items);
}

pub fn tryExtractAltLiterals(self: anytype, pattern: []const u8, find_opts: matcher.FindOptions) !void {
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
                j += 1;
                continue;
            }
            if (in_class) {
                if (ch == ']') in_class = false;
                continue;
            }
            if (ch == '[') {
                in_class = true;
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
            } else if (inner[1] != '?') {
                inner = inner[1 .. inner.len - 1];
            }
        }
    }

    var branches: [16][]const u8 = undefined;
    var n_branches: usize = 0;
    var branch_start: usize = 0;
    var depth: usize = 0;
    var in_class = false;
    var i: usize = 0;
    while (i < inner.len) : (i += 1) {
        const ch = inner[i];
        if (ch == '\\' and i + 1 < inner.len) {
            i += 1;
            continue;
        }
        if (in_class) {
            if (ch == ']') in_class = false;
            continue;
        }
        if (ch == '[') {
            in_class = true;
        } else if (ch == '(') {
            depth += 1;
        } else if (ch == ')') {
            if (depth > 0) depth -= 1;
        } else if (ch == '|' and depth == 0) {
            if (n_branches >= 15) return;
            branches[n_branches] = inner[branch_start..i];
            n_branches += 1;
            branch_start = i + 1;
        }
    }
    branches[n_branches] = inner[branch_start..];
    n_branches += 1;
    if (n_branches < 2) return;

    var prefixes = std.ArrayList([]const u8).empty;
    errdefer {
        for (prefixes.items) |s| self.allocator.free(s);
        prefixes.deinit(self.allocator);
    }

    var prefix_buf = std.ArrayList(u8).empty;
    defer prefix_buf.deinit(self.allocator);

    var all_exact = true;
    for (branches[0..n_branches]) |br| {
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
                    if (next_c == 'p' or next_c == 'P' or next_c == 'A' or next_c == 'z' or
                        next_c == 'd' or next_c == 'D' or next_c == 'w' or next_c == 'W' or
                        next_c == 's' or next_c == 'S' or next_c == 'b' or next_c == 'B' or next_c == '0')
                    {
                        br_exact = false;
                        break;
                    }
                    const lit_b: u8 = switch (next_c) {
                        'n' => if (self.multiline) {
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
                    if (c == '\n') {
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
        self.alt_is_exact = all_exact and !self.multiline;
    } else |_| {
        for (owned_slices) |s| self.allocator.free(s);
        self.allocator.free(owned_slices);
    }
}
