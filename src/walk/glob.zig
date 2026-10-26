//! Byte-level glob matching. `*` and `?` do not cross `/`, and `**` crosses directories only as a complete path component.
//! Character classes support ranges and `!` / `^` negation. Paths are compared byte-by-byte without assuming UTF-8.

const std = @import("std");

pub const rule_count_hard_cap: usize = 1024;
pub const rule_len_hard_cap: usize = 4096;
pub const brace_depth_hard_cap: usize = 8;

pub const GlobError = error{
    GlobCountExceeded,
    GlobTooLong,
    GlobBraceDepthExceeded,
    OutOfMemory,
};

pub const CompileOptions = struct {
    case_insensitive: bool = false,
    max_rules: ?usize = null,
    max_rule_len: ?usize = null,
};

pub const Class = enum {
    /// No metacharacters.
    exact,
    /// `*.ext`, where the key is the dot-prefixed extension.
    ext,
    /// Literal prefix followed by a trailing `*`.
    prefix,
    /// Leading `*` followed by a literal suffix.
    suffix,
    general,
};

/// A parsed glob rule. `text` and `key` are owned by the caller.
pub const Glob = struct {
    text: []const u8,
    key: []const u8,
    class: Class,
    anchored: bool = false,
    dir_only: bool = false,
    negated: bool = false,
    case_insensitive: bool = false,
};

/// Classifies a pattern by its metacharacters. `key` slices into the literal portion of `text`.
pub fn classify(text: []const u8) Glob {
    return classifyWithCase(text, false);
}

/// Classifies a pattern by its metacharacters and sets whether ASCII case is ignored.
pub fn classifyWithCase(text: []const u8, case_insensitive: bool) Glob {
    const class = classifyClass(text);
    const key = switch (class) {
        .ext, .suffix => text[1..],
        .prefix => if (text.len == 0) text else text[0 .. text.len - 1],
        .exact, .general => text,
    };
    return .{
        .text = text,
        .key = key,
        .class = class,
        .case_insensitive = case_insensitive,
    };
}

/// Expands nested braces `{a,{b,c}}` while enforcing limits on rule count, rule length, and nesting depth.
pub fn expandBraces(
    allocator: std.mem.Allocator,
    pattern: []const u8,
    out: *std.ArrayList([]u8),
    max_rules: usize,
) GlobError!void {
    const effective_max = @min(max_rules, rule_count_hard_cap);
    if (pattern.len > rule_len_hard_cap) return error.GlobTooLong;
    try checkBraceDepth(pattern);
    try expandBracesInner(allocator, pattern, out, effective_max, 0);
}

fn checkBraceDepth(pattern: []const u8) GlobError!void {
    var depth: usize = 0;
    var in_class = false;
    var i: usize = 0;
    while (i < pattern.len) : (i += 1) {
        if (pattern[i] == '\\' and i + 1 < pattern.len) {
            i += 1;
            continue;
        }
        if (in_class) {
            if (pattern[i] == ']') in_class = false;
            continue;
        }
        if (pattern[i] == '[') {
            in_class = true;
            continue;
        }
        if (pattern[i] == '{') {
            depth += 1;
            if (depth > brace_depth_hard_cap) return error.GlobBraceDepthExceeded;
        } else if (pattern[i] == '}') {
            if (depth > 0) depth -= 1;
        }
    }
}

const BraceSpan = struct {
    open: usize,
    close: usize,
};

fn findExpandableBrace(pattern: []const u8) ?BraceSpan {
    var in_class = false;
    var i: usize = 0;
    while (i < pattern.len) : (i += 1) {
        if (pattern[i] == '\\' and i + 1 < pattern.len) {
            i += 1;
            continue;
        }
        if (in_class) {
            if (pattern[i] == ']') in_class = false;
            continue;
        }
        if (pattern[i] == '[') {
            in_class = true;
            continue;
        }
        if (pattern[i] != '{') continue;

        var depth: usize = 1;
        var has_comma = false;
        var class_inner = false;
        var j: usize = i + 1;
        while (j < pattern.len) : (j += 1) {
            if (pattern[j] == '\\' and j + 1 < pattern.len) {
                j += 1;
                continue;
            }
            if (class_inner) {
                if (pattern[j] == ']') class_inner = false;
                continue;
            }
            if (pattern[j] == '[') {
                class_inner = true;
                continue;
            }
            if (pattern[j] == '{') {
                depth += 1;
            } else if (pattern[j] == '}') {
                depth -= 1;
                if (depth == 0) {
                    if (has_comma) return .{ .open = i, .close = j };
                    break;
                }
            } else if (pattern[j] == ',' and depth == 1) {
                has_comma = true;
            }
        }
    }
    return null;
}

fn expandBracesInner(
    allocator: std.mem.Allocator,
    pattern: []const u8,
    out: *std.ArrayList([]u8),
    max_rules: usize,
    depth: usize,
) GlobError!void {
    if (pattern.len > rule_len_hard_cap) return error.GlobTooLong;
    const span = findExpandableBrace(pattern) orelse {
        if (out.items.len >= max_rules) return error.GlobCountExceeded;
        const copy = try allocator.dupe(u8, pattern);
        errdefer allocator.free(copy);
        try out.append(allocator, copy);
        return;
    };
    if (depth >= brace_depth_hard_cap) return error.GlobBraceDepthExceeded;

    const prefix = pattern[0..span.open];
    const body = pattern[span.open + 1 .. span.close];
    const suffix = pattern[span.close + 1 ..];

    var part_start: usize = 0;
    var sub_depth: usize = 0;
    var in_class = false;
    var i: usize = 0;
    while (i <= body.len) : (i += 1) {
        if (i < body.len) {
            if (body[i] == '\\' and i + 1 < body.len) {
                i += 1;
                continue;
            }
            if (in_class) {
                if (body[i] == ']') in_class = false;
                continue;
            }
            if (body[i] == '[') {
                in_class = true;
                continue;
            }
            if (body[i] == '{') {
                sub_depth += 1;
                continue;
            }
            if (body[i] == '}') {
                if (sub_depth > 0) sub_depth -= 1;
                continue;
            }
        }
        if (i == body.len or (body[i] == ',' and sub_depth == 0)) {
            const part = body[part_start..i];
            const combined_len = prefix.len + part.len + suffix.len;
            if (combined_len > rule_len_hard_cap) return error.GlobTooLong;
            const combined = try allocator.alloc(u8, combined_len);
            defer allocator.free(combined);
            @memcpy(combined[0..prefix.len], prefix);
            @memcpy(combined[prefix.len .. prefix.len + part.len], part);
            @memcpy(combined[prefix.len + part.len ..], suffix);
            try expandBracesInner(allocator, combined, out, max_rules, depth + 1);
            part_start = i + 1;
        }
    }
}

/// Compiles glob rules supporting `!` negation and `{a,{b,c}}` nested braces while enforcing hard caps on rule count and length.
pub fn compileGlobs(
    arena: std.mem.Allocator,
    patterns: []const []const u8,
    options: CompileOptions,
) GlobError![]Glob {
    const max_rules = if (options.max_rules) |m| @min(m, rule_count_hard_cap) else rule_count_hard_cap;
    const max_len = if (options.max_rule_len) |m| @min(m, rule_len_hard_cap) else rule_len_hard_cap;
    if (patterns.len > max_rules) return error.GlobCountExceeded;

    var expanded: std.ArrayList([]u8) = .empty;
    defer expanded.deinit(arena);
    var out: std.ArrayList(Glob) = .empty;
    errdefer out.deinit(arena);

    for (patterns) |raw_pat| {
        if (raw_pat.len > max_len) return error.GlobTooLong;
        var body = raw_pat;
        var negated = false;
        if (body.len > 0 and body[0] == '!') {
            negated = true;
            body = body[1..];
        }
        expanded.clearRetainingCapacity();
        const remain = if (max_rules >= out.items.len) max_rules - out.items.len else 0;
        try expandBraces(arena, body, &expanded, remain);
        for (expanded.items) |branch| {
            if (branch.len > max_len) return error.GlobTooLong;
            var pat = branch;
            var dir_only = false;
            if (pat.len > 0 and pat[pat.len - 1] == '/') {
                dir_only = true;
                pat = pat[0 .. pat.len - 1];
            }
            var anchored = false;
            if (pat.len > 0 and pat[0] == '/') {
                anchored = true;
                pat = pat[1..];
            }
            if (std.mem.indexOfScalar(u8, pat, '/') != null) anchored = true;
            var g = classifyWithCase(pat, options.case_insensitive);
            g.negated = negated;
            g.dir_only = dir_only;
            g.anchored = anchored;
            try out.append(arena, g);
        }
    }
    return out.toOwnedSlice(arena);
}

/// Evaluates user glob rules with last-match-wins precedence: when positive rules exist, unmatched paths are excluded by default; `!` rules exclude matching paths.
pub fn matchGlobs(globs: []const Glob, rel: []const u8, base: []const u8, is_dir: bool) bool {
    var any_positive = false;
    var decision: ?bool = null;
    for (globs) |item| {
        if (!item.negated and !item.dir_only) any_positive = true;
        if (matches(item, rel, base, is_dir)) decision = !item.negated;
    }
    if (decision) |kept| return kept;
    return if (is_dir) true else !any_positive;
}

fn classifyClass(text: []const u8) Class {
    const meta = std.mem.indexOfAny(u8, text, "*?[") != null;
    if (!meta) return .exact;
    if (text.len >= 2 and text[0] == '*' and std.mem.indexOfAny(u8, text[1..], "*?[") == null) {
        if (text[1] == '.') return .ext;
        return .suffix;
    }
    if (text.len >= 1 and text[text.len - 1] == '*' and
        std.mem.indexOfAny(u8, text[0 .. text.len - 1], "*?[") == null and
        (text.len < 2 or text[text.len - 2] != '*'))
    {
        return .prefix;
    }
    return .general;
}

/// `rel` is the path relative to the current directory level, and `base` is its final segment.
pub fn matches(glob: Glob, rel: []const u8, base: []const u8, is_dir: bool) bool {
    if (glob.dir_only and !is_dir) return false;
    const hay = if (glob.anchored) rel else base;
    if (!glob.case_insensitive) {
        return switch (glob.class) {
            .exact => std.mem.eql(u8, hay, glob.key),
            .ext, .suffix => hay.len >= glob.key.len and std.mem.endsWith(u8, hay, glob.key),
            .prefix => std.mem.startsWith(u8, hay, glob.key),
            .general => matchText(glob.text, hay),
        };
    }
    return switch (glob.class) {
        .exact => std.ascii.eqlIgnoreCase(hay, glob.key),
        .ext, .suffix => hay.len >= glob.key.len and std.ascii.endsWithIgnoreCase(hay, glob.key),
        .prefix => std.ascii.startsWithIgnoreCase(hay, glob.key),
        .general => matchTextCase(glob.text, hay, true),
    };
}

/// `**` must occupy an entire path component; otherwise it is treated as a regular `*`.
fn isDoubleStar(pat: []const u8, index: usize) bool {
    if (index + 1 >= pat.len or pat[index] != '*' or pat[index + 1] != '*') return false;
    if (index != 0 and pat[index - 1] != '/') return false;
    if (index + 2 == pat.len) return true;
    return pat[index + 2] == '/';
}

pub fn matchText(pattern: []const u8, text: []const u8) bool {
    return matchFrom(pattern, text, false);
}

pub fn matchTextCase(pattern: []const u8, text: []const u8, case_insensitive: bool) bool {
    return matchFrom(pattern, text, case_insensitive);
}

fn matchFrom(pat: []const u8, text: []const u8, case_insensitive: bool) bool {
    return matchSegment(pat, text, case_insensitive);
}

fn matchSegment(pat: []const u8, text: []const u8, case_insensitive: bool) bool {
    var pi: usize = 0;
    var ti: usize = 0;
    var star_pi: ?usize = null;
    var star_ti: usize = 0;
    var dstar_pi: ?usize = null;
    var dstar_ti: usize = 0;

    while (true) {
        if (pi < pat.len and isDoubleStar(pat, pi)) {
            var rest = pi + 2;
            if (rest < pat.len and pat[rest] == '/') rest += 1;
            if (rest == pat.len) return true;
            dstar_pi = rest;
            dstar_ti = ti;
            star_pi = null;
            pi = rest;
            continue;
        }
        if (pi < pat.len and pat[pi] == '*') {
            while (pi < pat.len and pat[pi] == '*' and !isDoubleStar(pat, pi)) : (pi += 1) {}
            star_pi = pi;
            star_ti = ti;
            continue;
        }
        if (pi < pat.len and ti < text.len) {
            if (pat[pi] == '?') {
                if (text[ti] != '/') {
                    pi += 1;
                    ti += 1;
                    continue;
                }
            } else if (pat[pi] == '[') {
                if (std.mem.indexOfScalarPos(u8, pat, pi + 1, ']')) |close| {
                    if (classMatch(pat[pi + 1 .. close], text[ti], case_insensitive)) {
                        pi = close + 1;
                        ti += 1;
                        continue;
                    }
                }
            } else if (byteEqual(pat[pi], text[ti], case_insensitive)) {
                pi += 1;
                ti += 1;
                continue;
            }
        }
        if (pi == pat.len and ti == text.len) return true;

        // Backtrack to the most recent single `*` within the current path segment
        if (star_pi) |spi| {
            if (star_ti < text.len and text[star_ti] != '/') {
                star_ti += 1;
                ti = star_ti;
                pi = spi;
                continue;
            }
        }
        // Otherwise backtrack to the most recent `**` across path segments
        if (dstar_pi) |dspi| {
            if (dstar_ti < text.len) {
                if (pat[dspi - 1] == '/') {
                    // `**/` must resume at a segment boundary
                    if (std.mem.indexOfScalarPos(u8, text, dstar_ti, '/')) |slash| {
                        dstar_ti = slash + 1;
                    } else {
                        return false;
                    }
                } else {
                    dstar_ti += 1;
                }
                ti = dstar_ti;
                pi = dspi;
                star_pi = null;
                continue;
            }
        }
        return false;
    }
}

fn byteEqual(a: u8, b: u8, case_insensitive: bool) bool {
    if (!case_insensitive) return a == b;
    return std.ascii.toLower(a) == std.ascii.toLower(b);
}

fn classMatch(spec: []const u8, byte: u8, case_insensitive: bool) bool {
    if (byte == '/' or spec.len == 0) return false;
    var neg = false;
    var i: usize = 0;
    if (spec[0] == '!' or spec[0] == '^') {
        neg = true;
        i = 1;
    }
    const target = if (case_insensitive) std.ascii.toLower(byte) else byte;
    var ok = false;
    while (i < spec.len) : (i += 1) {
        if (i + 2 < spec.len and spec[i + 1] == '-') {
            const raw_lo = if (case_insensitive) std.ascii.toLower(spec[i]) else spec[i];
            const raw_hi = if (case_insensitive) std.ascii.toLower(spec[i + 2]) else spec[i + 2];
            const lo = @min(raw_lo, raw_hi);
            const hi = @max(raw_lo, raw_hi);
            if (target >= lo and target <= hi) ok = true;
            i += 2;
            continue;
        }
        const cand = if (case_insensitive) std.ascii.toLower(spec[i]) else spec[i];
        if (cand == target) ok = true;
    }
    return if (neg) !ok else ok;
}

pub fn basename(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return path;
    return path[slash + 1 ..];
}

test "classify: exact, extension, prefix, and suffix" {
    const exact = classify("foo");
    try std.testing.expectEqual(Class.exact, exact.class);

    const ext = classify("*.log");
    try std.testing.expectEqual(Class.ext, ext.class);
    try std.testing.expectEqualStrings(".log", ext.key);

    const prefix = classify("foo*");
    try std.testing.expectEqual(Class.prefix, prefix.class);
    try std.testing.expectEqualStrings("foo", prefix.key);

    const suffix = classify("*foo");
    try std.testing.expectEqual(Class.suffix, suffix.class);
    try std.testing.expectEqualStrings("foo", suffix.key);

    try std.testing.expectEqual(Class.general, classify("**").class);
    try std.testing.expectEqual(Class.general, classify("a/**/b").class);
    try std.testing.expectEqual(Class.general, classify("foo*bar").class);
}

test "glob disallows single star across slash while double star crosses" {
    try std.testing.expect(matchText("*.log", "a.log"));
    try std.testing.expect(matchText("*.log", ".log"));
    try std.testing.expect(!matchText("*.log", "dir/a.log"));
    try std.testing.expect(!matchText("foo*", "foo/bar"));
    try std.testing.expect(matchText("foo*", "foobar"));
    try std.testing.expect(matchText("?", "a"));
    try std.testing.expect(!matchText("?", "/"));
    try std.testing.expect(matchText("**/foo", "foo"));
    try std.testing.expect(matchText("**/foo", "a/b/foo"));
    try std.testing.expect(!matchText("**/foo", "foo/bar"));
    try std.testing.expect(!matchText("**/foo", "foobar"));
    try std.testing.expect(matchText("foo/**", "foo/a"));
    try std.testing.expect(matchText("foo/**", "foo/a/b"));
    try std.testing.expect(!matchText("foo/**", "foo"));
    try std.testing.expect(matchText("a/**/b", "a/b"));
    try std.testing.expect(matchText("a/**/b", "a/x/y/b"));
    try std.testing.expect(!matchText("a/**/b", "a/b/c"));
    try std.testing.expect(matchText("a*b*c", "aXXbYYc"));
    try std.testing.expect(!matchText("a*b*c", "a/b/c"));
}

test "character classes and negation" {
    try std.testing.expect(matchText("[abc]", "b"));
    try std.testing.expect(!matchText("[abc]", "d"));
    try std.testing.expect(matchText("[a-c]", "b"));
    try std.testing.expect(!matchText("[a-c]", "d"));
    try std.testing.expect(matchText("[!a]", "b"));
    try std.testing.expect(!matchText("[!a]", "a"));
    try std.testing.expect(!matchText("[a-c]", "/"));
    try std.testing.expect(matchText("*.[ch]", "a.c"));
    try std.testing.expect(matchText("*.[ch]", "a.h"));
    try std.testing.expect(!matchText("*.[ch]", "a.cc"));
}

test "later globs take precedence and nested braces respect limits" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // 1. Nested brace expansion + later rules take precedence
    const globs = try compileGlobs(arena, &.{
        "*.{zig,{c,h}}",
        "!bad.{c,h}",
        "bad.h",
    }, .{});
    try std.testing.expectEqual(@as(usize, 6), globs.len);
    try std.testing.expect(matchGlobs(globs, "src/main.zig", "main.zig", false));
    try std.testing.expect(matchGlobs(globs, "src/ok.c", "ok.c", false));
    try std.testing.expect(!matchGlobs(globs, "src/bad.c", "bad.c", false));
    try std.testing.expect(matchGlobs(globs, "src/bad.h", "bad.h", false));
    try std.testing.expect(!matchGlobs(globs, "src/readme.md", "readme.md", false));

    // 2. Reject when expanded rule count exceeds the limit
    try std.testing.expectError(
        error.GlobCountExceeded,
        compileGlobs(arena, &.{"*.{a,{b,{c,d}}}"}, .{ .max_rules = 3 }),
    );

    // 3. Reject when a single rule exceeds the length limit
    try std.testing.expectError(
        error.GlobTooLong,
        compileGlobs(arena, &.{"abcdef"}, .{ .max_rule_len = 4 }),
    );

    // 4. Reject when brace nesting depth exceeds the hard cap
    try std.testing.expectError(
        error.GlobBraceDepthExceeded,
        compileGlobs(arena, &.{"{a,{b,{c,{d,{e,{f,{g,{h,{i,j}}}}}}}}}"}, .{}),
    );
}

test "case-insensitive glob matching" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const globs = try compileGlobs(arena, &.{
        "*.{ZIG,Md}",
        "ReadMe*",
        "*_TEST.[c-f]",
        "!SKIP.zig",
    }, .{ .case_insensitive = true });

    try std.testing.expect(matchGlobs(globs, "src/main.zig", "main.zig", false));
    try std.testing.expect(matchGlobs(globs, "docs/API.MD", "API.MD", false));
    try std.testing.expect(matchGlobs(globs, "readme.txt", "readme.txt", false));
    try std.testing.expect(matchGlobs(globs, "unit_test.D", "unit_test.D", false));
    try std.testing.expect(!matchGlobs(globs, "src/skip.ZIG", "skip.ZIG", false));
}

test "pathological wildcard pattern runs in linear time without exponential blowup" {
    const pat = "a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b";
    const hay: [256]u8 = @splat('a');
    try std.testing.expect(!matchText(pat, &hay));
    try std.testing.expect(!matchText("**/a/**/a/**/a/**/b", "a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/a/c"));
}

