//! 字节 glob。`*` 和 `?` 不跨 `/`，`**` 只在作为完整路径分量时跨目录。
//! 字符类支持区间和 `!` / `^` 取反。路径按字节比较，不假定 UTF-8。

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
    /// 没有元字符。
    exact,
    /// `*.ext`，键是含点的后缀。
    ext,
    /// 字面量前缀加一个末尾 `*`。
    prefix,
    /// 一个开头 `*` 加字面量后缀。
    suffix,
    general,
};

/// 一条已经解析好的 glob。`text` 和 `key` 由调用方持有。
pub const Glob = struct {
    text: []const u8,
    key: []const u8,
    class: Class,
    anchored: bool = false,
    dir_only: bool = false,
    negated: bool = false,
    case_insensitive: bool = false,
};

/// 按元字符给模式分类。`key` 指向 `text` 里的字面量部分。
pub fn classify(text: []const u8) Glob {
    return classifyWithCase(text, false);
}

/// 按元字符给模式分类，并指定是否忽略 ASCII 大小写。
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

/// 展开嵌套花括号 `{a,{b,c}}`，并校验规则条数、单条长度与嵌套深度上限。
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

/// 编译一组支持 `!` 取反与 `{a,{b,c}}` 嵌套花括号的 glob 规则，并执行条数与长度硬顶检查。
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

/// 按“后写优先”评估一组用户 glob 规则：若存在正向规则，未命中的路径默认排除；`!` 规则排除命中路径。
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

/// `rel` 是相对本层目录的路径，`base` 是它的最后一段。
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

/// `**` 必须占完整的路径分量，否则按普通 `*` 处理。
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
    var pi: usize = 0;
    var ti: usize = 0;
    while (pi < pat.len) {
        if (isDoubleStar(pat, pi)) {
            var rest = pi + 2;
            if (rest < pat.len and pat[rest] == '/') rest += 1;
            if (rest == pat.len) return true;
            var k = ti;
            while (true) {
                if (matchFrom(pat[rest..], text[k..], case_insensitive)) return true;
                if (k >= text.len) return false;
                k += 1;
            }
        }
        if (pat[pi] == '*') {
            pi += 1;
            var k = ti;
            while (true) {
                if (matchFrom(pat[pi..], text[k..], case_insensitive)) return true;
                if (k >= text.len or text[k] == '/') return false;
                k += 1;
            }
        }
        if (ti >= text.len) return false;
        if (pat[pi] == '?') {
            if (text[ti] == '/') return false;
            pi += 1;
            ti += 1;
            continue;
        }
        if (pat[pi] == '[') {
            const close = std.mem.indexOfScalarPos(u8, pat, pi + 1, ']') orelse return false;
            if (!classMatch(pat[pi + 1 .. close], text[ti], case_insensitive)) return false;
            pi = close + 1;
            ti += 1;
            continue;
        }
        if (!byteEqual(pat[pi], text[ti], case_insensitive)) return false;
        pi += 1;
        ti += 1;
    }
    return ti == text.len;
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

test "分类：精确、扩展名、前后缀" {
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

test "glob 不让星号跨过斜杠，双星可以" {
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

test "字符类和取反" {
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

test "J01 后写的 glob 优先且花括号可嵌套并受上限保护" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // 1. 嵌套花括号展开 + 后写的规则优先
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

    // 2. 展开后条数超过上限时拒绝
    try std.testing.expectError(
        error.GlobCountExceeded,
        compileGlobs(arena, &.{"*.{a,{b,{c,d}}}"}, .{ .max_rules = 3 }),
    );

    // 3. 单条长度超过上限时拒绝
    try std.testing.expectError(
        error.GlobTooLong,
        compileGlobs(arena, &.{"abcdef"}, .{ .max_rule_len = 4 }),
    );

    // 4. 花括号嵌套深度超过硬顶时拒绝
    try std.testing.expectError(
        error.GlobBraceDepthExceeded,
        compileGlobs(arena, &.{"{a,{b,{c,{d,{e,{f,{g,{h,{i,j}}}}}}}}}"}, .{}),
    );
}

test "J02 glob 忽略大小写" {
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
