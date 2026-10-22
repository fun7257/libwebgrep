//! 字节 glob。`*` 和 `?` 不跨 `/`，`**` 只在作为完整路径分量时跨目录。
//! 字符类支持区间和 `!` / `^` 取反。路径按字节比较，不假定 UTF-8。

const std = @import("std");

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
};

/// 按元字符给模式分类。`key` 指向 `text` 里的字面量部分。
pub fn classify(text: []const u8) Glob {
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
    };
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
    return switch (glob.class) {
        .exact => std.mem.eql(u8, hay, glob.key),
        .ext, .suffix => hay.len >= glob.key.len and std.mem.endsWith(u8, hay, glob.key),
        .prefix => std.mem.startsWith(u8, hay, glob.key),
        .general => matchText(glob.text, hay),
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
    return matchFrom(pattern, text);
}

fn matchFrom(pat: []const u8, text: []const u8) bool {
    var pi: usize = 0;
    var ti: usize = 0;
    while (pi < pat.len) {
        if (isDoubleStar(pat, pi)) {
            var rest = pi + 2;
            if (rest < pat.len and pat[rest] == '/') rest += 1;
            if (rest == pat.len) return true;
            var k = ti;
            while (true) {
                if (matchFrom(pat[rest..], text[k..])) return true;
                if (k >= text.len) return false;
                k += 1;
            }
        }
        if (pat[pi] == '*') {
            pi += 1;
            var k = ti;
            while (true) {
                if (matchFrom(pat[pi..], text[k..])) return true;
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
            if (!classMatch(pat[pi + 1 .. close], text[ti])) return false;
            pi = close + 1;
            ti += 1;
            continue;
        }
        if (pat[pi] != text[ti]) return false;
        pi += 1;
        ti += 1;
    }
    return ti == text.len;
}

fn classMatch(spec: []const u8, byte: u8) bool {
    if (byte == '/' or spec.len == 0) return false;
    var neg = false;
    var i: usize = 0;
    if (spec[0] == '!' or spec[0] == '^') {
        neg = true;
        i = 1;
    }
    var ok = false;
    while (i < spec.len) : (i += 1) {
        if (i + 2 < spec.len and spec[i + 1] == '-') {
            const lo = spec[i];
            const hi = spec[i + 2];
            if (byte >= lo and byte <= hi) ok = true;
            i += 2;
            continue;
        }
        if (spec[i] == byte) ok = true;
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
