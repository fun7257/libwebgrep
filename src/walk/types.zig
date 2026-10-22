//! 按扩展名和少量固定文件名过滤。名字对齐 ripgrep 的 `-t`，只收了常用的一组。
//! 模式复用 glob：没有斜杠时对最后一段文件名匹配。

const std = @import("std");
const glob = @import("glob.zig");

pub const Type = struct {
    name: []const u8,
    patterns: []const []const u8,
};

pub const builtin = [_]Type{
    .{ .name = "asm", .patterns = &.{ "*.S", "*.asm", "*.s" } },
    .{ .name = "c", .patterns = &.{ "*.c", "*.h", "*.C", "*.H" } },
    .{ .name = "cmake", .patterns = &.{ "*.cmake", "CMakeLists.txt" } },
    .{ .name = "cpp", .patterns = &.{ "*.cc", "*.cpp", "*.cxx", "*.hh", "*.hpp", "*.hxx" } },
    .{ .name = "css", .patterns = &.{ "*.css", "*.scss" } },
    .{ .name = "go", .patterns = &.{"*.go"} },
    .{ .name = "html", .patterns = &.{ "*.htm", "*.html" } },
    .{ .name = "java", .patterns = &.{"*.java"} },
    .{ .name = "js", .patterns = &.{ "*.cjs", "*.js", "*.jsx", "*.mjs" } },
    .{ .name = "json", .patterns = &.{"*.json"} },
    .{ .name = "make", .patterns = &.{ "[Mm]akefile", "*.mk" } },
    .{ .name = "markdown", .patterns = &.{ "*.md", "*.markdown" } },
    .{ .name = "md", .patterns = &.{ "*.md", "*.markdown" } },
    .{ .name = "py", .patterns = &.{ "*.py", "*.pyi" } },
    .{ .name = "python", .patterns = &.{ "*.py", "*.pyi" } },
    .{ .name = "rust", .patterns = &.{"*.rs"} },
    .{ .name = "sh", .patterns = &.{ "*.sh", "*.bash", "*.zsh" } },
    .{ .name = "toml", .patterns = &.{"*.toml"} },
    .{ .name = "ts", .patterns = &.{ "*.ts", "*.tsx" } },
    .{ .name = "typescript", .patterns = &.{ "*.ts", "*.tsx" } },
    .{ .name = "txt", .patterns = &.{"*.txt"} },
    .{ .name = "yaml", .patterns = &.{ "*.yaml", "*.yml" } },
    .{ .name = "zig", .patterns = &.{"*.zig"} },
};

pub fn find(name: []const u8) ?Type {
    for (builtin) |item| {
        if (std.mem.eql(u8, item.name, name)) return item;
    }
    return null;
}

/// `selected` 为空表示不过滤。否则文件名只要命中其中一个类型即可。
pub fn matches(selected: []const []const u8, base: []const u8) bool {
    if (selected.len == 0) return true;
    for (selected) |name| {
        const item = find(name) orelse continue;
        for (item.patterns) |pattern| {
            var compiled = glob.classify(pattern);
            compiled.anchored = false;
            if (glob.matches(compiled, base, base, false)) return true;
        }
    }
    return false;
}

test "类型表能认出 zig 和 Makefile" {
    try std.testing.expect(find("zig") != null);
    try std.testing.expect(find("nope") == null);
    try std.testing.expect(matches(&.{"zig"}, "main.zig"));
    try std.testing.expect(!matches(&.{"zig"}, "main.txt"));
    try std.testing.expect(matches(&.{"make"}, "Makefile"));
    try std.testing.expect(matches(&.{ "zig", "txt" }, "a.txt"));
    try std.testing.expect(matches(&.{}, "anything"));
}
