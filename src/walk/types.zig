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
    return findInTable(&.{}, name);
}

/// 先在调用方注入的 `table` 中按后写优先查找，未找到则回退至 `builtin`。
pub fn findInTable(table: []const Type, name: []const u8) ?Type {
    var i: usize = table.len;
    while (i > 0) {
        i -= 1;
        if (std.mem.eql(u8, table[i].name, name)) return table[i];
    }
    for (builtin) |item| {
        if (std.mem.eql(u8, item.name, name)) return item;
    }
    return null;
}

/// 将调用方选择与排除的类型名（结合注入的 `table` 与 `builtin`）展开为 `glob.Glob` 切片。
pub fn expandTypesToGlobs(
    arena: std.mem.Allocator,
    table: []const Type,
    include: []const []const u8,
    exclude: []const []const u8,
) glob.GlobError![]glob.Glob {
    var raw_list: std.ArrayList([]const u8) = .empty;
    defer raw_list.deinit(arena);

    for (include) |name| {
        const item = findInTable(table, name) orelse continue;
        for (item.patterns) |pat| {
            if (raw_list.items.len >= glob.rule_count_hard_cap) return error.GlobCountExceeded;
            try raw_list.append(arena, pat);
        }
    }
    for (exclude) |name| {
        const item = findInTable(table, name) orelse continue;
        for (item.patterns) |pat| {
            if (raw_list.items.len >= glob.rule_count_hard_cap) return error.GlobCountExceeded;
            const neg = try std.fmt.allocPrint(arena, "!{s}", .{pat});
            try raw_list.append(arena, neg);
        }
    }
    return glob.compileGlobs(arena, raw_list.items, .{});
}

/// `selected` 为空表示不过滤正向类型；命中任一 `excluded` 类型则直接拒绝。
pub fn matchesWithTable(
    table: []const Type,
    selected: []const []const u8,
    excluded: []const []const u8,
    base: []const u8,
) bool {
    for (excluded) |name| {
        const item = findInTable(table, name) orelse continue;
        for (item.patterns) |pattern| {
            var compiled = glob.classify(pattern);
            compiled.anchored = false;
            if (glob.matches(compiled, base, base, false)) return false;
        }
    }
    if (selected.len == 0) return true;
    for (selected) |name| {
        const item = findInTable(table, name) orelse continue;
        for (item.patterns) |pattern| {
            var compiled = glob.classify(pattern);
            compiled.anchored = false;
            if (glob.matches(compiled, base, base, false)) return true;
        }
    }
    return false;
}

/// `selected` 为空表示不过滤。否则文件名只要命中其中一个类型即可。
pub fn matches(selected: []const []const u8, base: []const u8) bool {
    return matchesWithTable(&.{}, selected, &.{}, base);
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

test "J12 调用方注入类型表展开为 glob 与排除过滤" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const custom = [_]Type{
        .{ .name = "proto", .patterns = &.{ "*.proto", "*.{pb.go,pb.cc}" } },
    };
    const expanded = try expandTypesToGlobs(arena, &custom, &.{ "proto", "zig" }, &.{"c"});
    try std.testing.expect(glob.matchGlobs(expanded, "api.proto", "api.proto", false));
    try std.testing.expect(glob.matchGlobs(expanded, "api.pb.go", "api.pb.go", false));
    try std.testing.expect(glob.matchGlobs(expanded, "main.zig", "main.zig", false));
    try std.testing.expect(!glob.matchGlobs(expanded, "legacy.c", "legacy.c", false));
    try std.testing.expect(!glob.matchGlobs(expanded, "readme.md", "readme.md", false));

    try std.testing.expect(matchesWithTable(&custom, &.{"proto"}, &.{"go"}, "api.proto"));
    try std.testing.expect(!matchesWithTable(&custom, &.{"proto"}, &.{"go"}, "api.pb.go"));
}
