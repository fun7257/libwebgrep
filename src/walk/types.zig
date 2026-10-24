//! File filtering by extension and a small set of fixed filenames. Names align with ripgrep's `-t` for common file types.
//! Patterns reuse glob matching: when no slash is present, they match against the final filename segment.

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

/// Searches the caller-supplied `table` in reverse (last-defined wins) before falling back to `builtin`.
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

/// Expands caller-selected and excluded type names (combining `table` and `builtin`) into a slice of `glob.Glob`.
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

/// An empty `selected` slice applies no positive type filter; matching any `excluded` type rejects the file immediately.
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

/// An empty `selected` slice applies no filter. Otherwise, the filename matches if it hits at least one selected type.
pub fn matches(selected: []const []const u8, base: []const u8) bool {
    return matchesWithTable(&.{}, selected, &.{}, base);
}

test "type table recognizes zig and Makefile" {
    try std.testing.expect(find("zig") != null);
    try std.testing.expect(find("nope") == null);
    try std.testing.expect(matches(&.{"zig"}, "main.zig"));
    try std.testing.expect(!matches(&.{"zig"}, "main.txt"));
    try std.testing.expect(matches(&.{"make"}, "Makefile"));
    try std.testing.expect(matches(&.{ "zig", "txt" }, "a.txt"));
    try std.testing.expect(matches(&.{}, "anything"));
}

test "caller-supplied type table expands to globs and filters exclusions" {
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
