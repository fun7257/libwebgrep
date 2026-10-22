//! gitignore 子集。
//!
//! 支持注释、行首转义、`!`、尾部 `/`、锚定 `/`、不跨 `/` 的 `*` 和 `?`、
//! `**/`、字符类。同一份规则里后写的胜出。调用方把更深层的集合链在父集合后面，
//! 所以深层覆盖浅层。父目录一旦被忽略，里面的文件不再被重新包含。
//!
//! 不读全局 `core.excludesFile`。`.git/info/exclude` 由遍历层放进最外层集合。

const std = @import("std");
const glob = @import("glob.zig");

pub const Affix = struct {
    text: []const u8,
    index: u32,
};

/// 某一层目录的规则。建好之后只读，worker 可以共享。
pub const Set = struct {
    parent: ?*const Set = null,
    /// 这一层目录在搜索根相对路径里的字节长度。根目录是 0。
    prefix: usize = 0,
    /// 仓库根在搜索根之上时，exclude 规则要先加上这段路径。
    repo_prefix: []const u8 = &.{},
    globs: []const glob.Glob = &.{},
    exact: std.StringHashMapUnmanaged([]const u32) = .empty,
    exts: std.StringHashMapUnmanaged([]const u32) = .empty,
    prefixes: []const Affix = &.{},
    suffixes: []const Affix = &.{},
    general: []const u32 = &.{},
};

/// 把一份忽略文件追加成 glob。`text` 会复制进 `allocator`。
pub fn parseInto(allocator: std.mem.Allocator, text: []const u8, out: *std.ArrayList(glob.Glob)) !void {
    var line_start: usize = 0;
    while (line_start <= text.len) {
        const line_end = std.mem.indexOfScalarPos(u8, text, line_start, '\n') orelse text.len;
        var line = text[line_start..line_end];
        if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
        if (try parseLine(allocator, line)) |item| try out.append(allocator, item);
        if (line_end == text.len) break;
        line_start = line_end + 1;
    }
}

/// 解析一行。空行和注释返回 null。
pub fn parseLine(allocator: std.mem.Allocator, line: []const u8) !?glob.Glob {
    const trimmed = stripTrailingSpace(line);
    if (trimmed.len == 0 or trimmed[0] == '#') return null;

    var body = trimmed;
    var negated = false;
    if (body[0] == '!') {
        negated = true;
        body = body[1..];
        if (body.len == 0) return null;
    }

    var raw: std.ArrayList(u8) = .empty;
    errdefer raw.deinit(allocator);
    try unescape(allocator, &raw, body);
    if (raw.items.len == 0) {
        raw.deinit(allocator);
        return null;
    }

    var dir_only = false;
    if (raw.items[raw.items.len - 1] == '/') {
        dir_only = true;
        raw.items.len -= 1;
        if (raw.items.len == 0) {
            raw.deinit(allocator);
            return null;
        }
    }

    var anchored = false;
    var pattern = raw.items;
    if (pattern[0] == '/') {
        anchored = true;
        pattern = pattern[1..];
    }
    if (std.mem.indexOfScalar(u8, pattern, '/') != null) anchored = true;
    if (pattern.len == 0) {
        raw.deinit(allocator);
        return null;
    }

    const owned = try allocator.dupe(u8, pattern);
    raw.deinit(allocator);
    var item = glob.classify(owned);
    item.anchored = anchored;
    item.dir_only = dir_only;
    item.negated = negated;
    return item;
}

fn stripTrailingSpace(line: []const u8) []const u8 {
    var end = line.len;
    while (end > 0 and line[end - 1] == ' ') {
        var slashes: usize = 0;
        var j = end - 1;
        while (j > 0 and line[j - 1] == '\\') {
            slashes += 1;
            j -= 1;
        }
        if (slashes % 2 == 1) break;
        end -= 1;
    }
    return line[0..end];
}

fn unescape(allocator: std.mem.Allocator, out: *std.ArrayList(u8), body: []const u8) !void {
    var i: usize = 0;
    while (i < body.len) : (i += 1) {
        if (body[i] == '\\' and i + 1 < body.len) {
            i += 1;
            try out.append(allocator, body[i]);
            continue;
        }
        try out.append(allocator, body[i]);
    }
}

/// 用 arena 分配索引。`globs` 的文本必须活得和集合一样久。
pub fn build(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    parent: ?*const Set,
    prefix: usize,
    repo_prefix: []const u8,
    globs: []const glob.Glob,
) !Set {
    var exact_lists: std.StringHashMapUnmanaged(std.ArrayList(u32)) = .empty;
    defer {
        var it = exact_lists.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(gpa);
        exact_lists.deinit(gpa);
    }
    var ext_lists: std.StringHashMapUnmanaged(std.ArrayList(u32)) = .empty;
    defer {
        var it = ext_lists.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(gpa);
        ext_lists.deinit(gpa);
    }
    var prefixes: std.ArrayList(Affix) = .empty;
    defer prefixes.deinit(gpa);
    var suffixes: std.ArrayList(Affix) = .empty;
    defer suffixes.deinit(gpa);
    var general: std.ArrayList(u32) = .empty;
    defer general.deinit(gpa);

    for (globs, 0..) |item, index| {
        const id: u32 = @intCast(index);
        if (item.anchored or item.class == .general) {
            try general.append(gpa, id);
            continue;
        }
        switch (item.class) {
            .exact => try appendIndex(gpa, &exact_lists, item.key, id),
            .ext => try appendIndex(gpa, &ext_lists, item.key, id),
            .prefix => try prefixes.append(gpa, .{ .text = item.key, .index = id }),
            .suffix => try suffixes.append(gpa, .{ .text = item.key, .index = id }),
            .general => try general.append(gpa, id),
        }
    }

    return .{
        .parent = parent,
        .prefix = prefix,
        .repo_prefix = try arena.dupe(u8, repo_prefix),
        .globs = globs,
        .exact = try freeze(arena, gpa, &exact_lists),
        .exts = try freeze(arena, gpa, &ext_lists),
        .prefixes = try arena.dupe(Affix, prefixes.items),
        .suffixes = try arena.dupe(Affix, suffixes.items),
        .general = try arena.dupe(u32, general.items),
    };
}

fn appendIndex(
    gpa: std.mem.Allocator,
    map: *std.StringHashMapUnmanaged(std.ArrayList(u32)),
    key: []const u8,
    index: u32,
) !void {
    const slot = try map.getOrPut(gpa, key);
    if (!slot.found_existing) slot.value_ptr.* = .empty;
    try slot.value_ptr.append(gpa, index);
}

fn freeze(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    map: *std.StringHashMapUnmanaged(std.ArrayList(u32)),
) !std.StringHashMapUnmanaged([]const u32) {
    var out: std.StringHashMapUnmanaged([]const u32) = .empty;
    var it = map.iterator();
    while (it.next()) |entry| {
        const copy = try arena.dupe(u32, entry.value_ptr.items);
        try out.put(arena, entry.key_ptr.*, copy);
    }
    _ = gpa;
    return out;
}

/// 父目录被忽略时，里面的路径也算忽略，后写的 `!` 不能把它救回来。
pub fn isIgnored(set: *const Set, rel: []const u8, is_dir: bool, scratch: []u8) bool {
    if (!is_dir) {
        var end = rel.len;
        while (std.mem.lastIndexOfScalar(u8, rel[0..end], '/')) |slash| {
            if (decide(set, rel[0..slash], true, scratch)) return true;
            end = slash;
        }
    }
    return decide(set, rel, is_dir, scratch);
}

fn decide(set: *const Set, rel: []const u8, is_dir: bool, scratch: []u8) bool {
    var ignored = if (set.parent) |parent| decide(parent, rel, is_dir, scratch) else false;
    const local = view(set, rel, scratch) orelse return ignored;
    if (lastMatch(set, local, is_dir)) |item| ignored = !item.negated;
    return ignored;
}

fn view(set: *const Set, rel: []const u8, scratch: []u8) ?[]const u8 {
    var path = rel;
    if (set.repo_prefix.len != 0) {
        const need = set.repo_prefix.len + 1 + rel.len;
        if (need > scratch.len) return null;
        @memcpy(scratch[0..set.repo_prefix.len], set.repo_prefix);
        scratch[set.repo_prefix.len] = '/';
        @memcpy(scratch[set.repo_prefix.len + 1 .. need], rel);
        path = scratch[0..need];
        if (rel.len == 0) path = scratch[0..set.repo_prefix.len];
    }
    if (set.prefix == 0) return path;
    if (path.len < set.prefix) return null;
    if (path.len == set.prefix) return path[path.len..];
    if (path[set.prefix] != '/') return null;
    return path[set.prefix + 1 ..];
}

fn lastMatch(set: *const Set, local: []const u8, is_dir: bool) ?glob.Glob {
    const base = glob.basename(local);
    var best: ?u32 = null;
    considerGroup(set, set.exact.get(base), is_dir, &best);
    if (extensionOf(base)) |ext| considerGroup(set, set.exts.get(ext), is_dir, &best);
    for (set.prefixes) |item| {
        if (std.mem.startsWith(u8, base, item.text)) considerOne(set, item.index, is_dir, &best);
    }
    for (set.suffixes) |item| {
        if (base.len >= item.text.len and std.mem.endsWith(u8, base, item.text)) {
            considerOne(set, item.index, is_dir, &best);
        }
    }
    for (set.general) |index| {
        if (glob.matches(set.globs[index], local, base, is_dir)) considerOne(set, index, is_dir, &best);
    }
    return if (best) |index| set.globs[index] else null;
}

fn considerGroup(set: *const Set, group: ?[]const u32, is_dir: bool, best: *?u32) void {
    const indexes = group orelse return;
    for (indexes) |index| considerOne(set, index, is_dir, best);
}

fn considerOne(set: *const Set, index: u32, is_dir: bool, best: *?u32) void {
    if (set.globs[index].dir_only and !is_dir) return;
    if (best.*) |old| {
        if (index > old) best.* = index;
    } else best.* = index;
}

fn extensionOf(base: []const u8) ?[]const u8 {
    const dot = std.mem.lastIndexOfScalar(u8, base, '.') orelse return null;
    if (dot == 0) return null;
    return base[dot..];
}

fn parseAll(allocator: std.mem.Allocator, text: []const u8) ![]glob.Glob {
    var list: std.ArrayList(glob.Glob) = .empty;
    try parseInto(allocator, text, &list);
    return list.toOwnedSlice(allocator);
}

test "解析注释、转义、否定和目录" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const globs = try parseAll(arena,
        \\# comment
        \\
        \\\#keep
        \\!foo
        \\build/
        \\/rooted
        \\a/b
        \\*.log
        \\name\ 
    );
    try std.testing.expectEqual(@as(usize, 7), globs.len);
    try std.testing.expectEqualStrings("#keep", globs[0].text);
    try std.testing.expect(globs[1].negated);
    try std.testing.expectEqualStrings("foo", globs[1].text);
    try std.testing.expect(globs[2].dir_only);
    try std.testing.expect(globs[3].anchored);
    try std.testing.expectEqualStrings("rooted", globs[3].text);
    try std.testing.expect(globs[4].anchored);
    try std.testing.expectEqual(glob.Class.ext, globs[5].class);
}

test "后写优先，父目录被忽略后不能重新包含" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const globs = try parseAll(arena,
        \\*
        \\!*/
        \\!keep.txt
        \\sub/
        \\!sub/keep.txt
    );
    const set = try build(arena, std.testing.allocator, null, 0, &.{}, globs);
    var scratch: [256]u8 = undefined;
    try std.testing.expect(isIgnored(&set, "other.txt", false, &scratch));
    try std.testing.expect(!isIgnored(&set, "keep.txt", false, &scratch));
    try std.testing.expect(!isIgnored(&set, "dir", true, &scratch));
    try std.testing.expect(isIgnored(&set, "sub", true, &scratch));
    try std.testing.expect(isIgnored(&set, "sub/keep.txt", false, &scratch));
    try std.testing.expect(isIgnored(&set, "sub/other.txt", false, &scratch));
}

test "深层集合覆盖浅层" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const parent_globs = try parseAll(arena, "*.log\n");
    const child_globs = try parseAll(arena, "!keep.log\n");
    const parent = try build(arena, std.testing.allocator, null, 0, &.{}, parent_globs);
    const child = try build(arena, std.testing.allocator, &parent, 3, &.{}, child_globs);
    var scratch: [256]u8 = undefined;
    try std.testing.expect(isIgnored(&child, "dir/no.log", false, &scratch));
    try std.testing.expect(!isIgnored(&child, "dir/keep.log", false, &scratch));
    try std.testing.expect(isIgnored(&parent, "dir/keep.log", false, &scratch));
}
