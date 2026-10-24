//! Subset of gitignore rule matching.
//!
//! Supports comments, leading-character escaping, `!` negation, trailing `/`, anchored `/`,
//! non-slash-crossing `*` and `?`, `**/`, and character classes. Within the same rule set,
//! later rules win. Callers chain deeper sets behind parent sets so child directories override
//! ancestor rules. Once a parent directory is ignored, files inside it cannot be re-included.
//!
//! Rule text is supplied directly by the caller; neither the process environment nor parent
//! directories above the root are consulted for ignore files.

const std = @import("std");
const glob = @import("glob.zig");

pub const Affix = struct {
    text: []const u8,
    index: u32,
};

/// Rules for a single directory level. Read-only once built and safe to share across workers.
pub const Set = struct {
    parent: ?*const Set = null,
    /// Byte length of this directory's path relative to the search root (0 for the root itself).
    prefix: usize = 0,
    /// Path prefix prepended before matching rules. Empty means relative to this directory level.
    repo_prefix: []const u8 = &.{},
    globs: []const glob.Glob = &.{},
    exact: std.StringHashMapUnmanaged([]const u32) = .empty,
    exts: std.StringHashMapUnmanaged([]const u32) = .empty,
    prefixes: []const Affix = &.{},
    suffixes: []const Affix = &.{},
    general: []const u32 = &.{},
};

pub const ParseOptions = struct {
    case_insensitive: bool = false,
    max_rules: ?usize = null,
};

pub const LayerFiles = struct {
    git_exclude: ?[]const u8 = null,
    gitignore: ?[]const u8 = null,
    ignore: ?[]const u8 = null,
    rgignore: ?[]const u8 = null,
};

pub const LayerSwitch = struct {
    /// Whether to enable `.ignore` and `.rgignore`.
    dot: bool = true,
    /// Whether to enable `.gitignore`.
    vcs: bool = true,
    /// Whether to enable repository-local `.git/info/exclude`.
    exclude: bool = true,
    /// Whether ignore rules match ASCII case-insensitively.
    case_insensitive: bool = false,
    /// Maximum number of rules parsed per call (bounded by the hard cap).
    max_rules: ?usize = null,
};

/// Parses an ignore file and appends its globs. `text` is duplicated into `allocator`.
pub fn parseInto(allocator: std.mem.Allocator, text: []const u8, out: *std.ArrayList(glob.Glob)) !void {
    return parseIntoWithOptions(allocator, text, out, .{});
}

/// Parses ignore rule text with options and appends to `out`, enforcing the rule count cap.
pub fn parseIntoWithOptions(
    allocator: std.mem.Allocator,
    text: []const u8,
    out: *std.ArrayList(glob.Glob),
    options: ParseOptions,
) !void {
    const cap = if (options.max_rules) |m| @min(m, glob.rule_count_hard_cap) else glob.rule_count_hard_cap;
    var line_start: usize = 0;
    while (line_start <= text.len) {
        const line_end = std.mem.indexOfScalarPos(u8, text, line_start, '\n') orelse text.len;
        var line = text[line_start..line_end];
        if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
        if (try parseLineWithOptions(allocator, line, options.case_insensitive)) |item| {
            if (out.items.len >= cap) return error.GlobCountExceeded;
            try out.append(allocator, item);
        }
        if (line_end == text.len) break;
        line_start = line_end + 1;
    }
}

/// Parses multiple caller-supplied plain-text ignore rule blocks (does not accept file paths).
pub fn parseTextsInto(
    allocator: std.mem.Allocator,
    texts: []const []const u8,
    out: *std.ArrayList(glob.Glob),
    options: ParseOptions,
) !void {
    for (texts) |text| {
        try parseIntoWithOptions(allocator, text, out, options);
    }
}

/// Parses ignore texts for a single directory level in priority order (`git_exclude` < `.gitignore` < `.ignore` < `.rgignore`) according to `switches`.
pub fn parseLayerInto(
    allocator: std.mem.Allocator,
    files: LayerFiles,
    switches: LayerSwitch,
    out: *std.ArrayList(glob.Glob),
) !void {
    const opts = ParseOptions{
        .case_insensitive = switches.case_insensitive,
        .max_rules = switches.max_rules,
    };
    if (switches.exclude) {
        if (files.git_exclude) |bytes| try parseIntoWithOptions(allocator, bytes, out, opts);
    }
    if (switches.vcs) {
        if (files.gitignore) |bytes| try parseIntoWithOptions(allocator, bytes, out, opts);
    }
    if (switches.dot) {
        if (files.ignore) |bytes| try parseIntoWithOptions(allocator, bytes, out, opts);
        if (files.rgignore) |bytes| try parseIntoWithOptions(allocator, bytes, out, opts);
    }
}

/// Parses a single line. Empty lines and comments return null.
pub fn parseLine(allocator: std.mem.Allocator, line: []const u8) !?glob.Glob {
    return parseLineWithOptions(allocator, line, false);
}

/// Parses a single line with optional ASCII case-insensitivity.
pub fn parseLineWithOptions(
    allocator: std.mem.Allocator,
    line: []const u8,
    case_insensitive: bool,
) !?glob.Glob {
    if (line.len > glob.rule_len_hard_cap) return error.GlobTooLong;
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
    var item = glob.classifyWithCase(owned, case_insensitive);
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

/// Allocates the rule index in `arena`. The pattern strings in `globs` must outlive the returned `Set`.
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
        if (item.anchored or item.case_insensitive or item.class == .general) {
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

/// If any parent directory is ignored, paths inside it are also ignored and cannot be re-included by a later `!` rule.
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

test "parse comments, escapes, negation, and directory-only rules" {
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

test "later rules win and ignored parent directories cannot be re-included" {
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

test "deeper rule sets override shallower ones" {
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

test "plain-text ignore rules and per-layer switches" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // 1. Injected plain-text ignore rules (later blocks override earlier ones, supporting case-insensitive matching)
    var injected: std.ArrayList(glob.Glob) = .empty;
    try parseTextsInto(
        arena,
        &.{ "*.TMP\nsecret.txt\n", "!keep.tmp\n" },
        &injected,
        .{ .case_insensitive = true },
    );
    const injected_set = try build(arena, std.testing.allocator, null, 0, &.{}, injected.items);
    var scratch: [256]u8 = undefined;
    try std.testing.expect(isIgnored(&injected_set, "cache.tmp", false, &scratch));
    try std.testing.expect(!isIgnored(&injected_set, "KEEP.TMP", false, &scratch));
    try std.testing.expect(isIgnored(&injected_set, "SECRET.TXT", false, &scratch));

    // 2. Layer file precedence (git_exclude < .gitignore < .ignore < .rgignore) and fine-grained switches
    const files = LayerFiles{
        .git_exclude = "*.bak\n",
        .gitignore = "*.log\n",
        .ignore = "!app.log\n*.out\n",
        .rgignore = "!final.out\n",
    };

    var all_globs: std.ArrayList(glob.Glob) = .empty;
    try parseLayerInto(arena, files, .{}, &all_globs);
    const full_set = try build(arena, std.testing.allocator, null, 0, &.{}, all_globs.items);
    try std.testing.expect(isIgnored(&full_set, "a.bak", false, &scratch));
    try std.testing.expect(isIgnored(&full_set, "debug.log", false, &scratch));
    try std.testing.expect(!isIgnored(&full_set, "app.log", false, &scratch));
    try std.testing.expect(isIgnored(&full_set, "temp.out", false, &scratch));
    try std.testing.expect(!isIgnored(&full_set, "final.out", false, &scratch));

    // Disable vcs and exclude, keeping only dot (.ignore / .rgignore)
    var dot_only_globs: std.ArrayList(glob.Glob) = .empty;
    try parseLayerInto(arena, files, .{ .vcs = false, .exclude = false, .dot = true }, &dot_only_globs);
    const dot_set = try build(arena, std.testing.allocator, null, 0, &.{}, dot_only_globs.items);
    try std.testing.expect(!isIgnored(&dot_set, "a.bak", false, &scratch));
    try std.testing.expect(!isIgnored(&dot_set, "debug.log", false, &scratch));
    try std.testing.expect(isIgnored(&dot_set, "temp.out", false, &scratch));
    try std.testing.expect(!isIgnored(&dot_set, "final.out", false, &scratch));
}
