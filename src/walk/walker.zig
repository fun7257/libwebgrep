//! Directory traversal. Ignore rules are chained on an immutable parent list, and discovered subdirectories are pushed to the caller's queue.
//! Filesystem access goes directly through `std.Io.Dir`, bypassing the vtable in `source.zig`.
//!
//! Hidden files and `.git` are skipped by default. Symbolic links are skipped by default and may be opted into via `Config.follow_symlinks` with ancestor `(dev, ino)` cycle detection. Paths are concatenated byte-by-byte without assuming UTF-8.

const builtin = @import("builtin");
const std = @import("std");
const file_id = @import("file_id.zig");
const glob = @import("glob.zig");
const ignore = @import("ignore.zig");
const list_dir = @import("list_dir.zig");
const types = @import("types.zig");

pub const SortBy = enum {
    none,
    path,
    path_reverse,
};

pub const ScopedIgnore = struct {
    /// Path prefix relative to the directory where `text` lives (empty means relative to the search root).
    repo_prefix: []const u8 = "",
    /// Plain-text ignore rules (file paths are not accepted).
    text: []const u8,
};

pub const AncestorNode = struct {
    parent: ?*const AncestorNode = null,
    id: file_id.Id,
};

pub const Config = struct {
    /// Fixed server-side hard cap on maximum traversal depth.
    pub const max_depth_hard_cap: u32 = 64;
    /// Fixed server-side hard cap on the number of visited source entries.
    pub const max_entries_hard_cap: u64 = 100_000;

    hidden: bool = false,
    read_ignore: bool = true,
    /// Fine-grained ignore switches: dot (`.ignore`/`.rgignore`), vcs (`.gitignore`), repository-local info exclude, and case sensitivity.
    ignore_switches: ignore.LayerSwitch = .{},
    /// Caller-supplied plain-text ignore rules (file paths are not accepted).
    ignore_texts: []const []const u8 = &.{},
    /// Caller-supplied scoped plain-text ignore layers (chained outermost-first before `ignore_texts`).
    scoped_ignores: []const ScopedIgnore = &.{},
    /// Null defaults to `max_depth_hard_cap`. 1 visits only files in the starting directory; 0 lists nothing.
    max_depth: ?u32 = null,
    /// Maximum budget of file source entries visited during traversal, bounded by `max_entries_hard_cap`.
    max_entries: ?u64 = null,
    /// Shares the same value as the per-source scan byte limit. Files larger than this are skipped during traversal. Null disables size pre-skipping at this layer.
    max_filesize: ?u64 = null,
    globs: []const []const u8 = &.{},
    /// Glob rules matched ASCII case-insensitively.
    iglobs: []const []const u8 = &.{},
    /// Whether `globs` should also be matched ASCII case-insensitively.
    iglob: bool = false,
    types: []const []const u8 = &.{},
    /// Excluded file type names.
    types_not: []const []const u8 = &.{},
    /// Caller-supplied custom file type table.
    custom_types: []const types.Type = &.{},
    /// Worker thread count, determined by the caller's `max_concurrency` or explicit configuration (0 means single-threaded 1; host CPU core count is never probed).
    threads: u32 = 0,
    skip_git: bool = true,
    /// By default, directories on a different device than the search root are not entered. Callers may disable this.
    one_file_system: bool = true,
    /// Opt-in symbolic link traversal with lock-free ancestor `(dev, ino)` cycle detection. Disabled by default.
    follow_symlinks: bool = false,
    /// When true, leaf files are visited inline on the directory worker (avoiding per-file heap jobs) while subdirectories still fan out.
    inline_files: bool = false,
    /// Deterministic entry ordering. When non-`.none`, entries are sorted by name and processed inline in pre-order DFS.
    sort_by: SortBy = .none,
    /// Maximum byte limit for reading ignore files (.gitignore, .ignore, etc.). Defaults to 1 MiB.
    max_ignore_file_bytes: usize = 1024 * 1024,
    /// Maximum glob rules parsed. Null uses glob default.
    max_glob_rules: ?usize = null,
    /// Maximum length of a single glob rule. Null uses glob default.
    max_glob_rule_len: ?usize = null,
    /// Maximum nested brace depth in globs. Null uses glob default.
    max_glob_brace_depth: ?usize = null,

    pub fn effectiveMaxDepth(self: Config) u32 {
        return self.max_depth orelse max_depth_hard_cap;
    }

    pub fn effectiveMaxEntries(self: Config) u64 {
        return self.max_entries orelse max_entries_hard_cap;
    }
};

pub const Control = enum { cont, stop };

pub const Visit = struct {
    /// Valid only for the duration of this callback.
    path: []const u8,
    dir: std.Io.Dir,
    name: []const u8,
    size: u64,
};

pub const Host = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    config: Config,
    session: *Session,
    stop: *std.atomic.Value(bool),
    /// Optional count of currently parked workers; when non-null and zero, leaf files are visited
    /// inline on the current worker without duplicating directory fds or allocating per-file jobs.
    idle: ?*const std.atomic.Value(u32) = null,
    push: *const fn (*anyopaque, *Job) anyerror!void,
    push_ctx: *anyopaque,
    on_file: *const fn (*anyopaque, Visit) anyerror!Control,
    file_ctx: *anyopaque,
    on_error: *const fn (*anyopaque, []const u8, anyerror) void,
    error_ctx: *anyopaque,
};

pub const Job = struct {
    /// Open directory handle when already opened (root jobs), or `null` for deferred jobs opened on demand
    /// when a worker executes the job (preventing fd-table growth / `expand_files` RCU stalls).
    dir: ?std.Io.Dir = null,
    /// Root path passed by the caller; must remain valid throughout traversal.
    root: []const u8,
    rel: []u8,
    ignore: *const ignore.Set,
    depth: u32,
    /// Device ID of this directory (or parent directory when `dir == null`). 0 means unavailable.
    dev: u64 = 0,
    /// Immutable ancestor `(dev, ino)` chain for cycle detection when `follow_symlinks` is enabled.
    ancestors: ?*const AncestorNode = null,
    allocator: std.mem.Allocator,
    /// When non-null, this job visits only these filenames without listing the directory. Names are freed by this job.
    files: ?[][]u8 = null,

    pub fn destroy(self: *Job, io: std.Io) void {
        if (self.files) |names| {
            for (names) |name| self.allocator.free(name);
            self.allocator.free(names);
        }
        if (self.dir) |d| d.close(io);
        self.allocator.free(self.rel);
        self.allocator.destroy(self);
    }
};

pub const Session = struct {
    arena: std.heap.ArenaAllocator,
    lock: std.Io.Mutex = .init,
    gpa: std.mem.Allocator,
    empty: ignore.Set = .{},
    base_ignore: ?*const ignore.Set = null,
    user_globs: []const glob.Glob = &.{},
    type_includes: []const glob.Glob = &.{},
    type_excludes: []const glob.Glob = &.{},
    has_type_includes: bool = false,
    globs_prepared: bool = false,
    types_prepared: bool = false,
    ignore_prepared: bool = false,
    entries_visited: std.atomic.Value(u64) = .init(0),

    pub fn init(gpa: std.mem.Allocator) Session {
        return .{
            .arena = std.heap.ArenaAllocator.init(gpa),
            .gpa = gpa,
        };
    }

    pub fn deinit(self: *Session) void {
        self.arena.deinit();
    }

    pub fn prepareConfig(self: *Session, io: std.Io, config: Config) !void {
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);
        const arena = self.arena.allocator();
        if (!self.globs_prepared and (config.globs.len > 0 or config.iglobs.len > 0)) {
            var list: std.ArrayList(glob.Glob) = .empty;
            const max_rules = config.max_glob_rules orelse glob.rule_count_hard_cap;
            const max_len = config.max_glob_rule_len;
            const max_brace = config.max_glob_brace_depth;
            if (config.globs.len > 0) {
                const compiled = try glob.compileGlobs(arena, config.globs, .{
                    .case_insensitive = config.iglob,
                    .max_rules = max_rules,
                    .max_rule_len = max_len,
                    .max_brace_depth = max_brace,
                });
                try list.appendSlice(arena, compiled);
            }
            if (config.iglobs.len > 0) {
                if (list.items.len >= max_rules) return error.GlobCountExceeded;
                const remain = max_rules - list.items.len;
                const compiled_i = try glob.compileGlobs(arena, config.iglobs, .{
                    .case_insensitive = true,
                    .max_rules = remain,
                    .max_rule_len = max_len,
                    .max_brace_depth = max_brace,
                });
                try list.appendSlice(arena, compiled_i);
            }
            self.user_globs = try list.toOwnedSlice(arena);
            self.globs_prepared = true;
        }
        if (!self.types_prepared and (config.types.len > 0 or config.types_not.len > 0)) {
            const type_opts = glob.CompileOptions{
                .max_rules = config.max_glob_rules,
                .max_rule_len = config.max_glob_rule_len,
                .max_brace_depth = config.max_glob_brace_depth,
            };
            self.has_type_includes = config.types.len > 0;
            if (config.types.len > 0) {
                const inc = try types.expandTypesToGlobsWithOptions(
                    arena,
                    config.custom_types,
                    config.types,
                    &.{},
                    type_opts,
                );
                for (inc) |*g| g.anchored = false;
                self.type_includes = inc;
            }
            if (config.types_not.len > 0) {
                const exc = try types.expandTypesToGlobsWithOptions(
                    arena,
                    config.custom_types,
                    config.types_not,
                    &.{},
                    type_opts,
                );
                for (exc) |*g| g.anchored = false;
                self.type_excludes = exc;
            }
            self.types_prepared = true;
        }
        if (!self.ignore_prepared and (config.scoped_ignores.len > 0 or config.ignore_texts.len > 0)) {
            const parse_opts = ignore.ParseOptions{
                .case_insensitive = config.ignore_switches.case_insensitive,
                .max_rules = config.max_glob_rules orelse config.ignore_switches.max_rules,
                .max_rule_len = config.max_glob_rule_len orelse config.ignore_switches.max_rule_len,
                .max_brace_depth = config.max_glob_brace_depth orelse config.ignore_switches.max_brace_depth,
            };
            var cur_parent: ?*const ignore.Set = null;
            for (config.scoped_ignores) |layer| {
                if (layer.text.len == 0) continue;
                var layer_list: std.ArrayList(glob.Glob) = .empty;
                try ignore.parseIntoWithOptions(arena, layer.text, &layer_list, parse_opts);
                if (layer_list.items.len == 0) continue;
                const owned = try layer_list.toOwnedSlice(arena);
                const set = try arena.create(ignore.Set);
                set.* = try ignore.build(arena, self.gpa, cur_parent, 0, layer.repo_prefix, owned);
                cur_parent = set;
            }
            if (config.ignore_texts.len > 0) {
                var ig_list: std.ArrayList(glob.Glob) = .empty;
                try ignore.parseTextsInto(arena, config.ignore_texts, &ig_list, parse_opts);
                if (ig_list.items.len > 0) {
                    const owned = try ig_list.toOwnedSlice(arena);
                    const set = try arena.create(ignore.Set);
                    set.* = try ignore.build(arena, self.gpa, cur_parent, 0, &.{}, owned);
                    cur_parent = set;
                }
            }
            self.base_ignore = cur_parent;
            self.ignore_prepared = true;
        }
    }
};

fn openRoot(io: std.Io, path: []const u8, follow: bool) !std.Io.Dir {
    const options = withLinkResolve(std.Io.Dir.OpenOptions{ .iterate = true }, follow);
    if (std.Io.Dir.path.isAbsolute(path)) return std.Io.Dir.openDirAbsolute(io, path, options);
    return std.Io.Dir.cwd().openDir(io, path, options);
}

/// Opens a search root without reading ignore rules above it. The caller pushes the returned job into the queue.
pub fn createRoot(host: *Host, root_path: []const u8) !*Job {
    try host.session.prepareConfig(host.io, host.config);
    const shown = trimSlash(root_path);
    const dir = try openRoot(host.io, shown, host.config.follow_symlinks);
    errdefer dir.close(host.io);
    const root_id: ?file_id.Id = if (host.config.one_file_system or host.config.follow_symlinks)
        (file_id.fromDir(dir) catch null)
    else
        null;
    const dev: u64 = if (host.config.one_file_system) (if (root_id) |id| id.dev else 0) else 0;
    var ancestors: ?*const AncestorNode = null;
    if (host.config.follow_symlinks) {
        if (root_id) |id| {
            if (id.dev != 0 or id.ino != 0) {
                ancestors = try allocAncestor(host, null, id);
            }
        }
    }
    const base = host.session.base_ignore orelse &host.session.empty;
    return createJobWithDev(host, dir, shown, "", base, 1, dev, ancestors);
}

/// Sets the `*symlinks` boolean flag on `std.Io.Dir` open/stat option structs according to `follow`.
fn withLinkResolve(options: anytype, follow: bool) @TypeOf(options) {
    var out = options;
    const info = @typeInfo(@TypeOf(options)).@"struct";
    comptime var found = false;
    inline for (info.field_names, info.field_types) |field_name, field_type| {
        if (comptime field_type == bool and std.mem.endsWith(u8, field_name, "symlinks")) {
            found = true;
            @field(out, field_name) = follow;
        }
    }
    if (comptime !found) @compileError("directory options lack a boolean flag to control symlink resolution");
    return out;
}

fn allocAncestor(host: *Host, parent: ?*const AncestorNode, id: file_id.Id) !*const AncestorNode {
    host.session.lock.lockUncancelable(host.io);
    defer host.session.lock.unlock(host.io);
    const node = try host.session.arena.allocator().create(AncestorNode);
    node.* = .{ .parent = parent, .id = id };
    return node;
}

fn hasAncestor(ancestors: ?*const AncestorNode, id: file_id.Id) bool {
    var cur = ancestors;
    while (cur) |node| {
        if (node.id.eql(id)) return true;
        cur = node.parent;
    }
    return false;
}

fn openJobDir(host: *Host, job: *const Job) !std.Io.Dir {
    const follow = host.config.follow_symlinks;
    if (job.rel.len == 0) return openRoot(host.io, job.root, follow);
    if (job.root.len == 0) return openRoot(host.io, job.rel, follow);
    var stack_path: [std.Io.Dir.max_path_bytes]u8 = undefined;
    if (job.root.len + 1 + job.rel.len <= stack_path.len) {
        @memcpy(stack_path[0..job.root.len], job.root);
        stack_path[job.root.len] = '/';
        @memcpy(stack_path[job.root.len + 1 ..][0..job.rel.len], job.rel);
        return openRoot(host.io, stack_path[0 .. job.root.len + 1 + job.rel.len], follow);
    }
    const heap_path = try displayPath(host.allocator, job.root, job.rel);
    defer host.allocator.free(heap_path);
    return openRoot(host.io, heap_path, follow);
}

const DirContext = struct {
    dir_id: file_id.Id = .{ .dev = 0, .ino = 0 },
    child_ancestors: ?*const AncestorNode = null,
    need_child_ancestor: bool = false,

    fn ensureChildAncestors(self: *DirContext, host: *Host, job: *Job) !?*const AncestorNode {
        if (self.need_child_ancestor) {
            self.child_ancestors = try allocAncestor(host, job.ancestors, self.dir_id);
            self.need_child_ancestor = false;
        }
        return self.child_ancestors;
    }
};

pub fn process(host: *Host, job: *Job) void {
    defer job.destroy(host.io);
    if (host.stop.load(.acquire)) return;

    if (job.files) |names| {
        const dir = job.dir orelse (openJobDir(host, job) catch |err| {
            report(host, job, "", err);
            return;
        });
        defer if (job.dir == null) dir.close(host.io);
        for (names) |name| {
            if (host.stop.load(.acquire)) return;
            var rel_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const rel = joinRel(&rel_buf, job.rel, name) catch {
                report(host, job, name, error.NameTooLong);
                continue;
            };
            visitCheckedFile(host, job, dir, name, rel, null);
        }
        return;
    }

    if (job.depth > host.config.effectiveMaxDepth()) return;

    const dir = job.dir orelse (openJobDir(host, job) catch |err| {
        report(host, job, "", err);
        return;
    });
    defer if (job.dir == null) dir.close(host.io);

    var dir_ctx = DirContext{
        .child_ancestors = job.ancestors,
    };
    if (job.dir == null) {
        if (host.config.one_file_system or host.config.follow_symlinks) {
            if (file_id.fromDir(dir)) |id| {
                dir_ctx.dir_id = id;
                if (host.config.one_file_system and job.dev != 0 and id.dev != 0) {
                    if (id.dev != job.dev) return;
                    job.dev = id.dev;
                }
                if (host.config.follow_symlinks and (id.dev != 0 or id.ino != 0)) {
                    if (hasAncestor(job.ancestors, id)) {
                        report(host, job, "", error.SymLinkLoop);
                        return;
                    }
                    dir_ctx.need_child_ancestor = true;
                }
            } else |_| {}
        }
        job.ignore = loadRules(host, dir, job.ignore, job.rel.len) catch |err| {
            report(host, job, "", err);
            return;
        };
    }

    if (host.config.sort_by != .none) {
        processSorted(host, job, dir, &dir_ctx);
    } else {
        processUnsorted(host, job, dir, &dir_ctx);
    }
}

fn processUnsorted(host: *Host, job: *Job, dir: std.Io.Dir, dir_ctx: *DirContext) void {
    const scratch = host.allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(@alignOf(usize)),
        list_dir.buffer_len,
    ) catch |err| {
        report(host, job, "", err);
        return;
    };
    defer host.allocator.free(scratch);

    var lister = list_dir.Lister.init(dir, scratch);
    var entries: [64]std.Io.Dir.Entry = undefined;
    var batch: FileBatch = .{};
    while (!host.stop.load(.acquire)) {
        const n = lister.fill(host.io, &entries) catch |err| {
            report(host, job, "", err);
            return;
        };
        if (n == 0) break;
        for (entries[0..n]) |entry| {
            if (host.stop.load(.acquire)) break;
            handleEntry(host, job, dir, dir_ctx, entry.name, entry.kind, &batch);
            if (batch.len == file_batch) flushFiles(host, job, dir, &batch);
        }
    }
    flushFiles(host, job, dir, &batch);
}

const SortedEntry = struct {
    offset: usize,
    len: usize,
    kind: std.Io.File.Kind,
};

const SortedEntryCtx = struct {
    buf: []const u8,
    reverse: bool,

    fn lessThan(ctx: SortedEntryCtx, a: SortedEntry, b: SortedEntry) bool {
        const sa = ctx.buf[a.offset..][0..a.len];
        const sb = ctx.buf[b.offset..][0..b.len];
        const ord = std.mem.order(u8, sa, sb);
        return if (ctx.reverse) ord == .gt else ord == .lt;
    }
};

noinline fn drainSortedEntries(
    host: *Host,
    job: *Job,
    dir: std.Io.Dir,
    names_buf: *std.ArrayList(u8),
    sorted_entries: *std.ArrayList(SortedEntry),
) bool {
    const scratch = host.allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(@alignOf(usize)),
        list_dir.buffer_len,
    ) catch |err| {
        report(host, job, "", err);
        return false;
    };
    defer host.allocator.free(scratch);

    var lister = list_dir.Lister.init(dir, scratch);
    var entries: [64]std.Io.Dir.Entry = undefined;
    while (!host.stop.load(.acquire)) {
        const n = lister.fill(host.io, &entries) catch |err| {
            report(host, job, "", err);
            return false;
        };
        if (n == 0) break;
        for (entries[0..n]) |entry| {
            if (entry.name.len == 0) continue;
            const offset = names_buf.items.len;
            names_buf.appendSlice(host.allocator, entry.name) catch |err| {
                report(host, job, entry.name, err);
                return false;
            };
            sorted_entries.append(host.allocator, .{
                .offset = offset,
                .len = entry.name.len,
                .kind = entry.kind,
            }) catch |err| {
                report(host, job, entry.name, err);
                return false;
            };
        }
    }
    return true;
}

fn processSorted(host: *Host, job: *Job, dir: std.Io.Dir, dir_ctx: *DirContext) void {
    var names_buf: std.ArrayList(u8) = .empty;
    defer names_buf.deinit(host.allocator);
    var sorted_entries: std.ArrayList(SortedEntry) = .empty;
    defer sorted_entries.deinit(host.allocator);

    if (!drainSortedEntries(host, job, dir, &names_buf, &sorted_entries)) return;
    if (host.stop.load(.acquire)) return;

    std.mem.sortUnstable(
        SortedEntry,
        sorted_entries.items,
        SortedEntryCtx{
            .buf = names_buf.items,
            .reverse = host.config.sort_by == .path_reverse,
        },
        SortedEntryCtx.lessThan,
    );

    for (sorted_entries.items) |se| {
        if (host.stop.load(.acquire)) break;
        const name = names_buf.items[se.offset..][0..se.len];
        if (handleSortedEntry(host, job, dir, dir_ctx, name, se.kind)) |child_job| {
            process(host, child_job);
        }
    }
}

const file_batch = 16;

const FileBatch = struct {
    names: [file_batch][]const u8 = undefined,
    storage: [4096]u8 = undefined,
    used: usize = 0,
    len: usize = 0,
    /// Total files already dispatched from this directory, used to adapt batch granularity.
    dispatched: usize = 0,

    fn push(self: *FileBatch, host: *Host, job: *Job, dir: std.Io.Dir, name: []const u8) void {
        if (name.len > self.storage.len) {
            var rel_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const rel = joinRel(&rel_buf, job.rel, name) catch {
                report(host, job, name, error.NameTooLong);
                return;
            };
            visitCheckedFile(host, job, dir, name, rel, null);
            return;
        }
        if (self.used + name.len > self.storage.len or self.len == file_batch) {
            flushFiles(host, job, dir, self);
        }
        const slice = self.storage[self.used..][0..name.len];
        @memcpy(slice, name);
        self.used += name.len;
        self.names[self.len] = slice;
        self.len += 1;
    }
};

fn dispatchFileSlice(host: *Host, job: *Job, dir: std.Io.Dir, names: []const []const u8) void {
    const child = createFileJob(host, job, names) catch {
        for (names) |name| {
            var rel_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const rel = joinRel(&rel_buf, job.rel, name) catch continue;
            visitCheckedFile(host, job, dir, name, rel, null);
        }
        return;
    };
    host.push(host.push_ctx, child) catch |err| {
        child.destroy(host.io);
        report(host, job, "", err);
        for (names) |name| {
            var rel_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const rel = joinRel(&rel_buf, job.rel, name) catch continue;
            visitCheckedFile(host, job, dir, name, rel, null);
        }
    };
}

fn flushFiles(host: *Host, job: *Job, dir: std.Io.Dir, batch: *FileBatch) void {
    if (batch.len == 0) return;
    const count = batch.len;
    batch.len = 0;
    batch.used = 0;
    if (host.config.threads > 1) {
        // Dispatch the first 8 files in a directory individually so directories containing a few
        // large files fan out across all cores immediately; batch subsequent files (8 per job)
        // to cut heap overhead in large small-file directories.
        var idx: usize = 0;
        while (idx < count and batch.dispatched < 8) : ({
            idx += 1;
            batch.dispatched += 1;
        }) {
            const single = [_][]const u8{batch.names[idx]};
            dispatchFileSlice(host, job, dir, &single);
        }
        while (idx < count) {
            const end = @min(idx + 8, count);
            dispatchFileSlice(host, job, dir, batch.names[idx..end]);
            batch.dispatched += end - idx;
            idx = end;
        }
    } else {
        batch.dispatched += count;
        dispatchFileSlice(host, job, dir, batch.names[0..count]);
    }
}

fn dispatchOrVisitFile(
    host: *Host,
    job: *Job,
    dir: std.Io.Dir,
    name: []const u8,
    rel: []const u8,
    known_size: ?u64,
    batch: ?*FileBatch,
) void {
    if (batch) |b| {
        const should_batch = !host.config.inline_files and
            host.config.threads > 1 and
            (host.idle == null or host.idle.?.load(.acquire) > 0);
        if (should_batch) {
            b.push(host, job, dir, name);
            return;
        }
    }
    visitCheckedFile(host, job, dir, name, rel, known_size);
}

fn handleEntry(
    host: *Host,
    job: *Job,
    dir: std.Io.Dir,
    dir_ctx: *DirContext,
    name: []const u8,
    kind: std.Io.File.Kind,
    batch: *FileBatch,
) void {
    if (name.len == 0) return;
    if (host.config.skip_git and std.mem.eql(u8, name, ".git")) return;
    if (name[0] == '.' and !host.config.hidden) return;

    var rel_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const rel = joinRel(&rel_buf, job.rel, name) catch {
        report(host, job, name, error.NameTooLong);
        return;
    };
    var scratch: [4096]u8 = undefined;

    switch (kind) {
        .directory => {
            if (job.depth >= host.config.effectiveMaxDepth()) return;
            if (ignore.isIgnored(job.ignore, rel, true, &scratch) or blockDirectory(host, rel)) return;
            descendDeferred(host, job, dir_ctx, name, rel);
        },
        .file => {
            if (ignore.isIgnored(job.ignore, rel, false, &scratch)) return;
            if (!allowFile(host, rel)) return;
            if (!allowType(host, name)) return;
            dispatchOrVisitFile(host, job, dir, name, rel, null, batch);
        },
        .sym_link => {
            if (!host.config.follow_symlinks) return;
            const st = dir.statFile(host.io, name, withLinkResolve(std.Io.Dir.StatFileOptions{}, true)) catch |err| {
                report(host, job, name, err);
                return;
            };
            switch (st.kind) {
                .directory => {
                    if (job.depth >= host.config.effectiveMaxDepth()) return;
                    if (ignore.isIgnored(job.ignore, rel, true, &scratch) or blockDirectory(host, rel)) return;
                    descendDeferred(host, job, dir_ctx, name, rel);
                },
                .file => {
                    if (ignore.isIgnored(job.ignore, rel, false, &scratch)) return;
                    if (!allowFile(host, rel)) return;
                    if (!allowType(host, name)) return;
                    if (host.config.max_filesize) |limit| {
                        if (st.size > limit) return;
                    }
                    dispatchOrVisitFile(host, job, dir, name, rel, st.size, batch);
                },
                else => {},
            }
        },
        .unknown => {
            const st = dir.statFile(
                host.io,
                name,
                withLinkResolve(std.Io.Dir.StatFileOptions{}, host.config.follow_symlinks),
            ) catch |err| {
                report(host, job, name, err);
                return;
            };
            switch (st.kind) {
                .directory => {
                    if (job.depth >= host.config.effectiveMaxDepth()) return;
                    if (ignore.isIgnored(job.ignore, rel, true, &scratch) or blockDirectory(host, rel)) return;
                    descendDeferred(host, job, dir_ctx, name, rel);
                },
                .file => {
                    if (ignore.isIgnored(job.ignore, rel, false, &scratch)) return;
                    if (!allowFile(host, rel)) return;
                    if (!allowType(host, name)) return;
                    if (host.config.max_filesize) |limit| {
                        if (st.size > limit) return;
                    }
                    dispatchOrVisitFile(host, job, dir, name, rel, st.size, batch);
                },
                else => {},
            }
        },
        else => {},
    }
}

/// Evaluates a single entry in sorted DFS mode. Returns a child directory `*Job` to process inline
/// after this function's stack buffers (`rel_buf`, `scratch`) are popped, or `null` for files/skipped entries.
noinline fn handleSortedEntry(
    host: *Host,
    job: *Job,
    dir: std.Io.Dir,
    dir_ctx: *DirContext,
    name: []const u8,
    kind: std.Io.File.Kind,
) ?*Job {
    if (name.len == 0) return null;
    if (host.config.skip_git and std.mem.eql(u8, name, ".git")) return null;
    if (name[0] == '.' and !host.config.hidden) return null;

    var rel_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const rel = joinRel(&rel_buf, job.rel, name) catch {
        report(host, job, name, error.NameTooLong);
        return null;
    };
    var scratch: [4096]u8 = undefined;

    switch (kind) {
        .directory => {
            if (job.depth >= host.config.effectiveMaxDepth()) return null;
            if (ignore.isIgnored(job.ignore, rel, true, &scratch) or blockDirectory(host, rel)) return null;
            return makeChildDirJob(host, job, dir_ctx, name, rel);
        },
        .file => {
            if (ignore.isIgnored(job.ignore, rel, false, &scratch)) return null;
            if (!allowFile(host, rel)) return null;
            if (!allowType(host, name)) return null;
            visitCheckedFile(host, job, dir, name, rel, null);
            return null;
        },
        .sym_link => {
            if (!host.config.follow_symlinks) return null;
            const st = dir.statFile(host.io, name, withLinkResolve(std.Io.Dir.StatFileOptions{}, true)) catch |err| {
                report(host, job, name, err);
                return null;
            };
            switch (st.kind) {
                .directory => {
                    if (job.depth >= host.config.effectiveMaxDepth()) return null;
                    if (ignore.isIgnored(job.ignore, rel, true, &scratch) or blockDirectory(host, rel)) return null;
                    return makeChildDirJob(host, job, dir_ctx, name, rel);
                },
                .file => {
                    if (ignore.isIgnored(job.ignore, rel, false, &scratch)) return null;
                    if (!allowFile(host, rel)) return null;
                    if (!allowType(host, name)) return null;
                    visitCheckedFile(host, job, dir, name, rel, st.size);
                    return null;
                },
                else => return null,
            }
        },
        .unknown => {
            const st = dir.statFile(
                host.io,
                name,
                withLinkResolve(std.Io.Dir.StatFileOptions{}, host.config.follow_symlinks),
            ) catch |err| {
                report(host, job, name, err);
                return null;
            };
            switch (st.kind) {
                .directory => {
                    if (job.depth >= host.config.effectiveMaxDepth()) return null;
                    if (ignore.isIgnored(job.ignore, rel, true, &scratch) or blockDirectory(host, rel)) return null;
                    return makeChildDirJob(host, job, dir_ctx, name, rel);
                },
                .file => {
                    if (ignore.isIgnored(job.ignore, rel, false, &scratch)) return null;
                    if (!allowFile(host, rel)) return null;
                    if (!allowType(host, name)) return null;
                    visitCheckedFile(host, job, dir, name, rel, st.size);
                    return null;
                },
                else => return null,
            }
        },
        else => return null,
    }
}

fn makeChildDirJob(
    host: *Host,
    job: *Job,
    dir_ctx: *DirContext,
    name: []const u8,
    rel: []const u8,
) ?*Job {
    const child_anc = dir_ctx.ensureChildAncestors(host, job) catch |err| {
        report(host, job, name, err);
        return null;
    };
    return createDeferredDirJob(host, job.root, rel, job.ignore, job.depth + 1, job.dev, child_anc) catch |err| {
        report(host, job, name, err);
        return null;
    };
}

fn descendDeferred(
    host: *Host,
    job: *Job,
    dir_ctx: *DirContext,
    name: []const u8,
    rel: []const u8,
) void {
    const child = makeChildDirJob(host, job, dir_ctx, name, rel) orelse return;
    host.push(host.push_ctx, child) catch |err| {
        child.destroy(host.io);
        report(host, job, name, err);
    };
}

fn visitCheckedFile(
    host: *Host,
    job: *Job,
    dir: std.Io.Dir,
    name: []const u8,
    rel: []const u8,
    known_size: ?u64,
) void {
    var size: u64 = known_size orelse 0;
    if (host.config.max_filesize) |limit| {
        if (known_size == null) {
            const stat = dir.statFile(
                host.io,
                name,
                withLinkResolve(std.Io.Dir.StatFileOptions{}, host.config.follow_symlinks),
            ) catch |err| {
                report(host, job, name, err);
                return;
            };
            size = stat.size;
        }
        if (size > limit) return;
    }

    const entry_cap = host.config.effectiveMaxEntries();
    const seen = host.session.entries_visited.fetchAdd(1, .monotonic);
    if (seen >= entry_cap) {
        host.stop.store(true, .release);
        return;
    }

    var stack_path: [std.Io.Dir.max_path_bytes]u8 = undefined;
    var heap_path: []u8 = &.{};
    defer if (heap_path.len != 0) host.allocator.free(heap_path);
    const path: []const u8 = if (rel.len == 0)
        job.root
    else if (job.root.len == 0)
        rel
    else if (job.root.len + 1 + rel.len <= stack_path.len) blk: {
        @memcpy(stack_path[0..job.root.len], job.root);
        stack_path[job.root.len] = '/';
        @memcpy(stack_path[job.root.len + 1 ..][0..rel.len], rel);
        break :blk stack_path[0 .. job.root.len + 1 + rel.len];
    } else blk: {
        heap_path = displayPath(host.allocator, job.root, rel) catch |err| {
            report(host, job, name, err);
            return;
        };
        break :blk heap_path;
    };
    const control = host.on_file(host.file_ctx, .{
        .path = path,
        .dir = dir,
        .name = name,
        .size = size,
    }) catch |err| {
        report(host, job, name, err);
        return;
    };
    if (control == .stop) host.stop.store(true, .release);
}

fn createFileJob(host: *Host, parent: *Job, names: []const []const u8) !*Job {
    const job = try host.allocator.create(Job);
    errdefer host.allocator.destroy(job);
    const rel_copy = try host.allocator.dupe(u8, parent.rel);
    errdefer host.allocator.free(rel_copy);
    const owned = try host.allocator.alloc([]u8, names.len);
    errdefer host.allocator.free(owned);
    var filled: usize = 0;
    errdefer for (owned[0..filled]) |item| host.allocator.free(item);
    for (names) |name| {
        owned[filled] = try host.allocator.dupe(u8, name);
        filled += 1;
    }
    job.* = .{
        .dir = null,
        .root = parent.root,
        .rel = rel_copy,
        .ignore = parent.ignore,
        .depth = parent.depth,
        .dev = parent.dev,
        .ancestors = parent.ancestors,
        .allocator = host.allocator,
        .files = owned,
    };
    return job;
}

fn createDeferredDirJob(
    host: *Host,
    root: []const u8,
    rel: []const u8,
    parent: *const ignore.Set,
    depth: u32,
    dev: u64,
    ancestors: ?*const AncestorNode,
) !*Job {
    const job = try host.allocator.create(Job);
    errdefer host.allocator.destroy(job);
    const rel_copy = try host.allocator.dupe(u8, rel);
    errdefer host.allocator.free(rel_copy);
    job.* = .{
        .dir = null,
        .root = root,
        .rel = rel_copy,
        .ignore = parent,
        .depth = depth,
        .dev = dev,
        .ancestors = ancestors,
        .allocator = host.allocator,
    };
    return job;
}

fn createJobWithDev(
    host: *Host,
    dir: std.Io.Dir,
    root: []const u8,
    rel: []const u8,
    parent: *const ignore.Set,
    depth: u32,
    dev: u64,
    ancestors: ?*const AncestorNode,
) !*Job {
    const job = try host.allocator.create(Job);
    errdefer host.allocator.destroy(job);
    const rel_copy = try host.allocator.dupe(u8, rel);
    errdefer host.allocator.free(rel_copy);
    const rules = try loadRules(host, dir, parent, rel_copy.len);
    job.* = .{
        .dir = dir,
        .root = root,
        .rel = rel_copy,
        .ignore = rules,
        .depth = depth,
        .dev = dev,
        .ancestors = ancestors,
        .allocator = host.allocator,
    };
    return job;
}

fn loadRules(
    host: *Host,
    dir: std.Io.Dir,
    parent: *const ignore.Set,
    prefix: usize,
) !*const ignore.Set {
    if (!host.config.read_ignore) return parent;
    var sw = host.config.ignore_switches;
    if (host.config.max_glob_rules) |r| sw.max_rules = r;
    if (host.config.max_glob_rule_len) |l| sw.max_rule_len = l;
    if (host.config.max_glob_brace_depth) |b| sw.max_brace_depth = b;
    const git_excl = if (sw.exclude and prefix == 0) readOptional(host, dir, ".git/info/exclude") else null;
    defer if (git_excl) |bytes| host.allocator.free(bytes);
    const git = if (sw.vcs) readOptional(host, dir, ".gitignore") else null;
    defer if (git) |bytes| host.allocator.free(bytes);
    const local = if (sw.dot) readOptional(host, dir, ".ignore") else null;
    defer if (local) |bytes| host.allocator.free(bytes);
    const rg = if (sw.dot) readOptional(host, dir, ".rgignore") else null;
    defer if (rg) |bytes| host.allocator.free(bytes);

    const has_any = (git_excl != null and git_excl.?.len > 0) or
        (git != null and git.?.len > 0) or
        (local != null and local.?.len > 0) or
        (rg != null and rg.?.len > 0);
    if (!has_any) return parent;

    host.session.lock.lockUncancelable(host.io);
    defer host.session.lock.unlock(host.io);
    const arena = host.session.arena.allocator();
    var globs: std.ArrayList(glob.Glob) = .empty;
    try ignore.parseLayerInto(arena, .{
        .git_exclude = git_excl,
        .gitignore = git,
        .ignore = local,
        .rgignore = rg,
    }, sw, &globs);
    if (globs.items.len == 0) {
        globs.deinit(arena);
        return parent;
    }
    const owned = try arena.dupe(glob.Glob, globs.items);
    globs.deinit(arena);
    const set = try arena.create(ignore.Set);
    set.* = try ignore.build(arena, host.allocator, parent, prefix, &.{}, owned);
    return set;
}

fn readOptional(host: *Host, dir: std.Io.Dir, name: []const u8) ?[]u8 {
    return dir.readFileAlloc(host.io, name, host.allocator, .limited(host.config.max_ignore_file_bytes)) catch null;
}

fn allowFile(host: *Host, rel: []const u8) bool {
    const base = glob.basename(rel);
    var any_positive = false;
    var decision: ?bool = null;
    for (host.session.user_globs) |item| {
        if (!item.negated) any_positive = true;
        if (glob.matches(item, rel, base, false)) decision = !item.negated;
    }
    if (decision) |kept| return kept;
    return !any_positive;
}

fn allowType(host: *const Host, base: []const u8) bool {
    const s = host.session;
    for (s.type_excludes) |item| {
        if (glob.matches(item, base, base, false)) return false;
    }
    if (!s.has_type_includes) return true;
    for (s.type_includes) |item| {
        if (glob.matches(item, base, base, false)) return true;
    }
    return false;
}

fn blockDirectory(host: *Host, rel: []const u8) bool {
    const base = glob.basename(rel);
    var decision: ?bool = null;
    for (host.session.user_globs) |item| {
        if (glob.matches(item, rel, base, true)) decision = !item.negated;
    }
    return if (decision) |kept| !kept else false;
}

fn joinRel(buf: []u8, parent: []const u8, name: []const u8) error{NameTooLong}![]const u8 {
    const extra: usize = if (parent.len == 0) 0 else 1;
    if (parent.len + extra + name.len > buf.len) return error.NameTooLong;
    var n: usize = 0;
    if (parent.len != 0) {
        @memcpy(buf[0..parent.len], parent);
        buf[parent.len] = '/';
        n = parent.len + 1;
    }
    @memcpy(buf[n..][0..name.len], name);
    return buf[0 .. n + name.len];
}

fn displayPath(allocator: std.mem.Allocator, root: []const u8, rel: []const u8) ![]u8 {
    if (rel.len == 0) return allocator.dupe(u8, root);
    if (root.len == 0) return allocator.dupe(u8, rel);
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, rel });
}

fn trimSlash(path: []const u8) []const u8 {
    if (path.len <= 1) return path;
    const trimmed = std.mem.trimEnd(u8, path, "/\\");
    return if (trimmed.len == 0) path[0..1] else trimmed;
}

fn report(host: *Host, job: *Job, name: []const u8, err: anyerror) void {
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const rel = if (name.len == 0) job.rel else (joinRel(&buf, job.rel, name) catch job.rel);
    const path = displayPath(host.allocator, job.root, rel) catch {
        host.on_error(host.error_ctx, job.root, err);
        return;
    };
    defer host.allocator.free(path);
    host.on_error(host.error_ctx, path, err);
}

fn noopPush(ctx: *anyopaque, job: *Job) anyerror!void {
    const stack: *std.ArrayList(*Job) = @ptrCast(@alignCast(ctx));
    try stack.append(std.testing.allocator, job);
}

fn collectFile(ctx: *anyopaque, visit: Visit) anyerror!Control {
    const out: *std.ArrayList([]u8) = @ptrCast(@alignCast(ctx));
    try out.append(std.testing.allocator, try std.testing.allocator.dupe(u8, visit.path));
    return .cont;
}

fn collectError(ctx: *anyopaque, path: []const u8, err: anyerror) void {
    _ = ctx;
    std.debug.print("walk {s}: {t}\n", .{ path, err });
}

test "traversal skips gitignore, hidden files, and .git" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "keep.txt", .data = "a" });
    try tmp.dir.writeFile(io, .{ .sub_path = "skip.log", .data = "a" });
    try tmp.dir.writeFile(io, .{ .sub_path = ".hid", .data = "a" });
    try tmp.dir.writeFile(io, .{ .sub_path = ".gitignore", .data = "*.log\n" });
    try tmp.dir.createDir(io, ".git", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = ".git/config", .data = "a" });
    try tmp.dir.createDir(io, "sub", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/keep.txt", .data = "a" });
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/.ignore", .data = "keep.txt\n" });

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const root = path_buf[0..path_len];

    var session = Session.init(std.testing.allocator);
    defer session.deinit();
    var stop = std.atomic.Value(bool).init(false);
    var stack: std.ArrayList(*Job) = .empty;
    defer stack.deinit(std.testing.allocator);
    var found: std.ArrayList([]u8) = .empty;
    defer {
        for (found.items) |item| std.testing.allocator.free(item);
        found.deinit(std.testing.allocator);
    }
    var host = Host{
        .allocator = std.testing.allocator,
        .io = io,
        .config = .{},
        .session = &session,
        .stop = &stop,
        .push = noopPush,
        .push_ctx = &stack,
        .on_file = collectFile,
        .file_ctx = &found,
        .on_error = collectError,
        .error_ctx = undefined,
    };
    const job = try createRoot(&host, root);
    try stack.append(std.testing.allocator, job);
    while (stack.pop()) |item| process(&host, item);

    try std.testing.expectEqual(@as(usize, 1), found.items.len);
    try std.testing.expect(std.mem.endsWith(u8, found.items[0], "/keep.txt"));
}

fn countWalkError(ctx: *anyopaque, path: []const u8, err: anyerror) void {
    const n: *usize = @ptrCast(@alignCast(ctx));
    n.* += 1;
    std.debug.print("walk {s}: {t}\n", .{ path, err });
}

test "symbolic links are not traversed and cannot escape search root" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = "outside.txt", .data = "outside" });
    try tmp.dir.createDir(io, "escaped", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "escaped/secret.txt", .data = "secret" });
    try tmp.dir.createDir(io, "root", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "root/inside.txt", .data = "inside" });
    try tmp.dir.createDir(io, "root/sub", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "root/sub/nested.txt", .data = "nested" });
    try tmp.dir.symLink(io, "inside.txt", "root/link_inside", .{});
    try tmp.dir.symLink(io, "../outside.txt", "root/link_outside", .{});
    try tmp.dir.symLink(io, "sub", "root/link_sub", .{ .is_directory = true });
    try tmp.dir.symLink(io, "../escaped", "root/link_dir", .{ .is_directory = true });
    try tmp.dir.symLink(io, "nested.txt", "root/sub/link_nested", .{});

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPathFile(io, "root", &path_buf);
    const root = path_buf[0..path_len];

    var session = Session.init(std.testing.allocator);
    defer session.deinit();
    var stop = std.atomic.Value(bool).init(false);
    var stack: std.ArrayList(*Job) = .empty;
    defer stack.deinit(std.testing.allocator);
    var found: std.ArrayList([]u8) = .empty;
    defer {
        for (found.items) |item| std.testing.allocator.free(item);
        found.deinit(std.testing.allocator);
    }
    var errors: usize = 0;
    var host = Host{
        .allocator = std.testing.allocator,
        .io = io,
        .config = .{},
        .session = &session,
        .stop = &stop,
        .push = noopPush,
        .push_ctx = &stack,
        .on_file = collectFile,
        .file_ctx = &found,
        .on_error = countWalkError,
        .error_ctx = &errors,
    };
    const job = try createRoot(&host, root);
    try stack.append(std.testing.allocator, job);
    while (stack.pop()) |item| process(&host, item);

    try std.testing.expectEqual(@as(usize, 0), errors);
    const expected = [_][]const u8{ "inside.txt", "sub/nested.txt" };
    try std.testing.expectEqual(expected.len, found.items.len);
    var matched = std.mem.zeroes([expected.len]bool);
    for (found.items) |path| {
        try std.testing.expect(std.mem.startsWith(u8, path, root));
        try std.testing.expect(path.len > root.len and path[root.len] == '/');
        const rel = path[root.len + 1 ..];
        var ok = false;
        for (expected, 0..) |want, i| {
            if (!std.mem.eql(u8, rel, want)) continue;
            try std.testing.expect(!matched[i]);
            matched[i] = true;
            ok = true;
        }
        if (!ok) {
            std.debug.print("unexpected walk path: {s}\n", .{path});
            return error.TestUnexpectedResult;
        }
    }
    for (matched) |hit| try std.testing.expect(hit);
}

fn silentWalkError(_: *anyopaque, _: []const u8, _: anyerror) void {}

fn freeFound(found: *std.ArrayList([]u8)) void {
    for (found.items) |item| std.testing.allocator.free(item);
    found.deinit(std.testing.allocator);
}

fn sawBase(found: []const []const u8, base: []const u8) bool {
    for (found) |path| {
        if (path.len < base.len) continue;
        if (!std.mem.endsWith(u8, path, base)) continue;
        if (path.len == base.len or path[path.len - base.len - 1] == '/') return true;
    }
    return false;
}

fn collectWalk(root: []const u8, config: Config, found: *std.ArrayList([]u8)) !void {
    const io = std.testing.io;
    var session = Session.init(std.testing.allocator);
    defer session.deinit();
    var stop = std.atomic.Value(bool).init(false);
    var stack: std.ArrayList(*Job) = .empty;
    defer stack.deinit(std.testing.allocator);
    var host = Host{
        .allocator = std.testing.allocator,
        .io = io,
        .config = config,
        .session = &session,
        .stop = &stop,
        .push = noopPush,
        .push_ctx = &stack,
        .on_file = collectFile,
        .file_ctx = found,
        .on_error = silentWalkError,
        .error_ctx = undefined,
    };
    const job = try createRoot(&host, root);
    try stack.append(std.testing.allocator, job);
    while (stack.pop()) |item| process(&host, item);
}

test "does not read gitignore or exclude above search root" {
    inline for (@typeInfo(Config).@"struct".field_names) |field| {
        try std.testing.expect(std.mem.find(u8, field, "parent") == null);
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.writeFile(io, .{ .sub_path = ".gitignore", .data = "*.log\n" });
    try tmp.dir.createDir(io, ".git", .default_dir);
    try tmp.dir.createDir(io, ".git/info", .default_dir);
    const exclude_name = ".git/info/" ++ "exclude";
    try tmp.dir.writeFile(io, .{ .sub_path = exclude_name, .data = "*.md\n" });
    try tmp.dir.createDir(io, "root", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "root/keep.txt", .data = "a" });
    try tmp.dir.writeFile(io, .{ .sub_path = "root/keep.md", .data = "a" });
    try tmp.dir.writeFile(io, .{ .sub_path = "root/keep.log", .data = "a" });

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPathFile(io, "root", &path_buf);
    var found: std.ArrayList([]u8) = .empty;
    defer freeFound(&found);
    try collectWalk(path_buf[0..path_len], .{}, &found);
    try std.testing.expect(sawBase(found.items, "keep.txt"));
    try std.testing.expect(sawBase(found.items, "keep.md"));
    try std.testing.expect(sawBase(found.items, "keep.log"));
}

test "does not read global excludes" {
    inline for (@typeInfo(Config).@"struct".field_names) |field| {
        try std.testing.expect(std.mem.find(u8, field, "global") == null);
        try std.testing.expect(std.mem.find(u8, field, "excludes") == null);
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.createDir(io, ".config", .default_dir);
    try tmp.dir.createDir(io, ".config/git", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = ".config/git/ignore", .data = "*.txt\n" });
    try tmp.dir.createDir(io, "root", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "root/keep.txt", .data = "a" });

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPathFile(io, "root", &path_buf);
    var found: std.ArrayList([]u8) = .empty;
    defer freeFound(&found);
    try collectWalk(path_buf[0..path_len], .{}, &found);
    try std.testing.expect(sawBase(found.items, "keep.txt"));
}

test "does not cross filesystems by default" {
    try std.testing.expect((Config{}).one_file_system);
    try std.testing.expect(!(Config{}).follow_symlinks);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    try tmp.dir.createDir(io, "sub", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/inside.txt", .data = "a" });
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    var same: std.ArrayList([]u8) = .empty;
    defer freeFound(&same);
    try collectWalk(path_buf[0..path_len], .{}, &same);
    try std.testing.expect(sawBase(same.items, "inside.txt"));

    const marker = "cross-fs.txt";
    var shm = std.Io.Dir.openDirAbsolute(io, "/dev/shm", .{}) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer shm.close(io);
    try shm.writeFile(io, .{ .sub_path = marker, .data = "secret\n" });
    defer shm.deleteFile(io, marker) catch {};

    var blocked: std.ArrayList([]u8) = .empty;
    defer freeFound(&blocked);
    try collectWalk("/dev", .{ .max_depth = 2 }, &blocked);
    try std.testing.expect(!sawBase(blocked.items, marker));

    var opened: std.ArrayList([]u8) = .empty;
    defer freeFound(&opened);
    try collectWalk("/dev", .{ .one_file_system = false, .max_depth = 2 }, &opened);
    try std.testing.expect(sawBase(opened.items, marker));
}

test "ignore rules take effect even without a .git directory" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    // Without creating a .git directory, verify that .gitignore, .ignore, and .rgignore still take effect and override by priority
    try tmp.dir.writeFile(io, .{ .sub_path = ".gitignore", .data = "*.log\n*.tmp\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = ".ignore", .data = "!keep.log\n*.bak\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = ".rgignore", .data = "!keep.bak\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "a.txt", .data = "ok" });
    try tmp.dir.writeFile(io, .{ .sub_path = "drop.log", .data = "no" });
    try tmp.dir.writeFile(io, .{ .sub_path = "keep.log", .data = "ok" });
    try tmp.dir.writeFile(io, .{ .sub_path = "drop.tmp", .data = "no" });
    try tmp.dir.writeFile(io, .{ .sub_path = "drop.bak", .data = "no" });
    try tmp.dir.writeFile(io, .{ .sub_path = "keep.bak", .data = "ok" });

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const root = path_buf[0..path_len];

    var found: std.ArrayList([]u8) = .empty;
    defer freeFound(&found);
    try collectWalk(root, .{
        .ignore_texts = &.{"injected_skip.txt\n"},
    }, &found);

    try std.testing.expect(sawBase(found.items, "a.txt"));
    try std.testing.expect(sawBase(found.items, "keep.log"));
    try std.testing.expect(sawBase(found.items, "keep.bak"));
    try std.testing.expect(!sawBase(found.items, "drop.log"));
    try std.testing.expect(!sawBase(found.items, "drop.tmp"));
    try std.testing.expect(!sawBase(found.items, "drop.bak"));
}

test "fixed maximum traversal depth and entry count cap" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    try tmp.dir.writeFile(io, .{ .sub_path = "d1.txt", .data = "1" });
    try tmp.dir.createDir(io, "sub1", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "sub1/d2.txt", .data = "2" });
    try tmp.dir.createDir(io, "sub1/sub2", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "sub1/sub2/d3.txt", .data = "3" });

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const root = path_buf[0..path_len];

    // 1. Unspecified max_depth defaults to max_depth_hard_cap, and caller-configured high depth is respected without clamping
    const cfg_default = Config{};
    try std.testing.expectEqual(Config.max_depth_hard_cap, cfg_default.effectiveMaxDepth());
    const cfg_huge = Config{ .max_depth = 9999 };
    try std.testing.expectEqual(@as(u32, 9999), cfg_huge.effectiveMaxDepth());

    var depth2_found: std.ArrayList([]u8) = .empty;
    defer freeFound(&depth2_found);
    try collectWalk(root, .{ .max_depth = 2 }, &depth2_found);
    try std.testing.expect(sawBase(depth2_found.items, "d1.txt"));
    try std.testing.expect(sawBase(depth2_found.items, "d2.txt"));
    try std.testing.expect(!sawBase(depth2_found.items, "d3.txt"));

    // 2. max_entries caps the number of visited file source entries
    var capped_found: std.ArrayList([]u8) = .empty;
    defer freeFound(&capped_found);
    try collectWalk(root, .{ .max_entries = 2 }, &capped_found);
    try std.testing.expectEqual(@as(usize, 2), capped_found.items.len);
}

test "root .git/info/exclude and nested negation handle compound extensions" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    try tmp.dir.createDir(io, ".git", .default_dir);
    try tmp.dir.createDir(io, ".git/info", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = ".git/info/exclude", .data = "*.local.log\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = ".gitignore", .data = "build/\n*.gen.c\n*.tmp\n" });
    try tmp.dir.createDir(io, "build", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "build/artifact.c", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = "keep.c", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = "drop.gen.c", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = "drop.local.log", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = "keep.log", .data = "x" });
    try tmp.dir.createDir(io, "sub", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/.gitignore", .data = "!important.tmp\n!keep_me.gen.c\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/important.tmp", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/drop.tmp", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/keep_me.gen.c", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/other.gen.c", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/nested.local.log", .data = "x" });

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const root = path_buf[0..path_len];

    var found: std.ArrayList([]u8) = .empty;
    defer freeFound(&found);
    try collectWalk(root, .{}, &found);

    try std.testing.expect(sawBase(found.items, "keep.c"));
    try std.testing.expect(sawBase(found.items, "keep.log"));
    try std.testing.expect(sawBase(found.items, "important.tmp"));
    try std.testing.expect(sawBase(found.items, "keep_me.gen.c"));
    try std.testing.expect(!sawBase(found.items, "artifact.c"));
    try std.testing.expect(!sawBase(found.items, "drop.gen.c"));
    try std.testing.expect(!sawBase(found.items, "other.gen.c"));
    try std.testing.expect(!sawBase(found.items, "drop.local.log"));
    try std.testing.expect(!sawBase(found.items, "nested.local.log"));
    try std.testing.expect(!sawBase(found.items, "drop.tmp"));
}

test "scoped_ignores chain outermost-first with repo_prefix and local overrides" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    try tmp.dir.createDir(io, "generated", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "generated/skip.c", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = "main.c", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = "drop.gen.c", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = "keep_me.gen.c", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = "trace.local.log", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = ".gitignore", .data = "!keep_me.gen.c\n" });

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const root = path_buf[0..path_len];

    const layers = [_]ScopedIgnore{
        .{ .repo_prefix = "src/mod_000", .text = "*.local.log\n" },
        .{ .repo_prefix = "src/mod_000", .text = "/src/mod_000/generated/\n*.gen.c\n" },
    };

    var found: std.ArrayList([]u8) = .empty;
    defer freeFound(&found);
    try collectWalk(root, .{ .scoped_ignores = &layers }, &found);

    try std.testing.expect(sawBase(found.items, "main.c"));
    try std.testing.expect(sawBase(found.items, "keep_me.gen.c"));
    try std.testing.expect(!sawBase(found.items, "skip.c"));
    try std.testing.expect(!sawBase(found.items, "drop.gen.c"));
    try std.testing.expect(!sawBase(found.items, "trace.local.log"));
}

test "follow_symlinks traverses files and dirs, halts on cycles, and soft-errors broken links" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    try tmp.dir.createDir(io, "target_dir", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "target_dir/linked_in_dir.txt", .data = "ok" });
    try tmp.dir.writeFile(io, .{ .sub_path = "target_file.txt", .data = "hello" });

    try tmp.dir.createDir(io, "root", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "root/real.txt", .data = "real" });
    try tmp.dir.createDir(io, "root/sub", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "root/sub/nested.txt", .data = "nested" });
    try tmp.dir.symLink(io, "../target_file.txt", "root/link_file.txt", .{});
    try tmp.dir.symLink(io, "../target_dir", "root/link_dir", .{ .is_directory = true });
    try tmp.dir.symLink(io, "..", "root/sub/loop_to_root", .{ .is_directory = true });
    try tmp.dir.symLink(io, "does_not_exist.txt", "root/broken_link", .{});

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPathFile(io, "root", &path_buf);
    const root = path_buf[0..path_len];

    const ErrRec = struct {
        loops: usize = 0,
        broken: usize = 0,
        other: usize = 0,
        fn onErr(ctx: *anyopaque, _: []const u8, err: anyerror) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (err == error.SymLinkLoop) {
                self.loops += 1;
            } else if (err == error.FileNotFound) {
                self.broken += 1;
            } else {
                self.other += 1;
            }
        }
    };

    var session = Session.init(std.testing.allocator);
    defer session.deinit();
    var stop = std.atomic.Value(bool).init(false);
    var stack: std.ArrayList(*Job) = .empty;
    defer stack.deinit(std.testing.allocator);
    var found: std.ArrayList([]u8) = .empty;
    defer freeFound(&found);
    var err_rec = ErrRec{};

    var host = Host{
        .allocator = std.testing.allocator,
        .io = io,
        .config = .{ .follow_symlinks = true },
        .session = &session,
        .stop = &stop,
        .push = noopPush,
        .push_ctx = &stack,
        .on_file = collectFile,
        .file_ctx = &found,
        .on_error = ErrRec.onErr,
        .error_ctx = &err_rec,
    };
    const job = try createRoot(&host, root);
    try stack.append(std.testing.allocator, job);
    while (stack.pop()) |item| process(&host, item);

    try std.testing.expect(sawBase(found.items, "real.txt"));
    try std.testing.expect(sawBase(found.items, "nested.txt"));
    try std.testing.expect(sawBase(found.items, "link_file.txt"));
    try std.testing.expect(sawBase(found.items, "linked_in_dir.txt"));
    try std.testing.expectEqual(@as(usize, 4), found.items.len);
    try std.testing.expectEqual(@as(usize, 1), err_rec.loops);
    try std.testing.expectEqual(@as(usize, 1), err_rec.broken);
    try std.testing.expectEqual(@as(usize, 0), err_rec.other);
}

test "sort_by path and path_reverse produce deterministic pre-order DFS matching ripgrep" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    try tmp.dir.createDir(io, "b", .default_dir);
    try tmp.dir.createDir(io, "b-dir", .default_dir);
    try tmp.dir.createDir(io, "b_dir", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "a.txt", .data = "a" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b/1.txt", .data = "1" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b-dir/x.txt", .data = "x" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b.txt", .data = "b" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b_dir/y.txt", .data = "y" });

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const root = path_buf[0..path_len];

    const expected_asc = [_][]const u8{
        "a.txt",
        "b/1.txt",
        "b-dir/x.txt",
        "b.txt",
        "b_dir/y.txt",
    };

    var asc: std.ArrayList([]u8) = .empty;
    defer freeFound(&asc);
    try collectWalk(root, .{ .sort_by = .path }, &asc);
    try std.testing.expectEqual(expected_asc.len, asc.items.len);
    for (expected_asc, 0..) |want, i| {
        const rel = asc.items[i][root.len + 1 ..];
        try std.testing.expectEqualStrings(want, rel);
    }

    var desc: std.ArrayList([]u8) = .empty;
    defer freeFound(&desc);
    try collectWalk(root, .{ .sort_by = .path_reverse }, &desc);
    try std.testing.expectEqual(expected_asc.len, desc.items.len);
    for (expected_asc, 0..) |want, i| {
        const rel = desc.items[desc.items.len - 1 - i][root.len + 1 ..];
        try std.testing.expectEqualStrings(want, rel);
    }
}

test "inline_files visits leaves inline without pushing file jobs while fanning out dirs" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;

    try tmp.dir.writeFile(io, .{ .sub_path = "a.rs", .data = "fn a() {}" });
    try tmp.dir.writeFile(io, .{ .sub_path = "b.py", .data = "def b(): pass" });
    try tmp.dir.createDir(io, "sub", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/c.rs", .data = "fn c() {}" });

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const root = path_buf[0..path_len];

    const PushTracker = struct {
        stack: std.ArrayList(*Job) = .empty,
        file_jobs: usize = 0,
        dir_jobs: usize = 0,
        fn push(ctx: *anyopaque, j: *Job) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (j.files != null) self.file_jobs += 1 else self.dir_jobs += 1;
            try self.stack.append(std.testing.allocator, j);
        }
    };

    var tracker = PushTracker{};
    defer tracker.stack.deinit(std.testing.allocator);
    var session = Session.init(std.testing.allocator);
    defer session.deinit();
    var stop = std.atomic.Value(bool).init(false);
    var found: std.ArrayList([]u8) = .empty;
    defer freeFound(&found);

    var host = Host{
        .allocator = std.testing.allocator,
        .io = io,
        .config = .{
            .threads = 4,
            .inline_files = true,
            .types = &.{"rust"},
        },
        .session = &session,
        .stop = &stop,
        .push = PushTracker.push,
        .push_ctx = &tracker,
        .on_file = collectFile,
        .file_ctx = &found,
        .on_error = silentWalkError,
        .error_ctx = undefined,
    };
    const job = try createRoot(&host, root);
    try tracker.stack.append(std.testing.allocator, job);
    while (tracker.stack.pop()) |item| process(&host, item);

    try std.testing.expectEqual(@as(usize, 0), tracker.file_jobs);
    try std.testing.expectEqual(@as(usize, 1), tracker.dir_jobs);
    try std.testing.expectEqual(@as(usize, 2), found.items.len);
    try std.testing.expect(sawBase(found.items, "a.rs"));
    try std.testing.expect(sawBase(found.items, "c.rs"));
    try std.testing.expect(!sawBase(found.items, "b.py"));
}
