//! Directory traversal. Ignore rules are chained on an immutable parent list, and discovered subdirectories are pushed to the caller's queue.
//! Filesystem access goes directly through `std.Io.Dir`, bypassing the vtable in `source.zig`.
//!
//! Hidden files and `.git` are skipped by default. Symbolic links are never traversed. Paths are concatenated byte-by-byte without assuming UTF-8.

const builtin = @import("builtin");
const std = @import("std");
const file_id = @import("file_id.zig");
const glob = @import("glob.zig");
const ignore = @import("ignore.zig");
const list_dir = @import("list_dir.zig");
const types = @import("types.zig");

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
    /// By default, directories on a different device than the search root are not entered. Callers may disable this; there is no field to enable link traversal.
    one_file_system: bool = true,

    pub fn effectiveMaxDepth(self: Config) u32 {
        return if (self.max_depth) |d| @min(d, max_depth_hard_cap) else max_depth_hard_cap;
    }

    pub fn effectiveMaxEntries(self: Config) u64 {
        return if (self.max_entries) |n| @min(n, max_entries_hard_cap) else max_entries_hard_cap;
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
    push: *const fn (*anyopaque, *Job) anyerror!void,
    push_ctx: *anyopaque,
    on_file: *const fn (*anyopaque, Visit) anyerror!Control,
    file_ctx: *anyopaque,
    on_error: *const fn (*anyopaque, []const u8, anyerror) void,
    error_ctx: *anyopaque,
};

pub const Job = struct {
    dir: std.Io.Dir,
    /// Root path passed by the caller; must remain valid throughout traversal.
    root: []const u8,
    rel: []u8,
    ignore: *const ignore.Set,
    depth: u32,
    /// Device ID of this directory. 0 means unavailable and is not used for cross-device checks.
    dev: u64 = 0,
    allocator: std.mem.Allocator,
    /// When non-null, this job visits only these filenames without listing the directory. Names are freed by this job.
    files: ?[][]u8 = null,

    pub fn destroy(self: *Job, io: std.Io) void {
        if (self.files) |names| {
            for (names) |name| self.allocator.free(name);
            self.allocator.free(names);
        }
        self.dir.close(io);
        self.allocator.free(self.rel);
        self.allocator.destroy(self);
    }
};

pub const Session = struct {
    arena: std.heap.ArenaAllocator,
    lock: std.Io.Mutex = .init,
    gpa: std.mem.Allocator,
    empty: ignore.Set = .{},
    user_globs: []const glob.Glob = &.{},
    globs_prepared: bool = false,
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

    pub fn prepareGlobs(self: *Session, io: std.Io, texts: []const []const u8) !void {
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);
        const arena = self.arena.allocator();
        self.user_globs = try glob.compileGlobs(arena, texts, .{});
        self.globs_prepared = true;
    }

    pub fn prepareConfig(self: *Session, io: std.Io, config: Config) !void {
        self.lock.lockUncancelable(io);
        defer self.lock.unlock(io);
        const arena = self.arena.allocator();
        if (!self.globs_prepared and (config.globs.len > 0 or config.iglobs.len > 0)) {
            var list: std.ArrayList(glob.Glob) = .empty;
            if (config.globs.len > 0) {
                const compiled = try glob.compileGlobs(arena, config.globs, .{
                    .case_insensitive = config.iglob,
                });
                try list.appendSlice(arena, compiled);
            }
            if (config.iglobs.len > 0) {
                if (list.items.len >= glob.rule_count_hard_cap) return error.GlobCountExceeded;
                const remain = glob.rule_count_hard_cap - list.items.len;
                const compiled_i = try glob.compileGlobs(arena, config.iglobs, .{
                    .case_insensitive = true,
                    .max_rules = remain,
                });
                try list.appendSlice(arena, compiled_i);
            }
            self.user_globs = try list.toOwnedSlice(arena);
            self.globs_prepared = true;
        }
        if (!self.ignore_prepared and config.ignore_texts.len > 0) {
            var ig_list: std.ArrayList(glob.Glob) = .empty;
            try ignore.parseTextsInto(arena, config.ignore_texts, &ig_list, .{
                .case_insensitive = config.ignore_switches.case_insensitive,
                .max_rules = config.ignore_switches.max_rules,
            });
            if (ig_list.items.len > 0) {
                const owned = try ig_list.toOwnedSlice(arena);
                self.empty = try ignore.build(arena, self.gpa, null, 0, &.{}, owned);
            }
            self.ignore_prepared = true;
        }
    }
};

fn openRoot(io: std.Io, path: []const u8) !std.Io.Dir {
    const options = withoutLinkResolve(std.Io.Dir.OpenOptions{ .iterate = true });
    if (std.fs.path.isAbsolute(path)) return std.Io.Dir.openDirAbsolute(io, path, options);
    return std.Io.Dir.cwd().openDir(io, path, options);
}

/// Opens a search root without reading ignore rules above it. The caller pushes the returned job into the queue.
pub fn createRoot(host: *Host, root_path: []const u8) !*Job {
    try host.session.prepareConfig(host.io, host.config);
    const shown = trimSlash(root_path);
    const dir = try openRoot(host.io, shown);
    errdefer dir.close(host.io);
    return createJob(host, dir, shown, "", &host.session.empty, 1);
}

/// Opening a directory or stating a file resolves symbolic links by default. Traversal must disable
/// such boolean options so subdirectories or `.git` cannot redirect reads outside the caller-supplied root.
fn withoutLinkResolve(options: anytype) @TypeOf(options) {
    var out = options;
    const info = @typeInfo(@TypeOf(options)).@"struct";
    comptime var found = false;
    inline for (info.field_names, info.field_types) |field_name, field_type| {
        if (comptime field_type == bool and std.mem.endsWith(u8, field_name, "symlinks")) {
            found = true;
            @field(out, field_name) = false;
        }
    }
    if (comptime !found) @compileError("directory options lack a boolean flag to disable symlink resolution");
    return out;
}

pub fn process(host: *Host, job: *Job) void {
    if (job.files) |names| {
        defer job.destroy(host.io);
        if (host.stop.load(.acquire)) return;
        for (names) |name| {
            if (host.stop.load(.acquire)) return;
            var rel_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const rel = joinRel(&rel_buf, job.rel, name) catch {
                report(host, job, name, error.NameTooLong);
                continue;
            };
            visitCheckedFile(host, job, name, rel);
        }
        return;
    }

    defer job.destroy(host.io);
    if (host.stop.load(.acquire)) return;
    if (job.depth > host.config.effectiveMaxDepth()) return;

    const scratch = host.allocator.alignedAlloc(
        u8,
        std.mem.Alignment.fromByteUnits(@alignOf(usize)),
        list_dir.buffer_len,
    ) catch |err| {
        report(host, job, "", err);
        return;
    };
    defer host.allocator.free(scratch);

    var lister = list_dir.Lister.init(job.dir, scratch);
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
            handleEntry(host, job, entry, &batch);
            if (batch.len == file_batch) flushFiles(host, job, &batch);
        }
    }
    flushFiles(host, job, &batch);
}

const file_batch = 16;

const FileBatch = struct {
    names: [file_batch][]const u8 = undefined,
    storage: [4096]u8 = undefined,
    used: usize = 0,
    len: usize = 0,

    fn push(self: *FileBatch, host: *Host, job: *Job, name: []const u8) void {
        if (name.len > self.storage.len) {
            var rel_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const rel = joinRel(&rel_buf, job.rel, name) catch {
                report(host, job, name, error.NameTooLong);
                return;
            };
            visitCheckedFile(host, job, name, rel);
            return;
        }
        if (self.used + name.len > self.storage.len or self.len == file_batch) {
            flushFiles(host, job, self);
        }
        const slice = self.storage[self.used..][0..name.len];
        @memcpy(slice, name);
        self.used += name.len;
        self.names[self.len] = slice;
        self.len += 1;
    }
};

fn flushFiles(host: *Host, job: *Job, batch: *FileBatch) void {
    if (batch.len == 0) return;
    const names = batch.names[0..batch.len];
    batch.len = 0;
    batch.used = 0;
    const child = createFileJob(host, job, names) catch {
        for (names) |name| {
            var rel_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const rel = joinRel(&rel_buf, job.rel, name) catch continue;
            visitCheckedFile(host, job, name, rel);
        }
        return;
    };
    host.push(host.push_ctx, child) catch |err| {
        child.destroy(host.io);
        report(host, job, "", err);
        for (names) |name| {
            var rel_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
            const rel = joinRel(&rel_buf, job.rel, name) catch continue;
            visitCheckedFile(host, job, name, rel);
        }
    };
}

fn handleEntry(host: *Host, job: *Job, entry: std.Io.Dir.Entry, batch: *FileBatch) void {
    const name = entry.name;
    if (name.len == 0) return;
    if (host.config.skip_git and std.mem.eql(u8, name, ".git")) return;
    if (name[0] == '.' and !host.config.hidden) return;

    var rel_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const rel = joinRel(&rel_buf, job.rel, name) catch {
        report(host, job, name, error.NameTooLong);
        return;
    };
    var scratch: [4096]u8 = undefined;

    switch (entry.kind) {
        .directory => {
            const child_dir = job.dir.openDir(
                host.io,
                name,
                withoutLinkResolve(std.Io.Dir.OpenOptions{ .iterate = true }),
            ) catch |err| {
                report(host, job, name, err);
                return;
            };
            descend(host, job, name, rel, &scratch, child_dir);
        },
        .file => {
            if (ignore.isIgnored(job.ignore, rel, false, &scratch)) return;
            if (!allowFile(host, rel)) return;
            if (!types.matchesWithTable(host.config.custom_types, host.config.types, host.config.types_not, name)) return;
            if (host.config.threads > 1) {
                batch.push(host, job, name);
            } else {
                visitCheckedFile(host, job, name, rel);
            }
        },
        // Symbolic links themselves are never entered; targets are not read even inside the search root, and traversal cannot escape the root via links.
        .sym_link => {},
        else => {},
    }
}

fn directoryDevice(dir: std.Io.Dir) ?u64 {
    const id = file_id.fromDir(dir) catch return null;
    if (id.dev == 0) return null;
    return id.dev;
}

fn descend(
    host: *Host,
    job: *Job,
    name: []const u8,
    rel: []const u8,
    scratch: []u8,
    child_dir: std.Io.Dir,
) void {
    if (host.config.one_file_system and job.dev != 0) {
        if (directoryDevice(child_dir)) |child_dev| {
            if (child_dev != job.dev) {
                child_dir.close(host.io);
                return;
            }
        }
    }
    if (ignore.isIgnored(job.ignore, rel, true, scratch) or blockDirectory(host, rel)) {
        child_dir.close(host.io);
        return;
    }
    if (job.depth >= host.config.effectiveMaxDepth()) {
        child_dir.close(host.io);
        return;
    }
    const child = createJob(host, child_dir, job.root, rel, job.ignore, job.depth + 1) catch |err| {
        child_dir.close(host.io);
        report(host, job, name, err);
        return;
    };
    host.push(host.push_ctx, child) catch |err| {
        child.destroy(host.io);
        report(host, job, name, err);
    };
}

fn visitCheckedFile(
    host: *Host,
    job: *Job,
    name: []const u8,
    rel: []const u8,
) void {
    var size: u64 = 0;
    if (host.config.max_filesize) |limit| {
        const stat = job.dir.statFile(
            host.io,
            name,
            withoutLinkResolve(std.Io.Dir.StatFileOptions{}),
        ) catch |err| {
            report(host, job, name, err);
            return;
        };
        size = stat.size;
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
        .dir = job.dir,
        .name = name,
        .size = size,
    }) catch |err| {
        report(host, job, name, err);
        return;
    };
    if (control == .stop) host.stop.store(true, .release);
}

fn duplicateDir(dir: std.Io.Dir) ?std.Io.Dir {
    if (builtin.os.tag == .windows) return null;
    // `std.posix.system` uses direct Linux syscalls when libc is not linked.
    // `std.c.fcntl` is extern "c" and would force linking libc on Linux.
    const rc = std.posix.system.fcntl(dir.handle, std.posix.F.DUPFD_CLOEXEC, @as(usize, 0));
    if (std.posix.errno(rc) != .SUCCESS) return null;
    return .{ .handle = @intCast(rc) };
}

fn createFileJob(host: *Host, parent: *Job, names: []const []const u8) !*Job {
    const dir = duplicateDir(parent.dir) orelse return error.SystemResources;
    errdefer dir.close(host.io);
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
        .dir = dir,
        .root = parent.root,
        .rel = rel_copy,
        .ignore = parent.ignore,
        .depth = parent.depth,
        .dev = parent.dev,
        .allocator = host.allocator,
        .files = owned,
    };
    return job;
}

fn createJob(
    host: *Host,
    dir: std.Io.Dir,
    root: []const u8,
    rel: []const u8,
    parent: *const ignore.Set,
    depth: u32,
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
        .dev = directoryDevice(dir) orelse 0,
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
    const sw = host.config.ignore_switches;
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
    return dir.readFileAlloc(host.io, name, host.allocator, .limited(1 << 20)) catch null;
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
    var end = path.len;
    while (end > 1 and (path[end - 1] == '/' or path[end - 1] == '\\')) end -= 1;
    return path[0..end];
}

fn report(host: *Host, job: *Job, name: []const u8, err: anyerror) void {
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const rel = joinRel(&buf, job.rel, name) catch job.rel;
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
        try std.testing.expect(std.mem.indexOf(u8, field, "parent") == null);
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
        try std.testing.expect(std.mem.indexOf(u8, field, "global") == null);
        try std.testing.expect(std.mem.indexOf(u8, field, "excludes") == null);
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
    inline for (@typeInfo(Config).@"struct".field_names) |field| {
        try std.testing.expect(!std.mem.endsWith(u8, field, "symlinks"));
    }

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

    // 1. Oversized max_depth is clamped to max_depth_hard_cap, and explicit depth limits are respected
    const cfg_huge = Config{ .max_depth = 9999 };
    try std.testing.expectEqual(Config.max_depth_hard_cap, cfg_huge.effectiveMaxDepth());

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
