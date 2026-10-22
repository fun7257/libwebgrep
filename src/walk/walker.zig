//! 目录遍历。忽略规则挂在不可变的父链上，发现的子目录交给调用方的队列。
//! 文件系统走 `std.Io.Dir`，不经过 `source.zig` 的虚表。
//!
//! 默认跳过隐藏文件和 `.git`。不跟随符号链接。路径按字节拼接，不假定 UTF-8。

const std = @import("std");
const file_id = @import("file_id.zig");
const glob = @import("glob.zig");
const ignore = @import("ignore.zig");
const list_dir = @import("list_dir.zig");
const types = @import("types.zig");

pub const Config = struct {
    hidden: bool = false,
    follow_symlinks: bool = false,
    read_ignore: bool = true,
    /// null 表示不限制。1 只看起始目录里的文件，0 什么也不列。和 rg 的 `--max-depth` 一致。
    max_depth: ?u32 = null,
    max_filesize: ?u64 = null,
    globs: []const []const u8 = &.{},
    types: []const []const u8 = &.{},
    /// 0 表示由调度层选择 CPU 数。
    threads: u32 = 0,
    skip_git: bool = true,
};

pub const Control = enum { cont, stop };

pub const Visit = struct {
    /// 只在这次回调期间有效。
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
    /// 调用方传入的根路径，遍历期间必须一直有效。
    root: []const u8,
    rel: []u8,
    ignore: *const ignore.Set,
    depth: u32,
    ancestors: []file_id.Id,
    allocator: std.mem.Allocator,

    pub fn destroy(self: *Job, io: std.Io) void {
        self.dir.close(io);
        self.allocator.free(self.rel);
        if (self.ancestors.len != 0) self.allocator.free(self.ancestors);
        self.allocator.destroy(self);
    }
};

pub const Session = struct {
    arena: std.heap.ArenaAllocator,
    lock: std.Io.Mutex = .init,
    gpa: std.mem.Allocator,
    empty: ignore.Set = .{},
    user_globs: []const glob.Glob = &.{},

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
        const owned = try arena.alloc(glob.Glob, texts.len);
        for (texts, owned) |text, *slot| {
            var body = text;
            var negated = false;
            if (body.len > 0 and body[0] == '!') {
                negated = true;
                body = body[1..];
            }
            const copy = try arena.dupe(u8, body);
            slot.* = glob.classify(copy);
            slot.negated = negated;
            slot.anchored = std.mem.indexOfScalar(u8, copy, '/') != null;
        }
        self.user_globs = owned;
    }
};

pub fn openRoot(io: std.Io, path: []const u8) !std.Io.Dir {
    const options = std.Io.Dir.OpenOptions{ .iterate = true };
    if (std.fs.path.isAbsolute(path)) return std.Io.Dir.openDirAbsolute(io, path, options);
    return std.Io.Dir.cwd().openDir(io, path, options);
}

/// 打开一个搜索根并装上 exclude / gitignore。调用方把返回的任务放进队列。
pub fn createRoot(host: *Host, root_path: []const u8) !*Job {
    const shown = trimSlash(root_path);
    const dir = try openRoot(host.io, shown);
    errdefer dir.close(host.io);
    const base = loadExclude(host, shown) catch &host.session.empty;
    return createJob(host, dir, shown, "", base, 1, &.{});
}

pub fn process(host: *Host, job: *Job) void {
    defer job.destroy(host.io);
    if (host.stop.load(.acquire)) return;
    if (host.config.max_depth) |max| {
        if (job.depth > max) return;
    }

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
    while (!host.stop.load(.acquire)) {
        const n = lister.fill(host.io, &entries) catch |err| {
            report(host, job, "", err);
            return;
        };
        if (n == 0) return;
        for (entries[0..n]) |entry| {
            if (host.stop.load(.acquire)) return;
            handleEntry(host, job, entry);
        }
    }
}

fn handleEntry(host: *Host, job: *Job, entry: std.Io.Dir.Entry) void {
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
            const child_dir = job.dir.openDir(host.io, name, .{
                .iterate = true,
                .follow_symlinks = false,
            }) catch |err| {
                report(host, job, name, err);
                return;
            };
            descend(host, job, name, rel, &scratch, child_dir, null);
        },
        .file => visitFile(host, job, name, rel, &scratch, null),
        .sym_link => if (host.config.follow_symlinks) followLink(host, job, name, rel, &scratch),
        else => {},
    }
}

fn descend(
    host: *Host,
    job: *Job,
    name: []const u8,
    rel: []const u8,
    scratch: []u8,
    child_dir: std.Io.Dir,
    known: ?file_id.Id,
) void {
    if (ignore.isIgnored(job.ignore, rel, true, scratch) or blockDirectory(host, rel)) {
        child_dir.close(host.io);
        return;
    }
    if (host.config.max_depth) |max| {
        if (job.depth >= max) {
            child_dir.close(host.io);
            return;
        }
    }
    var ancestors = job.ancestors;
    var owned_ancestors: ?[]file_id.Id = null;
    defer if (owned_ancestors) |ids| host.allocator.free(ids);
    if (known) |id| {
        if (seen(job.ancestors, id)) {
            child_dir.close(host.io);
            return;
        }
        owned_ancestors = extendAncestors(host.allocator, job.ancestors, id) catch |err| {
            child_dir.close(host.io);
            report(host, job, name, err);
            return;
        };
        ancestors = owned_ancestors.?;
    }
    const child = createJob(host, child_dir, job.root, rel, job.ignore, job.depth + 1, ancestors) catch |err| {
        child_dir.close(host.io);
        report(host, job, name, err);
        return;
    };
    host.push(host.push_ctx, child) catch |err| {
        child.destroy(host.io);
        report(host, job, name, err);
    };
}

fn visitFile(
    host: *Host,
    job: *Job,
    name: []const u8,
    rel: []const u8,
    scratch: []u8,
    size_override: ?u64,
) void {
    if (ignore.isIgnored(job.ignore, rel, false, scratch)) return;
    if (!allowFile(host, rel)) return;
    if (!types.matches(host.config.types, name)) return;

    var size = size_override orelse 0;
    if (host.config.max_filesize) |limit| {
        if (size_override == null) {
            const stat = job.dir.statFile(host.io, name, .{}) catch |err| {
                report(host, job, name, err);
                return;
            };
            size = stat.size;
        }
        if (size > limit) return;
    }

    const path = displayPath(host.allocator, job.root, rel) catch |err| {
        report(host, job, name, err);
        return;
    };
    defer host.allocator.free(path);
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

fn followLink(host: *Host, job: *Job, name: []const u8, rel: []const u8, scratch: []u8) void {
    const stat = job.dir.statFile(host.io, name, .{ .follow_symlinks = true }) catch |err| {
        report(host, job, name, err);
        return;
    };
    switch (stat.kind) {
        .directory => {
            const opened = job.dir.openDir(host.io, name, .{
                .iterate = true,
                .follow_symlinks = true,
            }) catch |err| {
                report(host, job, name, err);
                return;
            };
            const id = file_id.fromFile(host.io, .{ .handle = opened.handle, .flags = .{ .nonblocking = false } }) catch |err| {
                opened.close(host.io);
                report(host, job, name, err);
                return;
            };
            descend(host, job, name, rel, scratch, opened, id);
        },
        .file => visitFile(host, job, name, rel, scratch, stat.size),
        else => {},
    }
}

fn createJob(
    host: *Host,
    dir: std.Io.Dir,
    root: []const u8,
    rel: []const u8,
    parent: *const ignore.Set,
    depth: u32,
    ancestors: []const file_id.Id,
) !*Job {
    const job = try host.allocator.create(Job);
    errdefer host.allocator.destroy(job);
    const rel_copy = try host.allocator.dupe(u8, rel);
    errdefer host.allocator.free(rel_copy);
    const ancestor_copy = try host.allocator.alloc(file_id.Id, ancestors.len);
    errdefer if (ancestor_copy.len != 0) host.allocator.free(ancestor_copy);
    @memcpy(ancestor_copy, ancestors);
    const rules = try loadRules(host, dir, parent, rel_copy.len);
    job.* = .{
        .dir = dir,
        .root = root,
        .rel = rel_copy,
        .ignore = rules,
        .depth = depth,
        .ancestors = ancestor_copy,
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
    const git = readOptional(host, dir, ".gitignore");
    defer if (git) |bytes| host.allocator.free(bytes);
    const local = readOptional(host, dir, ".ignore");
    defer if (local) |bytes| host.allocator.free(bytes);
    if ((git == null or git.?.len == 0) and (local == null or local.?.len == 0)) return parent;

    host.session.lock.lockUncancelable(host.io);
    defer host.session.lock.unlock(host.io);
    const arena = host.session.arena.allocator();
    var globs: std.ArrayList(glob.Glob) = .empty;
    if (git) |bytes| try ignore.parseInto(arena, bytes, &globs);
    if (local) |bytes| try ignore.parseInto(arena, bytes, &globs);
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

fn loadExclude(host: *Host, root_path: []const u8) !*const ignore.Set {
    if (!host.config.read_ignore) return &host.session.empty;
    const found = (try readExclude(host, root_path)) orelse return &host.session.empty;
    defer host.allocator.free(found.prefix);
    defer host.allocator.free(found.bytes);
    if (found.bytes.len == 0) return &host.session.empty;

    host.session.lock.lockUncancelable(host.io);
    defer host.session.lock.unlock(host.io);
    const arena = host.session.arena.allocator();
    var globs: std.ArrayList(glob.Glob) = .empty;
    try ignore.parseInto(arena, found.bytes, &globs);
    if (globs.items.len == 0) {
        globs.deinit(arena);
        return &host.session.empty;
    }
    const owned = try arena.dupe(glob.Glob, globs.items);
    globs.deinit(arena);
    const prefix = try arena.dupe(u8, found.prefix);
    const set = try arena.create(ignore.Set);
    set.* = try ignore.build(arena, host.allocator, null, 0, prefix, owned);
    return set;
}

const ExcludeFile = struct {
    prefix: []u8,
    bytes: []u8,
};

fn readExclude(host: *Host, root_path: []const u8) !?ExcludeFile {
    var buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const n = std.Io.Dir.cwd().realPathFile(host.io, root_path, &buf) catch return null;
    const root_abs = try host.allocator.dupe(u8, buf[0..n]);
    defer host.allocator.free(root_abs);
    var abs = buf[0..n];
    while (true) {
        const git = try std.fmt.allocPrint(host.allocator, "{s}/.git", .{abs});
        defer host.allocator.free(git);
        if (std.Io.Dir.cwd().statFile(host.io, git, .{ .follow_symlinks = false })) |stat| {
            if (stat.kind == .directory) {
                const exclude = try std.fmt.allocPrint(host.allocator, "{s}/.git/info/exclude", .{abs});
                defer host.allocator.free(exclude);
                const bytes = std.Io.Dir.cwd().readFileAlloc(
                    host.io,
                    exclude,
                    host.allocator,
                    .limited(1 << 20),
                ) catch try host.allocator.alloc(u8, 0);
                const prefix = repoPrefix(abs, root_abs);
                return .{
                    .prefix = try host.allocator.dupe(u8, prefix),
                    .bytes = bytes,
                };
            }
        } else |_| {}
        const parent = std.fs.path.dirname(abs) orelse return null;
        if (parent.len == abs.len) return null;
        abs = buf[0..parent.len];
    }
}

fn repoPrefix(repo: []const u8, root_abs: []const u8) []const u8 {
    if (std.mem.eql(u8, repo, root_abs)) return "";
    if (root_abs.len > repo.len and std.mem.startsWith(u8, root_abs, repo) and root_abs[repo.len] == '/') {
        return root_abs[repo.len + 1 ..];
    }
    return "";
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

fn seen(ancestors: []const file_id.Id, id: file_id.Id) bool {
    for (ancestors) |old| if (old.eql(id)) return true;
    return false;
}

fn extendAncestors(allocator: std.mem.Allocator, parent: []const file_id.Id, id: file_id.Id) ![]file_id.Id {
    const out = try allocator.alloc(file_id.Id, parent.len + 1);
    @memcpy(out[0..parent.len], parent);
    out[parent.len] = id;
    return out;
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

test "遍历跳过 gitignore、隐藏文件和 .git" {
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
