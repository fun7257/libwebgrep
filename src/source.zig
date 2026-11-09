//! Minimal interface for archive and network inputs. Filesystem traversal bypasses this and uses `std.Io.Dir` directly.
//! Defines the interface and provides an in-memory directory for testing.

const std = @import("std");

pub const Kind = enum { file, directory, other };

pub const Entry = struct {
    name: []const u8,
    kind: Kind,
};

pub const VTable = struct {
    open: *const fn (*anyopaque, std.Io, []const u8) anyerror!usize,
    read: *const fn (*anyopaque, std.Io, usize, []u8) anyerror!usize,
    list: *const fn (*anyopaque, std.Io, usize, []Entry) anyerror!usize,
    close: *const fn (*anyopaque, std.Io, usize) void,
};

pub const Source = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub fn open(self: Source, io: std.Io, path: []const u8) !usize {
        return self.vtable.open(self.ctx, io, path);
    }

    pub fn read(self: Source, io: std.Io, handle: usize, dest: []u8) !usize {
        return self.vtable.read(self.ctx, io, handle, dest);
    }

    pub fn list(self: Source, io: std.Io, handle: usize, out: []Entry) !usize {
        return self.vtable.list(self.ctx, io, handle, out);
    }

    pub fn close(self: Source, io: std.Io, handle: usize) void {
        self.vtable.close(self.ctx, io, handle);
    }
};

pub const Node = struct {
    name: []const u8,
    kind: Kind,
    bytes: []const u8 = &.{},
    children: []const *const Node = &.{},
};

/// Handles are 1-based slot indices; 0 is reserved.
pub const Memory = struct {
    pub const Slot = struct {
        node: *const Node,
        offset: usize = 0,
    };

    root: *const Node,
    slots: [64]?Slot = @splat(null),

    pub fn source(self: *Memory) Source {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn openSlot(self: *Memory) error{SystemResources}!usize {
        for (self.slots, 0..) |slot, i| {
            if (slot == null) return i + 1;
        }
        return error.SystemResources;
    }

    fn slotPtr(self: *Memory, handle: usize) !*Slot {
        if (handle == 0 or handle > self.slots.len) return error.InvalidHandle;
        if (self.slots[handle - 1]) |*s| return s;
        return error.InvalidHandle;
    }

    pub fn lookup(root: *const Node, path: []const u8) ?*const Node {
        return lookupNode(root, path);
    }
};

const OpenError = error{ NotFound, InvalidHandle, SystemResources };
const ReadError = error{ InvalidHandle, NotFile };
const ListError = error{ InvalidHandle, NotDir };

pub fn lookupNode(node: *const Node, path: []const u8) ?*const Node {
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return null;
    if (std.mem.indexOfScalar(u8, path, 0) != null) return null;
    if (path.len == 0 or std.mem.eql(u8, path, "/") or std.mem.eql(u8, path, ".")) return node;
    var rest = if (path[0] == '/') path[1..] else path;
    var current = node;
    while (rest.len > 0) {
        const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
        const name = rest[0..slash];
        if (std.mem.eql(u8, name, "..")) return null;
        if (name.len > 0 and !std.mem.eql(u8, name, ".")) {
            if (current.kind != .directory) return null;
            var found: ?*const Node = null;
            for (current.children) |child| {
                if (std.mem.eql(u8, child.name, name)) {
                    found = child;
                    break;
                }
            }
            current = found orelse return null;
        }
        if (slash == rest.len) break;
        rest = rest[slash + 1 ..];
    }
    return current;
}

fn memOpen(ctx: *anyopaque, io: std.Io, path: []const u8) OpenError!usize {
    _ = io;
    const self: *Memory = @ptrCast(@alignCast(ctx));
    const node = lookupNode(self.root, path) orelse return error.NotFound;
    const handle = try self.openSlot();
    self.slots[handle - 1] = .{ .node = node, .offset = 0 };
    return handle;
}

fn memRead(ctx: *anyopaque, io: std.Io, handle: usize, dest: []u8) ReadError!usize {
    _ = io;
    const self: *Memory = @ptrCast(@alignCast(ctx));
    const slot = self.slotPtr(handle) catch return error.InvalidHandle;
    if (slot.node.kind != .file) return error.NotFile;
    if (slot.offset >= slot.node.bytes.len) return 0;
    const rem = slot.node.bytes[slot.offset..];
    const n = @min(dest.len, rem.len);
    @memcpy(dest[0..n], rem[0..n]);
    slot.offset += n;
    return n;
}

fn memList(ctx: *anyopaque, io: std.Io, handle: usize, out: []Entry) ListError!usize {
    _ = io;
    const self: *Memory = @ptrCast(@alignCast(ctx));
    const slot = self.slotPtr(handle) catch return error.InvalidHandle;
    if (slot.node.kind != .directory) return error.NotDir;
    if (slot.offset >= slot.node.children.len) return 0;
    const rem = slot.node.children[slot.offset..];
    const n = @min(out.len, rem.len);
    for (rem[0..n], out[0..n]) |child, *out_entry| {
        out_entry.* = .{ .name = child.name, .kind = child.kind };
    }
    slot.offset += n;
    return n;
}

fn memClose(ctx: *anyopaque, io: std.Io, handle: usize) void {
    _ = io;
    const self: *Memory = @ptrCast(@alignCast(ctx));
    if (handle == 0 or handle > self.slots.len) return;
    self.slots[handle - 1] = null;
}

const vtable = VTable{
    .open = memOpen,
    .read = memRead,
    .list = memList,
    .close = memClose,
};

test "in-memory directory can open, list, and read" {
    const file = Node{ .name = "a.txt", .kind = .file, .bytes = "hello" };
    const dir = Node{ .name = "", .kind = .directory, .children = &.{&file} };
    var memory = Memory{ .root = &dir };
    const src = memory.source();
    const handle = try src.open(std.testing.io, "");
    defer src.close(std.testing.io, handle);
    var entries: [4]Entry = undefined;
    const n = try src.list(std.testing.io, handle, &entries);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqualStrings("a.txt", entries[0].name);

    const child = try src.open(std.testing.io, "a.txt");
    defer src.close(std.testing.io, child);
    var buf: [8]u8 = undefined;
    const got = try src.read(std.testing.io, child, &buf);
    try std.testing.expectEqualStrings("hello", buf[0..got]);
}

test "source.Memory chunked read advances cursor to EOF" {
    const file = Node{ .name = "chunked.txt", .kind = .file, .bytes = "abcdefghij" };
    const dir = Node{ .name = "", .kind = .directory, .children = &.{&file} };
    var memory = Memory{ .root = &dir };
    const src = memory.source();

    const handle = try src.open(std.testing.io, "chunked.txt");
    defer src.close(std.testing.io, handle);

    var buf: [4]u8 = undefined;
    const n1 = try src.read(std.testing.io, handle, &buf);
    try std.testing.expectEqual(@as(usize, 4), n1);
    try std.testing.expectEqualStrings("abcd", buf[0..n1]);

    const n2 = try src.read(std.testing.io, handle, &buf);
    try std.testing.expectEqual(@as(usize, 4), n2);
    try std.testing.expectEqualStrings("efgh", buf[0..n2]);

    const n3 = try src.read(std.testing.io, handle, &buf);
    try std.testing.expectEqual(@as(usize, 2), n3);
    try std.testing.expectEqualStrings("ij", buf[0..n3]);

    const n4 = try src.read(std.testing.io, handle, &buf);
    try std.testing.expectEqual(@as(usize, 0), n4);
}

test "source.Memory batched list advances cursor to end" {
    const f1 = Node{ .name = "1.txt", .kind = .file, .bytes = "1" };
    const f2 = Node{ .name = "2.txt", .kind = .file, .bytes = "2" };
    const f3 = Node{ .name = "3.txt", .kind = .file, .bytes = "3" };
    const dir = Node{ .name = "", .kind = .directory, .children = &.{ &f1, &f2, &f3 } };
    var memory = Memory{ .root = &dir };
    const src = memory.source();

    const handle = try src.open(std.testing.io, "");
    defer src.close(std.testing.io, handle);

    var batch: [2]Entry = undefined;
    const n1 = try src.list(std.testing.io, handle, &batch);
    try std.testing.expectEqual(@as(usize, 2), n1);
    try std.testing.expectEqualStrings("1.txt", batch[0].name);
    try std.testing.expectEqualStrings("2.txt", batch[1].name);

    const n2 = try src.list(std.testing.io, handle, &batch);
    try std.testing.expectEqual(@as(usize, 1), n2);
    try std.testing.expectEqualStrings("3.txt", batch[0].name);

    const n3 = try src.list(std.testing.io, handle, &batch);
    try std.testing.expectEqual(@as(usize, 0), n3);
}

test "source.Memory slot reuse after close" {
    const f = Node{ .name = "a.txt", .kind = .file, .bytes = "hello" };
    const dir = Node{ .name = "", .kind = .directory, .children = &.{&f} };
    var memory = Memory{ .root = &dir };
    const src = memory.source();

    var handles: [64]usize = undefined;
    for (&handles) |*h| {
        h.* = try src.open(std.testing.io, "a.txt");
    }
    try std.testing.expectError(error.SystemResources, src.open(std.testing.io, "a.txt"));

    src.close(std.testing.io, handles[10]);
    const reused = try src.open(std.testing.io, "a.txt");
    try std.testing.expectEqual(handles[10], reused);

    for (handles) |h| {
        src.close(std.testing.io, h);
    }
}

test "source.Memory lookup rejects .. path traversal" {
    const secret = Node{ .name = "secret.txt", .kind = .file, .bytes = "secret" };
    const sub = Node{ .name = "sub", .kind = .directory, .children = &.{} };
    const root = Node{ .name = "", .kind = .directory, .children = &.{ &secret, &sub } };
    var memory = Memory{ .root = &root };
    const src = memory.source();

    try std.testing.expectError(error.NotFound, src.open(std.testing.io, "../secret.txt"));
    try std.testing.expectError(error.NotFound, src.open(std.testing.io, "sub/../secret.txt"));
    try std.testing.expectError(error.NotFound, src.open(std.testing.io, ".."));
    try std.testing.expectError(error.NotFound, src.open(std.testing.io, "sub\\secret.txt"));
}



