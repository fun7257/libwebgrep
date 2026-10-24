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
    root: *const Node,
    slots: [8]?*const Node = @splat(null),

    pub fn source(self: *Memory) Source {
        return .{ .ctx = self, .vtable = &vtable };
    }

    fn openSlot(self: *Memory) error{SystemResources}!usize {
        for (self.slots, 0..) |slot, i| {
            if (slot == null) return i + 1;
        }
        return error.SystemResources;
    }

    fn node(self: *Memory, handle: usize) !*const Node {
        if (handle == 0 or handle > self.slots.len) return error.InvalidHandle;
        return self.slots[handle - 1] orelse error.InvalidHandle;
    }
};

const OpenError = error{ NotFound, InvalidHandle, SystemResources };
const ReadError = error{ InvalidHandle, NotFile };
const ListError = error{ InvalidHandle, NotDir };

fn lookup(node: *const Node, path: []const u8) ?*const Node {
    if (path.len == 0 or std.mem.eql(u8, path, "/")) return node;
    var rest = if (path[0] == '/') path[1..] else path;
    var current = node;
    while (rest.len > 0) {
        const slash = std.mem.indexOfScalar(u8, rest, '/') orelse rest.len;
        const name = rest[0..slash];
        if (current.kind != .directory) return null;
        var found: ?*const Node = null;
        for (current.children) |child| {
            if (std.mem.eql(u8, child.name, name)) {
                found = child;
                break;
            }
        }
        current = found orelse return null;
        if (slash == rest.len) break;
        rest = rest[slash + 1 ..];
    }
    return current;
}

fn memOpen(ctx: *anyopaque, io: std.Io, path: []const u8) OpenError!usize {
    _ = io;
    const self: *Memory = @ptrCast(@alignCast(ctx));
    const node = lookup(self.root, path) orelse return error.NotFound;
    const handle = try self.openSlot();
    self.slots[handle - 1] = node;
    return handle;
}

fn memRead(ctx: *anyopaque, io: std.Io, handle: usize, dest: []u8) ReadError!usize {
    _ = io;
    const self: *Memory = @ptrCast(@alignCast(ctx));
    const node = self.node(handle) catch return error.InvalidHandle;
    if (node.kind != .file) return error.NotFile;
    const n = @min(dest.len, node.bytes.len);
    @memcpy(dest[0..n], node.bytes[0..n]);
    return n;
}

fn memList(ctx: *anyopaque, io: std.Io, handle: usize, out: []Entry) ListError!usize {
    _ = io;
    const self: *Memory = @ptrCast(@alignCast(ctx));
    const node = self.node(handle) catch return error.InvalidHandle;
    if (node.kind != .directory) return error.NotDir;
    const n = @min(out.len, node.children.len);
    for (node.children[0..n], out[0..n]) |child, *slot| {
        slot.* = .{ .name = child.name, .kind = child.kind };
    }
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
