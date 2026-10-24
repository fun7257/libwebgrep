//! Device ID and inode for open files.
//!
//! This is how each platform obtains the same pair of numbers, not an optional performance toggle:
//! Linux uses `dev_major` / `dev_minor` / `ino` from `statx`.
//! Other POSIX platforms use `dev` / `ino` from `fstat`.
//! Windows `File.Stat` lacks a device ID, so only the inode is used (noted in the design documentation).

const builtin = @import("builtin");
const std = @import("std");

pub const Id = struct {
    dev: u64,
    ino: u64,

    pub fn eql(self: Id, other: Id) bool {
        return self.dev == other.dev and self.ino == other.ino;
    }
};

pub const Error = error{Unexpected} || std.Io.File.StatError;

pub fn fromDir(dir: std.Io.Dir) Error!Id {
    switch (builtin.os.tag) {
        .linux => return linuxId(dir.handle),
        .windows => return .{ .dev = 0, .ino = 0 },
        else => return posixId(dir.handle),
    }
}

pub fn fromFile(io: std.Io, file: std.Io.File) Error!Id {
    switch (builtin.os.tag) {
        .linux => return linuxId(file.handle),
        .windows => {
            const stat = try file.stat(io);
            return .{ .dev = 0, .ino = toU64(stat.inode) };
        },
        else => return posixId(file.handle),
    }
}

fn linuxId(handle: std.posix.fd_t) Error!Id {
    var stx = std.mem.zeroes(std.os.linux.Statx);
    const rc = std.os.linux.statx(handle, "", std.os.linux.AT.EMPTY_PATH, std.os.linux.STATX.BASIC_STATS, &stx);
    switch (std.os.linux.errno(rc)) {
        .SUCCESS => {},
        else => return error.Unexpected,
    }
    const dev = (@as(u64, stx.dev_major) << 32) | @as(u64, stx.dev_minor);
    return .{ .dev = dev, .ino = stx.ino };
}

fn posixId(handle: std.posix.fd_t) Error!Id {
    var st: std.c.Stat = undefined;
    if (std.c.fstat(handle, &st) != 0) return error.Unexpected;
    return .{
        .dev = toU64(st.dev),
        .ino = toU64(st.ino),
    };
}

fn toU64(value: anytype) u64 {
    const info = @typeInfo(@TypeOf(value)).int;
    if (info.signedness == .unsigned) return @intCast(value);
    const unsigned = @Int(.unsigned, info.bits);
    return unsigned: {
        const bits: unsigned = @bitCast(value);
        break :unsigned @intCast(bits);
    };
}

test "opening the same file twice yields the same identity" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "a.txt", .data = "a" });
    const first = try tmp.dir.openFile(std.testing.io, "a.txt", .{});
    defer first.close(std.testing.io);
    const second = try tmp.dir.openFile(std.testing.io, "a.txt", .{});
    defer second.close(std.testing.io);
    const a = try fromFile(std.testing.io, first);
    const b = try fromFile(std.testing.io, second);
    try std.testing.expect(a.eql(b));

    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "b.txt", .data = "b" });
    const other = try tmp.dir.openFile(std.testing.io, "b.txt", .{});
    defer other.close(std.testing.io);
    const c = try fromFile(std.testing.io, other);
    try std.testing.expect(!a.eql(c));
}
