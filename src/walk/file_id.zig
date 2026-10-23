//! 打开文件的设备号和 inode。
//!
//! 这是各平台拿到同一对数字的办法，不是可选的性能开关：
//! Linux 用 `statx` 的 `dev_major` / `dev_minor` / `ino`。
//! 其他 POSIX 用 `fstat` 的 `dev` / `ino`。
//! Windows 的 `File.Stat` 没有设备号，只用 inode，并在设计说明里记一笔。

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
    const rc = std.os.linux.statx(handle, "", std.os.linux.AT.EMPTY_PATH, .{ .INO = true }, &stx);
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

test "同一文件的两次打开得到同一个身份" {
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
