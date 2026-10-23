//! 大文件按 8 MiB 窗口映射，再拷进 Searcher 已有的缓冲。
//!
//! 这是可选的文件读取方式，不是默认路径。只有构建选项打开时，
//! 文件搜索才会调用这里。默认构建不编译这份文件。
//! 小文件、比搜索缓冲还小的文件、以及映射失败，都退回 `readPositional`。
//!
//! 丢掉窗口时通知内核可以回收页面。Linux 走 `madvise` 系统调用，不链接 libc。
//! macOS 用系统 libc 里的 `madvise`。Windows 和 WASI 跳过。
//! 这里没有 CPU 分派。向量宽度仍由 P0 的 `suggestVectorLength` 决定。

const builtin = @import("builtin");
const std = @import("std");

pub const window_len: usize = 8 * 1024 * 1024;

const ReadError = error{ OutOfMemory, ReadFailed } || std.Io.File.ReadPositionalError;

pub const Reader = struct {
    io: std.Io,
    file: std.Io.File,
    size: u64,
    page: usize,
    offset: u64 = 0,
    window: ?std.Io.File.MemoryMap = null,
    window_off: u64 = 0,
    window_len: usize = 0,
    fallback: bool = false,

    pub fn close(self: *Reader) void {
        self.drop();
    }

    fn drop(self: *Reader) void {
        if (self.window) |*mapped| {
            adviseDontNeed(mapped.memory);
            mapped.destroy(self.io);
            self.window = null;
        }
    }

    fn ensure(self: *Reader) ReadError!void {
        if (self.fallback or self.offset >= self.size) return;
        if (self.window != null and self.offset < self.window_off + self.window_len) return;
        self.drop();
        const off = self.offset - (self.offset % self.page);
        const remain = self.size - off;
        const len: usize = @intCast(@min(remain, window_len));
        const mapped = std.Io.File.MemoryMap.create(self.io, self.file, .{
            .len = len,
            .offset = off,
            .protection = .{ .read = true, .write = false },
            .populate = false,
        }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => {
                self.fallback = true;
                return;
            },
        };
        self.window = mapped;
        self.window_off = off;
        self.window_len = len;
    }
};

/// 文件不大于 `small_limit`，或第一次映射失败时返回 null。只有内存不足向上传。
pub fn open(io: std.Io, file: std.Io.File, small_limit: usize) error{OutOfMemory}!?Reader {
    const stat = file.stat(io) catch return null;
    if (stat.kind != .file) return null;
    if (stat.size <= small_limit) return null;
    if (stat.size > std.math.maxInt(usize)) return null;
    const page = std.heap.pageSize();
    if (page == 0) return null;
    var reader = Reader{
        .io = io,
        .file = file,
        .size = stat.size,
        .page = page,
    };
    reader.ensure() catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    if (reader.fallback or reader.window == null) {
        reader.close();
        return null;
    }
    return reader;
}

pub fn readBytes(raw: *anyopaque, dest: []u8) ReadError!usize {
    const self: *Reader = @ptrCast(@alignCast(raw));
    if (dest.len == 0 or self.offset >= self.size) return 0;
    if (self.fallback) return readPositional(self, dest);
    try self.ensure();
    if (self.fallback or self.window == null) return readPositional(self, dest);
    const mapped = &self.window.?;
    const local: usize = @intCast(self.offset - self.window_off);
    if (local >= mapped.memory.len) return readPositional(self, dest);
    const avail = @min(mapped.memory.len - local, self.window_len -| local);
    const want = @min(dest.len, @min(avail, @as(usize, @intCast(self.size - self.offset))));
    if (want == 0) return 0;
    @memcpy(dest[0..want], mapped.memory[local..][0..want]);
    self.offset += want;
    if (self.offset >= self.window_off + self.window_len) self.drop();
    return want;
}

fn readPositional(self: *Reader, dest: []u8) ReadError!usize {
    var iov = [_][]u8{dest};
    const n = try self.file.readPositional(self.io, &iov, self.offset);
    self.offset += n;
    return n;
}

fn adviseDontNeed(memory: []align(std.heap.page_size_min) u8) void {
    switch (comptime builtin.os.tag) {
        .linux => {
            // musl 目标不会自动链接 libc。直接系统调用，失败也不影响读到的字节。
            _ = std.os.linux.madvise(memory.ptr, memory.len, std.os.linux.MADV.DONTNEED);
        },
        .windows, .wasi => {},
        else => {
            if (comptime @TypeOf(std.c.MADV) == void) return;
            _ = std.c.madvise(memory.ptr, memory.len, std.c.MADV.DONTNEED);
        },
    }
}

test "比缓冲大的文件能从窗口里读出" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = std.testing.io;
    const payload = "abcdefghijklmnopqrstuvwxyz012345";
    try tmp.dir.writeFile(io, .{ .sub_path = "wide.txt", .data = payload });
    const file = try tmp.dir.openFile(io, "wide.txt", .{});
    defer file.close(io);
    var reader = (try open(io, file, 8)) orelse return error.TestUnexpectedResult;
    defer reader.close();
    var got: [64]u8 = undefined;
    var n: usize = 0;
    while (n < payload.len) {
        const read = try readBytes(&reader, got[n..]);
        if (read == 0) break;
        n += read;
    }
    try std.testing.expectEqualStrings(payload, got[0..n]);
}
