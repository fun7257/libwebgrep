//! Large files are mapped in 8 MiB windows and copied into the Searcher's existing buffer.
//!
//! This is an optional file-reading path, not the default. File search invokes it only when enabled
//! via build options; default builds do not compile this file.
//! Small files, files smaller than the search buffer, and mapping failures all fall back to `readPositional`.
//!
//! When dropping a window, the kernel is advised that pages can be reclaimed. Linux uses the `madvise` syscall without linking libc.
//! macOS uses `madvise` from system libc. Windows and WASI are no-ops.
//! There is no CPU dispatch here; vector width is still determined by `suggestVectorLength`.

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

/// Returns null if the file is no larger than `small_limit` or if the initial mapping fails. Only `OutOfMemory` is propagated.
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
            // musl targets do not link libc automatically; invoke the syscall directly and ignore failures since read bytes are unaffected.
            _ = std.os.linux.madvise(memory.ptr, memory.len, std.os.linux.MADV.DONTNEED);
        },
        .windows, .wasi => {},
        else => {
            if (comptime @TypeOf(std.c.MADV) == void) return;
            _ = std.c.madvise(memory.ptr, memory.len, std.c.MADV.DONTNEED);
        },
    }
}

test "file larger than buffer can be read from window" {
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
