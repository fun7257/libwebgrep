//! 目录枚举。默认用 `std.Io.Dir.Reader` 和调用方提供的 32 KiB 缓冲。
//! Linux 上标准库自己会走 `getdents64`，所以这条路径已经是大缓冲的 getdents。
//! `-Dlinux-getdents` 才改用 `linux_getdents.zig` 里的直接系统调用。

const std = @import("std");
const build_options = @import("build_options");

pub const buffer_len: usize = 32 * 1024;

pub const State = struct {
    index: usize = 0,
    end: usize = 0,
    finished: bool = false,
};

pub const Lister = struct {
    dir: std.Io.Dir,
    scratch: []align(@alignOf(usize)) u8,
    state: State = .{},

    pub fn init(dir: std.Io.Dir, scratch: []align(@alignOf(usize)) u8) Lister {
        std.debug.assert(scratch.len >= std.Io.Dir.Reader.min_buffer_len);
        return .{ .dir = dir, .scratch = scratch };
    }

    pub fn fill(self: *Lister, io: std.Io, out: []std.Io.Dir.Entry) std.Io.Dir.Reader.Error!usize {
        if (self.state.finished) return 0;
        if (comptime build_options.linux_getdents) {
            const linux_state = @import("linux_getdents.zig").State{
                .index = self.state.index,
                .end = self.state.end,
                .finished = self.state.finished,
            };
            var cursor = linux_state;
            const n = try @import("linux_getdents.zig").fill(io, self.dir, self.scratch, &cursor, out);
            self.state = .{
                .index = cursor.index,
                .end = cursor.end,
                .finished = cursor.finished,
            };
            return n;
        }
        var reader = std.Io.Dir.Reader{
            .dir = self.dir,
            .state = if (self.state.end == 0 and self.state.index == 0) .reset else .reading,
            .index = self.state.index,
            .end = self.state.end,
            .buffer = self.scratch,
        };
        const n = try reader.read(io, out);
        self.state.index = reader.index;
        self.state.end = reader.end;
        self.state.finished = reader.state == .finished;
        return n;
    }
};
