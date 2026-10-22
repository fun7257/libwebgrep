//! Linux 专用的目录枚举。只在 `-Dlinux-getdents` 且目标是 Linux 时编进遍历。
//!
//! 直接调用 `getdents64`，解析 `dirent64`，跳过 `.` 和 `..`。
//! 取消点走 `Io.checkCancel`。没有这组构建选项时，遍历使用 `std.Io.Dir.Reader`。

const std = @import("std");

const linux = std.os.linux;

pub const State = struct {
    index: usize = 0,
    end: usize = 0,
    finished: bool = false,
};

pub fn fill(
    io: std.Io,
    dir: std.Io.Dir,
    scratch: []align(@alignOf(usize)) u8,
    state: *State,
    out: []std.Io.Dir.Entry,
) std.Io.Dir.Reader.Error!usize {
    var written: usize = 0;
    while (written < out.len) {
        if (state.end == state.index) {
            if (written != 0) break;
            const n = try readKernel(io, dir, scratch);
            if (n == 0) {
                state.finished = true;
                return written;
            }
            state.index = 0;
            state.end = n;
        }
        const entry: *align(1) linux.dirent64 = @ptrCast(&scratch[state.index]);
        const next = state.index + entry.reclen;
        if (next > state.end) return error.Unexpected;
        state.index = next;
        const name_ptr: [*]u8 = &entry.name;
        const padded_len = entry.reclen - @offsetOf(linux.dirent64, "name");
        const padded = name_ptr[0..padded_len];
        const name_len = std.mem.indexOfScalar(u8, padded, 0) orelse return error.Unexpected;
        const name = name_ptr[0..name_len];
        if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
        out[written] = .{
            .name = name,
            .kind = kindOf(entry.type),
            .inode = entry.ino,
        };
        written += 1;
    }
    return written;
}

fn readKernel(io: std.Io, dir: std.Io.Dir, scratch: []u8) std.Io.Dir.Reader.Error!usize {
    while (true) {
        const rc = linux.getdents64(
            dir.handle,
            scratch.ptr,
            @min(scratch.len, std.math.maxInt(c_uint)),
        );
        switch (linux.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => {
                try io.checkCancel();
                continue;
            },
            .NOENT => return 0,
            .ACCES => return error.AccessDenied,
            .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
    }
}

fn kindOf(dtype: u8) std.Io.File.Kind {
    return switch (dtype) {
        linux.DT.BLK => .block_device,
        linux.DT.CHR => .character_device,
        linux.DT.DIR => .directory,
        linux.DT.FIFO => .named_pipe,
        linux.DT.LNK => .sym_link,
        linux.DT.REG => .file,
        linux.DT.SOCK => .unix_domain_socket,
        linux.DT.WHT => .whiteout,
        else => .unknown,
    };
}
