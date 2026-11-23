//! Directory enumeration using `std.Io.Dir.Reader` with a caller-supplied 32 KiB buffer.
//! On Linux, `std.Io.Dir.Reader` invokes `getdents64` directly with the caller's buffer.

const std = @import("std");

pub const buffer_len: usize = 32 * 1024;

pub const Lister = struct {
    reader: std.Io.Dir.Reader,

    pub fn init(dir: std.Io.Dir, scratch: []align(@alignOf(usize)) u8) Lister {
        std.debug.assert(scratch.len >= std.Io.Dir.Reader.min_buffer_len);
        return .{ .reader = std.Io.Dir.Reader.init(dir, scratch) };
    }

    pub fn fill(self: *Lister, io: std.Io, out: []std.Io.Dir.Entry) std.Io.Dir.Reader.Error!usize {
        if (self.reader.state == .finished) return 0;
        return self.reader.read(io, out);
    }
};
