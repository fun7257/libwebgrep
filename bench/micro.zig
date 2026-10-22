//! 内核微基准。P0 的查找内核接上之前只确认 ReleaseFast 入口可用。

const std = @import("std");
const zrg = @import("zrg");

pub fn main(init: std.process.Init) !void {
    _ = init;
    std.debug.print("zrg microbench: default buffer {d} bytes\n", .{zrg.SearchConfig.default_buffer_size});
}
