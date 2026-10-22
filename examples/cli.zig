//! 示例 CLI。只用于测试和基准，不追求兼容 rg 的全部参数。
//! 搜索开关在打印器落地后接上。

const std = @import("std");
const zrg = @import("zrg");

pub fn main(init: std.process.Init) !void {
    _ = init;
    _ = zrg.SearchConfig{};
    std.debug.print("zrg: 字面量搜索库的示例程序。\n", .{});
}

test "示例链接到库" {
    try std.testing.expectEqual(@as(usize, 256 * 1024), zrg.SearchConfig.default_buffer_size);
}
