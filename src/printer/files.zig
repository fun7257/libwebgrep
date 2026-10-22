//! 文件名打印器。第一次匹配就写下路径并停止这个输入。
//! 用于 `-l` / `--files-with-matches`。`--files` 不搜索，不走这里。

const std = @import("std");
const sink = @import("../sink.zig");

pub const Files = struct {
    writer: *std.Io.Writer,
    path: []const u8 = "",
    write_error: ?std.Io.Writer.Error = null,

    pub fn begin(self: *Files, path: []const u8) bool {
        self.path = path;
        self.write_error = null;
        return true;
    }

    pub fn matched(self: *Files, line: sink.Line) bool {
        _ = line;
        self.writer.print("{s}\n", .{self.path}) catch |err| {
            self.write_error = err;
            return false;
        };
        return false;
    }
};

const testing = std.testing;
const Finder = @import("../finder/finder.zig").Finder;
const searchSlice = @import("../searcher.zig").searchSlice;

test "命中一次就写出路径并停止" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var printer = Files{ .writer = &out.writer };
    var finder = try Finder.init("MATCH", .{});
    const result = try searchSlice(Files, &printer, "no\nMATCH\nMATCH\n", "a.txt", &finder, .{});
    try testing.expect(printer.write_error == null);
    try testing.expectEqualStrings("a.txt\n", out.written());
    try testing.expectEqual(@as(u64, 1), result.matched_lines);
}
