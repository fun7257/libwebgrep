//! 计数打印器。每个输入在 `finish` 时写一行。
//!
//! 单输入且不要求路径时只写数字。否则是 `路径:数字`。零次匹配默认不写，
//! `include_zero` 为真时写 0。不实现 `binary`，因此 NUL 之后的匹配行也会计入，
//! 并且不会写出二进制说明。这和 `rg -c` 一致。

const std = @import("std");
const sink = @import("../sink.zig");

/// 统计 `matched` 的调用次数。上下文行没有 `matched`，不会计入。
pub const Count = struct {
    writer: *std.Io.Writer,
    show_path: bool = false,
    include_zero: bool = false,

    path: []const u8 = "",
    count: u64 = 0,
    write_error: ?std.Io.Writer.Error = null,

    pub fn begin(self: *Count, path: []const u8) bool {
        self.path = path;
        self.count = 0;
        self.write_error = null;
        return true;
    }

    pub fn matched(self: *Count, line: sink.Line) bool {
        _ = line;
        self.count += 1;
        return true;
    }

    pub fn finish(self: *Count, result: sink.Result) bool {
        _ = result;
        if (self.write_error != null) return false;
        if (self.count == 0 and !self.include_zero) return true;
        if (self.show_path and self.path.len != 0) {
            self.writer.print("{s}:{d}\n", .{ self.path, self.count }) catch |err| {
                self.write_error = err;
                return false;
            };
        } else {
            self.writer.print("{d}\n", .{self.count}) catch |err| {
                self.write_error = err;
                return false;
            };
        }
        return true;
    }
};

const testing = std.testing;
const Finder = @import("../finder/finder.zig").Finder;
const searchSlice = @import("../searcher.zig").searchSlice;

fn run(
    hay: []const u8,
    pattern: []const u8,
    config: @import("../searcher.zig").SearchConfig,
    show_path: bool,
    include_zero: bool,
    name: []const u8,
) !std.Io.Writer.Allocating {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer out.deinit();
    var counter = Count{ .writer = &out.writer, .show_path = show_path, .include_zero = include_zero };
    var finder = try Finder.init(pattern, .{});
    _ = try searchSlice(Count, &counter, hay, name, &finder, config);
    try testing.expect(counter.write_error == null);
    return out;
}

test "计数：单文件、多文件、零次和二进制" {
    var one = try run("MATCH\nno\nMATCH MATCH\n", "MATCH", .{}, false, false, "t.txt");
    defer one.deinit();
    try testing.expectEqualStrings("2\n", one.written());

    var headed = try run("MATCH\n", "MATCH", .{}, true, false, "t.txt");
    defer headed.deinit();
    try testing.expectEqualStrings("t.txt:1\n", headed.written());

    var miss = try run("no\n", "MATCH", .{}, true, false, "t.txt");
    defer miss.deinit();
    try testing.expectEqualStrings("", miss.written());

    var zero = try run("no\n", "MATCH", .{}, true, true, "t.txt");
    defer zero.deinit();
    try testing.expectEqualStrings("t.txt:0\n", zero.written());

    var bin = try run("MATCH\na\x00\nMATCH2\n", "MATCH", .{ .binary = .report }, false, false, "");
    defer bin.deinit();
    try testing.expectEqualStrings("2\n", bin.written());
}

test "计数：max_count 的 after 窗口里抬成匹配的行也算" {
    var out = try run("a\nb\nMATCH\nc\nd\ne\nMATCH2\nf\n", "MATCH", .{
        .after = 4,
        .max_count = 1,
    }, false, false, "");
    defer out.deinit();
    try testing.expectEqualStrings("2\n", out.written());
}
