//! JSON Lines，字段对齐 `rg --json`。
//!
//! 没有匹配的文件不写 begin/match/end，但调用方仍把它算进 summary.searches。
//! `lines.text` 在 rg 里带原来的换行。Searcher 交给 Sink 的行不含 `\n`，这里补一个。
//! 文件末尾没有换行时也会补上，所以不和 rg 逐字节比较。
//! 一行里的多个命中用 Searcher 已经按起点排好的区间，这里不再重扫。
//! 耗时字段不要求和 rg 的数字一致。

const std = @import("std");
const Finder = @import("../finder/finder.zig").Finder;
const sink = @import("../sink.zig");

pub const Json = struct {
    const Self = @This();

    writer: *std.Io.Writer,
    path: []const u8 = "",
    started: bool = false,
    matched_lines: u64 = 0,
    matches: u64 = 0,
    binary_offset: ?u64 = null,
    bytes_searched: u64 = 0,
    write_error: ?std.Io.Writer.Error = null,

    pub fn begin(self: *Self, path: []const u8) bool {
        self.path = path;
        self.started = false;
        self.matched_lines = 0;
        self.matches = 0;
        self.binary_offset = null;
        self.write_error = null;
        return true;
    }

    pub fn matched(self: *Self, line: sink.Line) bool {
        if (!self.ensureBegin()) return false;
        if (!self.writeLine("match", line, true)) return false;
        self.matched_lines += 1;
        return true;
    }

    pub fn context(self: *Self, line: sink.Line) bool {
        if (!self.ensureBegin()) return false;
        return self.writeLine("context", line, false);
    }

    pub fn binary(self: *Self, offset: u64) bool {
        self.binary_offset = offset;
        return true;
    }

    pub fn finish(self: *Self, result: sink.Result) bool {
        if (result.nul_offset) |offset| self.binary_offset = offset;
        return self.write_error == null;
    }

    pub fn writeEnd(self: *Self, elapsed_ns: u64) bool {
        if (!self.started or self.write_error != null) return self.write_error == null;
        self.writer.writeAll("{\"type\":\"end\",\"data\":{\"path\":{\"text\":") catch |err| {
            self.write_error = err;
            return false;
        };
        writeJsonString(self.writer, self.path) catch |err| {
            self.write_error = err;
            return false;
        };
        self.writer.writeAll("},\"binary_offset\":") catch |err| {
            self.write_error = err;
            return false;
        };
        writeOptionalU64(self.writer, self.binary_offset) catch |err| {
            self.write_error = err;
            return false;
        };
        self.writer.writeAll(",\"stats\":{") catch |err| {
            self.write_error = err;
            return false;
        };
        writeStats(self.writer, elapsed_ns, .{
            .searches = 1,
            .searches_with_match = if (self.matched_lines > 0) 1 else 0,
            .bytes_searched = self.bytes_searched,
            .bytes_printed = 0,
            .matched_lines = self.matched_lines,
            .matches = self.matches,
        }) catch |err| {
            self.write_error = err;
            return false;
        };
        self.writer.writeAll("}}}\n") catch |err| {
            self.write_error = err;
            return false;
        };
        return true;
    }

    fn ensureBegin(self: *Self) bool {
        if (self.started) return true;
        self.started = true;
        self.writer.writeAll("{\"type\":\"begin\",\"data\":{\"path\":{\"text\":") catch |err| {
            self.write_error = err;
            return false;
        };
        writeJsonString(self.writer, self.path) catch |err| {
            self.write_error = err;
            return false;
        };
        self.writer.writeAll("}}}\n") catch |err| {
            self.write_error = err;
            return false;
        };
        return true;
    }

    fn writeLine(self: *Self, kind: []const u8, line: sink.Line, with_matches: bool) bool {
        self.writer.print("{{\"type\":\"{s}\",\"data\":{{\"path\":{{\"text\":", .{kind}) catch |err| {
            self.write_error = err;
            return false;
        };
        writeJsonString(self.writer, self.path) catch |err| {
            self.write_error = err;
            return false;
        };
        self.writer.writeAll("},\"lines\":{\"text\":") catch |err| {
            self.write_error = err;
            return false;
        };
        writeJsonStringNewline(self.writer, line.bytes) catch |err| {
            self.write_error = err;
            return false;
        };
        self.writer.writeAll("},\"line_number\":") catch |err| {
            self.write_error = err;
            return false;
        };
        writeOptionalU64(self.writer, line.number) catch |err| {
            self.write_error = err;
            return false;
        };
        self.writer.print(",\"absolute_offset\":{d},\"submatches\":", .{line.offset}) catch |err| {
            self.write_error = err;
            return false;
        };
        if (with_matches) {
            self.writeSubmatches(line) catch |err| {
                self.write_error = err;
                return false;
            };
        } else {
            self.writer.writeAll("[]") catch |err| {
                self.write_error = err;
                return false;
            };
        }
        self.writer.writeAll("}}\n") catch |err| {
            self.write_error = err;
            return false;
        };
        return true;
    }

    fn writeSubmatches(self: *Self, line: sink.Line) !void {
        try self.writer.writeByte('[');
        var one: [1]sink.Span = undefined;
        const spans: []const sink.Span = if (line.matches.len > 0) line.matches else blk: {
            if (line.match) |span| {
                one[0] = span;
                break :blk &one;
            }
            try self.writer.writeByte(']');
            return;
        };
        for (spans, 0..) |span, i| {
            if (i != 0) try self.writer.writeByte(',');
            const end = @min(span.end, line.bytes.len);
            const start = @min(span.start, end);
            const text = if (start < line.bytes.len) line.bytes[start..end] else "";
            try writeSubmatch(self.writer, text, span.start, span.end);
            self.matches += 1;
        }
        try self.writer.writeByte(']');
    }
};

pub const Totals = struct {
    searches: u64,
    searches_with_match: u64,
    bytes_searched: u64,
    bytes_printed: u64,
    matched_lines: u64,
    matches: u64,
};

pub fn writeSummary(writer: *std.Io.Writer, elapsed_ns: u64, totals: Totals) std.Io.Writer.Error!void {
    try writer.writeAll("{\"type\":\"summary\",\"data\":{\"elapsed_total\":");
    try writeElapsed(writer, elapsed_ns);
    try writer.writeAll(",\"stats\":{");
    try writeStats(writer, elapsed_ns, totals);
    try writer.writeAll("}}}\n");
}

fn writeStats(writer: *std.Io.Writer, elapsed_ns: u64, totals: Totals) std.Io.Writer.Error!void {
    try writer.writeAll("\"elapsed\":");
    try writeElapsed(writer, elapsed_ns);
    try writer.print(
        ",\"searches\":{d},\"searches_with_match\":{d},\"bytes_searched\":{d},\"bytes_printed\":{d},\"matched_lines\":{d},\"matches\":{d}",
        .{
            totals.searches,
            totals.searches_with_match,
            totals.bytes_searched,
            totals.bytes_printed,
            totals.matched_lines,
            totals.matches,
        },
    );
}

fn writeElapsed(writer: *std.Io.Writer, elapsed_ns: u64) std.Io.Writer.Error!void {
    const secs = elapsed_ns / std.time.ns_per_s;
    const nanos = elapsed_ns % std.time.ns_per_s;
    var human: [48]u8 = undefined;
    const text = std.fmt.bufPrint(&human, "{d}.{d:0>6}s", .{ secs, nanos / std.time.ns_per_us }) catch "0s";
    try writer.print("{{\"secs\":{d},\"nanos\":{d},\"human\":", .{ secs, nanos });
    try writeJsonString(writer, text);
    try writer.writeByte('}');
}

fn writeOptionalU64(writer: *std.Io.Writer, value: ?u64) std.Io.Writer.Error!void {
    if (value) |number| {
        try writer.print("{d}", .{number});
    } else {
        try writer.writeAll("null");
    }
}

fn writeSubmatch(writer: *std.Io.Writer, text: []const u8, start: usize, end: usize) std.Io.Writer.Error!void {
    try writer.writeAll("{\"match\":{\"text\":");
    try writeJsonString(writer, text);
    try writer.writeByte('}');
    try writer.print(",\"start\":{d},\"end\":{d}", .{ start, end });
    try writer.writeByte('}');
}

fn writeJsonStringNewline(writer: *std.Io.Writer, bytes: []const u8) std.Io.Writer.Error!void {
    try writer.writeByte('"');
    try writeJsonBody(writer, bytes);
    try writer.writeAll("\\n\"");
}

pub fn writeJsonString(writer: *std.Io.Writer, bytes: []const u8) std.Io.Writer.Error!void {
    try writer.writeByte('"');
    try writeJsonBody(writer, bytes);
    try writer.writeByte('"');
}

fn writeJsonBody(writer: *std.Io.Writer, bytes: []const u8) std.Io.Writer.Error!void {
    const hex = "0123456789abcdef";
    for (bytes) |c| switch (c) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0x00...0x08, 0x0b, 0x0c, 0x0e...0x1f => {
            try writer.writeAll("\\u00");
            try writer.writeByte(hex[c >> 4]);
            try writer.writeByte(hex[c & 0xf]);
        },
        else => try writer.writeByte(c),
    };
}

const testing = std.testing;
const searchSlice = @import("../searcher.zig").searchSlice;

test "命中行写出 begin、match 和多个子匹配，未命中不写" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var finder = try Finder.init("ab", .{});
    var printer = Json{ .writer = &out.writer, .bytes_searched = 11 };
    const hit = try searchSlice(Json, &printer, "ab ab\nno\n", "b.txt", &finder, .{ .line_numbers = true });
    try testing.expect(printer.write_error == null);
    try testing.expect(printer.started);
    try testing.expect(printer.writeEnd(0));
    const text = out.written();
    try testing.expect(std.mem.indexOf(u8, text, "{\"type\":\"begin\",\"data\":{\"path\":{\"text\":\"b.txt\"}}}\n") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"type\":\"match\"") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"line_number\":1") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"start\":0,\"end\":2") != null);
    try testing.expect(std.mem.indexOf(u8, text, "\"start\":3,\"end\":5") != null);
    try testing.expect(std.mem.indexOf(u8, text, "ab ab\\n") != null);
    try testing.expectEqual(@as(u64, 1), hit.matched_lines);
    try testing.expectEqual(@as(u64, 2), printer.matches);

    var miss_out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer miss_out.deinit();
    var miss = Json{ .writer = &miss_out.writer };
    _ = try searchSlice(Json, &miss, "nope\n", "a.txt", &finder, .{ .line_numbers = true });
    try testing.expect(!miss.started);
    try testing.expectEqual(@as(usize, 0), miss_out.written().len);
}

test "路径里的引号被转义" {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var finder = try Finder.init("a", .{});
    var printer = Json{ .writer = &out.writer };
    _ = try searchSlice(Json, &printer, "a\n", "say \"hi\".txt", &finder, .{ .line_numbers = true });
    try testing.expect(printer.writeEnd(0));
    try testing.expect(std.mem.indexOf(u8, out.written(), "say \\\"hi\\\".txt") != null);
}
