//! 标准文本打印器，输出对齐 `rg --no-config --color=never` 的行格式。
//!
//! 匹配行用 `:`，上下文行用 `-`。列号是 1 起的字节偏移，而且只在 `column` 为真、
//! 这一行带了匹配区间时才打印。普通上下文没有区间；反选里被当成上下文的模式行有。
//! 行切片不含结尾的 `\n`，这里补上。`\r` 原样保留。
//!
//! 二进制句子与 ripgrep 15 相同。`binary` 在任何行写出之前被调用时，先压住行，
//! 确认有匹配后再只写那句说明。已经写出过行时，把说明接在后面。
//! 计数模式不要用这个类型，它不会把 NUL 之后的命中算进去。

const std = @import("std");
const sink = @import("../sink.zig");

/// 把 Searcher 的回调写成文本。
/// `writer`、`show_path`、`column` 在多次 `begin` 之间保持不变，其余字段每次 `begin` 清零。
pub const Text = struct {
    writer: *std.Io.Writer,
    /// 多文件或 `-H` 时为真。路径为空时不打印路径。
    show_path: bool = false,
    /// 为真时，在有匹配区间的行上打印列号。行号本身来自 `Line.number`。
    /// 列号和行号分开设置。rg 的 `--column` 会同时打开行号，调用方要对齐时自己打开。
    column: bool = false,

    path: []const u8 = "",
    match_count: u64 = 0,
    wrote_line: bool = false,
    suppress: bool = false,
    nul_offset: ?u64 = null,
    /// 写入失败时留下的错误。搜索本身不通过 Sink 传递错误。
    write_error: ?std.Io.Writer.Error = null,

    pub fn begin(self: *Text, path: []const u8) bool {
        self.path = path;
        self.match_count = 0;
        self.wrote_line = false;
        self.suppress = false;
        self.nul_offset = null;
        self.write_error = null;
        return true;
    }

    pub fn matched(self: *Text, line: sink.Line) bool {
        self.match_count += 1;
        if (self.suppress) return false;
        return self.writeLine(line, .match);
    }

    pub fn context(self: *Text, line: sink.Line) bool {
        if (self.suppress) return true;
        return self.writeLine(line, .context);
    }

    pub fn contextBreak(self: *Text) bool {
        if (self.suppress) return true;
        if (!self.raw("--\n")) return false;
        self.wrote_line = true;
        return true;
    }

    /// 返回 false 表示不要再读这个输入。还没有匹配时返回 true，让搜索继续，
    /// 以便区分“二进制里有匹配”和“没有匹配”。
    pub fn binary(self: *Text, offset: u64) bool {
        self.nul_offset = offset;
        self.suppress = true;
        return self.match_count == 0;
    }

    pub fn finish(self: *Text, result: sink.Result) bool {
        if (self.write_error != null) return false;
        if (self.match_count == 0) return true;
        const offset = self.nul_offset orelse result.nul_offset orelse 0;
        switch (result.outcome) {
            .binary_matched => return self.writeBinary(binary_match, offset),
            .binary_quit => {
                if (!self.wrote_line) return true;
                return self.writeBinary(binary_quit, offset);
            },
            .complete, .stopped => return true,
        }
    }

    const Kind = enum { match, context };

    fn writeLine(self: *Text, line: sink.Line, kind: Kind) bool {
        const sep: u8 = if (kind == .match) ':' else '-';
        if (self.show_path and self.path.len != 0) {
            if (!self.raw(self.path)) return false;
            if (!self.raw(&.{sep})) return false;
        }
        if (line.number) |number| {
            if (!self.dec(number, sep)) return false;
        }
        if (self.column) {
            if (line.match) |span| {
                if (!self.dec(@as(u64, span.start) + 1, sep)) return false;
            }
        }
        if (!self.raw(line.bytes)) return false;
        if (!self.raw("\n")) return false;
        self.wrote_line = true;
        return true;
    }

    fn writeBinary(self: *Text, sentence: []const u8, offset: u64) bool {
        if (self.show_path and self.path.len != 0) {
            if (!self.raw(self.path)) return false;
            if (!self.raw(": ")) return false;
        }
        if (!self.raw(sentence)) return false;
        if (!self.dec(offset, ')')) return false;
        return self.raw("\n");
    }

    fn dec(self: *Text, n: u64, sep: u8) bool {
        var buf: [40]u8 = undefined;
        const text = std.fmt.bufPrint(&buf, "{d}", .{n}) catch {
            self.write_error = error.WriteFailed;
            return false;
        };
        if (!self.raw(text)) return false;
        return self.raw(&.{sep});
    }

    fn raw(self: *Text, bytes: []const u8) bool {
        self.writer.writeAll(bytes) catch |err| {
            self.write_error = err;
            return false;
        };
        return true;
    }
};

const binary_match = "binary file matches (found \"\\0\" byte around offset ";
const binary_quit = "WARNING: stopped searching binary file after match (found \"\\0\" byte around offset ";

const testing = std.testing;
const Finder = @import("../finder/finder.zig").Finder;
const SearchConfig = @import("../searcher.zig").SearchConfig;
const searchSlice = @import("../searcher.zig").searchSlice;
const searchReader = @import("../searcher.zig").searchReader;

fn run(
    hay: []const u8,
    pattern: []const u8,
    config: SearchConfig,
    show_path: bool,
    column: bool,
    name: []const u8,
) !std.Io.Writer.Allocating {
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    errdefer out.deinit();
    var text = Text{ .writer = &out.writer, .show_path = show_path, .column = column };
    var finder = try Finder.init(pattern, .{});
    const result = try searchSlice(Text, &text, hay, name, &finder, config);
    try testing.expect(text.write_error == null);
    _ = result;
    return out;
}

test "文本：行号、上下文、列号和路径" {
    var out = try run("a\nb\nMATCH\nc\nd\ne\nMATCH2\nf\n", "MATCH", .{
        .line_numbers = true,
        .before = 1,
        .after = 1,
    }, false, false, "t.txt");
    defer out.deinit();
    try testing.expectEqualStrings(
        \\2-b
        \\3:MATCH
        \\4-c
        \\--
        \\6-e
        \\7:MATCH2
        \\8-f
        \\
    , out.written());

    var plain = try run("MATCH\n", "MATCH", .{}, false, false, "t.txt");
    defer plain.deinit();
    try testing.expectEqualStrings("MATCH\n", plain.written());

    var numbered = try run("a\nMATCH\n", "MATCH", .{ .line_numbers = true }, false, false, "");
    defer numbered.deinit();
    try testing.expectEqualStrings("2:MATCH\n", numbered.written());

    var headed = try run("a\nMATCH\n", "MATCH", .{ .line_numbers = true }, true, false, "t.txt");
    defer headed.deinit();
    try testing.expectEqualStrings("t.txt:2:MATCH\n", headed.written());

    var col = try run("xxMATCHyy\n", "MATCH", .{ .line_numbers = true }, false, true, "");
    defer col.deinit();
    try testing.expectEqualStrings("1:3:xxMATCHyy\n", col.written());

    var col_path = try run("xxMATCHyy\n", "MATCH", .{ .line_numbers = true }, true, true, "col.txt");
    defer col_path.deinit();
    try testing.expectEqualStrings("col.txt:1:3:xxMATCHyy\n", col_path.written());

    var inv = try run("a\nb\nMATCH\nc\n", "MATCH", .{
        .line_numbers = true,
        .invert = true,
        .before = 1,
        .after = 1,
    }, false, true, "");
    defer inv.deinit();
    try testing.expectEqualStrings(
        \\1:a
        \\2:b
        \\3-1-MATCH
        \\4:c
        \\
    , inv.written());
}

test "文本：空行、无结尾换行、CRLF" {
    var empty_line = try run("a\n\nb\n", "b", .{ .line_numbers = true, .before = 1 }, false, false, "");
    defer empty_line.deinit();
    try testing.expectEqualStrings("2-\n3:b\n", empty_line.written());

    var no_nl = try run("foo", "foo", .{ .line_numbers = true }, false, false, "");
    defer no_nl.deinit();
    try testing.expectEqualStrings("1:foo\n", no_nl.written());

    var crlf = try run("a\r\nMATCH\r\n", "MATCH", .{ .line_numbers = true }, false, false, "");
    defer crlf.deinit();
    try testing.expectEqualStrings("2:MATCH\r\n", crlf.written());
}

test "文本：小文件里的 NUL 只报告一句" {
    var out = try run("xxMATCH\x00yy\n", "MATCH", .{ .line_numbers = true }, false, false, "bin.txt");
    defer out.deinit();
    try testing.expectEqualStrings("binary file matches (found \"\\0\" byte around offset 7)\n", out.written());

    var headed = try run("xxMATCH\x00yy\n", "MATCH", .{}, true, false, "bin.txt");
    defer headed.deinit();
    try testing.expectEqualStrings("bin.txt: binary file matches (found \"\\0\" byte around offset 7)\n", headed.written());

    var miss = try run("xx\x00yy\n", "MATCH", .{}, false, false, "");
    defer miss.deinit();
    try testing.expectEqualStrings("", miss.written());

    var as_text = try run("xxMATCH\x00yy\n", "MATCH", .{ .line_numbers = true, .binary = .none }, false, false, "");
    defer as_text.deinit();
    try testing.expectEqualStrings("1:xxMATCH\x00yy\n", as_text.written());
}

test "文本：跨块时先打印命中，再补二进制说明" {
    const hay = "MATCH\nfoo\x00\n";
    var reader = std.Io.Reader.fixed(hay);
    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var text = Text{ .writer = &out.writer };
    var finder = try Finder.init("MATCH", .{});
    const reported = try searchReader(Text, testing.allocator, &text, &reader, "", &finder, .{
        .line_numbers = true,
        .buffer_size = 8,
        .max_line_len = 64,
        .binary = .report,
    });
    try testing.expectEqualStrings("1:MATCH\nbinary file matches (found \"\\0\" byte around offset 9)\n", out.written());
    try testing.expectEqual(sink.Outcome.binary_matched, reported.outcome);

    var reader_q = std.Io.Reader.fixed(hay);
    var out_q: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out_q.deinit();
    var text_q = Text{ .writer = &out_q.writer };
    var finder_q = try Finder.init("MATCH", .{});
    const quit = try searchReader(Text, testing.allocator, &text_q, &reader_q, "p", &finder_q, .{
        .line_numbers = true,
        .buffer_size = 8,
        .max_line_len = 64,
        .binary = .quit,
    });
    try testing.expectEqualStrings("1:MATCH\nWARNING: stopped searching binary file after match (found \"\\0\" byte around offset 9)\n", out_q.written());
    try testing.expectEqual(sink.Outcome.binary_quit, quit.outcome);
}
