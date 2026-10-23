//! 测试用的库外 NDJSON 编码器。
//! 不从 `src/root.zig` 导出。序列化留在库外，core 只提供事件字段。

const std = @import("std");
const searcher = @import("searcher.zig");

const Event = searcher.Event;
const testing = std.testing;

fn writeString(writer: *std.Io.Writer, text: []const u8) !void {
    try writer.writeByte('"');
    for (text) |b| switch (b) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        else => if (b < 0x20) {
            try writer.print("\\u{x:0>4}", .{b});
        } else try writer.writeByte(b),
    };
    try writer.writeByte('"');
}

fn writeStatus(writer: *std.Io.Writer, status: searcher.BinaryStatus) !void {
    const name = switch (status) {
        .none => "none",
        .detected => "detected",
        .suppressed => "suppressed",
    };
    try writeString(writer, name);
}

/// 把一条事件写成一行 JSON。字段和事件结构一一对应，调用方可以再解析回来。
pub fn writeEvent(writer: *std.Io.Writer, ev: Event) !void {
    switch (ev) {
        .begin => |b| {
            try writer.writeAll("{\"type\":\"begin\",\"source_id\":");
            try writeString(writer, b.source_id);
            try writer.writeAll("}\n");
        },
        .context_break => |b| {
            try writer.writeAll("{\"type\":\"context_break\",\"source_id\":");
            try writeString(writer, b.source_id);
            try writer.writeAll("}\n");
        },
        .progress => |p| {
            try writer.writeAll("{\"type\":\"progress\",\"source_id\":");
            try writeString(writer, p.source_id);
            try writer.print(
                ",\"bytes_searched\":{d},\"matches\":{d},\"matched_lines\":{d}}}\n",
                .{ p.bytes_searched, p.matches, p.matched_lines },
            );
        },
        .heartbeat => |h| {
            try writer.writeAll("{\"type\":\"heartbeat\",\"source_id\":");
            try writeString(writer, h.source_id);
            try writer.print(
                ",\"bytes_searched\":{d},\"matches\":{d},\"matched_lines\":{d}}}\n",
                .{ h.bytes_searched, h.matches, h.matched_lines },
            );
        },
        .end => |e| {
            try writer.writeAll("{\"type\":\"end\",\"source_id\":");
            try writeString(writer, e.source_id);
            try writer.print(
                ",\"matched_lines\":{d},\"matches\":{d},\"bytes_read\":{d},\"partial\":{s},\"limit_hit\":\"{s}\"}}\n",
                .{ e.matched_lines, e.matches, e.bytes_read, if (e.partial) "true" else "false", @tagName(e.limit_hit) },
            );
        },
        .summary => |s| {
            try writer.writeAll("{\"type\":\"summary\",\"source_id\":");
            try writeString(writer, s.source_id);
            try writer.print(
                ",\"elapsed\":{d},\"searches\":{d},\"searches_with_match\":{d},\"bytes_searched\":{d},\"bytes_printed\":{d},\"matched_lines\":{d},\"matches\":{d},\"bytes_read_raw\":{d},\"sources_failed\":{d}}}\n",
                .{
                    s.elapsed,
                    s.searches,
                    s.searches_with_match,
                    s.bytes_searched,
                    s.bytes_printed,
                    s.matched_lines,
                    s.matches,
                    s.bytes_read_raw,
                    s.sources_failed,
                },
            );
        },
        .match, .context => |line| {
            const kind = switch (ev) {
                .match => "match",
                .context => "context",
                else => unreachable,
            };
            try writer.print("{{\"type\":\"{s}\",\"source_id\":", .{kind});
            try writeString(writer, line.source_id);
            try writer.print(",\"line_number\":{d},\"absolute_offset\":{d},\"bytes\":", .{ line.line_number, line.absolute_offset });
            try writeString(writer, line.bytes);
            try writer.writeAll(",\"column\":");
            if (line.column) |col| try writer.print("{d}", .{col}) else try writer.writeAll("null");
            try writer.writeAll(",\"matches\":[");
            for (line.matches, 0..) |span, i| {
                if (i != 0) try writer.writeByte(',');
                try writer.print(
                    "{{\"start\":{d},\"end\":{d},\"u16_start\":{d},\"u16_end\":{d}}}",
                    .{ span.start, span.end, span.u16_start, span.u16_end },
                );
            }
            try writer.print("],\"truncated\":{s},\"line_len\":{d},\"window_start\":{d},\"binary_status\":", .{
                if (line.truncated) "true" else "false",
                line.line_len,
                line.window_start,
            });
            try writeStatus(writer, line.binary_status);
            try writer.writeAll("}\n");
        },
    }
}

const SpanRow = struct {
    start: usize,
    end: usize,
    u16_start: usize,
    u16_end: usize,
};

const MatchRow = struct {
    @"type": []const u8,
    source_id: []const u8,
    line_number: u64,
    column: ?u64 = null,
    absolute_offset: u64,
    bytes: []const u8,
    matches: []SpanRow,
    truncated: bool,
    line_len: u64,
    window_start: u64,
    binary_status: []const u8,
};

const EndRow = struct {
    @"type": []const u8,
    source_id: []const u8,
    matched_lines: u64,
    matches: u64,
    bytes_read: u64,
    partial: bool,
    limit_hit: []const u8,
};

const SummaryRow = struct {
    @"type": []const u8,
    source_id: []const u8,
    elapsed: u64,
    searches: u64,
    searches_with_match: u64,
    bytes_searched: u64,
    bytes_printed: u64,
    matched_lines: u64,
    matches: u64,
    bytes_read_raw: u64,
    sources_failed: u64,
};

test "事件可被库外编码器写成 NDJSON" {
    const Capture = struct {
        lines: std.ArrayList([]u8) = .empty,

        fn deinit(self: *@This()) void {
            for (self.lines.items) |line| testing.allocator.free(line);
            self.lines.deinit(testing.allocator);
        }

        pub fn event(self: *@This(), ev: Event) bool {
            var out: std.Io.Writer.Allocating = .init(testing.allocator);
            defer out.deinit();
            writeEvent(&out.writer, ev) catch unreachable;
            const text = testing.allocator.dupe(u8, out.written()) catch unreachable;
            self.lines.append(testing.allocator, text) catch unreachable;
            return true;
        }
    };
    var cap = Capture{};
    defer cap.deinit();
    var finder = try @import("finder/finder.zig").Finder.init("ab", .{});
    const result = try searcher.searchSourceSlice(Capture, &cap, "say \"hi\"", "abXab\n", &finder, .{
        .binary = .none,
    });
    try testing.expectEqual(@as(u64, 1), result.matched_lines);
    try testing.expectEqual(@as(u64, 2), result.matches);
    try testing.expect(cap.lines.items.len >= 3);

    const match_parsed = try std.json.parseFromSlice(MatchRow, testing.allocator, cap.lines.items[1], .{});
    defer match_parsed.deinit();
    try testing.expectEqualStrings("match", match_parsed.value.@"type");
    try testing.expectEqualStrings("say \"hi\"", match_parsed.value.source_id);
    try testing.expectEqual(@as(u64, 1), match_parsed.value.line_number);
    try testing.expectEqual(@as(?u64, 1), match_parsed.value.column);
    try testing.expectEqual(@as(u64, 0), match_parsed.value.absolute_offset);
    try testing.expectEqualStrings("abXab", match_parsed.value.bytes);
    try testing.expectEqual(@as(usize, 2), match_parsed.value.matches.len);
    try testing.expectEqual(@as(usize, 0), match_parsed.value.matches[0].start);
    try testing.expectEqual(@as(usize, 2), match_parsed.value.matches[0].end);
    try testing.expectEqual(@as(usize, 3), match_parsed.value.matches[1].start);
    try testing.expectEqual(@as(usize, 5), match_parsed.value.matches[1].end);
    try testing.expect(!match_parsed.value.truncated);
    try testing.expectEqualStrings("none", match_parsed.value.binary_status);

    const end_parsed = try std.json.parseFromSlice(EndRow, testing.allocator, cap.lines.items[2], .{});
    defer end_parsed.deinit();
    try testing.expectEqualStrings("end", end_parsed.value.@"type");
    try testing.expectEqualStrings("say \"hi\"", end_parsed.value.source_id);
    try testing.expectEqual(@as(u64, 1), end_parsed.value.matched_lines);
    try testing.expectEqual(@as(u64, 2), end_parsed.value.matches);
    try testing.expect(!end_parsed.value.partial);
    try testing.expectEqualStrings("none", end_parsed.value.limit_hit);

    const summary_parsed = try std.json.parseFromSlice(SummaryRow, testing.allocator, cap.lines.items[3], .{});
    defer summary_parsed.deinit();
    try testing.expectEqualStrings("summary", summary_parsed.value.@"type");
    try testing.expectEqual(@as(u64, 1), summary_parsed.value.searches);
    try testing.expectEqual(@as(u64, 1), summary_parsed.value.searches_with_match);
    try testing.expectEqual(@as(u64, 1), summary_parsed.value.matched_lines);
    try testing.expectEqual(@as(u64, 2), summary_parsed.value.matches);
    try testing.expect(summary_parsed.value.bytes_searched > 0);
    try testing.expect(summary_parsed.value.bytes_printed > 0);
    try testing.expectEqual(summary_parsed.value.bytes_searched, summary_parsed.value.bytes_read_raw);
    try testing.expectEqual(@as(u64, 0), summary_parsed.value.sources_failed);
}
