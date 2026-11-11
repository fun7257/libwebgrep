const std = @import("std");
const testing = std.testing;

const searcher = @import("../searcher.zig");
const sink_mod = @import("../sink.zig");
const source_mod = @import("../source.zig");
const decompress_mod = @import("../codec/decompress.zig");
const Finder = @import("../finder/finder.zig").Finder;
const pull_mod = @import("pull.zig");
const ignore_mod = @import("../walk/ignore.zig");
const walker_mod = @import("../walk/walker.zig");
const glob_mod = @import("../walk/glob.zig");
const encoding_mod = @import("../codec/encoding.zig");
const format_mod = @import("format.zig");
const state_mod = @import("state.zig");
const config_mod = @import("config.zig");
const context_ring_mod = @import("context_ring.zig");
const Span = sink_mod.Span;
const Event = sink_mod.Event;

const OneByteReader = struct {
    reader: std.Io.Reader,
    data: []const u8,
    pos: usize = 0,

    const vtable: std.Io.Reader.VTable = .{
        .stream = streamFn,
    };

    pub fn init(data: []const u8) OneByteReader {
        return .{
            .reader = .{
                .vtable = &vtable,
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },
            .data = data,
            .pos = 0,
        };
    }

    fn streamFn(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *OneByteReader = @fieldParentPtr("reader", r);
        if (self.pos >= self.data.len) return error.EndOfStream;
        const max_len = limit.minInt(1);
        if (max_len == 0) return 0;
        const n = try w.write(self.data[self.pos .. self.pos + 1]);
        self.pos += n;
        return n;
    }
};

test "vector 1.1: fragmented 1-byte stream reading UTF-8 identical to slice pull" {
    const raw_utf8 =
        "line 1: ascii header\n" ++
        "line 2: café résumé naïve\n" ++
        "line 3: before context\r\n" ++
        "日本語のテキストで検索テスト: match 日本語 here!\r\n" ++
        "line 5: after context 🚀✨\n";

    var finder = try Finder.init("日本語", .{});

    var ref_pull = pull_mod.openSourcePull(testing.allocator, &finder, "vec-1-1", raw_utf8, .{
        .before = 1,
        .after = 1,
    });
    defer ref_pull.deinit();

    var one_byte = OneByteReader.init(raw_utf8);
    var target_pull = try pull_mod.openReaderPull(testing.allocator, &finder, "vec-1-1", &one_byte.reader, .{
        .before = 1,
        .after = 1,
    });
    defer target_pull.deinit();

    var event_count: usize = 0;
    while (try ref_pull.next()) |ref_ev| {
        const tgt_ev = (try target_pull.next()) orelse return error.TestUnexpectedResult;
        event_count += 1;
        try testing.expectEqual(ref_ev.kind, tgt_ev.kind);
        try testing.expectEqualStrings(ref_ev.source_id, tgt_ev.source_id);
        if (ref_ev.kind == .match or ref_ev.kind == .context) {
            try testing.expectEqual(ref_ev.line_number, tgt_ev.line_number);
            try testing.expectEqual(ref_ev.absolute_offset, tgt_ev.absolute_offset);
            try testing.expectEqual(ref_ev.raw_offset, tgt_ev.raw_offset);
            try testing.expectEqualStrings(ref_ev.bytes, tgt_ev.bytes);
            try testing.expectEqual(ref_ev.spans.len, tgt_ev.spans.len);
            for (ref_ev.spans, tgt_ev.spans) |rm, tm| {
                try testing.expectEqual(rm.start, tm.start);
                try testing.expectEqual(rm.end, tm.end);
                try testing.expectEqual(rm.pattern_id, tm.pattern_id);
                try testing.expectEqual(rm.u16_start, tm.u16_start);
                try testing.expectEqual(rm.u16_end, tm.u16_end);
            }
        }
    }
    try testing.expect((try target_pull.next()) == null);
    try testing.expect(event_count >= 3);
}

fn encodeUtf16LeWithBom(allocator: std.mem.Allocator, utf8: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, &[_]u8{ 0xFF, 0xFE });
    var view = try std.unicode.Utf8View.init(utf8);
    var it = view.iterator();
    while (it.nextCodepoint()) |cp| {
        if (cp <= 0xFFFF) {
            var buf: [2]u8 = undefined;
            std.mem.writeInt(u16, &buf, @intCast(cp), .little);
            try out.appendSlice(allocator, &buf);
        } else {
            const adj = cp - 0x10000;
            const high: u16 = @intCast(0xD800 + (adj >> 10));
            const low: u16 = @intCast(0xDC00 + (adj & 0x3FF));
            var buf: [4]u8 = undefined;
            std.mem.writeInt(u16, buf[0..2], high, .little);
            std.mem.writeInt(u16, buf[2..4], low, .little);
            try out.appendSlice(allocator, &buf);
        }
    }
    return out.toOwnedSlice(allocator);
}

test "vector 1.2: fragmented 1-byte stream reading UTF-16LE identical to slice search" {
    const utf8_text = "header line\nmatch 😀 target here\ntrailer line\n";
    const utf16_bytes = try encodeUtf16LeWithBom(testing.allocator, utf8_text);
    defer testing.allocator.free(utf16_bytes);

    var finder = try Finder.init("target", .{});

    var ref_pull = pull_mod.openSourcePull(testing.allocator, &finder, "vec-1-2", utf16_bytes, .{
        .allocator = testing.allocator,
        .encoding = .auto,
    });
    defer ref_pull.deinit();

    var ref_matches: usize = 0;
    var ref_line: u64 = 0;
    var ref_raw: u64 = 0;
    while (try ref_pull.next()) |ev| {
        if (ev.kind == .match) {
            ref_matches += 1;
            ref_line = ev.line_number;
            ref_raw = ev.raw_offset;
        }
    }
    try testing.expectEqual(@as(usize, 1), ref_matches);

    var one_byte = OneByteReader.init(utf16_bytes);
    var pull = try pull_mod.openReaderPull(testing.allocator, &finder, "vec-1-2", &one_byte.reader, .{
        .encoding = .auto,
    });
    defer pull.deinit();

    var stream_matches: usize = 0;
    while (try pull.next()) |ev| {
        if (ev.kind == .match) {
            stream_matches += 1;
            try testing.expectEqual(ref_line, ev.line_number);
            try testing.expectEqual(ref_raw, ev.raw_offset);
            try testing.expectEqualStrings("match 😀 target here", ev.bytes);
        }
    }
    try testing.expectEqual(ref_matches, stream_matches);
}

test "vector 1.3: fragmented 1-byte stream reading GBK across chunk boundaries" {
    // GBK for "中文测试: match 成功\n":
    // 中(D6 D0) 文(CE C4) 测(B2 E2) 试(CA D4) ": match " 成(B3 C9) 功(B9 A6) "\n"
    const gbk_bytes = [_]u8{
        'h',  'e',  'a',  'd',  '\n',
        0xD6, 0xD0, 0xCE, 0xC4, 0xB2, 0xE2, 0xCA, 0xD4,
        ':',  ' ',  'm',  'a',  't',  'c',  'h',  ' ',
        0xB3, 0xC9, 0xB9, 0xA6, '\n',
    };

    var finder = try Finder.init("成功", .{});
    var one_byte = OneByteReader.init(&gbk_bytes);
    var pull = try pull_mod.openReaderPull(testing.allocator, &finder, "vec-1-3", &one_byte.reader, .{
        .charset = "gbk",
    });
    defer pull.deinit();

    var matches: usize = 0;
    while (try pull.next()) |ev| {
        if (ev.kind == .match) {
            matches += 1;
            try testing.expectEqual(@as(u64, 2), ev.line_number);
            try testing.expectEqual(@as(u64, 5), ev.raw_offset);
            try testing.expectEqualStrings("中文测试: match 成功", ev.bytes);
        }
    }
    try testing.expectEqual(@as(usize, 1), matches);
}

test "vector 2.1: Gzip compression bomb triggers ratio and size limits" {
    // Construct a payload > 1024 bytes and compress with Stored Gzip, then enforce max_decompressed_bytes = 256
    const payload = try testing.allocator.alloc(u8, 4096);
    defer testing.allocator.free(payload);
    @memset(payload, 'A');
    payload[50] = '\n';
    @memcpy(payload[0..6], "needle");

    const gz = try decompress_mod.compressGzipStoredAlloc(testing.allocator, payload);
    defer testing.allocator.free(gz);

    var finder = try Finder.init("needle", .{});
    var reader = std.Io.Reader.fixed(gz);
    var pull = try pull_mod.openReaderPull(testing.allocator, &finder, "vec-2-1", &reader, .{
        .compression = .gzip,
        .max_decompressed_bytes = 256,
    });
    defer pull.deinit();

    var saw_end = false;
    while (try pull.next()) |ev| {
        if (ev.kind == .end) {
            saw_end = true;
            try testing.expectEqual(sink_mod.LimitHit.decompressed_bytes, ev.limit_hit);
            try testing.expect(ev.partial);
        }
    }
    try testing.expect(saw_end);
}

test "vector 3: early drop on streaming ReaderPull frees all buffers with zero leaks" {
    const raw =
        "context 1\n" ++
        "context 2\n" ++
        "match 1: alpha\n" ++
        "context 3\n" ++
        "match 2: beta\n";
    var finder = try Finder.init("match", .{});

    // 1. Drop immediately after openReaderPull without calling next()
    {
        var r1 = std.Io.Reader.fixed(raw);
        var pull1 = try pull_mod.openReaderPull(testing.allocator, &finder, "vec-3-a", &r1, .{
            .before = 2,
            .after = 2,
            .replacement = "REPL",
        });
        pull1.deinit();
    }

    // 2. Drop after consuming only begin + first match
    {
        var r2 = std.Io.Reader.fixed(raw);
        var pull2 = try pull_mod.openReaderPull(testing.allocator, &finder, "vec-3-b", &r2, .{
            .before = 2,
            .after = 2,
            .replacement = "REPL",
        });
        _ = try pull2.next(); // begin
        _ = try pull2.next(); // context 1
        _ = try pull2.next(); // context 2
        const m = (try pull2.next()).?;
        try testing.expectEqual(m.kind, .match);
        pull2.deinit();
    }
}

test "vector 4.1: source.Memory chunked 1-byte read until EOF and read past EOF" {
    const payload = "0123456789abcdef";
    const file = source_mod.Node{ .name = "data.bin", .kind = .file, .bytes = payload };
    const root = source_mod.Node{ .name = "", .kind = .directory, .children = &.{&file} };
    var mem = source_mod.Memory{ .root = &root };
    const src = mem.source();

    const h = try src.open(testing.io, "data.bin");
    defer src.close(testing.io, h);

    var assembled: [payload.len]u8 = undefined;
    var i: usize = 0;
    while (i < payload.len) : (i += 1) {
        var one: [1]u8 = undefined;
        const n = try src.read(testing.io, h, &one);
        try testing.expectEqual(@as(usize, 1), n);
        assembled[i] = one[0];
    }
    try testing.expectEqualStrings(payload, &assembled);

    // Subsequent reads at and past EOF return 0
    var extra: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), try src.read(testing.io, h, &extra));
    try testing.expectEqual(@as(usize, 0), try src.read(testing.io, h, &extra));
}

test "vector 4.2: source.Memory batched 1-entry list until 0" {
    const f1 = source_mod.Node{ .name = "a.txt", .kind = .file, .bytes = "a" };
    const f2 = source_mod.Node{ .name = "b.txt", .kind = .file, .bytes = "b" };
    const f3 = source_mod.Node{ .name = "c.txt", .kind = .file, .bytes = "c" };
    const f4 = source_mod.Node{ .name = "d.txt", .kind = .file, .bytes = "d" };
    const root = source_mod.Node{ .name = "", .kind = .directory, .children = &.{ &f1, &f2, &f3, &f4 } };
    var mem = source_mod.Memory{ .root = &root };
    const src = mem.source();

    const h = try src.open(testing.io, "");
    defer src.close(testing.io, h);

    const expected = [_][]const u8{ "a.txt", "b.txt", "c.txt", "d.txt" };
    for (expected) |want| {
        var entry: [1]source_mod.Entry = undefined;
        const n = try src.list(testing.io, h, &entry);
        try testing.expectEqual(@as(usize, 1), n);
        try testing.expectEqualStrings(want, entry[0].name);
    }

    var tail: [1]source_mod.Entry = undefined;
    try testing.expectEqual(@as(usize, 0), try src.list(testing.io, h, &tail));
    try testing.expectEqual(@as(usize, 0), try src.list(testing.io, h, &tail));
}

test "vector 4.3: source.Memory handle exhaustion (64 max handles) and reuse" {
    const f = source_mod.Node{ .name = "f.txt", .kind = .file, .bytes = "ok" };
    const root = source_mod.Node{ .name = "", .kind = .directory, .children = &.{&f} };
    var mem = source_mod.Memory{ .root = &root };
    const src = mem.source();

    var handles: [64]usize = undefined;
    for (&handles) |*h| {
        h.* = try src.open(testing.io, "f.txt");
    }
    try testing.expectError(error.SystemResources, src.open(testing.io, "f.txt"));

    // Close two handles and verify they can be re-acquired and independently read
    src.close(testing.io, handles[7]);
    src.close(testing.io, handles[42]);

    const h_a = try src.open(testing.io, "f.txt");
    const h_b = try src.open(testing.io, "f.txt");
    try testing.expectEqual(handles[7], h_a);
    try testing.expectEqual(handles[42], h_b);
    try testing.expectError(error.SystemResources, src.open(testing.io, "f.txt"));

    for (handles) |h| src.close(testing.io, h);
}

test "vector 5.1: complex hierarchical .gitignore with parent negation and child override" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var root_globs: std.ArrayList(glob_mod.Glob) = .empty;
    try ignore_mod.parseInto(arena, "*.log\n!important.log\nbuild/\n", &root_globs);
    const root_set = try ignore_mod.build(arena, testing.allocator, null, 0, &.{}, root_globs.items);

    var sub_globs: std.ArrayList(glob_mod.Glob) = .empty;
    try ignore_mod.parseInto(arena, "important.log\n!local_keep.log\n", &sub_globs);
    const sub_set = try ignore_mod.build(arena, testing.allocator, &root_set, 3, &.{}, sub_globs.items);

    var scratch: [256]u8 = undefined;
    // At root: *.log is ignored except important.log; build/ and its descendants are ignored
    try testing.expect(ignore_mod.isIgnored(&root_set, "debug.log", false, &scratch));
    try testing.expect(!ignore_mod.isIgnored(&root_set, "important.log", false, &scratch));
    try testing.expect(ignore_mod.isIgnored(&root_set, "build/important.log", false, &scratch));

    // In sub/: child overrides !important.log back to ignored, and un-ignores local_keep.log
    try testing.expect(ignore_mod.isIgnored(&sub_set, "sub/debug.log", false, &scratch));
    try testing.expect(ignore_mod.isIgnored(&sub_set, "sub/important.log", false, &scratch));
    try testing.expect(!ignore_mod.isIgnored(&sub_set, "sub/local_keep.log", false, &scratch));
}

test "vector 5.2: tree depth limit max_depth = 2 on 5-level nested directory" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;

    try tmp.dir.writeFile(io, .{ .sub_path = "l1.txt", .data = "level1" });
    try tmp.dir.createDir(io, "d1", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "d1/l2.txt", .data = "level2" });
    try tmp.dir.createDir(io, "d1/d2", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "d1/d2/l3.txt", .data = "level3" });
    try tmp.dir.createDir(io, "d1/d2/d3", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "d1/d2/d3/l4.txt", .data = "level4" });
    try tmp.dir.createDir(io, "d1/d2/d3/d4", .default_dir);
    try tmp.dir.writeFile(io, .{ .sub_path = "d1/d2/d3/d4/l5.txt", .data = "level5" });

    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const root_path = path_buf[0..path_len];

    var session = walker_mod.Session.init(testing.allocator);
    defer session.deinit();
    var stop = std.atomic.Value(bool).init(false);
    var stack: std.ArrayList(*walker_mod.Job) = .empty;
    defer stack.deinit(testing.allocator);
    var found: std.ArrayList([]u8) = .empty;
    defer {
        for (found.items) |p| testing.allocator.free(p);
        found.deinit(testing.allocator);
    }

    const WalkHelpers = struct {
        fn push(ctx: *anyopaque, j: *walker_mod.Job) !void {
            const s: *std.ArrayList(*walker_mod.Job) = @ptrCast(@alignCast(ctx));
            try s.append(testing.allocator, j);
        }
        fn onFile(ctx: *anyopaque, v: walker_mod.Visit) !walker_mod.Control {
            const list: *std.ArrayList([]u8) = @ptrCast(@alignCast(ctx));
            try list.append(testing.allocator, try testing.allocator.dupe(u8, v.path));
            return .cont;
        }
        fn onError(_: *anyopaque, _: []const u8, _: anyerror) void {}
    };

    var host = walker_mod.Host{
        .allocator = testing.allocator,
        .io = io,
        .config = .{ .max_depth = 2 },
        .session = &session,
        .stop = &stop,
        .push = WalkHelpers.push,
        .push_ctx = &stack,
        .on_file = WalkHelpers.onFile,
        .file_ctx = &found,
        .on_error = WalkHelpers.onError,
        .error_ctx = undefined,
    };

    const root_job = try walker_mod.createRoot(&host, root_path);
    try stack.append(testing.allocator, root_job);
    while (stack.pop()) |job| walker_mod.process(&host, job);

    try testing.expectEqual(@as(usize, 2), found.items.len);
    var saw_l1 = false;
    var saw_l2 = false;
    for (found.items) |p| {
        if (std.mem.endsWith(u8, p, "/l1.txt")) saw_l1 = true;
        if (std.mem.endsWith(u8, p, "/l2.txt")) saw_l2 = true;
        try testing.expect(!std.mem.endsWith(u8, p, "/l3.txt"));
        try testing.expect(!std.mem.endsWith(u8, p, "/l4.txt"));
        try testing.expect(!std.mem.endsWith(u8, p, "/l5.txt"));
    }
    try testing.expect(saw_l1);
    try testing.expect(saw_l2);
}

// ============================================================================
// EMPIRICAL CHALLENGER STRESS TESTS: MILESTONE 1
// ============================================================================

test "M1 CHALLENGE 1: gatherSpans collects all spans for 1, 2, 5, 20, 65, 100, 256 spans" {
    const target_counts = [_]usize{ 1, 2, 5, 20, 65, 100, 256 };
    for (target_counts) |count| {
        // Build a line with exact `count` occurrences of "TARGET "
        var line_buf = std.ArrayList(u8).empty;
        defer line_buf.deinit(testing.allocator);
        for (0..count) |_| {
            try line_buf.appendSlice(testing.allocator, "TARGET ");
        }
        try line_buf.appendSlice(testing.allocator, "\n");
        const line_str = line_buf.items;

        var finder = try Finder.init("TARGET", .{});

        // Test with replacement == null (critical regression check for worker's reverted short-circuit)
        const SpanCounterSink = struct {
            match_events: usize = 0,
            spans_count: usize = 0,
            spans_valid: bool = true,
            pub fn event(self: *@This(), ev: Event) bool {
                if (ev == .match) {
                    self.match_events += 1;
                    self.spans_count = ev.match.matches.len;
                    for (ev.match.matches, 0..) |s, i| {
                        const expected_start = i * 7;
                        const expected_end = i * 7 + 6;
                        if (s.start != expected_start or s.end != expected_end) {
                            self.spans_valid = false;
                        }
                    }
                }
                return true;
            }
        };

        var sink = SpanCounterSink{};
        const res = try searcher.searchSourceSlice(SpanCounterSink, &sink, "m1-gather-null-repl", line_str, &finder, .{
            .allocator = testing.allocator,
        });

        try testing.expectEqual(@as(usize, 1), sink.match_events);
        try testing.expectEqual(count, sink.spans_count);
        try testing.expect(sink.spans_valid);
        try testing.expectEqual(@as(u64, 1), res.matched_lines);
        try testing.expectEqual(@as(u64, count), res.matches);

        // Also test with replacement set
        var sink_repl = SpanCounterSink{};
        const res_repl = try searcher.searchSourceSlice(SpanCounterSink, &sink_repl, "m1-gather-repl", line_str, &finder, .{
            .allocator = testing.allocator,
            .replacement = "REPL",
        });

        try testing.expectEqual(@as(usize, 1), sink_repl.match_events);
        try testing.expectEqual(count, sink_repl.spans_count);
        try testing.expect(sink_repl.spans_valid);
        try testing.expectEqual(@as(u64, 1), res_repl.matched_lines);
        try testing.expectEqual(@as(u64, count), res_repl.matches);
    }
}

test "M1 CHALLENGE 2: state.matches tallies all spans across multi-line inputs with variable span density" {
    // Multi-line file:
    // Line 1: 1 match
    // Line 2: 2 matches
    // Line 3: 5 matches
    // Line 4: 20 matches
    // Line 5: 75 matches (>64)
    // Line 6: 0 matches (interspersed context / non-matching)
    // Line 7: 10 matches
    const counts = [_]usize{ 1, 2, 5, 20, 75, 0, 10 };
    var total_expected_matches: usize = 0;
    var total_expected_lines: usize = 0;
    var file_buf = std.ArrayList(u8).empty;
    defer file_buf.deinit(testing.allocator);

    for (counts) |c| {
        if (c > 0) {
            total_expected_matches += c;
            total_expected_lines += 1;
            for (0..c) |_| {
                try file_buf.appendSlice(testing.allocator, "HIT ");
            }
        } else {
            try file_buf.appendSlice(testing.allocator, "no-match-here on this line");
        }
        try file_buf.appendSlice(testing.allocator, "\n");
    }

    var finder = try Finder.init("HIT", .{});

    const TallySink = struct {
        lines_seen: usize = 0,
        matches_tallied: usize = 0,
        summary_matches: usize = 0,
        summary_lines: usize = 0,
        end_matches: usize = 0,
        end_lines: usize = 0,
        pub fn event(self: *@This(), ev: Event) bool {
            switch (ev) {
                .match => |m| {
                    self.lines_seen += 1;
                    self.matches_tallied += m.matches.len;
                },
                .end => |e| {
                    self.end_matches = @intCast(e.matches);
                    self.end_lines = @intCast(e.matched_lines);
                },
                .summary => |s| {
                    self.summary_matches = @intCast(s.matches);
                    self.summary_lines = @intCast(s.matched_lines);
                },
                else => {},
            }
            return true;
        }
    };

    var sink = TallySink{};
    const res = try searcher.searchSourceSlice(TallySink, &sink, "m1-tally", file_buf.items, &finder, .{
        .allocator = testing.allocator,
    });

    try testing.expectEqual(total_expected_lines, sink.lines_seen);
    try testing.expectEqual(total_expected_matches, sink.matches_tallied);
    try testing.expectEqual(total_expected_matches, sink.summary_matches);
    try testing.expectEqual(total_expected_lines, sink.summary_lines);
    try testing.expectEqual(total_expected_matches, sink.end_matches);
    try testing.expectEqual(total_expected_lines, sink.end_lines);
    try testing.expectEqual(@as(u64, total_expected_lines), res.matched_lines);
    try testing.expectEqual(@as(u64, total_expected_matches), res.matches);
}

test "M1 CHALLENGE 3: ASCII fast path in buildLine (isAsciiSlice == true) preserves column & byte equality" {
    const ascii_line = "alpha FOO beta BAR gamma BAZ delta FOO end\n";
    try testing.expect(encoding_mod.isAsciiSlice(ascii_line));

    const Multi = @import("../finder/multi.zig").Multi;
    var multi = try Multi.init(testing.allocator, &.{ "FOO", "BAR", "BAZ" }, .{});
    defer multi.deinit();

    const LineCaptureSink = struct {
        u16_all_equal_byte: bool = true,
        span_count: usize = 0,
        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) {
                self.span_count = ev.match.matches.len;
                for (ev.match.matches) |s| {
                    if (s.u16_start != s.start or s.u16_end != s.end) {
                        self.u16_all_equal_byte = false;
                    }
                }
                // Verify column calculation
                if (ev.match.matches.len > 0) {
                    if (ev.match.column != ev.match.matches[0].start + 1) self.u16_all_equal_byte = false;
                    if (ev.match.u16_column != ev.match.matches[0].u16_start + 1) self.u16_all_equal_byte = false;
                }
            }
            return true;
        }
    };

    var sink = LineCaptureSink{};
    const res = try searcher.searchSourceSlice(LineCaptureSink, &sink, "m1-ascii", ascii_line, &multi, .{
        .allocator = testing.allocator,
    });

    try testing.expectEqual(@as(u64, 1), res.matched_lines);
    try testing.expectEqual(@as(u64, 4), res.matches); // 2x FOO, 1x BAR, 1x BAZ
    try testing.expectEqual(@as(usize, 4), sink.span_count);
    try testing.expect(sink.u16_all_equal_byte);
}

test "M1 CHALLENGE 4: UTF-8 multibyte CJK and Greek fallback accurately computes UTF-16 code units" {
    // Chinese characters are 3 bytes each in UTF-8, 1 code unit in UTF-16
    // "开源项目: libwebgrep 高性能文本搜索! 支持多模式搜索.\n"
    const utf8_cjk = "开源项目: libwebgrep 高性能文本搜索! 支持多模式搜索.\n";
    try testing.expect(!encoding_mod.isAsciiSlice(utf8_cjk));

    var finder = try Finder.init("搜索", .{});

    // Oracle calculation:
    // Prefix: "开源项目: libwebgrep 高性能文本"
    // "开源项目" = 4 chars * 3 bytes = 12 bytes; 4 UTF-16 units
    // ": " = 2 bytes; 2 UTF-16 units
    // "libwebgrep " = 11 bytes; 11 UTF-16 units
    // "高性能文本" = 5 chars * 3 bytes = 15 bytes; 5 UTF-16 units
    // Match 1 "搜索":
    // byte_start = 12 + 2 + 11 + 15 = 40
    // byte_end = 40 + 6 = 46
    // u16_start = 4 + 2 + 11 + 5 = 22
    // u16_end = 22 + 2 = 24
    // Intermediate: "! 支持多模式"
    // "!" = 1 byte; 1 UTF-16 unit
    // " " = 1 byte; 1 UTF-16 unit
    // "支持多模式" = 5 chars * 3 bytes = 15 bytes; 5 UTF-16 units
    // Match 2 "搜索":
    // byte_start = 46 + 1 + 1 + 15 = 63
    // byte_end = 63 + 6 = 69
    // u16_start = 24 + 1 + 1 + 5 = 31
    // u16_end = 31 + 2 = 33

    const CjkSink = struct {
        s0_start: usize = 0,
        s0_end: usize = 0,
        s0_u16_start: usize = 0,
        s0_u16_end: usize = 0,
        s1_start: usize = 0,
        s1_end: usize = 0,
        s1_u16_start: usize = 0,
        s1_u16_end: usize = 0,
        span_count: usize = 0,
        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) {
                self.span_count = ev.match.matches.len;
                if (ev.match.matches.len >= 2) {
                    self.s0_start = ev.match.matches[0].start;
                    self.s0_end = ev.match.matches[0].end;
                    self.s0_u16_start = ev.match.matches[0].u16_start;
                    self.s0_u16_end = ev.match.matches[0].u16_end;

                    self.s1_start = ev.match.matches[1].start;
                    self.s1_end = ev.match.matches[1].end;
                    self.s1_u16_start = ev.match.matches[1].u16_start;
                    self.s1_u16_end = ev.match.matches[1].u16_end;
                }
            }
            return true;
        }
    };

    var sink = CjkSink{};
    const res = try searcher.searchSourceSlice(CjkSink, &sink, "m1-cjk", utf8_cjk, &finder, .{
        .allocator = testing.allocator,
    });

    try testing.expectEqual(@as(u64, 1), res.matched_lines);
    try testing.expectEqual(@as(u64, 2), res.matches);
    try testing.expectEqual(@as(usize, 2), sink.span_count);

    try testing.expectEqual(@as(usize, 40), sink.s0_start);
    try testing.expectEqual(@as(usize, 46), sink.s0_end);
    try testing.expectEqual(@as(usize, 22), sink.s0_u16_start);
    try testing.expectEqual(@as(usize, 24), sink.s0_u16_end);

    try testing.expectEqual(@as(usize, 63), sink.s1_start);
    try testing.expectEqual(@as(usize, 69), sink.s1_end);
    try testing.expectEqual(@as(usize, 31), sink.s1_u16_start);
    try testing.expectEqual(@as(usize, 33), sink.s1_u16_end);
}

test "M1 CHALLENGE 5: Astral plane emojis (4-byte UTF-8, 2 UTF-16 surrogate units) compute accurately" {
    // In UTF-16, astral plane characters (U+10000..U+10FFFF) require a surrogate pair (2 code units).
    // In UTF-8, they take 4 bytes.
    // "Emoji: 🚀 rocket, 🎉 party!\n"
    const emoji_line = "Emoji: 🚀 rocket, 🎉 party!\n";
    try testing.expect(!encoding_mod.isAsciiSlice(emoji_line));

    const Multi = @import("../finder/multi.zig").Multi;
    var multi = try Multi.init(testing.allocator, &.{ "rocket", "party" }, .{});
    defer multi.deinit();

    // Match 1: "rocket"
    // byte_start = 7 + 4 + 1 = 12
    // byte_end = 12 + 6 = 18
    // u16_start = 7 + 2 + 1 = 10
    // u16_end = 10 + 6 = 16

    // Match 2: "party"
    // byte_start = 18 + 2 + 4 + 1 = 25
    // byte_end = 25 + 5 = 30
    // u16_start = 16 + 2 + 2 + 1 = 21
    // u16_end = 21 + 5 = 26

    const EmojiSink = struct {
        matches_len: usize = 0,
        m0_start: usize = 0,
        m0_end: usize = 0,
        m0_u16_start: usize = 0,
        m0_u16_end: usize = 0,
        m1_start: usize = 0,
        m1_end: usize = 0,
        m1_u16_start: usize = 0,
        m1_u16_end: usize = 0,
        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) {
                self.matches_len = ev.match.matches.len;
                if (ev.match.matches.len >= 2) {
                    self.m0_start = ev.match.matches[0].start;
                    self.m0_end = ev.match.matches[0].end;
                    self.m0_u16_start = ev.match.matches[0].u16_start;
                    self.m0_u16_end = ev.match.matches[0].u16_end;

                    self.m1_start = ev.match.matches[1].start;
                    self.m1_end = ev.match.matches[1].end;
                    self.m1_u16_start = ev.match.matches[1].u16_start;
                    self.m1_u16_end = ev.match.matches[1].u16_end;
                }
            }
            return true;
        }
    };

    var sink = EmojiSink{};
    const res = try searcher.searchSourceSlice(EmojiSink, &sink, "m1-emoji", emoji_line, &multi, .{
        .allocator = testing.allocator,
    });

    try testing.expectEqual(@as(u64, 1), res.matched_lines);
    try testing.expectEqual(@as(u64, 2), res.matches);
    try testing.expectEqual(@as(usize, 2), sink.matches_len);

    try testing.expectEqual(@as(usize, 12), sink.m0_start);
    try testing.expectEqual(@as(usize, 18), sink.m0_end);
    try testing.expectEqual(@as(usize, 10), sink.m0_u16_start);
    try testing.expectEqual(@as(usize, 16), sink.m0_u16_end);

    try testing.expectEqual(@as(usize, 25), sink.m1_start);
    try testing.expectEqual(@as(usize, 30), sink.m1_end);
    try testing.expectEqual(@as(usize, 21), sink.m1_u16_start);
    try testing.expectEqual(@as(usize, 26), sink.m1_u16_end);
}

test "M1 CHALLENGE 6: Hybrid extreme stress - 80 matches on mixed ASCII+CJK+Emoji line (>64 buffer expansion)" {
    // 80 repetitions of "A🚀中B "
    // Per block:
    // "A" : 1 byte, 1 u16 unit
    // "🚀": 4 bytes, 2 u16 units
    // "中": 3 bytes, 1 u16 unit
    // "B" : 1 byte, 1 u16 unit
    // " " : 1 byte, 1 u16 unit
    // Total bytes per block = 10
    // Total u16 units per block = 6
    // Match "B":
    // In block k (0 <= k < 80):
    // byte_start = k * 10 + 8
    // byte_end   = k * 10 + 9
    // u16_start  = k * 6 + 4
    // u16_end    = k * 6 + 5
    const total_blocks: usize = 80;
    var line_buf = std.ArrayList(u8).empty;
    defer line_buf.deinit(testing.allocator);

    for (0..total_blocks) |_| {
        try line_buf.appendSlice(testing.allocator, "A🚀中B ");
    }
    try line_buf.appendSlice(testing.allocator, "\n");

    var finder = try Finder.init("B", .{});

    const StressSink = struct {
        matches_count: usize = 0,
        all_exact: bool = true,
        bad_index: usize = 0,
        expected_b_start: usize = 0,
        actual_b_start: usize = 0,
        expected_u16_start: usize = 0,
        actual_u16_start: usize = 0,
        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) {
                self.matches_count = ev.match.matches.len;
                for (ev.match.matches, 0..) |s, k| {
                    const exp_b_start = k * 10 + 8;
                    const exp_b_end = k * 10 + 9;
                    const exp_u16_start = k * 6 + 4;
                    const exp_u16_end = k * 6 + 5;
                    if (s.start != exp_b_start or s.end != exp_b_end or s.u16_start != exp_u16_start or s.u16_end != exp_u16_end) {
                        self.all_exact = false;
                        self.bad_index = k;
                        self.expected_b_start = exp_b_start;
                        self.actual_b_start = s.start;
                        self.expected_u16_start = exp_u16_start;
                        self.actual_u16_start = s.u16_start;
                        return false;
                    }
                }
            }
            return true;
        }
    };

    var sink = StressSink{};
    const res = try searcher.searchSourceSlice(StressSink, &sink, "m1-hybrid-stress", line_buf.items, &finder, .{
        .allocator = testing.allocator,
    });

    try testing.expectEqual(@as(u64, 1), res.matched_lines);
    try testing.expectEqual(@as(u64, total_blocks), res.matches);
    try testing.expectEqual(total_blocks, sink.matches_count);
    if (!sink.all_exact) {
        std.debug.print("\nMismatch at block {d}: expected byte {d}, got {d}; expected u16 {d}, got {d}\n", .{
            sink.bad_index,
            sink.expected_b_start,
            sink.actual_b_start,
            sink.expected_u16_start,
            sink.actual_u16_start,
        });
    }
    try testing.expect(sink.all_exact);
}

test "regression: BinaryPolicy.quit emits complete matching lines before NUL deterministically across slice, reader, and pull" {
    const hay = "MATCH 1\nclean line\nMATCH 2\nbinary\x00line\nMATCH 3\n";
    var finder = try Finder.init("MATCH", .{});

    const LineRec = struct {
        lines: std.ArrayList([]u8) = .empty,
        pub fn matched(self: *@This(), line: sink_mod.Line) bool {
            const dup = testing.allocator.dupe(u8, line.bytes) catch return false;
            self.lines.append(testing.allocator, dup) catch {
                testing.allocator.free(dup);
                return false;
            };
            return true;
        }
        fn deinit(self: *@This()) void {
            for (self.lines.items) |s| testing.allocator.free(s);
            self.lines.deinit(testing.allocator);
        }
    };

    // 1. searchSlice
    var rec_slice = LineRec{};
    defer rec_slice.deinit();
    const res_slice = try searcher.searchSlice(LineRec, &rec_slice, hay, "s", &finder, .{ .binary = .quit });
    try testing.expectEqual(sink_mod.Outcome.binary_quit, res_slice.outcome);
    try testing.expectEqual(@as(u64, 2), res_slice.matched_lines);
    try testing.expectEqual(@as(usize, 2), rec_slice.lines.items.len);
    try testing.expectEqualStrings("MATCH 1", rec_slice.lines.items[0]);
    try testing.expectEqualStrings("MATCH 2", rec_slice.lines.items[1]);

    // 2. searchReader with large buffer (single chunk) and small buffer (multi-chunk)
    for ([_]usize{ 64 * 1024, 12 }) |buf_sz| {
        var rec_rdr = LineRec{};
        defer rec_rdr.deinit();
        var rdr = std.Io.Reader.fixed(hay);
        const res_rdr = try searcher.searchReader(LineRec, testing.allocator, &rec_rdr, &rdr, "r", &finder, .{
            .binary = .quit,
            .buffer_size = buf_sz,
            .max_line_len = 64,
        });
        try testing.expectEqual(sink_mod.Outcome.binary_quit, res_rdr.outcome);
        try testing.expectEqual(@as(u64, 2), res_rdr.matched_lines);
        try testing.expectEqual(@as(usize, 2), rec_rdr.lines.items.len);
        try testing.expectEqualStrings("MATCH 1", rec_rdr.lines.items[0]);
        try testing.expectEqualStrings("MATCH 2", rec_rdr.lines.items[1]);
    }

    // 3. openReaderPull
    var rdr_pull = std.Io.Reader.fixed(hay);
    var pull = try pull_mod.openReaderPull(testing.allocator, &finder, "p", &rdr_pull, .{ .binary = .quit });
    defer pull.deinit();
    var pull_matches: usize = 0;
    var pull_outcome: sink_mod.Outcome = .complete;
    while (try pull.next()) |ev| {
        if (ev.kind == .match) pull_matches += 1;
        if (ev.kind == .end) pull_outcome = ev.outcome;
    }
    try testing.expectEqual(@as(usize, 2), pull_matches);
    try testing.expectEqual(sink_mod.Outcome.binary_quit, pull_outcome);
}

test "regression: count-only sink without matched callback honors exists and max_results" {
    const CountOnlySink = struct {
        progress_calls: usize = 0,
        pub fn progress(self: *@This(), _: u64, _: u64, _: u64) bool {
            self.progress_calls += 1;
            return true;
        }
    };
    const hay = "hit 1\nhit 2\nhit 3\nhit 4\n";
    var finder = try Finder.init("hit", .{});

    var s_exists = CountOnlySink{};
    const r_exists = try searcher.searchSlice(CountOnlySink, &s_exists, hay, "ex", &finder, .{
        .exists = true,
        .binary = .none,
    });
    try testing.expectEqual(sink_mod.Outcome.stopped, r_exists.outcome);
    try testing.expectEqual(@as(u64, 1), r_exists.matched_lines);

    var s_max = CountOnlySink{};
    const r_max = try searcher.searchSlice(CountOnlySink, &s_max, hay, "max", &finder, .{
        .max_results = 2,
        .progress_interval = 1,
        .binary = .none,
    });
    try testing.expectEqual(sink_mod.Outcome.stopped, r_max.outcome);
    try testing.expectEqual(sink_mod.LimitHit.max_results, r_max.limit_hit);
    try testing.expectEqual(@as(u64, 2), r_max.matched_lines);
    try testing.expectEqual(@as(?u64, 12), r_max.resume_at);
    try testing.expect(s_max.progress_calls >= 1);
}

test "regression: Regex prefix DFA respects .earliest vs .leftmost_first and findWatched single-pass" {
    const Regex = @import("../regex/vm.zig").Regex;

    var re1 = try Regex.init(testing.allocator, "prefix(a|ab)", .{});
    defer re1.deinit();
    const e1 = re1.find("prefixab", 0, .earliest).?;
    const l1 = re1.find("prefixab", 0, .leftmost_first).?;
    try testing.expectEqual(@as(usize, 0), e1.start);
    try testing.expectEqual(@as(usize, 7), e1.end);
    try testing.expectEqual(@as(usize, 0), l1.start);
    try testing.expectEqual(@as(usize, 7), l1.end);

    var re2 = try Regex.init(testing.allocator, "prefix(ab|a)", .{});
    defer re2.deinit();
    const e2 = re2.find("prefixab", 0, .earliest).?;
    const l2 = re2.find("prefixab", 0, .leftmost_first).?;
    try testing.expectEqual(@as(usize, 0), e2.start);
    try testing.expectEqual(@as(usize, 8), e2.end);
    try testing.expectEqual(@as(usize, 0), l2.start);
    try testing.expectEqual(@as(usize, 8), l2.end);

    var re3 = try Regex.init(testing.allocator, "WARN_[0-9]{4}_[a-z]{3,8}", .{});
    defer re3.deinit();
    const e3 = re3.find("WARN_1234_abcdefgh", 0, .earliest).?;
    const l3 = re3.find("WARN_1234_abcdefgh", 0, .leftmost_first).?;
    try testing.expectEqual(@as(usize, 18), e3.end);
    try testing.expectEqual(@as(usize, 18), l3.end);

    var nul_pos: ?usize = null;
    const w_hit = re3.findWatched("ok\nWARN_1234_abc\nfoo\x00\n", 0, &nul_pos).?;
    try testing.expect(nul_pos == null);
    try testing.expectEqual(@as(usize, 3), w_hit.start);
    try testing.expectEqual(@as(usize, 16), w_hit.end);

    var nul_pos2: ?usize = null;
    try testing.expect(re3.findWatched("foo\x00\nWARN_1234_abc\n", 0, &nul_pos2) == null);
    try testing.expectEqual(@as(?usize, 3), nul_pos2);

    var re4 = try Regex.init(testing.allocator, "[a-z]+tion\\s+[a-z]+\\s+the", .{});
    defer re4.deinit();
    try testing.expect(re4.find("national generation gap of", 0, .earliest) == null);
    const hit4 = re4.find("national generation gap the end", 0, .earliest).?;
    try testing.expectEqual(@as(usize, 9), hit4.start);
    try testing.expectEqual(@as(usize, 27), hit4.end);
    const hit4_lf = re4.find("nation generation gap the end", 0, .leftmost_first).?;
    try testing.expectEqual(@as(usize, 7), hit4_lf.start);
    try testing.expectEqual(@as(usize, 25), hit4_lf.end);

    var re5 = try Regex.init(testing.allocator, "order_id=[0-9a-f]{8}-[0-9a-f]{4}", .{});
    defer re5.deinit();
    try testing.expect(re5.find("order_id=zzzzzzzz-1234", 0, .earliest) == null);
    const hit5 = re5.find("prefix order_id=deadbeef-cafe suffix", 0, .earliest).?;
    try testing.expectEqual(@as(usize, 7), hit5.start);
    try testing.expectEqual(@as(usize, 29), hit5.end);

    // Unicode case-insensitive interior literal regex does not mis-trigger ASCII suffix DFA
    var re_uni = try Regex.init(testing.allocator, "[a-z]+tion\\s+the", .{ .case = .insensitive, .unicode_case = true });
    defer re_uni.deinit();
    try testing.expectEqual(@as(u16, 0), re_uni.dfa_suffix_state);
    const hit_uni = re_uni.find("NaTiOn   ThE", 0, .earliest).?;
    try testing.expectEqual(@as(usize, 0), hit_uni.start);
    try testing.expectEqual(@as(usize, 12), hit_uni.end);
}

test "regression: searchSlice fused BinaryPolicy.quit honors max_count and stop atomic flag" {
    const MatchMode = @import("../matcher.zig").MatchMode;
    const hay = "hit 1\nhit 2\nhit 3\nhit 4\n";
    var finder = try Finder.init("hit", .{});

    const CountOnlySink = struct {};
    const CallbackSink = struct {
        seen: usize = 0,
        stop_flag: ?*std.atomic.Value(bool) = null,
        stop_on_hit: usize = 0,
        pub fn matched(self: *@This(), _: sink_mod.Line) bool {
            self.seen += 1;
            if (self.stop_flag) |f| {
                if (self.seen >= self.stop_on_hit) f.store(true, .release);
            }
            return true;
        }
    };

    // 1. Count-only sink with max_count = 1 and max_count = 2 under default .binary = .quit
    var c1 = CountOnlySink{};
    const r_c1 = try searcher.searchSlice(CountOnlySink, &c1, hay, "mc1", &finder, .{
        .max_count = 1,
        .binary = .quit,
    });
    try testing.expectEqual(sink_mod.Outcome.stopped, r_c1.outcome);
    try testing.expectEqual(@as(u64, 1), r_c1.matched_lines);

    var c2 = CountOnlySink{};
    const r_c2 = try searcher.searchSlice(CountOnlySink, &c2, hay, "mc2", &finder, .{
        .max_count = 2,
        .binary = .quit,
    });
    try testing.expectEqual(sink_mod.Outcome.stopped, r_c2.outcome);
    try testing.expectEqual(@as(u64, 2), r_c2.matched_lines);

    // 2. Callback sink with max_count = 1 and max_count = 2 under default .binary = .quit (both .earliest and .leftmost_first)
    for ([_]MatchMode{ .earliest, .leftmost_first }) |mm| {
        var cb1 = CallbackSink{};
        const r_cb1 = try searcher.searchSlice(CallbackSink, &cb1, hay, "cb1", &finder, .{
            .max_count = 1,
            .binary = .quit,
            .match_mode = mm,
        });
        try testing.expectEqual(sink_mod.Outcome.stopped, r_cb1.outcome);
        try testing.expectEqual(@as(u64, 1), r_cb1.matched_lines);
        try testing.expectEqual(@as(usize, 1), cb1.seen);

        var cb2 = CallbackSink{};
        const r_cb2 = try searcher.searchSlice(CallbackSink, &cb2, hay, "cb2", &finder, .{
            .max_count = 2,
            .binary = .quit,
            .match_mode = mm,
        });
        try testing.expectEqual(sink_mod.Outcome.stopped, r_cb2.outcome);
        try testing.expectEqual(@as(u64, 2), r_cb2.matched_lines);
        try testing.expectEqual(@as(usize, 2), cb2.seen);
    }

    // 3. Atomic stop flag pre-set and set mid-search
    var flag_pre = std.atomic.Value(bool).init(true);
    var c_pre = CountOnlySink{};
    const r_pre = try searcher.searchSlice(CountOnlySink, &c_pre, hay, "stop-pre", &finder, .{
        .stop = &flag_pre,
        .binary = .quit,
    });
    try testing.expectEqual(sink_mod.Outcome.stopped, r_pre.outcome);
    try testing.expectEqual(@as(u64, 0), r_pre.matched_lines);

    var flag_mid = std.atomic.Value(bool).init(false);
    var cb_mid = CallbackSink{ .stop_flag = &flag_mid, .stop_on_hit = 2 };
    const r_mid = try searcher.searchSlice(CallbackSink, &cb_mid, hay, "stop-mid", &finder, .{
        .stop = &flag_mid,
        .binary = .quit,
    });
    try testing.expectEqual(sink_mod.Outcome.stopped, r_mid.outcome);
    try testing.expectEqual(@as(u64, 2), r_mid.matched_lines);
    try testing.expectEqual(@as(usize, 2), cb_mid.seen);
}

test "regression: pumpLong emits completed > max_line_len long line before subsequent-line NUL quit" {
    // Construct a > max_line_len (max_line_len = 32) matching line followed by a normal line and a binary line with NUL.
    const long_line = "AAA_MATCH_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx_END\n";
    const tail = "SECOND_MATCH_LINE\nbinary\x00line\nTHIRD_MATCH\n";
    const payload = long_line ++ tail;

    var finder = try Finder.init("MATCH", .{});

    const RecSink = struct {
        matched_count: usize = 0,
        first_truncated: bool = false,
        pub fn matched(self: *@This(), line: sink_mod.Line) bool {
            if (self.matched_count == 0) self.first_truncated = line.truncated;
            self.matched_count += 1;
            return true;
        }
    };

    // Test with buffer_size = 40 so Chunk 1 enters state.long_active, and Chunk 2 reads both the '\n' of long_line and the '\x00' of tail!
    var sink = RecSink{};
    var reader = std.Io.Reader.fixed(payload);
    const res = try searcher.searchReader(RecSink, testing.allocator, &sink, &reader, "long-nul", &finder, .{
        .binary = .quit,
        .max_line_len = 32,
        .buffer_size = 40,
    });
    try testing.expectEqual(sink_mod.Outcome.binary_quit, res.outcome);
    try testing.expectEqual(@as(u64, 2), res.matched_lines);
    try testing.expectEqual(@as(usize, 2), sink.matched_count);
    try testing.expect(sink.first_truncated);
}

test "regression: parallel.run count_lines_only = false preserves multi-span stats.matches vs count_lines_only = true" {
    const parallel = @import("../parallel.zig");
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const io = testing.io;

    try tmp.dir.writeFile(io, .{ .sub_path = "multi.txt", .data = "hit hit hit\nhit hit\nnone\n" });
    var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const path_len = try tmp.dir.realPath(io, &path_buf);
    const root_path = path_buf[0..path_len];

    var out: std.Io.Writer.Allocating = .init(testing.allocator);
    defer out.deinit();
    var saw = false;

    // 1. Default count_lines_only = false preserves exact span count (5 matches across 2 lines)
    const st_default = try parallel.run(testing.allocator, io, .{
        .pattern = "hit",
        .roots = &.{root_path},
        .walk = .{ .threads = 1 },
        .emit = .count,
        .stdout = &out.writer,
        .saw_output = &saw,
    });
    try testing.expectEqual(@as(u64, 2), st_default.matched_lines);
    try testing.expectEqual(@as(u64, 5), st_default.matches);

    // 2. Fast CLI mode count_lines_only = true skips per-line span enumeration (2 matched_lines, 2 matches)
    const st_fast = try parallel.run(testing.allocator, io, .{
        .pattern = "hit",
        .roots = &.{root_path},
        .walk = .{ .threads = 1 },
        .emit = .count,
        .count_lines_only = true,
        .stdout = &out.writer,
        .saw_output = &saw,
    });
    try testing.expectEqual(@as(u64, 2), st_fast.matched_lines);
    try testing.expectEqual(@as(u64, 2), st_fast.matches);
}
