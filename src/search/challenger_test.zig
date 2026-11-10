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
