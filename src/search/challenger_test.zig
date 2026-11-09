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
