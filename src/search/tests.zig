//! [Module] search/tests.zig
//! [Layer] Layer 4 — Comprehensive Search Pipeline Unit & Contract Test Suite
//! [Role] End-to-end verification of slice/reader search, context rings, ultra-long lines,
//!        replacement templates, encodings, streaming decompression, multi-tenant budgets, and pagination.

const std = @import("std");
const build_options = @import("build_options");
const decompress = @import("../codec/decompress.zig");
const encoding = @import("../codec/encoding.zig");
const matcher_mod = @import("../matcher.zig");
const memchr = @import("../finder/memchr.zig");
const regex_mod = @import("../regex.zig");
const sink_mod = @import("../sink.zig");
const unicode_fold = @import("../finder/unicode_fold.zig");
const searcher = @import("../searcher.zig");

const Encoding = searcher.Encoding;
const Compression = searcher.Compression;
const BinaryPolicy = searcher.BinaryPolicy;
const SearchConfig = searcher.SearchConfig;
const Outcome = searcher.Outcome;
const Result = searcher.Result;
const Line = searcher.Line;
const Span = searcher.Span;
const BinaryStatus = searcher.BinaryStatus;
const Event = searcher.Event;
const LineEvent = searcher.LineEvent;
const EndEvent = searcher.EndEvent;
const Flow = searcher.Flow;
const Summary = searcher.Summary;
const Progress = searcher.Progress;
const Heartbeat = searcher.Heartbeat;
const ResumeState = searcher.ResumeState;
const SliceError = searcher.SliceError;
const ReadError = searcher.ReadError;
const PullEvent = searcher.PullEvent;
const SourcePull = searcher.SourcePull;
const searchSlice = searcher.searchSlice;
const searchReader = searcher.searchReader;
const searchFile = searcher.searchFile;
const searchSourceSlice = searcher.searchSourceSlice;
const resumeSourceSlice = searcher.resumeSourceSlice;
const searchSource = searcher.searchSource;
const resumeSource = searcher.resumeSource;
const openSourcePull = searcher.openSourcePull;
const drive = searcher.pipeline_mod.drive;
const serviceConfig = searcher.config_mod.serviceConfig;
const beforeContextCapacity = searcher.config_mod.beforeContextCapacity;
const EventBridge = searcher.pull_mod.EventBridge;
const emitSummary = searcher.pull_mod.emitSummary;

const testing = std.testing;
const Finder = @import("../finder/finder.zig").Finder;

const Rec = struct {
    text: std.ArrayList(u8) = .empty,
    matches: u64 = 0,
    breaks: u32 = 0,
    begun: []const u8 = "",
    nul: ?u64 = null,
    stop_after: ?u64 = null,
    suppress_lines: bool = false,

    fn deinit(self: *Rec, allocator: std.mem.Allocator) void {
        self.text.deinit(allocator);
    }

    pub fn begin(self: *Rec, path: []const u8) bool {
        self.begun = path;
        return true;
    }

    pub fn matched(self: *Rec, line: Line) bool {
        self.matches += 1;
        if (self.suppress_lines) return self.keepGoing();
        self.write(line, true);
        return self.keepGoing();
    }

    pub fn context(self: *Rec, line: Line) bool {
        if (self.suppress_lines) return true;
        self.write(line, false);
        return true;
    }

    pub fn contextBreak(self: *Rec) bool {
        if (self.suppress_lines) return true;
        self.breaks += 1;
        return true;
    }

    pub fn binary(self: *Rec, offset: u64) bool {
        self.nul = offset;
        self.suppress_lines = true;
        return self.matches == 0;
    }

    pub fn finish(self: *Rec, result: Result) bool {
        if (result.outcome == .binary_matched and self.matches > 0 and self.text.items.len == 0) {
            self.text.appendSlice(testing.allocator, "binary file matches\n") catch unreachable;
        }
        return true;
    }

    fn keepGoing(self: *Rec) bool {
        if (self.stop_after) |n| return self.matches < n;
        return true;
    }

    fn write(self: *Rec, line: Line, is_match: bool) void {
        const sep: u8 = if (is_match) ':' else '-';
        if (line.number) |n| {
            var tmp: [32]u8 = undefined;
            const s = std.fmt.bufPrint(&tmp, "{d}", .{n}) catch unreachable;
            self.text.appendSlice(testing.allocator, s) catch unreachable;
            self.text.append(testing.allocator, sep) catch unreachable;
        }
        self.text.appendSlice(testing.allocator, line.bytes) catch unreachable;
        self.text.append(testing.allocator, '\n') catch unreachable;
    }
};

fn run(hay: []const u8, pattern: []const u8, config: SearchConfig) !Rec {
    var finder = try Finder.init(pattern, .{});
    var rec = Rec{};
    errdefer rec.deinit(testing.allocator);
    _ = try searchSlice(Rec, &rec, hay, "f", &finder, config);
    return rec;
}

test "slice: line numbers, context, and context break" {
    var rec = try run("a\nb\nMATCH\nc\nd\ne\nMATCH2\nf\n", "MATCH", .{
        .line_numbers = true,
        .before = 1,
        .after = 1,
    });
    defer rec.deinit(testing.allocator);
    try testing.expectEqualStrings(
        \\2-b
        \\3:MATCH
        \\4-c
        \\6-e
        \\7:MATCH2
        \\8-f
        \\
    , rec.text.items);
    try testing.expectEqual(@as(u64, 2), rec.matches);
    try testing.expectEqual(@as(u32, 1), rec.breaks);
}

test "slice: max_count still flushes after-context, and hits inside the window keep match formatting" {
    var rec = try run("a\nb\nMATCH\nc\nd\ne\nMATCH2\nf\n", "MATCH", .{
        .line_numbers = true,
        .after = 4,
        .max_count = 1,
    });
    defer rec.deinit(testing.allocator);
    try testing.expectEqualStrings(
        \\3:MATCH
        \\4-c
        \\5-d
        \\6-e
        \\7:MATCH2
        \\
    , rec.text.items);
}

test "slice: inverted matching and inverted context" {
    var plain = try run("a\nb\nMATCH\nc\n", "MATCH", .{ .line_numbers = true, .invert = true });
    defer plain.deinit(testing.allocator);
    try testing.expectEqualStrings(
        \\1:a
        \\2:b
        \\4:c
        \\
    , plain.text.items);

    var ctx = try run("a\nb\nMATCH\nc\n", "MATCH", .{
        .line_numbers = true,
        .invert = true,
        .before = 1,
        .after = 1,
    });
    defer ctx.deinit(testing.allocator);
    try testing.expectEqualStrings(
        \\1:a
        \\2:b
        \\3-MATCH
        \\4:c
        \\
    , ctx.text.items);
}

test "slice: empty lines, missing trailing newline, and CRLF stripping CR" {
    var empty_lines = try run("a\n\nMATCH\n\nb\n", "MATCH", .{
        .line_numbers = true,
        .before = 1,
        .after = 1,
    });
    defer empty_lines.deinit(testing.allocator);
    try testing.expectEqualStrings(
        \\2-
        \\3:MATCH
        \\4-
        \\
    , empty_lines.text.items);

    var no_nl = try run("foo\nbar", "foo", .{ .line_numbers = true });
    defer no_nl.deinit(testing.allocator);
    try testing.expectEqualStrings("1:foo\n", no_nl.text.items);

    var crlf = try run("a\r\nMATCH\r\nb\r\n", "MATCH", .{ .line_numbers = true });
    defer crlf.deinit(testing.allocator);
    try testing.expectEqualStrings("2:MATCH\n", crlf.text.items);
}

test "slice: empty pattern matches every line, column is the first matched byte" {
    var all = try run("a\nb\n", "", .{ .line_numbers = true });
    defer all.deinit(testing.allocator);
    try testing.expectEqualStrings("1:a\n2:b\n", all.text.items);

    const Col = struct {
        start: usize = 0,
        pub fn matched(self: *@This(), line: Line) bool {
            self.start = line.match.?.start;
            return true;
        }
    };
    var finder = try Finder.init("MATCH", .{});
    var col = Col{};
    _ = try searchSlice(Col, &col, "xxMATCHyy\n", "", &finder, .{ .binary = .none });
    try testing.expectEqual(@as(usize, 2), col.start);
}

test "slice: binary report and quit policies" {
    var report = try run("xxMATCH\x00yy\n", "MATCH", .{ .binary = .report });
    defer report.deinit(testing.allocator);
    try testing.expectEqual(Outcome.binary_matched, (try finishOf("xxMATCH\x00yy\n", "MATCH", .report)).outcome);
    try testing.expectEqual(@as(?u64, 7), report.nul);
    try testing.expectEqualStrings("binary file matches\n", report.text.items);

    var quiet = try run("MATCH\nfoo\x00\n", "MATCH", .{ .binary = .quit, .buffer_size = 64 });
    defer quiet.deinit(testing.allocator);
    try testing.expectEqualStrings("", quiet.text.items);
    const q = try finishOf("MATCH\nfoo\x00\n", "MATCH", .quit);
    try testing.expectEqual(Outcome.binary_quit, q.outcome);
    try testing.expectEqual(@as(u64, 0), q.matched_lines);

    var text = try run("xxMATCH\x00yy\n", "MATCH", .{ .binary = .none, .line_numbers = true });
    defer text.deinit(testing.allocator);
    try testing.expectEqualStrings("1:xxMATCH\x00yy\n", text.text.items);
}

fn finishOf(hay: []const u8, pattern: []const u8, policy: BinaryPolicy) !Result {
    var finder = try Finder.init(pattern, .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    return searchSlice(Rec, &rec, hay, "", &finder, .{ .binary = policy, .buffer_size = 64 });
}

test "slice: overlong matching line emits a window" {
    const Cap = struct {
        truncated: bool = false,
        line_len: u64 = 0,
        window_start: u64 = 0,
        offset: u64 = 0,
        bytes: [8]u8 = undefined,
        len: usize = 0,
        mstart: usize = 0,
        pub fn matched(self: *@This(), line: Line) bool {
            self.truncated = line.truncated;
            self.line_len = line.line_len;
            self.window_start = line.window_start;
            self.offset = line.offset;
            self.len = @min(line.bytes.len, self.bytes.len);
            @memcpy(self.bytes[0..self.len], line.bytes[0..self.len]);
            self.mstart = line.match.?.start;
            return true;
        }
    };
    var finder = try Finder.init("MATCH", .{});
    var cap = Cap{};
    const hay = "MATCHxxxxxxxxxxxxxxxxxxxx";
    const result = try searchSlice(Cap, &cap, hay, "", &finder, .{ .max_line_len = 8, .binary = .none });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expect(cap.truncated);
    try testing.expectEqual(@as(u64, hay.len), cap.line_len);
    try testing.expectEqual(@as(u64, 0), cap.offset);
    try testing.expectEqual(@as(usize, 8), cap.len);
    try testing.expectEqualStrings(hay[cap.window_start..][0..cap.len], cap.bytes[0..cap.len]);
    try testing.expectEqual(@as(u64, 0), cap.window_start + cap.mstart);
}

test "chunked reading fuses NUL detection into search" {
    // Lines are split on LF and not in NUL record mode, so NUL remains a binary signal.
    var reader = std.Io.Reader.fixed("ab\ncd\nMATCH\n");
    var finder = try Finder.init("MATCH", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = try searchReader(Rec, testing.allocator, &rec, &reader, "", &finder, .{
        .line_numbers = true,
        .buffer_size = 4,
        .max_line_len = 64,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqual(@as(?u64, null), result.nul_offset);
    try testing.expectEqualStrings("3:MATCH\n", rec.text.items);

    var bin_reader = std.Io.Reader.fixed("xxMATCH\x00yy\n");
    var bin_finder = try Finder.init("MATCH", .{});
    var bin = Rec{};
    defer bin.deinit(testing.allocator);
    const bin_result = try searchReader(Rec, testing.allocator, &bin, &bin_reader, "", &bin_finder, .{
        .buffer_size = 64,
        .max_line_len = 64,
        .binary = .report,
    });
    try testing.expectEqual(Outcome.binary_matched, bin_result.outcome);
    try testing.expectEqual(@as(?u64, 7), bin_result.nul_offset);
    try testing.expectEqualStrings("binary file matches\n", bin.text.items);

    var quit_reader = std.Io.Reader.fixed("MATCH\nfoo\x00\n");
    var quit_finder = try Finder.init("MATCH", .{});
    var quit = Rec{};
    defer quit.deinit(testing.allocator);
    const quit_result = try searchReader(Rec, testing.allocator, &quit, &quit_reader, "", &quit_finder, .{
        .binary = .quit,
        .buffer_size = 64,
        .max_line_len = 64,
    });
    try testing.expectEqual(Outcome.binary_quit, quit_result.outcome);
    try testing.expectEqual(@as(u64, 0), quit_result.matched_lines);
    try testing.expectEqualStrings("", quit.text.items);

    var byte_reader = std.Io.Reader.fixed("ab\ncd\nZ\n");
    var byte_finder = try Finder.init("Z", .{});
    var byte_rec = Rec{};
    defer byte_rec.deinit(testing.allocator);
    const byte_result = try searchReader(Rec, testing.allocator, &byte_rec, &byte_reader, "", &byte_finder, .{
        .line_numbers = true,
        .buffer_size = 3,
        .max_line_len = 64,
    });
    try testing.expectEqual(Outcome.complete, byte_result.outcome);
    try testing.expectEqualStrings("3:Z\n", byte_rec.text.items);
}

test "Reader preserves partial lines across chunks" {
    const hay = "abcMATCH\nzzz\nMATCH\n";
    var reader = std.Io.Reader.fixed(hay);
    var finder = try Finder.init("MATCH", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = try searchReader(Rec, testing.allocator, &rec, &reader, "r", &finder, .{
        .line_numbers = true,
        .buffer_size = 8,
        .max_line_len = 64,
        .binary = .none,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqualStrings("1:abcMATCH\n3:MATCH\n", rec.text.items);
}

test "file reading matches slice search" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const hay = "a\nMATCH\nb\n";
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "t.txt", .data = hay });
    const file = try tmp.dir.openFile(testing.io, "t.txt", .{});
    defer file.close(testing.io);

    var finder = try Finder.init("MATCH", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = try searchFile(Rec, testing.allocator, testing.io, &rec, file, "t.txt", &finder, .{
        .line_numbers = true,
        .before = 1,
        .after = 1,
        .binary = .none,
        .buffer_size = 4,
        .max_line_len = 64,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqualStrings("1-a\n2:MATCH\n3-b\n", rec.text.items);
    try testing.expectEqualStrings("t.txt", rec.begun);
}

test "chunked file reading matches slice search" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var hay: [4096 + 64]u8 = @splat('a');
    hay[100] = '\n';
    const needle = "MATCH";
    @memcpy(hay[200..][0..needle.len], needle);
    hay[200 + needle.len] = '\n';
    @memcpy(hay[hay.len - needle.len ..], needle);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "big.txt", .data = &hay });
    const file = try tmp.dir.openFile(testing.io, "big.txt", .{});
    defer file.close(testing.io);

    var finder = try Finder.init(needle, .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = try searchFile(Rec, testing.allocator, testing.io, &rec, file, "big.txt", &finder, .{
        .line_numbers = true,
        .buffer_size = 128,
        .max_line_len = hay.len,
        .binary = .none,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqual(@as(u64, 2), rec.matches);
    try testing.expect(std.mem.indexOf(u8, rec.text.items, "MATCH") != null);
}

test "stops when Sink returns false" {
    var finder = try Finder.init("M", .{});
    var rec = Rec{ .stop_after = 1 };
    defer rec.deinit(testing.allocator);
    const result = try searchSlice(Rec, &rec, "M\nM\n", "", &finder, .{ .line_numbers = true, .binary = .none });
    try testing.expectEqual(Outcome.stopped, result.outcome);
    try testing.expectEqualStrings("1:M\n", rec.text.items);
}

test "case-insensitive search" {
    var finder = try Finder.init("foo", .{ .case = .insensitive });
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    _ = try searchSlice(Rec, &rec, "Foo\nbar\nFOO\n", "", &finder, .{
        .line_numbers = true,
        .binary = .none,
    });
    try testing.expectEqualStrings("1:Foo\n3:FOO\n", rec.text.items);
}

test "Reader can finish reading a line that exactly reaches the single-line limit" {
    var reader = std.Io.Reader.fixed("abcd\nzzz\n");
    var finder = try Finder.init("zzz", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = try searchReader(Rec, testing.allocator, &rec, &reader, "", &finder, .{
        .line_numbers = true,
        .buffer_size = 4,
        .max_line_len = 4,
        .binary = .none,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqualStrings("2:zzz\n", rec.text.items);
}

test "Reader still emits a window when a line exceeds the single-line limit" {
    var reader = std.Io.Reader.fixed("abcdef\n");
    var finder = try Finder.init("a", .{});
    const Cap = struct {
        truncated: bool = false,
        line_len: u64 = 0,
        text: [8]u8 = undefined,
        len: usize = 0,
        pub fn matched(self: *@This(), line: Line) bool {
            self.truncated = line.truncated;
            self.line_len = line.line_len;
            self.len = @min(line.bytes.len, self.text.len);
            @memcpy(self.text[0..self.len], line.bytes[0..self.len]);
            return true;
        }
    };
    var cap = Cap{};
    const result = try searchReader(Cap, testing.allocator, &cap, &reader, "", &finder, .{
        .buffer_size = 4,
        .max_line_len = 4,
        .binary = .none,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expect(cap.truncated);
    try testing.expectEqual(@as(u64, 6), cap.line_len);
    try testing.expectEqual(@as(usize, 4), cap.len);
    try testing.expectEqualStrings("abcd", cap.text[0..cap.len]);
}

test "pull iterator" {
    const Iter = sink_mod.SliceIter(*Finder);
    var finder = try Finder.init("ab", .{});
    var it = Iter{ .matcher = &finder, .haystack = "xxab\nab", .line_numbers = true };
    const first = it.next().?;
    try testing.expectEqualStrings("xxab", first.bytes);
    try testing.expectEqual(@as(usize, 2), first.match.?.start);
    try testing.expectEqual(@as(?u64, 1), first.number);
    const second = it.next().?;
    try testing.expectEqualStrings("ab", second.bytes);
    try testing.expectEqual(@as(?u64, 2), second.number);
    try testing.expect(it.next() == null);
}

test "external stop flag prevents streaming search from reading the next chunk" {
    var reader = std.Io.Reader.fixed("MATCH\nMATCH\n");
    var finder = try Finder.init("MATCH", .{});
    var flag = std.atomic.Value(bool).init(true);
    const Sink = struct {
        pub fn matched(_: *@This(), _: Line) bool {
            return true;
        }
    };
    var sink = Sink{};
    const result = try searchReader(Sink, testing.allocator, &sink, &reader, "", &finder, .{
        .stop = &flag,
    });
    try testing.expectEqual(Outcome.stopped, result.outcome);
    try testing.expectEqual(@as(u64, 0), result.matched_lines);
}

test "scratch buffer is reused across searches" {
    var scratch: []u8 = &.{};
    defer testing.allocator.free(scratch);
    const Sink = struct {
        pub fn matched(_: *@This(), _: Line) bool {
            return true;
        }
    };
    var sink = Sink{};
    var finder = try Finder.init("MATCH", .{});
    const cfg = SearchConfig{ .scratch = &scratch, .buffer_size = 32, .max_line_len = 64 };
    var first = std.Io.Reader.fixed("MATCH\n");
    _ = try searchReader(Sink, testing.allocator, &sink, &first, "", &finder, cfg);
    try testing.expect(scratch.len >= 32);
    const ptr = scratch.ptr;
    var second = std.Io.Reader.fixed("MATCH\n");
    _ = try searchReader(Sink, testing.allocator, &sink, &second, "", &finder, cfg);
    try testing.expectEqual(ptr, scratch.ptr);
}

test "multi-pattern chunked reading matches slice search, and NUL before a hit stops" {
    const Multi = @import("../finder/multi.zig").Multi;
    const pats = [_][]const u8{ "pq", "rs" };
    var multi = try Multi.init(testing.allocator, &pats, .{});
    defer multi.deinit();
    try testing.expect(multi.kind == .pairs);

    var hay: [103]u8 = @splat('x');
    hay[31] = '\n';
    @memset(hay[32..64], 'y');
    hay[64] = 'p';
    hay[65] = 'q';
    hay[66] = '\n';
    @memset(hay[67..99], 'z');
    hay[99] = '\n';
    hay[100] = 'r';
    hay[101] = 's';
    hay[102] = '\n';

    const cfg = SearchConfig{
        .line_numbers = true,
        .buffer_size = 32,
        .max_line_len = 128,
        .binary = .none,
        .match_mode = .leftmost_first,
    };
    var slice_rec = Rec{};
    defer slice_rec.deinit(testing.allocator);
    const slice_result = try searchSlice(Rec, &slice_rec, &hay, "f", &multi, cfg);

    var reader = std.Io.Reader.fixed(&hay);
    var read_rec = Rec{};
    defer read_rec.deinit(testing.allocator);
    const read_result = try searchReader(Rec, testing.allocator, &read_rec, &reader, "f", &multi, cfg);

    var expect: [42]u8 = undefined;
    @memcpy(expect[0..2], "2:");
    @memset(expect[2..34], 'y');
    @memcpy(expect[34..37], "pq\n");
    @memcpy(expect[37..42], "4:rs\n");
    try testing.expectEqualStrings(&expect, slice_rec.text.items);
    try testing.expectEqualStrings(&expect, read_rec.text.items);
    try testing.expectEqual(slice_result.matched_lines, read_result.matched_lines);
    try testing.expectEqual(@as(u64, 2), read_result.matched_lines);

    var raw: [32]u8 = @splat('x');
    raw[8] = 0;
    raw[16] = 'p';
    raw[17] = 'q';
    raw[18] = '\n';
    var nul_reader = std.Io.Reader.fixed(&raw);
    var nul_rec = Rec{};
    defer nul_rec.deinit(testing.allocator);
    const nul_result = try searchReader(Rec, testing.allocator, &nul_rec, &nul_reader, "f", &multi, .{
        .buffer_size = 32,
        .max_line_len = 64,
        .binary = .quit,
        .match_mode = .leftmost_first,
    });
    try testing.expectEqual(Outcome.binary_quit, nul_result.outcome);
    try testing.expectEqual(@as(?u64, 8), nul_result.nul_offset);
    try testing.expectEqual(@as(u64, 0), nul_result.matched_lines);
    try testing.expectEqualStrings("", nul_rec.text.items);
}

test "benchmark scenario slice hits match the benchmark configuration" {
    const multi = @import("../finder/multi.zig");
    var hay: [256]u8 = undefined;
    multi.fillScenarioText(&hay);
    const Sink = struct {
        pub fn matched(_: *@This(), _: Line) bool {
            return true;
        }
    };
    var sink = Sink{};

    var sensitive = try Finder.init("NEEDLE", .{ .case = .sensitive });
    try testing.expectEqual(@as(u64, 1), (try searchSlice(Sink, &sink, &hay, "", &sensitive, .{})).matched_lines);

    var ignore = try Finder.init("needle", .{ .case = .insensitive });
    try testing.expectEqual(@as(u64, 1), (try searchSlice(Sink, &sink, &hay, "", &ignore, .{})).matched_lines);

    var smart = try Finder.init("needle", .{ .case = .smart });
    try testing.expectEqual(@as(u64, 1), (try searchSlice(Sink, &sink, &hay, "", &smart, .{})).matched_lines);

    const Group = struct { pats: []const []const u8, lines: u64 };
    const groups = [_]Group{
        .{ .pats = multi.scenario_bytes, .lines = 0 },
        .{ .pats = multi.scenario_pairs, .lines = 1 },
        .{ .pats = multi.scenario_teddy, .lines = 0 },
        .{ .pats = multi.scenario_ac, .lines = 0 },
    };
    for (groups) |group| {
        var many = try multi.Multi.init(testing.allocator, group.pats, .{});
        defer many.deinit();
        const result = try searchSlice(Sink, &sink, &hay, "", &many, .{});
        try testing.expectEqual(group.lines, result.matched_lines);
    }
}

test "CRLF line content excludes CR, and whole-line matching does not include CR" {
    var plain = try run("a\r\nMATCH\r\nb\r\n", "MATCH", .{ .line_numbers = true, .binary = .none });
    defer plain.deinit(testing.allocator);
    try testing.expectEqualStrings("2:MATCH\n", plain.text.items);
    try testing.expect(std.mem.indexOfScalar(u8, plain.text.items, '\r') == null);

    var whole = try run("a\r\nMATCH\r\nb\r\n", "MATCH", .{
        .line_numbers = true,
        .whole_line = true,
        .binary = .none,
    });
    defer whole.deinit(testing.allocator);
    try testing.expectEqualStrings("2:MATCH\n", whole.text.items);

    var with_cr = try run("MATCH\r\n", "MATCH\r", .{ .whole_line = true, .binary = .none });
    defer with_cr.deinit(testing.allocator);
    try testing.expectEqualStrings("", with_cr.text.items);

    var longer = try run("MATCHX\r\n", "MATCH", .{ .whole_line = true, .binary = .none });
    defer longer.deinit(testing.allocator);
    try testing.expectEqualStrings("", longer.text.items);
}

test "whole-word half-boundary matching" {
    var paren = try run("(-2)\n", "-2", .{ .whole_word = true, .line_numbers = true, .binary = .none });
    defer paren.deinit(testing.allocator);
    try testing.expectEqualStrings("1:(-2)\n", paren.text.items);

    var left = try run("x-2\n", "-2", .{ .whole_word = true, .binary = .none });
    defer left.deinit(testing.allocator);
    try testing.expectEqualStrings("", left.text.items);

    var right = try run("-2y\n", "-2", .{ .whole_word = true, .binary = .none });
    defer right.deinit(testing.allocator);
    try testing.expectEqualStrings("", right.text.items);

    var word = try run("foo bar\nfoobar\n", "foo", .{ .whole_word = true, .line_numbers = true, .binary = .none });
    defer word.deinit(testing.allocator);
    try testing.expectEqualStrings("1:foo bar\n", word.text.items);

    const Multi = @import("../finder/multi.zig").Multi;
    var multi = try Multi.init(testing.allocator, &.{ "fo", "foo" }, .{});
    defer multi.deinit();
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    _ = try searchSlice(Rec, &rec, "(foo)\nxfo\nfoo\n", "", &multi, .{
        .whole_word = true,
        .line_numbers = true,
        .binary = .none,
    });
    try testing.expectEqualStrings("1:(foo)\n3:foo\n", rec.text.items);
}

test "whole-line takes precedence over whole-word" {
    const both = SearchConfig{
        .whole_word = true,
        .whole_line = true,
        .line_numbers = true,
        .binary = .none,
    };
    var word_only = try run("(-2)\n", "-2", .{ .whole_word = true, .line_numbers = true, .binary = .none });
    defer word_only.deinit(testing.allocator);
    try testing.expectEqualStrings("1:(-2)\n", word_only.text.items);

    var paren = try run("(-2)\n", "-2", both);
    defer paren.deinit(testing.allocator);
    try testing.expectEqualStrings("", paren.text.items);

    var exact = try run("-2\r\n", "-2", both);
    defer exact.deinit(testing.allocator);
    try testing.expectEqualStrings("1:-2\n", exact.text.items);

    var stuck = try run("x-2\n-2y\n", "-2", both);
    defer stuck.deinit(testing.allocator);
    try testing.expectEqualStrings("", stuck.text.items);
}

const LimitGate = struct { reads: usize = 0 };

fn searchOrReject(
    allocator: std.mem.Allocator,
    patterns: []const []const u8,
    options: matcher_mod.FindOptions,
    gate: *LimitGate,
) !Result {
    const Multi = @import("../finder/multi.zig").Multi;
    var multi = try Multi.init(allocator, patterns, options);
    defer multi.deinit();
    const Sink = struct {
        pub fn matched(_: *@This(), _: Line) bool {
            return true;
        }
    };
    var sink = Sink{};
    return drive(Sink, allocator, &sink, &multi, .{
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 64,
    }, "", struct {
        fn read(raw: *anyopaque, dest: []u8) ReadError!usize {
            _ = dest;
            const ctx: *LimitGate = @ptrCast(@alignCast(raw));
            ctx.reads += 1;
            return 0;
        }
    }.read, gate);
}

test "pattern count and total byte length are rejected before construction" {
    const Multi = @import("../finder/multi.zig").Multi;
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const alloc = failing.allocator();
    var gate = LimitGate{};

    var pats: [matcher_mod.pattern_count_hard_cap + 1][]const u8 = undefined;
    for (&pats) |*slot| slot.* = "a";
    try testing.expectError(error.PatternCountExceeded, searchOrReject(alloc, &pats, .{}, &gate));
    try testing.expectEqual(@as(usize, 0), gate.reads);
    try testing.expectEqual(@as(usize, 0), failing.allocations);

    try testing.expectError(error.PatternCountExceeded, searchOrReject(alloc, &pats, .{
        .max_pattern_count = matcher_mod.pattern_count_hard_cap + 50,
    }, &gate));
    try testing.expectEqual(@as(usize, 0), gate.reads);

    try testing.expectError(error.PatternCountExceeded, Multi.init(alloc, &.{ "a", "b" }, .{ .max_pattern_count = 1 }));
    try testing.expectError(error.PatternBytesExceeded, Multi.init(alloc, &.{"abcd"}, .{ .max_pattern_bytes = 3 }));
    try testing.expectError(error.PatternCountExceeded, Finder.init("a", .{ .max_pattern_count = 0 }));

    const big = try testing.allocator.alloc(u8, matcher_mod.pattern_bytes_hard_cap + 1);
    defer testing.allocator.free(big);
    @memset(big, 'b');
    try testing.expectError(error.PatternBytesExceeded, searchOrReject(alloc, &.{big}, .{
        .max_pattern_bytes = matcher_mod.pattern_bytes_hard_cap + 10,
    }, &gate));
    try testing.expectError(error.PatternBytesExceeded, Finder.init(big, .{}));
    try testing.expectEqual(@as(usize, 0), gate.reads);

    var ok = try Multi.init(testing.allocator, &.{ "foo", "bar" }, .{
        .max_pattern_count = 8,
        .max_pattern_bytes = 64,
    });
    defer ok.deinit();
    try testing.expect(ok.find("foo", 0, .leftmost_first) != null);
    try testing.expect(ok.find("bar", 0, .leftmost_first) != null);
    try testing.expect(ok.find("nope", 0, .leftmost_first) == null);
}

const CountedRead = struct {
    rest: []const u8,
    reads: usize = 0,
    closed: u32 = 0,

    fn read(raw: *anyopaque, dest: []u8) ReadError!usize {
        const self: *CountedRead = @ptrCast(@alignCast(raw));
        self.reads += 1;
        if (self.rest.len == 0) return 0;
        const n = @min(dest.len, self.rest.len);
        @memcpy(dest[0..n], self.rest[0..n]);
        self.rest = self.rest[n..];
        return n;
    }

    fn close(raw: ?*anyopaque) void {
        const self: *CountedRead = @ptrCast(@alignCast(raw.?));
        self.closed += 1;
    }
};

test "stops reading upstream after max_count is reached" {
    const hay = "MATCH\nMATCH2\nbbbb\n";
    var ctx = CountedRead{ .rest = hay };
    var finder = try Finder.init("MATCH", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = try drive(Rec, testing.allocator, &rec, &finder, .{
        .max_count = 1,
        .after = 4,
        .line_numbers = true,
        .binary = .none,
        .buffer_size = 13,
        .max_line_len = 64,
        .close_input = CountedRead.close,
        .close_ctx = &ctx,
    }, "", CountedRead.read, &ctx);
    try testing.expectEqual(@as(usize, 1), ctx.reads);
    try testing.expectEqual(@as(u32, 1), ctx.closed);
    try testing.expectEqual(@as(u64, 13), result.bytes_read);
    try testing.expect(ctx.rest.len > 0);
    try testing.expectEqualStrings("1:MATCH\n2:MATCH2\n", rec.text.items);
    try testing.expectEqual(Outcome.stopped, result.outcome);

    var open = CountedRead{ .rest = "MATCH\n" };
    var again = Rec{};
    defer again.deinit(testing.allocator);
    const full = try drive(Rec, testing.allocator, &again, &finder, .{
        .max_count = 5,
        .line_numbers = true,
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 64,
        .close_input = CountedRead.close,
        .close_ctx = &open,
    }, "", CountedRead.read, &open);
    try testing.expectEqual(@as(u32, 0), open.closed);
    try testing.expect(open.reads >= 2);
    try testing.expectEqual(Outcome.complete, full.outcome);
    try testing.expectEqualStrings("1:MATCH\n", again.text.items);
}

test "AND and NOT filters work together and are distinct from invert" {
    const hay =
        \\foo bar
        \\foo
        \\bar
        \\foo bar baz
        \\bar baz
        \\zzz
        \\foo qux bar
        \\
    ;
    const filtered = SearchConfig{
        .line_numbers = true,
        .binary = .none,
        .contains = &.{ "foo", "bar" },
        .excludes = &.{ "baz", "qux" },
    };
    var both = try run(hay, "foo", filtered);
    defer both.deinit(testing.allocator);
    try testing.expectEqualStrings("1:foo bar\n", both.text.items);

    var inverted = try run(hay, "foo", .{ .line_numbers = true, .binary = .none, .invert = true });
    defer inverted.deinit(testing.allocator);
    try testing.expectEqualStrings(
        \\3:bar
        \\5:bar baz
        \\6:zzz
        \\
    , inverted.text.items);

    var together = try run(hay, "foo", .{
        .line_numbers = true,
        .binary = .none,
        .invert = true,
        .contains = &.{"bar"},
        .excludes = &.{"baz"},
    });
    defer together.deinit(testing.allocator);
    try testing.expectEqualStrings("3:bar\n", together.text.items);
    try testing.expect(!std.mem.eql(u8, both.text.items, inverted.text.items));
    try testing.expect(!std.mem.eql(u8, together.text.items, inverted.text.items));
    try testing.expect(!std.mem.eql(u8, together.text.items, both.text.items));
}

const Win = struct {
    calls: u32 = 0,
    truncated: bool = false,
    line_len: u64 = 0,
    window_start: u64 = 0,
    offset: u64 = 0,
    mstart: usize = 0,
    bytes: []u8 = &.{},

    fn deinit(self: *Win) void {
        if (self.bytes.len != 0) testing.allocator.free(self.bytes);
    }

    pub fn matched(self: *Win, line: Line) bool {
        self.calls += 1;
        self.truncated = line.truncated;
        self.line_len = line.line_len;
        self.window_start = line.window_start;
        self.offset = line.offset;
        self.mstart = if (line.match) |span| span.start else 0;
        if (self.bytes.len != 0) testing.allocator.free(self.bytes);
        self.bytes = testing.allocator.dupe(u8, line.bytes) catch unreachable;
        return true;
    }
};

test "overlong line retains only the match window with exact offsets" {
    const max_line: usize = 16;
    var hay = try testing.allocator.alloc(u8, 4001);
    defer testing.allocator.free(hay);
    @memset(hay, 'z');
    const match_at: usize = 2500;
    @memcpy(hay[match_at..][0..5], "MATCH");
    hay[4000] = '\n';

    var slice_finder = try Finder.init("MATCH", .{});
    var slice_win = Win{};
    defer slice_win.deinit();
    const slice_result = try searchSlice(Win, &slice_win, hay, "", &slice_finder, .{
        .max_line_len = max_line,
        .binary = .none,
    });
    try testing.expectEqual(Outcome.complete, slice_result.outcome);
    try testing.expectEqual(@as(u32, 1), slice_win.calls);
    try testing.expect(slice_win.truncated);
    try testing.expectEqual(@as(u64, 4000), slice_win.line_len);
    try testing.expectEqual(@as(u64, 0), slice_win.offset);
    try testing.expect(slice_win.bytes.len <= max_line);
    try testing.expect(slice_win.bytes.len > 0);
    try testing.expectEqualStrings(hay[slice_win.window_start..][0..slice_win.bytes.len], slice_win.bytes);
    try testing.expect(std.mem.indexOf(u8, slice_win.bytes, "MATCH") != null);
    try testing.expectEqual(@as(u64, match_at), slice_win.window_start + slice_win.mstart);

    var reader = std.Io.Reader.fixed(hay);
    var read_finder = try Finder.init("MATCH", .{});
    var read_win = Win{};
    defer read_win.deinit();
    const read_result = try searchReader(Win, testing.allocator, &read_win, &reader, "", &read_finder, .{
        .max_line_len = max_line,
        .buffer_size = 8,
        .binary = .none,
    });
    try testing.expectEqual(Outcome.complete, read_result.outcome);
    try testing.expectEqual(@as(u32, 1), read_win.calls);
    try testing.expect(read_win.truncated);
    try testing.expectEqual(@as(u64, 4000), read_win.line_len);
    try testing.expectEqual(@as(u64, 0), read_win.offset);
    try testing.expect(read_win.bytes.len <= max_line);
    try testing.expectEqualStrings(hay[read_win.window_start..][0..read_win.bytes.len], read_win.bytes);
    try testing.expect(std.mem.indexOf(u8, read_win.bytes, "MATCH") != null);
    try testing.expectEqual(@as(u64, match_at), read_win.window_start + read_win.mstart);
}

test "non-matching overlong line does not grow buffer past the limit" {
    const max_line: usize = 32;
    const line_len: usize = 3000;
    var hay = try testing.allocator.alloc(u8, line_len + 1 + 6);
    defer testing.allocator.free(hay);
    @memset(hay[0..line_len], 'z');
    hay[line_len] = '\n';
    @memcpy(hay[line_len + 1 ..][0..6], "MATCH\n");

    var scratch: []u8 = &.{};
    defer testing.allocator.free(scratch);
    var finder = try Finder.init("MATCH", .{});
    var win = Win{};
    defer win.deinit();
    var reader = std.Io.Reader.fixed(hay);
    const result = try searchReader(Win, testing.allocator, &win, &reader, "", &finder, .{
        .scratch = &scratch,
        .buffer_size = 16,
        .max_line_len = max_line,
        .binary = .none,
        .line_numbers = true,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expect(scratch.len <= max_line + 1);
    try testing.expect(scratch.len < line_len);
    try testing.expectEqual(@as(u32, 1), win.calls);
    try testing.expect(!win.truncated);
    try testing.expectEqual(@as(u64, line_len + 1), win.offset);
    try testing.expectEqualStrings("MATCH", win.bytes);
}

test "binary skips by default and populates binary_offset" {
    var ctx = CountedRead{ .rest = "abc\x00MATCH\nMORE\n" };
    var finder = try Finder.init("MATCH", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = try drive(Rec, testing.allocator, &rec, &finder, .{
        .buffer_size = 8,
        .max_line_len = 64,
    }, "", CountedRead.read, &ctx);
    try testing.expectEqual(@as(?u64, 3), result.binary_offset);
    try testing.expectEqual(result.binary_offset, result.nul_offset);
    try testing.expectEqual(Outcome.binary_quit, result.outcome);
    try testing.expectEqual(@as(u64, 0), result.matched_lines);
    try testing.expectEqual(@as(usize, 1), ctx.reads);
    try testing.expect(ctx.rest.len > 0);
    try testing.expectEqualStrings("", rec.text.items);
}

test "searches binary input without returning line contents" {
    const Sink = struct {
        calls: u32 = 0,
        bytes: usize = 0,
        pub fn matched(self: *@This(), line: Line) bool {
            self.calls += 1;
            self.bytes += line.bytes.len;
            return true;
        }
    };
    var sink = Sink{};
    var finder = try Finder.init("MATCH", .{});
    const result = try searchSlice(Sink, &sink, "xxMATCH\x00yy\nMATCH2\n", "", &finder, .{
        .binary = .report,
    });
    try testing.expect(result.binary_offset != null);
    try testing.expectEqual(@as(?u64, 7), result.binary_offset);
    try testing.expect(result.matched_lines > 0);
    try testing.expect(sink.calls > 0);
    try testing.expectEqual(@as(usize, 0), sink.bytes);
    try testing.expectEqual(Outcome.binary_matched, result.outcome);
}

test "binary input treated as text still uses the overlong line window" {
    var hay = try testing.allocator.alloc(u8, 64);
    defer testing.allocator.free(hay);
    @memset(hay, 'q');
    @memcpy(hay[4..9], "MATCH");
    hay[20] = 0;
    hay[63] = '\n';
    var finder = try Finder.init("MATCH", .{});
    var win = Win{};
    defer win.deinit();
    const result = try searchSlice(Win, &win, hay, "", &finder, .{
        .max_line_len = 8,
        .binary = .none,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expect(win.truncated);
    try testing.expectEqual(@as(u64, 63), win.line_len);
    try testing.expect(std.mem.indexOf(u8, win.bytes, "MATCH") != null);
    try testing.expect(win.bytes.len <= 8);
}

test "before-context capacity does not exceed context line limit times single-line limit" {
    const max_line: usize = 16;
    const before: u32 = 3;
    const cfg = SearchConfig{
        .before = before,
        .max_line_len = max_line,
        .max_context_lines = 4,
        .buffer_size = 32,
        .binary = .none,
        .line_numbers = true,
    };
    try testing.expectEqual(@as(usize, 48), beforeContextCapacity(cfg));
    try testing.expect(beforeContextCapacity(cfg) <= @as(usize, SearchConfig.context_lines_hard_cap) * max_line);

    const Sink = struct {
        text: [64]u8 = undefined,
        len: usize = 0,
        fn add(self: *@This(), line: Line, mark: u8) void {
            if (line.number) |n| {
                if (self.len < self.text.len) {
                    self.text[self.len] = '0' + @as(u8, @intCast(n));
                    self.len += 1;
                }
            }
            if (self.len < self.text.len) {
                self.text[self.len] = mark;
                self.len += 1;
            }
            const n = @min(line.bytes.len, self.text.len - self.len);
            @memcpy(self.text[self.len..][0..n], line.bytes[0..n]);
            self.len += n;
            if (self.len < self.text.len) {
                self.text[self.len] = '\n';
                self.len += 1;
            }
        }
        pub fn context(self: *@This(), line: Line) bool {
            self.add(line, '-');
            return true;
        }
        pub fn matched(self: *@This(), line: Line) bool {
            self.add(line, ':');
            return true;
        }
    };
    var sink = Sink{};
    var finder = try Finder.init("M", .{});
    var reader = std.Io.Reader.fixed("a\nb\nc\nd\ne\nM\n");
    var scratch: []u8 = &.{};
    defer testing.allocator.free(scratch);
    var counted = CountAlloc{ .parent = testing.allocator };
    const result = try searchReader(Sink, counted.allocator(), &sink, &reader, "", &finder, .{
        .before = before,
        .max_line_len = max_line,
        .max_context_lines = 4,
        .buffer_size = 32,
        .binary = .none,
        .line_numbers = true,
        .scratch = &scratch,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqualStrings("3-c\n4-d\n5-e\n6:M\n", sink.text[0..sink.len]);
    try testing.expect(counted.peak <= scratch.len + beforeContextCapacity(cfg) + 64);
    try testing.expect(counted.peak <= @as(usize, SearchConfig.context_lines_hard_cap) * max_line + scratch.len + 64);
}

const CountAlloc = struct {
    parent: std.mem.Allocator,
    peak: usize = 0,
    live: usize = 0,

    fn allocator(self: *CountAlloc) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountAlloc = @ptrCast(@alignCast(ctx));
        const ptr = self.parent.rawAlloc(len, alignment, ret_addr) orelse return null;
        self.live += len;
        self.peak = @max(self.peak, self.live);
        return ptr;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountAlloc = @ptrCast(@alignCast(ctx));
        if (!self.parent.rawResize(memory, alignment, new_len, ret_addr)) return false;
        self.live = self.live - memory.len + new_len;
        self.peak = @max(self.peak, self.live);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountAlloc = @ptrCast(@alignCast(ctx));
        const ptr = self.parent.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
        self.live = self.live - memory.len + new_len;
        self.peak = @max(self.peak, self.live);
        return ptr;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountAlloc = @ptrCast(@alignCast(ctx));
        self.parent.rawFree(memory, alignment, ret_addr);
        self.live -= memory.len;
    }
};

test "symmetric context can be overridden on either side" {
    var both = try run("a\nb\nM\nc\n", "M", .{
        .line_numbers = true,
        .context = 1,
        .binary = .none,
    });
    defer both.deinit(testing.allocator);
    try testing.expectEqualStrings("2-b\n3:M\n4-c\n", both.text.items);

    var only_after = try run("a\nb\nM\nc\n", "M", .{
        .line_numbers = true,
        .context = 1,
        .before = 0,
        .binary = .none,
    });
    defer only_after.deinit(testing.allocator);
    try testing.expectEqualStrings("3:M\n4-c\n", only_after.text.items);

    var only_before = try run("a\nb\nM\nc\n", "M", .{
        .line_numbers = true,
        .context = 1,
        .after = 0,
        .binary = .none,
    });
    defer only_before.deinit(testing.allocator);
    try testing.expectEqualStrings("2-b\n3:M\n", only_before.text.items);

    var mixed = try run("a\nb\nM\nc\nd\n", "M", .{
        .line_numbers = true,
        .context = 2,
        .after = 1,
        .binary = .none,
    });
    defer mixed.deinit(testing.allocator);
    try testing.expectEqualStrings("1-a\n2-b\n3:M\n4-c\n", mixed.text.items);
}

test "context break is an event marker rather than two hyphens" {
    var rec = try run("a\nb\nMATCH\nc\nd\ne\nMATCH2\nf\n", "MATCH", .{
        .line_numbers = true,
        .before = 1,
        .after = 1,
        .binary = .none,
    });
    defer rec.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 1), rec.breaks);
    try testing.expect(std.mem.indexOf(u8, rec.text.items, "--") == null);
    try testing.expectEqualStrings("2-b\n3:MATCH\n4-c\n6-e\n7:MATCH2\n8-f\n", rec.text.items);
}

test "context line count cannot exceed the hard cap" {
    var finder = try Finder.init("M", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const over = SearchConfig.context_lines_hard_cap + 1;
    try testing.expectError(error.ContextLinesExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .context = over,
    }));
    try testing.expectError(error.ContextLinesExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .before = over,
    }));
    try testing.expectError(error.ContextLinesExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .after = over,
    }));
    try testing.expectError(error.ContextLinesExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .before = over,
        .max_context_lines = over + 5,
    }));
    try testing.expectError(error.ContextLinesExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .context = 3,
        .max_context_lines = 2,
    }));
    const ok = try searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .context = 2,
        .max_context_lines = 4,
        .binary = .none,
    });
    try testing.expectEqual(@as(u64, 1), ok.matched_lines);
}

fn writeUtf16(dst: []u8, little: bool, ascii: []const u8) []const u8 {
    dst[0] = if (little) 0xff else 0xfe;
    dst[1] = if (little) 0xfe else 0xff;
    var i: usize = 2;
    for (ascii) |b| {
        if (little) {
            dst[i] = b;
            dst[i + 1] = 0;
        } else {
            dst[i] = 0;
            dst[i + 1] = b;
        }
        i += 2;
    }
    return dst[0..i];
}

const Mark = struct {
    bytes: [32]u8 = undefined,
    len: usize = 0,
    raw: [32]u8 = undefined,
    raw_len: usize = 0,
    text: [32]u8 = undefined,
    text_len: usize = 0,
    b0: usize = 0,
    b1: usize = 0,
    u0: usize = 0,
    u1: usize = 0,
    column: ?u64 = null,
    number: ?u64 = null,
    offset: u64 = 0,

    pub fn matched(self: *Mark, line: Line) bool {
        self.len = @min(line.bytes.len, self.bytes.len);
        @memcpy(self.bytes[0..self.len], line.bytes[0..self.len]);
        self.raw_len = @min(line.raw.len, self.raw.len);
        @memcpy(self.raw[0..self.raw_len], line.raw[0..self.raw_len]);
        self.text_len = @min(line.text.len, self.text.len);
        @memcpy(self.text[0..self.text_len], line.text[0..self.text_len]);
        const span = line.match.?;
        self.b0 = span.start;
        self.b1 = span.end;
        self.u0 = span.u16_start;
        self.u1 = span.u16_end;
        self.column = line.u16_column;
        self.number = line.number;
        self.offset = line.offset;
        return true;
    }
};

test "NUL delimiter counts by record" {
    // The default binary policy is quit. In NUL record mode, NUL is just the record delimiter and LF does not break lines.
    // NUL acts as a binary signal only when splitting on LF and not in this raw record mode.
    const hay = "a\nb\x00c\x00d\ne";
    var first = try run(hay, "b", .{ .line_numbers = true, .null_data = true });
    defer first.deinit(testing.allocator);
    try testing.expectEqualStrings("1:a\nb\n", first.text.items);

    var second = try run(hay, "c", .{ .line_numbers = true, .null_data = true });
    defer second.deinit(testing.allocator);
    try testing.expectEqualStrings("2:c\n", second.text.items);

    var third = try run(hay, "e", .{ .line_numbers = true, .null_data = true });
    defer third.deinit(testing.allocator);
    try testing.expectEqualStrings("3:d\ne\n", third.text.items);

    var finder = try Finder.init("e", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = try searchSlice(Rec, &rec, hay, "", &finder, .{
        .null_data = true,
        .line_numbers = true,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqual(@as(?u64, null), result.binary_offset);
    try testing.expectEqual(@as(?u64, null), result.nul_offset);
    try testing.expectEqual(@as(u64, 1), result.matched_lines);

    var reader = std.Io.Reader.fixed(hay);
    var streamed = Rec{};
    defer streamed.deinit(testing.allocator);
    var stream_finder = try Finder.init("e", .{});
    const streamed_result = try searchReader(Rec, testing.allocator, &streamed, &reader, "", &stream_finder, .{
        .null_data = true,
        .line_numbers = true,
        .buffer_size = 3,
        .max_line_len = 64,
    });
    try testing.expectEqual(Outcome.complete, streamed_result.outcome);
    try testing.expectEqual(@as(?u64, null), streamed_result.binary_offset);
    try testing.expectEqualStrings("3:d\ne\n", streamed.text.items);
}

test "UTF-8 BOM is stripped and excluded from matching" {
    const hay = "\xEF\xBB\xBFfoo\nbar\n";
    var hit = try run(hay, "foo", .{ .line_numbers = true, .binary = .none });
    defer hit.deinit(testing.allocator);
    try testing.expectEqualStrings("1:foo\n", hit.text.items);

    var bom = try run(hay, "\xEF\xBB\xBF", .{ .binary = .none });
    defer bom.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 0), bom.matches);

    var byte = try run(hay, "\xEF", .{ .binary = .none });
    defer byte.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 0), byte.matches);

    const bad = "\xEF\xBB\xBFa\xffb\n";
    var replaced = Mark{};
    var rep_finder = try Finder.init("\u{FFFD}", .{});
    const rep = try searchSlice(Mark, &replaced, bad, "", &rep_finder, .{
        .binary = .none,
        .decode_allocator = testing.allocator,
    });
    try testing.expectEqual(@as(u64, 1), rep.matched_lines);
    try testing.expectEqualStrings("a\u{FFFD}b", replaced.bytes[0..replaced.len]);

    var raw_bad = try run(bad, "\xff", .{
        .binary = .none,
        .decode_allocator = testing.allocator,
    });
    defer raw_bad.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 0), raw_bad.matches);

    var reader = std.Io.Reader.fixed(hay);
    var finder = try Finder.init("foo", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const split = try searchReader(Rec, testing.allocator, &rec, &reader, "", &finder, .{
        .line_numbers = true,
        .binary = .none,
        .buffer_size = 2,
        .max_line_len = 64,
    });
    try testing.expectEqual(Outcome.complete, split.outcome);
    try testing.expectEqualStrings("1:foo\n", rec.text.items);
}

test "UTF-16LE and UTF-16BE match after transcoding to UTF-8" {
    // The read buffer is smaller than the BOM (2 bytes) plus one UTF-16 code unit (2 bytes), splitting the code unit across two chunks.
    const cap: usize = 3;
    try testing.expect(cap < 4);

    var le_buf: [10]u8 = undefined;
    const le = writeUtf16(&le_buf, true, "foo\n");
    var le_reader = std.Io.Reader.fixed(le);
    var le_finder = try Finder.init("foo", .{});
    var le_rec = Rec{};
    defer le_rec.deinit(testing.allocator);
    const le_result = try searchReader(Rec, testing.allocator, &le_rec, &le_reader, "", &le_finder, .{
        .line_numbers = true,
        .buffer_size = cap,
        .max_line_len = 64,
    });
    try testing.expectEqual(Outcome.complete, le_result.outcome);
    try testing.expectEqual(@as(?u64, null), le_result.binary_offset);
    try testing.expectEqualStrings("1:foo\n", le_rec.text.items);

    var be_buf: [10]u8 = undefined;
    const be = writeUtf16(&be_buf, false, "foo\n");
    var be_reader = std.Io.Reader.fixed(be);
    var be_finder = try Finder.init("foo", .{});
    var be_rec = Rec{};
    defer be_rec.deinit(testing.allocator);
    const be_result = try searchReader(Rec, testing.allocator, &be_rec, &be_reader, "", &be_finder, .{
        .line_numbers = true,
        .buffer_size = cap,
        .max_line_len = 64,
    });
    try testing.expectEqual(Outcome.complete, be_result.outcome);
    try testing.expectEqualStrings("1:foo\n", be_rec.text.items);

    var slice_mark = Mark{};
    var slice_finder = try Finder.init("foo", .{});
    const slice_result = try searchSlice(Mark, &slice_mark, le, "", &slice_finder, .{
        .decode_allocator = testing.allocator,
        .line_numbers = true,
    });
    try testing.expectEqual(Outcome.complete, slice_result.outcome);
    try testing.expectEqualStrings("foo", slice_mark.bytes[0..slice_mark.len]);
    try testing.expectEqual(@as(u64, 0), slice_mark.offset);
    try testing.expectEqual(@as(?u64, 1), slice_mark.number);
}

test "invalid UTF-16 is replaced with U+FFFD" {
    const lone = [_]u8{ 0xFF, 0xFE, 0x61, 0x00, 0x00, 0xD8, 0x62, 0x00, 0x0A, 0x00 };
    var mark = Mark{};
    var finder = try Finder.init("\u{FFFD}", .{});
    var reader = std.Io.Reader.fixed(&lone);
    const result = try searchReader(Mark, testing.allocator, &mark, &reader, "", &finder, .{
        .buffer_size = 3,
        .max_line_len = 64,
        .binary = .none,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqualStrings("a\u{FFFD}b", mark.bytes[0..mark.len]);

    const odd = [_]u8{ 0xFF, 0xFE, 0x61, 0x00, 0xFF };
    var odd_mark = Mark{};
    var odd_finder = try Finder.init("\u{FFFD}", .{});
    const odd_result = try searchSlice(Mark, &odd_mark, &odd, "", &odd_finder, .{
        .decode_allocator = testing.allocator,
        .binary = .none,
    });
    try testing.expectEqual(@as(u64, 1), odd_result.matched_lines);
    try testing.expectEqualStrings("a\u{FFFD}", odd_mark.bytes[0..odd_mark.len]);

    const be = [_]u8{ 0xFE, 0xFF, 0x00, 0x61, 0xD8, 0x00, 0x00, 0x0A };
    var be_mark = Mark{};
    var be_finder = try Finder.init("a", .{});
    const be_result = try searchSlice(Mark, &be_mark, &be, "", &be_finder, .{
        .decode_allocator = testing.allocator,
        .binary = .none,
    });
    try testing.expectEqual(@as(u64, 1), be_result.matched_lines);
    try testing.expectEqualStrings("a\u{FFFD}", be_mark.bytes[0..be_mark.len]);
}

test "raw byte mode does not sniff BOM" {
    const hay = "\xEF\xBB\xBFfoo\n";
    var kept = try run(hay, "\xEF\xBB\xBF", .{
        .encoding = .none,
        .line_numbers = true,
        .binary = .none,
    });
    defer kept.deinit(testing.allocator);
    try testing.expectEqualStrings("1:\xEF\xBB\xBFfoo\n", kept.text.items);

    var text = try run(hay, "foo", .{
        .encoding = .none,
        .line_numbers = true,
        .binary = .none,
    });
    defer text.deinit(testing.allocator);
    try testing.expectEqualStrings("1:\xEF\xBB\xBFfoo\n", text.text.items);

    var le_buf: [10]u8 = undefined;
    const le = writeUtf16(&le_buf, true, "foo\n");
    var miss = try run(le, "foo", .{ .encoding = .none, .binary = .none });
    defer miss.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 0), miss.matches);

    var bom = try run(le, "\xFF\xFE", .{ .encoding = .none, .binary = .none });
    defer bom.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 1), bom.matches);
}

test "match UTF-16 offsets are measured in code units" {
    const hay = "aé你😀x\n";
    var ex = Mark{};
    var ex_finder = try Finder.init("é", .{});
    _ = try searchSlice(Mark, &ex, hay, "", &ex_finder, .{ .binary = .none });
    try testing.expectEqual(@as(usize, 1), ex.b0);
    try testing.expectEqual(@as(usize, 3), ex.b1);
    try testing.expectEqual(@as(usize, 1), ex.u0);
    try testing.expectEqual(@as(usize, 2), ex.u1);
    try testing.expectEqual(@as(?u64, 2), ex.column);

    var face = Mark{};
    var face_finder = try Finder.init("😀", .{});
    _ = try searchSlice(Mark, &face, hay, "", &face_finder, .{ .binary = .none });
    try testing.expectEqual(@as(usize, 6), face.b0);
    try testing.expectEqual(@as(usize, 10), face.b1);
    try testing.expectEqual(@as(usize, 3), face.u0);
    try testing.expectEqual(@as(usize, 5), face.u1);
    try testing.expectEqual(@as(?u64, 4), face.column);

    var ex_x = Mark{};
    var x_finder = try Finder.init("x", .{});
    _ = try searchSlice(Mark, &ex_x, hay, "", &x_finder, .{ .binary = .none });
    try testing.expectEqual(@as(usize, 10), ex_x.b0);
    try testing.expectEqual(@as(usize, 11), ex_x.b1);
    try testing.expectEqual(@as(usize, 5), ex_x.u0);
    try testing.expectEqual(@as(usize, 6), ex_x.u1);
    try testing.expectEqual(@as(?u64, 6), ex_x.column);
}

test "invalid UTF-8 provides both lossy text and raw bytes" {
    const hay = "a\xffb\n";
    var letter = Mark{};
    var letter_finder = try Finder.init("b", .{});
    const found = try searchSlice(Mark, &letter, hay, "", &letter_finder, .{ .binary = .none });
    try testing.expectEqual(@as(u64, 1), found.matched_lines);
    try testing.expectEqualStrings("a\xffb", letter.bytes[0..letter.len]);
    try testing.expectEqualStrings("a\xffb", letter.raw[0..letter.raw_len]);
    try testing.expectEqualStrings("a\u{FFFD}b", letter.text[0..letter.text_len]);
    try testing.expectEqual(@as(usize, 2), letter.b0);
    try testing.expectEqual(@as(usize, 3), letter.b1);
    try testing.expectEqual(@as(usize, 2), letter.u0);
    try testing.expectEqual(@as(usize, 3), letter.u1);
    try testing.expectEqual(@as(?u64, 3), letter.column);

    var bad = Mark{};
    var bad_finder = try Finder.init("\xff", .{});
    _ = try searchSlice(Mark, &bad, hay, "", &bad_finder, .{ .binary = .none });
    try testing.expectEqual(@as(usize, 1), bad.b0);
    try testing.expectEqual(@as(usize, 2), bad.b1);
    try testing.expectEqual(@as(usize, 1), bad.u0);
    try testing.expectEqual(@as(usize, 2), bad.u1);
    try testing.expectEqualStrings("a\xffb", bad.raw[0..bad.raw_len]);
    try testing.expectEqualStrings("a\u{FFFD}b", bad.text[0..bad.text_len]);
}

const EvKind = enum { begin, match, context, brk, progress, heartbeat, end, summary };

const Saved = struct {
    kind: EvKind,
    id: []u8,
    line_number: u64 = 0,
    column: ?u64 = null,
    u16_column: ?u64 = null,
    offset: u64 = 0,
    bytes: []u8 = &.{},
    matches: []Span = &.{},
    truncated: bool = false,
    line_len: u64 = 0,
    window_start: u64 = 0,
    status: BinaryStatus = .none,
    matched_lines: u64 = 0,
    match_count: u64 = 0,
    bytes_searched: u64 = 0,
    bytes_printed: u64 = 0,
    bytes_read_raw: u64 = 0,
    elapsed: u64 = 0,
    searches: u64 = 0,
    searches_with_match: u64 = 0,
    sources_failed: u64 = 0,

    fn free(self: *Saved) void {
        const a = testing.allocator;
        if (self.id.len != 0) a.free(self.id);
        if (self.bytes.len != 0) a.free(self.bytes);
        if (self.matches.len != 0) a.free(self.matches);
    }
};

const Bag = struct {
    items: std.ArrayList(Saved) = .empty,

    fn deinit(self: *Bag) void {
        self.reset();
    }

    fn reset(self: *Bag) void {
        for (self.items.items) |*item| item.free();
        self.items.deinit(testing.allocator);
        self.items = .empty;
    }

    pub fn event(self: *Bag, ev: Event) bool {
        const saved: Saved = switch (ev) {
            .begin => |b| bare(.begin, b.source_id),
            .context_break => |b| bare(.brk, b.source_id),
            .progress => |p| blk: {
                var row = bare(.progress, p.source_id);
                row.bytes_searched = p.bytes_searched;
                row.match_count = p.matches;
                row.matched_lines = p.matched_lines;
                break :blk row;
            },
            .heartbeat => |h| blk: {
                var row = bare(.heartbeat, h.source_id);
                row.bytes_searched = h.bytes_searched;
                row.match_count = h.matches;
                row.matched_lines = h.matched_lines;
                break :blk row;
            },
            .end => |e| blk: {
                var row = bare(.end, e.source_id);
                row.status = e.binary_status;
                row.matched_lines = e.matched_lines;
                row.match_count = e.matches;
                break :blk row;
            },
            .summary => |s| blk: {
                var row = bare(.summary, s.source_id);
                row.elapsed = s.elapsed;
                row.searches = s.searches;
                row.searches_with_match = s.searches_with_match;
                row.bytes_searched = s.bytes_searched;
                row.bytes_printed = s.bytes_printed;
                row.matched_lines = s.matched_lines;
                row.match_count = s.matches;
                row.bytes_read_raw = s.bytes_read_raw;
                row.sources_failed = s.sources_failed;
                break :blk row;
            },
            .match => |line| fromLine(.match, line),
            .context => |line| fromLine(.context, line),
        };
        self.items.append(testing.allocator, saved) catch unreachable;
        return true;
    }

    fn kindCount(self: *const Bag, kind: EvKind) usize {
        var n: usize = 0;
        for (self.items.items) |item| {
            if (item.kind == kind) n += 1;
        }
        return n;
    }

    fn matchAt(self: *const Bag, n: usize) *const Saved {
        var seen: usize = 0;
        for (self.items.items) |*item| {
            if (item.kind != .match) continue;
            if (seen == n) return item;
            seen += 1;
        }
        unreachable;
    }

    fn find(self: *const Bag, kind: EvKind) *const Saved {
        var i = self.items.items.len;
        while (i > 0) {
            i -= 1;
            if (self.items.items[i].kind == kind) return &self.items.items[i];
        }
        unreachable;
    }
};

fn bare(kind: EvKind, id: []const u8) Saved {
    return .{
        .kind = kind,
        .id = testing.allocator.dupe(u8, id) catch unreachable,
    };
}

fn fromLine(kind: EvKind, line: LineEvent) Saved {
    const a = testing.allocator;
    return .{
        .kind = kind,
        .id = a.dupe(u8, line.source_id) catch unreachable,
        .line_number = line.line_number,
        .column = line.column,
        .u16_column = line.u16_column,
        .offset = line.absolute_offset,
        .bytes = if (line.bytes.len == 0) &.{} else a.dupe(u8, line.bytes) catch unreachable,
        .matches = if (line.matches.len == 0) &.{} else a.dupe(Span, line.matches) catch unreachable,
        .truncated = line.truncated,
        .line_len = line.line_len,
        .window_start = line.window_start,
        .status = line.binary_status,
    };
}

fn searchId(bag: *Bag, id: []const u8, hay: []const u8, pattern: []const u8, config: SearchConfig) !Result {
    var finder = try Finder.init(pattern, .{});
    return searchSourceSlice(Bag, bag, id, hay, &finder, config);
}

test "service entry points accept only a source ID" {
    var bag = Bag{};
    defer bag.deinit();
    const slice_result = try searchId(&bag, "sid-7", "MATCH\n", "MATCH", .{});
    try testing.expectEqual(Outcome.complete, slice_result.outcome);
    try testing.expect(bag.kindCount(.begin) == 1);
    try testing.expect(bag.kindCount(.end) == 1);
    try testing.expect(bag.kindCount(.match) == 1);
    for (bag.items.items) |item| try testing.expectEqualStrings("sid-7", item.id);

    bag.reset();
    var reader = std.Io.Reader.fixed("MATCH\n");
    var finder = try Finder.init("MATCH", .{});
    const read_result = try searchSource(Bag, testing.allocator, &bag, &reader, "sid-8", &finder, .{});
    try testing.expectEqual(Outcome.complete, read_result.outcome);
    try testing.expect(bag.kindCount(.match) == 1);
    for (bag.items.items) |item| try testing.expectEqualStrings("sid-8", item.id);
    try testing.expect(bag.items.items[0].kind == .begin);
    try testing.expect(bag.find(.end).kind == .end);
    try testing.expect(bag.items.items[bag.items.items.len - 1].kind == .summary);
}

test "events include line number, byte column, and absolute offset" {
    var bag = Bag{};
    defer bag.deinit();
    _ = try searchId(&bag, "pos", "éMATCH\nzz\nMATCH\n", "MATCH", .{});
    const first = bag.matchAt(0);
    try testing.expectEqual(@as(u64, 1), first.line_number);
    try testing.expectEqual(@as(?u64, 3), first.column);
    try testing.expectEqual(@as(?u64, 2), first.u16_column);
    try testing.expectEqual(@as(u64, 0), first.offset);
    try testing.expect(first.column != first.u16_column);

    const second = bag.matchAt(1);
    try testing.expectEqual(@as(u64, 3), second.line_number);
    try testing.expectEqual(@as(?u64, 1), second.column);
    try testing.expectEqual(@as(u64, 11), second.offset);

    bag.reset();
    _ = try searchId(&bag, "rec", "a\nb\x00zzMATCH", "MATCH", .{ .null_data = true });
    const record = bag.matchAt(0);
    try testing.expectEqual(@as(u64, 2), record.line_number);
    try testing.expectEqual(@as(?u64, 3), record.column);
    try testing.expectEqual(@as(u64, 4), record.offset);
    try testing.expectEqualStrings("zzMATCH", record.bytes);
}

test "multiple match spans on a single line are sorted by start offset" {
    var bag = Bag{};
    defer bag.deinit();
    _ = try searchId(&bag, "many", "abXabYab\n", "ab", .{});
    const line = bag.matchAt(0);
    try testing.expectEqual(@as(usize, 3), line.matches.len);
    try testing.expectEqual(@as(usize, 0), line.matches[0].start);
    try testing.expectEqual(@as(usize, 2), line.matches[0].end);
    try testing.expectEqual(@as(usize, 3), line.matches[1].start);
    try testing.expectEqual(@as(usize, 5), line.matches[1].end);
    try testing.expectEqual(@as(usize, 6), line.matches[2].start);
    try testing.expectEqual(@as(usize, 8), line.matches[2].end);
    try testing.expect(line.matches[0].start <= line.matches[1].start);
    try testing.expect(line.matches[1].start <= line.matches[2].start);
    try testing.expectEqualStrings("ab", line.bytes[line.matches[0].start..line.matches[0].end]);
    try testing.expectEqualStrings("ab", line.bytes[line.matches[2].start..line.matches[2].end]);
    try testing.expectEqual(@as(?u64, 1), line.column);
    try testing.expect(std.mem.indexOfScalar(u8, line.bytes, 0x1b) == null);
}

test "each event carries only the source ID" {
    var bag = Bag{};
    defer bag.deinit();
    _ = try searchId(&bag, "id-9", "a\nb\nMATCH\nc\nd\ne\nMATCH2\nf\n", "MATCH", .{
        .before = 1,
        .after = 1,
        .binary = .none,
    });
    try testing.expect(bag.kindCount(.begin) == 1);
    try testing.expect(bag.kindCount(.match) == 2);
    try testing.expect(bag.kindCount(.context) >= 1);
    try testing.expect(bag.kindCount(.brk) == 1);
    try testing.expect(bag.kindCount(.end) == 1);
    for (bag.items.items) |item| try testing.expectEqualStrings("id-9", item.id);
}

test "three binary status values" {
    var bag = Bag{};
    defer bag.deinit();
    _ = try searchId(&bag, "plain", "MATCH\n", "MATCH", .{});
    try testing.expectEqual(BinaryStatus.none, bag.find(.end).status);

    bag.reset();
    _ = try searchId(&bag, "text", "xxMATCH\x00yy\n", "MATCH", .{ .binary = .none });
    try testing.expectEqual(BinaryStatus.none, bag.find(.end).status);
    try testing.expect(std.mem.indexOfScalar(u8, bag.matchAt(0).bytes, 0) != null);

    bag.reset();
    _ = try searchId(&bag, "seen", "xxMATCH\x00yy\n", "MATCH", .{ .binary = .report });
    try testing.expectEqual(BinaryStatus.detected, bag.find(.end).status);

    bag.reset();
    _ = try searchId(&bag, "skip", "ab\x00MATCH\n", "MATCH", .{ .binary = .quit });
    try testing.expectEqual(BinaryStatus.suppressed, bag.find(.end).status);
    try testing.expectEqual(@as(u64, 0), bag.find(.end).matched_lines);
    try testing.expectEqual(@as(usize, 0), bag.kindCount(.match));
}

test "truncation fields come from the overlong line window" {
    var hay: [80]u8 = undefined;
    @memset(&hay, 'z');
    const match_at: usize = 40;
    @memcpy(hay[match_at..][0..5], "MATCH");
    var bag = Bag{};
    defer bag.deinit();
    _ = try searchId(&bag, "win", &hay, "MATCH", .{ .max_line_len = 16, .binary = .none });
    const line = bag.matchAt(0);
    try testing.expect(line.truncated);
    try testing.expectEqual(@as(u64, hay.len), line.line_len);
    try testing.expectEqual(@as(u64, 0), line.offset);
    try testing.expect(line.bytes.len <= 16);
    try testing.expect(line.bytes.len > 0);
    try testing.expectEqualStrings(hay[line.window_start..][0..line.bytes.len], line.bytes);
    try testing.expect(line.matches.len >= 1);
    try testing.expectEqual(@as(u64, match_at), line.window_start + line.matches[0].start);
}

test "unmatched source still emits begin and end" {
    var bag = Bag{};
    defer bag.deinit();
    const result = try searchId(&bag, "miss", "nope\n", "MATCH", .{});
    try testing.expectEqual(@as(u64, 0), result.matched_lines);
    try testing.expect(bag.items.items[0].kind == .begin);
    try testing.expect(bag.find(.end).kind == .end);
    try testing.expectEqualStrings("miss", bag.items.items[0].id);
    try testing.expectEqualStrings("miss", bag.find(.end).id);
    try testing.expectEqual(@as(u64, 0), bag.find(.end).matched_lines);
    try testing.expectEqual(@as(u64, 0), bag.find(.end).match_count);
    try testing.expectEqual(@as(usize, 0), bag.kindCount(.match));
}

test "leading whitespace on a line is returned verbatim" {
    var bag = Bag{};
    defer bag.deinit();
    _ = try searchId(&bag, "pad", "  MATCH\n", "MATCH", .{});
    const line = bag.matchAt(0);
    try testing.expectEqualStrings("  MATCH", line.bytes);
    try testing.expectEqual(@as(u64, 0), line.offset);
    try testing.expectEqual(@as(usize, 1), line.matches.len);
    try testing.expectEqual(@as(usize, 2), line.matches[0].start);
    try testing.expectEqual(@as(usize, 7), line.matches[0].end);
    try testing.expectEqual(@as(?u64, 3), line.column);
    try testing.expect(std.mem.indexOfScalar(u8, line.bytes, 0x1b) == null);
    try testing.expect(std.mem.indexOf(u8, line.bytes, "<") == null);
}

test "events are delivered one by one via callback" {
    var scratch: [8]u8 = undefined;
    var src = std.testing.Reader.init(&scratch, &.{.{ .buffer = "M\nM\n" }});
    src.artificial_limit = .limited(2);
    const Watch = struct {
        src: *std.testing.Reader,
        n: u32 = 0,
        offset_at_begin: usize = 99,
        offset_at_first: usize = 99,
        matches: u32 = 0,
        end_before_second: bool = false,

        pub fn event(self: *@This(), ev: Event) bool {
            self.n += 1;
            switch (ev) {
                .begin => self.offset_at_begin = self.src.next_offset,
                .match => {
                    self.matches += 1;
                    if (self.matches == 1) self.offset_at_first = self.src.next_offset;
                },
                .end => if (self.matches < 2) {
                    self.end_before_second = true;
                },
                else => {},
            }
            return true;
        }
    };
    var watch = Watch{ .src = &src };
    var finder = try Finder.init("M", .{});
    const result = try searchSource(Watch, testing.allocator, &watch, &src.interface, "stream", &finder, .{
        .buffer_size = 2,
        .max_line_len = 64,
        .binary = .none,
        .encoding = .none,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqual(@as(usize, 0), watch.offset_at_begin);
    try testing.expectEqual(@as(usize, 2), watch.offset_at_first);
    try testing.expectEqual(@as(u32, 2), watch.matches);
    try testing.expectEqual(@as(u32, 5), watch.n);
    try testing.expect(!watch.end_before_second);
}

const Quiet = struct {
    pub fn event(_: *@This(), _: Event) bool {
        return true;
    }
};

fn badRead(_: *anyopaque, _: []u8) error{BrokenStream}!usize {
    return error.BrokenStream;
}

const CapLog = struct {
    buf: [160]u8 = undefined,
    len: usize = 0,

    fn write(ctx: ?*anyopaque, message: []const u8) void {
        const self: *@This() = @ptrCast(@alignCast(ctx.?));
        const n = @min(message.len, self.buf.len);
        @memcpy(self.buf[0..n], message[0..n]);
        self.len = n;
    }
};

fn driveCapped(finder: *Finder, hay: []const u8, source_cap: ?u64, request_cap: ?u64) !struct {
    result: Result,
    rest: usize,
    closed: u32,
} {
    var ctx = CountedRead{ .rest = hay };
    var sink = Quiet{};
    const result = try drive(Quiet, testing.allocator, &sink, finder, .{
        .max_source_bytes = source_cap,
        .max_request_bytes = request_cap,
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 64,
        .close_input = CountedRead.close,
        .close_ctx = &ctx,
    }, "", CountedRead.read, &ctx);
    return .{ .result = result, .rest = ctx.rest.len, .closed = ctx.closed };
}

test "both source byte cap and request byte cap stop the search" {
    const hay = "MATCH\nMATCH\nMORE\n";
    var finder = try Finder.init("MATCH", .{});
    const source = try driveCapped(&finder, hay, 6, null);
    try testing.expectEqual(@as(u64, 6), source.result.bytes_read);
    try testing.expect(source.rest > 0);
    try testing.expectEqual(@as(u32, 1), source.closed);
    try testing.expectEqual(sink_mod.LimitHit.max_bytes, source.result.limit_hit);
    try testing.expect(source.result.partial);

    const request = try driveCapped(&finder, hay, null, 6);
    try testing.expectEqual(@as(u64, 6), request.result.bytes_read);
    try testing.expect(request.rest > 0);
    try testing.expectEqual(sink_mod.LimitHit.max_bytes, request.result.limit_hit);
    try testing.expectEqual(@as(u32, 1), request.closed);

    const request_wins = try driveCapped(&finder, hay, 100, 6);
    try testing.expectEqual(@as(u64, 6), request_wins.result.bytes_read);
    const source_wins = try driveCapped(&finder, hay, 6, 100);
    try testing.expectEqual(@as(u64, 6), source_wins.result.bytes_read);

    const open = try driveCapped(&finder, hay, null, null);
    try testing.expectEqual(@as(u64, hay.len), open.result.bytes_read);
    try testing.expectEqual(@as(usize, 0), open.rest);
    try testing.expectEqual(sink_mod.LimitHit.none, open.result.limit_hit);
    try testing.expect(!open.result.partial);
    try testing.expectEqual(@as(u32, 0), open.closed);
}

const DeadlineGate = struct {
    rest: []const u8,
    reads: usize = 0,
    matches: u32 = 0,
    blocked: bool = false,

    fn read(raw: *anyopaque, dest: []u8) ReadError!usize {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.reads += 1;
        if (self.reads > 1) {
            self.blocked = true;
            return 0;
        }
        const n = @min(dest.len, @min(self.rest.len, 12));
        @memcpy(dest[0..n], self.rest[0..n]);
        self.rest = self.rest[n..];
        return n;
    }

    fn now(raw: ?*anyopaque) i128 {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        if (self.matches == 0) return 0;
        return 1_000_000;
    }

    pub fn matched(self: *@This(), _: Line) bool {
        self.matches += 1;
        return true;
    }
};

test "deadline is enforced inside the matching loop" {
    var gate = DeadlineGate{ .rest = "MATCH\nMATCH\nTAIL\n" };
    var finder = try Finder.init("MATCH", .{});
    const result = try drive(DeadlineGate, testing.allocator, &gate, &finder, .{
        .binary = .none,
        .buffer_size = 64,
        .max_line_len = 64,
        .time_budget_ns = 1,
        .clock = DeadlineGate.now,
        .clock_ctx = &gate,
    }, "", DeadlineGate.read, &gate);
    try testing.expectEqual(@as(usize, 1), gate.reads);
    try testing.expect(!gate.blocked);
    try testing.expectEqual(@as(u32, 1), gate.matches);
    try testing.expectEqual(sink_mod.LimitHit.deadline, result.limit_hit);
    try testing.expect(result.partial);
    try testing.expectEqual(@as(u64, 1), result.matched_lines);
}

const CancelGate = struct {
    rest: []const u8,
    reads: usize = 0,
    matches: u32 = 0,
    closed: u32 = 0,
    flag: std.atomic.Value(bool) = .init(false),

    fn read(raw: *anyopaque, dest: []u8) ReadError!usize {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.reads += 1;
        if (self.reads > 1) return 0;
        const n = @min(dest.len, @min(self.rest.len, 12));
        @memcpy(dest[0..n], self.rest[0..n]);
        self.rest = self.rest[n..];
        return n;
    }

    fn close(raw: ?*anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        self.closed += 1;
    }

    pub fn matched(self: *@This(), _: Line) bool {
        self.matches += 1;
        self.flag.store(true, .release);
        return true;
    }
};

test "cancellation token closes upstream" {
    var gate = CancelGate{ .rest = "MATCH\nMATCH\nTAIL\n" };
    var finder = try Finder.init("MATCH", .{});
    const result = try drive(CancelGate, testing.allocator, &gate, &finder, .{
        .binary = .none,
        .buffer_size = 64,
        .max_line_len = 64,
        .cancel = &gate.flag,
        .close_input = CancelGate.close,
        .close_ctx = &gate,
    }, "", CancelGate.read, &gate);
    try testing.expectEqual(@as(u32, 1), gate.matches);
    try testing.expectEqual(@as(usize, 1), gate.reads);
    try testing.expectEqual(@as(u32, 1), gate.closed);
    try testing.expectEqual(sink_mod.LimitHit.cancelled, result.limit_hit);
    try testing.expect(result.partial);
}

const Page = struct {
    lines: std.ArrayList([]u8) = .empty,
    cursor: ?u64 = null,
    limit: sink_mod.LimitHit = .none,
    partial: bool = false,

    fn deinit(self: *Page) void {
        for (self.lines.items) |line| testing.allocator.free(line);
        self.lines.deinit(testing.allocator);
    }

    pub fn event(self: *Page, ev: Event) bool {
        switch (ev) {
            .match => |line| {
                const copy = testing.allocator.dupe(u8, line.bytes) catch unreachable;
                self.lines.append(testing.allocator, copy) catch unreachable;
            },
            .end => |end| {
                self.cursor = end.resume_at;
                self.limit = end.limit_hit;
                self.partial = end.partial;
            },
            else => {},
        }
        return true;
    }
};

test "max_results populates resume offset" {
    const hay = "aa MATCH\nbb MATCH\ncc MATCH\n";
    var finder = try Finder.init("MATCH", .{});
    var first = Page{};
    defer first.deinit();
    const opened = try searchSourceSlice(Page, &first, "page", hay, &finder, .{
        .max_results = 1,
        .binary = .none,
    });
    try testing.expectEqual(sink_mod.LimitHit.max_results, opened.limit_hit);
    try testing.expectEqual(sink_mod.LimitHit.max_results, first.limit);
    try testing.expect(first.partial);
    try testing.expectEqual(@as(usize, 1), first.lines.items.len);
    try testing.expectEqualStrings("aa MATCH", first.lines.items[0]);
    const cursor = first.cursor orelse return error.TestExpectedEqual;
    try testing.expectEqual(cursor, opened.resume_at.?);

    var second = Page{};
    defer second.deinit();
    const continued = try searchSourceSlice(Page, &second, "page", hay, &finder, .{
        .resume_from = cursor,
        .binary = .none,
    });
    try testing.expectEqual(sink_mod.LimitHit.none, continued.limit_hit);
    try testing.expect(!continued.partial);
    try testing.expectEqual(@as(usize, 2), second.lines.items.len);
    try testing.expectEqualStrings("bb MATCH", second.lines.items[0]);
    try testing.expectEqualStrings("cc MATCH", second.lines.items[1]);
}

const OutCount = struct {
    matches: u32 = 0,
    contexts: u32 = 0,

    pub fn event(self: *OutCount, ev: Event) bool {
        switch (ev) {
            .match => self.matches += 1,
            .context => self.contexts += 1,
            else => {},
        }
        return true;
    }
};

test "output byte cap stops emitting further line events" {
    var finder = try Finder.init("MATCH", .{});
    var lines = OutCount{};
    _ = try searchSourceSlice(OutCount, &lines, "out", "MATCH\nMATCH\n", &finder, .{
        .max_output_bytes = 5,
        .binary = .none,
    });
    try testing.expectEqual(@as(u32, 1), lines.matches);
    try testing.expectEqual(@as(u32, 0), lines.contexts);

    var around = OutCount{};
    _ = try searchSourceSlice(OutCount, &around, "ctx", "ab\nMATCH\n", &finder, .{
        .max_output_bytes = 2,
        .before = 1,
        .binary = .none,
    });
    try testing.expectEqual(@as(u32, 1), around.contexts);
    try testing.expectEqual(@as(u32, 0), around.matches);
}

const QueueSink = struct {
    called: bool = false,
    live: u32 = 0,
    max_live: u32 = 0,

    pub fn matched(self: *QueueSink, _: Line) bool {
        self.called = true;
        self.live += 1;
        self.max_live = @max(self.max_live, self.live);
        self.live -= 1;
        return true;
    }
};

const DecodeFeed = struct {
    left: usize = 8000,
    sent: usize = 0,
    reads: usize = 0,

    fn read(raw: *anyopaque, dest: []u8) ReadError!usize {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.reads += 1;
        var i: usize = 0;
        if (self.sent == 0 and dest.len >= 2) {
            dest[0] = 0xff;
            dest[1] = 0xfe;
            i = 2;
            self.sent = 2;
        }
        while (i < dest.len and self.left > 0) {
            dest[i] = 'a';
            i += 1;
            self.left -= 1;
            self.sent += 1;
        }
        return i;
    }
};

test "all three internal buffers enforce their caps" {
    var finder = try Finder.init("MATCH", .{});
    var reads: usize = 0;
    const CountRead = struct {
        fn read(raw: *anyopaque, dest: []u8) ReadError!usize {
            _ = dest;
            const n: *usize = @ptrCast(@alignCast(raw));
            n.* += 1;
            return 0;
        }
    };
    var sink = Quiet{};
    try testing.expectError(error.BufferLimit, drive(Quiet, testing.allocator, &sink, &finder, .{
        .before = 4,
        .max_line_len = 64,
        .max_before_bytes = 8,
        .binary = .none,
        .buffer_size = 16,
    }, "", CountRead.read, &reads));
    try testing.expectEqual(@as(usize, 0), reads);

    var feed = DecodeFeed{};
    var counted = CountAlloc{ .parent = testing.allocator };
    try testing.expectError(error.DecodeLimit, drive(Quiet, counted.allocator(), &sink, &finder, .{
        .encoding = .auto,
        .max_decode_bytes = 8,
        .buffer_size = 32,
        .max_line_len = 64,
        .binary = .none,
    }, "", DecodeFeed.read, &feed));
    try testing.expect(feed.reads <= 2);
    try testing.expect(feed.left > 0);
    try testing.expect(counted.peak < 8192);

    var queued = QueueSink{};
    try testing.expectError(error.BufferLimit, searchSlice(QueueSink, &queued, "MATCH\n", "q", &finder, .{
        .max_queued_event_bytes = 2,
        .binary = .none,
    }));
    try testing.expect(!queued.called);

    queued = .{};
    _ = try searchSlice(QueueSink, &queued, "MATCH\nMATCH\n", "", &finder, .{
        .max_queued_event_bytes = 8,
        .binary = .none,
    });
    try testing.expect(queued.called);
    try testing.expectEqual(@as(u32, 1), queued.max_live);
}

test "budgets come from caller parameters" {
    const hay = "MATCH\nMATCH\nMORE\n";
    var finder = try Finder.init("MATCH", .{});
    const tight = try driveCapped(&finder, hay, 4, null);
    const loose = try driveCapped(&finder, hay, 100, null);
    try testing.expect(tight.result.bytes_read < loose.result.bytes_read);
    try testing.expectEqual(@as(u64, hay.len), loose.result.bytes_read);

    const caller = SearchConfig{ .max_concurrency = 3 };
    try testing.expectEqual(@as(?u32, 3), caller.max_concurrency);
    try testing.expect((SearchConfig{}).max_source_bytes == null);

    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    try testing.expectError(error.BudgetExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .max_source_bytes = SearchConfig.max_source_bytes_hard_cap + 1,
    }));
    try testing.expectError(error.BudgetExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .time_budget_ns = SearchConfig.max_time_budget_ns + 1,
    }));

    var reader = std.Io.Reader.fixed(hay);
    var quiet = Quiet{};
    const served = try searchSource(Quiet, testing.allocator, &quiet, &reader, "tenant", &finder, .{
        .max_source_bytes = 6,
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 64,
    });
    try testing.expectEqual(@as(u64, 6), served.bytes_read);
    try testing.expectEqual(sink_mod.LimitHit.max_bytes, served.limit_hit);
}

test "directly passed streams are also subject to the source size cap" {
    var finder = try Finder.init("MATCH", .{});
    var sink = Quiet{};
    var reader = std.Io.Reader.fixed("MATCH\nMORE MATCH\n");
    const stopped = try searchSource(Quiet, testing.allocator, &sink, &reader, "direct", &finder, .{
        .max_source_bytes = 6,
        .max_request_bytes = SearchConfig.max_request_bytes_hard_cap,
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 64,
        .encoding = .none,
    });
    try testing.expectEqual(@as(u64, 6), stopped.bytes_read);
    try testing.expectEqual(sink_mod.LimitHit.max_bytes, stopped.limit_hit);
    try testing.expect(stopped.partial);
    try testing.expect(stopped.bytes_read < "MATCH\nMORE MATCH\n".len);

    const armed = serviceConfig(.{});
    try testing.expectEqual(SearchConfig.default_max_source_bytes, armed.max_source_bytes.?);
    try testing.expectEqual(SearchConfig.default_max_request_bytes, armed.max_request_bytes.?);
    try testing.expect(armed.max_source_bytes.? <= SearchConfig.max_source_bytes_hard_cap);
    try testing.expectEqual(SearchConfig.default_time_budget_ns, armed.time_budget_ns.?);
    try testing.expectEqual(BinaryPolicy.quit, (SearchConfig{}).binary);

    const total: usize = @intCast(SearchConfig.default_max_source_bytes + 32);
    const big = try testing.allocator.alloc(u8, total);
    defer testing.allocator.free(big);
    @memset(big, 'a');
    var at: usize = 15;
    while (at < big.len) : (at += 16) big[at] = '\n';
    @memcpy(big[0..5], "MATCH");
    var wide = std.Io.Reader.fixed(big);
    const capped = try searchSource(Quiet, testing.allocator, &sink, &wide, "direct-default", &finder, .{
        .binary = .none,
        .buffer_size = 64 * 1024,
        .max_line_len = 64,
        .encoding = .none,
    });
    try testing.expectEqual(SearchConfig.default_max_source_bytes, capped.bytes_read);
    try testing.expectEqual(sink_mod.LimitHit.max_bytes, capped.limit_hit);
    try testing.expect(capped.bytes_read < big.len);
}

test "default build does not memory-map files" {
    try testing.expect(!build_options.window_map);
}

test "soft errors are distinguishable from matches and non-matches" {
    var finder = try Finder.init("MATCH", .{});
    var sink = Quiet{};
    const matched = try searchSlice(Quiet, &sink, "MATCH\n", "", &finder, .{ .binary = .none });
    try testing.expect(matched.soft_error == null);
    try testing.expect(matched.matched_lines > 0);

    const missed = try searchSlice(Quiet, &sink, "nope\n", "", &finder, .{ .binary = .none });
    try testing.expect(missed.soft_error == null);
    try testing.expectEqual(@as(u64, 0), missed.matched_lines);
    try testing.expectEqual(Outcome.complete, missed.outcome);

    var raw: u8 = 0;
    const soft = try drive(Quiet, testing.allocator, &sink, &finder, .{
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 32,
    }, "src", badRead, &raw);
    try testing.expectEqual(sink_mod.SoftError.read_failed, soft.soft_error.?);
    try testing.expect(soft.soft_error != missed.soft_error);
    try testing.expectEqual(@as(u64, 0), soft.matched_lines);

    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    try testing.expectError(error.ContextLinesExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .context = SearchConfig.context_lines_hard_cap + 1,
    }));
}

test "returned errors do not contain file paths" {
    const secret = "/var/lib/secret/path.txt";
    var log = CapLog{};
    var finder = try Finder.init("MATCH", .{});
    var sink = Quiet{};
    try testing.expectError(error.BufferLimit, searchSlice(Quiet, &sink, "MATCH\n", secret, &finder, .{
        .max_queued_event_bytes = 1,
        .binary = .none,
        .log = CapLog.write,
        .log_ctx = &log,
    }));
    try testing.expect(std.mem.indexOf(u8, log.buf[0..log.len], secret) != null);
    try testing.expect(std.mem.indexOf(u8, @errorName(error.BufferLimit), secret) == null);

    log.len = 0;
    var raw: u8 = 0;
    const soft = try drive(Quiet, testing.allocator, &sink, &finder, .{
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 32,
        .log = CapLog.write,
        .log_ctx = &log,
    }, secret, badRead, &raw);
    try testing.expectEqual(sink_mod.SoftError.read_failed, soft.soft_error.?);
    try testing.expect(std.mem.indexOf(u8, log.buf[0..log.len], secret) != null);
    try testing.expect(std.mem.indexOf(u8, @tagName(soft.soft_error.?), "/") == null);
}

test "core does not read environment variables" {
    var finder = try Finder.init("MATCH", .{});
    var sink = Quiet{};
    const open = try searchSlice(Quiet, &sink, "MATCH\n", "", &finder, .{});
    try testing.expectEqual(Outcome.complete, open.outcome);
    try testing.expectEqual(sink_mod.LimitHit.none, open.limit_hit);
    try testing.expectEqual(@as(u64, 1), open.matched_lines);
    const cfg = SearchConfig{ .max_concurrency = 2 };
    try testing.expectEqual(@as(?u32, 2), cfg.max_concurrency);
    try testing.expect(cfg.max_source_bytes == null);
    try testing.expect(cfg.time_budget_ns == null);
}

const ExistsGate = struct {
    rest: []const u8,
    reads: usize = 0,
    matches: u32 = 0,
    closed: u32 = 0,

    fn read(raw: *anyopaque, dest: []u8) ReadError!usize {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.reads += 1;
        if (self.reads > 1) return 0;
        const n = @min(dest.len, @min(self.rest.len, 6));
        @memcpy(dest[0..n], self.rest[0..n]);
        self.rest = self.rest[n..];
        return n;
    }

    fn close(raw: ?*anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        self.closed += 1;
    }

    pub fn matched(self: *@This(), _: Line) bool {
        self.matches += 1;
        return true;
    }
};

test "existence query stops after the first match" {
    var gate = ExistsGate{ .rest = "MATCH\nMORE MATCH\n" };
    var finder = try Finder.init("MATCH", .{});
    const result = try drive(ExistsGate, testing.allocator, &gate, &finder, .{
        .exists = true,
        .binary = .none,
        .buffer_size = 32,
        .max_line_len = 64,
        .close_input = ExistsGate.close,
        .close_ctx = &gate,
    }, "", ExistsGate.read, &gate);
    try testing.expectEqual(@as(u32, 1), gate.matches);
    try testing.expectEqual(@as(usize, 1), gate.reads);
    try testing.expectEqual(@as(u32, 1), gate.closed);
    try testing.expectEqual(@as(u64, 1), result.matched_lines);
    try testing.expectEqual(sink_mod.LimitHit.none, result.limit_hit);
}

test "limit_hit covers every stop reason" {
    var seen: [@typeInfo(sink_mod.LimitHit).@"enum".field_names.len]bool = @splat(false);
    var finder = try Finder.init("MATCH", .{});
    var sink = Quiet{};

    const plain = try searchSlice(Quiet, &sink, "MATCH\n", "", &finder, .{ .binary = .none });
    seen[@backingInt(plain.limit_hit)] = true;

    const bytes = try driveCapped(&finder, "MATCH\nMATCH\nMORE\n", 6, null);
    seen[@backingInt(bytes.result.limit_hit)] = true;

    var deadline = DeadlineGate{ .rest = "MATCH\nMATCH\nTAIL\n" };
    const timed = try drive(DeadlineGate, testing.allocator, &deadline, &finder, .{
        .binary = .none,
        .buffer_size = 64,
        .max_line_len = 64,
        .time_budget_ns = 1,
        .clock = DeadlineGate.now,
        .clock_ctx = &deadline,
    }, "", DeadlineGate.read, &deadline);
    seen[@backingInt(timed.limit_hit)] = true;

    var cancel = CancelGate{ .rest = "MATCH\nMATCH\nTAIL\n" };
    const stopped = try drive(CancelGate, testing.allocator, &cancel, &finder, .{
        .binary = .none,
        .buffer_size = 64,
        .max_line_len = 64,
        .cancel = &cancel.flag,
        .close_input = CancelGate.close,
        .close_ctx = &cancel,
    }, "", CancelGate.read, &cancel);
    seen[@backingInt(stopped.limit_hit)] = true;

    var page = Page{};
    defer page.deinit();
    const capped = try searchSourceSlice(Page, &page, "p", "MATCH\nMATCH\n", &finder, .{
        .max_results = 1,
        .binary = .none,
    });
    seen[@backingInt(capped.limit_hit)] = true;

    var raw: u8 = 0;
    const inflated = try drive(Quiet, testing.allocator, &sink, &finder, .{
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 32,
        .decompressed_bytes = 8,
        .max_decompressed_bytes = 4,
    }, "", badRead, &raw);
    seen[@backingInt(inflated.limit_hit)] = true;

    for (std.enums.values(sink_mod.LimitHit)) |reason| {
        try testing.expect(seen[@backingInt(reason)]);
    }
}

test "incomplete scans mark counts as partial" {
    var finder = try Finder.init("MATCH", .{});
    var watch = Page{};
    defer watch.deinit();
    var reader = std.Io.Reader.fixed("MATCH\nMATCH\nMORE\n");
    const stopped = try searchSource(Page, testing.allocator, &watch, &reader, "count", &finder, .{
        .max_source_bytes = 6,
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 64,
    });
    try testing.expect(stopped.partial);
    try testing.expect(watch.partial);
    try testing.expect(stopped.matched_lines < 2);
    try testing.expectEqual(stopped.partial, watch.partial);

    var full_watch = Page{};
    defer full_watch.deinit();
    var full = std.Io.Reader.fixed("MATCH\nMATCH\n");
    const done = try searchSource(Page, testing.allocator, &full_watch, &full, "count", &finder, .{
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 64,
        .max_source_bytes = SearchConfig.default_max_source_bytes,
        .max_request_bytes = SearchConfig.default_max_request_bytes,
    });
    try testing.expect(!done.partial);
    try testing.expect(!full_watch.partial);
    try testing.expectEqual(@as(u64, 2), done.matched_lines);
}

test "match count is distinct from matched line count" {
    var bag = Bag{};
    defer bag.deinit();
    const result = try searchId(&bag, "g03", "MATCH MATCH\nMATCH\n", "MATCH", .{ .binary = .none });
    try testing.expectEqual(@as(u64, 2), result.matched_lines);
    try testing.expectEqual(@as(u64, 3), result.matches);
    try testing.expectEqual(@as(u64, 2), bag.find(.end).matched_lines);
    try testing.expectEqual(@as(u64, 3), bag.find(.end).match_count);
}

test "files_without_match stops at the first hit" {
    const Watch = struct {
        matches: u32 = 0,
        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) self.matches += 1;
            return true;
        }
    };
    var scratch: [32]u8 = undefined;
    const hay = "MATCH\nMORE\n";
    var src = std.testing.Reader.init(&scratch, &.{.{ .buffer = hay }});
    src.artificial_limit = .limited(6);
    var watch = Watch{};
    var finder = try Finder.init("MATCH", .{});
    var closed = std.atomic.Value(bool).init(false);
    const result = try searchSource(Watch, testing.allocator, &watch, &src.interface, "miss-list", &finder, .{
        .files_without_match = true,
        .buffer_size = 6,
        .max_line_len = 64,
        .binary = .none,
        .encoding = .none,
        .close_input = struct {
            fn close(ctx: ?*anyopaque) void {
                const flag: *std.atomic.Value(bool) = @ptrCast(@alignCast(ctx.?));
                flag.store(true, .release);
            }
        }.close,
        .close_ctx = &closed,
    });
    try testing.expectEqual(@as(u32, 0), watch.matches);
    try testing.expectEqual(@as(u64, 1), result.matched_lines);
    try testing.expect(closed.load(.acquire));
    try testing.expect(src.next_offset < hay.len);

    var bag = Bag{};
    defer bag.deinit();
    const missed = try searchId(&bag, "none", "nope\n", "ZZ", .{ .files_without_match = true, .binary = .none });
    try testing.expectEqual(@as(u64, 0), missed.matched_lines);
    try testing.expectEqual(@as(u64, 0), bag.find(.end).matched_lines);
    try testing.expectEqual(@as(u64, 0), bag.find(.end).match_count);
    try testing.expectEqual(@as(usize, 0), bag.kindCount(.match));
}

test "zero-match source still has counts in end event" {
    var bag = Bag{};
    defer bag.deinit();
    const result = try searchId(&bag, "zero", "nothing\n", "MATCH", .{ .binary = .none });
    try testing.expectEqual(@as(u64, 0), result.matched_lines);
    try testing.expectEqual(@as(u64, 0), result.matches);
    const end = bag.find(.end);
    try testing.expectEqual(@as(u64, 0), end.matched_lines);
    try testing.expectEqual(@as(u64, 0), end.match_count);
    try testing.expectEqualStrings("zero", end.id);
}

test "counts: single file, multiple files, zero matches, and binary" {
    var one = Bag{};
    defer one.deinit();
    const single = try searchId(&one, "one", "MATCH\nno\nMATCH MATCH\n", "MATCH", .{ .binary = .none });
    try testing.expectEqual(@as(u64, 2), single.matched_lines);
    try testing.expectEqual(@as(u64, 3), single.matches);
    try testing.expectEqual(@as(u64, 2), one.find(.end).matched_lines);
    try testing.expectEqual(@as(u64, 3), one.find(.end).match_count);

    var multi = Bag{};
    defer multi.deinit();
    _ = try searchId(&multi, "a.txt", "MATCH\n", "MATCH", .{ .binary = .none });
    const a_end = multi.find(.end);
    try testing.expectEqual(@as(u64, 1), a_end.matched_lines);
    try testing.expectEqualStrings("a.txt", a_end.id);
    multi.reset();
    _ = try searchId(&multi, "b.txt", "no\n", "MATCH", .{ .binary = .none });
    try testing.expectEqual(@as(u64, 0), multi.find(.end).matched_lines);
    try testing.expectEqualStrings("b.txt", multi.find(.end).id);

    var zero = Bag{};
    defer zero.deinit();
    _ = try searchId(&zero, "t.txt", "no\n", "MATCH", .{ .binary = .none });
    try testing.expectEqual(@as(u64, 0), zero.find(.end).match_count);

    var bin = Bag{};
    defer bin.deinit();
    const binary = try searchId(&bin, "bin", "MATCH\na\x00\nMATCH2\n", "MATCH", .{ .binary = .report });
    try testing.expectEqual(@as(u64, 2), binary.matched_lines);
    try testing.expect(binary.matches >= 2);
    try testing.expectEqual(@as(u64, 2), bin.find(.end).matched_lines);
}

test "counts: lines promoted to matches inside max_count after-context window are also counted" {
    const Nop = struct {
        pub fn matched(_: *@This(), _: Line) bool {
            return true;
        }
    };
    var nop = Nop{};
    var finder = try Finder.init("MATCH", .{});
    const result = try searchSlice(Nop, &nop, "a\nb\nMATCH\nc\nd\ne\nMATCH2\nf\n", "", &finder, .{
        .after = 4,
        .max_count = 1,
        .line_numbers = true,
        .binary = .none,
    });
    try testing.expectEqual(@as(u64, 2), result.matched_lines);
}

test "summary fields are complete and summary is omitted when scan is incomplete" {
    const Clock = struct {
        now: i128 = 0,
        fn tick(ctx: ?*anyopaque) i128 {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.now += 5;
            return self.now;
        }
    };
    var clock = Clock{};
    var bag = Bag{};
    defer bag.deinit();
    const hay = "MATCH MATCH\nMATCH\n";
    _ = try searchId(&bag, "sum", hay, "MATCH", .{
        .binary = .none,
        .clock = Clock.tick,
        .clock_ctx = &clock,
        .time_budget_ns = SearchConfig.max_time_budget_ns,
    });
    try testing.expectEqual(@as(usize, 1), bag.kindCount(.summary));
    const sum = bag.find(.summary);
    try testing.expect(sum.elapsed >= 5);
    try testing.expectEqual(@as(u64, 1), sum.searches);
    try testing.expectEqual(@as(u64, 1), sum.searches_with_match);
    try testing.expectEqual(@as(u64, hay.len), sum.bytes_searched);
    try testing.expect(sum.bytes_printed > 0);
    try testing.expectEqual(@as(u64, 2), sum.matched_lines);
    try testing.expectEqual(@as(u64, 3), sum.match_count);
    try testing.expectEqual(@as(u64, hay.len), sum.bytes_read_raw);
    try testing.expectEqual(@as(u64, 0), sum.sources_failed);
    try testing.expect(bag.find(.end).kind == .end);

    bag.reset();
    _ = try searchId(&bag, "part", "MATCH\nMATCH\nMORE\n", "MATCH", .{
        .max_source_bytes = 4,
        .binary = .none,
    });
    try testing.expectEqual(@as(usize, 0), bag.kindCount(.summary));
    try testing.expectEqual(@as(usize, 1), bag.kindCount(.end));
}

test "progress includes bytes_searched and match counts" {
    var bag = Bag{};
    defer bag.deinit();
    _ = try searchId(&bag, "prog", "MATCH\nabcd\nMATCH\n", "MATCH", .{
        .progress_interval = 4,
        .binary = .none,
    });
    try testing.expect(bag.kindCount(.progress) >= 1);
    var saw_bytes = false;
    var saw_matches = false;
    for (bag.items.items) |item| {
        if (item.kind != .progress) continue;
        if (item.bytes_searched >= 4) saw_bytes = true;
        if (item.match_count >= 1) saw_matches = true;
    }
    try testing.expect(saw_bytes);
    try testing.expect(saw_matches);
}

test "callback can pause and resume" {
    const Gate = struct {
        hits: u32 = 0,
        ends: u32 = 0,
        begins: u32 = 0,
        pub fn event(self: *@This(), ev: Event) Flow {
            switch (ev) {
                .begin => self.begins += 1,
                .match => {
                    self.hits += 1;
                    if (self.hits == 1) return .pause;
                },
                .end => self.ends += 1,
                else => {},
            }
            return .cont;
        }
    };
    var gate = Gate{};
    var finder = try Finder.init("MATCH", .{});
    const hay = "MATCH\nno\nMATCH\n";
    const first = try searchSourceSlice(Gate, &gate, "pause", hay, &finder, .{ .binary = .none });
    try testing.expect(first.paused);
    try testing.expectEqual(@as(u32, 1), gate.hits);
    try testing.expectEqual(@as(u32, 1), gate.begins);
    try testing.expectEqual(@as(u32, 0), gate.ends);

    const second = try resumeSourceSlice(Gate, &gate, "pause", hay, &finder, .{ .binary = .none }, first);
    try testing.expect(!second.paused);
    try testing.expectEqual(@as(u32, 2), gate.hits);
    try testing.expectEqual(@as(u32, 1), gate.begins);
    try testing.expectEqual(@as(u32, 1), gate.ends);
    try testing.expectEqual(@as(u64, 2), second.matched_lines);
    try testing.expect(second.scanned_all);

    const Stop = struct {
        hits: u32 = 0,
        ends: u32 = 0,
        pub fn event(self: *@This(), ev: Event) Flow {
            switch (ev) {
                .match => {
                    self.hits += 1;
                    return .stop;
                },
                .end => self.ends += 1,
                else => {},
            }
            return .cont;
        }
    };
    var stop = Stop{};
    const stopped = try searchSourceSlice(Stop, &stop, "stop", hay, &finder, .{ .binary = .none });
    try testing.expect(!stopped.paused);
    try testing.expectEqual(@as(u32, 1), stop.hits);
    try testing.expectEqual(@as(u32, 1), stop.ends);
    try testing.expect(!stopped.scanned_all);
}

test "pull interface yields begin through end" {
    var finder = try Finder.init("MATCH", .{});
    var pull = openSourcePull(testing.allocator, &finder, "pull-1", "a\nMATCH\nb\n", .{
        .before = 1,
        .after = 1,
        .binary = .none,
    });
    defer pull.deinit();
    var saw_begin = false;
    var saw_context = false;
    var saw_match = false;
    var saw_end = false;
    while (try pull.next()) |ev| {
        switch (ev.kind) {
            .begin => {
                saw_begin = true;
                try testing.expectEqualStrings("pull-1", ev.source_id);
            },
            .context => {
                try testing.expect(saw_begin);
                try testing.expect(!saw_end);
                saw_context = true;
            },
            .match => {
                try testing.expect(saw_begin);
                try testing.expectEqualStrings("MATCH", ev.bytes);
                saw_match = true;
            },
            .end => {
                try testing.expect(saw_begin);
                try testing.expect(saw_match);
                saw_end = true;
            },
            else => {},
        }
    }
    try testing.expect(saw_begin);
    try testing.expect(saw_context);
    try testing.expect(saw_match);
    try testing.expect(saw_end);
}

test "live stream emits heartbeat when idle" {
    const Src = struct {
        step: u8 = 0,
        now: i128 = 0,
        closed: std.atomic.Value(bool) = .init(false),
        heartbeats: u32 = 0,
        summary_before_heartbeat: bool = false,
        saw_summary: bool = false,
        saw_end: bool = false,

        fn clock(ctx: ?*anyopaque) i128 {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            return self.now;
        }

        fn read(ctx: *anyopaque, dest: []u8) ReadError!usize {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.step += 1;
            switch (self.step) {
                1 => {
                    const data = "idle\n";
                    @memcpy(dest[0..data.len], data);
                    return data.len;
                },
                2 => {
                    self.now = 1_000;
                    return 0;
                },
                3 => {
                    const data = "MATCH\n";
                    @memcpy(dest[0..data.len], data);
                    return data.len;
                },
                else => {
                    self.closed.store(true, .release);
                    return 0;
                },
            }
        }

        pub fn event(self: *@This(), ev: Event) bool {
            switch (ev) {
                .heartbeat => {
                    self.heartbeats += 1;
                    self.summary_before_heartbeat = self.saw_summary;
                },
                .summary => self.saw_summary = true,
                .end => self.saw_end = true,
                else => {},
            }
            return true;
        }
    };
    var src = Src{};
    var finder = try Finder.init("MATCH", .{});
    const cfg = SearchConfig{
        .live = true,
        .idle_timeout_ns = 1_000,
        .live_closed = &src.closed,
        .clock = Src.clock,
        .clock_ctx = &src,
        .time_budget_ns = SearchConfig.max_time_budget_ns,
        .binary = .none,
        .buffer_size = 64,
        .max_line_len = 64,
        .encoding = .none,
        .line_numbers = true,
    };
    var bridge = EventBridge(Src){
        .inner = &src,
        .source_id = "live",
        .config = cfg,
    };
    const result = try drive(EventBridge(Src), testing.allocator, &bridge, &finder, cfg, "live", Src.read, &src);
    try testing.expect(src.heartbeats >= 1);
    try testing.expect(!src.summary_before_heartbeat);
    try testing.expect(src.saw_end);
    try testing.expect(!src.saw_summary);
    try testing.expectEqual(sink_mod.LimitHit.none, result.limit_hit);
    try testing.expect(result.soft_error == null);
    try testing.expectEqual(@as(u64, 1), result.matched_lines);
    emitSummary(Src, &src, "live", cfg, result);
    try testing.expect(src.saw_summary);
}

test "writes source ID and stops on the first hit" {
    const Stop = struct {
        id: []const u8 = "",
        hits: u32 = 0,
        pub fn event(self: *@This(), ev: Event) bool {
            switch (ev) {
                .begin => |b| self.id = b.source_id,
                .match => |line| {
                    self.hits += 1;
                    self.id = line.source_id;
                    return false;
                },
                else => {},
            }
            return true;
        }
    };
    var scratch: [32]u8 = undefined;
    const hay = "no\nMATCH\nMATCH\n";
    var src = std.testing.Reader.init(&scratch, &.{.{ .buffer = hay }});
    src.artificial_limit = .limited(9);
    var stop = Stop{};
    var finder = try Finder.init("MATCH", .{});
    const result = try searchSource(Stop, testing.allocator, &stop, &src.interface, "src-1", &finder, .{
        .buffer_size = 9,
        .max_line_len = 64,
        .binary = .none,
        .encoding = .none,
    });
    try testing.expectEqualStrings("src-1", stop.id);
    try testing.expectEqual(@as(u32, 1), stop.hits);
    try testing.expectEqual(@as(u64, 1), result.matched_lines);
    try testing.expect(src.next_offset < hay.len);
}

test "empty line in pattern list matches all lines and limits are checked before construction" {
    const Multi = @import("../finder/multi.zig").Multi;
    var multi = try Multi.initFromText(testing.allocator, "alpha\r\n\nomega", .{});
    defer multi.deinit();
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const res = try searchSlice(Rec, &rec, "one\ntwo\nthree\n", "", &multi, .{ .line_numbers = true });
    try testing.expectEqual(@as(u64, 3), res.matched_lines);
}

test "ordered input stops and closes upstream at the first non-matching line after a hit" {
    const OrderedSrc = struct {
        reads: usize = 0,
        closed: bool = false,
        matched: u32 = 0,

        fn read(ctx: *anyopaque, dest: []u8) ReadError!usize {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.reads += 1;
            const chunk: []const u8 = switch (self.reads) {
                1 => "2026-01-01 skip\n2026-01-02 MATCH-1\n",
                2 => "2026-01-02 MATCH-2\n2026-01-03 after\n",
                3 => "2026-01-02 MATCH-LATE\n",
                else => "",
            };
            @memcpy(dest[0..chunk.len], chunk);
            return chunk.len;
        }

        fn close(ctx: ?*anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.closed = true;
        }

        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) self.matched += 1;
            return true;
        }
    };

    var src = OrderedSrc{};
    var finder = try Finder.init("2026-01-02", .{});
    const cfg = SearchConfig{
        .stop_on_nonmatch = true,
        .close_input = OrderedSrc.close,
        .close_ctx = &src,
        .buffer_size = 64,
        .max_line_len = 64,
        .binary = .none,
        .encoding = .none,
    };
    var bridge = EventBridge(OrderedSrc){
        .inner = &src,
        .source_id = "ordered",
        .config = cfg,
    };
    const result = try drive(EventBridge(OrderedSrc), testing.allocator, &bridge, &finder, cfg, "ordered", OrderedSrc.read, &src);
    try testing.expectEqual(@as(u64, 2), result.matched_lines);
    try testing.expectEqual(@as(u32, 2), src.matched);
    try testing.expectEqual(@as(usize, 2), src.reads);
    try testing.expect(src.closed);
}

test "passthru mode emits all lines and respects max_output_bytes" {
    const PassSink = struct {
        match_lines: u32 = 0,
        context_lines: u32 = 0,
        breaks: u32 = 0,

        pub fn event(self: *@This(), ev: Event) bool {
            switch (ev) {
                .match => self.match_lines += 1,
                .context => self.context_lines += 1,
                .context_break => self.breaks += 1,
                else => {},
            }
            return true;
        }
    };

    var finder = try Finder.init("HIT", .{});
    const hay = "line1\nHIT-line2\nline3\nHIT-line4\nline5\n";

    var full = PassSink{};
    const res_full = try searchSourceSlice(PassSink, &full, "doc", hay, &finder, .{
        .passthru = true,
        .line_numbers = true,
    });
    try testing.expectEqual(@as(u64, 2), res_full.matched_lines);
    try testing.expectEqual(@as(u32, 2), full.match_lines);
    try testing.expectEqual(@as(u32, 3), full.context_lines);
    try testing.expectEqual(@as(u32, 0), full.breaks);
    try testing.expect(!res_full.partial);

    var capped = PassSink{};
    const res_capped = try searchSourceSlice(PassSink, &capped, "doc", hay, &finder, .{
        .passthru = true,
        .max_output_bytes = 16,
    });
    try testing.expect(res_capped.partial);
    try testing.expect(!res_capped.scanned_all);
    try testing.expectEqual(@as(u32, 1), capped.match_lines);
    try testing.expectEqual(@as(u32, 1), capped.context_lines);
}

test "replacement preview does not mutate input and matches span replacement text" {
    const ReplSink = struct {
        saw_line: bool = false,
        replaced_copy: [64]u8 = undefined,
        replaced_len: usize = 0,
        span_count: usize = 0,
        first_repl: []const u8 = "",
        raw_ref: []const u8 = "",

        pub fn event(self: *@This(), ev: Event) bool {
            switch (ev) {
                .match => |line| {
                    self.saw_line = true;
                    self.raw_ref = line.bytes;
                    self.span_count = line.matches.len;
                    if (line.matches.len > 0) {
                        self.first_repl = line.matches[0].replacement orelse "";
                    }
                    if (line.replaced) |r| {
                        @memcpy(self.replaced_copy[0..r.len], r);
                        self.replaced_len = r.len;
                    }
                },
                else => {},
            }
            return true;
        }
    };

    var input_buf = "hello foo and foo!\n".*;
    var finder = try Finder.init("foo", .{});
    var sink = ReplSink{};
    const res = try searchSourceSlice(ReplSink, &sink, "repl", &input_buf, &finder, .{
        .replacement = "BAR_BAZ",
    });
    try testing.expectEqual(@as(u64, 1), res.matched_lines);
    try testing.expectEqual(@as(u64, 2), res.matches);
    try testing.expect(sink.saw_line);
    try testing.expectEqualStrings("hello foo and foo!\n", &input_buf);
    try testing.expectEqualStrings("hello foo and foo!", sink.raw_ref);
    try testing.expectEqual(@as(usize, 2), sink.span_count);
    try testing.expectEqualStrings("BAR_BAZ", sink.first_repl);
    try testing.expectEqualStrings("hello BAR_BAZ and BAR_BAZ!", sink.replaced_copy[0..sink.replaced_len]);
}

test "Regex integration with Searcher and replacement preview" {
    const Regex = @import("../regex.zig").Regex;
    const Collect = struct {
        hits: u32 = 0,
        replaced_buf: [64]u8 = undefined,
        replaced_len: usize = 0,

        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) {
                self.hits += 1;
                if (ev.match.replaced) |r| {
                    @memcpy(self.replaced_buf[0..r.len], r);
                    self.replaced_len = r.len;
                }
            }
            return true;
        }
    };

    var re = try Regex.init(testing.allocator, "ERR_[0-9]+", .{});
    defer re.deinit();

    var sink = Collect{};
    const res = try searchSourceSlice(Collect, &sink, "log", "ok\nfail ERR_502 and ERR_504!\n", &re, .{
        .replacement = "CODE",
    });
    try testing.expectEqual(@as(u64, 1), res.matched_lines);
    try testing.expectEqual(@as(u64, 2), res.matches);
    try testing.expectEqual(@as(u32, 1), sink.hits);
    try testing.expectEqualStrings("fail CODE and CODE!", sink.replaced_buf[0..sink.replaced_len]);
}

test "stops reading upstream once multiline window is exhausted" {
    const Regex = @import("../regex.zig").Regex;
    const MlStream = struct {
        reads: usize = 0,
        closed: bool = false,
        hits: u32 = 0,

        fn read(ctx: *anyopaque, dest: []u8) ReadError!usize {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.reads += 1;
            const chunk: []const u8 = switch (self.reads) {
                1 => "BEGIN\n1234567890\n",
                2 => "12345678901234567890\n",
                3 => "END\n",
                else => "",
            };
            @memcpy(dest[0..chunk.len], chunk);
            return chunk.len;
        }

        fn close(ctx: ?*anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.closed = true;
        }

        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) self.hits += 1;
            return true;
        }
    };

    var src = MlStream{};
    var re = try Regex.init(testing.allocator, "\\ABEGIN.*END", .{
        .multiline = true,
        .dot_all = true,
        .max_multiline_window = 24,
    });
    defer re.deinit();

    const cfg = SearchConfig{
        .close_input = MlStream.close,
        .close_ctx = &src,
        .buffer_size = 64,
        .max_line_len = 64,
        .binary = .none,
        .encoding = .none,
    };
    var bridge = EventBridge(MlStream){
        .inner = &src,
        .source_id = "ml",
        .config = cfg,
    };
    const res = try drive(EventBridge(MlStream), testing.allocator, &bridge, &re, cfg, "ml", MlStream.read, &src);
    try testing.expectEqual(@as(u64, 0), res.matched_lines);
    try testing.expectEqual(@as(u32, 0), src.hits);
    try testing.expectEqual(@as(usize, 2), src.reads);
    try testing.expect(src.closed);
}

test "gzip bomb is blocked by compression ratio and decompressed byte caps" {
    var finder = try Finder.init("MATCH", .{});
    const gz_ok = try decompress.compressGzipStoredAlloc(testing.allocator, "skip\nMATCH_HERE\n");
    defer testing.allocator.free(gz_ok);

    var quiet = Quiet{};
    const ok_res = try searchSourceSlice(Quiet, &quiet, "gz-ok", gz_ok, &finder, .{
        .compression = .auto,
        .decode_allocator = testing.allocator,
    });
    try testing.expectEqual(@as(u64, 1), ok_res.matched_lines);
    try testing.expectEqual(sink_mod.LimitHit.none, ok_res.limit_hit);

    // 1. Blocked by decompressed byte cap `max_decompressed_bytes`
    const cap_res = try searchSourceSlice(Quiet, &quiet, "gz-cap", gz_ok, &finder, .{
        .compression = .auto,
        .decode_allocator = testing.allocator,
        .max_decompressed_bytes = 8,
    });
    try testing.expectEqual(sink_mod.LimitHit.decompressed_bytes, cap_res.limit_hit);
    try testing.expect(cap_res.partial);

    // 2. Blocked by maximum compression ratio `max_compression_ratio` (24-byte Gzip bomb inflating to 1032 bytes)
    const bomb_gz = [_]u8{
        0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x73, 0x74, 0xa4, 0x3d, 0x00, 0x00, 0x8d, 0xef, 0x72, 0x2f,
        0x08, 0x04, 0x00, 0x00,
    };
    var bomb_reader = std.Io.Reader.fixed(&bomb_gz);
    const bomb_res = try searchSource(Quiet, testing.allocator, &quiet, &bomb_reader, "gz-bomb", &finder, .{
        .compression = .gzip,
        .max_compression_ratio = 3,
    });
    try testing.expectEqual(sink_mod.LimitHit.decompressed_bytes, bomb_res.limit_hit);
    try testing.expect(bomb_res.partial);
}

test "zstd decompression shares bomb limits and classifies corruption as a soft error" {
    var finder = try Finder.init("MATCH_ZSTD", .{});
    const zst_ok = try decompress.compressZstdRawAlloc(testing.allocator, "line1\nMATCH_ZSTD\n");
    defer testing.allocator.free(zst_ok);

    var quiet = Quiet{};
    var ok_reader = std.Io.Reader.fixed(zst_ok);
    const ok_res = try searchSource(Quiet, testing.allocator, &quiet, &ok_reader, "zst-ok", &finder, .{
        .compression = .auto,
    });
    try testing.expectEqual(@as(u64, 1), ok_res.matched_lines);
    try testing.expect(ok_res.soft_error == null);

    // Blocked by decompression limit
    var cap_reader = std.Io.Reader.fixed(zst_ok);
    const cap_res = try searchSource(Quiet, testing.allocator, &quiet, &cap_reader, "zst-cap", &finder, .{
        .compression = .auto,
        .max_decompressed_bytes = 6,
    });
    try testing.expectEqual(sink_mod.LimitHit.decompressed_bytes, cap_res.limit_hit);

    // A corrupt zstd stream does not raise a fatal error; it maps to SoftError.read_failed
    const corrupt_zst = [_]u8{ 0x28, 0xB5, 0x2F, 0xFD, 0xFF, 0xFF, 0xFF };
    var bad_reader = std.Io.Reader.fixed(&corrupt_zst);
    const bad_res = try searchSource(Quiet, testing.allocator, &quiet, &bad_reader, "zst-bad", &finder, .{
        .compression = .auto,
    });
    try testing.expectEqual(sink_mod.SoftError.read_failed, bad_res.soft_error.?);
}

test "GBK transcoding via charset hint matches and maps offsets" {
    // GBK-encoded lines:
    // Line 1: C4 E3 BA C3, Line 2: B2 E2 CA D4 B4 ED CE F3 C8 D5 D6 BE
    const gbk_bytes = "\xC4\xE3\xBA\xC3\n\xB2\xE2\xCA\xD4\xB4\xED\xCE\xF3\xC8\xD5\xD6\xBE\n";
    var finder = try Finder.init("错误", .{});

    const OffsetSink = struct {
        hits: u32 = 0,
        abs_off: u64 = 0,
        raw_off: u64 = 0,

        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) {
                self.hits += 1;
                self.abs_off = ev.match.absolute_offset;
                self.raw_off = ev.match.raw_offset;
            }
            return true;
        }
    };

    var sink = OffsetSink{};
    const res = try searchSourceSlice(OffsetSink, &sink, "gbk-doc", gbk_bytes, &finder, .{
        .charset = "text/plain; charset=GBK",
        .decode_allocator = testing.allocator,
    });
    try testing.expectEqual(@as(u64, 1), res.matched_lines);
    try testing.expectEqual(@as(u32, 1), sink.hits);
    // In UTF-8 the first line takes 3 + 3 + 1 = 7 bytes; in raw GBK "\xC4\xE3\xBA\xC3\n" takes 2 + 2 + 1 = 5 bytes
    try testing.expectEqual(@as(u64, 7), sink.abs_off);
    try testing.expectEqual(@as(u64, 5), sink.raw_off);
}

test "preserves raw byte stream offsets after transcoding and decompression" {
    const OffsetSink = struct {
        abs_off: u64 = 0,
        raw_off: u64 = 0,

        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) {
                self.abs_off = ev.match.absolute_offset;
                self.raw_off = ev.match.raw_offset;
            }
            return true;
        }
    };

    // UTF-16LE with 2-byte BOM (FF FE), line 1 "ab\n" (6 bytes), line 2 "HIT\n" (8 bytes).
    // Line 2 is at offset 3 ("ab\n") in transcoded UTF-8, and at offset 2 (BOM) + 6 ("ab\n") = 8 in the raw UTF-16LE stream.
    const utf16le_data = [_]u8{
        0xFF, 0xFE,
        'a',  0,
        'b',  0,
        '\n', 0,
        'H',  0,
        'I',  0,
        'T',  0,
        '\n', 0,
    };
    var finder = try Finder.init("HIT", .{});
    var sink = OffsetSink{};
    var reader = std.Io.Reader.fixed(&utf16le_data);
    const res = try searchSource(OffsetSink, testing.allocator, &sink, &reader, "u16", &finder, .{});
    try testing.expectEqual(@as(u64, 1), res.matched_lines);
    try testing.expectEqual(@as(u64, 3), sink.abs_off);
    try testing.expectEqual(@as(u64, 8), sink.raw_off);
}

test "filter_smart_case, contains_regexes, and excludes_regexes" {
    var finder = try Finder.init("ERROR", .{});
    var re_must = try regex_mod.Regex.init(testing.allocator, "code=[0-9]+", .{});
    defer re_must.deinit();
    var re_overlap = try regex_mod.Regex.init(testing.allocator, "ERROR_[0-9]+", .{});
    defer re_overlap.deinit();
    var re_excl = try regex_mod.Regex.init(testing.allocator, "ignore_[a-z]+", .{});
    defer re_excl.deinit();

    const SpanCheckSink = struct {
        matched_lines: u32 = 0,
        span_count: usize = 0,
        first_span: Span = .{ .start = 0, .end = 0 },

        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) {
                self.matched_lines += 1;
                self.span_count = ev.match.matches.len;
                if (ev.match.matches.len >= 1) self.first_span = ev.match.matches[0];
            }
            return true;
        }
    };

    const input =
        "ERROR_500 service=Auth code=500\n" ++
        "ERROR_500 service=auth code=500\n" ++
        "ERROR_500 service=Auth code=500 ignore_me\n" ++
        "ERROR_500 service=Auth no_code\n";

    var sink = SpanCheckSink{};
    // Smart-case filter: "auth" (all lowercase -> case-insensitive, matches both Auth and auth),
    // "Auth" (has uppercase -> case-sensitive, matches only Auth).
    const res = try searchSourceSlice(SpanCheckSink, &sink, "filter-regex", input, &finder, .{
        .contains = &.{ "auth", "Auth" },
        .filter_smart_case = true,
        .contains_regexes = &.{ re_must, re_overlap },
        .excludes_regexes = &.{re_excl},
    });
    try testing.expectEqual(@as(u64, 1), res.matched_lines);
    try testing.expectEqual(@as(u32, 1), sink.matched_lines);
    // Primary matcher (`finder` = "ERROR") span [0..5) is reported cleanly without contains_regexes pollution.
    try testing.expectEqual(@as(usize, 1), sink.span_count);
    try testing.expectEqual(@as(usize, 0), sink.first_span.start);
    try testing.expectEqual(@as(usize, 5), sink.first_span.end);
}

test "regex capture group replacement and literal dollar escape" {
    var re = try regex_mod.Regex.init(testing.allocator, "([a-z]+)=([0-9]+)", .{});
    defer re.deinit();

    var pull = openSourcePull(testing.allocator, &re, "repl", "key=42 port=8080\n", .{
        .replacement = "${2}:$1($$/$0)",
    });
    defer pull.deinit();

    var matched = false;
    while (try pull.next()) |ev| {
        if (ev.kind == .match) {
            matched = true;
            try testing.expectEqualStrings("42:key($/key=42) 8080:port($/port=8080)", ev.replaced.?);
        }
    }
    try testing.expect(matched);
}

test "resumeSource and UTF-16LE tail resumeSourceSlice" {
    const utf16le_data = [_]u8{
        0xFF, 0xFE,
        'H',  0,
        'I',  0,
        'T',  0,
        '\n', 0,
        'H',  0,
        'I',  0,
        'T',  0,
        '\n', 0,
    };
    const PauseOnce = struct {
        pause_first: bool = true,
        begins: u32 = 0,
        hits: u32 = 0,
        last_raw_off: u64 = 0,

        pub fn event(self: *@This(), ev: Event) Flow {
            switch (ev) {
                .begin => self.begins += 1,
                .match => |m| {
                    self.hits += 1;
                    self.last_raw_off = m.raw_offset;
                    if (self.pause_first) {
                        self.pause_first = false;
                        return .pause;
                    }
                },
                else => {},
            }
            return .cont;
        }
    };

    var finder = try Finder.init("HIT", .{});
    var sink = PauseOnce{};
    const first = try searchSourceSlice(PauseOnce, &sink, "u16-resume", &utf16le_data, &finder, .{
        .decode_allocator = testing.allocator,
    });
    try testing.expect(first.paused);
    try testing.expectEqual(@as(u64, 10), first.resume_state.raw_resume_at);
    const second = try resumeSourceSlice(PauseOnce, &sink, "u16-resume", &utf16le_data, &finder, .{
        .decode_allocator = testing.allocator,
    }, first);
    try testing.expect(!second.paused);
    try testing.expectEqual(@as(u32, 1), sink.begins);
    try testing.expectEqual(@as(u32, 2), sink.hits);
    try testing.expectEqual(@as(u64, 10), sink.last_raw_off);

    // Also verify resumeSource over a std.Io.Reader stream
    var r1 = std.Io.Reader.fixed("HIT\nHIT\n");
    var stream_sink = PauseOnce{};
    const s_first = try searchSource(PauseOnce, testing.allocator, &stream_sink, &r1, "stream-resume", &finder, .{});
    try testing.expect(s_first.paused);
    var r2 = std.Io.Reader.fixed("HIT\nHIT\n");
    const s_second = try resumeSource(PauseOnce, testing.allocator, &stream_sink, &r2, "stream-resume", &finder, .{}, s_first);
    try testing.expect(!s_second.paused);
    try testing.expectEqual(@as(u32, 1), stream_sink.begins);
    try testing.expectEqual(@as(u32, 2), stream_sink.hits);
}

test "Unicode whole_word, Unicode filter_smart_case, and streaming compression=.auto" {
    const CountSink = struct {
        hits: u32 = 0,
        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) self.hits += 1;
            return true;
        }
    };

    var finder_cjk = try Finder.init("你好", .{});
    var sink_w = CountSink{};
    // Line 1 has U+4F60 U+597D bounded by spaces/parens; Line 2 embeds it inside adjacent CJK word characters.
    const res_w = try searchSourceSlice(CountSink, &sink_w, "u-word", " (你好) \n世界你好吗\n", &finder_cjk, .{
        .whole_word = true,
    });
    try testing.expectEqual(@as(u64, 1), res_w.matched_lines);
    try testing.expectEqual(@as(u32, 1), sink_w.hits);

    // Unicode smart-case line filter: "δelta" (all lowercase -> case-insensitive) matches "ΔELTA", while "Δelta" (has uppercase) is case-sensitive.
    var sink_f = CountSink{};
    const res_f = try searchSourceSlice(CountSink, &sink_f, "u-filter", "你好 ΔELTA\n你好 Δelta\n", &finder_cjk, .{
        .contains = &.{ "δelta", "Δelta" },
        .filter_smart_case = true,
    });
    try testing.expectEqual(@as(u64, 1), res_f.matched_lines);

    // Streaming compression = .auto on an uncompressed stream stops after the first chunk when exists = true.
    var big_stream: [8192]u8 = @splat('x');
    @memcpy(big_stream[0.."你好\n".len], "你好\n");
    var reader = std.Io.Reader.fixed(&big_stream);
    var sink_auto = CountSink{};
    const res_auto = try searchSource(CountSink, testing.allocator, &sink_auto, &reader, "auto-stream", &finder_cjk, .{
        .compression = .auto,
        .buffer_size = 64,
        .exists = true,
    });
    try testing.expectEqual(@as(u64, 1), res_auto.matched_lines);
    try testing.expect(res_auto.bytes_read < 512);
}

