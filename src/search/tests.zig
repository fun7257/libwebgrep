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
const validateBudgets = searcher.config_mod.validateBudgets;
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
    try testing.expectEqualStrings("MATCH\n", quiet.text.items);
    const q = try finishOf("MATCH\nfoo\x00\n", "MATCH", .quit);
    try testing.expectEqual(Outcome.binary_quit, q.outcome);
    try testing.expectEqual(@as(u64, 1), q.matched_lines);

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
    try testing.expectEqual(@as(u64, 1), quit_result.matched_lines);
    try testing.expectEqualStrings("MATCH\n", quit.text.items);

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
    try testing.expect(std.mem.find(u8, rec.text.items, "MATCH") != null);
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
    try testing.expect(std.mem.findScalar(u8, plain.text.items, '\r') == null);

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

    var pats: [matcher_mod.default_max_pattern_count + 1][]const u8 = undefined;
    for (&pats) |*slot| slot.* = "a";
    try testing.expectError(error.PatternCountExceeded, searchOrReject(alloc, &pats, .{}, &gate));
    try testing.expectEqual(@as(usize, 0), gate.reads);
    try testing.expectEqual(@as(usize, 0), failing.allocations);

    // Raising max_pattern_count above former hard cap allows patterns to pass limit gate
    var allowed_gate = LimitGate{};
    _ = searchOrReject(alloc, &pats, .{
        .max_pattern_count = matcher_mod.default_max_pattern_count + 50,
    }, &allowed_gate) catch {};

    // Lowering max_pattern_count below count still fails
    try testing.expectError(error.PatternCountExceeded, searchOrReject(alloc, &pats, .{
        .max_pattern_count = matcher_mod.default_max_pattern_count - 10,
    }, &gate));
    try testing.expectEqual(@as(usize, 0), gate.reads);

    try testing.expectError(error.PatternCountExceeded, Multi.init(alloc, &.{ "a", "b" }, .{ .max_pattern_count = 1 }));
    try testing.expectError(error.PatternBytesExceeded, Multi.init(alloc, &.{"abcd"}, .{ .max_pattern_bytes = 3 }));
    try testing.expectError(error.PatternCountExceeded, Finder.init("a", .{ .max_pattern_count = 0 }));

    const big = try testing.allocator.alloc(u8, matcher_mod.default_max_pattern_bytes + 1);
    defer testing.allocator.free(big);
    @memset(big, 'b');
    // Default limit rejects big pattern bytes
    try testing.expectError(error.PatternBytesExceeded, searchOrReject(alloc, &.{big}, .{}, &gate));
    try testing.expectError(error.PatternBytesExceeded, Finder.init(big, .{}));
    // Custom limit higher than former hard cap allows it past limit gate
    _ = searchOrReject(alloc, &.{big}, .{
        .max_pattern_bytes = matcher_mod.default_max_pattern_bytes + 10,
    }, &gate) catch {};
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
    try testing.expect(std.mem.find(u8, slice_win.bytes, "MATCH") != null);
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
    try testing.expect(std.mem.find(u8, read_win.bytes, "MATCH") != null);
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
    try testing.expect(std.mem.find(u8, win.bytes, "MATCH") != null);
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
    try testing.expect(std.mem.find(u8, rec.text.items, "--") == null);
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
    // Before > 10 without allocator or scratch_pool returns error.BufferLimit
    try testing.expectError(error.BufferLimit, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .before = over,
        .max_context_lines = over + 5,
        .binary = .none,
    }));
    const ok_high = try searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .before = over,
        .max_context_lines = over + 5,
        .binary = .none,
        .allocator = testing.allocator,
    });
    try testing.expectEqual(@as(u64, 1), ok_high.matched_lines);
    try testing.expectError(error.ContextLinesExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .before = over + 6,
        .max_context_lines = over + 5,
        .allocator = testing.allocator,
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
    try testing.expect(std.mem.findScalar(u8, line.bytes, 0x1b) == null);
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
    try testing.expect(std.mem.findScalar(u8, bag.matchAt(0).bytes, 0) != null);

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
    try testing.expect(std.mem.findScalar(u8, line.bytes, 0x1b) == null);
    try testing.expect(std.mem.find(u8, line.bytes, "<") == null);
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
    // Custom limits above former hard caps are accepted without error
    _ = try searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .max_source_bytes = SearchConfig.max_source_bytes_hard_cap + 1,
    });
    _ = try searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .time_budget_ns = SearchConfig.max_time_budget_ns + 1,
    });
    // Artificial invalid budgets are still rejected
    try testing.expectError(error.BudgetExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .max_line_len = std.math.maxInt(usize),
    }));
    try testing.expectError(error.BudgetExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .max_compression_ratio = 0,
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
    try testing.expect(std.mem.find(u8, log.buf[0..log.len], secret) != null);
    try testing.expect(std.mem.find(u8, @errorName(error.BufferLimit), secret) == null);

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
    try testing.expect(std.mem.find(u8, log.buf[0..log.len], secret) != null);
    try testing.expect(std.mem.find(u8, @tagName(soft.soft_error.?), "/") == null);
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

test "AnyMatcher, AnyEventSink, AnySink.init, and pattern_id propagation in search pipeline" {
    const EventRecorder = struct {
        matches: u32 = 0,
        last_pids: [8]?u32 = @splat(null),
        last_pids_len: usize = 0,
        replaced_buf: [64]u8 = undefined,
        replaced_len: usize = 0,

        pub fn event(self: *@This(), ev: Event) Flow {
            if (ev == .match) {
                self.matches += 1;
                const n = @min(ev.match.matches.len, self.last_pids.len);
                for (0..n) |i| self.last_pids[i] = ev.match.matches[i].pattern_id;
                self.last_pids_len = n;
                if (ev.match.replaced) |r| {
                    const rn = @min(r.len, self.replaced_buf.len);
                    @memcpy(self.replaced_buf[0..rn], r[0..rn]);
                    self.replaced_len = rn;
                }
            }
            return .cont;
        }
    };

    const Multi = @import("../finder/multi.zig").Multi;
    var multi = try Multi.init(testing.allocator, &.{ "alpha", "beta", "gamma" }, .{});
    defer multi.deinit();
    const any_multi = matcher_mod.AnyMatcher.init(Multi, &multi);

    var rec = EventRecorder{};
    var any_ev_sink = sink_mod.AnyEventSink.init(EventRecorder, &rec);
    const res_m = try searchSourceSlice(sink_mod.AnyEventSink, &any_ev_sink, "poly-multi", "beta and gamma and alpha\n", &any_multi, .{});
    try testing.expectEqual(@as(u64, 1), res_m.matched_lines);
    try testing.expectEqual(@as(usize, 3), rec.last_pids_len);
    try testing.expectEqual(@as(?u32, 1), rec.last_pids[0]);
    try testing.expectEqual(@as(?u32, 2), rec.last_pids[1]);
    try testing.expectEqual(@as(?u32, 0), rec.last_pids[2]);

    // Whole-line match with Multi and AnyMatcher preserves pattern_id
    rec = .{};
    _ = try searchSourceSlice(sink_mod.AnyEventSink, &any_ev_sink, "poly-wl", "alpha\ngamma\n", &any_multi, .{
        .whole_line = true,
    });
    try testing.expectEqual(@as(u32, 2), rec.matches);
    try testing.expectEqual(@as(?u32, 2), rec.last_pids[0]);

    // Regex wrapped in AnyMatcher preserves $1 capture group replacement preview
    var re = try regex_mod.Regex.init(testing.allocator, "user=([a-z]+)", .{});
    defer re.deinit();
    const any_re = matcher_mod.AnyMatcher.init(regex_mod.Regex, &re);
    rec = .{};
    _ = try searchSourceSlice(sink_mod.AnyEventSink, &any_ev_sink, "poly-re", "id: user=alice ok\n", &any_re, .{
        .replacement = "[$1]",
    });
    try testing.expectEqualStrings("id: [alice] ok", rec.replaced_buf[0..rec.replaced_len]);

    // Legacy AnySink.init helper
    const LegacyCollector = struct {
        lines: u32 = 0,
        last_pid: ?u32 = null,
        pub fn matched(self: *@This(), line: Line) bool {
            self.lines += 1;
            if (line.match) |m| self.last_pid = m.pattern_id;
            return true;
        }
    };
    var leg = LegacyCollector{};
    var any_leg = sink_mod.AnySink.init(LegacyCollector, &leg);
    _ = try searchSlice(sink_mod.AnySink, &any_leg, "xxgammayy\n", "leg", &any_multi, .{});
    try testing.expectEqual(@as(u32, 1), leg.lines);
    try testing.expectEqual(@as(?u32, 2), leg.last_pid);
}

test "Scratch pool achieves zero steady-state allocations across slice and reader searches" {
    var scratch = searcher.Scratch.init(testing.allocator);
    defer scratch.deinit();

    var finder = try Finder.init("HIT", .{});
    const NoopSink = struct {
        hits: usize = 0,
        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) self.hits += 1;
            return true;
        }
    };

    // Build a line with >32 matches to force heap span buffer growth on warm-up
    var many_hits_line: [512]u8 = undefined;
    var pos: usize = 0;
    for (0..40) |_| {
        @memcpy(many_hits_line[pos .. pos + 4], "HIT ");
        pos += 4;
    }
    many_hits_line[pos] = '\n';
    pos += 1;
    const payload = many_hits_line[0..pos];

    var sink = NoopSink{};
    var r1 = std.Io.Reader.fixed(payload);
    _ = try searchSource(NoopSink, testing.allocator, &sink, &r1, "warm-1", &finder, .{
        .before = 2,
        .buffer_size = 64,
        .max_line_len = 256,
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(usize, 1), sink.hits);

    // Second streaming search with FailingAllocator as the call allocator must succeed with 0 new allocations
    var fail_alloc = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    var r2 = std.Io.Reader.fixed(payload);
    _ = try searchSource(NoopSink, fail_alloc.allocator(), &sink, &r2, "warm-2", &finder, .{
        .before = 2,
        .buffer_size = 64,
        .max_line_len = 256,
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(usize, 2), sink.hits);
    try testing.expectEqual(@as(usize, 0), fail_alloc.allocations);

    // Slice search with >32 spans on a single line reuses scratch.span_buf with 0 new allocations
    _ = try searchSourceSlice(NoopSink, &sink, "slice-warm", payload, &finder, .{
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(usize, 3), sink.hits);
}

test "regression: >64 spans on a line and Scratch.span_buf growth preserve all spans without Use-After-Free" {
    const Multi = @import("../finder/multi.zig").Multi;
    var multi = try Multi.init(testing.allocator, &.{ "AA", "BB", "CC" }, .{});
    defer multi.deinit();

    var line = std.ArrayList(u8).empty;
    defer line.deinit(testing.allocator);
    for (0..45) |_| try line.appendSlice(testing.allocator, "AA BB ");
    try line.appendSlice(testing.allocator, "CC\n"); // 91 matches total (> 64)

    const VerifySink = struct {
        count: usize = 0,
        first_pid: ?u32 = null,
        second_pid: ?u32 = null,
        last_pid: ?u32 = null,
        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) {
                self.count = ev.match.matches.len;
                if (ev.match.matches.len >= 2) {
                    self.first_pid = ev.match.matches[0].pattern_id;
                    self.second_pid = ev.match.matches[1].pattern_id;
                    self.last_pid = ev.match.matches[ev.match.matches.len - 1].pattern_id;
                }
            }
            return true;
        }
    };

    var sink = VerifySink{};
    _ = try searchSourceSlice(VerifySink, &sink, "repro-1a", line.items, &multi, .{
        .allocator = testing.allocator,
    });
    try testing.expectEqual(@as(usize, 91), sink.count);
    try testing.expectEqual(@as(?u32, 0), sink.first_pid);
    try testing.expectEqual(@as(?u32, 1), sink.second_pid);
    try testing.expectEqual(@as(?u32, 2), sink.last_pid);

    // Also test Scratch.span_buf growing from 64 (40 matches) to 128 (91 matches)
    var scratch = searcher.Scratch.init(testing.allocator);
    defer scratch.deinit();
    var line40 = std.ArrayList(u8).empty;
    defer line40.deinit(testing.allocator);
    for (0..20) |_| try line40.appendSlice(testing.allocator, "AA BB ");
    try line40.appendSlice(testing.allocator, "\n");

    sink = .{};
    _ = try searchSourceSlice(VerifySink, &sink, "repro-1b-warm", line40.items, &multi, .{
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(usize, 40), sink.count);

    sink = .{};
    _ = try searchSourceSlice(VerifySink, &sink, "repro-1b-grow", line.items, &multi, .{
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(usize, 91), sink.count);
    try testing.expectEqual(@as(?u32, 0), sink.first_pid);
    try testing.expectEqual(@as(?u32, 1), sink.second_pid);
    try testing.expectEqual(@as(?u32, 2), sink.last_pid);
}

test "regression: beginLong OOM when growing Scratch.long_seen does not double-free" {
    var fail_alloc = std.testing.FailingAllocator.init(testing.allocator, .{});
    var scratch = searcher.Scratch.init(fail_alloc.allocator());
    defer scratch.deinit();

    var finder = try Finder.init("HIT", .{});
    const NoopSink = struct {
        pub fn event(_: *@This(), _: Event) bool {
            return true;
        }
    };
    var sink = NoopSink{};
    const long_input = "zzzzzzzzzzzzzzzzzzzzzzzzHITzzzzzzzzzzzzzzzzzzzzzzzz\n";

    var r1 = std.Io.Reader.fixed(long_input);
    _ = try searchSource(NoopSink, fail_alloc.allocator(), &sink, &r1, "l1", &finder, .{
        .buffer_size = 8,
        .max_line_len = 16,
        .contains = &.{"z"},
        .scratch_pool = &scratch,
    });

    var fail_next = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    scratch.allocator = fail_next.allocator();
    defer scratch.allocator = fail_alloc.allocator();

    var r2 = std.Io.Reader.fixed(long_input);
    try testing.expectError(error.OutOfMemory, searchSource(NoopSink, fail_next.allocator(), &sink, &r2, "l2", &finder, .{
        .buffer_size = 8,
        .max_line_len = 16,
        .contains = &.{ "z", "H" },
        .scratch_pool = &scratch,
    }));
}

test "regression: pipeline.drive offset_map uses pool_alloc when Scratch allocator and call allocator differ" {
    var scratch_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer scratch_arena.deinit();
    var scratch = searcher.Scratch.init(scratch_arena.allocator());
    defer scratch.deinit();

    const utf16le_data = [_]u8{ 0xFF, 0xFE, 'H', 0, 'I', 0, 'T', 0, '\n', 0 };
    const NoopSink = struct {
        pub fn event(_: *@This(), _: Event) bool {
            return true;
        }
    };
    var finder = try Finder.init("HIT", .{});
    var sink = NoopSink{};
    var r1 = std.Io.Reader.fixed(&utf16le_data);
    const res = try searchSource(NoopSink, testing.allocator, &sink, &r1, "u16-drive", &finder, .{
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(u64, 1), res.matched_lines);
}

test "regression: pipeline.materialize offset_map uses prep.alloc when Scratch allocator and SearchConfig.allocator differ" {
    var scratch_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer scratch_arena.deinit();
    var scratch = searcher.Scratch.init(scratch_arena.allocator());
    defer scratch.deinit();

    const utf16le_data = [_]u8{ 0xFF, 0xFE, 'H', 0, 'I', 0, 'T', 0, '\n', 0 };
    const NoopSink = struct {
        pub fn event(_: *@This(), _: Event) bool {
            return true;
        }
    };
    var finder = try Finder.init("HIT", .{});
    var sink = NoopSink{};
    const res_u16 = try searchSourceSlice(NoopSink, &sink, "u16-slice", &utf16le_data, &finder, .{
        .allocator = testing.allocator,
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(u64, 1), res_u16.matched_lines);

    const gbk_data = "HIT\xd6\xd0\n";
    const res_gbk = try searchSourceSlice(NoopSink, &sink, "gbk-slice", gbk_data, &finder, .{
        .encoding = .gbk,
        .allocator = testing.allocator,
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(u64, 1), res_gbk.matched_lines);

    const utf8_bom_invalid = [_]u8{ 0xEF, 0xBB, 0xBF, 'H', 'I', 'T', 0xFF, '\n' };
    const res_bom = try searchSourceSlice(NoopSink, &sink, "bom-slice", &utf8_bom_invalid, &finder, .{
        .allocator = testing.allocator,
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(u64, 1), res_bom.matched_lines);
}

// ============================================================================
// EMPIRICAL CHALLENGER VERIFICATION TESTS (challenger_m1_2_gen2)
// ============================================================================

test "empirical: Bug 1 (Bug 5) - growSpans extreme scale and multiple grow/shrink cycles without span corruption" {
    const Multi = @import("../finder/multi.zig").Multi;
    var multi = try Multi.init(testing.allocator, &.{ "P0", "P1", "P2" }, .{});
    defer multi.deinit();

    var scratch = searcher.Scratch.init(testing.allocator);
    defer scratch.deinit();

    const SpanCollector = struct {
        count: usize = 0,
        valid: bool = true,
        bad_idx: usize = 0,
        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) {
                self.count = ev.match.matches.len;
                for (ev.match.matches, 0..) |s, i| {
                    if (s.pattern_id) |pid| {
                        if (pid > 2) {
                            self.valid = false;
                            self.bad_idx = i;
                            return false;
                        }
                    } else {
                        self.valid = false;
                        self.bad_idx = i;
                        return false;
                    }
                    if (s.start >= 1_000_000 or s.end >= 1_000_000 or s.start > s.end) {
                        self.valid = false;
                        self.bad_idx = i;
                        return false;
                    }
                }
            }
            return true;
        }
    };

    // Cycle through various match counts: 10, 45, 90, 180, 360, 15, 450
    const counts = [_]usize{ 10, 45, 90, 180, 360, 15, 450 };
    for (counts) |target_matches| {
        var line = std.ArrayList(u8).empty;
        defer line.deinit(testing.allocator);
        for (0..target_matches) |i| {
            const pat = switch (i % 3) {
                0 => "P0 ",
                1 => "P1 ",
                2 => "P2 ",
                else => unreachable,
            };
            try line.appendSlice(testing.allocator, pat);
        }
        try line.appendSlice(testing.allocator, "\n");

        var collector = SpanCollector{};
        _ = try searchSourceSlice(SpanCollector, &collector, "empirical-spans", line.items, &multi, .{
            .scratch_pool = &scratch,
        });
        try testing.expect(collector.valid);
        try testing.expectEqual(target_matches, collector.count);
    }
}

test "empirical: Bug 2 (Bug 6) - beginLong OOM safety across all FailingAllocator indices during Scratch.long_seen resize" {
    for (0..8) |fail_idx| {
        var fail_alloc = std.testing.FailingAllocator.init(testing.allocator, .{});
        var scratch = searcher.Scratch.init(fail_alloc.allocator());
        defer scratch.deinit();

        var finder = try Finder.init("NEEDLE", .{});
        const NoopSink = struct {
            pub fn event(_: *@This(), _: Event) bool {
                return true;
            }
        };
        var sink = NoopSink{};
        const long_line_bytes = "------------------------NEEDLE------------------------\n";

        // Step 1: Initial search with 1 contains pattern to allocate Scratch.long_seen with len = 1
        var r1 = std.Io.Reader.fixed(long_line_bytes);
        _ = try searchSource(NoopSink, fail_alloc.allocator(), &sink, &r1, "pre-alloc", &finder, .{
            .buffer_size = 16,
            .max_line_len = 32,
            .contains = &.{"-"},
            .scratch_pool = &scratch,
        });

        // Step 2: Injected failure on allocator during resize to total_contains = 4
        var fail_next = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = fail_idx });
        scratch.allocator = fail_next.allocator();
        defer scratch.allocator = fail_alloc.allocator();

        var r2 = std.Io.Reader.fixed(long_line_bytes);
        _ = searchSource(NoopSink, fail_next.allocator(), &sink, &r2, "oom-step", &finder, .{
            .buffer_size = 16,
            .max_line_len = 32,
            .contains = &.{ "-", "N", "E", "D" },
            .scratch_pool = &scratch,
        }) catch |err| {
            try testing.expectEqual(error.OutOfMemory, err);
        };
    }
}

test "empirical: Bug 3 (Bug 7) - pipeline.drive offset_map deinit with distinct allocators across encodings" {
    var scratch_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer scratch_arena.deinit();
    var scratch = searcher.Scratch.init(scratch_arena.allocator());
    defer scratch.deinit();

    var finder = try Finder.init("TEST", .{});
    const NoopSink = struct {
        pub fn event(_: *@This(), _: Event) bool {
            return true;
        }
    };
    var sink = NoopSink{};

    // 1. UTF-16LE streaming
    const utf16le_data = [_]u8{ 0xFF, 0xFE, 'T', 0, 'E', 0, 'S', 0, 'T', 0, '\n', 0 };
    var r_le = std.Io.Reader.fixed(&utf16le_data);
    const res_le = try searchSource(NoopSink, testing.allocator, &sink, &r_le, "u16le-stream", &finder, .{
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(u64, 1), res_le.matched_lines);

    // 2. UTF-16BE streaming
    const utf16be_data = [_]u8{ 0xFE, 0xFF, 0, 'T', 0, 'E', 0, 'S', 0, 'T', 0, '\n' };
    var r_be = std.Io.Reader.fixed(&utf16be_data);
    const res_be = try searchSource(NoopSink, testing.allocator, &sink, &r_be, "u16be-stream", &finder, .{
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(u64, 1), res_be.matched_lines);

    // 3. UTF-8 BOM with invalid tail byte streaming
    const utf8_bom_data = [_]u8{ 0xEF, 0xBB, 0xBF, 'T', 'E', 'S', 'T', 0xFF, '\n' };
    var r_bom = std.Io.Reader.fixed(&utf8_bom_data);
    const res_bom = try searchSource(NoopSink, testing.allocator, &sink, &r_bom, "utf8bom-stream", &finder, .{
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(u64, 1), res_bom.matched_lines);

    // 4. GBK streaming
    const gbk_data = "TEST\xd6\xd0\n";
    var r_gbk = std.Io.Reader.fixed(gbk_data);
    const res_gbk = try searchSource(NoopSink, testing.allocator, &sink, &r_gbk, "gbk-stream", &finder, .{
        .encoding = .gbk,
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(u64, 1), res_gbk.matched_lines);

    // 5. Latin-1 streaming
    const latin1_data = "TEST\xe9\n";
    var r_lat = std.Io.Reader.fixed(latin1_data);
    const res_lat = try searchSource(NoopSink, testing.allocator, &sink, &r_lat, "latin1-stream", &finder, .{
        .encoding = .latin1,
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(u64, 1), res_lat.matched_lines);
}

test "empirical: Bug 4 (Bug 8) - pipeline.materialize offset_map deinit with distinct allocators across encodings" {
    var scratch_arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer scratch_arena.deinit();
    var scratch = searcher.Scratch.init(scratch_arena.allocator());
    defer scratch.deinit();

    var finder = try Finder.init("DATA", .{});
    const NoopSink = struct {
        pub fn event(_: *@This(), _: Event) bool {
            return true;
        }
    };
    var sink = NoopSink{};

    // 1. UTF-16LE slice
    const utf16le_data = [_]u8{ 0xFF, 0xFE, 'D', 0, 'A', 0, 'T', 0, 'A', 0, '\n', 0 };
    const res_le = try searchSourceSlice(NoopSink, &sink, "u16le-mat", &utf16le_data, &finder, .{
        .allocator = testing.allocator,
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(u64, 1), res_le.matched_lines);

    // 2. UTF-16BE slice
    const utf16be_data = [_]u8{ 0xFE, 0xFF, 0, 'D', 0, 'A', 0, 'T', 0, 'A', 0, '\n' };
    const res_be = try searchSourceSlice(NoopSink, &sink, "u16be-mat", &utf16be_data, &finder, .{
        .allocator = testing.allocator,
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(u64, 1), res_be.matched_lines);

    // 3. UTF-8 BOM slice
    const utf8_bom_data = [_]u8{ 0xEF, 0xBB, 0xBF, 'D', 'A', 'T', 'A', 0xFF, '\n' };
    const res_bom = try searchSourceSlice(NoopSink, &sink, "utf8bom-mat", &utf8_bom_data, &finder, .{
        .allocator = testing.allocator,
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(u64, 1), res_bom.matched_lines);

    // 4. GBK slice
    const gbk_data = "DATA\xd6\xd0\n";
    const res_gbk = try searchSourceSlice(NoopSink, &sink, "gbk-mat", gbk_data, &finder, .{
        .encoding = .gbk,
        .allocator = testing.allocator,
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(u64, 1), res_gbk.matched_lines);

    // 5. Latin-1 slice
    const latin1_data = "DATA\xe9\n";
    const res_lat = try searchSourceSlice(NoopSink, &sink, "latin1-mat", latin1_data, &finder, .{
        .encoding = .latin1,
        .allocator = testing.allocator,
        .scratch_pool = &scratch,
    });
    try testing.expectEqual(@as(u64, 1), res_lat.matched_lines);
}

test "empirical: Scratch pool stress test across 5,000 iterations asserting zero steady-state allocations" {
    const CountingAllocator = struct {
        parent: std.mem.Allocator,
        alloc_count: usize = 0,
        realloc_count: usize = 0,
        free_count: usize = 0,

        fn allocator(self: *@This()) std.mem.Allocator {
            return .{ .ptr = self, .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            } };
        }

        fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.alloc_count += 1;
            return self.parent.rawAlloc(len, alignment, ret_addr);
        }

        fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (new_len > memory.len) self.realloc_count += 1;
            return self.parent.rawResize(memory, alignment, new_len, ret_addr);
        }

        fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.realloc_count += 1;
            return self.parent.rawRemap(memory, alignment, new_len, ret_addr);
        }

        fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.free_count += 1;
            self.parent.rawFree(memory, alignment, ret_addr);
        }
    };

    var counting = CountingAllocator{ .parent = testing.allocator };
    var scratch = searcher.Scratch.init(counting.allocator());
    defer scratch.deinit();

    var finder = try Finder.init("TOKEN", .{});
    const Multi = @import("../finder/multi.zig").Multi;
    var multi = try Multi.init(testing.allocator, &.{ "TOKEN", "ALPHA", "BETA" }, .{});
    defer multi.deinit();

    const NoopSink = struct {
        hits: usize = 0,
        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) self.hits += 1;
            return true;
        }
    };
    var sink = NoopSink{};

    // --- WARM UP PHASE: Pre-size all internal Scratch buffers ---
    // 1. Long stream with before/after context
    const stream_warm = "line1\nline2\nTOKEN\nline4\nline5\n";
    var r_warm = std.Io.Reader.fixed(stream_warm);
    _ = try searchSource(NoopSink, counting.allocator(), &sink, &r_warm, "warm-stream", &finder, .{
        .before = 2,
        .after = 2,
        .buffer_size = 64,
        .scratch_pool = &scratch,
    });

    // 2. Long line exceeding max_line_len to size long_hold and long_seen
    const long_line_warm = "========================TOKEN========================\n";
    var r_long_warm = std.Io.Reader.fixed(long_line_warm);
    _ = try searchSource(NoopSink, counting.allocator(), &sink, &r_long_warm, "warm-long", &finder, .{
        .buffer_size = 16,
        .max_line_len = 32,
        .contains = &.{ "=", "T" },
        .scratch_pool = &scratch,
    });

    // 3. Line with >32 spans to size span_buf
    var span_line: [512]u8 = undefined;
    var sp_len: usize = 0;
    for (0..40) |_| {
        @memcpy(span_line[sp_len .. sp_len + 6], "TOKEN ");
        sp_len += 6;
    }
    span_line[sp_len] = '\n';
    sp_len += 1;
    _ = try searchSourceSlice(NoopSink, &sink, "warm-spans", span_line[0..sp_len], &finder, .{
        .scratch_pool = &scratch,
    });

    // 4. Replacement to size text_buf and replace_buf
    _ = try searchSourceSlice(NoopSink, &sink, "warm-replace", "here is TOKEN and TOKEN\n", &finder, .{
        .replacement = "[REPLACED_TOKEN]",
        .scratch_pool = &scratch,
    });

    // 5. Transcoding to size decode_buf
    const utf16_warm = [_]u8{ 0xFF, 0xFE, 'T', 0, 'O', 0, 'K', 0, 'E', 0, 'N', 0, '\n', 0 };
    _ = try searchSourceSlice(NoopSink, &sink, "warm-transcode", &utf16_warm, &finder, .{
        .allocator = counting.allocator(),
        .scratch_pool = &scratch,
    });

    // Record steady-state counts after warm-up
    const steady_allocs = counting.alloc_count;
    const steady_reallocs = counting.realloc_count;
    try testing.expect(steady_allocs > 0);

    // --- STRESS PHASE: 5,000 searches across slice, stream, context, replacements ---
    var fail_call_alloc = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const call_alloc = fail_call_alloc.allocator();

    for (0..5000) |i| {
        switch (i % 5) {
            0 => {
                _ = try searchSourceSlice(NoopSink, &sink, "s-slice", "BETA and ALPHA and TOKEN\n", &multi, .{
                    .scratch_pool = &scratch,
                });
            },
            1 => {
                const doc = "start\nmiddle with TOKEN\nend\n";
                var r = std.Io.Reader.fixed(doc);
                _ = try searchSource(NoopSink, call_alloc, &sink, &r, "s-stream", &finder, .{
                    .before = 1,
                    .after = 1,
                    .buffer_size = 64,
                    .scratch_pool = &scratch,
                });
            },
            2 => {
                _ = try searchSourceSlice(NoopSink, &sink, "s-replace", "prefix TOKEN suffix\n", &finder, .{
                    .replacement = "REPL",
                    .scratch_pool = &scratch,
                });
            },
            3 => {
                _ = try searchSourceSlice(NoopSink, &sink, "s-spans", span_line[0 .. 30 * 6 + 1], &finder, .{
                    .scratch_pool = &scratch,
                });
            },
            4 => {
                var r_l = std.Io.Reader.fixed(long_line_warm);
                _ = try searchSource(NoopSink, call_alloc, &sink, &r_l, "s-overlong", &finder, .{
                    .buffer_size = 16,
                    .max_line_len = 32,
                    .contains = &.{"="},
                    .scratch_pool = &scratch,
                });
            },
            else => unreachable,
        }
    }

    try testing.expectEqual(steady_allocs, counting.alloc_count);
    try testing.expectEqual(steady_reallocs, counting.realloc_count);
    try testing.expectEqual(@as(usize, 0), fail_call_alloc.allocations);
}

test "empirical: AnyEventSink flow control (cont, pause, stop, resume) and AnyMatcher polymorphism" {
    const FlowSink = struct {
        matches_seen: usize = 0,
        heartbeats_seen: usize = 0,
        ends_seen: usize = 0,
        stop_at: ?usize = null,
        pause_at: ?usize = null,

        pub fn event(self: *@This(), ev: Event) Flow {
            switch (ev) {
                .match => {
                    self.matches_seen += 1;
                    if (self.stop_at) |s| {
                        if (self.matches_seen >= s) return .stop;
                    }
                    if (self.pause_at) |p| {
                        if (self.matches_seen >= p) return .pause;
                    }
                    return .cont;
                },
                .heartbeat => {
                    self.heartbeats_seen += 1;
                    return .cont;
                },
                .end => {
                    self.ends_seen += 1;
                    return .cont;
                },
                else => return .cont,
            }
        }
    };

    const Multi = @import("../finder/multi.zig").Multi;
    var multi = try Multi.init(testing.allocator, &.{ "one", "two", "three" }, .{});
    defer multi.deinit();
    const any_multi = matcher_mod.AnyMatcher.init(Multi, &multi);

    var finder = try Finder.init("match", .{});
    const any_finder = matcher_mod.AnyMatcher.init(Finder, &finder);

    var re = try regex_mod.Regex.init(testing.allocator, "[0-9]+", .{});
    defer re.deinit();
    const any_re = matcher_mod.AnyMatcher.init(regex_mod.Regex, &re);

    // 1. AnyEventSink with .stop stops immediately after target match count
    var flow_sink = FlowSink{ .stop_at = 2 };
    var any_sink = sink_mod.AnyEventSink.init(FlowSink, &flow_sink);
    const corpus = "one\ntwo\nthree\none\n";
    const res_stop = try searchSourceSlice(sink_mod.AnyEventSink, &any_sink, "stop-test", corpus, &any_multi, .{});
    try testing.expectEqual(Outcome.stopped, res_stop.outcome);
    try testing.expectEqual(@as(usize, 2), flow_sink.matches_seen);

    // 2. AnyEventSink with .pause and resumeSourceSlice
    flow_sink = FlowSink{ .pause_at = 1 };
    any_sink = sink_mod.AnyEventSink.init(FlowSink, &flow_sink);
    const res_pause = try searchSourceSlice(sink_mod.AnyEventSink, &any_sink, "pause-test", corpus, &any_multi, .{});
    try testing.expect(res_pause.paused);
    try testing.expectEqual(@as(usize, 1), flow_sink.matches_seen);

    // Resume from paused result
    flow_sink.pause_at = null;
    const res_resumed = try resumeSourceSlice(sink_mod.AnyEventSink, &any_sink, "pause-test", corpus, &any_multi, .{}, res_pause);
    try testing.expectEqual(Outcome.complete, res_resumed.outcome);
    try testing.expect(!res_resumed.paused);
    try testing.expectEqual(@as(usize, 4), flow_sink.matches_seen);

    // 3. AnyMatcher with match modes and word boundary
    const word_corpus = "oneword one two\n";
    flow_sink = FlowSink{};
    any_sink = sink_mod.AnyEventSink.init(FlowSink, &flow_sink);
    _ = try searchSourceSlice(sink_mod.AnyEventSink, &any_sink, "word-test", word_corpus, &any_multi, .{
        .whole_word = true,
    });
    try testing.expectEqual(@as(usize, 1), flow_sink.matches_seen);

    // 4. AnyMatcher findWatched with NUL detection
    var nul_pos: ?usize = null;
    const nul_hay = "abc\x00def match";
    const m_watch = any_finder.findWatched(nul_hay, 0, &nul_pos);
    try testing.expect(m_watch == null);
    try testing.expectEqual(@as(?usize, 3), nul_pos);

    // Without NUL, match is returned
    var no_nul_pos: ?usize = null;
    const no_nul_hay = "abc def match";
    const m_no_watch = any_finder.findWatched(no_nul_hay, 0, &no_nul_pos);
    try testing.expect(m_no_watch != null);
    try testing.expectEqual(@as(?usize, null), no_nul_pos);

    // 5. AnyMatcher wrapping Regex
    flow_sink = FlowSink{};
    any_sink = sink_mod.AnyEventSink.init(FlowSink, &flow_sink);
    _ = try searchSourceSlice(sink_mod.AnyEventSink, &any_sink, "re-test", "val: 12345 and 678\n", &any_re, .{});
    try testing.expectEqual(@as(usize, 1), flow_sink.matches_seen);
}

test "policy limits: default limits apply when omitted and unconstrained custom limits work above former hard caps" {
    const alloc = testing.allocator;
    const Multi = @import("../finder/multi.zig").Multi;
    const Regex = regex_mod.Regex;
    const RegexSet = regex_mod.RegexSet;

    // 1. Multi pattern count default (1024) vs custom limit (1100)
    var pat_bufs = try alloc.alloc([16]u8, 1101);
    defer alloc.free(pat_bufs);
    var pat_slices = try alloc.alloc([]const u8, 1101);
    defer alloc.free(pat_slices);
    for (0..1101) |i| {
        pat_slices[i] = try std.fmt.bufPrint(&pat_bufs[i], "k_{d:0>5}", .{i});
    }

    // Default options (null max_pattern_count) rejects 1025 patterns
    try testing.expectError(error.PatternCountExceeded, Multi.init(alloc, pat_slices[0..1025], .{}));

    // Custom max_pattern_count > 1024 succeeds and finds matches
    var multi_high = try Multi.init(alloc, pat_slices[0..1100], .{ .max_pattern_count = 1200 });
    defer multi_high.deinit();
    const m_hit = multi_high.find("prefix k_01099 suffix", 0, .earliest);
    try testing.expect(m_hit != null);
    try testing.expectEqual(@as(u32, 1099), m_hit.?.pattern_id.?);

    // 2. Regex repeat count default (1000) vs custom limit (1200)
    try testing.expectError(error.RegexTooLarge, Regex.init(alloc, "a{1001}", .{}));
    var re_repeat = try Regex.init(alloc, "a{1200}", .{ .max_repeat = 1500, .max_inst = 20000 });
    defer re_repeat.deinit();
    const hay_a = try alloc.alloc(u8, 1205);
    defer alloc.free(hay_a);
    @memset(hay_a, 'a');
    try testing.expect(re_repeat.find(hay_a, 0, .earliest) != null);

    // 3. Regex recursion depth default (64) vs custom limit (80)
    var deep_pat: [200]u8 = undefined;
    for (0..70) |i| deep_pat[i] = '(';
    deep_pat[70] = 'z';
    for (71..141) |i| deep_pat[i] = ')';
    const deep_slice = deep_pat[0..141];

    try testing.expectError(error.RegexTooLarge, Regex.init(alloc, deep_slice, .{}));
    var re_deep = try Regex.init(alloc, deep_slice, .{ .max_recursion_depth = 80 });
    defer re_deep.deinit();
    try testing.expect(re_deep.find("test z test", 0, .earliest) != null);

    // 4. RegexSet with pattern count > 1024 and custom max_inst
    var rset_high = try RegexSet.init(alloc, pat_slices[0..1100], .{ .max_pattern_count = 1200, .max_inst = 20000 });
    defer rset_high.deinit();
    var rset_out: [4]u32 = undefined;
    const rset_matches = rset_high.matches("test k_01050 end", &rset_out);
    try testing.expect(rset_matches > 0);
    try testing.expectEqual(@as(u32, 1050), rset_out[0]);

    // 5. SearchConfig context lines default (10) vs custom limit (25)
    try testing.expectError(error.ContextLinesExceeded, validateBudgets(.{ .context = 11 }));
    try validateBudgets(.{ .max_context_lines = 25, .context = 20 });
    try testing.expectError(error.ContextLinesExceeded, validateBudgets(.{ .max_context_lines = 25, .context = 26 }));

    // 5b. BeforeRing dynamic heap_slots when before > 10 (25 non-matching lines + 1 matching line)
    {
        const Scratch = searcher.Scratch;
        var hay_list = std.ArrayList(u8).empty;
        defer hay_list.deinit(alloc);
        for (1..26) |line_idx| {
            var buf: [32]u8 = undefined;
            const s = try std.fmt.bufPrint(&buf, "ctx_{d:0>2}\n", .{line_idx});
            try hay_list.appendSlice(alloc, s);
        }
        try hay_list.appendSlice(alloc, "TARGET_HIT\n");

        const finder_ctx = try Finder.init("TARGET_HIT", .{});

        // (i) searchSlice with .allocator = alloc
        {
            var rec_slice = Rec{};
            defer rec_slice.deinit(alloc);
            const res = try searchSlice(Rec, &rec_slice, hay_list.items, "ctx_slice", &finder_ctx, .{
                .line_numbers = true,
                .max_context_lines = 25,
                .before = 20,
                .allocator = alloc,
            });
            try testing.expectEqual(@as(u64, 1), res.matched_lines);
            var ctx_lines: usize = 0;
            var it = std.mem.splitScalar(u8, rec_slice.text.items, '\n');
            while (it.next()) |ln| {
                if (ln.len == 0) continue;
                if (std.mem.findScalar(u8, ln, '-') != null) ctx_lines += 1;
            }
            try testing.expectEqual(@as(usize, 20), ctx_lines);
            try testing.expect(std.mem.startsWith(u8, rec_slice.text.items, "6-ctx_06\n"));
        }

        // (ii) searchSlice with Scratch pool reuse
        {
            var sp = Scratch.init(alloc);
            defer sp.deinit();
            var rec_sp = Rec{};
            defer rec_sp.deinit(alloc);
            const res = try searchSlice(Rec, &rec_sp, hay_list.items, "ctx_sp", &finder_ctx, .{
                .line_numbers = true,
                .max_context_lines = 25,
                .before = 20,
                .scratch_pool = &sp,
            });
            try testing.expectEqual(@as(u64, 1), res.matched_lines);
            try testing.expect(sp.ring_slots.len >= 20);
            try testing.expect(std.mem.startsWith(u8, rec_sp.text.items, "6-ctx_06\n"));
        }

        // (iii) searchReader / searchSource streaming
        {
            var reader = std.Io.Reader.fixed(hay_list.items);
            var rec_stream = Rec{};
            defer rec_stream.deinit(alloc);
            const res = try searchReader(Rec, alloc, &rec_stream, &reader, "ctx_reader", &finder_ctx, .{
                .line_numbers = true,
                .max_context_lines = 25,
                .before = 20,
                .buffer_size = 64,
            });
            try testing.expectEqual(@as(u64, 1), res.matched_lines);
            var ctx_lines: usize = 0;
            var it = std.mem.splitScalar(u8, rec_stream.text.items, '\n');
            while (it.next()) |ln| {
                if (ln.len == 0) continue;
                if (std.mem.findScalar(u8, ln, '-') != null) ctx_lines += 1;
            }
            try testing.expectEqual(@as(usize, 20), ctx_lines);
            try testing.expect(std.mem.startsWith(u8, rec_stream.text.items, "6-ctx_06\n"));
        }

        // (iv) openReaderPull streaming pull iterator
        {
            var reader = std.Io.Reader.fixed(hay_list.items);
            var rpull = try searcher.openReaderPull(alloc, &finder_ctx, "ctx_rpull", &reader, .{
                .max_context_lines = 25,
                .before = 20,
                .buffer_size = 64,
            });
            defer rpull.deinit();
            var pull_ctx_count: usize = 0;
            var pull_match_count: usize = 0;
            var first_ctx_line: u64 = 0;
            while (try rpull.next()) |ev| {
                if (ev.kind == .context) {
                    if (pull_ctx_count == 0) first_ctx_line = ev.line_number;
                    pull_ctx_count += 1;
                } else if (ev.kind == .match) {
                    pull_match_count += 1;
                }
            }
            try testing.expectEqual(@as(usize, 20), pull_ctx_count);
            try testing.expectEqual(@as(usize, 1), pull_match_count);
            try testing.expectEqual(@as(u64, 6), first_ctx_line);
        }
    }

    // 6. SearchConfig source bytes > 64 MiB and compression ratio > 1000
    try validateBudgets(.{
        .max_source_bytes = 100 * 1024 * 1024,
        .max_compression_ratio = 2000,
    });

    // 7. Walker depth default (64) vs custom limit (100)
    const walk_def = @import("../walk/walker.zig").Config{};
    try testing.expectEqual(@as(u32, 64), walk_def.effectiveMaxDepth());
    const walk_high = @import("../walk/walker.zig").Config{ .max_depth = 100 };
    try testing.expectEqual(@as(u32, 100), walk_high.effectiveMaxDepth());

    // 8. Glob brace depth default (8) vs custom limit (12)
    const brace_pat = "{a,{b,{c,{d,{e,{f,{g,{h,{i,j}}}}}}}}}"; // 9 levels
    var brace_list = std.ArrayList([]u8).empty;
    defer {
        for (brace_list.items) |b| alloc.free(b);
        brace_list.deinit(alloc);
    }
    const glob_mod = @import("../walk/glob.zig");
    try testing.expectError(error.GlobBraceDepthExceeded, glob_mod.expandBraces(alloc, brace_pat, &brace_list, 100));
    try glob_mod.expandBracesWithOptions(alloc, brace_pat, &brace_list, .{ .max_brace_depth = 12 });
    try testing.expect(brace_list.items.len > 0);

    // 9. Parallel threads > 32
    const parallel_mod = @import("../parallel.zig");
    try testing.expectEqual(@as(u32, 48), parallel_mod.resolveThreads(48));
    try testing.expectEqual(@as(u32, 48), parallel_mod.resolveConcurrency(1, 48));
}

test "multiline: Finder and Multi literal cross-line matching across all engines and CRLF" {
    const alloc = testing.allocator;
    const Multi = @import("../finder/multi.zig").Multi;

    // 1. Default options reject \n in Finder and Multi
    try testing.expectError(error.PatternHasNewline, Finder.init("alpha\nbeta", .{}));
    try testing.expectError(error.PatternHasNewline, Multi.init(alloc, &.{ "ok", "alpha\nbeta" }, .{}));

    // 2. Finder multiline: 2 lines, 3+ lines, CRLF
    const f2 = try Finder.init("alpha\nbeta", .{ .multiline = true });
    var bag = Bag{};
    defer bag.deinit();
    const res2 = try searchSourceSlice(Bag, &bag, "ml-f2", "header\nxx alpha\nbeta yy\nfooter\n", &f2, .{ .multiline = true });
    try testing.expectEqual(@as(u64, 1), res2.matched_lines);
    try testing.expectEqual(@as(u64, 1), res2.matches);
    const m2 = bag.matchAt(0);
    try testing.expectEqual(@as(u64, 2), m2.line_number);
    try testing.expectEqual(@as(?u64, 4), m2.column);
    try testing.expectEqualStrings("xx alpha\nbeta yy", m2.bytes);
    try testing.expectEqual(@as(usize, 1), m2.matches.len);
    try testing.expectEqualStrings("alpha\nbeta", m2.bytes[m2.matches[0].start..m2.matches[0].end]);

    // 3+ lines
    bag.reset();
    const f3 = try Finder.init("one\ntwo\nthree", .{ .multiline = true });
    const res3 = try searchSourceSlice(Bag, &bag, "ml-f3", "0\none\ntwo\nthree!\n4\n", &f3, .{ .multiline = true });
    try testing.expectEqual(@as(u64, 1), res3.matched_lines);
    const m3 = bag.matchAt(0);
    try testing.expectEqual(@as(u64, 2), m3.line_number);
    try testing.expectEqualStrings("one\ntwo\nthree!", m3.bytes);

    // CRLF cross-line literal
    bag.reset();
    const fcrlf = try Finder.init("alpha\r\nbeta", .{ .multiline = true });
    const rescrlf = try searchSourceSlice(Bag, &bag, "ml-crlf", "first\r\nalpha\r\nbeta\r\nlast\r\n", &fcrlf, .{ .multiline = true });
    try testing.expectEqual(@as(u64, 1), rescrlf.matched_lines);
    const mcrlf = bag.matchAt(0);
    try testing.expectEqual(@as(u64, 2), mcrlf.line_number);
    try testing.expectEqualStrings("alpha\r\nbeta", mcrlf.bytes);

    // 3. Multi multiline across RarePair (2 patterns), Teddy (4 patterns), AhoCorasick (>32 patterns), and Unicode case folding
    // RarePair
    {
        var m_pair = try Multi.init(alloc, &.{ "alpha\nbeta", "gamma\ndelta" }, .{ .multiline = true });
        defer m_pair.deinit();
        bag.reset();
        const rp_res = try searchSourceSlice(Bag, &bag, "ml-pair", "line1\ngamma\ndelta\nline4\n", &m_pair, .{});
        try testing.expectEqual(@as(u64, 1), rp_res.matched_lines);
        try testing.expectEqual(@as(u32, 1), bag.matchAt(0).matches[0].pattern_id.?);
        try testing.expectEqualStrings("gamma\ndelta", bag.matchAt(0).bytes);
    }
    // Teddy
    {
        var m_teddy = try Multi.init(alloc, &.{ "p1\nq1", "p2\nq2", "p3\nq3", "p4\nq4" }, .{ .multiline = true });
        defer m_teddy.deinit();
        bag.reset();
        const td_res = try searchSourceSlice(Bag, &bag, "ml-teddy", "start\np3\nq3\nend\n", &m_teddy, .{});
        try testing.expectEqual(@as(u64, 1), td_res.matched_lines);
        try testing.expectEqual(@as(u32, 2), bag.matchAt(0).matches[0].pattern_id.?);
        try testing.expectEqualStrings("p3\nq3", bag.matchAt(0).bytes);
    }
    // AhoCorasick (36 patterns)
    {
        var pat_bufs: [36][16]u8 = undefined;
        var pat_slices: [36][]const u8 = undefined;
        for (0..36) |i| {
            pat_slices[i] = try std.fmt.bufPrint(&pat_bufs[i], "k{d:0>2}\nv{d:0>2}", .{ i, i });
        }
        var m_ac = try Multi.init(alloc, &pat_slices, .{ .multiline = true });
        defer m_ac.deinit();
        bag.reset();
        const ac_res = try searchSourceSlice(Bag, &bag, "ml-ac", "head\nk34\nv34\ntail\n", &m_ac, .{});
        try testing.expectEqual(@as(u64, 1), ac_res.matched_lines);
        try testing.expectEqual(@as(u32, 34), bag.matchAt(0).matches[0].pattern_id.?);
    }
    // Unicode case folding with cross-line pattern
    {
        var m_uni = try Multi.init(alloc, &.{ "δ\nε", "ω\nψ" }, .{
            .case = .insensitive,
            .unicode_case = true,
            .multiline = true,
        });
        defer m_uni.deinit();
        bag.reset();
        const uni_res = try searchSourceSlice(Bag, &bag, "ml-uni", "0\nΔ\nΕ\n3\n", &m_uni, .{});
        try testing.expectEqual(@as(u64, 1), uni_res.matched_lines);
        try testing.expectEqualStrings("Δ\nΕ", bag.matchAt(0).bytes);
    }
}

test "multiline: Regex, RegexSet, scoped (?m:...), dot_all, anchors, and SIMD cross-line prefilter" {
    const alloc = testing.allocator;
    const Regex = regex_mod.Regex;
    const RegexSet = regex_mod.RegexSet;

    var bag = Bag{};
    defer bag.deinit();

    // 1. \n escape and raw \n in Regex
    {
        var re_esc = try Regex.init(alloc, "foo\\nbar", .{ .multiline = true });
        defer re_esc.deinit();
        const res = try searchSourceSlice(Bag, &bag, "re-esc", "a\nfoo\nbar\nb\n", &re_esc, .{});
        try testing.expectEqual(@as(u64, 1), res.matched_lines);
        try testing.expectEqualStrings("foo\nbar", bag.matchAt(0).bytes);
    }
    {
        bag.reset();
        var re_raw = try Regex.init(alloc, "foo\nbar", .{ .multiline = true });
        defer re_raw.deinit();
        const res = try searchSourceSlice(Bag, &bag, "re-raw", "a\nfoo\nbar\nb\n", &re_raw, .{});
        try testing.expectEqual(@as(u64, 1), res.matched_lines);
        try testing.expectEqualStrings("foo\nbar", bag.matchAt(0).bytes);
    }

    // 2. dot_all = true and (?s) across lines
    {
        bag.reset();
        var re_dot = try Regex.init(alloc, "BEGIN.+?END", .{ .multiline = true, .dot_all = true });
        defer re_dot.deinit();
        const res = try searchSourceSlice(Bag, &bag, "re-dot", "0\nBEGIN\nmid\nEND\n4\n", &re_dot, .{});
        try testing.expectEqual(@as(u64, 1), res.matched_lines);
        try testing.expectEqual(@as(u64, 2), bag.matchAt(0).line_number);
        try testing.expectEqualStrings("BEGIN\nmid\nEND", bag.matchAt(0).bytes);
    }

    // 3. ^ and $ matching internal line boundaries across lines
    {
        bag.reset();
        var re_anc = try Regex.init(alloc, "^first$\\n^second$", .{ .multiline = true });
        defer re_anc.deinit();
        const res = try searchSourceSlice(Bag, &bag, "re-anc", "prefix\nfirst\nsecond\nsuffix\n", &re_anc, .{});
        try testing.expectEqual(@as(u64, 1), res.matched_lines);
        try testing.expectEqual(@as(u64, 2), bag.matchAt(0).line_number);
        try testing.expectEqualStrings("first\nsecond", bag.matchAt(0).bytes);
    }

    // 4. Scoped (?m:...) inline flag enables multiline without top-level options.multiline
    {
        bag.reset();
        var re_scoped = try Regex.init(alloc, "(?m:alpha\\nbeta)", .{});
        defer re_scoped.deinit();
        try testing.expect(re_scoped.isMultiline());
        const res = try searchSourceSlice(Bag, &bag, "re-scoped", "x\nalpha\nbeta\ny\n", &re_scoped, .{});
        try testing.expectEqual(@as(u64, 1), res.matched_lines);
        try testing.expectEqualStrings("alpha\nbeta", bag.matchAt(0).bytes);
    }

    // 5. Regex with cross-line literal prefilter ("START\n[0-9]+\nEND" and "FOO\nBAR|BAZ\nQUX")
    {
        bag.reset();
        var re_pre = try Regex.init(alloc, "START\\n[0-9]+\\nEND", .{ .multiline = true });
        defer re_pre.deinit();
        try testing.expect(re_pre.prefilter != null);
        const res = try searchSourceSlice(Bag, &bag, "re-pre1", "pad\nSTART\n12345\nEND\n", &re_pre, .{});
        try testing.expectEqual(@as(u64, 1), res.matched_lines);
        try testing.expectEqualStrings("START\n12345\nEND", bag.matchAt(0).bytes);

        bag.reset();
        var re_alt = try Regex.init(alloc, "FOO\\nBAR|BAZ\\nQUX", .{ .multiline = true });
        defer re_alt.deinit();
        try testing.expect(re_alt.alt_prefilter != null);
        const res_alt = try searchSourceSlice(Bag, &bag, "re-pre2", "0\nBAZ\nQUX\n3\n", &re_alt, .{});
        try testing.expectEqual(@as(u64, 1), res_alt.matched_lines);
        try testing.expectEqualStrings("BAZ\nQUX", bag.matchAt(0).bytes);
    }

    // 6. RegexSet cross-line matching via searchSourceSlice and matches()
    {
        bag.reset();
        var rset = try RegexSet.init(alloc, &.{ "alpha\\n[0-9]+", "beta\\ngamma" }, .{ .multiline = true });
        defer rset.deinit();
        var ids: [4]u32 = undefined;
        const n_ids = rset.matches("xx alpha\n42 yy beta\ngamma zz", &ids);
        try testing.expectEqual(@as(usize, 2), n_ids);
        try testing.expectEqual(@as(u32, 0), ids[0]);
        try testing.expectEqual(@as(u32, 1), ids[1]);

        const res_set = try searchSourceSlice(Bag, &bag, "rset-ml", "line1\nalpha\n42\nline4\nbeta\ngamma\n", &rset, .{});
        try testing.expectEqual(@as(u64, 2), res_set.matched_lines);
        try testing.expectEqual(@as(u64, 2), bag.matchAt(0).line_number);
        try testing.expectEqualStrings("alpha\n42", bag.matchAt(0).bytes);
        try testing.expectEqual(@as(u64, 5), bag.matchAt(1).line_number);
        try testing.expectEqualStrings("beta\ngamma", bag.matchAt(1).bytes);
    }
}

test "multiline: edge cases (trailing newline, bridging matches, context, invert, passthru, whole_word, whole_line, replacement, UTF-16, pause/resume)" {
    const alloc = testing.allocator;
    const Regex = regex_mod.Regex;

    var bag = Bag{};
    defer bag.deinit();

    // 1. Trailing \n in match: "alpha\n" on "alpha\nbeta\n" emits ONLY line 1 ("alpha"), NOT "alpha\nbeta"
    {
        const f_trail = try Finder.init("alpha\n", .{ .multiline = true });
        const res = try searchSourceSlice(Bag, &bag, "trail-nl", "alpha\nbeta\n", &f_trail, .{ .multiline = true });
        try testing.expectEqual(@as(u64, 1), res.matched_lines);
        try testing.expectEqual(@as(u64, 1), bag.matchAt(0).line_number);
        try testing.expectEqualStrings("alpha", bag.matchAt(0).bytes);
        try testing.expectEqual(@as(usize, 1), bag.matchAt(0).matches.len);
        try testing.expectEqual(@as(usize, 0), bag.matchAt(0).matches[0].start);
        try testing.expectEqual(@as(usize, 5), bag.matchAt(0).matches[0].end);
    }

    // 2. Bridging matches:
    // (a) "foo\nbar foo\nbar\ntail\n" with "foo\nbar" -> 1 MatchEvent (line 1, bytes="foo\nbar foo\nbar", 2 Spans)
    {
        bag.reset();
        const f_bridge = try Finder.init("foo\nbar", .{ .multiline = true });
        const res = try searchSourceSlice(Bag, &bag, "bridge-1", "foo\nbar foo\nbar\ntail\n", &f_bridge, .{ .multiline = true });
        try testing.expectEqual(@as(u64, 1), res.matched_lines);
        try testing.expectEqual(@as(u64, 2), res.matches);
        const m = bag.matchAt(0);
        try testing.expectEqual(@as(u64, 1), m.line_number);
        try testing.expectEqualStrings("foo\nbar foo\nbar", m.bytes);
        try testing.expectEqual(@as(usize, 2), m.matches.len);
        try testing.expectEqualStrings("foo\nbar", m.bytes[m.matches[0].start..m.matches[0].end]);
        try testing.expectEqualStrings("foo\nbar", m.bytes[m.matches[1].start..m.matches[1].end]);
    }
    // (b) "foo\nbar\nbar\n" with "\nbar" -> 1 MatchEvent (line 1, bytes="foo\nbar\nbar", 2 Spans)
    {
        bag.reset();
        const f_bridge2 = try Finder.init("\nbar", .{ .multiline = true });
        const res = try searchSourceSlice(Bag, &bag, "bridge-2", "foo\nbar\nbar\n", &f_bridge2, .{ .multiline = true });
        try testing.expectEqual(@as(u64, 1), res.matched_lines);
        try testing.expectEqual(@as(u64, 2), res.matches);
        const m = bag.matchAt(0);
        try testing.expectEqual(@as(u64, 1), m.line_number);
        try testing.expectEqualStrings("foo\nbar\nbar", m.bytes);
        try testing.expectEqual(@as(usize, 2), m.matches.len);
    }

    // 3. Context lines (-B, -A, -C) and context_break around a 3-line multiline match
    {
        const f3 = try Finder.init("m1\nm2\nm3", .{ .multiline = true });
        var rec = Rec{};
        defer rec.deinit(alloc);
        const hay = "c1\nm1\nm2\nm3\nc5\ngap6\nc7\nm1\nm2\nm3\nc11\n";
        const res = try searchSlice(Rec, &rec, hay, "ctx", &f3, .{
            .line_numbers = true,
            .multiline = true,
            .before = 1,
            .after = 1,
        });
        try testing.expectEqual(@as(u64, 2), res.matched_lines);
        try testing.expectEqual(@as(u32, 1), rec.breaks);
        try testing.expectEqualStrings(
            \\1-c1
            \\2:m1
            \\m2
            \\m3
            \\5-c5
            \\7-c7
            \\8:m1
            \\m2
            \\m3
            \\11-c11
            \\
        , rec.text.items);
    }

    // 4. invert (-v), passthru, max_count, whole_word (-w), whole_line (-x), contains/excludes
    {
        const f_ml = try Finder.init("a\nb", .{ .multiline = true });
        // invert
        var rec_inv = Rec{};
        defer rec_inv.deinit(alloc);
        _ = try searchSlice(Rec, &rec_inv, "keep1\na\nb\nkeep4\n", "inv", &f_ml, .{
            .line_numbers = true,
            .multiline = true,
            .invert = true,
        });
        try testing.expectEqualStrings("1:keep1\n4:keep4\n", rec_inv.text.items);

        // passthru
        var rec_pass = Rec{};
        defer rec_pass.deinit(alloc);
        _ = try searchSlice(Rec, &rec_pass, "ctx1\na\nb\nctx4\n", "pass", &f_ml, .{
            .line_numbers = true,
            .multiline = true,
            .passthru = true,
        });
        try testing.expectEqualStrings("1-ctx1\n2:a\nb\n4-ctx4\n", rec_pass.text.items);

        // whole_word (-w) across lines
        bag.reset();
        _ = try searchSourceSlice(Bag, &bag, "ww", "xa\nb\na\nby\na\nb\n", &f_ml, .{
            .multiline = true,
            .whole_word = true,
        });
        try testing.expectEqual(@as(u64, 1), bag.kindCount(.match));
        try testing.expectEqual(@as(u64, 5), bag.matchAt(0).line_number);

        // whole_line (-x) across lines
        bag.reset();
        _ = try searchSourceSlice(Bag, &bag, "wl", "xx a\nb\na\nb yy\na\nb\n", &f_ml, .{
            .multiline = true,
            .whole_line = true,
        });
        try testing.expectEqual(@as(u64, 1), bag.kindCount(.match));
        try testing.expectEqual(@as(u64, 5), bag.matchAt(0).line_number);
        try testing.expectEqualStrings("a\nb", bag.matchAt(0).bytes);

        // contains & excludes on multiline block
        bag.reset();
        _ = try searchSourceSlice(Bag, &bag, "ce", "a\nb skip\na\nb keep\n", &f_ml, .{
            .multiline = true,
            .contains = &.{"keep"},
            .excludes = &.{"skip"},
        });
        try testing.expectEqual(@as(u64, 1), bag.kindCount(.match));
        try testing.expectEqual(@as(u64, 3), bag.matchAt(0).line_number);
        try testing.expectEqualStrings("a\nb keep", bag.matchAt(0).bytes);
    }

    // 5. Replacement ($1 across lines) & UTF-16 u16_start/u16_end
    {
        var re_cap = try Regex.init(alloc, "키=([0-9]+)\\n값=([a-z]+)", .{ .multiline = true });
        defer re_cap.deinit();
        const CapSink = struct {
            replaced: [64]u8 = undefined,
            replaced_len: usize = 0,
            u16_start: usize = 0,
            u16_end: usize = 0,
            pub fn event(self: *@This(), ev: Event) bool {
                if (ev == .match) {
                    const m = ev.match;
                    if (m.replaced) |r| {
                        self.replaced_len = @min(r.len, self.replaced.len);
                        @memcpy(self.replaced[0..self.replaced_len], r[0..self.replaced_len]);
                    }
                    if (m.matches.len > 0) {
                        self.u16_start = m.matches[0].u16_start;
                        self.u16_end = m.matches[0].u16_end;
                    }
                }
                return true;
            }
        };
        var cs = CapSink{};
        const res = try searchSourceSlice(CapSink, &cs, "rep-ml", "😀 키=42\n값=ok!\n", &re_cap, .{
            .multiline = true,
            .replacement = "$1:$2",
            .allocator = alloc,
        });
        try testing.expectEqual(@as(u64, 1), res.matched_lines);
        try testing.expectEqualStrings("😀 42:ok!", cs.replaced[0..cs.replaced_len]);
        // "😀 " is 2 UTF-16 code units (surrogate pair) + 1 space = 3
        try testing.expectEqual(@as(usize, 3), cs.u16_start);
        try testing.expect(cs.u16_end > cs.u16_start);
    }

    // 6. Flow.pause + resumeSourceSlice / resumeSource across multiline matches
    {
        const f_ml = try Finder.init("a\nb", .{ .multiline = true });
        const PauseSink = struct {
            hits: usize = 0,
            pause_first: bool = true,
            last_line: u64 = 0,
            pub fn event(self: *@This(), ev: Event) Flow {
                if (ev == .match) {
                    self.hits += 1;
                    self.last_line = ev.match.line_number;
                    if (self.pause_first and self.hits == 1) return .pause;
                }
                return .cont;
            }
        };
        const hay = "0\na\nb\n3\na\nb\n6\n";
        var ps = PauseSink{};
        const r1 = try searchSourceSlice(PauseSink, &ps, "pause-slice", hay, &f_ml, .{ .multiline = true });
        try testing.expect(r1.paused);
        try testing.expectEqual(@as(usize, 1), ps.hits);
        try testing.expectEqual(@as(u64, 2), ps.last_line);

        ps.pause_first = false;
        const r2 = try resumeSourceSlice(PauseSink, &ps, "pause-slice", hay, &f_ml, .{ .multiline = true }, r1);
        try testing.expect(!r2.paused);
        try testing.expectEqual(@as(usize, 2), ps.hits);
        try testing.expectEqual(@as(u64, 5), ps.last_line);
        try testing.expectEqual(@as(u64, 2), r2.matched_lines);

        // Streaming pause + resumeSource
        var ps_stream = PauseSink{};
        var reader1 = std.Io.Reader.fixed(hay);
        const sr1 = try searchSource(PauseSink, alloc, &ps_stream, &reader1, "pause-stream", &f_ml, .{
            .multiline = true,
            .buffer_size = 8,
            .max_multiline_window = 8,
        });
        try testing.expect(sr1.paused);
        try testing.expectEqual(@as(usize, 1), ps_stream.hits);
        ps_stream.pause_first = false;
        var reader2 = std.Io.Reader.fixed(hay);
        const sr2 = try resumeSource(PauseSink, alloc, &ps_stream, &reader2, "pause-stream", &f_ml, .{
            .multiline = true,
            .buffer_size = 8,
            .max_multiline_window = 8,
        }, sr1);
        try testing.expect(!sr2.paused);
        try testing.expectEqual(@as(usize, 2), ps_stream.hits);
        try testing.expectEqual(@as(u64, 5), ps_stream.last_line);
    }
}

test "multiline: adversarial streaming chunk boundaries (1, 3, 7, 17 bytes) and binary NUL handling" {
    const alloc = testing.allocator;
    const Regex = regex_mod.Regex;

    const hay =
        "line01 header\n" ++
        "line02 start foo\nbar middle foo\nbar end\n" ++
        "line05 nonmatch\n" ++
        "line06 alpha\nbeta\ngamma tail\n" ++
        "line09 footer\n";

    var re = try Regex.init(alloc, "foo\\nbar|alpha\\nbeta\\ngamma", .{
        .multiline = true,
        .max_multiline_window = 32,
    });
    defer re.deinit();

    const cfg = SearchConfig{
        .multiline = true,
        .max_multiline_window = 32,
        .buffer_size = 16,
        .before = 1,
        .after = 1,
        .binary = .none,
        .encoding = .none,
    };

    var ref_bag = Bag{};
    defer ref_bag.deinit();
    const ref_res = try searchSourceSlice(Bag, &ref_bag, "adv-ml", hay, &re, cfg);
    try testing.expectEqual(@as(u64, 2), ref_res.matched_lines);
    try testing.expectEqual(@as(u64, 3), ref_res.matches);

    const chunk_sizes = [_]usize{ 1, 3, 7, 17 };
    for (chunk_sizes) |cs| {
        // 1. searchSource with artificial_limit = cs
        var rbuf: [64]u8 = undefined;
        var t_reader = std.testing.Reader.init(&rbuf, &.{.{ .buffer = hay }});
        t_reader.artificial_limit = .limited(cs);

        var stream_bag = Bag{};
        defer stream_bag.deinit();
        const stream_res = try searchSource(Bag, alloc, &stream_bag, &t_reader.interface, "adv-ml", &re, cfg);
        try testing.expectEqual(ref_res.matched_lines, stream_res.matched_lines);
        try testing.expectEqual(ref_res.matches, stream_res.matches);
        try testing.expectEqual(ref_bag.items.items.len, stream_bag.items.items.len);

        for (ref_bag.items.items, stream_bag.items.items) |exp, got| {
            try testing.expectEqual(exp.kind, got.kind);
            if (exp.kind == .match or exp.kind == .context) {
                try testing.expectEqual(exp.line_number, got.line_number);
                try testing.expectEqual(exp.offset, got.offset);
                try testing.expectEqualStrings(exp.bytes, got.bytes);
                try testing.expectEqual(exp.matches.len, got.matches.len);
                for (exp.matches, got.matches) |em, gm| {
                    try testing.expectEqual(em.start, gm.start);
                    try testing.expectEqual(em.end, gm.end);
                }
            }
        }

        // 2. openReaderPull with artificial_limit = cs
        var rbuf2: [64]u8 = undefined;
        var t_reader2 = std.testing.Reader.init(&rbuf2, &.{.{ .buffer = hay }});
        t_reader2.artificial_limit = .limited(cs);

        var rpull = try searcher.openReaderPull(alloc, &re, "adv-ml", &t_reader2.interface, cfg);
        defer rpull.deinit();
        var idx: usize = 0;
        while (try rpull.next()) |pev| : (idx += 1) {
            const exp = ref_bag.items.items[idx];
            if (pev.kind == .match or pev.kind == .context) {
                try testing.expectEqual(exp.line_number, pev.line_number);
                try testing.expectEqual(exp.offset, pev.absolute_offset);
                try testing.expectEqualStrings(exp.bytes, pev.bytes);
                try testing.expectEqual(exp.matches.len, pev.spans.len);
            }
        }
        try testing.expectEqual(ref_bag.items.items.len, idx);
    }

    // Binary NUL byte detection before, inside, and after a cross-line match under .quit, .report, and .none
    const f_ml = try Finder.init("A\nB", .{ .multiline = true });
    const bin_before = "x\x00y\nA\nB\n";
    const bin_inside = "A\n\x00B\nA\nB\n";
    const bin_after = "A\nB\nx\x00y\n";

    // .quit
    {
        var r1 = std.Io.Reader.fixed(bin_before);
        var rec1 = Rec{};
        defer rec1.deinit(alloc);
        const res1 = try searchReader(Rec, alloc, &rec1, &r1, "b1", &f_ml, .{ .multiline = true, .binary = .quit, .buffer_size = 8, .max_multiline_window = 8 });
        try testing.expectEqual(Outcome.binary_quit, res1.outcome);
        try testing.expectEqual(@as(u64, 0), res1.matched_lines);

        var r2 = std.Io.Reader.fixed(bin_after);
        var rec2 = Rec{};
        defer rec2.deinit(alloc);
        const res2 = try searchReader(Rec, alloc, &rec2, &r2, "b2", &f_ml, .{ .multiline = true, .binary = .quit, .buffer_size = 8, .max_multiline_window = 8 });
        try testing.expectEqual(Outcome.binary_quit, res2.outcome);
        try testing.expectEqual(@as(u64, 1), res2.matched_lines);
    }
    // .report
    {
        var r_rep = std.Io.Reader.fixed(bin_inside);
        var rec_rep = Rec{};
        defer rec_rep.deinit(alloc);
        const res_rep = try searchReader(Rec, alloc, &rec_rep, &r_rep, "brep", &f_ml, .{ .multiline = true, .binary = .report, .buffer_size = 8, .max_multiline_window = 8 });
        try testing.expectEqual(Outcome.binary_matched, res_rep.outcome);
        try testing.expect(res_rep.matched_lines >= 1);
    }
    // .none
    {
        var r_none = std.Io.Reader.fixed(bin_inside);
        var rec_none = Rec{};
        defer rec_none.deinit(alloc);
        const res_none = try searchReader(Rec, alloc, &rec_none, &r_none, "bnone", &f_ml, .{ .multiline = true, .binary = .none, .buffer_size = 8, .max_multiline_window = 8 });
        try testing.expectEqual(Outcome.complete, res_none.outcome);
        try testing.expectEqual(@as(u64, 1), res_none.matched_lines);
    }

    // Regression 1: gatherSpans / replacement with trailing \r?\n delimiter matches (\r|\n, alpha|\n, foo\n)
    {
        var re_crlf = try Regex.init(alloc, "\\r|\\n", .{ .multiline = true });
        defer re_crlf.deinit();
        var bag_crlf = Bag{};
        defer bag_crlf.deinit();
        const res_crlf = try searchSourceSlice(Bag, &bag_crlf, "reg-crlf", "alpha\r\n", &re_crlf, .{ .multiline = true });
        try testing.expectEqual(@as(u64, 1), res_crlf.matched_lines);
        try testing.expectEqual(@as(usize, 1), bag_crlf.matchAt(0).matches.len);
        try testing.expectEqual(@as(usize, 5), bag_crlf.matchAt(0).matches[0].start);
        try testing.expectEqual(@as(usize, 5), bag_crlf.matchAt(0).matches[0].end);

        const RepCapture = struct {
            replaced: [64]u8 = undefined,
            len: usize = 0,
            spans: usize = 0,
            pub fn event(self: *@This(), ev: Event) bool {
                if (ev == .match) {
                    self.spans = ev.match.matches.len;
                    if (ev.match.replaced) |r| {
                        self.len = @min(r.len, self.replaced.len);
                        @memcpy(self.replaced[0..self.len], r[0..self.len]);
                    }
                }
                return true;
            }
        };

        var re_anl = try Regex.init(alloc, "alpha|\\n", .{ .multiline = true });
        defer re_anl.deinit();
        var rc1 = RepCapture{};
        _ = try searchSourceSlice(RepCapture, &rc1, "reg-anl", "alpha beta\n", &re_anl, .{
            .multiline = true,
            .replacement = "X",
            .allocator = alloc,
        });
        try testing.expectEqual(@as(usize, 1), rc1.spans);
        try testing.expectEqualStrings("X beta", rc1.replaced[0..rc1.len]);

        var re_foonl = try Regex.init(alloc, "foo\\n|foo", .{ .multiline = true });
        defer re_foonl.deinit();
        var rc2 = RepCapture{};
        _ = try searchSourceSlice(RepCapture, &rc2, "reg-foonl", "foo bar foo\n", &re_foonl, .{
            .multiline = true,
            .replacement = "X",
            .allocator = alloc,
        });
        try testing.expectEqual(@as(usize, 2), rc2.spans);
        try testing.expectEqualStrings("X bar X", rc2.replaced[0..rc2.len]);

        var re_foonl2 = try Regex.init(alloc, "foo\\n", .{ .multiline = true });
        defer re_foonl2.deinit();
        var rc3 = RepCapture{};
        const r_fnl2 = try searchSourceSlice(RepCapture, &rc3, "reg-foonl2", "foo\nbar foo\n", &re_foonl2, .{
            .multiline = true,
            .replacement = "X",
            .allocator = alloc,
        });
        try testing.expectEqual(@as(u64, 2), r_fnl2.matched_lines);
        try testing.expectEqual(@as(usize, 1), rc3.spans);
        try testing.expectEqualStrings("bar X", rc3.replaced[0..rc3.len]);
    }

    // Regression 2: Count-only searchReader (!need_ls) across streaming horizon with bridged multiline match
    {
        const CountOnlySink = struct {};
        const f_bridge = try Finder.init("foo\nbar", .{ .multiline = true });
        const bridge_doc = "header123\nfoo\nbar foo\nbar\ntail\n";

        var csink_slice = CountOnlySink{};
        const slice_cnt = try searchSlice(CountOnlySink, &csink_slice, bridge_doc, "cnt-slice", &f_bridge, .{
            .multiline = true,
            .line_numbers = false,
            .max_multiline_window = 10,
            .buffer_size = 12,
        });
        try testing.expectEqual(@as(u64, 1), slice_cnt.matched_lines);

        for ([_]usize{ 1, 3, 5, 11 }) |chunk_sz| {
            var rbuf: [64]u8 = undefined;
            var t_reader = std.testing.Reader.init(&rbuf, &.{.{ .buffer = bridge_doc }});
            t_reader.artificial_limit = .limited(chunk_sz);
            var csink_stream = CountOnlySink{};
            const stream_cnt = try searchReader(CountOnlySink, alloc, &csink_stream, &t_reader.interface, "cnt-stream", &f_bridge, .{
                .multiline = true,
                .line_numbers = false,
                .max_multiline_window = 10,
                .buffer_size = 12,
            });
            try testing.expectEqual(slice_cnt.matched_lines, stream_cnt.matched_lines);
            try testing.expectEqual(slice_cnt.matches, stream_cnt.matches);
        }
    }
}

test "multiline: soundness audit regressions (UTF-8 loop collapse, fused NUL leftmost_first, ReaderPull canFuse, EOF & zero-offset holdback)" {
    const alloc = testing.allocator;
    const Regex = regex_mod.Regex;
    const Multi = @import("../finder/multi.zig").Multi;

    // 1. UTF-8 multi-byte codepoint atomicity vs byte-exact loop peephole optimization:
    //    - Lazy [^a]+? on "©" (0xC2 0xA9) must match full 2-byte codepoint, not 1 byte.
    //    - (?m)^.+.$ on 1-codepoint "©" must NOT match (only 1 codepoint, not >= 2).
    //    - ^[^z]+\B on 1-codepoint "α" (0xCE 0xB1) must NOT match mid-codepoint.
    //    - foo[^\n]+ in .earliest mode on "foo©" must match full "foo©" (0..5), not "foo\xC2" (0..4).
    //    - Top-level (?m)foo\nbar(?-m)baz must set isMultiline() == true.
    //    - Greedy [^\n]*\n / [^\n]+\n followed by ASCII still collapses to byte-exact DFA.
    {
        var re_lazy = try Regex.init(alloc, "[^a]+?", .{});
        defer re_lazy.deinit();
        const m_lazy = re_lazy.find("©", 0, .leftmost_first).?;
        try testing.expectEqual(@as(usize, 0), m_lazy.start);
        try testing.expectEqual(@as(usize, 2), m_lazy.end);

        var re_two = try Regex.init(alloc, "(?m)^.+.$", .{});
        defer re_two.deinit();
        try testing.expect(re_two.find("©", 0, .leftmost_first) == null);
        try testing.expect(re_two.find("©!", 0, .leftmost_first) != null);

        var re_nwb = try Regex.init(alloc, "^[^z]+\\B", .{});
        defer re_nwb.deinit();
        try testing.expect(re_nwb.find("α", 0, .leftmost_first) == null);

        var re_earl = try Regex.init(alloc, "foo[^\\n]+", .{});
        defer re_earl.deinit();
        const m_earl = re_earl.find("foo©", 0, .earliest).?;
        try testing.expectEqual(@as(usize, 0), m_earl.start);
        try testing.expectEqual(@as(usize, 5), m_earl.end);

        var re_scoped_m = try Regex.init(alloc, "(?m)^foo\\nbar$(?-m)baz", .{});
        defer re_scoped_m.deinit();
        try testing.expect(re_scoped_m.isMultiline());

        var re_s16 = try Regex.init(alloc, "ERROR \\[http\\][^\\n]*\\n[^\\n]*WARN \\[cache\\]", .{ .multiline = true });
        defer re_s16.deinit();
        try testing.expect(re_s16.dfa_is_exact);

        var re_s18 = try Regex.init(alloc, "zealtionou[^\\n]+\\n[a-z]+", .{ .multiline = true });
        defer re_s18.deinit();
        try testing.expect(re_s18.dfa_is_exact);
    }

    // 2. Multiline fused NUL check (default binary = .quit) with .leftmost_first alternation:
    //    On "a\nbb\n", findWatched (.earliest) sees "b" on line 2 first, but leftmost_first
    //    must still find "a\nbb" starting on line 1 across slice, streaming, and ReaderPull.
    {
        const hay = "a\nbb\ntail\n";
        var m_alt = try Multi.init(alloc, &.{ "a\nbb", "b" }, .{ .multiline = true });
        defer m_alt.deinit();
        var re_alt = try Regex.init(alloc, "a\\nbb|b", .{ .multiline = true });
        defer re_alt.deinit();

        const cfg = SearchConfig{
            .multiline = true,
            .max_multiline_window = 16,
            .buffer_size = 8,
            .binary = .quit,
            .match_mode = .leftmost_first,
        };

        var bag_m = Bag{};
        defer bag_m.deinit();
        const res_m = try searchSourceSlice(Bag, &bag_m, "fuse-m", hay, &m_alt, cfg);
        try testing.expectEqual(@as(u64, 1), res_m.matched_lines);
        try testing.expectEqual(@as(u64, 1), bag_m.matchAt(0).line_number);
        try testing.expectEqualStrings("a\nbb", bag_m.matchAt(0).bytes);
        try testing.expectEqual(@as(usize, 0), bag_m.matchAt(0).matches[0].start);
        try testing.expectEqual(@as(usize, 4), bag_m.matchAt(0).matches[0].end);

        var bag_re = Bag{};
        defer bag_re.deinit();
        const res_re = try searchSourceSlice(Bag, &bag_re, "fuse-re", hay, &re_alt, cfg);
        try testing.expectEqual(@as(u64, 1), res_re.matched_lines);
        try testing.expectEqual(@as(u64, 1), bag_re.matchAt(0).line_number);
        try testing.expectEqualStrings("a\nbb", bag_re.matchAt(0).bytes);

        var r1 = std.Io.Reader.fixed(hay);
        var bag_sr = Bag{};
        defer bag_sr.deinit();
        const res_sr = try searchSource(Bag, alloc, &bag_sr, &r1, "fuse-sr", &re_alt, cfg);
        try testing.expectEqual(@as(u64, 1), res_sr.matched_lines);
        try testing.expectEqualStrings("a\nbb", bag_sr.matchAt(0).bytes);
    }

    // 3. ReaderPull / openReaderPull cross-chunk multiline parity with default binary = .quit (canFuse active)
    //    plus zero-offset cross-chunk bridging match holdback.
    {
        const hay = "foo\nbar foo\nbar\nalpha\nbeta\n";
        var re = try Regex.init(alloc, "foo\\nbar|alpha\\nbeta", .{
            .multiline = true,
            .max_multiline_window = 32,
        });
        defer re.deinit();

        const cfg = SearchConfig{
            .multiline = true,
            .max_multiline_window = 32,
            .buffer_size = 8,
            .binary = .quit,
        };

        var ref_bag = Bag{};
        defer ref_bag.deinit();
        const ref_res = try searchSourceSlice(Bag, &ref_bag, "pull-fuse", hay, &re, cfg);
        try testing.expectEqual(@as(u64, 2), ref_res.matched_lines);
        try testing.expectEqual(@as(u64, 3), ref_res.matches);

        for ([_]usize{ 1, 3, 5, 8 }) |cs| {
            var rbuf: [64]u8 = undefined;
            var t_reader = std.testing.Reader.init(&rbuf, &.{.{ .buffer = hay }});
            t_reader.artificial_limit = .limited(cs);

            var stream_bag = Bag{};
            defer stream_bag.deinit();
            const sres = try searchSource(Bag, alloc, &stream_bag, &t_reader.interface, "pull-fuse", &re, cfg);
            try testing.expectEqual(ref_res.matched_lines, sres.matched_lines);
            try testing.expectEqual(ref_res.matches, sres.matches);
            try testing.expectEqualStrings("foo\nbar foo\nbar", stream_bag.matchAt(0).bytes);
            try testing.expectEqualStrings("alpha\nbeta", stream_bag.matchAt(1).bytes);

            var rbuf2: [64]u8 = undefined;
            var t_reader2 = std.testing.Reader.init(&rbuf2, &.{.{ .buffer = hay }});
            t_reader2.artificial_limit = .limited(cs);

            var rpull = try searcher.openReaderPull(alloc, &re, "pull-fuse", &t_reader2.interface, cfg);
            defer rpull.deinit();
            var idx: usize = 0;
            while (try rpull.next()) |pev| : (idx += 1) {
                const exp = ref_bag.items.items[idx];
                try testing.expectEqualStrings(@tagName(exp.kind), @tagName(pev.kind));
                if (pev.kind == .match) {
                    try testing.expectEqual(exp.line_number, pev.line_number);
                    try testing.expectEqualStrings(exp.bytes, pev.bytes);
                    try testing.expectEqual(exp.matches.len, pev.spans.len);
                }
            }
            try testing.expectEqual(ref_bag.items.items.len, idx);
        }
    }

    // 4. bridgingProbeLimit end-of-text (\z) safety when config.max_multiline_window < matcher.multilineWindow(),
    //    plus Unicode 1->3 byte case-fold ('k' <-> 'K') earliestPendingStart streaming holdback.
    {
        var re_z = try Regex.init(alloc, "start|foo(\\nbar)+\\z", .{
            .multiline = true,
            .max_multiline_window = 64,
        });
        defer re_z.deinit();
        var bag_z = Bag{};
        defer bag_z.deinit();
        const res_z = try searchSourceSlice(Bag, &bag_z, "probe-z", "start foo\nbar\n1234567890\n", &re_z, .{
            .multiline = true,
            .max_multiline_window = 3,
            .match_mode = .leftmost_first,
        });
        try testing.expectEqual(@as(u64, 1), res_z.matched_lines);
        try testing.expectEqual(@as(u64, 1), res_z.matches);
        try testing.expectEqualStrings("start foo", bag_z.matchAt(0).bytes);

        var re_kelvin = try Regex.init(alloc, "key\\nval", .{
            .multiline = true,
            .case = .insensitive,
            .unicode_case = true,
            .max_multiline_window = 32,
        });
        defer re_kelvin.deinit();
        const kelvin_hay = "pad\nKey\nval\n";
        for ([_]usize{ 1, 3, 5 }) |cs| {
            var rbuf: [64]u8 = undefined;
            var t_reader = std.testing.Reader.init(&rbuf, &.{.{ .buffer = kelvin_hay }});
            t_reader.artificial_limit = .limited(cs);
            var bag_k = Bag{};
            defer bag_k.deinit();
            const res_k = try searchSource(Bag, alloc, &bag_k, &t_reader.interface, "kelvin-stream", &re_kelvin, .{
                .multiline = true,
                .max_multiline_window = 32,
                .buffer_size = 8,
            });
            try testing.expectEqual(@as(u64, 1), res_k.matched_lines);
            try testing.expectEqualStrings("Key\nval", bag_k.matchAt(0).bytes);
        }
    }
}

test "fuzz: multiline differential oracle (Regex DFA/prefilter/watched vs pure NFA, Finder/Multi, RegexSet)" {
    const alloc = testing.allocator;
    const Regex = regex_mod.Regex;
    const RegexSet = regex_mod.RegexSet;
    const Multi = @import("../finder/multi.zig").Multi;

    // --- Part 1: Deterministic Reproducers for ALL #55, #56, and #58 Findings ---

    // #55 F1a: Fast Path 3 interior required literal max window (over-window W=10 & premature truncation W=14)
    {
        var re_over = try Regex.init(alloc, "[a-z\\n]+ERROR[a-z\\n]+", .{
            .multiline = true,
            .max_multiline_window = 10,
        });
        defer re_over.deinit();
        var re_over_nfa = try Regex.init(alloc, "[a-z\\n]+ERROR[a-z\\n]+", .{
            .multiline = true,
            .max_multiline_window = 10,
            .max_dfa_states = 0,
            .aot_dfa_max_insts = 0,
        });
        defer re_over_nfa.deinit();

        const over_hay = "aaaaa\naaaaERRORbb\nbb";
        const m_lf = re_over.find(over_hay, 0, .leftmost_first).?;
        const m_nfa = re_over_nfa.find(over_hay, 0, .leftmost_first).?;
        try testing.expect(m_lf.end - m_lf.start <= 10);
        try testing.expectEqual(m_nfa.start, m_lf.start);
        try testing.expectEqual(m_nfa.end, m_lf.end);

        var nul: ?usize = null;
        const m_w = re_over.findWatched(over_hay, 0, &nul).?;
        try testing.expect(nul == null);
        try testing.expect(m_w.end - m_w.start <= 10);

        var re_trunc = try Regex.init(alloc, "[a-z]+ERROR[a-z]*", .{
            .multiline = true,
            .max_multiline_window = 14,
        });
        defer re_trunc.deinit();
        const trunc_hay = "99ERROR99aERRORbbbbbb";
        const mt = re_trunc.find(trunc_hay, 0, .leftmost_first).?;
        try testing.expectEqual(@as(usize, 9), mt.start);
        try testing.expectEqual(@as(usize, 21), mt.end);
        var nul2: ?usize = null;
        const mtw = re_trunc.findWatched(trunc_hay, 0, &nul2).?;
        try testing.expectEqual(@as(usize, 9), mtw.start);
        try testing.expectEqual(@as(usize, 21), mtw.end);
    }

    // #55 F1b: Fast Path 2 / 4, runWithDfaGeneric (>=8 restarts), RegexSet.find, and 3x Unicode req_is_exact window
    {
        var re_alt = try Regex.init(alloc, "FOO[0-9]+|BAR[a-z]+", .{
            .multiline = true,
            .max_multiline_window = 10,
        });
        defer re_alt.deinit();
        const m_alt = re_alt.find("FOO_BARabcdefg", 0, .leftmost_first).?;
        try testing.expectEqual(@as(usize, 4), m_alt.start);
        try testing.expectEqual(@as(usize, 14), m_alt.end);

        var rs_alt = try RegexSet.init(alloc, &.{ "FOO[0-9]+", "BAR[a-z]+" }, .{
            .multiline = true,
            .max_multiline_window = 10,
        });
        defer rs_alt.deinit();
        const m_rs = rs_alt.find("FOO_BARabcdefg", 0, .leftmost_first).?;
        try testing.expectEqual(@as(usize, 4), m_rs.start);
        try testing.expectEqual(@as(usize, 14), m_rs.end);
        try testing.expectEqual(@as(?u32, 1), m_rs.pattern_id);

        var re_restarts = try Regex.init(alloc, "[0-9][a-z\\n]{8}", .{
            .multiline = true,
            .max_multiline_window = 10,
        });
        defer re_restarts.deinit();
        const m_rst = re_restarts.find("1a!2a!3a!4a!5a!6a!7a!8aaaa9bcdefgh\n", 0, .leftmost_first).?;
        try testing.expectEqual(@as(usize, 26), m_rst.start);
        try testing.expectEqual(@as(usize, 35), m_rst.end);

        var re_eszett = try Regex.init(alloc, "ßßß", .{
            .multiline = true,
            .case = .insensitive,
            .unicode_case = true,
            .max_multiline_window = 7,
        });
        defer re_eszett.deinit();
        // "ẞẞẞ" is 9 UTF-8 bytes (> window 7) and must NOT exceed max_multiline_window!
        try testing.expect(re_eszett.find("ẞẞẞ", 0, .leftmost_first) == null);
    }

    // #55 F2: Lockstep NFA gen_table shadowing under max_multiline_window = 5
    {
        var re_shadow = try Regex.init(alloc, "[x\\n]+[e]nd", .{
            .multiline = true,
            .max_multiline_window = 5,
        });
        defer re_shadow.deinit();
        const ms = re_shadow.find("xxxxxxend", 0, .leftmost_first).?;
        try testing.expectEqual(@as(usize, 4), ms.start);
        try testing.expectEqual(@as(usize, 9), ms.end);

        var rs_shadow = try RegexSet.init(alloc, &.{"[x\\n]+END"}, .{
            .multiline = true,
            .max_multiline_window = 5,
        });
        defer rs_shadow.deinit();
        var shadow_ids: [4]u32 = undefined;
        try testing.expectEqual(@as(usize, 1), rs_shadow.matches("xxxxxxEND", &shadow_ids));
        try testing.expectEqual(@as(u32, 0), shadow_ids[0]);
        const mrs = rs_shadow.find("xxxxxxEND", 0, .leftmost_first).?;
        try testing.expectEqual(@as(usize, 4), mrs.start);
        try testing.expectEqual(@as(usize, 9), mrs.end);
    }

    // #55 F3 + #56 F14 + #58 #2: findWatched alt_prefilter & in-match NUL detection
    {
        var re_lp = try Regex.init(alloc, "LONG_PREFIX\\n[0-9]+|NG_[0-9]+", .{ .multiline = true });
        defer re_lp.deinit();
        var nul: ?usize = null;
        const mlp = re_lp.findWatched("LONG_PREFIX\n123", 0, &nul).?;
        try testing.expect(nul == null);
        try testing.expectEqual(@as(usize, 0), mlp.start);
        try testing.expectEqual(@as(usize, 15), mlp.end);

        var re_bc = try Regex.init(alloc, "a\\nbcd1|bc[89]", .{ .multiline = true });
        defer re_bc.deinit();
        var bc_bag = Bag{};
        defer bc_bag.deinit();
        const bc_res = try searchSourceSlice(Bag, &bc_bag, "bc", "a\nbcd1\n", &re_bc, .{ .multiline = true });
        try testing.expectEqual(@as(u64, 1), bc_res.matched_lines);

        var re_nul = try Regex.init(alloc, "BEGIN.*END", .{ .multiline = true, .dot_all = true });
        defer re_nul.deinit();
        var nul_at: ?usize = null;
        try testing.expect(re_nul.findWatched("BEGIN\x00END", 0, &nul_at) == null);
        try testing.expectEqual(@as(?usize, 5), nul_at);
    }

    // #55 F4, F5, F6, F7, F8, F9 + #58 #1 & #3:
    // .earliest greediness, 'k'/'K' & 's'/'ſ' Unicode NFA/classes, (?i)FOO(?-i)bar in RegexSet,
    // explicit (?-m) anchor scope, single-line \r windowLimit, [^\D]/[^\W]/[^\S], RegexSet.findAllowed, []|]
    {
        var re_greedy = try Regex.init(alloc, "ERR[0-9]+", .{ .multiline = true });
        defer re_greedy.deinit();
        var nul_g: ?usize = null;
        const mg1 = re_greedy.find("ERR123", 0, .earliest).?;
        const mg2 = re_greedy.findWatched("ERR123", 0, &nul_g).?;
        try testing.expectEqual(@as(usize, 6), mg1.end);
        try testing.expectEqual(mg1.end, mg2.end);

        var re_cap_k = try Regex.init(alloc, "(key)\\nval", .{ .multiline = true, .case = .insensitive, .unicode_case = true });
        defer re_cap_k.deinit();
        try testing.expect(re_cap_k.find("pad\nKey\nval\n", 0, .leftmost_first) != null);
        try testing.expect(re_cap_k.acceptsSpan("Key\nval", .leftmost_first));

        var re_k_plus = try Regex.init(alloc, "key\\nval+", .{ .multiline = true, .case = .insensitive, .unicode_case = true });
        defer re_k_plus.deinit();
        try testing.expect(re_k_plus.find("Key\nvalll", 0, .leftmost_first) != null);

        var re_long_s = try Regex.init(alloc, "status\\n1", .{ .multiline = true, .case = .insensitive, .unicode_case = true });
        defer re_long_s.deinit();
        try testing.expect(re_long_s.find("ſtatus\n1", 0, .leftmost_first) != null);

        var re_mixed_cls = try Regex.init(alloc, "(?i)[kα]", .{ .unicode_case = true });
        defer re_mixed_cls.deinit();
        try testing.expect(re_mixed_cls.isMatch("K"));

        var rs_inline_i = try RegexSet.init(alloc, &.{"(?i)FOO(?-i)bar"}, .{});
        defer rs_inline_i.deinit();
        try testing.expect(rs_inline_i.isMatch("foobar"));
        try testing.expect(!rs_inline_i.isMatch("fooBAR"));

        var re_neg_m = try Regex.init(alloc, "(?m)000\\n(?-m:^alpha)", .{});
        defer re_neg_m.deinit();
        try testing.expect(re_neg_m.find("000\nalpha\n", 0, .leftmost_first) == null);

        var re_cr = try Regex.init(alloc, "a+bar\\r", .{});
        defer re_cr.deinit();
        const mcr = re_cr.find("aaabar\r\n", 0, .leftmost_first).?;
        try testing.expectEqual(@as(usize, 0), mcr.start);
        try testing.expectEqual(@as(usize, 7), mcr.end);

        var re_dneg = try Regex.init(alloc, "^[^\\D]+$", .{});
        defer re_dneg.deinit();
        try testing.expect(re_dneg.isMatch("0123456789"));
        try testing.expect(!re_dneg.isMatch("你好"));
        try testing.expect(!re_dneg.isMatch("😀"));

        var re_wneg = try Regex.init(alloc, "^[^\\W]+$", .{});
        defer re_wneg.deinit();
        try testing.expect(re_wneg.isMatch("azAZ09_"));
        try testing.expect(!re_wneg.isMatch("你好"));

        var re_sneg = try Regex.init(alloc, "^[^\\S]+$", .{});
        defer re_sneg.deinit();
        try testing.expect(re_sneg.isMatch(" \t"));
        try testing.expect(!re_sneg.isMatch("😀"));

        var rs_ww = try RegexSet.init(alloc, &.{ "foo", "foobar" }, .{});
        defer rs_ww.deinit();
        var ww_bag = Bag{};
        defer ww_bag.deinit();
        const ww_res = try searchSourceSlice(Bag, &ww_bag, "ww", "foobar\n", &rs_ww, .{ .whole_word = true });
        try testing.expectEqual(@as(u64, 1), ww_res.matched_lines);
        try testing.expectEqual(@as(?u32, 1), ww_bag.matchAt(0).matches[0].pattern_id);

        var re_cls_pipe = try Regex.init(alloc, "\\A[]|]x", .{});
        defer re_cls_pipe.deinit();
        try testing.expect(re_cls_pipe.find("|x", 0, .leftmost_first) != null);
        try testing.expect(re_cls_pipe.find("z|x", 0, .leftmost_first) == null);
    }

    // #56 F1..F12 Pipeline Reproducers:
    {
        // F1: .binary = .report fused findWatched
        var m_rep = try Multi.init(alloc, &.{ "a\nbb", "b" }, .{ .multiline = true });
        defer m_rep.deinit();
        var rep_bag = Bag{};
        defer rep_bag.deinit();
        const rep_res = try searchSourceSlice(Bag, &rep_bag, "f1", "a\nbb\n", &m_rep, .{
            .multiline = true,
            .binary = .report,
            .match_mode = .leftmost_first,
        });
        try testing.expectEqual(@as(u64, 1), rep_res.matched_lines);
        try testing.expectEqual(@as(u64, 1), rep_bag.matchAt(0).line_number);

        // F2 & F10 & F12: $1 capture replacement consuming \r?\n, by-value Regex in ReaderPull, gatherSpans \b
        var re_rep = try Regex.init(alloc, "(foo)\\r?\\n", .{ .multiline = true });
        defer re_rep.deinit();
        var pull_crlf = openSourcePull(alloc, &re_rep, "f2", "foo\r\n", .{
            .multiline = true,
            .replacement = "[$1]",
            .allocator = alloc,
        });
        defer pull_crlf.deinit();
        var saw_f2 = false;
        while (try pull_crlf.next()) |ev| {
            if (ev.kind == .match) {
                try testing.expectEqualStrings("[foo]", ev.replaced.?);
                saw_f2 = true;
            }
        }
        try testing.expect(saw_f2);

        // F10: By-value Regex in openReaderPull
        var re_by_val = try Regex.init(alloc, "id=([0-9]+)", .{});
        defer re_by_val.deinit();
        var fixed_bv = std.Io.Reader.fixed("user id=777 ok\n");
        var rpull_bv = try searcher.openReaderPull(alloc, re_by_val, "f10", &fixed_bv, .{
            .replacement = "<$1>",
            .allocator = alloc,
        });
        defer rpull_bv.deinit();
        var saw_f10 = false;
        while (try rpull_bv.next()) |ev| {
            if (ev.kind == .match) {
                try testing.expectEqualStrings("user <777> ok", ev.replaced.?);
                saw_f10 = true;
            }
        }
        try testing.expect(saw_f10);

        // F12: gatherSpans intermediate zero-width \b match
        var re_zw_mid = try Regex.init(alloc, "bar|\\b|foo", .{ .multiline = true });
        defer re_zw_mid.deinit();
        var pull_f12 = openSourcePull(alloc, &re_zw_mid, "f12", "bar! foo\n", .{
            .multiline = true,
            .replacement = "X",
            .allocator = alloc,
        });
        defer pull_f12.deinit();
        while (try pull_f12.next()) |ev| {
            if (ev.kind == .match) {
                try testing.expectEqualStrings("XX! Xfoo", ev.replaced.?);
            }
        }

        var re_zw_mid2 = try Regex.init(alloc, "bar|foo|\\b", .{ .multiline = true });
        defer re_zw_mid2.deinit();
        var pull_f12b = openSourcePull(alloc, &re_zw_mid2, "f12b", "bar! foo\n", .{
            .multiline = true,
            .match_mode = .leftmost_first,
            .replacement = "X",
            .allocator = alloc,
        });
        defer pull_f12b.deinit();
        while (try pull_f12b.next()) |ev| {
            if (ev.kind == .match) {
                try testing.expectEqualStrings("XX! X", ev.replaced.?);
            }
        }

        // F3: Count-only EOF zero-width (?m)$ and \z
        const EmptyCountSink = struct {};
        var re_eof_z = try Regex.init(alloc, "\\z", .{ .multiline = true });
        defer re_eof_z.deinit();
        var csink = EmptyCountSink{};
        const z_cnt = try searchSlice(EmptyCountSink, &csink, "abc", "f3", &re_eof_z, .{ .multiline = true, .binary = .quit });
        try testing.expectEqual(@as(u64, 1), z_cnt.matched_lines);

        // F4: whole_line (-x) multiline
        var m_wl = try Multi.init(alloc, &.{ "bar", "foo bar\nbaz" }, .{ .multiline = true });
        defer m_wl.deinit();
        var wl_bag = Bag{};
        defer wl_bag.deinit();
        const wl_res = try searchSourceSlice(Bag, &wl_bag, "f4", "foo bar\nbaz\n", &m_wl, .{
            .multiline = true,
            .whole_line = true,
            .match_mode = .earliest,
        });
        try testing.expectEqual(@as(u64, 1), wl_res.matched_lines);
        try testing.expectEqualStrings("foo bar\nbaz", wl_bag.matchAt(0).bytes);

        // F5: Cross-line match bridging into ultra-long line (max_line_len = 32, buffer_size = 48)
        const f_long_ml = try Finder.init("ALPHA\nBETA", .{ .multiline = true });
        const long_ml_doc = "ALPHA\nBETAxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n";
        const long_ml_cfg = SearchConfig{
            .multiline = true,
            .max_line_len = 32,
            .buffer_size = 48,
            .binary = .none,
        };
        var sl_cnt = EmptyCountSink{};
        const r_sl = try searchSlice(EmptyCountSink, &sl_cnt, long_ml_doc, "f5s", &f_long_ml, long_ml_cfg);
        try testing.expectEqual(@as(u64, 1), r_sl.matched_lines);

        var rbuf5: [64]u8 = undefined;
        var tr5 = std.testing.Reader.init(&rbuf5, &.{.{ .buffer = long_ml_doc }});
        tr5.artificial_limit = .limited(11);
        var sr_cnt = EmptyCountSink{};
        const r_sr = try searchReader(EmptyCountSink, alloc, &sr_cnt, &tr5.interface, "f5r", &f_long_ml, long_ml_cfg);
        try testing.expectEqual(@as(u64, 1), r_sr.matched_lines);

        // F6: \A streaming incomplete line 2 & -A after-context
        var re_anc = try Regex.init(alloc, "\\Afoo\\nbar", .{ .multiline = true, .max_multiline_window = 16 });
        defer re_anc.deinit();
        const anc_doc = "foo\nbar_rest_of_line_2\nc1\nc2\n";
        var rbuf6: [64]u8 = undefined;
        var tr6 = std.testing.Reader.init(&rbuf6, &.{.{ .buffer = anc_doc }});
        tr6.artificial_limit = .limited(16);
        var anc_bag = Bag{};
        defer anc_bag.deinit();
        const anc_res = try searchSource(Bag, alloc, &anc_bag, &tr6.interface, "f6", &re_anc, .{
            .multiline = true,
            .max_multiline_window = 16,
            .buffer_size = 16,
            .after = 2,
        });
        try testing.expectEqual(@as(u64, 1), anc_res.matched_lines);
        try testing.expectEqualStrings("foo\nbar_rest_of_line_2", anc_bag.matchAt(0).bytes);
        try testing.expectEqual(@as(usize, 2), anc_bag.kindCount(.context));

        // F7: SliceIter zero-width EOF termination + populated .column
        const f_empty = try Finder.init("", .{});
        var sit = sink_mod.SliceIter(*const Finder).init("abc", &f_empty);
        const first_it = sit.next().?;
        try testing.expectEqual(@as(?u64, 1), first_it.column);
        try testing.expect(sit.next() == null);

        // F9: afterContext with max_count + invert + multiline
        const f_ab = try Finder.init("a\nb", .{ .multiline = true });
        var rec_f9 = Rec{};
        defer rec_f9.deinit(alloc);
        const res_f9 = try searchSlice(Rec, &rec_f9, "ok\na\nb\n", "f9", &f_ab, .{
            .multiline = true,
            .invert = true,
            .max_count = 1,
            .after = 2,
            .line_numbers = true,
        });
        try testing.expectEqual(@as(u64, 1), res_f9.matched_lines);
        try testing.expectEqualStrings("1:ok\n2-a\n3-b\n", rec_f9.text.items);

        // F11: Flow.pause on .context preserves resume_line
        const PauseOnCtx = struct {
            paused_once: bool = false,
            last_match_ln: u64 = 0,
            pub fn event(self: *@This(), ev: Event) Flow {
                switch (ev) {
                    .context => {
                        if (!self.paused_once) {
                            self.paused_once = true;
                            return .pause;
                        }
                    },
                    .match => |m| self.last_match_ln = m.line_number,
                    else => {},
                }
                return .cont;
            }
        };
        const f_hit = try Finder.init("HIT", .{});
        var pctx = PauseOnCtx{};
        const pdoc = "c1\nHIT1\na1\na2\nHIT2\n";
        const p1 = try searchSourceSlice(PauseOnCtx, &pctx, "f11", pdoc, &f_hit, .{ .after = 2 });
        try testing.expect(p1.paused);
        const p2 = try resumeSourceSlice(PauseOnCtx, &pctx, "f11", pdoc, &f_hit, .{ .after = 2 }, p1);
        try testing.expect(!p2.paused);
        try testing.expectEqual(@as(u64, 5), pctx.last_match_ln);
    }

    // --- Part 2: Randomized PRNG Multiline Differential Oracle (DFA/Prefilter/Watched vs Pure NFA & RegexSet) ---
    {
        const Spec = struct {
            pat: []const u8,
            win: usize,
            ci: bool = false,
            dot_all: bool = false,
        };
        const specs = [_]Spec{
            .{ .pat = "[a-d\\n]+ab[a-d\\n]*", .win = 9 },
            .{ .pat = "ab[0-3\\n]+|cd[a-d]+", .win = 11 },
            .{ .pat = "[a-d\\n]+[c]d", .win = 6 },
            .{ .pat = "(?i)ka\\n[b-d]+", .win = 12, .ci = true },
            .{ .pat = "(?i)sa[0-3\\n]+b", .win = 10, .ci = true },
            .{ .pat = "a.*b", .win = 10, .dot_all = true },
            .{ .pat = "(?m)^[a-d]+\\n[0-3]+$", .win = 16 },
            .{ .pat = "ab\\r?\\ncd|[0-3]{2}\\n[a-d]{2}", .win = 14 },
        };

        const tokens = [_][]const u8{
            "a", "b", "c", "d", "0", "1", "2", "\n", "\r\n", " ", "ab", "cd", "\u{212A}", "\u{017F}",
        };

        var prng = std.Random.DefaultPrng.init(0x5EED_CAFE_2026);
        const rand = prng.random();

        for (specs) |sp| {
            const fast_opts = regex_mod.RegexOptions{
                .multiline = true,
                .dot_all = sp.dot_all,
                .case = if (sp.ci) .insensitive else .sensitive,
                .unicode_case = true,
                .max_multiline_window = sp.win,
            };
            var nfa_opts = fast_opts;
            nfa_opts.max_dfa_states = 0;
            nfa_opts.aot_dfa_max_insts = 0;

            var re_fast = try Regex.init(alloc, sp.pat, fast_opts);
            defer re_fast.deinit();
            var re_nfa = try Regex.init(alloc, sp.pat, nfa_opts);
            defer re_nfa.deinit();

            var hay_buf: [96]u8 = undefined;
            for (0..32) |_| {
                var hlen: usize = 0;
                const tok_cnt = rand.intRangeAtMost(usize, 4, 24);
                for (0..tok_cnt) |_| {
                    const tok = tokens[rand.uintLessThan(usize, tokens.len)];
                    if (hlen + tok.len > hay_buf.len) break;
                    @memcpy(hay_buf[hlen .. hlen + tok.len], tok);
                    hlen += tok.len;
                }
                const hay = hay_buf[0..hlen];

                for ([_]matcher_mod.MatchMode{ .earliest, .leftmost_first }) |mode| {
                    var pos: usize = 0;
                    while (pos <= hay.len) : (pos += 1) {
                        if (pos > 0 and pos < hay.len and (hay[pos] & 0xC0) == 0x80) continue; // UTF-8 boundary
                        const mf = re_fast.find(hay, pos, mode);
                        const mn = re_nfa.find(hay, pos, mode);
                        try testing.expectEqual(mn != null, mf != null);
                        if (mn) |en| {
                            const ef = mf.?;
                            try testing.expect(ef.end - ef.start <= sp.win);
                            try testing.expectEqual(en.start, ef.start);
                            try testing.expectEqual(en.end, ef.end);
                        }
                    }
                }

                var nul_w: ?usize = null;
                const mw = re_fast.findWatched(hay, 0, &nul_w);
                try testing.expect(nul_w == null);
                const mn0 = re_nfa.find(hay, 0, .earliest);
                try testing.expectEqual(mn0 != null, mw != null);
            }
        }

        // Differential check for RegexSet.matches & Multi.find across randomized multiline inputs
        var rs_ora = try RegexSet.init(alloc, &.{
            "[a-d\\n]+ab[a-d\\n]*",
            "ab[0-3\\n]+|cd[a-d]+",
            "[a-d\\n]+[c]d",
            "(?m)^[a-d]+\\n[0-3]+$",
        }, .{ .multiline = true, .max_multiline_window = 10 });
        defer rs_ora.deinit();

        var nfa0 = try Regex.init(alloc, "[a-d\\n]+ab[a-d\\n]*", .{ .multiline = true, .max_multiline_window = 10, .max_dfa_states = 0, .aot_dfa_max_insts = 0 });
        defer nfa0.deinit();
        var nfa1 = try Regex.init(alloc, "ab[0-3\\n]+|cd[a-d]+", .{ .multiline = true, .max_multiline_window = 10, .max_dfa_states = 0, .aot_dfa_max_insts = 0 });
        defer nfa1.deinit();
        var nfa2 = try Regex.init(alloc, "[a-d\\n]+[c]d", .{ .multiline = true, .max_multiline_window = 10, .max_dfa_states = 0, .aot_dfa_max_insts = 0 });
        defer nfa2.deinit();
        var nfa3 = try Regex.init(alloc, "(?m)^[a-d]+\\n[0-3]+$", .{ .multiline = true, .max_multiline_window = 10, .max_dfa_states = 0, .aot_dfa_max_insts = 0 });
        defer nfa3.deinit();
        const nfas = [_]*const Regex{ &nfa0, &nfa1, &nfa2, &nfa3 };

        var m_ora = try Multi.init(alloc, &.{ "ab\nc", "cd\n0", "a\r\nb" }, .{ .multiline = true, .max_multiline_window = 8 });
        defer m_ora.deinit();

        var hay_buf2: [96]u8 = undefined;
        for (0..40) |_| {
            var hlen: usize = 0;
            const tok_cnt = rand.intRangeAtMost(usize, 5, 24);
            for (0..tok_cnt) |_| {
                const tok = tokens[rand.uintLessThan(usize, tokens.len)];
                if (hlen + tok.len > hay_buf2.len) break;
                @memcpy(hay_buf2[hlen .. hlen + tok.len], tok);
                hlen += tok.len;
            }
            const hay = hay_buf2[0..hlen];

            var got_ids: [8]u32 = undefined;
            const got_n = rs_ora.matches(hay, &got_ids);
            var exp_ids: [8]u32 = undefined;
            var exp_n: usize = 0;
            for (nfas, 0..) |rptr, idx| {
                if (rptr.isMatch(hay)) {
                    exp_ids[exp_n] = @intCast(idx);
                    exp_n += 1;
                }
            }
            try testing.expectEqualSlices(u32, exp_ids[0..exp_n], got_ids[0..got_n]);
            try testing.expectEqual(exp_n > 0, rs_ora.find(hay, 0, .leftmost_first) != null);

            const m_hit = m_ora.find(hay, 0, .leftmost_first);
            const has_lit = (std.mem.find(u8, hay, "ab\nc") != null) or
                (std.mem.find(u8, hay, "cd\n0") != null) or
                (std.mem.find(u8, hay, "a\r\nb") != null);
            try testing.expectEqual(has_lit, m_hit != null);
        }
    }
}

fn encodeAsciiAsUtf16WithBomAlloc(alloc: std.mem.Allocator, ascii_text: []const u8, little_endian: bool) ![]u8 {
    const out = try alloc.alloc(u8, 2 + ascii_text.len * 2);
    if (little_endian) {
        out[0] = 0xFF;
        out[1] = 0xFE;
        for (ascii_text, 0..) |b, i| {
            out[2 + i * 2] = b;
            out[2 + i * 2 + 1] = 0;
        }
    } else {
        out[0] = 0xFE;
        out[1] = 0xFF;
        for (ascii_text, 0..) |b, i| {
            out[2 + i * 2] = 0;
            out[2 + i * 2 + 1] = b;
        }
    }
    return out;
}

test "multiline: 5-way pipeline equivalence matrix (slice quit/report/none vs chunked searchSource vs ReaderPull)" {
    const alloc = testing.allocator;
    const Regex = regex_mod.Regex;

    const assert5Way = struct {
        fn check(matcher_ptr: anytype, hay: []const u8, base_cfg: SearchConfig) !void {
            var cfg_quit = base_cfg;
            cfg_quit.binary = .quit;
            cfg_quit.allocator = alloc;

            var ref_bag = Bag{};
            defer ref_bag.deinit();
            const ref_res = try searchSourceSlice(Bag, &ref_bag, "m5", hay, matcher_ptr, cfg_quit);

            // (2) & (3) slice .report and .none on non-binary text must emit identical events
            for ([_]BinaryPolicy{ .report, .none }) |pol| {
                var c = cfg_quit;
                c.binary = pol;
                var b = Bag{};
                defer b.deinit();
                const r = try searchSourceSlice(Bag, &b, "m5", hay, matcher_ptr, c);
                try testing.expectEqual(ref_res.matched_lines, r.matched_lines);
                try testing.expectEqual(ref_res.matches, r.matches);
                try testing.expectEqual(ref_bag.items.items.len, b.items.items.len);
            }

            // (4) searchSource & (5) openReaderPull across chunk sizes 1, 2, 3, 7, 19, 64
            for ([_]usize{ 1, 2, 3, 7, 19, 64 }) |cs| {
                var rbuf1: [128]u8 = undefined;
                var tr1 = std.testing.Reader.init(&rbuf1, &.{.{ .buffer = hay }});
                tr1.artificial_limit = .limited(cs);

                var stream_bag = Bag{};
                defer stream_bag.deinit();
                const sres = try searchSource(Bag, alloc, &stream_bag, &tr1.interface, "m5", matcher_ptr, cfg_quit);
                try testing.expectEqual(ref_res.matched_lines, sres.matched_lines);
                try testing.expectEqual(ref_res.matches, sres.matches);
                try testing.expectEqual(ref_bag.items.items.len, stream_bag.items.items.len);
                for (ref_bag.items.items, stream_bag.items.items) |exp, got| {
                    try testing.expectEqual(exp.kind, got.kind);
                    if (exp.kind == .match or exp.kind == .context) {
                        try testing.expectEqual(exp.line_number, got.line_number);
                        try testing.expectEqualStrings(exp.bytes, got.bytes);
                        try testing.expectEqual(exp.matches.len, got.matches.len);
                    }
                }

                var rbuf2: [128]u8 = undefined;
                var tr2 = std.testing.Reader.init(&rbuf2, &.{.{ .buffer = hay }});
                tr2.artificial_limit = .limited(cs);

                var rpull = try searcher.openReaderPull(alloc, matcher_ptr, "m5", &tr2.interface, cfg_quit);
                defer rpull.deinit();
                var idx: usize = 0;
                while (try rpull.next()) |pev| : (idx += 1) {
                    const exp = ref_bag.items.items[idx];
                    if (pev.kind == .match or pev.kind == .context) {
                        try testing.expectEqual(exp.line_number, pev.line_number);
                        try testing.expectEqualStrings(exp.bytes, pev.bytes);
                        try testing.expectEqual(exp.matches.len, pev.spans.len);
                    }
                }
                try testing.expectEqual(ref_bag.items.items.len, idx);
            }
        }
    }.check;

    // 1. 7-line multi-chunk bridging chain ("hit\nhit" across 7 consecutive lines = 1 bridged MatchEvent with 6 matches) + -B/-A context
    {
        const f_chain = try Finder.init("hit\nhit", .{ .multiline = true });
        const chain_doc = "c0\nc1\nhit\nhit\nhit\nhit\nhit\nhit\nhit\na0\na1\nsep\nhit\nhit\ntail\n";
        try assert5Way(&f_chain, chain_doc, .{
            .multiline = true,
            .max_multiline_window = 24,
            .buffer_size = 16,
            .before = 2,
            .after = 2,
        });
    }

    // 2. Invert (-v), passthru, whole_line (-x), whole_word (-w), CRLF, and $1 replacement
    {
        var re_pair = try Regex.init(alloc, "([a-z]+)\\r?\\n([0-9]+)", .{
            .multiline = true,
            .max_multiline_window = 32,
        });
        defer re_pair.deinit();
        const crlf_doc = "hdr\r\nkey\r\n42\r\nmid\r\nfoo_bar\r\n99\r\nend\r\n";

        try assert5Way(&re_pair, crlf_doc, .{
            .multiline = true,
            .max_multiline_window = 32,
            .buffer_size = 16,
            .replacement = "$2=$1",
        });
        try assert5Way(&re_pair, crlf_doc, .{
            .multiline = true,
            .max_multiline_window = 32,
            .buffer_size = 16,
            .invert = true,
            .context = 1,
        });
        try assert5Way(&re_pair, crlf_doc, .{
            .multiline = true,
            .max_multiline_window = 32,
            .buffer_size = 16,
            .passthru = true,
        });
        try assert5Way(&re_pair, crlf_doc, .{
            .multiline = true,
            .max_multiline_window = 32,
            .buffer_size = 16,
            .whole_line = true,
        });
        try assert5Way(&re_pair, crlf_doc, .{
            .multiline = true,
            .max_multiline_window = 32,
            .buffer_size = 16,
            .whole_word = true,
        });
    }

    // 3. UTF-16LE BOM, UTF-16BE BOM, Gzip streaming multiline, and Flow.pause / resume
    {
        const f_ml = try Finder.init("ALPHA\nBETA", .{ .multiline = true });
        const plain = "row1\nALPHA\nBETA\nrow4\nALPHA\nBETA\nrow7\n";

        const u16le = try encodeAsciiAsUtf16WithBomAlloc(alloc, plain, true);
        defer alloc.free(u16le);
        try assert5Way(&f_ml, u16le, .{ .multiline = true, .buffer_size = 24 });

        const u16be = try encodeAsciiAsUtf16WithBomAlloc(alloc, plain, false);
        defer alloc.free(u16be);
        try assert5Way(&f_ml, u16be, .{ .multiline = true, .buffer_size = 24 });

        const gz = try decompress.compressGzipStoredAlloc(alloc, plain);
        defer alloc.free(gz);
        try assert5Way(&f_ml, gz, .{ .multiline = true, .compression = .gzip, .buffer_size = 24 });

        // Flow.pause + resumeSourceSlice across multiline blocks
        const PauseFirstMatch = struct {
            paused_once: bool = false,
            hits: usize = 0,
            last_ln: u64 = 0,
            pub fn event(self: *@This(), ev: Event) Flow {
                if (ev == .match) {
                    self.hits += 1;
                    self.last_ln = ev.match.line_number;
                    if (!self.paused_once) {
                        self.paused_once = true;
                        return .pause;
                    }
                }
                return .cont;
            }
        };
        var ps = PauseFirstMatch{};
        const r1 = try searchSourceSlice(PauseFirstMatch, &ps, "ml-pause", plain, &f_ml, .{ .multiline = true });
        try testing.expect(r1.paused);
        try testing.expectEqual(@as(usize, 1), ps.hits);
        const r2 = try resumeSourceSlice(PauseFirstMatch, &ps, "ml-pause", plain, &f_ml, .{ .multiline = true }, r1);
        try testing.expect(!r2.paused);
        try testing.expectEqual(@as(usize, 2), ps.hits);
        try testing.expectEqual(@as(u64, 5), ps.last_ln);
    }
}

const TrackingRandomSource = struct {
    data: []const u8,
    min_offset: u64 = std.math.maxInt(u64),
    max_end_offset: u64 = 0,
    bytes_read: u64 = 0,
    calls: usize = 0,
    skipped_lo: u64 = 0,
    skipped_hi: u64 = 0,
    touched_skipped_region: bool = false,

    fn randomAccess(self: *TrackingRandomSource) searcher.RandomAccess {
        return .{
            .ctx = self,
            .read_at = readAtFn,
            .size = @intCast(self.data.len),
        };
    }

    fn readAtFn(ctx: ?*anyopaque, offset: u64, dest: []u8) anyerror!usize {
        const self: *TrackingRandomSource = @ptrCast(@alignCast(ctx.?));
        self.calls += 1;
        if (offset >= self.data.len or dest.len == 0) return 0;
        const off: usize = @intCast(offset);
        const n = @min(dest.len, self.data.len - off);
        @memcpy(dest[0..n], self.data[off .. off + n]);
        if (offset < self.min_offset) self.min_offset = offset;
        if (offset + n > self.max_end_offset) self.max_end_offset = offset + n;
        if (self.skipped_hi > self.skipped_lo) {
            if (offset < self.skipped_hi and offset + n > self.skipped_lo) {
                self.touched_skipped_region = true;
            }
        }
        self.bytes_read += n;
        return n;
    }
};

test "primitives: end-to-end P0-1, P0-2, P1-1, P1-2, P2-2a and cross-primitive seekable + bloom + scheduler + probe + archive workflow" {
    const alloc = testing.allocator;
    const probe_mod = @import("../probe.zig");
    const seekable_mod = @import("../codec/seekable.zig");
    const bloom_mod = @import("../finder/bloom.zig");
    const scheduler_mod = @import("../scheduler.zig");
    const archive_mod = @import("../codec/archive.zig");
    const tree_mod = @import("tree.zig");

    // -------------------------------------------------------------------------
    // 1. [P0-1] & [P0-2]: Seekable Byte-Range Search + LineNumberMode
    //    Proves [0, start) is NEVER read via searchSourceRange / read_at / seek_input!
    // -------------------------------------------------------------------------
    {
        var big_log = std.ArrayList(u8).empty;
        defer big_log.deinit(alloc);
        var line_starts = std.ArrayList(u64).empty;
        defer line_starts.deinit(alloc);

        var row_tmp: [64]u8 = undefined;
        for (0..200) |idx| {
            try line_starts.append(alloc, @intCast(big_log.items.len));
            const s = try std.fmt.bufPrint(&row_tmp, "row={d:0>4} token={s}\n", .{
                idx + 1,
                if (idx == 5 or idx == 120 or idx == 122 or idx == 195) "TARGET" else "normal",
            });
            try big_log.appendSlice(alloc, s);
        }

        const f_target = try Finder.init("TARGET", .{});
        const range_start = line_starts.items[118];
        const range_end = line_starts.items[125];

        var track = TrackingRandomSource{ .data = big_log.items };

        // Default .auto mid-file range: [0, range_start) is NEVER read, limit_hit == .none, partial == false, line_number_known == false!
        const KnownRecorder = struct {
            count: usize = 0,
            first_ln: u64 = 999,
            last_ln: u64 = 999,
            all_known: bool = true,
            any_known: bool = false,
            pub fn event(self: *@This(), ev: Event) bool {
                if (ev == .match) {
                    if (self.count == 0) self.first_ln = ev.match.line_number;
                    self.last_ln = ev.match.line_number;
                    self.all_known = self.all_known and ev.match.line_number_known;
                    self.any_known = self.any_known or ev.match.line_number_known;
                    self.count += 1;
                }
                return true;
            }
        };

        var krec = KnownRecorder{};
        const r_auto = try searcher.searchSourceRange(
            KnownRecorder,
            alloc,
            &krec,
            track.randomAccess(),
            .{ .start = range_start, .end = range_end },
            "p0-range",
            &f_target,
            .{ .buffer_size = 64 },
        );
        try testing.expectEqual(Outcome.complete, r_auto.outcome);
        try testing.expectEqual(sink_mod.LimitHit.none, r_auto.limit_hit);
        try testing.expect(!r_auto.partial);
        try testing.expectEqual(@as(u64, 2), r_auto.matched_lines);
        try testing.expect(track.min_offset >= range_start);
        try testing.expect(track.max_end_offset <= range_end);
        try testing.expect(!krec.any_known);
        try testing.expectEqual(@as(u64, 0), krec.first_ln);

        // With initial_line_number = 119 -> exact line numbers 121 and 123, line_number_known == true!
        var krec_init = KnownRecorder{};
        _ = try searcher.searchSourceRange(
            KnownRecorder,
            alloc,
            &krec_init,
            track.randomAccess(),
            .{ .start = range_start, .end = range_end },
            "p0-range-ln",
            &f_target,
            .{ .buffer_size = 64, .initial_line_number = 119 },
        );
        try testing.expect(krec_init.all_known);
        try testing.expectEqual(@as(u64, 121), krec_init.first_ln);
        try testing.expectEqual(@as(u64, 123), krec_init.last_ln);

        // range_align_lines = true + stream_offset test
        var pre_positioned = std.Io.Reader.fixed(big_log.items[@intCast(range_start)..]);
        var krec_stream = KnownRecorder{};
        const r_so = try searchSource(KnownRecorder, alloc, &krec_stream, &pre_positioned, "p0-so", &f_target, .{
            .byte_range = .{ .start = range_start + 3, .end = line_starts.items[122] + 5 },
            .range_align_lines = true,
            .stream_offset = range_start,
            .line_number_mode = .unknown,
        });
        // range_start + 3 skips line 119 -> starts at line 120; end inside line 123 extends through end of line 123 -> finds idx 120 & 122!
        try testing.expectEqual(@as(u64, 2), r_so.matched_lines);
        try testing.expect(!krec_stream.any_known);
    }

    // -------------------------------------------------------------------------
    // 2. [P1-1]: Pre-Count / Pre-Quota line_filter (slice, reader, long line, invert)
    // -------------------------------------------------------------------------
    {
        const FilterState = struct {
            seen: usize = 0,
            fn acceptKeep(ctx: ?*anyopaque, cand: searcher.LineFilterCandidate) bool {
                const self: *@This() = @ptrCast(@alignCast(ctx.?));
                self.seen += 1;
                return std.mem.find(u8, cand.bytes, "ALLOW") != null;
            }
        };

        const f_hit = try Finder.init("HIT", .{});
        const fdoc = "ctx0\nHIT DENY 1\nctx1\nHIT DENY 2\nctx2\nHIT ALLOW 3\nctx3\n";
        var fstate = FilterState{};
        var fbag = Bag{};
        defer fbag.deinit();
        const fres = try searchSourceSlice(Bag, &fbag, "p1-lf", fdoc, &f_hit, .{
            .max_count = 1,
            .max_results = 1,
            .before = 1,
            .line_filter = FilterState.acceptKeep,
            .line_filter_ctx = &fstate,
        });
        // Denied hits MUST NOT consume max_count/max_results, increment matched_lines/matches, or emit before-context!
        try testing.expectEqual(@as(usize, 3), fstate.seen);
        try testing.expectEqual(@as(u64, 1), fres.matched_lines);
        try testing.expectEqual(@as(u64, 1), fres.matches);
        try testing.expectEqual(@as(usize, 1), fbag.kindCount(.context));
        try testing.expectEqualStrings("ctx2", fbag.items.items[1].bytes);
        try testing.expectEqualStrings("HIT ALLOW 3", fbag.matchAt(0).bytes);

        // Long line (> max_line_len = 24) pre-quota line_filter in streaming searchSource
        const long_fdoc = "HIT DENY pppppppppppppppppppppppppppppp\nHIT ALLOW pppppppppppppppppppppppppppppp\n";
        var fstate2 = FilterState{};
        var lreader = std.Io.Reader.fixed(long_fdoc);
        var fbag2 = Bag{};
        defer fbag2.deinit();
        const fres2 = try searchSource(Bag, alloc, &fbag2, &lreader, "p1-long-lf", &f_hit, .{
            .max_line_len = 24,
            .buffer_size = 32,
            .max_count = 1,
            .line_filter = FilterState.acceptKeep,
            .line_filter_ctx = &fstate2,
        });
        try testing.expectEqual(@as(u64, 1), fres2.matched_lines);
        try testing.expectEqual(@as(u64, 2), fbag2.matchAt(0).line_number);
    }

    // -------------------------------------------------------------------------
    // 3. [P1-2]: Reverse Tail Search (slice & O(tail) RandomAccess, CRLF, multiline, pagination)
    // -------------------------------------------------------------------------
    {
        var tail_doc = std.ArrayList(u8).empty;
        defer tail_doc.deinit(alloc);
        var tmp: [64]u8 = undefined;
        for (0..400) |idx| {
            const s = try std.fmt.bufPrint(&tmp, "seq={d:0>4} level={s}\r\n", .{
                idx + 1,
                if (idx % 10 == 0) "ERR" else "OK",
            });
            try tail_doc.appendSlice(alloc, s);
        }

        const f_err = try Finder.init("ERR", .{});
        var track_rev = TrackingRandomSource{ .data = tail_doc.items };

        const RevBag = struct {
            lines: std.ArrayList([]u8) = .empty,
            nums: std.ArrayList(u64) = .empty,
            fn deinit(self: *@This(), a: std.mem.Allocator) void {
                for (self.lines.items) |l| a.free(l);
                self.lines.deinit(a);
                self.nums.deinit(a);
            }
            pub fn event(self: *@This(), ev: Event) bool {
                if (ev == .match) {
                    self.lines.append(testing.allocator, testing.allocator.dupe(u8, ev.match.bytes) catch unreachable) catch unreachable;
                    self.nums.append(testing.allocator, ev.match.line_number) catch unreachable;
                }
                return true;
            }
        };

        // O(tail) max_count = 2 on 400-line source: must read ONLY the tail (min_offset > 0)!
        var rbag = RevBag{};
        defer rbag.deinit(alloc);
        const rev_tail = try searcher.searchSourceReverseAt(
            RevBag,
            alloc,
            &rbag,
            track_rev.randomAccess(),
            "rev-tail",
            &f_err,
            .{ .buffer_size = 512, .max_count = 2, .initial_line_number = 400 },
        );
        try testing.expectEqual(@as(u64, 2), rev_tail.matched_lines);
        try testing.expect(track_rev.min_offset > 0);
        try testing.expectEqualSlices(u64, &.{ 391, 381 }, rbag.nums.items);

        // Full backward pagination via max_results = 15 across small chunks must match searchSourceReverseSlice 100%!
        var full_slice_rev = RevBag{};
        defer full_slice_rev.deinit(alloc);
        _ = try searcher.searchSourceReverseSlice(RevBag, &full_slice_rev, "rev-s", tail_doc.items, &f_err, .{
            .initial_line_number = 400,
        });
        try testing.expectEqual(@as(usize, 40), full_slice_rev.lines.items.len);

        var paged_rev = RevBag{};
        defer paged_rev.deinit(alloc);
        var cur_end: ?u64 = null;
        while (true) {
            const page = try searcher.searchSourceReverseAt(
                RevBag,
                alloc,
                &paged_rev,
                track_rev.randomAccess(),
                "rev-page",
                &f_err,
                .{
                    .buffer_size = 256,
                    .byte_range = .{ .start = 0, .end = cur_end },
                    .max_results = 15,
                    .line_number_mode = .unknown,
                },
            );
            if (page.limit_hit == .max_results and page.resume_at != null) {
                cur_end = page.resume_at;
            } else break;
        }
        try testing.expectEqual(full_slice_rev.lines.items.len, paged_rev.lines.items.len);
        for (full_slice_rev.lines.items, paged_rev.lines.items) |e_line, g_line| {
            try testing.expectEqualStrings(e_line, g_line);
        }

        // Multiline reverse tail search
        const f_ml_rev = try Finder.init("BEGIN\nEND", .{ .multiline = true });
        const ml_rev_doc = "0\nBEGIN\nEND\nmid\nBEGIN\nEND\ntail\n";
        var ml_rbag = RevBag{};
        defer ml_rbag.deinit(alloc);
        const ml_ra_slice: []const u8 = ml_rev_doc;
        _ = try searcher.searchSourceReverseAt(
            RevBag,
            alloc,
            &ml_rbag,
            probe_mod.RandomAccess.fromSlice(&ml_ra_slice),
            "rev-ml",
            &f_ml_rev,
            .{ .multiline = true, .max_multiline_window = 16, .buffer_size = 16, .initial_line_number = 7 },
        );
        try testing.expectEqualSlices(u64, &.{ 5, 2 }, ml_rbag.nums.items);
    }

    // -------------------------------------------------------------------------
    // 4. [P2-2a]: Flow.skipTo(offset) across slice, seekable read_at, and unseekable stream
    // -------------------------------------------------------------------------
    {
        var skip_doc = std.ArrayList(u8).empty;
        defer skip_doc.deinit(alloc);
        try skip_doc.appendSlice(alloc, "HIT_START\n"); // 0..10
        const mid_pad: [8192]u8 = @splat('.');
        try skip_doc.appendSlice(alloc, &mid_pad);
        try skip_doc.append(alloc, '\n'); // 10..8203
        const tail_off: u64 = @intCast(skip_doc.items.len);
        try skip_doc.appendSlice(alloc, "HIT_TAIL\n");

        const SkipSink = struct {
            jump_to: u64,
            hits: usize = 0,
            last_known: bool = true,
            last_ln: u64 = 0,
            pub fn event(self: *@This(), ev: Event) sink_mod.FlowAction {
                if (ev == .match) {
                    self.hits += 1;
                    self.last_known = ev.match.line_number_known;
                    self.last_ln = ev.match.line_number;
                    if (self.hits == 1) return Flow.skipTo(self.jump_to);
                }
                return .cont;
            }
        };

        const f_hit = try Finder.init("HIT_", .{});

        // (a) Slice jump preserves exact line number (line 3)!
        var ss_slice = SkipSink{ .jump_to = tail_off };
        const res_skip_slice = try searchSourceSlice(SkipSink, &ss_slice, "skip-s", skip_doc.items, &f_hit, .{});
        try testing.expectEqual(@as(u64, 2), res_skip_slice.matched_lines);
        try testing.expect(ss_slice.last_known);
        try testing.expectEqual(@as(u64, 3), ss_slice.last_ln);

        // (b) Seekable read_at jump with small 256B buffer NEVER reads the middle [1024..7500) region!
        var track_skip = TrackingRandomSource{
            .data = skip_doc.items,
            .skipped_lo = 1024,
            .skipped_hi = 7500,
        };
        var dummy_reader = std.Io.Reader.fixed("");
        var ss_ra = SkipSink{ .jump_to = tail_off };
        const res_skip_ra = try searchSource(SkipSink, alloc, &ss_ra, &dummy_reader, "skip-ra", &f_hit, .{
            .buffer_size = 256,
            .read_at = TrackingRandomSource.readAtFn,
            .read_at_ctx = &track_skip,
        });
        try testing.expectEqual(@as(u64, 2), res_skip_ra.matched_lines);
        try testing.expect(!track_skip.touched_skipped_region);
        try testing.expect(!ss_ra.last_known);

        // (c) Unseekable stream drains cleanly to target_offset
        var unseek_r = std.Io.Reader.fixed(skip_doc.items);
        var ss_unseek = SkipSink{ .jump_to = tail_off };
        const res_skip_unseek = try searchSource(SkipSink, alloc, &ss_unseek, &unseek_r, "skip-u", &f_hit, .{
            .buffer_size = 256,
        });
        try testing.expectEqual(@as(u64, 2), res_skip_unseek.matched_lines);
    }

    // -------------------------------------------------------------------------
    // 5. Cross-Primitive Workflow: ZstdSeekTable + GzipIndex + NgramBloom + Scheduler + probeLineAt + Archive entry_filter
    // -------------------------------------------------------------------------
    {
        const shard0_plain = "2026-11-18 INFO boot ok\n2026-11-18 INFO steady state\n";
        const shard1_plain = "2026-11-18 INFO warmup\n2026-11-18 CRITICAL_NEEDLE_777 db_timeout\n2026-11-18 INFO recovered\n";

        const zst_shard0 = try seekable_mod.compressSeekableZstdAlloc(alloc, shard0_plain, 32);
        defer alloc.free(zst_shard0);
        var zst_tab0 = try seekable_mod.ZstdSeekTable.parseFromSlice(alloc, zst_shard0);
        defer zst_tab0.deinit(alloc);

        const gz_shard1 = try seekable_mod.compressMultiMemberGzipAlloc(alloc, &.{ shard1_plain[0..23], shard1_plain[23..] });
        defer alloc.free(gz_shard1);
        var gz_idx1 = try seekable_mod.GzipIndex.buildFromSlice(alloc, gz_shard1, 16);
        defer gz_idx1.deinit(alloc);

        var bloom0 = try bloom_mod.NgramBloom.init(alloc, .{});
        defer bloom0.deinit();
        bloom0.addSlice(shard0_plain);

        var bloom1 = try bloom_mod.NgramBloom.init(alloc, .{});
        defer bloom1.deinit();
        bloom1.addSlice(shard1_plain);

        const needle_finder = try Finder.init("critical_needle_777", .{ .case = .insensitive, .unicode_case = true });

        const WorkCtx = struct {
            alloc: std.mem.Allocator,
            zst_bytes: []const u8,
            zst_table: *const seekable_mod.ZstdSeekTable,
            gz_bytes: []const u8,
            gz_index: *const seekable_mod.GzipIndex,
            b0: *const bloom_mod.NgramBloom,
            b1: *const bloom_mod.NgramBloom,
            finder: *const Finder,
            bloom_skips: std.atomic.Value(u32) = .init(0),
            found_hits: std.atomic.Value(u32) = .init(0),
            probed_ok: std.atomic.Value(bool) = .init(false),

            pub fn run(self: *@This(), shard_id: u32, _: anytype) !void {
                if (shard_id == 0) {
                    if (!self.b0.mayContainMatcher(self.finder)) {
                        _ = self.bloom_skips.fetchAdd(1, .acq_rel);
                        return;
                    }
                    const raw_ra = probe_mod.RandomAccess.fromSlice(&self.zst_bytes);
                    const zr = seekable_mod.SeekableZstdReader.init(self.alloc, raw_ra, self.zst_table);
                    const Empty = struct {
                        pub fn event(_: *@This(), _: Event) bool {
                            return true;
                        }
                    };
                    var es = Empty{};
                    const res = try searcher.searchSourceRange(Empty, self.alloc, &es, zr.randomAccess(), .{ .start = 0, .end = null }, "s0", self.finder, .{});
                    _ = self.found_hits.fetchAdd(@intCast(res.matched_lines), .acq_rel);
                } else {
                    if (!self.b1.mayContainMatcher(self.finder)) {
                        _ = self.bloom_skips.fetchAdd(1, .acq_rel);
                        return;
                    }
                    const raw_ra = probe_mod.RandomAccess.fromSlice(&self.gz_bytes);
                    const gr = seekable_mod.IndexedGzipReader.init(self.alloc, raw_ra, self.gz_index);
                    const HitOffset = struct {
                        off: ?u64 = null,
                        pub fn event(h: *@This(), ev: Event) bool {
                            if (ev == .match) h.off = ev.match.absolute_offset + 5;
                            return true;
                        }
                    };
                    var ho = HitOffset{};
                    const res = try searcher.searchSourceReverseAt(HitOffset, self.alloc, &ho, gr.randomAccess(), "s1", self.finder, .{});
                    _ = self.found_hits.fetchAdd(@intCast(res.matched_lines), .acq_rel);
                    if (ho.off) |probe_off| {
                        var lp = (try probe_mod.probeLineAt(self.alloc, gr.randomAccess(), probe_off, .{})).?;
                        defer lp.deinit(self.alloc);
                        if (std.mem.eql(u8, lp.bytes, "2026-11-18 CRITICAL_NEEDLE_777 db_timeout")) {
                            self.probed_ok.store(true, .release);
                        }
                    }
                }
            }
        };

        var wctx = WorkCtx{
            .alloc = alloc,
            .zst_bytes = zst_shard0,
            .zst_table = &zst_tab0,
            .gz_bytes = gz_shard1,
            .gz_index = &gz_idx1,
            .b0 = &bloom0,
            .b1 = &bloom1,
            .finder = &needle_finder,
        };
        try scheduler_mod.Scheduler(u32, WorkCtx).run(alloc, std.testing.io, .{ .max_threads = 2 }, &wctx, &.{ 0, 1 });
        try testing.expectEqual(@as(u32, 1), wctx.bloom_skips.load(.acquire));
        try testing.expectEqual(@as(u32, 1), wctx.found_hits.load(.acquire));
        try testing.expect(wctx.probed_ok.load(.acquire));

        // Also verify Archive entry_filter integration in tree.searchArchiveSlice
        const zip_bytes = try archive_mod.buildTestZipAlloc(alloc, &.{
            .{ .path = "logs/old.log", .data = "CRITICAL_NEEDLE_777 old\n", .mtime = 1_600_000_000, .zip_method = .deflate },
            .{ .path = "logs/recent.log", .data = "CRITICAL_NEEDLE_777 fresh\n", .mtime = 1_750_000_000, .zip_method = .deflate },
        });
        defer alloc.free(zip_bytes);

        const MtimeFilter = struct {
            fn allowRecent(_: ?*anyopaque, meta: archive_mod.ArchiveEntryMeta) bool {
                if (meta.mtime) |ts| return ts >= 1_700_000_000;
                return false;
            }
        };
        var abag = Bag{};
        defer abag.deinit();
        const asum = try tree_mod.searchArchiveSlice(Bag, alloc, std.testing.io, &abag, zip_bytes, &needle_finder, .{
            .archive = .{ .entry_filter = MtimeFilter.allowRecent },
        });
        try testing.expectEqual(@as(u64, 1), asum.searches);
        try testing.expectEqual(@as(u64, 1), asum.matched_lines);
        try testing.expectEqualStrings("CRITICAL_NEEDLE_777 fresh", abag.matchAt(0).bytes);
    }
}

test "regressions: carbon final review items 1, 3, 4, 6, and 7" {
    const alloc = testing.allocator;
    const archive_mod = @import("../codec/archive.zig");
    const tree_mod = @import("tree.zig");

    // -------------------------------------------------------------------------
    // Item 1: Regex.findWatched Fast Path 3 (!req_is_prefix) when an earlier
    // required-literal occurrence fails the suffix DFA check and a match starts
    // before hit.start + req_prefix_shift and anchors on a later hit2.
    // -------------------------------------------------------------------------
    {
        var re = try regex_mod.Regex.init(alloc, "[0-9][a-zA-Z_]*ERROR_[0-9]+", .{});
        defer re.deinit();
        const input = "9ERROR_xERROR_1\n";
        var nul: ?usize = null;
        const m_watched = re.findWatched(input, 0, &nul).?;
        try testing.expectEqual(@as(usize, 0), m_watched.start);
        try testing.expectEqual(@as(usize, 15), m_watched.end);
        try testing.expectEqual(@as(?usize, null), nul);

        var bag = Bag{};
        defer bag.deinit();
        const res = try searchSourceSlice(Bag, &bag, "item1", input, &re, .{ .binary = .quit });
        try testing.expectEqual(@as(u64, 1), res.matched_lines);
        try testing.expectEqualStrings("9ERROR_xERROR_1", bag.matchAt(0).bytes);
    }

    // -------------------------------------------------------------------------
    // Item 3: Flow.skipTo(target) in slice search when !direct_sink
    // (e.g., match_mode = .leftmost_first or progress_interval != null)
    // must jump to target instead of clearing pending_skip_to and stopping!
    // -------------------------------------------------------------------------
    {
        const doc = "HIT_1\nHIT_2\nHIT_3\n"; // HIT_1: 0..6, HIT_2: 6..12, HIT_3: 12..18
        const f_hit = try Finder.init("HIT_", .{});

        const IndirectSkipSink = struct {
            jump_to: u64,
            lines: std.ArrayList(u64) = .empty,
            fn deinit(self: *@This(), a: std.mem.Allocator) void {
                self.lines.deinit(a);
            }
            pub fn event(self: *@This(), ev: Event) sink_mod.FlowAction {
                if (ev == .match) {
                    self.lines.append(testing.allocator, ev.match.line_number) catch unreachable;
                    if (self.lines.items.len == 1) return Flow.skipTo(self.jump_to);
                }
                return .cont;
            }
        };

        var sink1 = IndirectSkipSink{ .jump_to = 12 };
        defer sink1.deinit(alloc);
        const res1 = try searchSourceSlice(IndirectSkipSink, &sink1, "item3-lf", doc, &f_hit, .{
            .match_mode = .leftmost_first,
            .progress_interval = 4,
        });
        try testing.expectEqual(Outcome.complete, res1.outcome);
        try testing.expectEqual(@as(u64, 2), res1.matched_lines);
        try testing.expectEqualSlices(u64, &.{ 1, 3 }, sink1.lines.items);
    }

    // -------------------------------------------------------------------------
    // Item 4: Flow.skipTo(target) inside searchArchiveSlice / searchTree must
    // perform intra-file jumps without aborting the file, remaining files, or .summary!
    // -------------------------------------------------------------------------
    {
        const zip_bytes = try archive_mod.buildTestZipAlloc(alloc, &.{
            .{ .path = "a.txt", .data = "HIT_A1\nHIT_A2\nHIT_A3\n", .zip_method = .store },
            .{ .path = "b.txt", .data = "HIT_B1\n", .zip_method = .store },
        });
        defer alloc.free(zip_bytes);

        const TreeSkipSink = struct {
            matches: std.ArrayList([]u8) = .empty,
            saw_summary: bool = false,
            fn deinit(self: *@This(), a: std.mem.Allocator) void {
                for (self.matches.items) |m| a.free(m);
                self.matches.deinit(a);
            }
            pub fn event(self: *@This(), ev: Event) sink_mod.FlowAction {
                switch (ev) {
                    .match => |m| {
                        self.matches.append(testing.allocator, testing.allocator.dupe(u8, m.bytes) catch unreachable) catch unreachable;
                        if (std.mem.eql(u8, m.bytes, "HIT_A1")) {
                            // Jump past HIT_A2 (7..14) directly to HIT_A3 (offset 14)
                            return Flow.skipTo(14);
                        }
                    },
                    .summary => self.saw_summary = true,
                    else => {},
                }
                return .cont;
            }
        };

        const f_hit = try Finder.init("HIT_", .{});
        var tsink = TreeSkipSink{};
        defer tsink.deinit(alloc);
        const tsum = try tree_mod.searchArchiveSlice(TreeSkipSink, alloc, std.testing.io, &tsink, zip_bytes, &f_hit, .{});
        try testing.expect(tsink.saw_summary);
        try testing.expectEqual(@as(u64, 2), tsum.searches);
        try testing.expectEqual(@as(u64, 2), tsum.searches_with_match);
        try testing.expectEqual(@as(u64, 3), tsum.matched_lines);
        try testing.expectEqual(@as(usize, 3), tsink.matches.items.len);
        try testing.expectEqualStrings("HIT_A1", tsink.matches.items[0]);
        try testing.expectEqualStrings("HIT_A3", tsink.matches.items[1]);
        try testing.expectEqualStrings("HIT_B1", tsink.matches.items[2]);
    }

    // -------------------------------------------------------------------------
    // Item 6: Reverse search Flow.skipTo line-number accounting + binary = .report
    // with max_count when an earlier line in the window contains a NUL byte.
    // -------------------------------------------------------------------------
    {
        const f_any = try Finder.init("o", .{});
        // (a) Mid-line skipTo(8) on "hello\nworld\n" (offset 8 is inside "world\n", line 2):
        // truncating to [0..8) ("hello\nwo") must keep line 1 as line 1!
        const RevSkipBeginSink = struct {
            nums: std.ArrayList(u64) = .empty,
            fn deinit(self: *@This(), a: std.mem.Allocator) void {
                self.nums.deinit(a);
            }
            pub fn event(self: *@This(), ev: Event) sink_mod.FlowAction {
                switch (ev) {
                    .begin => return Flow.skipTo(8),
                    .match => |m| self.nums.append(testing.allocator, m.line_number) catch unreachable,
                    else => {},
                }
                return .cont;
            }
        };
        var rsb = RevSkipBeginSink{};
        defer rsb.deinit(alloc);
        _ = try searcher.searchSourceReverseSlice(RevSkipBeginSink, &rsb, "rev-skip-begin", "hello\nworld\n", &f_any, .{
            .initial_line_number = 2,
        });
        try testing.expectEqualSlices(u64, &.{ 2, 1 }, rsb.nums.items);

        // (b) Cross-window backward skipTo in searchSourceReverseSlice with small buffer_size
        var rev_doc = std.ArrayList(u8).empty;
        defer rev_doc.deinit(alloc);
        var line_offs = std.ArrayList(u64).empty;
        defer line_offs.deinit(alloc);
        var buf: [32]u8 = undefined;
        for (0..20) |i| {
            try line_offs.append(alloc, @intCast(rev_doc.items.len));
            const s = try std.fmt.bufPrint(&buf, "row_{d:0>2}_HIT\n", .{i + 1});
            try rev_doc.appendSlice(alloc, s);
        }
        const f_hit = try Finder.init("HIT", .{});
        const RevCrossWindowSkip = struct {
            target: u64,
            nums: std.ArrayList(u64) = .empty,
            fn deinit(self: *@This(), a: std.mem.Allocator) void {
                self.nums.deinit(a);
            }
            pub fn event(self: *@This(), ev: Event) sink_mod.FlowAction {
                if (ev == .match) {
                    self.nums.append(testing.allocator, ev.match.line_number) catch unreachable;
                    if (self.nums.items.len == 1) return Flow.skipTo(self.target);
                }
                return .cont;
            }
        };
        // Jump from line 20 back to end of line 5 (line_offs[5]) across 64-byte windows
        var rcw = RevCrossWindowSkip{ .target = line_offs.items[5] };
        defer rcw.deinit(alloc);
        _ = try searcher.searchSourceReverseSlice(RevCrossWindowSkip, &rcw, "rev-cw", rev_doc.items, &f_hit, .{
            .buffer_size = 64,
            .initial_line_number = 20,
        });
        try testing.expectEqualSlices(u64, &.{ 20, 5, 4, 3, 2, 1 }, rcw.nums.items);

        // (c) Reverse search with .binary = .report and .max_count = 1 when an earlier line has NUL
        const rev_bin_doc = "bad\x00HIT_OLD\ngood_HIT_NEW\n";
        var bin_bag = Bag{};
        defer bin_bag.deinit();
        const rev_bin_res = try searcher.searchSourceReverseSlice(Bag, &bin_bag, "rev-bin", rev_bin_doc, &f_hit, .{
            .binary = .report,
            .max_count = 1,
        });
        try testing.expectEqual(@as(u64, 1), rev_bin_res.matched_lines);
        try testing.expectEqual(@as(?u64, null), rev_bin_res.binary_offset);
        try testing.expectEqual(BinaryStatus.none, bin_bag.matchAt(0).status);
        try testing.expectEqual(BinaryStatus.none, bin_bag.find(.end).status);
        try testing.expectEqualStrings("good_HIT_NEW", bin_bag.matchAt(0).bytes);
    }

    // -------------------------------------------------------------------------
    // Item 7: Flow.skipTo with line_number_mode = .from_one across seekable read_at
    // (must mark line_number_known = false) vs unseekable sequential drain
    // (must count newlines across drained bytes so line_number stays exact).
    // -------------------------------------------------------------------------
    {
        var skip_doc = std.ArrayList(u8).empty;
        defer skip_doc.deinit(alloc);
        try skip_doc.appendSlice(alloc, "HIT_START\n"); // line 1 (0..10)
        for (0..100) |_| {
            try skip_doc.appendSlice(alloc, "filler_line_padding_0123456789\n"); // lines 2..101 (3100 bytes)
        }
        const tail_off: u64 = @intCast(skip_doc.items.len);
        try skip_doc.appendSlice(alloc, "HIT_TAIL\n"); // line 102

        const FromOneSkipSink = struct {
            jump_to: u64,
            hits: usize = 0,
            last_known: bool = true,
            last_ln: u64 = 999,
            pub fn event(self: *@This(), ev: Event) sink_mod.FlowAction {
                if (ev == .match) {
                    self.hits += 1;
                    self.last_known = ev.match.line_number_known;
                    self.last_ln = ev.match.line_number;
                    if (self.hits == 1) return Flow.skipTo(self.jump_to);
                }
                return .cont;
            }
        };

        const f_hit = try Finder.init("HIT_", .{});

        // (a) Seekable read_at with .line_number_mode = .from_one: jumping skips bytes -> line_number_known = false, line_number = 0
        var track_ra = TrackingRandomSource{ .data = skip_doc.items };
        var dummy_r = std.Io.Reader.fixed("");
        var sink_ra = FromOneSkipSink{ .jump_to = tail_off };
        const res_ra = try searchSource(FromOneSkipSink, alloc, &sink_ra, &dummy_r, "item7-ra", &f_hit, .{
            .buffer_size = 256,
            .line_number_mode = .from_one,
            .read_at = TrackingRandomSource.readAtFn,
            .read_at_ctx = &track_ra,
        });
        try testing.expectEqual(@as(u64, 2), res_ra.matched_lines);
        try testing.expect(!sink_ra.last_known);
        try testing.expectEqual(@as(u64, 0), sink_ra.last_ln);

        // (b) Unseekable sequential stream drain: draining counts newlines -> line_number_known = true, line_number = 102
        var unseek_r = std.Io.Reader.fixed(skip_doc.items);
        var sink_unseek = FromOneSkipSink{ .jump_to = tail_off };
        const res_unseek = try searchSource(FromOneSkipSink, alloc, &sink_unseek, &unseek_r, "item7-unseek", &f_hit, .{
            .buffer_size = 256,
            .line_number_mode = .from_one,
        });
        try testing.expectEqual(@as(u64, 2), res_unseek.matched_lines);
        try testing.expect(sink_unseek.last_known);
        try testing.expectEqual(@as(u64, 102), sink_unseek.last_ln);
    }
}

test "v0.7.0: replacement templates support ${10}..${32} and named ${name} captures" {
    const alloc = std.testing.allocator;
    const re_mod = @import("../regex.zig");
    var re2 = try re_mod.Regex.init(alloc, "(a)(b)(c)(d)(e)(f)(g)(h)(i)(?P<ten>j):(?<name>[a-z]+)-(?<code_num>[0-9]+)", .{});
    defer re2.deinit();

    const CaptureReplSink = struct {
        buf: [128]u8 = undefined,
        len: usize = 0,
        pub fn matched(self: *@This(), line: Line) bool {
            if (line.replaced) |r| {
                self.len = @min(r.len, self.buf.len);
                @memcpy(self.buf[0..self.len], r[0..self.len]);
            }
            return true;
        }
    };

    var s = CaptureReplSink{};
    const input = "prefix abcdefghij:alice-99 suffix\n";
    _ = try searchSlice(CaptureReplSink, &s, input, "repl", &re2, .{
        .allocator = alloc,
        .replacement = "ten=${10},user=${name},code=${code_num},full=${0}",
    });
    try testing.expectEqualStrings(
        "prefix ten=j,user=alice,code=99,full=abcdefghij:alice-99 suffix",
        s.buf[0..s.len],
    );
}


test {
    _ = @import("challenger_test.zig");
}

