//! [Module] search/parallel_tests.zig
//! [Role] Parity tests: intra-source parallel search (`parallel_source.zig`) must reproduce the sequential
//!        event stream and `Result` exactly for every configuration it accepts, and fall back transparently
//!        for every configuration it does not.

const std = @import("std");
const testing = std.testing;
const par = @import("parallel_source.zig");
const searcher = @import("../searcher.zig");
const sink_mod = @import("../sink.zig");
const finder_mod = @import("../finder/finder.zig");
const multi_mod = @import("../finder/multi.zig");
const regex_mod = @import("../regex.zig");
const probe_mod = @import("../probe.zig");
const matcher_mod = @import("../matcher.zig");
const cfg_mod = @import("config.zig");

const Event = sink_mod.Event;
const FlowAction = sink_mod.FlowAction;
const Result = cfg_mod.Result;
const SearchConfig = cfg_mod.SearchConfig;

const Corpus = struct {
    lines: usize = 800,
    nul_at: ?usize = null,
    nul_sep: bool = false,
};

fn buildCorpus(alloc: std.mem.Allocator, spec: Corpus) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(alloc);
    var seed: u64 = 0x9E37_79B9_7F4A_7C15;
    for (0..spec.lines) |i| {
        seed = seed *% 6364136223846793005 +% 1442695040888963407;
        switch ((seed >> 33) % 16) {
            0, 1, 2 => try out.print(alloc, "INFO request id={d} ok", .{i}),
            3 => try out.print(alloc, "WARN needle in haystack {d}", .{i}),
            4 => try out.print(alloc, "ERROR bar{d} failed needle", .{i}),
            5 => {},
            6 => {
                try out.appendNTimes(alloc, 'x', 150 + (i % 200));
                try out.appendSlice(alloc, " needle tail");
            },
            7 => try out.print(alloc, "foo baz{d} NEEDLE\r", .{i}),
            8 => try out.print(alloc, "\xc3\xbcn\xc3\xafc\xc3\xb6d\xc3\xa9 needle {d}", .{i}),
            9 => try out.appendSlice(alloc, "\xff\xfe broken needle"),
            10 => try out.print(alloc, "needle at start {d}", .{i}),
            11 => try out.print(alloc, "plain line {d} with needles and bazooka", .{i}),
            else => try out.print(alloc, "DEBUG value={d}", .{i * 7}),
        }
        if (spec.nul_at) |n| if (i == n) try out.append(alloc, 0);
        try out.append(alloc, if (spec.nul_sep and i % 3 == 0) 0 else '\n');
    }
    try out.appendSlice(alloc, "final line without newline needle");
    return out.toOwnedSlice(alloc);
}

const EvLog = struct {
    alloc: std.mem.Allocator,
    out: std.ArrayList(u8) = .empty,
    stop_after: ?usize = null,
    pause_after: ?usize = null,
    skip_after: ?usize = null,
    skip_delta: u64 = 0,
    ignore_bytes_read: bool = false,
    seen: usize = 0,

    fn deinit(self: *EvLog) void {
        self.out.deinit(self.alloc);
    }

    pub fn event(self: *EvLog, ev: Event) FlowAction {
        self.record(ev) catch @panic("EvLog out of memory");
        switch (ev) {
            .match => |le| {
                self.seen += 1;
                if (self.stop_after) |n| if (self.seen == n) return .stop;
                if (self.pause_after) |n| if (self.seen == n) return .pause;
                if (self.skip_after) |n| if (self.seen == n) return .{ .skip_to = le.absolute_offset + self.skip_delta };
            },
            else => {},
        }
        return .cont;
    }

    fn record(self: *EvLog, ev: Event) !void {
        const a = self.alloc;
        switch (ev) {
            .begin => |b| try self.out.print(a, "B {s}\n", .{b.source_id}),
            .match, .context => |le| {
                try self.out.print(a, "{s} {d} {d} {d} {any} {?d} {?d} {any} {d} {d} {s} |", .{
                    if (ev == .match) "M" else "C",
                    le.absolute_offset,
                    le.raw_offset,
                    le.line_number,
                    le.line_number_known,
                    le.column,
                    le.u16_column,
                    le.truncated,
                    le.line_len,
                    le.window_start,
                    @tagName(le.binary_status),
                });
                try self.out.appendSlice(a, le.bytes);
                try self.out.append(a, '|');
                try self.out.appendSlice(a, le.text);
                try self.out.append(a, '|');
                if (le.replaced) |r| try self.out.appendSlice(a, r);
                for (le.matches) |sp| {
                    try self.out.print(a, " [{d},{d},{?d},{d},{d},{s}]", .{ sp.start, sp.end, sp.pattern_id, sp.u16_start, sp.u16_end, sp.replacement orelse "-" });
                }
                try self.out.append(a, '\n');
            },
            .end => |e| {
                try self.out.print(a, "E {s} {s} {d} {d} {any} {?d} {?d} {s} {s}", .{
                    @tagName(e.outcome),
                    @tagName(e.limit_hit),
                    e.matched_lines,
                    e.matches,
                    e.partial,
                    e.resume_at,
                    e.binary_offset,
                    @tagName(e.binary_status),
                    if (e.soft_error) |se| @tagName(se) else "-",
                });
                if (!self.ignore_bytes_read) try self.out.print(a, " read={d}", .{e.bytes_read});
                try self.out.append(a, '\n');
            },
            .summary => |s| {
                try self.out.print(a, "S {d} {d} {d} {d} {d}", .{ s.matched_lines, s.matches, s.bytes_searched, s.bytes_printed, s.sources_failed });
                if (!self.ignore_bytes_read) try self.out.print(a, " raw={d}", .{s.bytes_read_raw});
                try self.out.append(a, '\n');
            },
            else => try self.out.print(a, "X {s}\n", .{@tagName(ev)}),
        }
    }
};

fn expectSameResult(want: Result, got: Result, check_read: bool) !void {
    try testing.expectEqual(want.outcome, got.outcome);
    try testing.expectEqual(want.paused, got.paused);
    try testing.expectEqual(want.matched_lines, got.matched_lines);
    try testing.expectEqual(want.matches, got.matches);
    try testing.expectEqual(want.limit_hit, got.limit_hit);
    try testing.expectEqual(want.partial, got.partial);
    try testing.expectEqual(want.resume_at, got.resume_at);
    try testing.expectEqual(want.nul_offset, got.nul_offset);
    try testing.expectEqual(want.scanned_all, got.scanned_all);
    try testing.expectEqual(want.output_bytes, got.output_bytes);
    try testing.expectEqual(want.bytes_searched, got.bytes_searched);
    try testing.expectEqual(want.soft_error, got.soft_error);
    try testing.expectEqual(want.resume_state.results_out, got.resume_state.results_out);
    try testing.expectEqual(want.resume_state.limit_count, got.resume_state.limit_count);
    try testing.expectEqual(want.resume_state.line_number, got.resume_state.line_number);
    if (check_read) try testing.expectEqual(want.bytes_read, got.bytes_read);
}

const Case = struct {
    cfg: SearchConfig = .{},
    stop_after: ?usize = null,
    pause_after: ?usize = null,
    skip_after: ?usize = null,
    skip_delta: u64 = 0,
};

const slice_cases = [_]Case{
    .{},
    .{ .cfg = .{ .max_count = 5 } },
    .{ .cfg = .{ .max_results = 7 } },
    .{ .cfg = .{ .exists = true } },
    .{ .cfg = .{ .invert = true } },
    .{ .cfg = .{ .invert = true, .max_count = 9 } },
    .{ .cfg = .{ .whole_word = true } },
    .{ .cfg = .{ .max_output_bytes = 700 } },
    .{ .cfg = .{ .byte_range = .{ .start = 1000, .end = 20000 }, .range_align_lines = true } },
    .{ .cfg = .{ .byte_range = .{ .start = 1001, .end = 19999 } } },
    .{ .cfg = .{ .line_number_mode = .unknown } },
    .{ .cfg = .{ .replacement = "<$0>" } },
    .{ .cfg = .{ .max_line_len = 64 } },
    .{ .cfg = .{ .contains = &.{"a"} } },
    .{ .cfg = .{ .max_queued_event_bytes = 120 } },
    .{ .cfg = .{ .max_source_bytes = 15000 } },
    .{ .cfg = .{ .match_mode = .leftmost_first } },
    .{ .stop_after = 3 },
    .{ .pause_after = 4 },
    .{ .skip_after = 2, .skip_delta = 5000 },
    .{ .skip_after = 1, .skip_delta = 37 },
};

const slice_opts = [_]par.ParallelOptions{
    .{ .workers = 4, .chunk_size = 37, .min_parallel_bytes = 0 },
    .{ .workers = 3, .chunk_size = 300, .min_parallel_bytes = 0 },
    .{ .workers = 4, .chunk_size = 2048, .min_parallel_bytes = 0, .max_buffered_bytes = 700 },
    .{ .workers = 2, .chunk_size = 1000, .min_parallel_bytes = 0, .max_inflight = 2 },
};

fn runSliceCase(hay: []const u8, matcher: anytype, case: Case, opts: par.ParallelOptions) !void {
    const alloc = testing.allocator;
    var seq = EvLog{ .alloc = alloc, .stop_after = case.stop_after, .pause_after = case.pause_after, .skip_after = case.skip_after, .skip_delta = case.skip_delta };
    defer seq.deinit();
    var got = EvLog{ .alloc = alloc, .stop_after = case.stop_after, .pause_after = case.pause_after, .skip_after = case.skip_after, .skip_delta = case.skip_delta };
    defer got.deinit();

    const seq_res = searcher.searchSourceSlice(EvLog, &seq, "src", hay, matcher, case.cfg);
    const par_res = par.searchSourceSliceParallel(EvLog, alloc, testing.io, &got, "src", hay, matcher, case.cfg, opts);
    try testing.expectEqualStrings(seq.out.items, got.out.items);
    if (seq_res) |want| {
        try expectSameResult(want, try par_res, true);
    } else |err| {
        try testing.expectError(err, par_res);
    }
}

fn runAllSliceCases(hay: []const u8, matcher: anytype) !void {
    for (slice_opts) |opts| {
        for (slice_cases) |case| try runSliceCase(hay, matcher, case, opts);
    }
}

test "parallel_source: service slice parity across matchers, limits, flow actions, and chunk geometry" {
    const alloc = testing.allocator;
    const hay = try buildCorpus(alloc, .{});
    defer alloc.free(hay);

    var lit = try finder_mod.Finder.init("needle", .{});
    try runAllSliceCases(hay, &lit);

    var lit_ci = try finder_mod.Finder.init("needle", .{ .case = .insensitive });
    try runAllSliceCases(hay, &lit_ci);

    var many = try multi_mod.Multi.init(alloc, &.{ "bar", "baz", "needle" }, .{});
    defer many.deinit();
    try runAllSliceCases(hay, &many);

    var re = try regex_mod.Regex.init(alloc, "ba[rz][0-9]+|\\bneedle\\b", .{});
    defer re.deinit();
    try runAllSliceCases(hay, &re);

    var anchored = try regex_mod.Regex.init(alloc, "^ERROR|needle$", .{});
    defer anchored.deinit();
    try runAllSliceCases(hay, matcher_mod.AnyMatcher.init(regex_mod.Regex, &anchored));
}

test "parallel_source: binary NUL quit/none and NUL-delimited records match sequential" {
    const alloc = testing.allocator;
    const bin = try buildCorpus(alloc, .{ .nul_at = 500 });
    defer alloc.free(bin);
    const recs = try buildCorpus(alloc, .{ .nul_sep = true });
    defer alloc.free(recs);

    var lit = try finder_mod.Finder.init("needle", .{});
    var re = try regex_mod.Regex.init(alloc, "ba[rz][0-9]+", .{});
    defer re.deinit();

    const bin_cases = [_]Case{
        .{},
        .{ .cfg = .{ .binary = .none } },
        .{ .cfg = .{ .max_count = 3 } },
        .{ .cfg = .{ .invert = true } },
        .{ .cfg = .{ .max_output_bytes = 900 } },
    };
    for (slice_opts) |opts| {
        for (bin_cases) |case| {
            try runSliceCase(bin, &lit, case, opts);
            try runSliceCase(bin, &re, case, opts);
        }
        try runSliceCase(recs, &lit, .{ .cfg = .{ .null_data = true } }, opts);
        try runSliceCase(recs, &re, .{ .cfg = .{ .null_data = true, .max_count = 11 } }, opts);
    }
}

test "parallel_source: count-only parity with the sequential counting path" {
    const alloc = testing.allocator;
    const hay = try buildCorpus(alloc, .{});
    defer alloc.free(hay);
    const bin = try buildCorpus(alloc, .{ .nul_at = 400 });
    defer alloc.free(bin);
    var lit = try finder_mod.Finder.init("needle", .{});
    var re = try regex_mod.Regex.init(alloc, "ba[rz][0-9]+|needle", .{});
    defer re.deinit();

    const CountSink = struct {};
    const cfgs = [_]SearchConfig{
        .{},
        .{ .max_count = 5 },
        .{ .max_results = 3 },
        .{ .exists = true },
        .{ .invert = true },
        .{ .max_output_bytes = 500 },
        .{ .whole_word = true, .line_number_mode = .unknown },
    };
    for (slice_opts) |opts| {
        for (cfgs) |cfg| {
            for ([_][]const u8{ hay, bin }) |input| {
                var cs = CountSink{};
                const want = try searcher.searchSlice(CountSink, &cs, input, "", &lit, cfg);
                try expectSameResult(want, try par.countSliceParallel(alloc, testing.io, input, &lit, cfg, opts), true);
                const want_re = try searcher.searchSlice(CountSink, &cs, input, "", &re, cfg);
                try expectSameResult(want_re, try par.countSliceParallel(alloc, testing.io, input, &re, cfg, opts), true);
            }
        }
    }
}

test "parallel_source: RandomAccess parity with searchSourceRange and countParallelAt" {
    const alloc = testing.allocator;
    const hay = try buildCorpus(alloc, .{});
    defer alloc.free(hay);
    const bin = try buildCorpus(alloc, .{ .nul_at = 600 });
    defer alloc.free(bin);
    var lit = try finder_mod.Finder.init("needle", .{});
    var re = try regex_mod.Regex.init(alloc, "ba[rz][0-9]+|\\bneedle\\b", .{});
    defer re.deinit();

    const ra_cases = [_]Case{
        .{},
        .{ .cfg = .{ .max_count = 6 } },
        .{ .cfg = .{ .max_results = 4 } },
        .{ .cfg = .{ .byte_range = .{ .start = 1000, .end = 20000 }, .range_align_lines = true } },
        .{ .cfg = .{ .max_line_len = 64 } },
        .{ .pause_after = 5 },
    };
    const ra_opts = [_]par.ParallelOptions{
        .{ .workers = 4, .chunk_size = 97, .min_parallel_bytes = 0 },
        .{ .workers = 3, .chunk_size = 1500, .min_parallel_bytes = 0, .max_buffered_bytes = 900 },
    };
    for ([_][]const u8{ hay, bin }) |input| {
        const ra = probe_mod.RandomAccess.fromSlice(&input);
        for (ra_opts) |opts| {
            for (ra_cases) |case| {
                inline for (.{ &lit, &re }) |m| {
                    var seq = EvLog{ .alloc = alloc, .pause_after = case.pause_after, .ignore_bytes_read = true };
                    defer seq.deinit();
                    var got = EvLog{ .alloc = alloc, .pause_after = case.pause_after, .ignore_bytes_read = true };
                    defer got.deinit();
                    const want = try searcher.searchSourceRange(EvLog, alloc, &seq, ra, case.cfg.byte_range orelse .{}, "src", m, case.cfg);
                    const res = try par.searchSourceParallelAt(EvLog, alloc, testing.io, &got, ra, "src", m, case.cfg, opts);
                    try testing.expectEqualStrings(seq.out.items, got.out.items);
                    try testing.expectEqual(want.matched_lines, res.matched_lines);
                    try testing.expectEqual(want.matches, res.matches);
                    try testing.expectEqual(want.outcome, res.outcome);
                    try testing.expectEqual(want.limit_hit, res.limit_hit);
                    try testing.expectEqual(want.resume_at, res.resume_at);
                    try testing.expectEqual(want.nul_offset, res.nul_offset);
                    try testing.expectEqual(want.paused, res.paused);
                }
            }
            const CountSink = struct {};
            var cs = CountSink{};
            const want_count = try searcher.searchSlice(CountSink, &cs, input, "", &lit, .{});
            const got_count = try par.countParallelAt(alloc, testing.io, ra, &lit, .{}, opts);
            try testing.expectEqual(want_count.matched_lines, got_count.matched_lines);
            try testing.expectEqual(want_count.matches, got_count.matches);
            try testing.expectEqual(want_count.nul_offset, got_count.nul_offset);
            try testing.expectEqual(want_count.outcome, got_count.outcome);
        }
    }
}

test "parallel_source: unsupported configurations fall back to the sequential engine transparently" {
    const alloc = testing.allocator;
    const hay = try buildCorpus(alloc, .{});
    defer alloc.free(hay);
    var lit = try finder_mod.Finder.init("needle", .{});
    var anchored = try regex_mod.Regex.init(alloc, "\\A(INFO|WARN)", .{});
    defer anchored.deinit();
    var tail_anchored = try regex_mod.Regex.init(alloc, "needle\\Z", .{});
    defer tail_anchored.deinit();

    const opts = par.ParallelOptions{ .workers = 4, .chunk_size = 200, .min_parallel_bytes = 0 };
    try runSliceCase(hay, &lit, .{ .cfg = .{ .context = 2 } }, opts);
    try runSliceCase(hay, &lit, .{ .cfg = .{ .before = 1, .after = 3 } }, opts);
    try runSliceCase(hay, &lit, .{ .cfg = .{ .passthru = true, .max_output_bytes = 4000 } }, opts);
    try runSliceCase(hay, &lit, .{ .cfg = .{ .binary = .report } }, opts);
    try runSliceCase(hay, &lit, .{ .cfg = .{ .encoding = .latin1 } }, opts);
    try runSliceCase(hay, &anchored, .{}, opts);
    try runSliceCase(hay, &tail_anchored, .{}, opts);
    // Inputs below `min_parallel_bytes` and single-worker requests stay sequential.
    try runSliceCase(hay, &lit, .{}, .{ .workers = 1 });
    try runSliceCase(hay, &lit, .{}, .{ .workers = 4 });

    const bom = try std.mem.concat(alloc, u8, &.{ "\xef\xbb\xbf", hay });
    defer alloc.free(bom);
    try runSliceCase(bom, &lit, .{}, opts);
}
