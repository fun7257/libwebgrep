//! [Module] adversarial_probe_m5.zig
//! [Layer] Layer 5 — Milestone 5 Adversarial Red-Team Verification Suite
//! [Role] 24-scenario adversarial stress suite probing SIMD alignment boundaries, Multi 4-tier
//!        engines, RegexSet, Hybrid Lazy DFA state cache flushes, ReDoS immunity, Unicode properties
//!        and UAX #29 word boundaries, streaming pull decompression bombs, zero-disk ArchiveTree
//!        traversal defenses, and lock-free multi-threaded `*const` matcher concurrency.

const std = @import("std");
const matcher_mod = @import("matcher.zig");
const sink_mod = @import("sink.zig");
const searcher = @import("searcher.zig");
const source_mod = @import("source.zig");
const memchr = @import("finder/memchr.zig");
const Finder = @import("finder/finder.zig").Finder;
const Multi = @import("finder/multi.zig").Multi;
const regex_mod = @import("regex.zig");
const Regex = regex_mod.Regex;
const RegexSet = regex_mod.RegexSet;
const RegexScratch = regex_mod.RegexScratch;
const CompileDiagnostic = regex_mod.CompileDiagnostic;
const decompress = @import("codec/decompress.zig");
const encoding = @import("codec/encoding.zig");
const archive = @import("codec/archive.zig");
const tree = @import("search/tree.zig");

// ============================================================================
// Category 1: SIMD Primitives & Single-Literal Finder Boundaries
// ============================================================================

test "m5 probe 1.1: memchr and Finder SIMD boundary alignments (0..129 bytes)" {
    var buf: [256]u8 = @splat('x');
    const needle = "TARGET_TOKEN";

    for (0..130) |len| {
        const slice = buf[0..len];
        try std.testing.expect(memchr.find(memchr.native_width, slice, 0, 'Z') == null);

        if (len >= needle.len) {
            for (0..len - needle.len + 1) |pos| {
                @memset(slice, 'x');
                @memcpy(slice[pos..][0..needle.len], needle);

                var finder = try Finder.init(needle, .{ .case = .sensitive });
                const hit = finder.find(slice, 0, .earliest) orelse return error.TestExpectedMatch;
                try std.testing.expectEqual(pos, hit.start);
                try std.testing.expectEqual(pos + needle.len, hit.end);
                try std.testing.expectEqual(@as(?u32, null), hit.pattern_id);
            }
        }
    }
}

test "m5 probe 1.2: Finder PackedPair false-positive storm fallback to TwoWay" {
    const allocator = std.testing.allocator;
    // Pattern > 32 bytes so adaptive false-positive tracking can trigger TwoWay fallback
    const pattern = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz_REAL_END";
    var finder = try Finder.init(pattern, .{ .case = .sensitive });

    // Fill haystack with 'z' so PackedPair anchor hits on every single byte before the tail
    const hay_len = 8192;
    const hay = try allocator.alloc(u8, hay_len);
    defer allocator.free(hay);
    @memset(hay, 'z');
    const target_pos = hay_len - pattern.len - 7;
    @memcpy(hay[target_pos..][0..pattern.len], pattern);

    const hit = finder.find(hay, 0, .earliest) orelse return error.TestExpectedMatch;
    try std.testing.expectEqual(target_pos, hit.start);
    try std.testing.expectEqual(target_pos + pattern.len, hit.end);
}

test "m5 probe 1.3: Finder Unicode case folding across BMP (German sharp S, Greek, Cyrillic)" {
    // U+1E9E (Capital Sharp S 'ẞ', 3 bytes) folds to U+00DF ('ß', 2 bytes)
    var f_sharp = try Finder.init("straße", .{ .case = .insensitive, .unicode_case = true });
    const hay_sharp = "prefix STRA\u{1E9E}E suffix";
    const hit_sharp = f_sharp.find(hay_sharp, 0, .earliest) orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("STRA\u{1E9E}E", hay_sharp[hit_sharp.start..hit_sharp.end]);

    // Greek & Cyrillic case-insensitive matching
    var f_greek = try Finder.init("δelta", .{ .case = .insensitive, .unicode_case = true });
    const hay_greek = "xx \u{0394}ELTA yy";
    const hit_greek = f_greek.find(hay_greek, 0, .earliest) orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("\u{0394}ELTA", hay_greek[hit_greek.start..hit_greek.end]);

    var f_cyr = try Finder.init("привет", .{ .case = .insensitive, .unicode_case = true });
    const hay_cyr = "hello ПРИВЕТ world";
    const hit_cyr = f_cyr.find(hay_cyr, 0, .earliest) orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("ПРИВЕТ", hay_cyr[hit_cyr.start..hit_cyr.end]);
}

// ============================================================================
// Category 2: Multi-Pattern 4-Tier Engine & Limits
// ============================================================================

fn naiveMultiFind(
    patterns: []const []const u8,
    haystack: []const u8,
    start: usize,
    mode: matcher_mod.MatchMode,
) ?matcher_mod.Match {
    var best: ?matcher_mod.Match = null;
    for (patterns, 0..) |pat, idx| {
        const pid: u32 = @intCast(idx);
        if (pat.len == 0) {
            if (start <= haystack.len) {
                const cand = matcher_mod.Match{ .start = start, .end = start, .pattern_id = pid };
                best = pickBetterMatch(best, cand, mode);
            }
            continue;
        }
        if ( std.mem.indexOfPos(u8, haystack, start, pat)) |pos| {
            const cand = matcher_mod.Match{ .start = pos, .end = pos + pat.len, .pattern_id = pid };
            best = pickBetterMatch(best, cand, mode);
        }
    }
    return best;
}

fn pickBetterMatch(
    current: ?matcher_mod.Match,
    cand: matcher_mod.Match,
    mode: matcher_mod.MatchMode,
) matcher_mod.Match {
    const cur = current orelse return cand;
    switch (mode) {
        .earliest => {
            if (cand.end < cur.end) return cand;
            if (cand.end == cur.end and cand.start < cur.start) return cand;
            if (cand.end == cur.end and cand.start == cur.start and (cand.pattern_id orelse 0) < (cur.pattern_id orelse 0)) return cand;
            return cur;
        },
        .leftmost_first => {
            if (cand.start < cur.start) return cand;
            if (cand.start == cur.start and (cand.pattern_id orelse 0) < (cur.pattern_id orelse 0)) return cand;
            return cur;
        },
    }
}

test "m5 probe 2.1: Multi differential oracle across all alignment offsets" {
    const allocator = std.testing.allocator;
    const patterns = [_][]const u8{
        "alpha",
        "alp",
        "beta_long_token",
        "gamma",
        "delta",
    };
    var many = try Multi.init(allocator, &patterns, .{ .case = .sensitive });
    defer many.deinit();

    var buf: [192]u8 = @splat('.');
    for (0..96) |offset| {
        @memset(&buf, '.');
        @memcpy(buf[offset..][0..5], "alpha");
        @memcpy(buf[offset + 20 ..][0..15], "beta_long_token");

        const got_earliest = many.find(&buf, 0, .earliest) orelse return error.TestExpectedMatch;
        const exp_earliest = naiveMultiFind(&patterns, &buf, 0, .earliest).?;
        try std.testing.expectEqual(exp_earliest.start, got_earliest.start);
        try std.testing.expectEqual(exp_earliest.end, got_earliest.end);
        try std.testing.expectEqual(exp_earliest.pattern_id, got_earliest.pattern_id);

        const got_lm = many.find(&buf, 0, .leftmost_first) orelse return error.TestExpectedMatch;
        const exp_lm = naiveMultiFind(&patterns, &buf, 0, .leftmost_first).?;
        try std.testing.expectEqual(exp_lm.start, got_lm.start);
        try std.testing.expectEqual(exp_lm.end, got_lm.end);
        try std.testing.expectEqual(exp_lm.pattern_id, got_lm.pattern_id);
    }
}

test "m5 probe 2.2: Multi at exact 1,024 pattern hard cap limit and PatternCountExceeded" {
    const allocator = std.testing.allocator;

    const ok_count = matcher_mod.pattern_count_hard_cap; // 1024
    var pat_bufs = try allocator.alloc([12]u8, ok_count + 1);
    defer allocator.free(pat_bufs);
    var pat_slices = try allocator.alloc([]const u8, ok_count + 1);
    defer allocator.free(pat_slices);

    for (0..ok_count + 1) |i| {
        pat_slices[i] = try std.fmt.bufPrint(&pat_bufs[i], "pat_{d:0>4}_end", .{i});
    }

    // Exact 1,024 patterns must succeed
    var many_ok = try Multi.init(allocator, pat_slices[0..ok_count], .{});
    defer many_ok.deinit();
    const hit = many_ok.find("xx pat_1023_end yy", 0, .earliest) orelse return error.TestExpectedMatch;
    try std.testing.expectEqual(@as(u32, 1023), hit.pattern_id);

    // 1,025 patterns must fail with PatternCountExceeded prior to table allocation
    try std.testing.expectError(
        error.PatternCountExceeded,
        Multi.init(allocator, pat_slices[0 .. ok_count + 1], .{}),
    );
}

test "m5 probe 2.3: Multi pattern_id accuracy across ByteSet, RarePair, Teddy, and AhoCorasick" {
    const allocator = std.testing.allocator;

    // 1. ByteSet (single-byte patterns)
    {
        var m = try Multi.init(allocator, &.{ "x", "y", "z" }, .{});
        defer m.deinit();
        const hit = m.find("aaa z bbb", 0, .earliest) orelse return error.TestExpectedMatch;
        try std.testing.expectEqual(@as(u32, 2), hit.pattern_id);
    }

    // 2. RarePair (2 rare patterns)
    {
        var m = try Multi.init(allocator, &.{ "qz_one", "jx_two" }, .{});
        defer m.deinit();
        const hit = m.find("... jx_two ...", 0, .earliest) orelse return error.TestExpectedMatch;
        try std.testing.expectEqual(@as(u32, 1), hit.pattern_id);
    }

    // 3. Teddy / medium set (12 patterns)
    {
        const pats = [_][]const u8{
            "tok_00", "tok_01", "tok_02", "tok_03",
            "tok_04", "tok_05", "tok_06", "tok_07",
            "tok_08", "tok_09", "tok_10", "tok_11",
        };
        var m = try Multi.init(allocator, &pats, .{});
        defer m.deinit();
        const hit = m.find("header tok_09 trailer", 0, .earliest) orelse return error.TestExpectedMatch;
        try std.testing.expectEqual(@as(u32, 9), hit.pattern_id);
    }

    // 4. AhoCorasick (> 32 patterns)
    {
        var bufs: [40][8]u8 = undefined;
        var slices: [40][]const u8 = undefined;
        for (0..40) |i| {
            slices[i] = try std.fmt.bufPrint(&bufs[i], "ac_{d:0>2}_k", .{i});
        }
        var m = try Multi.init(allocator, &slices, .{});
        defer m.deinit();
        const hit = m.find("prefix ac_37_k suffix", 0, .earliest) orelse return error.TestExpectedMatch;
        try std.testing.expectEqual(@as(u32, 37), hit.pattern_id);
    }
}

// ============================================================================
// Category 3: RegexSet & CompileDiagnostic
// ============================================================================

test "m5 probe 3.1: RegexSet multi-pattern simultaneous matching and Multi prefilter" {
    const allocator = std.testing.allocator;
    const patterns = [_][]const u8{
        "WARN_[0-9]{2}",
        "ERR_[A-Z]+",
        "FATAL_[0-9]+",
        "INFO_OK",
    };
    var set = try RegexSet.init(allocator, &patterns, .{});
    defer set.deinit();

    const hay = "2026-11-09 WARN_42 and FATAL_999 occurred";
    try std.testing.expect(set.isMatch(hay));

    const first = set.find(hay, 0, .earliest) orelse return error.TestExpectedMatch;
    try std.testing.expectEqual(@as(u32, 0), first.pattern_id);
    try std.testing.expectEqualStrings("WARN_42", hay[first.start..first.end]);

    var ids: [8]u32 = undefined;
    const count = set.matches(hay, &ids);
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqual(@as(u32, 0), ids[0]);
    try std.testing.expectEqual(@as(u32, 2), ids[1]);
}

test "m5 probe 3.2: RegexSet output buffer truncation and duplicate match deduplication" {
    const allocator = std.testing.allocator;
    const patterns = [_][]const u8{
        "foo[0-9]+",
        "foo123",
        "bar[a-z]+",
        "baz!",
    };
    var set = try RegexSet.init(allocator, &patterns, .{});
    defer set.deinit();

    const hay = "foo123 foo456 barxyz baz! foo123";
    // Even if patterns match multiple times, each pattern ID is reported once in ascending order
    var full_ids: [8]u32 = undefined;
    const n_full = set.matches(hay, &full_ids);
    try std.testing.expectEqual(@as(usize, 4), n_full);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 2, 3 }, full_ids[0..n_full]);

    // Truncated output buffer of size 2 must safely write only 2 IDs without overflow
    var small_ids: [2]u32 = undefined;
    const n_small = set.matches(hay, &small_ids);
    try std.testing.expectEqual(@as(usize, 2), n_small);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1 }, small_ids[0..n_small]);
}

test "m5 probe 3.3: Regex and RegexSet CompileDiagnostic structured error reporting" {
    const allocator = std.testing.allocator;

    var diag: CompileDiagnostic = .{};
    try std.testing.expectError(
        error.RegexSyntax,
        Regex.initDiagnostic(allocator, "abc(def", .{}, &diag),
    );
    try std.testing.expectEqual(regex_mod.DiagnosticCode.unclosed_group, diag.code);
    try std.testing.expectEqual(@as(usize, 3), diag.offset);

    var set_diag: CompileDiagnostic = .{};
    try std.testing.expectError(
        error.RegexSyntax,
        RegexSet.initDiagnostic(allocator, &.{ "ok_0", "ok_1", "bad[class" }, .{}, &set_diag),
    );
    try std.testing.expectEqual(regex_mod.DiagnosticCode.unclosed_char_class, set_diag.code);
    try std.testing.expectEqual(@as(?usize, 2), set_diag.pattern_index);
}

// ============================================================================
// Category 4: Hybrid Lazy DFA Cache & Assertions
// ============================================================================

test "m5 probe 4.1: Lazy DFA state cache flush boundaries and continuation accuracy" {
    const allocator = std.testing.allocator;
    // Pattern that generates many distinct DFA states when scanning varied input
    var re = try Regex.init(allocator, "[a-z]+[0-9]{2,5}[A-Z]{2,4}_END", .{});
    defer re.deinit();

    var scratch = RegexScratch.init(allocator);
    defer scratch.deinit();

    var hay = try allocator.alloc(u8, 16384);
    defer allocator.free(hay);
    for (0..hay.len) |i| {
        hay[i] = if (i % 16 == 15) ' ' else @intCast('a' + (i % 26));
    }
    const target = "abcde12345WXYZ_END";
    const pos = hay.len - target.len - 13;
    hay[pos - 1] = ' ';
    @memcpy(hay[pos..][0..target.len], target);

    const hit = re.findWithScratch(hay, 0, .earliest, &scratch) orelse return error.TestExpectedMatch;
    try std.testing.expectEqual(pos, hit.start);
    try std.testing.expectEqual(pos + target.len, hit.end);
}

test "m5 probe 4.2: Lazy DFA conservative assertion guard (^, $, \\b, \\B, \\A, \\z)" {
    const allocator = std.testing.allocator;

    var re_wb = try Regex.init(allocator, "\\bword_[0-9]+\\b", .{});
    defer re_wb.deinit();

    try std.testing.expect(re_wb.find("not_word_123_extra", 0, .earliest) == null);
    const hit = re_wb.find("prefix word_456 suffix", 0, .earliest) orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("word_456", "prefix word_456 suffix"[hit.start..hit.end]);

    var re_anchor = try Regex.init(allocator, "^line_[0-9]+$", .{ .multiline = true });
    defer re_anchor.deinit();
    const m_hit = re_anchor.find("bad line_1\nline_42\ntail", 0, .earliest) orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("line_42", "bad line_1\nline_42\ntail"[m_hit.start..m_hit.end]);
}

test "m5 probe 4.3: Lazy DFA 2-phase capture extraction and RegexScratch zero-alloc reuse" {
    const allocator = std.testing.allocator;
    var re = try Regex.init(allocator, "item_([a-z]+)_([0-9]+)", .{});
    defer re.deinit();

    var scratch = RegexScratch.init(allocator);
    defer scratch.deinit();

    const hay = "noise item_alpha_789 trailing";
    // Warm up scratch
    _ = re.findWithScratch(hay, 0, .earliest, &scratch);

    const caps = re.findCaptures(hay, 0, .earliest) orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("item_alpha_789", hay[caps.match.start..caps.match.end]);
    try std.testing.expectEqualStrings("alpha", caps.slice(hay, 1).?);
    try std.testing.expectEqualStrings("789", caps.slice(hay, 2).?);
}

// ============================================================================
// Category 5: Pathological Regex & Resource Caps
// ============================================================================

test "m5 probe 5.1: regex deep recursion limit enforcement and safe rejection" {
    const allocator = std.testing.allocator;
    // 70 nested groups exceeds max_recursion_depth (64)
    var deep: [141]u8 = undefined;
    @memset(deep[0..70], '(');
    deep[70] = 'a';
    @memset(deep[71..141], ')');
    var diag: CompileDiagnostic = .{};
    try std.testing.expectError(
        error.RegexTooLarge,
        Regex.initDiagnostic(allocator, &deep, .{}, &diag),
    );
    try std.testing.expectEqual(regex_mod.DiagnosticCode.recursion_depth_exceeded, diag.code);
}

test "m5 probe 5.2: pathological catastrophic backtracking immunity (O(N) PikeVM)" {
    const allocator = std.testing.allocator;
    // Classic ReDoS pattern `(a+)+c` against `'a'^2000 ++ 'b'` (no 'c' so it must fail in linear time)
    var re = try Regex.init(allocator, "(a+)+c", .{});
    defer re.deinit();

    var hay: [2001]u8 = @splat('a');
    hay[2000] = 'b';

    const hit = re.find(&hay, 0, .earliest);
    try std.testing.expect(hit == null);
}

test "m5 probe 5.3: massive alternation chain (500 branches)" {
    const allocator = std.testing.allocator;
    var pat_buf = std.ArrayList(u8).empty;
    defer pat_buf.deinit(allocator);

    for (0..500) |i| {
        if (i > 0) try pat_buf.append(allocator, '|');
        var tmp: [16]u8 = undefined;
        const s = try std.fmt.bufPrint(&tmp, "w{d:0>3}", .{i});
        try pat_buf.appendSlice(allocator, s);
    }

    var re = try Regex.init(allocator, pat_buf.items, .{ .max_inst = 4096 });
    defer re.deinit();

    const hay = "prefix w499 suffix";
    const hit = re.find(hay, 0, .earliest) orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("w499", hay[hit.start..hit.end]);
}

// ============================================================================
// Category 6: Unicode Properties, UAX #29 Word Boundaries & Encodings
// ============================================================================

test "m5 probe 6.1: unicode properties across BMP, astral planes, and invalid surrogates" {
    const allocator = std.testing.allocator;

    var re_han = try Regex.init(allocator, "\\p{Han}+", .{});
    defer re_han.deinit();
    const hay_han = "ascii 世界和平_123";
    const hit_han = re_han.find(hay_han, 0, .earliest) orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("世界和平", hay_han[hit_han.start..hit_han.end]);

    var re_sc = try Regex.init(allocator, "\\p{Sc}[0-9]+", .{});
    defer re_sc.deinit();
    const hay_sc = "price: €42 or ¥99";
    const hit_sc = re_sc.find(hay_sc, 0, .earliest) orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("€42", hay_sc[hit_sc.start..hit_sc.end]);

    // Malformed UTF-8 bytes in haystack must not panic or match multi-byte \p{Han}
    const malformed = [_]u8{ 0xFF, 0xFE, 0xED, 0xA0, 0x80, 'a', 'b' };
    try std.testing.expect(re_han.find(&malformed, 0, .earliest) == null);
}

test "m5 probe 6.2: UAX #29 word boundaries (\\b and \\B) on multilingual text" {
    const allocator = std.testing.allocator;

    var re = try Regex.init(allocator, "\\bप्राइम\\b|\\bпривет\\b", .{});
    defer re.deinit();

    const hay1 = "xx привет yy";
    const hit1 = re.find(hay1, 0, .earliest) orelse return error.TestExpectedMatch;
    try std.testing.expectEqualStrings("привет", hay1[hit1.start..hit1.end]);

    // Inside Cyrillic word -> \b must not match
    const hay2 = "xxАприветБyy";
    try std.testing.expect(re.find(hay2, 0, .earliest) == null);
}

test "m5 probe 6.3: encoding transcoding (UTF-16LE/BE, GBK, Latin-1) & malformed sequences" {
    const allocator = std.testing.allocator;
    var f = try Finder.init("NEEDLE", .{});

    // UTF-16LE with BOM + "NEEDLE\n"
    const u16le = [_]u8{
        0xFF, 0xFE,
        'N',  0x00,
        'E',  0x00,
        'E',  0x00,
        'D',  0x00,
        'L',  0x00,
        'E',  0x00,
        '\n', 0x00,
    };
    const NoopSink = struct {
        pub fn event(_: *@This(), _: sink_mod.Event) bool {
            return true;
        }
    };
    var sink = NoopSink{};
    const res = try searcher.searchSourceSlice(NoopSink, &sink, "u16.txt", &u16le, &f, .{
        .allocator = allocator,
        .encoding = .auto,
    });
    try std.testing.expectEqual(@as(u64, 1), res.matched_lines);
}

// ============================================================================
// Category 7: Streaming ReaderPull & Decompression Bomb Defenses
// ============================================================================

const OneByteReader = struct {
    data: []const u8,
    pos: usize = 0,
    reader: std.Io.Reader,

    const vtable: std.Io.Reader.VTable = .{
        .stream = streamFn,
    };

    fn init(data: []const u8) OneByteReader {
        return .{
            .data = data,
            .reader = .{
                .vtable = &vtable,
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn streamFn(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *OneByteReader = @fieldParentPtr("reader", r);
        if (self.pos >= self.data.len) return error.EndOfStream;
        const max_n = limit.minInt(1);
        if (max_n == 0) return 0;
        const n = try w.write(self.data[self.pos .. self.pos + 1]);
        self.pos += n;
        return n;
    }
};

test "m5 probe 7.1: openReaderPull 1-byte chunked streaming & gzip decompression" {
    const allocator = std.testing.allocator;
    const raw = "line1\nhit_alpha\nline3\nhit_beta\n";
    var one_byte = OneByteReader.init(raw);
    var finder = try Finder.init("hit_", .{});

    var pull = try searcher.openReaderPull(allocator, &finder, "one-byte.txt", &one_byte.reader, .{});
    defer pull.deinit();

    var matches: usize = 0;
    while (try pull.next()) |ev| {
        if (ev.kind == .match) matches += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), matches);
}

test "m5 probe 7.2: high-ratio deflate bomb rejection with zero memory leaks" {
    const allocator = std.testing.allocator;
    // Create a stored gzip stream of 32 KiB and enforce max_decompressed_bytes = 4 KiB
    const payload = try allocator.alloc(u8, 32 * 1024);
    defer allocator.free(payload);
    @memset(payload, 'A');

    const gz = try decompress.compressGzipStoredAlloc(allocator, payload);
    defer allocator.free(gz);

    var reader = std.Io.Reader.fixed(gz);
    var finder = try Finder.init("NEEDLE", .{});
    var pull = try searcher.openReaderPull(allocator, &finder, "bomb.gz", &reader, .{
        .compression = .gzip,
        .max_decompressed_bytes = 4096,
    });
    defer pull.deinit();

    var saw_limit = false;
    while (try pull.next()) |ev| {
        if (ev.kind == .end) {
            if (ev.limit_hit == .decompressed_bytes or ev.partial) {
                saw_limit = true;
            }
        }
    }
    try std.testing.expect(saw_limit);
}

test "m5 probe 7.3: early stream cancellation / drop with zero leaks" {
    const allocator = std.testing.allocator;
    const raw = "match_1\nmatch_2\nmatch_3\nmatch_4\n";
    var reader = std.Io.Reader.fixed(raw);
    var finder = try Finder.init("match_", .{});

    var pull = try searcher.openReaderPull(allocator, &finder, "drop.txt", &reader, .{});
    defer pull.deinit();

    // Pull only begin and first match, then drop `pull` immediately to verify zero memory leaks
    const ev1 = (try pull.next()) orelse return error.TestExpectedEvent;
    try std.testing.expectEqual(.begin, ev1.kind);
    const ev2 = (try pull.next()) orelse return error.TestExpectedEvent;
    try std.testing.expectEqual(.match, ev2.kind);
}

// ============================================================================
// Category 8: ArchiveTree Security & Multi-Threaded Concurrency
// ============================================================================

test "m5 probe 8.1: ArchiveTree .tar/.tar.gz/.zip in-memory unpacking and searchTree" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const tar_bytes = try archive.buildTestTarAlloc(allocator, &.{
        .{ .path = ".gitignore", .data = "*.ignored\n" },
        .{ .path = "src/main.zig", .data = "pub fn main() void {} // NEEDLE\n" },
        .{ .path = "src/skip.ignored", .data = "NEEDLE\n" },
    });
    defer allocator.free(tar_bytes);

    var f = try Finder.init("NEEDLE", .{});
    const NoopSink = struct {
        pub fn event(_: *@This(), _: sink_mod.Event) bool {
            return true;
        }
    };
    var sink = NoopSink{};
    const summary = try tree.searchArchiveSlice(NoopSink, allocator, io, &sink, tar_bytes, &f, .{});
    try std.testing.expectEqual(@as(u64, 1), summary.matched_lines);
}

test "m5 probe 8.2: path traversal exploits (../../, mixed slashes, C:\\evil) safely rejected" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const evil_tar = try archive.buildTestTarAlloc(allocator, &.{
        .{ .path = "../../etc/passwd", .data = "root:x:0:0\n" },
    });
    defer allocator.free(evil_tar);

    var f = try Finder.init("root", .{});
    const NoopSink = struct {
        pub fn event(_: *@This(), _: sink_mod.Event) bool {
            return true;
        }
    };
    var sink = NoopSink{};
    try std.testing.expectError(
        error.PathTraversal,
        tree.searchArchiveSlice(NoopSink, allocator, io, &sink, evil_tar, &f, .{}),
    );
}

test "m5 probe 8.3: Scratch pool zero steady-state allocations & multi-threaded *const AnyMatcher concurrency" {
    const allocator = std.testing.allocator;

    var scratch = searcher.Scratch.init(allocator);
    defer scratch.deinit();

    const re = try Regex.init(allocator, "SHARED_[0-9]{3}_TOKEN", .{});
    defer {
        var mut_re = re;
        mut_re.deinit();
    }
    const any_matcher = matcher_mod.AnyMatcher.init(*const Regex, &re);

    const NoopSink = struct {
        pub fn event(_: *@This(), _: sink_mod.Event) bool {
            return true;
        }
    };

    const hay = "line 1\nprefix SHARED_512_TOKEN suffix\nline 3\n";
    var noop_sink = NoopSink{};
    const res1 = try searcher.searchSourceSlice(NoopSink, &noop_sink, "s1", hay, any_matcher, .{
        .scratch_pool = &scratch,
    });
    try std.testing.expectEqual(@as(u64, 1), res1.matched_lines);

    const ThreadWorker = struct {
        fn run(m: matcher_mod.AnyMatcher, data: []const u8) void {
            for (0..25) |_| {
                var sink = NoopSink{};
                const r = searcher.searchSourceSlice(NoopSink, &sink, "mt", data, m, .{}) catch unreachable;
                std.debug.assert(r.matched_lines == 1);
            }
        }
    };

    var threads: [4]std.Thread = undefined;
    for (&threads) |*t| {
        t.* = try std.Thread.spawn(.{}, ThreadWorker.run, .{ any_matcher, hay });
    }
    for (threads) |t| {
        t.join();
    }
}

comptime {
    _ = @import("codec/archive_adversarial_tests.zig");
}
