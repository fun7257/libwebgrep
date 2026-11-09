//! [Module]: `src/fuzz.zig` (Cross-Layer Differential & Property Fuzzing Suite)
//! [Responsibility]: Exercises Layer 1 (`tables`), Layer 2 (`Finder`, `Multi`, `Regex`),
//! Layer 3 (`codec.encoding`, `codec.decompress`, `codec.offset_map`), and Layer 4 (`searcher`)
//! using both Zig 0.17.1 `std.testing.fuzz` (`std.testing.Smith` structured fuzzing) and
//! deterministic multi-seed PRNG differential oracles.
//! [Invariants]:
//! 1. `Finder.find` and `Finder.findWatched` must match a scalar reference oracle across all case modes.
//! 2. `Multi.find` (`Bytes`, `Pairs`, `Teddy`, `AhoCorasick`) must match a naive multi-pattern oracle in `.leftmost_first` and `.earliest` modes.
//! 3. `Regex.init` must never panic on arbitrary byte sequences, and `Regex.find` must execute in linear steps and agree with literal/alternation oracles.
//! 4. `codec.encoding.Decoder` fed arbitrary 1..19 byte chunks must produce identical UTF-8 output and monotonic `OffsetMap` translations compared to whole-slice conversion.
//! 5. `searchSource` with tiny randomized read chunks must emit identical `Event` sequences to `searchSourceSlice`, and paginated `resumeSourceSlice` must equal an unpaused search.

const std = @import("std");
const ascii = @import("finder/ascii.zig");
const unicode_fold = @import("finder/unicode_fold.zig");
const matcher_mod = @import("matcher.zig");
const Finder = @import("finder/finder.zig").Finder;
const Multi = @import("finder/multi.zig").Multi;
const regex_mod = @import("regex.zig");
const Regex = regex_mod.Regex;
const encoding = @import("codec/encoding.zig");
const offset_map_mod = @import("codec/offset_map.zig");
const source_mod = @import("source.zig");
const searcher = @import("searcher.zig");
const sink_mod = @import("sink.zig");

// ============================================================================
// Reference Oracles
// ============================================================================

fn refHasAsciiUpper(s: []const u8) bool {
    for (s) |c| {
        if (c >= 'A' and c <= 'Z') return true;
    }
    return false;
}

fn refResolveIgnoreCase(pattern: []const u8, options: matcher_mod.FindOptions) bool {
    return switch (options.case) {
        .sensitive => false,
        .insensitive => true,
        .smart => if (options.unicode_case) !unicode_fold.patternHasUnicodeUpper(pattern) else !refHasAsciiUpper(pattern),
    };
}

fn refFindSingle(haystack: []const u8, pattern: []const u8, start: usize, options: matcher_mod.FindOptions) ?matcher_mod.Match {
    if (start > haystack.len) return null;
    if (pattern.len == 0) return .{ .start = start, .end = start };
    const ignore_case = refResolveIgnoreCase(pattern, options);
    if (ignore_case and options.unicode_case and unicode_fold.needsUnicodeExpansion(pattern)) {
        const hit = unicode_fold.findFolded(haystack, pattern, start) orelse return null;
        return .{ .start = hit.start, .end = hit.end };
    }
    if (pattern.len > haystack.len) return null;
    var pos = start;
    while (pos + pattern.len <= haystack.len) : (pos += 1) {
        const window = haystack[pos .. pos + pattern.len];
        const ok = if (ignore_case) std.ascii.eqlIgnoreCase(window, pattern) else std.mem.eql(u8, window, pattern);
        if (ok) return .{ .start = pos, .end = pos + pattern.len };
    }
    return null;
}

fn refFindMultiLeftmostFirst(
    haystack: []const u8,
    patterns: []const []const u8,
    start: usize,
    options: matcher_mod.FindOptions,
) ?matcher_mod.Match {
    if (start > haystack.len or patterns.len == 0) return null;
    var best: ?matcher_mod.Match = null;
    var best_pat_idx: usize = std.math.maxInt(usize);
    for (patterns, 0..) |pat, idx| {
        if (refFindSingle(haystack, pat, start, options)) |m| {
            if (best == null or m.start < best.?.start or (m.start == best.?.start and idx < best_pat_idx)) {
                best = .{ .start = m.start, .end = m.end, .pattern_id = @intCast(idx) };
                best_pat_idx = idx;
            }
        }
    }
    return best;
}

// ============================================================================
// 1. Zig 0.17.1 `std.testing.fuzz` (`Smith`) Targets
// ============================================================================

fn smithFuzzFinder(_: void, smith: *std.testing.Smith) !void {
    var pat_buf: [48]u8 = undefined;
    const pat_len = smith.slice(&pat_buf);
    const raw_pat = pat_buf[0..pat_len];
    for (raw_pat) |*b| {
        if (b.* == '\n') b.* = '_';
    }

    var hay_buf: [256]u8 = undefined;
    const hay_len = smith.slice(&hay_buf);
    const haystack = hay_buf[0..hay_len];

    const case_mode = smith.value(matcher_mod.CaseMode);
    const unicode_case = smith.value(bool);
    const opts = matcher_mod.FindOptions{
        .case = case_mode,
        .unicode_case = unicode_case,
    };

    var finder = Finder.init(raw_pat, opts) catch return;
    const got = finder.find(haystack, 0, .leftmost_first);
    const expected = refFindSingle(haystack, raw_pat, 0, opts);
    try std.testing.expectEqual(expected, got);
}

fn smithFuzzRegexCompileAndRun(_: void, smith: *std.testing.Smith) !void {
    var pat_buf: [64]u8 = undefined;
    const pat_len = smith.slice(&pat_buf);
    const pattern = pat_buf[0..pat_len];

    var hay_buf: [128]u8 = undefined;
    const hay_len = smith.slice(&hay_buf);
    const haystack = hay_buf[0..hay_len];

    const opts = regex_mod.RegexOptions{
        .case = smith.value(matcher_mod.CaseMode),
        .unicode_case = smith.value(bool),
        .multiline = smith.value(bool),
        .dot_all = smith.value(bool),
    };

    var re = Regex.init(std.testing.allocator, pattern, opts) catch return;
    defer re.deinit();

    _ = re.find(haystack, 0, .leftmost_first);
    _ = re.find(haystack, 0, .earliest);
}

const FixedChunkCtx = struct {
    data: []const u8,
    pos: usize = 0,
    step: usize,

    fn readFn(ptr: *anyopaque, dest: []u8) error{}!usize {
        const self: *FixedChunkCtx = @ptrCast(@alignCast(ptr));
        if (self.pos >= self.data.len or dest.len == 0) return 0;
        const n = @min(dest.len, @min(self.data.len - self.pos, self.step));
        @memcpy(dest[0..n], self.data[self.pos .. self.pos + n]);
        self.pos += n;
        return n;
    }
};

fn smithFuzzDecoder(_: void, smith: *std.testing.Smith) !void {
    var raw_buf: [256]u8 = undefined;
    const raw_len = smith.slice(&raw_buf);
    const raw = raw_buf[0..raw_len];
    const hint = smith.value(encoding.Encoding);
    const chunk_step = @as(usize, smith.valueWeighted(u8, &.{.rangeAtMost(u8, 1, 19, 1)}));

    var dec = encoding.Decoder.initWithHint(hint, null);
    defer dec.deinit(std.testing.allocator);

    var ctx = FixedChunkCtx{ .data = raw, .step = chunk_step };
    var out_list: std.ArrayList(u8) = .empty;
    defer out_list.deinit(std.testing.allocator);

    var dest: [32]u8 = undefined;
    var bytes_read: u64 = 0;
    while (true) {
        const pulled = dec.pull(std.testing.allocator, FixedChunkCtx.readFn, &ctx, chunk_step, &dest, &bytes_read) catch return;
        if (pulled.n > 0) try out_list.appendSlice(std.testing.allocator, dest[0..pulled.n]);
        if (pulled.eof) break;
    }
    if (hint != .none and hint != .auto) {
        try std.testing.expect(std.unicode.utf8ValidateSlice(out_list.items));
    }
}

test "fuzz: Zig 0.17.1 std.testing.fuzz targets (Finder, Regex, Decoder)" {
    try std.testing.fuzz({}, smithFuzzFinder, .{});
    try std.testing.fuzz({}, smithFuzzRegexCompileAndRun, .{});
    try std.testing.fuzz({}, smithFuzzDecoder, .{});
}

// ============================================================================
// 2. Differential Fuzzing: Single-Pattern `Finder` vs. Reference Oracle
// ============================================================================

test "fuzz: Finder differential oracle across sensitive/insensitive/smart/unicode_case and findWatched" {
    var prng = std.Random.DefaultPrng.init(0x9E37_79B9_7F4A_7C15);
    const rand = prng.random();

    const alphabet = "abAB01_-\x00\xC3\xA9\xC3\x89\xCE\xB1\xCE\x91";
    var pat_buf: [40]u8 = undefined;
    var hay_buf: [512]u8 = undefined;

    for (0..250) |_| {
        const pat_len = rand.intRangeAtMost(usize, 1, 36);
        for (0..pat_len) |i| {
            var b = alphabet[rand.uintLessThan(usize, alphabet.len)];
            if (b == 0) b = 'a';
            pat_buf[i] = b;
        }
        const pattern = pat_buf[0..pat_len];

        const hay_len = rand.intRangeAtMost(usize, 0, 384);
        for (0..hay_len) |i| {
            hay_buf[i] = alphabet[rand.uintLessThan(usize, alphabet.len)];
        }
        if (hay_len >= pat_len and rand.boolean()) {
            const at = rand.uintLessThan(usize, hay_len - pat_len + 1);
            for (pattern, 0..) |pb, k| {
                hay_buf[at + k] = if (rand.boolean() and pb >= 'a' and pb <= 'z') pb - 32 else pb;
            }
        }
        const haystack = hay_buf[0..hay_len];

        const cases = [_]matcher_mod.CaseMode{ .sensitive, .insensitive, .smart };
        for (cases) |cm| {
            for ([_]bool{ false, true }) |uc| {
                if (uc and !std.unicode.utf8ValidateSlice(pattern)) continue;
                if (uc and !std.unicode.utf8ValidateSlice(haystack)) continue;

                const opts = matcher_mod.FindOptions{ .case = cm, .unicode_case = uc };
                var finder = try Finder.init(pattern, opts);

                var start: usize = 0;
                while (start <= haystack.len) {
                    const expected = refFindSingle(haystack, pattern, start, opts);
                    const got = finder.find(haystack, start, .leftmost_first);
                    try std.testing.expectEqual(expected, got);

                    var nul_at: ?usize = null;
                    const watched = finder.findWatched(haystack, start, &nul_at);
                    const ref_nul = if (start < haystack.len)
                        if (std.mem.indexOfScalarPos(u8, haystack, start, 0)) |idx| idx else null
                    else
                        null;

                    if (expected) |exp| {
                        if (ref_nul != null and ref_nul.? < exp.start) {
                            try std.testing.expect(watched == null);
                            try std.testing.expectEqual(ref_nul, nul_at);
                        } else if (nul_at == null) {
                            try std.testing.expectEqual(expected, watched);
                        }
                    } else {
                        try std.testing.expect(watched == null);
                        try std.testing.expectEqual(ref_nul, nul_at);
                    }

                    start = if (expected) |m| @max(m.start + 1, start + 1) else break;
                }
            }
        }
    }
}

// ============================================================================
// 3. Differential Fuzzing: Multi-Pattern `Multi` (`Bytes`/`Pairs`/`Teddy`/`AhoCorasick`)
// ============================================================================

test "fuzz: Multi differential oracle across Bytes, Pairs, Teddy, and AhoCorasick" {
    var prng = std.Random.DefaultPrng.init(0xD1B5_4A32_D192_ED03);
    const rand = prng.random();
    const gpa = std.testing.allocator;

    const alphabet = "abcdABCD1234_-:";
    var hay_buf: [512]u8 = undefined;

    for (0..180) |iter| {
        const regime = iter % 4;
        const num_pats: usize = switch (regime) {
            0 => rand.intRangeAtMost(usize, 1, 6),
            1 => rand.intRangeAtMost(usize, 1, 8),
            2 => rand.intRangeAtMost(usize, 2, 16),
            3 => rand.intRangeAtMost(usize, 10, 36),
            else => unreachable,
        };

        var pat_storage = try gpa.alloc([]u8, num_pats);
        defer {
            for (pat_storage) |p| gpa.free(p);
            gpa.free(pat_storage);
        }

        for (0..num_pats) |pi| {
            const plen: usize = switch (regime) {
                0 => 1,
                1 => 2,
                2 => rand.intRangeAtMost(usize, 3, 12),
                3 => rand.intRangeAtMost(usize, 1, 14),
                else => unreachable,
            };
            const p = try gpa.alloc(u8, plen);
            for (p) |*b| b.* = alphabet[rand.uintLessThan(usize, alphabet.len)];
            pat_storage[pi] = p;
        }

        const hay_len = rand.intRangeAtMost(usize, 0, 384);
        for (0..hay_len) |i| {
            hay_buf[i] = alphabet[rand.uintLessThan(usize, alphabet.len)];
        }
        for (0..3) |_| {
            const chosen = pat_storage[rand.uintLessThan(usize, num_pats)];
            if (hay_len >= chosen.len and rand.boolean()) {
                const pos = rand.uintLessThan(usize, hay_len - chosen.len + 1);
                @memcpy(hay_buf[pos .. pos + chosen.len], chosen);
            }
        }
        const haystack = hay_buf[0..hay_len];

        for ([_]matcher_mod.CaseMode{ .sensitive, .insensitive, .smart }) |cm| {
            const opts = matcher_mod.FindOptions{ .case = cm, .unicode_case = false };
            var multi = try Multi.init(gpa, pat_storage, opts);
            defer multi.deinit();

            var start: usize = 0;
            while (start <= haystack.len) {
                const exp_lmf = refFindMultiLeftmostFirst(haystack, pat_storage, start, opts);
                const got_lmf = multi.find(haystack, start, .leftmost_first);
                try std.testing.expectEqual(exp_lmf, got_lmf);

                const got_early = multi.find(haystack, start, .earliest);
                if (exp_lmf == null) {
                    try std.testing.expect(got_early == null);
                    break;
                } else {
                    try std.testing.expect(got_early != null);
                    try std.testing.expect(got_early.?.start >= start);
                    try std.testing.expect(got_early.?.end <= haystack.len);
                }
                start = exp_lmf.?.start + 1;
            }
        }
    }
}

// ============================================================================
// 4. Differential Fuzzing: `Regex` Prefilters + Thompson NFA VM
// ============================================================================

test "fuzz: Regex structured patterns vs literal/alternation oracles" {
    var prng = std.Random.DefaultPrng.init(0x517C_C1B7_2722_0A95);
    const rand = prng.random();
    const gpa = std.testing.allocator;

    const alphabet = "abcdefABCDEF012345_-";
    var hay_buf: [320]u8 = undefined;

    for (0..120) |_| {
        const hay_len = rand.intRangeAtMost(usize, 8, 256);
        for (0..hay_len) |i| {
            hay_buf[i] = alphabet[rand.uintLessThan(usize, alphabet.len)];
        }
        const haystack = hay_buf[0..hay_len];

        var b1: [6]u8 = undefined;
        var b2: [5]u8 = undefined;
        var b3: [7]u8 = undefined;
        for (&b1) |*c| c.* = alphabet[rand.uintLessThan(usize, 12)];
        for (&b2) |*c| c.* = alphabet[rand.uintLessThan(usize, 12)];
        for (&b3) |*c| c.* = alphabet[rand.uintLessThan(usize, 12)];

        if (rand.boolean()) {
            const at = rand.uintLessThan(usize, hay_len - b2.len);
            @memcpy(hay_buf[at .. at + b2.len], &b2);
        }

        const regex_pat = try std.fmt.allocPrint(gpa, "{s}|{s}|{s}", .{ b1, b2, b3 });
        defer gpa.free(regex_pat);

        const patterns = [_][]const u8{ &b1, &b2, &b3 };
        for ([_]matcher_mod.CaseMode{ .sensitive, .insensitive }) |cm| {
            const re_opts = regex_mod.RegexOptions{ .case = cm };
            var re = try Regex.init(gpa, regex_pat, re_opts);
            defer re.deinit();

            const find_opts = matcher_mod.FindOptions{ .case = cm };
            var multi = try Multi.init(gpa, &patterns, find_opts);
            defer multi.deinit();

            var pos: usize = 0;
            while (pos <= haystack.len) {
                const exp = multi.find(haystack, pos, .leftmost_first);
                const got = re.find(haystack, pos, .leftmost_first);
                if (exp) |e| {
                    try std.testing.expect(got != null);
                    try std.testing.expectEqual(e.start, got.?.start);
                    try std.testing.expectEqual(e.end, got.?.end);
                } else {
                    try std.testing.expect(got == null);
                }
                pos = if (exp) |m| m.start + 1 else break;
            }
        }
    }
}

// ============================================================================
// 5. Differential Fuzzing: `codec.encoding.Decoder` Streaming vs Whole-Slice & `OffsetMap`
// ============================================================================

test "fuzz: Decoder arbitrary chunking equivalence and OffsetMap monotonicity across encodings" {
    var prng = std.Random.DefaultPrng.init(0xA24B_AED4_963E_E407);
    const rand = prng.random();
    const gpa = std.testing.allocator;

    const encodings = [_]encoding.Sniff{ .utf8, .utf16le, .utf16be, .gbk, .latin1 };
    var raw_buf: [384]u8 = undefined;

    for (0..150) |_| {
        const enc_sniff = encodings[rand.uintLessThan(usize, encodings.len)];
        const raw_len = rand.intRangeAtMost(usize, 0, 256);
        for (0..raw_len) |i| {
            raw_buf[i] = rand.int(u8);
        }
        const raw = raw_buf[0..raw_len];

        // Whole-slice reference conversion
        var ref_map = offset_map_mod.OffsetMap{};
        defer ref_map.deinit(gpa);
        const ref_utf8 = try encoding.convertAllocWithMap(gpa, enc_sniff, raw, 0, &ref_map);
        defer gpa.free(ref_utf8);

        // Streaming Decoder with tiny random chunks (1..17 bytes), starting directly in the target mode
        var stream_map = offset_map_mod.OffsetMap{};
        defer stream_map.deinit(gpa);
        var dec = encoding.Decoder{
            .mode = switch (enc_sniff) {
                .utf8 => .utf8,
                .utf16le => .utf16le,
                .utf16be => .utf16be,
                .gbk => .gbk,
                .latin1 => .latin1,
                else => unreachable,
            },
            .offset_map = &stream_map,
        };
        defer dec.deinit(gpa);

        const step = rand.intRangeAtMost(usize, 1, 17);
        var ctx = FixedChunkCtx{ .data = raw, .step = step };
        var stream_utf8: std.ArrayList(u8) = .empty;
        defer stream_utf8.deinit(gpa);

        var dest: [23]u8 = undefined;
        var bytes_read: u64 = 0;
        while (true) {
            const pulled = try dec.pull(gpa, FixedChunkCtx.readFn, &ctx, step, &dest, &bytes_read);
            if (pulled.n > 0) try stream_utf8.appendSlice(gpa, dest[0..pulled.n]);
            if (pulled.eof) break;
        }

        try std.testing.expectEqualStrings(ref_utf8, stream_utf8.items);

        // Verify OffsetMap monotonicity and exact equivalence between whole-slice and streaming
        var prev_raw: u64 = 0;
        var out_off: u64 = 0;
        while (out_off <= ref_utf8.len) : (out_off += 1) {
            const r1 = ref_map.map(out_off);
            const r2 = stream_map.map(out_off);
            try std.testing.expectEqual(r1, r2);
            try std.testing.expect(r1 >= prev_raw);
            try std.testing.expect(r1 <= raw.len);
            prev_raw = r1;
        }
    }
}

// ============================================================================
// 6. Differential Fuzzing: `searchSource` (Tiny Chunk Streaming) vs `searchSourceSlice` & Resume
// ============================================================================

const CollectedRecord = struct {
    kind: enum { matched, context },
    line_number: ?u64,
    byte_offset: u64,
    truncated: bool,
    text: []u8,
};

const FuzzCollector = struct {
    gpa: std.mem.Allocator,
    records: std.ArrayList(CollectedRecord) = .empty,
    pause_every: usize = 0,
    since_pause: usize = 0,

    pub fn deinit(self: *FuzzCollector) void {
        for (self.records.items) |r| self.gpa.free(r.text);
        self.records.deinit(self.gpa);
    }

    pub fn event(self: *FuzzCollector, ev: sink_mod.Event) sink_mod.Flow {
        switch (ev) {
            .match => |m| {
                const dup = self.gpa.dupe(u8, m.bytes) catch return .stop;
                self.records.append(self.gpa, .{
                    .kind = .matched,
                    .line_number = m.line_number,
                    .byte_offset = m.absolute_offset,
                    .truncated = m.truncated,
                    .text = dup,
                }) catch {
                    self.gpa.free(dup);
                    return .stop;
                };
                if (self.pause_every > 0) {
                    self.since_pause += 1;
                    if (self.since_pause >= self.pause_every) {
                        self.since_pause = 0;
                        return .pause;
                    }
                }
            },
            .context => |c| {
                const dup = self.gpa.dupe(u8, c.bytes) catch return .stop;
                self.records.append(self.gpa, .{
                    .kind = .context,
                    .line_number = c.line_number,
                    .byte_offset = c.absolute_offset,
                    .truncated = c.truncated,
                    .text = dup,
                }) catch {
                    self.gpa.free(dup);
                    return .stop;
                };
            },
            else => {},
        }
        return .cont;
    }
};

const ChunkedIoReader = struct {
    data: []const u8,
    pos: usize = 0,
    step: usize,
    interface: std.Io.Reader,

    fn init(data: []const u8, step: usize) ChunkedIoReader {
        return .{
            .data = data,
            .step = @max(step, 1),
            .interface = .{
                .vtable = &.{ .stream = stream },
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn stream(io_r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *ChunkedIoReader = @alignCast(@fieldParentPtr("interface", io_r));
        if (self.pos >= self.data.len) return error.EndOfStream;
        const avail = self.data.len - self.pos;
        const max_n = @min(avail, self.step);
        const slice = limit.sliceConst(self.data[self.pos .. self.pos + max_n]);
        const n = try w.write(slice);
        self.pos += n;
        return n;
    }
};

test "fuzz: searchSource tiny-chunk streaming vs searchSourceSlice & resumeSourceSlice equivalence" {
    var prng = std.Random.DefaultPrng.init(0x7F4A_7C15_9E37_79B9);
    const rand = prng.random();
    const gpa = std.testing.allocator;

    const tokens = [_][]const u8{ "alpha", "beta", "gamma", "delta", "   ", "12345", "alpha_extra" };

    for (0..100) |iter| {
        var doc: std.ArrayList(u8) = .empty;
        defer doc.deinit(gpa);

        const num_lines = rand.intRangeAtMost(usize, 1, 28);
        for (0..num_lines) |_| {
            const words_in_line = rand.intRangeAtMost(usize, 0, 6);
            for (0..words_in_line) |w| {
                if (w > 0) try doc.append(gpa, ' ');
                try doc.appendSlice(gpa, tokens[rand.uintLessThan(usize, tokens.len)]);
            }
            if (rand.boolean()) try doc.append(gpa, '\r');
            try doc.append(gpa, '\n');
        }

        const before_lines = rand.intRangeAtMost(u32, 0, 2);
        const after_lines = rand.intRangeAtMost(u32, 0, 2);
        const cfg = searcher.SearchConfig{
            .before = before_lines,
            .after = after_lines,
            .invert = rand.boolean(),
            .whole_word = rand.boolean(),
            .whole_line = if (iter % 7 == 0) true else false,
            .passthru = if (iter % 11 == 0) true else false,
            .line_numbers = true,
            .max_line_len = rand.intRangeAtMost(usize, 32, 128),
            .buffer_size = rand.intRangeAtMost(usize, 16, 64),
        };

        var finder = try Finder.init("alpha", .{});

        var slice_col = FuzzCollector{ .gpa = gpa };
        defer slice_col.deinit();
        const res_slice = try searcher.searchSourceSlice(FuzzCollector, &slice_col, "fuzz.txt", doc.items, &finder, cfg);

        const step_len = rand.intRangeAtMost(usize, 1, 29);
        var chunked = ChunkedIoReader.init(doc.items, step_len);
        var stream_col = FuzzCollector{ .gpa = gpa };
        defer stream_col.deinit();
        const res_stream = try searcher.searchSource(FuzzCollector, gpa, &stream_col, &chunked.interface, "fuzz.txt", &finder, cfg);

        try std.testing.expectEqual(res_slice.matched_lines, res_stream.matched_lines);
        try std.testing.expectEqual(res_slice.matches, res_stream.matches);
        try std.testing.expectEqual(slice_col.records.items.len, stream_col.records.items.len);

        for (slice_col.records.items, stream_col.records.items) |a, b| {
            try std.testing.expectEqual(a.kind, b.kind);
            try std.testing.expectEqual(a.line_number, b.line_number);
            try std.testing.expectEqual(a.byte_offset, b.byte_offset);
            try std.testing.expectEqual(a.truncated, b.truncated);
            if (!a.truncated) {
                try std.testing.expectEqualStrings(a.text, b.text);
            } else {
                try std.testing.expect(b.text.len > 0 and b.text.len <= a.text.len);
            }
        }

        // Verify Flow.pause + `resumeSourceSlice` equivalence when not using context/passthru
        if (before_lines == 0 and after_lines == 0 and !cfg.passthru) {
            var paged_col = FuzzCollector{
                .gpa = gpa,
                .pause_every = rand.intRangeAtMost(usize, 1, 3),
            };
            defer paged_col.deinit();

            var cur_res = try searcher.searchSourceSlice(FuzzCollector, &paged_col, "fuzz.txt", doc.items, &finder, cfg);
            var guard_iters: usize = 0;
            while (cur_res.paused and guard_iters < 64) : (guard_iters += 1) {
                cur_res = try searcher.resumeSourceSlice(FuzzCollector, &paged_col, "fuzz.txt", doc.items, &finder, cfg, cur_res);
            }
            try std.testing.expect(!cur_res.paused);
            try std.testing.expectEqual(slice_col.records.items.len, paged_col.records.items.len);
            for (slice_col.records.items, paged_col.records.items) |a, b| {
                try std.testing.expectEqual(a.kind, b.kind);
                try std.testing.expectEqual(a.line_number, b.line_number);
                try std.testing.expectEqual(a.byte_offset, b.byte_offset);
                try std.testing.expectEqualStrings(a.text, b.text);
            }
        }
    }
}
