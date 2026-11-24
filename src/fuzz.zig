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
const builtin = @import("builtin");
const build_options = @import("build_options");
const aho = @import("finder/aho.zig");
const ascii = @import("finder/ascii.zig");
const cpuid = @import("io/cpuid.zig");
const frequency = @import("finder/frequency.zig");
const memchr = @import("finder/memchr.zig");
const packed_pair = @import("finder/packed_pair.zig");
const unicode_fold = @import("finder/unicode_fold.zig");
const matcher_mod = @import("matcher.zig");
const Finder = @import("finder/finder.zig").Finder;
const Multi = @import("finder/multi.zig").Multi;
const regex_mod = @import("regex.zig");
const Regex = regex_mod.Regex;
const RegexSet = regex_mod.RegexSet;
const encoding = @import("codec/encoding.zig");
const offset_map_mod = @import("codec/offset_map.zig");
const source_mod = @import("source.zig");
const searcher = @import("searcher.zig");
const search_format = @import("search/format.zig");
const search_state = @import("search/state.zig");
const sink_mod = @import("sink.zig");
const walker = @import("walk/walker.zig");

const teddy_on = build_options.teddy != .off;
const teddy_mod = if (teddy_on) @import("finder/teddy.zig") else struct {};

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
                        if (std.mem.findScalarPos(u8, haystack, start, 0)) |idx| idx else null
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

// ============================================================================
// 7. Differential Fuzz 1: `UnanchoredDfa` + `SetUnanchoredDfa` / `LazySetDfa` vs PikeVM Oracle
// ============================================================================

fn refFindMultiEarliest(
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
            const better = if (best) |b|
                m.end < b.end or (m.end == b.end and (m.start < b.start or (m.start == b.start and idx < best_pat_idx)))
            else
                true;
            if (better) {
                best = .{ .start = m.start, .end = m.end, .pattern_id = @intCast(idx) };
                best_pat_idx = idx;
            }
        }
    }
    return best;
}

fn checkWatchedMatchContract(
    expected: ?matcher_mod.Match,
    got: ?matcher_mod.Match,
    nul_at: ?usize,
    ref_nul: ?usize,
) !void {
    if (expected) |exp| {
        if (ref_nul != null and ref_nul.? < exp.end) {
            try std.testing.expect(got == null);
            try std.testing.expectEqual(ref_nul, nul_at);
        } else if (ref_nul == null) {
            try std.testing.expectEqual(expected, got);
            try std.testing.expect(nul_at == null);
        } else {
            if (got != null) {
                try std.testing.expectEqual(expected, got);
                try std.testing.expect(nul_at == null);
            } else {
                try std.testing.expectEqual(ref_nul, nul_at);
            }
        }
    } else {
        try std.testing.expect(got == null);
        try std.testing.expectEqual(ref_nul, nul_at);
    }
}

fn checkWatchedEndContract(
    expected_end: ?usize,
    got_end: ?usize,
    nul_at: ?usize,
    ref_nul: ?usize,
) !void {
    if (expected_end) |exp_end| {
        if (ref_nul != null and ref_nul.? < exp_end) {
            try std.testing.expect(got_end == null);
            try std.testing.expectEqual(ref_nul, nul_at);
        } else if (ref_nul == null) {
            try std.testing.expectEqual(expected_end, got_end);
            try std.testing.expect(nul_at == null);
        } else {
            if (got_end != null) {
                try std.testing.expectEqual(expected_end, got_end);
                try std.testing.expect(nul_at == null);
            } else {
                try std.testing.expectEqual(ref_nul, nul_at);
            }
        }
    } else {
        try std.testing.expect(got_end == null);
        try std.testing.expectEqual(ref_nul, nul_at);
    }
}

fn appendRandomUtf8Haystack(
    gpa: std.mem.Allocator,
    rand: std.Random,
    out: *std.ArrayList(u8),
    token_count: usize,
    extra_tokens: []const []const u8,
) !void {
    const base_tokens = [_][]const u8{
        "a",      "b",      "c",      "x",      "y",      "z",
        "A",      "Z",      "0",      "1",      "9",      "_",
        "-",      " ",      "\t",     "\n",     "!",      ".",
        "é",      "α",      "Б",      "\u{00A0}", "\u{3000}", "中",
        "文",     "测",     "试",     "ab_12",  "xyz_901", "ab 123",
        "Wab_12", "你ab_12", "ab_12你", "XY-45",  "ERR_42", "WARN_ok",
        "p_MID1_77", "9:MID2:ab", "PRE3_88", "ab_mix_12",
    };
    out.clearRetainingCapacity();
    for (0..token_count) |_| {
        if (extra_tokens.len > 0 and rand.uintLessThan(u8, 6) == 0) {
            try out.appendSlice(gpa, extra_tokens[rand.uintLessThan(usize, extra_tokens.len)]);
        } else {
            try out.appendSlice(gpa, base_tokens[rand.uintLessThan(usize, base_tokens.len)]);
        }
    }
}

fn oracleRegexSetFind(
    oracles: []const Regex,
    haystack: []const u8,
    start: usize,
    mode: matcher_mod.MatchMode,
) ?matcher_mod.Match {
    var best: ?matcher_mod.Match = null;
    for (oracles, 0..) |*re, pid| {
        if (re.find(haystack, start, mode)) |m| {
            const cand = matcher_mod.Match{
                .start = m.start,
                .end = m.end,
                .pattern_id = @intCast(pid),
            };
            const better = if (best) |b| switch (mode) {
                .earliest => cand.end < b.end or
                    (cand.end == b.end and (cand.start < b.start or (cand.start == b.start and cand.pattern_id.? < b.pattern_id.?))),
                .leftmost_first => cand.start < b.start or
                    (cand.start == b.start and cand.pattern_id.? < b.pattern_id.?),
            } else true;
            if (better) best = cand;
        }
    }
    return best;
}

fn verifyRegexVsPike(
    re_fast: *const Regex,
    re_pike: *const Regex,
    haystack: []const u8,
) !void {
    var pos: usize = 0;
    var steps: usize = 0;
    while (pos <= haystack.len and steps < 16) : (steps += 1) {
        const exp_lmf = re_pike.find(haystack, pos, .leftmost_first);
        const got_lmf = re_fast.find(haystack, pos, .leftmost_first);
        try std.testing.expectEqual(exp_lmf, got_lmf);

        const exp_ear = re_pike.find(haystack, pos, .earliest);
        const got_ear = re_fast.find(haystack, pos, .earliest);
        try std.testing.expectEqual(exp_ear, got_ear);

        const exp_end: ?usize = if (exp_ear) |m| m.end else null;
        try std.testing.expectEqual(exp_end, re_fast.findEnd(haystack, pos, .earliest));

        const ref_nul = if (pos < haystack.len) std.mem.findScalarPos(u8, haystack, pos, 0) else null;

        var nul_w: ?usize = null;
        const got_w = re_fast.findWatched(haystack, pos, &nul_w);
        try checkWatchedMatchContract(exp_ear, got_w, nul_w, ref_nul);

        var nul_ew: ?usize = null;
        const got_ew = re_fast.findEndWatched(haystack, pos, .earliest, &nul_ew);
        try checkWatchedEndContract(exp_end, got_ew, nul_ew, ref_nul);

        if (exp_ear) |m| {
            pos = @max(m.start + 1, pos + 1);
        } else {
            break;
        }
    }
}

fn verifyRegexSetVsPike(
    set_fast: *const RegexSet,
    set_pike: *const RegexSet,
    oracles: []const Regex,
    haystack: []const u8,
    max_steps: usize,
) !void {
    var pos: usize = 0;
    var steps: usize = 0;
    while (pos <= haystack.len and steps < max_steps) : (steps += 1) {
        const exp_lmf_re = oracleRegexSetFind(oracles, haystack, pos, .leftmost_first);
        const exp_lmf = set_pike.find(haystack, pos, .leftmost_first);
        const got_lmf = set_fast.find(haystack, pos, .leftmost_first);
        try std.testing.expectEqual(exp_lmf_re, exp_lmf);
        try std.testing.expectEqual(exp_lmf, got_lmf);

        const exp_ear = set_pike.find(haystack, pos, .earliest);
        const got_ear = set_fast.find(haystack, pos, .earliest);
        try std.testing.expectEqual(exp_ear, got_ear);

        const exp_end: ?usize = if (exp_ear) |m| m.end else null;
        try std.testing.expectEqual(exp_end, set_fast.findEnd(haystack, pos, .earliest));

        const ref_nul = if (pos < haystack.len) std.mem.findScalarPos(u8, haystack, pos, 0) else null;

        var nul_w: ?usize = null;
        const got_w = set_fast.findWatched(haystack, pos, &nul_w);
        try checkWatchedMatchContract(exp_ear, got_w, nul_w, ref_nul);

        var nul_ew: ?usize = null;
        const got_ew = set_fast.findEndWatched(haystack, pos, .earliest, &nul_ew);
        try checkWatchedEndContract(exp_end, got_ew, nul_ew, ref_nul);

        if (exp_ear) |m| {
            pos = @max(m.start + 1, pos + 1);
        } else {
            break;
        }
    }

    var got_ids: [16]u32 = undefined;
    const got_n = set_fast.matches(haystack, &got_ids);
    var exp_ids: [16]u32 = undefined;
    var exp_n: usize = 0;
    for (oracles, 0..) |*re, pid| {
        if (re.isMatch(haystack)) {
            exp_ids[exp_n] = @intCast(pid);
            exp_n += 1;
        }
    }
    try std.testing.expectEqualSlices(u32, exp_ids[0..exp_n], got_ids[0..got_n]);
}

test "fuzz: Differential 1 — UnanchoredDfa + SetUnanchoredDfa + LazySetDfa vs PikeVM oracle" {
    var prng = std.Random.DefaultPrng.init(0xA1B2_C3D4_E5F6_0718);
    const rand = prng.random();
    const gpa = std.testing.allocator;

    var hay: std.ArrayList(u8) = .empty;
    defer hay.deinit(gpa);
    var nul_hay: std.ArrayList(u8) = .empty;
    defer nul_hay.deinit(gpa);

    // 1. Single-regex: word-bounded interior-lit (`\b[a-z]{2,4}_[0-9]{2,3}\b`) & zero-lit `UnanchoredDfa` (`\b[a-z]{2,4}\s+[0-9]{2,3}\b`)
    const single_cases = [_]struct {
        pat: []const u8,
        opts: regex_mod.RegexOptions,
        expect_udfa: bool,
    }{
        .{ .pat = "\\b[a-z]{2,4}_[0-9]{2,3}\\b", .opts = .{ .unicode_word_boundary = true, .unicode_classes = true }, .expect_udfa = false },
        .{ .pat = "\\b[a-z]{2,4}_[0-9]{2,3}\\b", .opts = .{ .unicode_word_boundary = false, .unicode_classes = false }, .expect_udfa = false },
        .{ .pat = "\\b[a-z]{2,4}\\s+[0-9]{2,3}\\b", .opts = .{ .unicode_word_boundary = true, .unicode_classes = true }, .expect_udfa = true },
        .{ .pat = "\\b[a-z]{2,4}\\s+[0-9]{2,3}\\b", .opts = .{ .unicode_word_boundary = false, .unicode_classes = false }, .expect_udfa = true },
        .{ .pat = "\\b[a-z]{2,4}\\s+[0-9]{2,3}\\b", .opts = .{ .case = .insensitive, .unicode_word_boundary = true }, .expect_udfa = true },
    };

    for (single_cases) |sc| {
        var re_fast = try Regex.init(gpa, sc.pat, sc.opts);
        defer re_fast.deinit();
        if (sc.expect_udfa) try std.testing.expect(re_fast.unanchored_dfa != null);

        var pike_opts = sc.opts;
        pike_opts.max_dfa_states = 0;
        var re_pike = try Regex.init(gpa, sc.pat, pike_opts);
        defer re_pike.deinit();
        try std.testing.expect(re_pike.unanchored_dfa == null);
        try std.testing.expect(re_pike.precomputed_dfa == null);

        for (0..24) |_| {
            const n_toks = rand.intRangeAtMost(usize, 6, 48);
            try appendRandomUtf8Haystack(gpa, rand, &hay, n_toks, &.{ "ab_12", "cd_999", "ef 34", "gh\u{3000}567", "AB 89" });
            try verifyRegexVsPike(&re_fast, &re_pike, hay.items);

            // Inject NUL before, inside, right at end, and after a match
            if (re_pike.find(hay.items, 0, .earliest)) |m| {
                const positions = [_]usize{
                    if (m.start > 0) m.start - 1 else 0,
                    m.start + (m.end - m.start) / 2,
                    m.end,
                    @min(hay.items.len, m.end + 2),
                };
                for (positions) |ins| {
                    nul_hay.clearRetainingCapacity();
                    try nul_hay.appendSlice(gpa, hay.items[0..ins]);
                    try nul_hay.append(gpa, 0);
                    try nul_hay.appendSlice(gpa, hay.items[ins..]);
                    try verifyRegexVsPike(&re_fast, &re_pike, nul_hay.items);
                }
            } else if (hay.items.len > 0) {
                const ins = rand.uintLessThan(usize, hay.items.len + 1);
                nul_hay.clearRetainingCapacity();
                try nul_hay.appendSlice(gpa, hay.items[0..ins]);
                try nul_hay.append(gpa, 0);
                try nul_hay.appendSlice(gpa, hay.items[ins..]);
                try verifyRegexVsPike(&re_fast, &re_pike, nul_hay.items);
            }
        }
    }

    // 2. Multi-regex `RegexSet` across prefix-lit, interior-lit, zero-lit/`\b` Tier A (`SetUnanchoredDfa`), and mixed-case
    const set_cases = [_]struct {
        pats: []const []const u8,
        opts: regex_mod.RegexOptions,
        expect_set_udfa: bool,
    }{
        .{
            .pats = &.{ "ERR_[0-9]{2,3}", "WARN_[a-z]{2,4}", "OK_TAG" },
            .opts = .{},
            .expect_set_udfa = false,
        },
        .{
            .pats = &.{ "[a-z]{1,3}_MID1_[0-9]{2}", "[0-9]{1,2}:MID2:[a-z]{2}", "PRE3_[0-9]{2}" },
            .opts = .{},
            .expect_set_udfa = false,
        },
        .{
            .pats = &.{ "\\b[a-z]{2,4}\\s+[0-9]{2,3}\\b", "\\b[A-Z]{2,3}-[0-9]{2}\\b" },
            .opts = .{ .unicode_word_boundary = true, .unicode_classes = true },
            .expect_set_udfa = true,
        },
        .{
            .pats = &.{ "\\b[a-z]{2,4}\\s+[0-9]{2,3}\\b", "\\b[A-Z]{2,3}-[0-9]{2}\\b" },
            .opts = .{ .unicode_word_boundary = false, .unicode_classes = false },
            .expect_set_udfa = true,
        },
        .{
            .pats = &.{ "err_[0-9]{2}", "WARN_[a-z]{2}", "[a-z]{2}_mix_[0-9]{2}" },
            .opts = .{ .case = .smart },
            .expect_set_udfa = false,
        },
    };

    for (set_cases) |sc| {
        var set_fast = try RegexSet.init(gpa, sc.pats, sc.opts);
        defer set_fast.deinit();
        if (sc.expect_set_udfa) try std.testing.expect(set_fast.set_unanchored_dfa != null);

        var pike_opts = sc.opts;
        pike_opts.max_dfa_states = 0;
        var set_pike = try RegexSet.init(gpa, sc.pats, pike_opts);
        defer set_pike.deinit();
        if (set_pike.prefilter) |*pf| {
            pf.deinit();
            set_pike.prefilter = null;
        }
        try std.testing.expect(set_pike.set_unanchored_dfa == null);

        const oracles = try gpa.alloc(Regex, sc.pats.len);
        var built_oracles: usize = 0;
        defer {
            for (oracles[0..built_oracles]) |*r| r.deinit();
            gpa.free(oracles);
        }
        for (sc.pats, 0..) |p, idx| {
            oracles[idx] = try Regex.init(gpa, p, pike_opts);
            built_oracles += 1;
        }

        for (0..18) |_| {
            const n_toks = rand.intRangeAtMost(usize, 8, 44);
            try appendRandomUtf8Haystack(gpa, rand, &hay, n_toks, &.{ "OK_TAG", "ERR_42", "WARN_ab", "xy_MIX_99" });
            try verifyRegexSetVsPike(&set_fast, &set_pike, oracles, hay.items, 10);

            // Embedded NUL parity check
            if (hay.items.len > 0) {
                const ref_m = set_pike.find(hay.items, 0, .earliest);
                const ins = if (ref_m) |m| switch (rand.uintLessThan(u8, 3)) {
                    0 => if (m.start > 0) m.start - 1 else 0,
                    1 => m.start + (m.end - m.start) / 2,
                    else => m.end,
                } else rand.uintLessThan(usize, hay.items.len);

                nul_hay.clearRetainingCapacity();
                try nul_hay.appendSlice(gpa, hay.items[0..ins]);
                try nul_hay.append(gpa, 0);
                try nul_hay.appendSlice(gpa, hay.items[ins..]);
                try verifyRegexSetVsPike(&set_fast, &set_pike, oracles, nul_hay.items, 6);
            }
        }
    }

    // 3. Multi-regex Tier B `LazySetDfa` (>= 16 KiB haystack, `set_unanchored_dfa == null`, `has_byte_classes == true`)
    {
        const lazy_pats = [_][]const u8{
            "\\b[a-z]{2,4}\\s+[0-9]{2,3}\\b",
            "\\b[A-Z]{2,3}-[0-9]{2}\\b",
        };
        var set_lazy = try RegexSet.init(gpa, &lazy_pats, .{ .unicode_word_boundary = true });
        defer set_lazy.deinit();
        try std.testing.expect(set_lazy.has_byte_classes);
        // Drop Tier A AOT table cleanly so >= 16 KiB scans exercise Tier B `LazySetDfa` directly.
        if (set_lazy.set_unanchored_dfa) |udfa| {
            udfa.deinit(gpa);
            gpa.destroy(udfa);
            set_lazy.set_unanchored_dfa = null;
        }

        var set_lazy_pike = try RegexSet.init(gpa, &lazy_pats, .{ .unicode_word_boundary = true, .max_dfa_states = 0 });
        defer set_lazy_pike.deinit();
        try std.testing.expect(set_lazy_pike.prefilter == null and set_lazy_pike.set_unanchored_dfa == null);

        const oracles = try gpa.alloc(Regex, lazy_pats.len);
        var built: usize = 0;
        defer {
            for (oracles[0..built]) |*r| r.deinit();
            gpa.free(oracles);
        }
        for (lazy_pats, 0..) |p, idx| {
            oracles[idx] = try Regex.init(gpa, p, .{ .unicode_word_boundary = true, .max_dfa_states = 0 });
            built += 1;
        }

        var big = try gpa.alloc(u8, 17_024);
        defer gpa.free(big);
        for (0..4) |iter| {
            @memset(big, '.');
            // Sprinkle CJK + non-matches + planted match near end (> 16 KiB)
            const cjk_prefix = "前缀测试";
            @memcpy(big[100..][0..cjk_prefix.len], cjk_prefix);
            const cjk_nonmatch = "你abc 123你";
            @memcpy(big[8192..][0..cjk_nonmatch.len], cjk_nonmatch);
            const match_pos: usize = 16_500 + iter * 37;
            if (iter % 2 == 0) {
                @memcpy(big[match_pos .. match_pos + 7], "ab 123 ");
            } else {
                @memcpy(big[match_pos .. match_pos + 6], "XY-98!");
            }
            if (iter == 1) big[match_pos - 20] = 0; // NUL before match
            if (iter == 2) big[match_pos + 2] = 0; // NUL inside match
            if (iter == 3) big[match_pos + 5] = 0; // NUL right at match end

            try verifyRegexSetVsPike(&set_lazy, &set_lazy_pike, oracles, big, 4);
        }
    }
}

// ============================================================================
// 8. Differential Fuzz 2: 4-Stream ILP `AhoCorasick` + `Teddy` + `PackedPair` + `memchr.findSepOrNul`
// ============================================================================

fn refFindSepOrNul(haystack: []const u8, start: usize, sep: u8) memchr.SepOrNul {
    if (start >= haystack.len) return .{ .pos = null, .is_nul = false };
    for (haystack[start..], start..) |b, idx| {
        if (b == 0) return .{ .pos = idx, .is_nul = true };
        if (b == sep) return .{ .pos = idx, .is_nul = false };
    }
    return .{ .pos = null, .is_nul = false };
}

fn verifyTeddyEngine(
    comptime EngineType: type,
    rand: std.Random,
    gpa: std.mem.Allocator,
    pats: []const []const u8,
    ignore_case: bool,
) !void {
    const engine = EngineType.init(pats, ignore_case);
    const find_opts = matcher_mod.FindOptions{
        .case = if (ignore_case) .insensitive else .sensitive,
        .unicode_case = false,
    };

    // Synthesize ghost bytes from nibble cross-products of patterns[0..min(len,8)]
    var ghost_pool: [64]u8 = undefined;
    var ghost_len: usize = 0;
    const lim = @min(pats.len, 8);
    for (0..lim) |a| {
        for (0..lim) |b| {
            if (a == b or ghost_len >= ghost_pool.len) continue;
            const ba = pats[a][0];
            const bb = pats[b][0];
            const g: u8 = (ba & 0xF0) | (bb & 0x0F);
            if (g != 0 and g != '\n') {
                ghost_pool[ghost_len] = g;
                ghost_len += 1;
            }
        }
    }

    const SuffixVerifier = struct {
        pub fn verify(_: @This(), h: []const u8, _: usize, pat_end: usize, _: usize) teddy_mod.VerifyResult {
            if (pat_end + 3 <= h.len and std.mem.eql(u8, h[pat_end .. pat_end + 3], "!OK")) {
                return .{ .accept = pat_end + 3 };
            }
            return .reject;
        }
    };

    var hay = try gpa.alloc(u8, 640);
    defer gpa.free(hay);

    for (0..12) |iter| {
        const hay_len = rand.intRangeAtMost(usize, 40, hay.len);
        for (0..hay_len) |i| {
            if (ghost_len > 0 and rand.uintLessThan(u8, 3) == 0) {
                hay[i] = ghost_pool[rand.uintLessThan(usize, ghost_len)];
            } else {
                hay[i] = 'a' + @as(u8, @intCast(rand.uintLessThan(u8, 26)));
            }
        }
        // Plant decoys (without "!OK") and 1-2 verified matches (with "!OK")
        for (0..5) |k| {
            const chosen = pats[rand.uintLessThan(usize, pats.len)];
            if (hay_len > chosen.len + 4) {
                const at = rand.uintLessThan(usize, hay_len - chosen.len - 3);
                for (chosen, 0..) |ch, j| {
                    hay[at + j] = if (ignore_case and rand.boolean() and std.ascii.isAlphabetic(ch)) (ch ^ 32) else ch;
                }
                if (k == 4) {
                    @memcpy(hay[at + chosen.len ..][0..3], "!OK");
                } else {
                    @memcpy(hay[at + chosen.len ..][0..3], "bad");
                }
            }
        }
        if (iter % 3 == 0 and hay_len > 8) {
            hay[rand.uintLessThan(usize, hay_len)] = 0;
        }
        const slice = hay[0..hay_len];

        for ([_]usize{ 0, @min(13, hay_len), @min(31, hay_len) }) |start| {
            const ref_nul = if (start < slice.len) std.mem.findScalarPos(u8, slice, start, 0) else null;

            for ([_]matcher_mod.MatchMode{ .leftmost_first, .earliest }) |mode| {
                const exp = if (mode == .leftmost_first)
                    refFindMultiLeftmostFirst(slice, pats, start, find_opts)
                else
                    refFindMultiEarliest(slice, pats, start, find_opts);
                try std.testing.expectEqual(exp, engine.find(slice, start, mode));

                var nul_w: ?usize = null;
                const got_w = engine.findWatchingNul(slice, start, mode, &nul_w);
                try checkWatchedMatchContract(exp, got_w, nul_w, ref_nul);

                // Naive reference for `findVerified` with SuffixVerifier ("!OK")
                var exp_v: ?matcher_mod.Match = null;
                for (pats, 0..) |pat, pid| {
                    var s = start;
                    while (s <= slice.len) {
                        const hit = refFindSingle(slice, pat, s, find_opts) orelse break;
                        if (hit.end + 3 <= slice.len and std.mem.eql(u8, slice[hit.end .. hit.end + 3], "!OK")) {
                            const cand = matcher_mod.Match{ .start = hit.start, .end = hit.end + 3, .pattern_id = @intCast(pid) };
                            const better = if (exp_v) |b| switch (mode) {
                                .leftmost_first => cand.start < b.start or (cand.start == b.start and cand.pattern_id.? < b.pattern_id.?),
                                .earliest => cand.end < b.end or (cand.end == b.end and (cand.start < b.start or (cand.start == b.start and cand.pattern_id.? < b.pattern_id.?))),
                            } else true;
                            if (better) exp_v = cand;
                            break;
                        }
                        s = hit.start + 1;
                    }
                }

                const step = engine.findVerified(slice, start, mode, SuffixVerifier{});
                const got_v: ?matcher_mod.Match = switch (step) {
                    .match => |vm| .{ .start = vm.start, .end = vm.end, .pattern_id = @intCast(vm.id) },
                    .none => null,
                    .aborted => unreachable,
                };
                try std.testing.expectEqual(exp_v, got_v);

                var nul_vw: ?usize = null;
                const step_w = engine.findVerifiedWatchingNul(slice, start, mode, &nul_vw, SuffixVerifier{});
                const got_vw: ?matcher_mod.Match = switch (step_w) {
                    .match => |vm| .{ .start = vm.start, .end = vm.end, .pattern_id = @intCast(vm.id) },
                    .none => null,
                    .aborted => unreachable,
                };
                try checkWatchedMatchContract(exp_v, got_vw, nul_vw, ref_nul);
            }
        }
    }
}

test "fuzz: Differential 2 — 4-Stream ILP AhoCorasick, Teddy, PackedPair, and memchr.findSepOrNul" {
    var prng = std.Random.DefaultPrng.init(0x243F_6A88_85A3_08D3);
    const rand = prng.random();
    const gpa = std.testing.allocator;

    // 1. 4-Stream ILP AhoCorasick on 5, 64, and 400 patterns across lane boundaries (256..4096B)
    const ac_alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    const ac_counts = [_]usize{ 5, 64, 400 };
    const hay_lens = [_]usize{ 256, 513, 1024, 2049, 4096 };
    const hay_storage = try gpa.alloc(u8, 4096);
    defer gpa.free(hay_storage);

    for (ac_counts) |n_pats| {
        const pat_bufs = try gpa.alloc([16]u8, n_pats);
        defer gpa.free(pat_bufs);
        const pats = try gpa.alloc([]const u8, n_pats);
        defer gpa.free(pats);

        for (0..n_pats) |pi| {
            const plen = rand.intRangeAtMost(usize, 4, 15);
            for (0..plen) |k| {
                pat_bufs[pi][k] = ac_alphabet[rand.uintLessThan(usize, ac_alphabet.len)];
            }
            pats[pi] = pat_bufs[pi][0..plen];
        }

        for ([_]bool{ false, true }) |ignore_case| {
            var ac = try aho.build(gpa, pats, ignore_case);
            defer ac.deinit();
            const find_opts = matcher_mod.FindOptions{
                .case = if (ignore_case) .insensitive else .sensitive,
                .unicode_case = false,
            };

            for (hay_lens, 0..) |hlen, hidx| {
                const hay = hay_storage[0..hlen];
                for (hay) |*b| b.* = ac_alphabet[rand.uintLessThan(usize, ac_alphabet.len)];

                // Plant matches near 4-stream ILP lane boundaries (hlen/4, hlen/2, 3*hlen/4)
                const anchors = [_]usize{ hlen / 4 -| 3, hlen / 2 -| 2, (hlen * 3) / 4 -| 4 };
                for (anchors) |pos_a| {
                    const chosen = pats[rand.uintLessThan(usize, n_pats)];
                    if (pos_a + chosen.len <= hlen) {
                        for (chosen, 0..) |ch, j| {
                            hay[pos_a + j] = if (ignore_case and rand.boolean() and std.ascii.isAlphabetic(ch)) (ch ^ 32) else ch;
                        }
                    }
                }
                if (hidx % 2 == 1) {
                    hay[rand.uintLessThan(usize, hlen)] = 0;
                }

                for ([_]usize{ 0, @min(17, hlen) }) |start| {
                    const ref_nul = if (start < hlen) std.mem.findScalarPos(u8, hay, start, 0) else null;
                    for ([_]matcher_mod.MatchMode{ .earliest, .leftmost_first }) |mode| {
                        const exp = if (mode == .leftmost_first)
                            refFindMultiLeftmostFirst(hay, pats, start, find_opts)
                        else
                            refFindMultiEarliest(hay, pats, start, find_opts);
                        try std.testing.expectEqual(exp, ac.find(hay, start, mode));

                        var nul_w: ?usize = null;
                        const got_w = ac.findWatchingNul(hay, start, mode, &nul_w);
                        try checkWatchedMatchContract(exp, got_w, nul_w, ref_nul);
                    }
                }
            }
        }
    }

    // 2. Teddy (`find`, `findWatchingNul`, `findVerified`, `findVerifiedWatchingNul`) on 8 & 16 patterns
    if (comptime teddy_on) {
        const teddy_alpha = "abcdefghpqrstuvw01234567ABCDEFGH";
        for ([_]usize{ 8, 16 }) |n_pats| {
            var pat_bufs: [16][10]u8 = undefined;
            var pats: [16][]const u8 = undefined;
            for (0..n_pats) |pi| {
                const plen = rand.intRangeAtMost(usize, 3, 9);
                for (0..plen) |k| {
                    pat_bufs[pi][k] = teddy_alpha[rand.uintLessThan(usize, teddy_alpha.len)];
                }
                pats[pi] = pat_bufs[pi][0..plen];
            }
            for ([_]bool{ false, true }) |ic| {
                if (comptime build_options.teddy == .runtime and builtin.cpu.arch == .x86_64) {
                    try verifyTeddyEngine(teddy_mod.Ssse3Engine, rand, gpa, pats[0..n_pats], ic);
                    if (cpuid.detectX86().avx2) {
                        try verifyTeddyEngine(teddy_mod.RuntimeAvx2Engine, rand, gpa, pats[0..n_pats], ic);
                    }
                } else {
                    try verifyTeddyEngine(teddy_mod.Engine, rand, gpa, pats[0..n_pats], ic);
                }
            }
        }
    }

    // 3. PackedPair (`fold=true/false`, `watch_nul=true/false`, lengths `2..35`) across alignments & widths
    {
        const pp_alpha = "abcdABCD0123_-xyz";
        var pat_buf: [35]u8 = undefined;
        var pp_hay: [260]u8 = undefined;

        var plen: usize = 2;
        while (plen <= 35) : (plen += 1) {
            for (0..plen) |k| pat_buf[k] = pp_alpha[rand.uintLessThan(usize, pp_alpha.len)];
            const pat = pat_buf[0..plen];

            for ([_]bool{ false, true }) |fold| {
                const pp = packed_pair.PackedPair.init(pat, &frequency.default_rank, fold);
                const opts = matcher_mod.FindOptions{
                    .case = if (fold) .insensitive else .sensitive,
                    .unicode_case = false,
                };

                for (0..3) |trial| {
                    const hlen = rand.intRangeAtMost(usize, 0, pp_hay.len);
                    for (0..hlen) |i| pp_hay[i] = pp_alpha[rand.uintLessThan(usize, pp_alpha.len)];
                    if (hlen >= plen and trial != 2) {
                        const at = rand.uintLessThan(usize, hlen - plen + 1);
                        for (pat, 0..) |ch, k| {
                            pp_hay[at + k] = if (fold and rand.boolean() and std.ascii.isAlphabetic(ch)) (ch ^ 32) else ch;
                        }
                    }
                    if (trial == 1 and hlen > 0) {
                        pp_hay[rand.uintLessThan(usize, hlen)] = 0;
                    }
                    const hay = pp_hay[0..hlen];
                    const start = if (hlen > 0) rand.uintLessThan(usize, @min(hlen, 67)) else 0;
                    const exp = refFindSingle(hay, pat, start, opts);
                    const exp_start: ?usize = if (exp) |m| m.start else null;
                    const ref_nul = if (start < hlen) std.mem.findScalarPos(u8, hay, start, 0) else null;

                    inline for (.{ 16, 32, 64 }) |w| {
                        try std.testing.expectEqual(exp_start, pp.findWithWidth(w, hay, start, null));

                        var nul_w: ?usize = null;
                        const got_w = pp.findWatchingNulWithWidth(w, hay, start, null, &nul_w);
                        const got_m: ?matcher_mod.Match = if (got_w) |s| .{ .start = s, .end = s + plen } else null;
                        try checkWatchedMatchContract(exp, got_m, nul_w, ref_nul);

                        if (plen > packed_pair.owns_search_max_len) {
                            var guard = packed_pair.Guard{};
                            const g_got = pp.findWithWidth(w, hay, start, &guard);
                            if (!guard.gave_up) {
                                try std.testing.expectEqual(exp_start, g_got);
                            } else if (exp_start) |es| {
                                try std.testing.expect(guard.restart <= es);
                            }
                        }
                    }
                }
            }
        }
    }

    // 4. `memchr.findSepOrNul` across all vector alignments (widths 16/32/64) and NUL/sep positions
    {
        var buf: [195]u8 = undefined;
        const seps = [_]u8{ '\n', 0, ':' };
        for (0..180) |_| {
            const len = rand.intRangeAtMost(usize, 0, buf.len);
            @memset(buf[0..len], 'x');
            const sep = seps[rand.uintLessThan(usize, seps.len)];
            if (len > 0 and rand.boolean()) buf[rand.uintLessThan(usize, len)] = sep;
            if (len > 0 and rand.boolean()) buf[rand.uintLessThan(usize, len)] = 0;
            if (len > 1 and rand.uintLessThan(u8, 4) == 0) {
                const p = rand.uintLessThan(usize, len - 1);
                buf[p] = if (rand.boolean()) 0 else sep;
                buf[p + 1] = if (buf[p] == 0) sep else 0;
            }
            const start = if (len > 0) rand.uintLessThan(usize, @min(len + 1, 68)) else 0;
            const hay = buf[0..len];
            const exp = refFindSepOrNul(hay, start, sep);
            inline for (.{ 16, 32, 64 }) |w| {
                try std.testing.expectEqual(exp, memchr.findSepOrNul(w, hay, start, sep));
            }
        }
    }
}

// ============================================================================
// 9. Differential Fuzz 3: `scanFinderFast`, `PrefixAnyTail`, `matchedSpan`, `CompiledReplacement`
// ============================================================================

const NaiveScanResult = struct {
    outcome: sink_mod.Outcome = .complete,
    matched_lines: u64 = 0,
    nul_offset: ?u64 = null,
    out: std.ArrayList(u8) = .empty,

    fn deinit(self: *NaiveScanResult, gpa: std.mem.Allocator) void {
        self.out.deinit(gpa);
    }
};

fn refScanLinesOracle(
    gpa: std.mem.Allocator,
    haystack: []const u8,
    pattern: []const u8,
    find_opts: matcher_mod.FindOptions,
    policy: searcher.BinaryPolicy,
    line_numbers: bool,
) !NaiveScanResult {
    var res = NaiveScanResult{};
    errdefer res.deinit(gpa);

    var pos: usize = 0;
    var line_no: u64 = 1;
    while (pos < haystack.len) : (line_no += 1) {
        const nl_opt = std.mem.findScalarPos(u8, haystack, pos, '\n');
        const raw_end = if (nl_opt) |nl| nl + 1 else haystack.len;
        var content_end = if (nl_opt) |nl| nl else haystack.len;
        if (content_end > pos and haystack[content_end - 1] == '\r') {
            content_end -= 1;
        }

        if (policy == .quit) {
            if (std.mem.findScalarPos(u8, haystack[0..raw_end], pos, 0)) |nul_at| {
                res.outcome = .binary_quit;
                res.nul_offset = @intCast(nul_at);
                return res;
            }
        }

        const line_bytes = haystack[pos..content_end];
        if (refFindSingle(line_bytes, pattern, 0, find_opts) != null) {
            res.matched_lines += 1;
            if (line_numbers) {
                var num_buf: [32]u8 = undefined;
                const ns = std.fmt.bufPrint(&num_buf, "{d}:", .{line_no}) catch unreachable;
                try res.out.appendSlice(gpa, ns);
            }
            try res.out.appendSlice(gpa, line_bytes);
            try res.out.append(gpa, '\n');
        }
        pos = raw_end;
    }
    return res;
}

fn refExpandReplacement(
    gpa: std.mem.Allocator,
    re: *const Regex,
    line: []const u8,
    template: []const u8,
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);

    var pos: usize = 0;
    while (pos <= line.len) {
        const caps = re.findCaptures(line, pos, .leftmost_first) orelse {
            try out.appendSlice(gpa, line[pos..]);
            break;
        };
        try out.appendSlice(gpa, line[pos..caps.match.start]);

        var i: usize = 0;
        while (i < template.len) {
            if (template[i] == '$' and i + 1 < template.len) {
                const next = template[i + 1];
                if (next == '$') {
                    try out.append(gpa, '$');
                    i += 2;
                    continue;
                } else if (next == '0' or next == '&') {
                    try out.appendSlice(gpa, line[caps.match.start..caps.match.end]);
                    i += 2;
                    continue;
                } else if (next >= '1' and next <= '9') {
                    if (caps.slice(line, next - '0')) |s| try out.appendSlice(gpa, s);
                    i += 2;
                    continue;
                } else if (next == '{') {
                    if (std.mem.findScalarPos(u8, template, i + 2, '}')) |close| {
                        const inner = template[i + 2 .. close];
                        if (inner.len > 0) {
                            if (std.fmt.parseInt(usize, inner, 10)) |g| {
                                if (caps.slice(line, g)) |s| try out.appendSlice(gpa, s);
                                i = close + 1;
                                continue;
                            } else |_| {
                                if (caps.byName(re, inner)) |m| {
                                    try out.appendSlice(gpa, line[m.start..m.end]);
                                }
                                i = close + 1;
                                continue;
                            }
                        }
                    }
                }
            }
            try out.append(gpa, template[i]);
            i += 1;
        }
        pos = if (caps.match.end > caps.match.start) caps.match.end else caps.match.start + 1;
    }
    return out.toOwnedSlice(gpa);
}

test "fuzz: Differential 3 — scanFinderFast, PrefixAnyTail, matchedSpan, and CompiledReplacement" {
    var prng = std.Random.DefaultPrng.init(0xB7E1_5162_8AED_2A6A);
    const rand = prng.random();
    const gpa = std.testing.allocator;

    // 1. `scanFinderFast`: BareCount & matched_fast_line (slice & tiny-chunk reader) vs naive line-by-line oracle
    {
        const BareCount = struct {};
        const FastLineRec = struct {
            pub const matched_fast_line = true;
            alloc: std.mem.Allocator,
            out: std.ArrayList(u8) = .empty,
            nul: ?u64 = null,

            fn deinit(self: *@This()) void {
                self.out.deinit(self.alloc);
            }

            pub fn matched(self: *@This(), line: sink_mod.Line) bool {
                if (line.number) |n| {
                    var tmp: [32]u8 = undefined;
                    const s = std.fmt.bufPrint(&tmp, "{d}:", .{n}) catch return false;
                    self.out.appendSlice(self.alloc, s) catch return false;
                }
                self.out.appendSlice(self.alloc, line.bytes) catch return false;
                self.out.append(self.alloc, '\n') catch return false;
                return true;
            }

            pub fn binary(self: *@This(), offset: u64) bool {
                self.nul = offset;
                return true;
            }
        };

        const line_chunks = [_][]const u8{
            "plain text ", "MATCH ", "MaTcH ", "match ", "foo=bar ", "12345 ", "near_MAT ",
        };
        var doc: std.ArrayList(u8) = .empty;
        defer doc.deinit(gpa);

        for (0..45) |iter| {
            doc.clearRetainingCapacity();
            const n_lines = rand.intRangeAtMost(usize, 1, 18);
            const nul_line: ?usize = if (iter % 2 == 0) rand.uintLessThan(usize, n_lines) else null;

            for (0..n_lines) |li| {
                const parts = rand.intRangeAtMost(usize, 0, 5);
                var had_match_tok = false;
                for (0..parts) |_| {
                    const tok = line_chunks[rand.uintLessThan(usize, line_chunks.len)];
                    if (std.ascii.eqlIgnoreCase(tok[0..@min(tok.len, 5)], "MATCH")) had_match_tok = true;
                    try doc.appendSlice(gpa, tok);
                }
                if (nul_line != null and nul_line.? == li) {
                    // Exercise NUL before match, or specifically on same line AFTER match before `\n`!
                    if (!had_match_tok and rand.boolean()) {
                        try doc.appendSlice(gpa, "MATCH after_hit ");
                    }
                    try doc.append(gpa, 0);
                    try doc.appendSlice(gpa, "tail_after_nul");
                }
                const is_last = (li + 1 == n_lines);
                if (!is_last or rand.boolean()) {
                    if (rand.boolean()) try doc.append(gpa, '\r');
                    try doc.append(gpa, '\n');
                }
            }

            const cm: matcher_mod.CaseMode = if (iter % 2 == 0) .sensitive else .insensitive;
            const find_opts = matcher_mod.FindOptions{ .case = cm };
            var finder = try Finder.init("MATCH", find_opts);

            for ([_]searcher.BinaryPolicy{ .quit, .none }) |policy| {
                for ([_]bool{ false, true }) |with_ln| {
                    var oracle = try refScanLinesOracle(gpa, doc.items, "MATCH", find_opts, policy, with_ln);
                    defer oracle.deinit(gpa);

                    const cfg_slice = searcher.SearchConfig{
                        .binary = policy,
                        .line_numbers = with_ln,
                    };

                    var bare = BareCount{};
                    const r_bare = try searcher.searchSlice(BareCount, &bare, doc.items, "sf-bare", &finder, cfg_slice);
                    try std.testing.expectEqual(oracle.outcome, r_bare.outcome);
                    try std.testing.expectEqual(oracle.matched_lines, r_bare.matched_lines);
                    try std.testing.expectEqual(oracle.nul_offset, r_bare.nul_offset);

                    var fast_s = FastLineRec{ .alloc = gpa };
                    defer fast_s.deinit();
                    const r_fast_s = try searcher.searchSlice(FastLineRec, &fast_s, doc.items, "sf-fast", &finder, cfg_slice);
                    try std.testing.expectEqual(oracle.outcome, r_fast_s.outcome);
                    try std.testing.expectEqual(oracle.matched_lines, r_fast_s.matched_lines);
                    try std.testing.expectEqual(oracle.nul_offset, r_fast_s.nul_offset);
                    try std.testing.expectEqual(oracle.nul_offset, fast_s.nul);
                    try std.testing.expectEqualStrings(oracle.out.items, fast_s.out.items);

                    const step_sz = rand.intRangeAtMost(usize, 7, 29);
                    const cfg_rdr = searcher.SearchConfig{
                        .binary = policy,
                        .line_numbers = with_ln,
                        .buffer_size = rand.intRangeAtMost(usize, 24, 64),
                        .max_line_len = 512,
                    };
                    var chunked_b = ChunkedIoReader.init(doc.items, step_sz);
                    var bare_r = BareCount{};
                    const r_bare_r = try searcher.searchReader(BareCount, gpa, &bare_r, &chunked_b.interface, "sf-rbare", &finder, cfg_rdr);
                    try std.testing.expectEqual(oracle.outcome, r_bare_r.outcome);
                    try std.testing.expectEqual(oracle.matched_lines, r_bare_r.matched_lines);
                    try std.testing.expectEqual(oracle.nul_offset, r_bare_r.nul_offset);

                    var chunked_f = ChunkedIoReader.init(doc.items, step_sz);
                    var fast_r = FastLineRec{ .alloc = gpa };
                    defer fast_r.deinit();
                    const r_fast_r = try searcher.searchReader(FastLineRec, gpa, &fast_r, &chunked_f.interface, "sf-rfast", &finder, cfg_rdr);
                    try std.testing.expectEqual(oracle.outcome, r_fast_r.outcome);
                    try std.testing.expectEqual(oracle.matched_lines, r_fast_r.matched_lines);
                    try std.testing.expectEqual(oracle.nul_offset, r_fast_r.nul_offset);
                    try std.testing.expectEqualStrings(oracle.out.items, fast_r.out.items);
                }
            }
        }
    }

    // 2. `PrefixAnyTail` (`BEGIN.{1,25}END`, greedy & lazy, ASCII & multi-byte UTF-8) vs PikeVM reference
    {
        const pat_specs = [_]struct {
            pat: []const u8,
            opts: regex_mod.RegexOptions,
        }{
            .{ .pat = "BEGIN.{1,25}END", .opts = .{ .multiline = true, .dot_all = true } },
            .{ .pat = "BEGIN.{1,25}?END", .opts = .{ .multiline = true, .dot_all = true } },
            .{ .pat = "BEGIN.{1,25}END", .opts = .{ .multiline = true, .dot_all = true, .case = .insensitive, .unicode_case = false } },
            .{ .pat = "BEGIN.{1,25}?END", .opts = .{ .multiline = true, .dot_all = true, .case = .insensitive, .unicode_case = false } },
        };
        const units = [_][]const u8{
            "a", "x", "\n", "\r\n", "é", "中", "😀", "BEGIN", "END", "begin", "end", "BEG", "EN",
        };
        var hay: std.ArrayList(u8) = .empty;
        defer hay.deinit(gpa);

        for (pat_specs) |ps| {
            var re_fast = try Regex.init(gpa, ps.pat, ps.opts);
            defer re_fast.deinit();
            try std.testing.expect(re_fast.prefix_any_tail != null);

            var pike_opts = ps.opts;
            pike_opts.max_dfa_states = 0;
            var re_pike = try Regex.init(gpa, ps.pat, pike_opts);
            defer re_pike.deinit();
            re_pike.prefix_any_tail = null;

            for (0..32) |iter| {
                hay.clearRetainingCapacity();
                const n_u = rand.intRangeAtMost(usize, 5, 45);
                for (0..n_u) |_| {
                    try hay.appendSlice(gpa, units[rand.uintLessThan(usize, units.len)]);
                }
                if (iter % 3 == 0 and hay.items.len > 0) {
                    const zpos = rand.uintLessThan(usize, hay.items.len);
                    try hay.insert(gpa, zpos, 0);
                }

                var pos: usize = 0;
                var steps: usize = 0;
                while (pos <= hay.items.len and steps < 12) : (steps += 1) {
                    const exp_lmf = re_pike.find(hay.items, pos, .leftmost_first);
                    const got_lmf = re_fast.find(hay.items, pos, .leftmost_first);
                    try std.testing.expectEqual(exp_lmf, got_lmf);

                    const exp_ear = re_pike.find(hay.items, pos, .earliest);
                    const got_ear = re_fast.find(hay.items, pos, .earliest);
                    if (re_fast.prefix_any_tail.?.is_lazy) {
                        try std.testing.expectEqual(exp_ear, got_ear);
                    } else if (exp_ear) |ee| {
                        const ge = got_ear orelse return error.TestUnexpectedResult;
                        try std.testing.expectEqual(ee.start, ge.start);
                        try std.testing.expect(ge.end <= ee.end);
                        try std.testing.expect(re_pike.acceptsSpan(hay.items[ge.start..ge.end], .leftmost_first));
                    } else {
                        try std.testing.expect(got_ear == null);
                    }

                    const ref_nul = if (pos < hay.items.len) std.mem.findScalarPos(u8, hay.items, pos, 0) else null;
                    var nul_w: ?usize = null;
                    const got_w = re_fast.findWatched(hay.items, pos, &nul_w);
                    try checkWatchedMatchContract(got_ear, got_w, nul_w, ref_nul);

                    pos = if (exp_lmf) |m| @max(m.start + 1, pos + 1) else break;
                }
            }
        }
    }

    // 3. `matchedSpan` (`-o`) and `CompiledReplacement` (`-r`) parity
    {
        const SpanSink = struct {
            alloc: std.mem.Allocator,
            allow_stream: bool,
            spans: std.ArrayList([]u8) = .empty,

            fn deinit(self: *@This()) void {
                for (self.spans.items) |s| self.alloc.free(s);
                self.spans.deinit(self.alloc);
            }

            pub fn canStreamSpans(self: *const @This()) bool {
                return self.allow_stream;
            }

            pub fn matchedSpan(self: *@This(), bytes: []const u8) bool {
                const dup = self.alloc.dupe(u8, bytes) catch return false;
                self.spans.append(self.alloc, dup) catch {
                    self.alloc.free(dup);
                    return false;
                };
                return true;
            }

            pub fn matched(self: *@This(), line: sink_mod.Line) bool {
                for (line.matches) |sp| {
                    const dup = self.alloc.dupe(u8, line.bytes[sp.start..sp.end]) catch return false;
                    self.spans.append(self.alloc, dup) catch {
                        self.alloc.free(dup);
                        return false;
                    };
                }
                return true;
            }
        };

        const SkipCountSpanSink = struct {
            pub const matched_span_skip_line_count = true;
            alloc: std.mem.Allocator,
            spans: std.ArrayList([]u8) = .empty,

            fn deinit(self: *@This()) void {
                for (self.spans.items) |s| self.alloc.free(s);
                self.spans.deinit(self.alloc);
            }

            pub fn canStreamSpans(_: *const @This()) bool {
                return true;
            }

            pub fn matchedSpan(self: *@This(), bytes: []const u8) bool {
                const dup = self.alloc.dupe(u8, bytes) catch return false;
                self.spans.append(self.alloc, dup) catch {
                    self.alloc.free(dup);
                    return false;
                };
                return true;
            }
        };

        const ReplSink = struct {
            alloc: std.mem.Allocator,
            lines: std.ArrayList([]u8) = .empty,

            fn deinit(self: *@This()) void {
                for (self.lines.items) |s| self.alloc.free(s);
                self.lines.deinit(self.alloc);
            }

            pub fn matched(self: *@This(), line: sink_mod.Line) bool {
                if (line.replaced) |r| {
                    const dup = self.alloc.dupe(u8, r) catch return false;
                    self.lines.append(self.alloc, dup) catch {
                        self.alloc.free(dup);
                        return false;
                    };
                }
                return true;
            }
        };

        var re_cap = try Regex.init(gpa, "(?P<k>[a-z]{2,4})=(?P<v>[0-9]{1,3})", .{});
        defer re_cap.deinit();

        const repl_cases = [_]struct {
            tmpl: []const u8,
            mode: search_state.ReplMode,
        }{
            .{ .tmpl = "REDACTED", .mode = .literal_only },
            .{ .tmpl = "", .mode = .literal_only },
            .{ .tmpl = "a$$b", .mode = .literal_only },
            .{ .tmpl = "[$0]", .mode = .whole_match_only },
            .{ .tmpl = "<$&>", .mode = .whole_match_only },
            .{ .tmpl = "$2-$1", .mode = .needs_captures },
            .{ .tmpl = "${v}:${k}", .mode = .needs_captures },
            .{ .tmpl = "$0:$1-$2$$", .mode = .needs_captures },
        };
        for (repl_cases) |rc| {
            try std.testing.expectEqual(rc.mode, search_format.compileReplacement(rc.tmpl, &re_cap).mode);
        }

        const kv_tokens = [_][]const u8{ "ab=12", "xyz=9", "foo=100", "nope", "  ", "bar=42", "k=1" };
        var doc: std.ArrayList(u8) = .empty;
        defer doc.deinit(gpa);

        for (0..20) |_| {
            doc.clearRetainingCapacity();
            const n_lines = rand.intRangeAtMost(usize, 1, 12);
            for (0..n_lines) |_| {
                const words = rand.intRangeAtMost(usize, 0, 5);
                for (0..words) |w| {
                    if (w > 0) try doc.append(gpa, ' ');
                    try doc.appendSlice(gpa, kv_tokens[rand.uintLessThan(usize, kv_tokens.len)]);
                }
                if (rand.boolean()) try doc.append(gpa, '\r');
                try doc.append(gpa, '\n');
            }

            // matchedSpan parity (slice + streaming + skip_line_count vs fallback matched(Line))
            const span_cfg = searcher.SearchConfig{ .match_mode = .leftmost_first, .binary = .none };
            var ref_s = SpanSink{ .alloc = gpa, .allow_stream = false };
            defer ref_s.deinit();
            const r_ref = try searcher.searchSlice(SpanSink, &ref_s, doc.items, "sp-ref", &re_cap, span_cfg);

            var fast_s = SpanSink{ .alloc = gpa, .allow_stream = true };
            defer fast_s.deinit();
            const r_fast = try searcher.searchSlice(SpanSink, &fast_s, doc.items, "sp-fast", &re_cap, span_cfg);

            var skip_s = SkipCountSpanSink{ .alloc = gpa };
            defer skip_s.deinit();
            const r_skip = try searcher.searchSlice(SkipCountSpanSink, &skip_s, doc.items, "sp-skip", &re_cap, span_cfg);

            var chunked = ChunkedIoReader.init(doc.items, 19);
            var rdr_s = SpanSink{ .alloc = gpa, .allow_stream = true };
            defer rdr_s.deinit();
            const r_rdr = try searcher.searchReader(SpanSink, gpa, &rdr_s, &chunked.interface, "sp-rdr", &re_cap, .{
                .match_mode = .leftmost_first,
                .binary = .none,
                .buffer_size = 32,
                .max_line_len = 256,
            });

            try std.testing.expectEqual(r_ref.matched_lines, r_fast.matched_lines);
            try std.testing.expectEqual(r_ref.matches, r_fast.matches);
            try std.testing.expectEqual(r_ref.matches, r_skip.matches);
            try std.testing.expectEqual(r_ref.matched_lines, r_rdr.matched_lines);
            try std.testing.expectEqual(r_ref.matches, r_rdr.matches);
            try std.testing.expectEqual(ref_s.spans.items.len, fast_s.spans.items.len);
            try std.testing.expectEqual(ref_s.spans.items.len, skip_s.spans.items.len);
            try std.testing.expectEqual(ref_s.spans.items.len, rdr_s.spans.items.len);
            for (ref_s.spans.items, fast_s.spans.items, skip_s.spans.items, rdr_s.spans.items) |a, b, c, d| {
                try std.testing.expectEqualStrings(a, b);
                try std.testing.expectEqualStrings(a, c);
                try std.testing.expectEqualStrings(a, d);
            }

            // CompiledReplacement parity vs manual findCaptures expander
            const rc = repl_cases[rand.uintLessThan(usize, repl_cases.len)];
            var repl_sink = ReplSink{ .alloc = gpa };
            defer repl_sink.deinit();
            _ = try searcher.searchSlice(ReplSink, &repl_sink, doc.items, "repl", &re_cap, .{
                .match_mode = .leftmost_first,
                .replacement = rc.tmpl,
                .binary = .none,
                .allocator = gpa,
            });

            var line_idx: usize = 0;
            var pos: usize = 0;
            while (pos < doc.items.len) {
                const nl = std.mem.findScalarPos(u8, doc.items, pos, '\n') orelse doc.items.len;
                var cend = nl;
                if (cend > pos and doc.items[cend - 1] == '\r') cend -= 1;
                const line_bytes = doc.items[pos..cend];
                if (re_cap.find(line_bytes, 0, .leftmost_first) != null) {
                    const exp_line = try refExpandReplacement(gpa, &re_cap, line_bytes, rc.tmpl);
                    defer gpa.free(exp_line);
                    try std.testing.expect(line_idx < repl_sink.lines.items.len);
                    try std.testing.expectEqualStrings(exp_line, repl_sink.lines.items[line_idx]);
                    line_idx += 1;
                }
                pos = if (nl < doc.items.len) nl + 1 else doc.items.len;
            }
            try std.testing.expectEqual(line_idx, repl_sink.lines.items.len);
        }
    }
}

// ============================================================================
// 10. Differential Fuzz 4: Variant H GBK (`decodeGbkFastNoMap`) vs Mapped Scalar Reference
// ============================================================================

test "fuzz: Differential 4 — Variant H GBK fast path vs scalar mapped reference across tight dst buffers" {
    var prng = std.Random.DefaultPrng.init(0xC6EF_3720_9E37_79B9);
    const rand = prng.random();
    const gpa = std.testing.allocator;

    var raw: std.ArrayList(u8) = .empty;
    defer raw.deinit(gpa);
    var stream_out: std.ArrayList(u8) = .empty;
    defer stream_out.deinit(gpa);

    const tight_caps = [_]usize{ 1, 2, 3, 4, 5, 7, 15, 16, 31, 32, 33, 63, 64, 65, 127, 128, 4096 };
    const dst_buf = try gpa.alloc(u8, 4096);
    defer gpa.free(dst_buf);

    for (0..48) |iter| {
        raw.clearRetainingCapacity();
        const segs = if (iter == 47) 180 else rand.intRangeAtMost(usize, 1, 28);
        for (0..segs) |_| {
            switch (rand.uintLessThan(u8, 8)) {
                0, 1 => {
                    // Short or SIMD-boundary ASCII run
                    const run_len = switch (rand.uintLessThan(u8, 4)) {
                        0 => rand.intRangeAtMost(usize, 1, 5),
                        1 => rand.intRangeAtMost(usize, 15, 18),
                        2 => rand.intRangeAtMost(usize, 31, 34),
                        else => rand.intRangeAtMost(usize, 63, 67),
                    };
                    for (0..run_len) |_| {
                        try raw.append(gpa, 0x20 + @as(u8, @intCast(rand.uintLessThan(u8, 95))));
                    }
                },
                2, 3 => {
                    // Valid GBK 2-byte pair (lead 0x81..0xFE, trail 0x40..0x7E or 0x80..0xFE)
                    const pairs_n = rand.intRangeAtMost(usize, 1, 8);
                    for (0..pairs_n) |_| {
                        const lead = rand.intRangeAtMost(u8, 0x81, 0xFE);
                        var trail = rand.intRangeAtMost(u8, 0x40, 0xFE);
                        if (trail == 0x7F) trail = 0x80;
                        try raw.append(gpa, lead);
                        try raw.append(gpa, trail);
                    }
                },
                4 => try raw.append(gpa, 0x80), // Euro sign
                5 => {
                    // Invalid lead 0xFF or unmapped valid pair 0xFE 0xFE
                    if (rand.boolean()) {
                        try raw.append(gpa, 0xFF);
                    } else {
                        try raw.appendSlice(gpa, "\xFE\xFE");
                    }
                },
                6 => {
                    // Invalid trail byte (0x7F, 0xFF, or < 0x40) after valid lead
                    const lead = rand.intRangeAtMost(u8, 0x81, 0xFE);
                    const bad_trail: u8 = switch (rand.uintLessThan(u8, 3)) {
                        0 => 0x7F,
                        1 => 0xFF,
                        else => rand.intRangeAtMost(u8, 0x01, 0x3F),
                    };
                    try raw.append(gpa, lead);
                    try raw.append(gpa, bad_trail);
                },
                else => try raw.append(gpa, '\n'),
            }
        }
        // Randomly append a truncated trailing lead byte at EOF
        if (rand.boolean()) {
            try raw.append(gpa, rand.intRangeAtMost(u8, 0x81, 0xFE));
        }

        // Reference: mapped path (`has_map = true`, bypasses `decodeGbkFastNoMap`)
        var ref_map = offset_map_mod.OffsetMap{};
        defer ref_map.deinit(gpa);
        const ref_utf8 = try encoding.convertAllocWithMap(gpa, .gbk, raw.items, 0, &ref_map);
        defer gpa.free(ref_utf8);
        try std.testing.expect(std.unicode.utf8ValidateSlice(ref_utf8));
        try std.testing.expectEqual(ref_utf8.len, encoding.decodedSize(.gbk, raw.items));

        // Fast path 1: whole-slice `convertAlloc` (`has_map = false` -> `decodeGbkFastNoMap`)
        const fast_utf8 = try encoding.convertAlloc(gpa, .gbk, raw.items);
        defer gpa.free(fast_utf8);
        try std.testing.expectEqualStrings(ref_utf8, fast_utf8);

        // Fast path 2: streaming `Decoder.init(.gbk)` (`offset_map = null` -> `decodeGbkFastNoMap`) across tight dst caps
        const cap_a = tight_caps[iter % tight_caps.len];
        const cap_b = tight_caps[(iter * 5 + 3) % tight_caps.len];
        for ([_]usize{ cap_a, cap_b }) |cap| {
            stream_out.clearRetainingCapacity();
            var dec = encoding.Decoder.init(.gbk);
            defer dec.deinit(gpa);
            const read_step = rand.intRangeAtMost(usize, 1, 29);
            var ctx = FixedChunkCtx{ .data = raw.items, .step = read_step };
            var rb: u64 = 0;
            while (true) {
                const pulled = try dec.pull(gpa, FixedChunkCtx.readFn, &ctx, read_step, dst_buf[0..cap], &rb);
                if (pulled.n > 0) try stream_out.appendSlice(gpa, dst_buf[0..pulled.n]);
                if (pulled.eof) break;
            }
            try std.testing.expectEqualStrings(ref_utf8, stream_out.items);
        }
    }
}

// ============================================================================
// 11. OOM Injection (`std.testing.checkAllAllocationFailures`) Zero-Leak & Zero-Panic Audit
// ============================================================================

fn oomAhoBuild(alloc: std.mem.Allocator, pats: []const []const u8) !void {
    var ac = try aho.build(alloc, pats, false);
    defer ac.deinit();
    try std.testing.expect(!ac.use_anchor);
    try std.testing.expect(ac.dense_count > 0);
    try std.testing.expect(ac.sparse_states.len > 0);
}

fn oomRegexSetInterior(alloc: std.mem.Allocator) !void {
    const pats = [_][]const u8{
        "[a-z]{1,3}_KEY1_[0-9]{2}",
        "[a-z]{1,3}_KEY2_[0-9]{2}",
        "PRE3_[0-9]{2}",
    };
    var set = try RegexSet.init(alloc, &pats, .{});
    defer set.deinit();
    if (set.prefilter == null or set.pf_next_mask.len == 0 or set.pf_has_next_mask.len == 0) {
        return error.OutOfMemory;
    }
}

fn oomRegexSetZeroLit(alloc: std.mem.Allocator) !void {
    const pats = [_][]const u8{
        "\\b[a-z]{2,4}\\b",
        "[0-9]{3,5}",
    };
    var set = try RegexSet.init(alloc, &pats, .{});
    defer set.deinit();
    if (set.set_unanchored_dfa == null) {
        return error.OutOfMemory;
    }
}

fn oomRegexUnanchoredDfa(alloc: std.mem.Allocator) !void {
    var re = try Regex.init(alloc, "\\b[a-z]{2,4}[0-9]{2,3}\\b", .{});
    defer re.deinit();
    if (re.unanchored_dfa == null) return error.OutOfMemory;
}

fn oomRegexPrefixAnyTail(alloc: std.mem.Allocator) !void {
    var re = try Regex.init(alloc, "BEGIN.{1,12}END", .{
        .multiline = true,
        .dot_all = true,
        .max_dfa_states = 0,
    });
    defer re.deinit();
    if (re.prefix_any_tail == null) return error.OutOfMemory;
}

fn oomRegexAltPrefixBoundedDfa(alloc: std.mem.Allocator) !void {
    var re = try Regex.init(alloc, "ALPHA_[0-9]+|BETA_[0-9]+|GAMMA_[0-9]+", .{});
    defer re.deinit();
    if (re.alt_prefilter == null or re.precomputed_dfa == null) return error.OutOfMemory;
}

fn oomDecoderStreaming(alloc: std.mem.Allocator, enc: encoding.Encoding, payload: []const u8, with_map: bool) !void {
    var map = offset_map_mod.OffsetMap{};
    defer map.deinit(alloc);

    var dec = encoding.Decoder.init(enc);
    defer dec.deinit(alloc);
    if (with_map) dec.offset_map = &map;

    var ctx = FixedChunkCtx{ .data = payload, .step = 13 };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(alloc);

    var dest: [29]u8 = undefined;
    var rb: u64 = 0;
    while (true) {
        const pulled = try dec.pull(alloc, FixedChunkCtx.readFn, &ctx, 13, &dest, &rb);
        if (pulled.n > 0) try out.appendSlice(alloc, dest[0..pulled.n]);
        if (pulled.eof) break;
    }
}

fn oomWalkerAudit(alloc: std.mem.Allocator, root_path: []const u8) !void {
    const WalkCtx = struct {
        stop: *std.atomic.Value(bool),
        found_count: usize = 0,
        saw_loop: bool = false,
        saw_oom: bool = false,

        fn push(_: *anyopaque, j: *walker.Job) anyerror!void {
            j.destroy(std.testing.io);
            return error.OutOfMemory;
        }

        fn onFile(ctx: *anyopaque, _: walker.Visit) anyerror!walker.Control {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.found_count += 1;
            return .cont;
        }

        fn onErr(ctx: *anyopaque, path: []const u8, err: anyerror) void {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            if (err == error.OutOfMemory) {
                self.saw_oom = true;
                self.stop.store(true, .release);
            } else if (err == error.SymLinkLoop) {
                // `walker.report` falls back to `job.root` when `displayPath` hits OOM.
                if (std.mem.endsWith(u8, path, "loop_root")) {
                    self.saw_loop = true;
                } else {
                    self.saw_oom = true;
                    self.stop.store(true, .release);
                }
            }
        }
    };

    const scoped = [_]walker.ScopedIgnore{
        .{ .repo_prefix = "", .text = "*.gen.rs\n" },
    };

    var session = walker.Session.init(alloc);
    defer session.deinit();
    var stop = std.atomic.Value(bool).init(false);
    var wctx = WalkCtx{ .stop = &stop };

    var host = walker.Host{
        .allocator = alloc,
        .io = std.testing.io,
        .config = .{
            .follow_symlinks = true,
            .sort_by = .path,
            .scoped_ignores = &scoped,
            .types = &.{"rust"},
        },
        .session = &session,
        .stop = &stop,
        .push = WalkCtx.push,
        .push_ctx = &wctx,
        .on_file = WalkCtx.onFile,
        .file_ctx = &wctx,
        .on_error = WalkCtx.onErr,
        .error_ctx = &wctx,
    };

    const root_job = try walker.createRoot(&host, root_path);
    walker.process(&host, root_job);
    if (wctx.saw_oom or wctx.found_count != 4 or !wctx.saw_loop) return error.OutOfMemory;
}

test "fuzz: OOM Injection (checkAllAllocationFailures) — AhoCorasick, RegexSet, Regex, Decoder, Walker" {
    const gpa = std.testing.allocator;

    // 1. AhoCorasick.init (hybrid dense + sparse ~120 patterns)
    {
        const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
        var prng = std.Random.DefaultPrng.init(0x1357_9BDF_2468_ACE0);
        const rand = prng.random();
        var storage: [120][15]u8 = undefined;
        var pats: [120][]const u8 = undefined;
        for (0..120) |i| {
            // Ensure all 64 distinct bytes appear (nclasses=65, >16 anchor bytes) and 120 distinct depth-2 prefixes
            // so total trie nodes (~1,745) strictly exceed the dense cap (65,792/65 = 1,012), exercising both dense & sparse.
            storage[i][0] = alpha[i % alpha.len];
            storage[i][1] = alpha[((i / alpha.len) * 19 + i * 7 + 3) % alpha.len];
            for (2..15) |k| {
                storage[i][k] = alpha[rand.uintLessThan(usize, alpha.len)];
            }
            pats[i] = &storage[i];
        }
        try std.testing.checkAllAllocationFailures(gpa, oomAhoBuild, .{@as([]const []const u8, &pats)});
    }

    // 2. RegexSet.init (interior prefilter + zero-lit SetUnanchoredDfa)
    try std.testing.checkAllAllocationFailures(gpa, oomRegexSetInterior, .{});
    try std.testing.checkAllAllocationFailures(gpa, oomRegexSetZeroLit, .{});

    // 3. Regex.init (UnanchoredDfa + PrefixAnyTail + alt-prefix BoundedDfa)
    try std.testing.checkAllAllocationFailures(gpa, oomRegexUnanchoredDfa, .{});
    try std.testing.checkAllAllocationFailures(gpa, oomRegexPrefixAnyTail, .{});
    try std.testing.checkAllAllocationFailures(gpa, oomRegexAltPrefixBoundedDfa, .{});

    // 4. encoding.Decoder (GBK & UTF-16LE streaming decode, with and without OffsetMap)
    {
        const gbk_payload: []const u8 =
            "2026-11-24 INFO " ++
            "\xC4\xE3\xBA\xC3\xCA\xC0\xBD\xE7\xB2\xE2\xCA\xD4" ++
            " \x80 \x81\x7F \xFF \xB4\xED\xCE\xF3 ok\n" ++
            "line2 \xC4\xE3\xBA\xC3 tail\xFE";
        const u16_payload: []const u8 =
            "\xFF\xFE" ++
            "h\x00e\x00l\x00l\x00o\x00 \x00" ++
            "\x2D\x4E\x87\x65\x0A\x00" ++
            "w\x00o\x00r\x00l\x00d\x00!\x00";
        try std.testing.checkAllAllocationFailures(gpa, oomDecoderStreaming, .{ .gbk, gbk_payload, false });
        try std.testing.checkAllAllocationFailures(gpa, oomDecoderStreaming, .{ .gbk, gbk_payload, true });
        try std.testing.checkAllAllocationFailures(gpa, oomDecoderStreaming, .{ .utf16le, u16_payload, false });
        try std.testing.checkAllAllocationFailures(gpa, oomDecoderStreaming, .{ .utf16le, u16_payload, true });
    }

    // 5. walker (`follow_symlinks = true` with AncestorNode, `sort_by = .path`, `scoped_ignores`, `types = &.{"rust"}`)
    {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const io = std.testing.io;

        try tmp.dir.createDir(io, "target_dir", .default_dir);
        try tmp.dir.writeFile(io, .{ .sub_path = "target_dir/d.rs", .data = "fn d() {}" });
        try tmp.dir.createDir(io, "root", .default_dir);
        try tmp.dir.writeFile(io, .{ .sub_path = "root/.gitignore", .data = "!keep.gen.rs\n" });
        try tmp.dir.writeFile(io, .{ .sub_path = "root/a.rs", .data = "fn a() {}" });
        try tmp.dir.writeFile(io, .{ .sub_path = "root/b.py", .data = "def b(): pass" });
        try tmp.dir.writeFile(io, .{ .sub_path = "root/drop.gen.rs", .data = "fn drop() {}" });
        try tmp.dir.writeFile(io, .{ .sub_path = "root/keep.gen.rs", .data = "fn keep() {}" });
        try tmp.dir.createDir(io, "root/sub", .default_dir);
        try tmp.dir.writeFile(io, .{ .sub_path = "root/sub/c.rs", .data = "fn c() {}" });
        try tmp.dir.symLink(io, "..", "root/sub/loop_root", .{ .is_directory = true });
        try tmp.dir.symLink(io, "../target_dir", "root/link_dir", .{ .is_directory = true });

        var path_buf: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const path_len = try tmp.dir.realPathFile(io, "root", &path_buf);
        const root_path = path_buf[0..path_len];

        try std.testing.checkAllAllocationFailures(gpa, oomWalkerAudit, .{root_path});
    }
}
