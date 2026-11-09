//! In-process microbenchmark suite (`ReleaseFast` only).
//!
//! Each line is printed as:
//! `scenario <name> bytes <n> gbs <throughput> iters <count> sink <checksum>`
//! Throughput is measured in `bytes / second / 1e9` (GB/s). Every scenario runs one unmeasured warmup
//! iteration followed by at least 200 ms and at least 2 measured iterations, with compiler memory
//! barriers and first-byte bit-flipping to prevent dead-code elimination.
//!
//! Optional CLI filter:
//!   `zig build bench -Doptimize=ReleaseFast -- [substring]`
//! When provided, only scenarios whose name contains `substring` are executed.

const std = @import("std");
const internal = @import("libwebgrep_internal");

const bytes_64m = 64 * 1024 * 1024;
const bytes_16m = 16 * 1024 * 1024;
const bytes_4m = 4 * 1024 * 1024;
const sweep_body = 128 * 1024 * 1024;
const sweep_tail = "NEEDLE\n";
const sweep_bytes = sweep_body + sweep_tail.len;
const walk_files = 384;
const walk_file_bytes = 2048;
const walk_bytes = walk_files * walk_file_bytes;

const Sample = struct {
    gbs: f64,
    iters: u64,
    sink: usize,
};

const BenchTracker = struct {
    io: std.Io,
    filter: ?[]const u8 = null,
    count: usize = 0,
    min_gbs: f64 = std.math.inf(f64),
    max_gbs: f64 = 0.0,
    log_sum: f64 = 0.0,

    fn wants(self: *const BenchTracker, name: []const u8) bool {
        const f = self.filter orelse return true;
        return std.mem.indexOf(u8, name, f) != null;
    }

    fn wantsAny(self: *const BenchTracker, names: []const []const u8) bool {
        if (self.filter == null) return true;
        for (names) |name| {
            if (self.wants(name)) return true;
        }
        return false;
    }

    fn record(self: *BenchTracker, gbs: f64) void {
        self.count += 1;
        if (gbs < self.min_gbs) self.min_gbs = gbs;
        if (gbs > self.max_gbs) self.max_gbs = gbs;
        if (gbs > 0.0) self.log_sum += @log(gbs);
    }

    fn printSummary(self: *const BenchTracker) void {
        if (self.count == 0) return;
        const geomean = @exp(self.log_sum / @as(f64, @floatFromInt(self.count)));
        std.debug.print("summary scenarios {d} min_gbs {d:.3} max_gbs {d:.3} geomean_gbs {d:.3}\n", .{
            self.count,
            self.min_gbs,
            self.max_gbs,
            geomean,
        });
    }
};

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var args_it = try std.process.Args.Iterator.initAllocator(init.minimal.args, gpa);
    defer args_it.deinit();
    _ = args_it.next(); // skip argv[0]
    const filter_owned: ?[]u8 = if (args_it.next()) |arg| try gpa.dupe(u8, arg) else null;
    defer if (filter_owned) |f| gpa.free(f);

    var tracker = BenchTracker{
        .io = io,
        .filter = filter_owned,
    };

    std.debug.print("libwebgrep bench width {d} walk_default_threads {d}\n", .{
        internal.memchr.native_width,
        internal.parallel.resolveThreads(0),
    });

    const buf = try gpa.alloc(u8, bytes_64m);
    defer gpa.free(buf);
    internal.multi.fillScenarioText(buf);

    try benchScalar(&tracker, buf);
    try benchFinder(&tracker, buf);
    try benchMulti(gpa, &tracker, buf);

    if (tracker.wantsAny(&.{ "finder_alphabet", "regex_prefilter" })) {
        fillAlphabet(buf);
        var alphabet = try internal.Finder.init("libwebgrep", .{ .case = .sensitive });
        const alphabet_at = buf.len - "libwebgrep\n".len;
        var alphabet_ctx = FinderCtx{ .data = buf, .finder = &alphabet, .at = alphabet_at };
        try report(&tracker, "finder_alphabet", buf.len, alphabet_at, finderRun, &alphabet_ctx);

        var re_anchor = try internal.Regex.init(gpa, "libweb.*[0-9]*grep", .{});
        defer re_anchor.deinit();
        var regex_ctx = RegexCtx{ .data = buf, .re = &re_anchor, .at = alphabet_at };
        try report(&tracker, "regex_prefilter", buf.len, alphabet_at, regexRun, &regex_ctx);
    }

    const buf16 = buf[0..bytes_16m];
    try benchUnicode(gpa, &tracker, buf16);
    try benchRegex(gpa, &tracker, buf16);
    try benchEncoding(gpa, &tracker);
    try benchStreaming(gpa, &tracker, buf16);
    try benchSweep(gpa, &tracker);
    try benchWalk(gpa, &tracker);

    tracker.printSummary();
}

fn fillAlphabet(buf: []u8) void {
    const line = "abcdefghijklmnopqrstuvwxyz\n";
    var i: usize = 0;
    while (i + line.len <= buf.len) : (i += line.len) {
        @memcpy(buf[i..][0..line.len], line);
    }
    if (i < buf.len) @memset(buf[i..], 'a');
    const needle = "libwebgrep\n";
    @memcpy(buf[buf.len - needle.len ..], needle);
}

fn benchScalar(tracker: *BenchTracker, buf: []u8) !void {
    var find_miss = Miss{ .data = buf, .kind = .find };
    var either_miss = Miss{ .data = buf, .kind = .either };
    var std_miss = Miss{ .data = buf, .kind = .std };
    try report(tracker, "memchr_find", buf.len, 0, missByte, &find_miss);
    try report(tracker, "memchr_either", buf.len, 0, missByte, &either_miss);
    try report(tracker, "std_find_scalar", buf.len, 0, missByte, &std_miss);
}

const MissKind = enum { find, either, std };

const Miss = struct {
    data: []u8,
    kind: MissKind,
};

fn missByte(ctx: *Miss) !usize {
    ctx.data[0] ^= 1;
    defer ctx.data[0] ^= 1;
    const hit = switch (ctx.kind) {
        .find => internal.memchr.find(internal.memchr.native_width, ctx.data, 0, 0xff) != null,
        .either => internal.memchr.findEither(internal.memchr.native_width, ctx.data, 0, 0xff, 0xfe) != null,
        .std => std.mem.findScalar(u8, ctx.data, 0xff) != null,
    };
    if (hit) return error.UnexpectedMatch;
    return 0;
}

fn benchFinder(tracker: *BenchTracker, buf: []u8) !void {
    const at = buf.len - sweep_tail.len;
    var sensitive = try internal.Finder.init("NEEDLE", .{ .case = .sensitive });
    var ignore = try internal.Finder.init("needle", .{ .case = .insensitive });
    var smart = try internal.Finder.init("needle", .{ .case = .smart });
    var slice_finder = try internal.Finder.init("NEEDLE", .{});

    var sensitive_ctx = FinderCtx{ .data = buf, .finder = &sensitive, .at = at };
    var ignore_ctx = FinderCtx{ .data = buf, .finder = &ignore, .at = at };
    var smart_ctx = FinderCtx{ .data = buf, .finder = &smart, .at = at };
    var slice_ctx = SliceCtx{ .data = buf, .finder = &slice_finder };
    try report(tracker, "finder_sensitive", buf.len, at, finderRun, &sensitive_ctx);
    try report(tracker, "finder_ignore", buf.len, at, finderRun, &ignore_ctx);
    try report(tracker, "finder_smart", buf.len, at, finderRun, &smart_ctx);
    try report(tracker, "search_slice", buf.len, 1, sliceRun, &slice_ctx);
}

const FinderCtx = struct {
    data: []u8,
    finder: *internal.Finder,
    at: usize,
};

const RegexCtx = struct {
    data: []u8,
    re: *internal.Regex,
    at: usize,
};

fn regexRun(ctx: *RegexCtx) !usize {
    ctx.data[0] ^= 1;
    defer ctx.data[0] ^= 1;
    ctx.re.resetStats();
    const hit = ctx.re.find(ctx.data, 0, .earliest) orelse return error.ExpectedMatch;
    if (hit.start != ctx.at) return error.UnexpectedOffset;
    return hit.start;
}

fn finderRun(ctx: *FinderCtx) !usize {
    ctx.data[0] ^= 1;
    defer ctx.data[0] ^= 1;
    ctx.finder.resetStats();
    const hit = ctx.finder.find(ctx.data, 0, .earliest) orelse return error.UnexpectedMatch;
    if (hit.start != ctx.at) return error.UnexpectedMatch;
    return hit.start;
}

const SliceCtx = struct {
    data: []u8,
    finder: *internal.Finder,
    options: internal.SearchConfig = .{},
};

fn sliceRun(ctx: *SliceCtx) !usize {
    ctx.data[0] ^= 1;
    defer ctx.data[0] ^= 1;
    var nop = Nop{};
    const result = try internal.searchSlice(Nop, &nop, ctx.data, "", ctx.finder, ctx.options);
    if (result.matched_lines != 1) return error.UnexpectedMatch;
    return 1;
}

const MultiCtx = struct {
    data: []u8,
    many: *internal.Multi,
    lines: u64,
};

fn benchMulti(gpa: std.mem.Allocator, tracker: *BenchTracker, buf: []u8) !void {
    try benchOneMulti(gpa, tracker, buf, "multi_bytes", internal.multi.scenario_bytes, 0, .{});
    try benchOneMulti(gpa, tracker, buf, "multi_pairs", internal.multi.scenario_pairs, 1, .{});
    try benchOneMulti(gpa, tracker, buf, "multi_teddy", internal.multi.scenario_teddy, 0, .{});
    try benchOneMulti(gpa, tracker, buf, "multi_ac", internal.multi.scenario_ac, 0, .{});
}

fn benchOneMulti(
    gpa: std.mem.Allocator,
    tracker: *BenchTracker,
    buf: []u8,
    name: []const u8,
    patterns: []const []const u8,
    lines: u64,
    options: internal.FindOptions,
) !void {
    if (!tracker.wants(name)) return;
    var many = try internal.Multi.init(gpa, patterns, options);
    defer many.deinit();
    std.debug.print("engine {s} {s}\n", .{ name, many.engineName() });
    var ctx = MultiCtx{ .data = buf, .many = &many, .lines = lines };
    try report(tracker, name, buf.len, @intCast(lines), multiRun, &ctx);
}

fn multiRun(ctx: *MultiCtx) !usize {
    ctx.data[0] ^= 1;
    defer ctx.data[0] ^= 1;
    var nop = Nop{};
    const result = try internal.searchSlice(Nop, &nop, ctx.data, "", ctx.many, .{});
    if (result.matched_lines != ctx.lines) return error.UnexpectedMatch;
    return @intCast(result.matched_lines);
}

fn benchUnicode(gpa: std.mem.Allocator, tracker: *BenchTracker, buf: []u8) !void {
    if (!tracker.wantsAny(&.{ "finder_unicode_case", "multi_unicode_expanded", "search_unicode_word" })) return;

    const line = "普通测试文本行 normal text line with multilingual tokens\n";
    var i: usize = 0;
    while (i + line.len <= buf.len) : (i += line.len) {
        @memcpy(buf[i..][0..line.len], line);
    }
    if (i < buf.len) @memset(buf[i..], 'a');
    const tail = "\n前缀_目标词_后缀\n（目标词） STRA\u{1E9E}E\n";
    @memcpy(buf[buf.len - tail.len ..], tail);
    const strasse_at = buf.len - "STRA\u{1E9E}E\n".len;

    var u_finder = try internal.Finder.init("straße", .{ .case = .insensitive, .unicode_case = true });
    var u_finder_ctx = FinderCtx{ .data = buf, .finder = &u_finder, .at = strasse_at };
    try report(tracker, "finder_unicode_case", buf.len, strasse_at, finderRun, &u_finder_ctx);

    try benchOneMulti(
        gpa,
        tracker,
        buf,
        "multi_unicode_expanded",
        &.{ "δelta", "привет", "straße" },
        1,
        .{ .case = .insensitive, .unicode_case = true },
    );

    var word_finder = try internal.Finder.init("目标词", .{});
    var word_ctx = SliceCtx{
        .data = buf,
        .finder = &word_finder,
        .options = .{ .whole_word = true },
    };
    try report(tracker, "search_unicode_word", buf.len, 1, sliceRun, &word_ctx);
}

fn benchRegex(gpa: std.mem.Allocator, tracker: *BenchTracker, buf: []u8) !void {
    if (!tracker.wantsAny(&.{
        "regex_alternation",
        "regex_utf8_class",
        "regex_captures",
        "regex_replace_template",
    })) return;

    fillAlphabet(buf);
    const tail = "\n你好世界_42 libwebcore99grep\n";
    @memcpy(buf[buf.len - tail.len ..], tail);
    const utf8_at = buf.len - "你好世界_42 libwebcore99grep\n".len;
    const cap_at = buf.len - "libwebcore99grep\n".len;

    if (tracker.wants("regex_alternation")) {
        var re_alt = try internal.Regex.init(gpa, "(?:ALPHA_TOKEN|BETA_TOKEN|libwebcore[0-9]{2}grep)", .{});
        defer re_alt.deinit();
        var ctx = RegexCtx{ .data = buf, .re = &re_alt, .at = cap_at };
        try report(tracker, "regex_alternation", buf.len, cap_at, regexRun, &ctx);
    }

    if (tracker.wants("regex_utf8_class")) {
        var re_utf8 = try internal.Regex.init(gpa, "\\b[你好世界]+_[0-9]+\\b", .{});
        defer re_utf8.deinit();
        var ctx = RegexCtx{ .data = buf, .re = &re_utf8, .at = utf8_at };
        try report(tracker, "regex_utf8_class", buf.len, utf8_at, regexRun, &ctx);
    }

    if (tracker.wants("regex_captures")) {
        var re_cap = try internal.Regex.init(gpa, "libweb([a-z]+)([0-9]+)(grep)", .{});
        defer re_cap.deinit();
        var ctx = RegexCapCtx{ .data = buf, .re = &re_cap, .at = cap_at };
        try report(tracker, "regex_captures", buf.len, cap_at, regexCapRun, &ctx);
    }

    if (tracker.wants("regex_replace_template")) {
        var re_rep = try internal.Regex.init(gpa, "libweb([a-z]+)([0-9]+)(grep)", .{});
        defer re_rep.deinit();
        var ctx = RegexReplaceCtx{ .gpa = gpa, .data = buf, .re = &re_rep };
        try report(tracker, "regex_replace_template", buf.len, 1, regexReplaceRun, &ctx);
    }
}

const RegexCapCtx = struct {
    data: []u8,
    re: *internal.Regex,
    at: usize,
};

fn regexCapRun(ctx: *RegexCapCtx) !usize {
    ctx.data[0] ^= 1;
    defer ctx.data[0] ^= 1;
    ctx.re.resetStats();
    const caps = ctx.re.findCaptures(ctx.data, 0, .earliest) orelse return error.ExpectedMatch;
    if (caps.match.start != ctx.at) return error.UnexpectedOffset;
    if (!std.mem.eql(u8, caps.slice(ctx.data, 1).?, "core")) return error.UnexpectedCapture;
    if (!std.mem.eql(u8, caps.slice(ctx.data, 2).?, "99")) return error.UnexpectedCapture;
    return caps.match.start;
}

const RegexReplaceCtx = struct {
    gpa: std.mem.Allocator,
    data: []u8,
    re: *internal.Regex,
};

fn regexReplaceRun(ctx: *RegexReplaceCtx) !usize {
    ctx.data[0] ^= 1;
    defer ctx.data[0] ^= 1;
    var nop = Nop{};
    const result = try internal.searchSlice(
        Nop,
        &nop,
        ctx.data,
        "",
        ctx.re,
        .{
            .decode_allocator = ctx.gpa,
            .replacement = "$2:$1 ($0)",
        },
    );
    if (result.matched_lines != 1) return error.UnexpectedMatch;
    return 1;
}

fn benchEncoding(gpa: std.mem.Allocator, tracker: *BenchTracker) !void {
    if (!tracker.wantsAny(&.{ "encoding_utf16le", "encoding_gbk", "resume_utf16le_tail" })) return;

    const raw = try gpa.alloc(u8, bytes_4m);
    defer gpa.free(raw);

    if (tracker.wantsAny(&.{ "encoding_utf16le", "resume_utf16le_tail" })) {
        // Fill 4 MiB with valid UTF-16LE lines: BOM + ("abcdefghijklmno\n" in UTF-16LE = 32 bytes/line)
        raw[0] = 0xFF;
        raw[1] = 0xFE;
        const ascii_line = "abcdefghijklmno\n";
        var pos: usize = 2;
        while (pos + ascii_line.len * 2 <= raw.len) {
            for (ascii_line) |ch| {
                raw[pos] = ch;
                raw[pos + 1] = 0;
                pos += 2;
            }
        }
        while (pos < raw.len) : (pos += 1) raw[pos] = 0;
        const tail_ascii = "NEEDLE_UTF16LE!\n";
        var tpos = raw.len - tail_ascii.len * 2;
        for (tail_ascii) |ch| {
            raw[tpos] = ch;
            raw[tpos + 1] = 0;
            tpos += 2;
        }

        if (tracker.wants("encoding_utf16le")) {
            var ctx = EncodingCtx{ .gpa = gpa, .raw = raw, .enc = .utf16le };
            const expected_u16_utf8_len = (raw.len - 2) / 2 + 3;
            try report(tracker, "encoding_utf16le", raw.len, expected_u16_utf8_len, encodingRun, &ctx);
        }

        if (tracker.wants("resume_utf16le_tail")) {
            // Resume from the last 64 KiB of the 4 MiB UTF-16LE buffer using raw_resume_at
            const tail_window: usize = 64 * 1024;
            const raw_resume_at: u64 = @intCast(raw.len - tail_window);
            var finder = try internal.Finder.init("NEEDLE_UTF16LE!", .{});
            var prev = internal.sink.Result{};
            prev.paused = true;
            prev.resume_at = (raw_resume_at - 2) / 2;
            prev.resume_state = .{
                .line_number = 1000,
                .raw_resume_at = raw_resume_at,
            };
            var ctx = ResumeUtf16Ctx{
                .gpa = gpa,
                .raw = raw,
                .finder = &finder,
                .prev = prev,
            };
            try report(tracker, "resume_utf16le_tail", tail_window, 1, resumeUtf16Run, &ctx);
        }
    }

    if (tracker.wants("encoding_gbk")) {
        // Fill 4 MiB with GBK lines: CJK level-1 + GBK ext + Euro sign + ASCII (18 bytes/line)
        const gbk_line = [_]u8{
            0xC4, 0xE3, 0xBA, 0xC3, // GB2312 level-1 CJK (U+4F60, U+597D)
            0xE9, 0x46, 0x86, 0xB4, // GBK 3/4 extension CJK (U+9555, U+5586)
            0x80, // Euro sign (U+20AC)
            'a',  'b',  'c',  'd',  'e', 'f', 'g', 'h', '\n',
        };
        var pos: usize = 0;
        while (pos + gbk_line.len <= raw.len) : (pos += gbk_line.len) {
            @memcpy(raw[pos..][0..gbk_line.len], &gbk_line);
        }
        if (pos < raw.len) @memset(raw[pos..], '\n');
        const expected_utf8_len = (raw.len / gbk_line.len) * "你好镕喆€abcdefgh\n".len + (raw.len % gbk_line.len);
        var ctx = EncodingCtx{ .gpa = gpa, .raw = raw, .enc = .gbk };
        try report(tracker, "encoding_gbk", raw.len, expected_utf8_len, encodingRun, &ctx);
    }
}

const EncodingCtx = struct {
    gpa: std.mem.Allocator,
    raw: []const u8,
    enc: internal.encoding.Sniff,
};

fn encodingRun(ctx: *EncodingCtx) !usize {
    const out = try internal.encoding.convertAlloc(ctx.gpa, ctx.enc, ctx.raw);
    defer ctx.gpa.free(out);
    return out.len;
}

const ServiceNopSink = struct {
    pub fn event(_: *ServiceNopSink, _: internal.sink.Event) bool {
        return true;
    }
};

const ResumeUtf16Ctx = struct {
    gpa: std.mem.Allocator,
    raw: []const u8,
    finder: *internal.Finder,
    prev: internal.sink.Result,
};

fn resumeUtf16Run(ctx: *ResumeUtf16Ctx) !usize {
    var sink = ServiceNopSink{};
    const result = try internal.resumeSourceSlice(
        ServiceNopSink,
        &sink,
        "u16-tail",
        ctx.raw,
        ctx.finder,
        .{ .decode_allocator = ctx.gpa, .encoding = .auto },
        ctx.prev,
    );
    if (result.matched_lines != 1) return error.UnexpectedMatch;
    return 1;
}

fn benchStreaming(gpa: std.mem.Allocator, tracker: *BenchTracker, buf: []u8) !void {
    if (!tracker.wantsAny(&.{ "stream_auto_sniff", "service_ndjson_filter" })) return;

    internal.multi.fillScenarioText(buf);
    var finder = try internal.Finder.init("NEEDLE", .{});

    if (tracker.wants("stream_auto_sniff")) {
        var ctx = StreamAutoCtx{ .gpa = gpa, .data = buf, .finder = &finder };
        try report(tracker, "stream_auto_sniff", buf.len, 1, streamAutoRun, &ctx);
    }

    if (tracker.wants("service_ndjson_filter")) {
        var ctx = ServiceJsonCtx{ .data = buf, .finder = &finder };
        try report(tracker, "service_ndjson_filter", buf.len, 1, serviceJsonRun, &ctx);
    }
}

const StreamAutoCtx = struct {
    gpa: std.mem.Allocator,
    data: []u8,
    finder: *internal.Finder,
};

fn streamAutoRun(ctx: *StreamAutoCtx) !usize {
    ctx.data[0] ^= 1;
    defer ctx.data[0] ^= 1;
    var sink = ServiceNopSink{};
    var reader = std.Io.Reader.fixed(ctx.data);
    const result = try internal.searchSource(
        ServiceNopSink,
        ctx.gpa,
        &sink,
        &reader,
        "stream.txt",
        ctx.finder,
        .{
            .compression = .auto,
            .buffer_size = 256 * 1024,
            .max_source_bytes = bytes_64m,
            .max_request_bytes = bytes_64m,
        },
    );
    if (result.matched_lines != 1) return error.UnexpectedMatch;
    return 1;
}

const ServiceJsonCtx = struct {
    data: []u8,
    finder: *internal.Finder,
};

const NdjsonDiscardSink = struct {
    writer: *std.Io.Writer,
    pub fn event(self: *NdjsonDiscardSink, ev: internal.sink.Event) bool {
        internal.ndjson.writeEvent(self.writer, ev) catch return false;
        return true;
    }
};

fn serviceJsonRun(ctx: *ServiceJsonCtx) !usize {
    ctx.data[0] ^= 1;
    defer ctx.data[0] ^= 1;
    var out_buf: [256]u8 = undefined;
    var out: std.Io.Writer.Discarding = .init(&out_buf);
    var js = NdjsonDiscardSink{ .writer = &out.writer };
    const result = try internal.searchSourceSlice(
        NdjsonDiscardSink,
        &js,
        "slice.txt",
        ctx.data,
        ctx.finder,
        .{
            .max_source_bytes = bytes_64m,
            .max_request_bytes = bytes_64m,
            .contains = &.{"needle"},
            .filter_smart_case = true,
        },
    );
    if (result.matched_lines != 1) return error.UnexpectedMatch;
    return 1;
}

fn benchSweep(gpa: std.mem.Allocator, tracker: *BenchTracker) !void {
    const names = [_][]const u8{ "file_64KiB", "file_128KiB", "file_256KiB", "file_1MiB", "file_readall" };
    if (!tracker.wantsAny(&names)) return;

    const io = tracker.io;
    var dir = try std.Io.Dir.cwd().createDirPathOpen(io, "bench/tmp", .{});
    defer {
        dir.close(io);
        std.Io.Dir.cwd().deleteTree(io, "bench/tmp") catch {};
    }
    {
        var file = try dir.createFile(io, "sweep.txt", .{});
        defer file.close(io);
        var chunk: [1024 * 1024]u8 = undefined;
        @memset(&chunk, 'a');
        var i: usize = 63;
        while (i < chunk.len) : (i += 64) chunk[i] = '\n';
        var left: usize = sweep_body;
        while (left > 0) {
            const n = @min(left, chunk.len);
            try file.writeStreamingAll(io, chunk[0..n]);
            left -= n;
        }
        try file.writeStreamingAll(io, sweep_tail);
    }

    var file = try dir.openFile(io, "sweep.txt", .{});
    defer file.close(io);
    var sweep = Sweep{
        .gpa = gpa,
        .io = io,
        .file = file,
        .finder = try internal.Finder.init("NEEDLE", .{}),
        .buffer_size = 0,
        .file_bytes = sweep_bytes,
    };
    const sizes = [_]usize{ 64 * 1024, 128 * 1024, 256 * 1024, 1024 * 1024, sweep_bytes };
    for (sizes, names) |size, name| {
        sweep.buffer_size = size;
        try report(tracker, name, sweep_bytes, 1, fileRun, &sweep);
    }
}

const Sweep = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    file: std.Io.File,
    finder: internal.Finder,
    buffer_size: usize,
    file_bytes: u64,
};

fn fileRun(ctx: *Sweep) !usize {
    var nop = Nop{};
    const result = try internal.searchFile(
        Nop,
        ctx.gpa,
        ctx.io,
        &nop,
        ctx.file,
        "sweep.txt",
        &ctx.finder,
        .{ .buffer_size = ctx.buffer_size },
    );
    if (result.matched_lines != 1 or result.bytes_read != ctx.file_bytes) {
        std.debug.print("file buffer {d} lines {d} bytes_read {d}\n", .{
            ctx.buffer_size,
            result.matched_lines,
            result.bytes_read,
        });
        return error.UnexpectedMatch;
    }
    return 1;
}

fn benchWalk(gpa: std.mem.Allocator, tracker: *BenchTracker) !void {
    if (!tracker.wantsAny(&.{ "walk_1", "walk_4" })) return;
    const io = tracker.io;
    const hits = try prepareWalk(io);
    defer std.Io.Dir.cwd().deleteTree(io, "bench/tmp") catch {};
    var ctx = WalkCtx{ .gpa = gpa, .io = io, .hits = hits, .threads = 1 };
    try report(tracker, "walk_1", walk_bytes, @intCast(hits), walkRun, &ctx);
    ctx.threads = 4;
    try report(tracker, "walk_4", walk_bytes, @intCast(hits), walkRun, &ctx);
}

const WalkCtx = struct {
    gpa: std.mem.Allocator,
    io: std.Io,
    hits: u64,
    threads: u32,
};

fn walkRun(ctx: *WalkCtx) !usize {
    var saw = false;
    var out_buf: [64]u8 = undefined;
    var out: std.Io.Writer.Discarding = .init(&out_buf);
    const stats = try internal.parallel.run(ctx.gpa, ctx.io, .{
        .pattern = "NEEDLE",
        .roots = &.{"bench/tmp/walk"},
        .emit = .count,
        .stdout = &out.writer,
        .saw_output = &saw,
        .walk = .{ .threads = ctx.threads, .read_ignore = false },
    });
    if (stats.errors != 0 or stats.searches != walk_files or stats.matched_lines != ctx.hits or stats.bytes_searched != walk_bytes) {
        std.debug.print("walk threads {d} errors {d} searches {d} lines {d} bytes {d}\n", .{
            ctx.threads,
            stats.errors,
            stats.searches,
            stats.matched_lines,
            stats.bytes_searched,
        });
        return error.UnexpectedMatch;
    }
    return @intCast(stats.matched_lines);
}

fn prepareWalk(io: std.Io) !u64 {
    var cwd = std.Io.Dir.cwd();
    try cwd.createDirPath(io, "bench/tmp");
    try cwd.deleteTree(io, "bench/tmp/walk");
    var root = try cwd.createDirPathOpen(io, "bench/tmp/walk", .{});
    defer root.close(io);

    var made: usize = 0;
    var hits: u64 = 0;
    try writeDir(io, root, "flat", 128, &made, &hits);
    var index: usize = 0;
    while (made < walk_files) : (index += 1) {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "d{d}", .{index});
        const n = @min(walk_files - made, 32);
        try writeDir(io, root, name, n, &made, &hits);
    }
    return hits;
}

fn writeDir(
    io: std.Io,
    parent: std.Io.Dir,
    name: []const u8,
    n: usize,
    made: *usize,
    hits: *u64,
) !void {
    var dir = try parent.createDirPathOpen(io, name, .{});
    defer dir.close(io);
    var body: [walk_file_bytes]u8 = undefined;
    @memset(&body, 'a');
    var at: usize = 63;
    while (at < body.len) : (at += 64) body[at] = '\n';
    for (0..n) |i| {
        var file_name: [16]u8 = undefined;
        const file = try std.fmt.bufPrint(&file_name, "f{d:0>3}.txt", .{i});
        if (i == 0) {
            @memcpy(body[body.len - sweep_tail.len ..], sweep_tail);
            hits.* += 1;
        }
        var handle = try dir.createFile(io, file, .{});
        defer handle.close(io);
        try handle.writeStreamingAll(io, &body);
        if (i == 0) {
            @memset(body[body.len - sweep_tail.len ..], 'a');
            body[body.len - 1] = '\n';
        }
        made.* += 1;
    }
}

const Nop = struct {
    pub fn matched(self: *Nop, line: internal.Line) bool {
        _ = self;
        _ = line;
        return true;
    }
};

fn barrier() void {
    asm volatile ("" ::: .{ .memory = true });
}

fn report(
    tracker: *BenchTracker,
    name: []const u8,
    nbytes: usize,
    expect: usize,
    comptime run: anytype,
    ctx: anytype,
) !void {
    if (!tracker.wants(name)) return;
    const sample = try measure(tracker.io, nbytes, run, ctx);
    const total = expect *% @as(usize, @intCast(sample.iters));
    if (sample.iters == 0 or sample.sink != total) {
        std.debug.print("scenario {s} sink {d} iters {d} expected each {d}\n", .{
            name,
            sample.sink,
            sample.iters,
            expect,
        });
        return error.UnexpectedMatch;
    }
    tracker.record(sample.gbs);
    std.debug.print("scenario {s} bytes {d} gbs {d:.3} iters {d} sink {d}\n", .{
        name,
        nbytes,
        sample.gbs,
        sample.iters,
        sample.sink,
    });
}

/// Runs one unmeasured warmup pass, then times until >= 200 ms and >= 2 iterations have elapsed.
/// Returns throughput in GB/s (`bytes / second / 1e9`).
fn measure(io: std.Io, nbytes: usize, comptime run: anytype, ctx: anytype) !Sample {
    barrier();
    _ = try run(ctx);
    var sink: usize = 0;
    var iters: u64 = 0;
    const start = std.Io.Timestamp.now(io, .awake);
    var elapsed: i96 = 0;
    while (elapsed < 200 * std.time.ns_per_ms or iters < 2) {
        barrier();
        sink +%= try run(ctx);
        iters += 1;
        const now = std.Io.Timestamp.now(io, .awake);
        elapsed = start.durationTo(now).nanoseconds;
    }
    const bytes = @as(f64, @floatFromInt(nbytes)) * @as(f64, @floatFromInt(iters));
    const seconds = @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(std.time.ns_per_s));
    return .{
        .gbs = bytes / seconds / 1e9,
        .iters = iters,
        .sink = sink,
    };
}
