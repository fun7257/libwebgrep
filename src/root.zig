//! libwebgrep: Embeddable high-performance SIMD text and regex search engine library.
//!
//! Public functions that allocate or perform I/O accept an explicit allocator and `std.Io`.
//! Pure slice search requires neither. The library holds no mutable global state.
//! Complete caller documentation is in `docs/API.md`.

const std = @import("std");

/// Literal matching conventions: pattern count caps, byte caps, and case folding modes.
pub const matcher = @import("matcher.zig");
/// Events, lines, and result types. Borrowed slices are valid only until the callback returns.
pub const sink_mod = @import("sink.zig");
/// Search configuration and service entry points. Re-exported functions at the root are the primary API.
pub const searcher = @import("searcher.zig");

/// `earliest` selects the match that ends earliest; `leftmost_first` selects the leftmost start offset.
pub const MatchMode = matcher.MatchMode;
/// Half-open byte range `[start, end)` relative to the haystack passed to `find`.
pub const Match = matcher.Match;
/// Required literal extracted from a matcher (`bytes` and `offset_in_match`) for SIMD prefiltering.
pub const RequiredLiteral = matcher.RequiredLiteral;
/// `sensitive`, `insensitive`, or `smart`. Smart case is evaluated per pattern independently.
pub const CaseMode = matcher.CaseMode;
/// Options for constructing `Finder` or `Multi`. Pattern count and byte limits can only be lowered below hard caps.
pub const FindOptions = matcher.FindOptions;

/// Half-open byte span within a line, carrying precomputed UTF-16 code-unit endpoints.
pub const Span = sink_mod.Span;
/// A matched or context line on legacy callbacks. `bytes`, `text`, `raw`, and `matches` are valid only until the callback returns.
pub const Line = sink_mod.Line;
/// Binary detection status: `none`, `detected`, or `suppressed`.
pub const BinaryStatus = sink_mod.BinaryStatus;
/// Service entry event union: `begin`, `match`, `context`, `context_break`, `progress`, `heartbeat`, `end`, `summary`.
pub const Event = sink_mod.Event;
/// A line delivered on service entry points with `source_id`, line number, byte/UTF-16 columns, offsets, and spans.
pub const LineEvent = sink_mod.LineEvent;
/// Source completion event. Sources with zero matches still emit `begin` and `end`.
pub const EndEvent = sink_mod.EndEvent;
/// Runtime-polymorphic legacy sink wrapper. Its vtable must outlive `AnySink`.
pub const AnySink = sink_mod.AnySink;
/// Builds a vtable for a legacy sink type `S` without heap allocation.
pub const anyVtable = sink_mod.anyVtable;
/// Context-free pull iterator over a slice. `Line.bytes` borrows directly from `haystack`.
pub const SliceIter = sink_mod.SliceIter;
/// Search result returned on completion. Distinguishes matches, no matches, and per-source soft errors from fatal errors.
pub const Result = sink_mod.Result;
/// Search termination outcome: `complete`, `stopped`, `binary_quit`, or `binary_matched`.
pub const Outcome = sink_mod.Outcome;
/// Budget limit reached during search: `none`, `max_results`, `max_bytes`, `deadline`, `decompressed_bytes`, or `cancelled`.
pub const LimitHit = sink_mod.LimitHit;
/// Per-source soft error (`read_failed`), sanitized of any internal server paths.
pub const SoftError = sink_mod.SoftError;
/// Flow control returned by service event callbacks: `cont`, `pause`, or `stop`.
pub const Flow = sink_mod.Flow;
/// Final request summary emitted when the input finishes without pause or open live stream.
pub const Summary = sink_mod.Summary;
/// Periodic progress snapshot emitted at `progress_interval`.
pub const Progress = sink_mod.Progress;
/// Idle heartbeat emitted on a live stream when a read produces zero bytes.
pub const Heartbeat = sink_mod.Heartbeat;
/// Saved counters used by `resumeSourceSlice` to continue after `Flow.pause`.
pub const ResumeState = sink_mod.ResumeState;

/// Binary handling policy. Defaults to `quit` (binary inputs are skipped by default).
pub const BinaryPolicy = searcher.BinaryPolicy;
/// Input character encoding (`auto` sniffs UTF-8/UTF-16 BOM or uses `charset` hint; also `utf8`, `utf16le`, `utf16be`, `gbk`, `latin1`, `none`).
pub const Encoding = searcher.Encoding;
/// In-process streaming decompression mode: `none`, `auto`, `gzip`, `zstd`, or `xz`.
pub const Compression = searcher.Compression;
/// In-process bomb-safe streaming decompression and raw offset mapping module.
pub const decompress = @import("decompress.zig");
/// Search configuration. Service entry points populate default multi-tenant budgets when left null.
pub const SearchConfig = searcher.SearchConfig;
/// Legacy callback entry point for searching an in-memory slice without default service budgets.
pub const searchSlice = searcher.searchSlice;
/// Legacy callback entry point for searching a `std.Io.Reader`. Prefer `searchSource` for service workloads.
pub const searchReader = searcher.searchReader;
/// Service entry point: searches a `std.Io.Reader` with caller-assigned `source_id` and multi-tenant budgets.
pub const searchSource = searcher.searchSource;
/// Service entry point: searches an in-memory slice with zero heap allocation when no transcoding is needed.
pub const searchSourceSlice = searcher.searchSourceSlice;
/// Resumes searching the same slice from a previous `Flow.pause` state without re-emitting `begin`.
pub const resumeSourceSlice = searcher.resumeSourceSlice;
/// Pull-based iterator over service events for an in-memory slice.
pub const openSourcePull = searcher.openSourcePull;

test "default search configuration" {
    const cfg: SearchConfig = .{};
    try std.testing.expectEqual(SearchConfig.default_buffer_size, cfg.buffer_size);
    try std.testing.expectEqual(SearchConfig.default_max_line_len, cfg.max_line_len);
    try std.testing.expectEqual(BinaryPolicy.quit, cfg.binary);
    try std.testing.expectEqual(Encoding.auto, cfg.encoding);
    try std.testing.expect(!cfg.null_data);
    try std.testing.expectEqual(MatchMode.earliest, cfg.match_mode);
    try std.testing.expect(cfg.max_count == null);
    try std.testing.expect(cfg.max_source_bytes == null);
    try std.testing.expect(cfg.max_request_bytes == null);
    try std.testing.expect(cfg.time_budget_ns == null);
    try std.testing.expect(cfg.cancel == null);
    try std.testing.expect(!cfg.exists);
    try std.testing.expect(cfg.max_concurrency == null);
}

fn checkSearchFn(comptime F: type) !void {
    const info = @typeInfo(F);
    try std.testing.expect(info == .@"fn");
    inline for (info.@"fn".param_types) |maybe| {
        const T = maybe orelse continue;
        try std.testing.expect(T != std.Io.File);
        try std.testing.expect(T != std.Io.Dir);
        try std.testing.expect(T != *std.Io.File);
        try std.testing.expect(T != *std.Io.Dir);
    }
}

test "public search entry points accept no filesystem handles or paths" {
    try std.testing.expect(!@hasDecl(@This(), "searchFile"));
    try std.testing.expect(!@hasDecl(@This(), "parallel"));
    try std.testing.expect(!@hasDecl(@This(), "walker"));
    try checkSearchFn(@TypeOf(searchSlice));
    try checkSearchFn(@TypeOf(searchReader));
    try checkSearchFn(@TypeOf(searchSource));
    try checkSearchFn(@TypeOf(searchSourceSlice));
    try checkSearchFn(@TypeOf(resumeSourceSlice));
    try checkSearchFn(@TypeOf(openSourcePull));

    const Collect = struct {
        left: bool = false,
        right: bool = false,
        matches: u32 = 0,
        pub fn event(self: *@This(), ev: Event) bool {
            switch (ev) {
                .begin => |b| {
                    if (std.mem.eql(u8, b.source_id, "left")) self.left = true;
                    if (std.mem.eql(u8, b.source_id, "right")) self.right = true;
                },
                .match => self.matches += 1,
                else => {},
            }
            return true;
        }
    };
    var found = Collect{};
    var left = try finder.Finder.init("LEFT", .{});
    var right = try finder.Finder.init("RIGHT", .{});
    const left_result = try searchSourceSlice(Collect, &found, "left", "LEFT\n", &left, .{});
    const right_result = try searchSourceSlice(Collect, &found, "right", "RIGHT\n", &right, .{});
    try std.testing.expectEqual(sink_mod.Outcome.complete, left_result.outcome);
    try std.testing.expectEqual(sink_mod.Outcome.complete, right_result.outcome);
    try std.testing.expect(found.left);
    try std.testing.expect(found.right);
    try std.testing.expectEqual(@as(u32, 2), found.matches);
}

/// Vectorized single-byte search (`find`, `findEither`, `findAny`, `findLast`, `count`). Zero allocation; width is 16 or 32.
pub const memchr = @import("finder/memchr.zig");
/// `Finder` definition module for single-literal SIMD search.
pub const finder = @import("finder/finder.zig");
/// Single-literal SIMD finder. Pattern bytes are borrowed from the caller; empty pattern matches zero-width.
pub const Finder = finder.Finder;
/// `Multi` definition module for multi-literal OR search.
pub const multi = @import("finder/multi.zig");
/// Multi-literal OR search engine (`ByteSet`, `RarePair`, `Teddy`, `AhoCorasick`).
pub const Multi = multi.Multi;
/// `Regex` definition module for linear-time Thompson NFA search with SIMD literal prefiltering.
pub const regex = @import("regex.zig");
/// Linear-time regular expression matcher with compile size hard caps and bounded multiline windows.
pub const Regex = regex.Regex;
/// Options for constructing `Regex`: case mode, bounded multiline, `dot_all`, and instruction caps.
pub const RegexOptions = regex.RegexOptions;

test {
    _ = @import("decompress.zig");
    _ = @import("encoding.zig");
    _ = @import("matcher.zig");
    _ = @import("sink.zig");
    _ = @import("searcher.zig");
    _ = @import("regex.zig");
    _ = @import("ndjson_fixture.zig");
    _ = @import("finder/memchr.zig");
    _ = @import("finder/two_way.zig");
    _ = @import("finder/ascii.zig");
    _ = @import("finder/unicode_fold.zig");
    _ = @import("finder/frequency.zig");
    _ = @import("finder/packed_pair.zig");
    _ = @import("finder/finder.zig");
    _ = @import("finder/byteset.zig");
    _ = @import("finder/aho.zig");
    _ = @import("finder/pairs.zig");
    _ = @import("finder/multi.zig");
    if (@import("build_options").teddy != .off) {
        _ = @import("finder/teddy.zig");
        switch (@import("build_options").teddy) {
            .neon => _ = @import("finder/teddy_neon.zig"),
            .ssse3 => _ = @import("finder/teddy_ssse3.zig"),
            .avx2 => _ = @import("finder/teddy_avx2.zig"),
            .off => {},
        }
    }
}

/// Worst-case linear-time Two-Way substring finder without heap allocation.
pub const two_way = @import("finder/two_way.zig");

/// Abstract in-memory tree source interface for archive or virtual tree inputs.
pub const source = @import("source.zig");
/// Byte-oriented glob matcher supporting nested brace expansion, rule caps, and ASCII case insensitivity.
pub const walk_glob = @import("walk/glob.zig");
/// In-memory gitignore/ignore rule parser and hierarchical matcher with fine-grained switches.
pub const walk_ignore = @import("walk/ignore.zig");
/// Chase-Lev lock-free work-stealing deque for pointer elements.
pub const walk_deque = @import("walk/deque.zig");
/// Device and inode identifier helper for opened `std.Io.Dir` and `std.Io.File` handles.
pub const walk_file_id = @import("walk/file_id.zig");
/// File-type table filter supporting custom caller-injected type tables and glob expansion.
pub const walk_types = @import("walk/types.zig");
/// Batched directory entry reader over an already opened `std.Io.Dir`.
pub const walk_list = @import("walk/list_dir.zig");

test {
    _ = @import("source.zig");
    _ = @import("walk/glob.zig");
    _ = @import("walk/ignore.zig");
    _ = @import("walk/deque.zig");
    _ = @import("walk/file_id.zig");
    _ = @import("walk/types.zig");
    _ = @import("walk/list_dir.zig");
    _ = @import("walk/walker.zig");
    _ = @import("parallel.zig");
}
