//! Push-based output. Line slices point into Searcher's internal buffer or the caller's haystack, and are only valid until the callback returns.
//!
//! Sink is determined by the comptime parameter `S` of `search`. Returning false from a callback stops the current search.
//! In addition to the optional methods listed here, Searcher calls the optional
//! `pub fn binary(self: *S, offset: u64) bool` the first time it sees a NUL byte: returning false stops reading further data.
//! That method must be `pub` so `@hasDecl` can see it.

const std = @import("std");
const matcher = @import("matcher.zig");

/// Byte span of a match or context within a line, relative to `Line.bytes` / `Line.raw`.
/// `u16_start` and `u16_end` are the half-open UTF-16 code unit offsets on the lossy text, computed during scanning.
pub const Span = struct {
    start: usize,
    end: usize,
    u16_start: usize = 0,
    u16_end: usize = 0,
    /// Attached replacement text when `SearchConfig.replacement` is non-null. Valid only during the current callback.
    replacement: ?[]const u8 = null,
};

/// Flow control returned by callbacks. `bool` still means continue or stop; service entry points may also return this enum.
pub const Flow = enum {
    cont,
    pause,
    stop,
};

/// Counters needed to resume searching after a pause. Passed to `resumeSourceSlice`.
pub const ResumeState = struct {
    matched_lines: u64 = 0,
    matches: u64 = 0,
    bytes_read: u64 = 0,
    bytes_searched: u64 = 0,
    output_bytes: u64 = 0,
    results_out: u64 = 0,
    limit_count: u64 = 0,
    line_number: u64 = 1,
    started_ns: i128 = 0,
    deadline_armed: bool = false,
    skip_begin: bool = false,
};

/// Reason why the search stopped.
pub const LimitHit = enum {
    none,
    max_results,
    max_bytes,
    deadline,
    decompressed_bytes,
    cancelled,
};

/// Soft error on a single source. Contains only this tag, with no file path or syscall details.
pub const SoftError = enum {
    read_failed,
};

/// Result of a single search. Both `binary_offset` and `nul_offset` hold the absolute offset of the first NUL byte seen in the input.
/// Fatal errors are returned via the function's error union. Soft errors, matches, and non-matches are all returned as normal results and distinguished by the fields below.
pub const Result = struct {
    outcome: Outcome = .complete,
    /// Number of matching lines. Distinct from `matches`.
    matched_lines: u64 = 0,
    /// Total number of matches. A single line may contain multiple matches.
    matches: u64 = 0,
    /// Absolute offset where a NUL byte was detected, or null if none.
    binary_offset: ?u64 = null,
    /// Same as `binary_offset`.
    nul_offset: ?u64 = null,
    /// Actual bytes read. Directory search uses this for accounting instead of calling `fstat` on every file.
    bytes_read: u64 = 0,
    /// Reason why a budget or cancellation stopped the search. `none` when scanned to completion.
    limit_hit: LimitHit = .none,
    /// True if counts do not cover the entire input because a budget or cancellation stopped the scan before EOF.
    partial: bool = false,
    /// Searchable byte offset from which the next search can resume. Populated only when stopped by `max_results`.
    resume_at: ?u64 = null,
    /// Reading this source failed; the search call itself still returns normally.
    soft_error: ?SoftError = null,
    /// Callback requested a pause. Neither `end` nor `summary` has been emitted yet.
    paused: bool = false,
    /// Entire input was scanned. When false, `summary` is not emitted as a final result.
    scanned_all: bool = false,
    /// Elapsed nanoseconds from start to return. Can also be driven by a test clock.
    elapsed_ns: u64 = 0,
    /// Line bytes delivered to the caller so far.
    output_bytes: u64 = 0,
    /// Searchable bytes scanned so far.
    bytes_searched: u64 = 0,
    /// Counters for resuming after a pause. Also holds the final snapshot when not paused.
    resume_state: ResumeState = .{},
};

/// Completion reason for an input.
pub const Outcome = enum {
    complete,
    /// Sink returned false, or `max_count` was reached.
    stopped,
    binary_quit,
    binary_matched,
};

/// Binary status for the current source.
pub const BinaryStatus = enum {
    /// Not treated as binary: either no NUL was seen, or the caller requested text mode.
    none,
    /// NUL was seen; continued scanning to check for matches, but line contents are withheld.
    detected,
    /// NUL was seen; stopped reading and suppressed remaining content.
    suppressed,
};

/// A line on the service entry point. `bytes`, `text`, `raw`, and `matches` are valid only during the current callback.
pub const LineEvent = struct {
    /// Caller-assigned source identifier, opaque to the library.
    source_id: []const u8,
    /// 1-based line number, or record number in NUL-delimited mode.
    line_number: u64,
    /// 1-based byte column within `bytes`, or null if there is no match. Distinct from `u16_column`.
    column: ?u64 = null,
    /// 1-based UTF-16 column of the first match after sorting by start offset, or null if there is no match.
    u16_column: ?u64 = null,
    /// Absolute offset of the start of this line in the searchable byte stream.
    absolute_offset: u64,
    /// Offset of the start of this line in the raw (pre-transcoding / pre-decompression) byte stream. Equals `absolute_offset` when no transcoding or decompression occurred.
    raw_offset: u64 = 0,
    bytes: []const u8,
    text: []const u8 = &.{},
    raw: []const u8 = &.{},
    /// Preview text with matching spans in this line replaced when `SearchConfig.replacement` is non-null.
    /// Original `bytes` and input bytes remain unchanged. Valid only during the current callback.
    replaced: ?[]const u8 = null,
    /// Half-open byte spans relative to `bytes`, sorted by start offset.
    /// Slice `bytes` with these spans when displaying only matched fragments; there is no separate fragment output mode.
    /// The core library only reports spans and never inserts color codes or markup.
    matches: []const Span = &.{},
    truncated: bool = false,
    /// Original line content length after stripping the delimiter.
    line_len: u64 = 0,
    /// Starting offset of `bytes` within the original line content.
    window_start: u64 = 0,
    binary_status: BinaryStatus = .none,
};

/// Progress emitted during scanning at the caller-specified byte interval.
pub const Progress = struct {
    source_id: []const u8,
    bytes_searched: u64 = 0,
    /// Number of matches found so far.
    matches: u64 = 0,
    matched_lines: u64 = 0,
};

/// Idle timeout on a live stream. Neither an error nor end-of-stream.
pub const Heartbeat = struct {
    source_id: []const u8,
    bytes_searched: u64 = 0,
    matches: u64 = 0,
    matched_lines: u64 = 0,
};

/// Summary of a single request. Not emitted as a final result if the stream did not finish.
pub const Summary = struct {
    source_id: []const u8 = "",
    /// Elapsed time in nanoseconds.
    elapsed: u64 = 0,
    searches: u64 = 0,
    searches_with_match: u64 = 0,
    bytes_searched: u64 = 0,
    bytes_printed: u64 = 0,
    matched_lines: u64 = 0,
    matches: u64 = 0,
    bytes_read_raw: u64 = 0,
    sources_failed: u64 = 0,
};

/// End of a single source. Emitted even when there are no matches.
pub const EndEvent = struct {
    source_id: []const u8,
    binary_status: BinaryStatus = .none,
    binary_offset: ?u64 = null,
    matched_lines: u64 = 0,
    /// Number of matches. Always present even when 0.
    matches: u64 = 0,
    bytes_read: u64 = 0,
    outcome: Outcome = .complete,
    limit_hit: LimitHit = .none,
    partial: bool = false,
    resume_at: ?u64 = null,
    soft_error: ?SoftError = null,
};

/// Service entry point event. Invokes the callback once per event without batching multiple lines.
/// `begin`, `match`, `context`, `progress`, `end`, and `summary` carry only the source identifier.
/// Disjoint context groups emit `context_break`; idle live streams emit `heartbeat`.
pub const Event = union(enum) {
    begin: struct { source_id: []const u8 },
    match: LineEvent,
    context: LineEvent,
    /// Discontinuity between context groups, not a separator string.
    context_break: struct { source_id: []const u8 },
    progress: Progress,
    heartbeat: Heartbeat,
    end: EndEvent,
    summary: Summary,
};

/// A line delivered to a Sink.
pub const Line = struct {
    /// Line bytes used for searching. Excludes the record delimiter and, in LF mode, a single trailing `\r`.
    /// Valid only during the current callback.
    bytes: []const u8,
    /// Text with invalid UTF-8 replaced by U+FFFD. Points to `bytes` when already valid UTF-8.
    /// Valid only during the current callback. The library does not base64-encode these bytes.
    text: []const u8 = &.{},
    /// Raw bytes of this line, to which byte offsets are relative. Usually identical to `bytes`.
    /// Valid only during the current callback.
    raw: []const u8 = &.{},
    /// Preview text with matching spans in this line replaced when `SearchConfig.replacement` is non-null.
    /// Original `bytes` and input bytes remain unchanged. Valid only during the current callback.
    replaced: ?[]const u8 = null,
    /// Absolute offset of the first byte of this line in the searchable byte stream (measured in transcoded output when transcoded).
    offset: u64,
    /// Offset of the first byte of this line in the raw (pre-transcoding / pre-decompression) byte stream.
    raw_offset: u64 = 0,
    /// 1-based line number, or null when line numbers are disabled. Counts records in NUL-delimited mode.
    number: ?u64,
    /// Relative to `raw`. Ordinary context lines and inverted match lines have no match span.
    /// When inverted, pattern-matching lines emitted as context carry a span for column reporting.
    /// For overlong lines, `bytes` is a window and the span is relative to that window.
    match: ?Span,
    /// 1-based UTF-16 column of the match start, or null if there is no match.
    /// Refers to the match that discovered this line, distinct from the sorted byte column.
    u16_column: ?u64 = null,
    /// All matches on this line, relative to `bytes` and sorted by start offset. Valid only during the current callback.
    /// Used when displaying only matched fragments; the core library does not format fragments or insert color or markup.
    matches: []const Span = &.{},
    /// 1-based byte column within `bytes`, taken from the earliest start in `matches`, or null if there is no match.
    column: ?u64 = null,
    /// Binary status known at the time the line is emitted.
    binary_status: BinaryStatus = .none,
    /// True when the original line exceeds the single-line limit, in which case `bytes` is only a window.
    truncated: bool = false,
    /// Original content length after stripping the delimiter (and a single trailing CR in LF mode).
    line_len: u64 = 0,
    /// Starting offset of `bytes` within the original line content.
    window_start: u64 = 0,
};

/// Runtime-polymorphic Sink. Satisfies the comptime Sink method shape and can be passed directly to `search`.
pub const AnySink = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        begin: *const fn (*anyopaque, []const u8) bool,
        matched: *const fn (*anyopaque, Line) bool,
        context: *const fn (*anyopaque, Line) bool,
        context_break: *const fn (*anyopaque) bool,
        binary: *const fn (*anyopaque, u64) bool,
        finish: *const fn (*anyopaque, Result) bool,
    };

    pub fn begin(self: *AnySink, path: []const u8) bool {
        return self.vtable.begin(self.ctx, path);
    }

    pub fn matched(self: *AnySink, line: Line) bool {
        return self.vtable.matched(self.ctx, line);
    }

    pub fn context(self: *AnySink, line: Line) bool {
        return self.vtable.context(self.ctx, line);
    }

    pub fn contextBreak(self: *AnySink) bool {
        return self.vtable.context_break(self.ctx);
    }

    pub fn binary(self: *AnySink, offset: u64) bool {
        return self.vtable.binary(self.ctx, offset);
    }

    pub fn finish(self: *AnySink, result: Result) bool {
        return self.vtable.finish(self.ctx, result);
    }
};

/// Build a vtable for type `S`. Omitted methods default to continuing the search.
pub fn anyVtable(comptime S: type) AnySink.VTable {
    return .{
        .begin = if (@hasDecl(S, "begin")) &adapt(S, "begin") else &noopPath,
        .matched = if (@hasDecl(S, "matched")) &adapt(S, "matched") else &noopLine,
        .context = if (@hasDecl(S, "context")) &adapt(S, "context") else &noopLine,
        .context_break = if (@hasDecl(S, "contextBreak")) &adapt(S, "contextBreak") else &noopCtx,
        .binary = if (@hasDecl(S, "binary")) &adapt(S, "binary") else &noopBinary,
        .finish = if (@hasDecl(S, "finish")) &adapt(S, "finish") else &noopFinish,
    };
}

fn castSink(comptime S: type, ctx: *anyopaque) *S {
    return @ptrCast(@alignCast(ctx));
}

/// Wrap a method of `S` into a vtable function. The method name is comptime-known and its arity is fixed here.
fn adapt(comptime S: type, comptime name: []const u8) AdaptFn(S, name) {
    const types = @typeInfo(@TypeOf(@field(S, name))).@"fn".param_types;
    if (types.len == 1) {
        return struct {
            fn f(ctx: *anyopaque) bool {
                return @call(.auto, @field(S, name), .{castSink(S, ctx)});
            }
        }.f;
    }
    const Arg = types[1].?;
    return struct {
        fn f(ctx: *anyopaque, arg: Arg) bool {
            return @call(.auto, @field(S, name), .{ castSink(S, ctx), arg });
        }
    }.f;
}

fn AdaptFn(comptime S: type, comptime name: []const u8) type {
    const types = @typeInfo(@TypeOf(@field(S, name))).@"fn".param_types;
    if (types.len == 1) return fn (*anyopaque) bool;
    return fn (*anyopaque, types[1].?) bool;
}

fn noopPath(_: *anyopaque, _: []const u8) bool {
    return true;
}
fn noopLine(_: *anyopaque, _: Line) bool {
    return true;
}
fn noopCtx(_: *anyopaque) bool {
    return true;
}
fn noopBinary(_: *anyopaque, _: u64) bool {
    return true;
}
fn noopFinish(_: *anyopaque, _: Result) bool {
    return true;
}

/// Single-input, context-free pull iterator. `M` is a matcher pointer such as `*Finder`.
/// `Line.bytes` points into `haystack` and remains valid as long as `haystack` is valid; calling `next` does not invalidate previous lines.
pub fn SliceIter(comptime M: type) type {
    return struct {
        matcher: M,
        haystack: []const u8,
        pos: usize = 0,
        mode: matcher.MatchMode = .earliest,
        line_numbers: bool = false,
        numbered_at: usize = 0,
        line_no: u64 = 1,
        done: bool = false,

        const Iter = @This();

        pub fn next(self: *Iter) ?Line {
            if (self.done or self.pos > self.haystack.len) return null;
            const found = self.matcher.find(self.haystack, self.pos, self.mode) orelse {
                self.done = true;
                return null;
            };
            const start = lineStart(self.haystack, found.start);
            if (start == self.haystack.len) {
                self.done = true;
                return null;
            }
            const end = lineEnd(self.haystack, @max(found.end, start));
            if (end == start) {
                self.done = true;
                return null;
            }
            const content_end = withoutNewlineEnd(self.haystack, start, end);
            var number: ?u64 = null;
            if (self.line_numbers) {
                const memchr = @import("finder/memchr.zig");
                self.line_no += memchr.count(memchr.native_width, self.haystack, self.numbered_at, start, '\n');
                self.numbered_at = start;
                number = self.line_no;
            }
            self.pos = end;
            const mstart = found.start - start;
            const mend = @min(found.end, content_end) - start;
            const raw = self.haystack[start..content_end];
            const units = @import("encoding.zig").utf16Span(raw, mstart, mend);
            return .{
                .bytes = raw,
                .text = raw,
                .raw = raw,
                .offset = start,
                .number = number,
                .match = .{
                    .start = mstart,
                    .end = mend,
                    .u16_start = units.start,
                    .u16_end = units.end,
                },
                .u16_column = units.start + 1,
                .line_len = content_end - start,
            };
        }
    };
}

fn lineStart(haystack: []const u8, pos: usize) usize {
    const memchr = @import("finder/memchr.zig");
    const upto = @min(pos, haystack.len);
    if (memchr.findLast(memchr.native_width, haystack, 0, upto, '\n')) |i| return i + 1;
    return 0;
}

fn lineEnd(haystack: []const u8, from: usize) usize {
    const memchr = @import("finder/memchr.zig");
    if (from >= haystack.len) return haystack.len;
    if (memchr.find(memchr.native_width, haystack, from, '\n')) |i| return i + 1;
    return haystack.len;
}

fn withoutNewlineEnd(haystack: []const u8, start: usize, end: usize) usize {
    var cut = end;
    if (cut > start and haystack[cut - 1] == '\n') cut -= 1;
    if (cut > start and haystack[cut - 1] == '\r') cut -= 1;
    return cut;
}

const testing = std.testing;

test "AnySink default methods continue searching" {
    const Bare = struct {};
    const vt = anyVtable(Bare);
    var bare: Bare = .{};
    var any: AnySink = .{ .ctx = @ptrCast(&bare), .vtable = &vt };
    try testing.expect(any.begin(""));
    try testing.expect(any.contextBreak());
    try testing.expect(any.binary(0));
    try testing.expect(any.finish(.{}));
}

test "AnySink forwards calls to concrete type" {
    const Rec = struct {
        hits: u32 = 0,
        path: []const u8 = "",
        pub fn begin(self: *@This(), path: []const u8) bool {
            self.path = path;
            return true;
        }
        pub fn matched(self: *@This(), line: Line) bool {
            self.hits += @intCast(line.bytes.len);
            return false;
        }
    };
    const vt = anyVtable(Rec);
    var rec: Rec = .{};
    var any: AnySink = .{ .ctx = @ptrCast(&rec), .vtable = &vt };
    try testing.expect(any.begin("a.txt"));
    try testing.expect(!any.matched(.{
        .bytes = "ab",
        .offset = 0,
        .number = null,
        .match = null,
    }));
    try testing.expectEqualStrings("a.txt", rec.path);
    try testing.expectEqual(@as(u32, 2), rec.hits);
}
