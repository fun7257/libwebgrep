//! [Module] search/config.zig
//! [Layer] Layer 4 — Search Engine Configuration & Budget Validation
//! [Role] Defines `SearchConfig`, `BinaryPolicy`, `SliceError`, `ReadError`, and multi-tenant
//!        budget/context limit validation helpers.
//! [Invariants]
//!   1. Caller-supplied caps can only tighten limits below server hard caps; exceeding a hard cap returns `BudgetExceeded` or `ContextLinesExceeded`.
//!   2. Service entry points (`serviceConfig`) populate default multi-tenant budgets when left null.

const std = @import("std");
const decompress = @import("../codec/decompress.zig");
const encoding = @import("../codec/encoding.zig");
const matcher_mod = @import("../matcher.zig");
const memchr = @import("../finder/memchr.zig");
const regex_mod = @import("../regex.zig");
const sink_mod = @import("../sink.zig");

pub const Encoding = encoding.Encoding;
pub const Compression = decompress.Compression;

pub const BinaryPolicy = enum {
    /// Skip: stop reading as soon as a NUL byte is encountered. This is the default.
    quit,
    /// Continue searching until it is known whether a match exists, but withhold line contents.
    report,
    /// Treat as text; do not treat NUL bytes as binary.
    none,
};

pub const SearchConfig = struct {
    /// Initial chunk size. 1 MiB is the fastest of the four tiers on a 128 MiB file (see `BENCHMARKS.md`). Defaults to 1 MiB.
    pub const default_buffer_size: usize = 1024 * 1024;
    /// Single-line byte limit. The read buffer does not exceed this value plus one newline byte; longer lines use a sliding window.
    pub const default_max_line_len: usize = 2 * 1024 * 1024;
    /// Hard cap on context line count. Callers may lower the effective limit, but cannot exceed this value.
    pub const context_lines_hard_cap: u32 = 10;
    /// Hard cap on single-line byte length. Callers may override `max_line_len` up to this value.
    pub const max_line_len_hard_cap: usize = 8 * 1024 * 1024;
    /// Default scan limit for service entry points when unspecified. Legacy entry points remain unlimited unless specified by the caller.
    pub const default_max_source_bytes: u64 = 16 * 1024 * 1024;
    pub const max_source_bytes_hard_cap: u64 = 64 * 1024 * 1024;
    pub const default_max_request_bytes: u64 = 16 * 1024 * 1024;
    pub const max_request_bytes_hard_cap: u64 = 64 * 1024 * 1024;
    pub const default_time_budget_ns: u64 = 30 * std.time.ns_per_s;
    pub const max_time_budget_ns: u64 = 120 * std.time.ns_per_s;
    pub const default_max_output_bytes: u64 = 1024 * 1024;
    pub const max_output_bytes_hard_cap: u64 = 8 * 1024 * 1024;
    pub const default_max_decode_bytes: usize = 4 * 1024 * 1024;
    pub const max_decode_bytes_hard_cap: usize = 8 * 1024 * 1024;
    pub const default_max_queued_event_bytes: usize = default_max_line_len;
    pub const max_queued_event_bytes_hard_cap: usize = max_line_len_hard_cap;
    pub const default_max_before_bytes: usize = context_lines_hard_cap * default_max_line_len;
    pub const max_before_bytes_hard_cap: usize = context_lines_hard_cap * max_line_len_hard_cap;

    line_numbers: bool = false,
    invert: bool = false,
    /// Symmetric context line count. When `before` or `after` is non-null, that side uses its explicit value instead.
    context: u32 = 0,
    /// Null means fall back to `context`.
    before: ?u32 = null,
    /// Null means fall back to `context`.
    after: ?u32 = null,
    /// The service layer may set a context line limit lower than the hard cap. Values above the hard cap are clamped to the hard cap.
    max_context_lines: ?u32 = null,
    /// Maximum number of matching lines to report for this input. Null means unlimited.
    /// Only hits found by the main loop count toward this limit. Additional matching lines promoted inside an `-A` after-context window do not consume quota,
    /// though they still invoke `matched` (so counting printers include them, matching ripgrep 15).
    /// Once the limit is reached, no further chunks are read; after-context lines already in the buffer are still emitted.
    max_count: ?u64 = null,
    /// Whole-word matching. Only checks whether the byte immediately outside the match is an ASCII word character (alphanumeric or underscore).
    /// This is a half-boundary check: `-2` matches `(-2)`, but not `x-2` or `-2y`.
    /// Ignored when `whole_line` is also enabled.
    whole_word: bool = false,
    /// Whole-line matching. After stripping LF and a single preceding CR, the entire line content must match one of the patterns.
    whole_line: bool = false,
    /// Every byte slice listed here must appear in the line content for the line to be emitted (exact byte comparison unless `filter_case_insensitive` is set). Empty means no extra requirement.
    contains: []const []const u8 = &.{},
    /// None of the byte slices listed here may appear in the line content (exact byte comparison unless `filter_case_insensitive` is set). Independent of `invert`.
    excludes: []const []const u8 = &.{},
    /// When true, `contains` and `excludes` match using ASCII case-insensitive comparison.
    filter_case_insensitive: bool = false,
    /// When true, each filter in `contains` and `excludes` uses smart-case (case-insensitive unless the filter itself contains an ASCII uppercase byte).
    filter_smart_case: bool = false,
    /// Compiled regular expressions that must all match within the line content for the line to be emitted.
    contains_regexes: []const regex_mod.Regex = &.{},
    /// Compiled regular expressions that must not match within the line content.
    excludes_regexes: []const regex_mod.Regex = &.{},
    /// Invoked when `max_count` matching lines are reached to close the upstream source. Omitted if null.
    close_input: ?*const fn (?*anyopaque) void = null,
    close_ctx: ?*anyopaque = null,
    binary: BinaryPolicy = .quit,
    /// Delimit records by NUL. LF inside a record does not break lines, and NUL is not treated as a binary signal.
    null_data: bool = false,
    /// Sniff for a BOM at the start of the stream by default. `.none` disables sniffing and transcoding.
    encoding: Encoding = .auto,
    /// Optional HTTP Content-Type or WHATWG charset hint (e.g., `"gbk"`, `"text/plain; charset=gbk"`).
    /// Used to transcode when `encoding == .auto` and no BOM is present at the start of the stream.
    charset: ?[]const u8 = null,
    /// In-process streaming decompression mode (`.none`, `.auto`, `.gzip`, `.zstd`, `.xz`).
    compression: Compression = .none,
    /// Maximum allowed decompression expansion ratio (`decompressed_bytes / raw_bytes`); null uses the default of 100. Exceeding this records `LimitHit.decompressed_bytes`.
    max_compression_ratio: ?u64 = null,
    /// Used when a slice requires transcoding or lossy text does not fit in the stack buffer. Streaming search uses the allocator passed to the function.
    decode_allocator: ?std.mem.Allocator = null,
    buffer_size: usize = default_buffer_size,
    max_line_len: usize = default_max_line_len,
    match_mode: matcher_mod.MatchMode = .earliest,
    /// When non-null, reuses this buffer across calls and writes back any reallocated slice. When null, allocates and frees internally per call.
    scratch: ?*[]u8 = null,
    /// When non-null and set to true, stops before the next chunk begins. Used by directory traversal for early termination.
    /// Not a cancellation token: does not close upstream or set `limit_hit = cancelled`.
    stop: ?*const std.atomic.Value(bool) = null,
    /// Maximum bytes to scan from this source. Stops reading once reached. Null means legacy entry points impose no per-source cap.
    max_source_bytes: ?u64 = null,
    /// Maximum bytes to scan across this request. Enforced alongside `max_source_bytes`; whichever is reached first stops the scan.
    max_request_bytes: ?u64 = null,
    /// Request-level cap on emitted matching lines. When reached, the `end` event carries `resume_at`.
    /// Unlike `max_count`, which caps lines for a single source without a resume offset.
    max_results: ?u64 = null,
    /// Resume scanning from this byte offset in the searchable stream. Bytes before this offset produce no matches.
    resume_from: u64 = 0,
    /// Cumulative byte cap across emitted line events (both matches and context), including windowed bytes.
    max_output_bytes: ?u64 = null,
    /// Maximum allowed duration in nanoseconds from the start of the search. Null means unlimited on legacy entry points.
    time_budget_ns: ?u64 = null,
    /// When non-null, replaces the monotonic clock. Used by tests to deterministically assert deadline expiration.
    clock: ?*const fn (?*anyopaque) i128 = null,
    clock_ctx: ?*anyopaque = null,
    /// Cancellation token. When set, stops the search and closes the upstream source.
    cancel: ?*const std.atomic.Value(bool) = null,
    /// Decompressed bytes already accounted for prior to this search.
    decompressed_bytes: u64 = 0,
    /// Decompressed byte cap. Reaching this sets `limit_hit = decompressed_bytes`.
    max_decompressed_bytes: ?u64 = null,
    /// Byte cap for the before-context ring buffer. Null uses the hard cap.
    max_before_bytes: ?usize = null,
    /// Byte cap for the decode input buffer. Null uses the hard cap.
    max_decode_bytes: ?usize = null,
    /// Byte cap for a single pending line event awaiting callback delivery. Synchronous callbacks do not queue multiple events.
    max_queued_event_bytes: ?usize = null,
    /// Caller-injected concurrency cap. Single-input search neither spawns threads nor modifies this value.
    max_concurrency: ?u32 = null,
    /// Existence query: returns and closes upstream upon finding the first match. Distinct from listing matching sources.
    exists: bool = false,
    /// Sources-without-match query: stops scanning this source upon the first match without emitting any lines.
    /// Distinct from `invert`, which emits every line that does not match the pattern.
    files_without_match: bool = false,
    /// Emit a `progress` event every time this many searchable bytes are scanned. Null or 0 disables progress events.
    progress_interval: ?u64 = null,
    /// Marks the input as a live stream: a 0-byte read indicates idle rather than error or EOF.
    live: bool = false,
    /// Emit a `heartbeat` event when a live stream remains idle for at least this duration.
    idle_timeout_ns: ?u64 = null,
    /// Once set, the next 0-byte read on a live stream is treated as EOF.
    live_closed: ?*const std.atomic.Value(bool) = null,
    /// Continuation state for resuming after a pause, populated by `resumeSourceSlice`.
    continuation: ?*const sink_mod.ResumeState = null,
    /// For ordered inputs, immediately stop and close upstream upon encountering a non-matching line after the first match.
    stop_on_nonmatch: bool = false,
    /// Full-text highlighting mode: emit all lines, delivering non-matching lines as context events and matching lines as match events.
    passthru: bool = false,
    /// Read-only replacement preview template. When non-null, populates `Span.replacement` and `Line.replaced` / `LineEvent.replaced` without modifying the input.
    replacement: ?[]const u8 = null,
    /// Diagnostic logging callback. Messages may include file paths, whereas returned errors never do. The library never writes these messages to a terminal.
    log: ?*const fn (?*anyopaque, []const u8) void = null,
    log_ctx: ?*anyopaque = null,
};

pub const Outcome = sink_mod.Outcome;
pub const Result = sink_mod.Result;
pub const Line = sink_mod.Line;
pub const Span = sink_mod.Span;
pub const BinaryStatus = sink_mod.BinaryStatus;
pub const Event = sink_mod.Event;
pub const LineEvent = sink_mod.LineEvent;
pub const EndEvent = sink_mod.EndEvent;
pub const Flow = sink_mod.Flow;
pub const Summary = sink_mod.Summary;
pub const Progress = sink_mod.Progress;
pub const Heartbeat = sink_mod.Heartbeat;
pub const ResumeState = sink_mod.ResumeState;

pub const SliceError = error{
    ContextLinesExceeded,
    OutOfMemory,
    DecodeLimit,
    BufferLimit,
    BudgetExceeded,
};
pub const ReadError = error{
    OutOfMemory,
    ReadFailed,
    ContextLinesExceeded,
    DecodeLimit,
    BufferLimit,
    BudgetExceeded,
} || std.Io.File.ReadPositionalError;

pub const width = memchr.native_width;


pub fn serviceConfig(config: SearchConfig) SearchConfig {
    var cfg = config;
    cfg.line_numbers = true;
    if (cfg.max_source_bytes == null) cfg.max_source_bytes = SearchConfig.default_max_source_bytes;
    if (cfg.max_request_bytes == null) cfg.max_request_bytes = SearchConfig.default_max_request_bytes;
    if (cfg.time_budget_ns == null) cfg.time_budget_ns = SearchConfig.default_time_budget_ns;
    if (cfg.max_output_bytes == null) cfg.max_output_bytes = SearchConfig.default_max_output_bytes;
    if (cfg.max_decode_bytes == null) cfg.max_decode_bytes = SearchConfig.default_max_decode_bytes;
    if (cfg.max_queued_event_bytes == null) {
        const want = @max(cfg.max_line_len, SearchConfig.default_max_queued_event_bytes);
        cfg.max_queued_event_bytes = @min(want, SearchConfig.max_queued_event_bytes_hard_cap);
    }
    if (cfg.max_before_bytes == null) {
        const need = beforeContextCapacity(cfg);
        const want = @max(need, SearchConfig.default_max_before_bytes);
        cfg.max_before_bytes = @min(want, SearchConfig.max_before_bytes_hard_cap);
    }
    return cfg;
}


pub fn scanCap(config: SearchConfig) ?u64 {
    var cap: ?u64 = null;
    if (config.max_source_bytes) |n| cap = n;
    if (config.max_request_bytes) |n| cap = if (cap) |cur| @min(cur, n) else n;
    return cap;
}


pub fn decodeCap(config: SearchConfig) usize {
    return config.max_decode_bytes orelse SearchConfig.max_decode_bytes_hard_cap;
}


pub fn validateBudgets(config: SearchConfig) error{ ContextLinesExceeded, BudgetExceeded, BufferLimit }!void {
    try rejectWideContext(config);
    if (config.max_line_len > SearchConfig.max_line_len_hard_cap) return error.BudgetExceeded;
    if (config.max_source_bytes) |n| if (n > SearchConfig.max_source_bytes_hard_cap) return error.BudgetExceeded;
    if (config.max_request_bytes) |n| if (n > SearchConfig.max_request_bytes_hard_cap) return error.BudgetExceeded;
    if (config.time_budget_ns) |n| if (n > SearchConfig.max_time_budget_ns) return error.BudgetExceeded;
    if (config.max_output_bytes) |n| if (n > SearchConfig.max_output_bytes_hard_cap) return error.BudgetExceeded;
    if (config.max_decode_bytes) |n| if (n > SearchConfig.max_decode_bytes_hard_cap) return error.BudgetExceeded;
    if (config.max_queued_event_bytes) |n| if (n > SearchConfig.max_queued_event_bytes_hard_cap) return error.BudgetExceeded;
    if (config.max_before_bytes) |n| if (n > SearchConfig.max_before_bytes_hard_cap) return error.BudgetExceeded;
    if (config.max_decompressed_bytes) |n| if (n > SearchConfig.max_source_bytes_hard_cap) return error.BudgetExceeded;
    if (config.max_compression_ratio) |r| if (r == 0 or r > decompress.max_compression_ratio_hard_cap) return error.BudgetExceeded;
    const before_cap = config.max_before_bytes orelse SearchConfig.max_before_bytes_hard_cap;
    if (beforeContextCapacity(config) > before_cap) return error.BufferLimit;
}


pub fn bufferWindow(config: SearchConfig) usize {
    if (config.buffer_size == 0) return SearchConfig.default_buffer_size;
    return config.buffer_size;
}

pub fn recordSep(config: SearchConfig) u8 {
    return if (config.null_data) 0 else '\n';
}

/// NUL is treated as a binary signal only when splitting lines on LF and not in NUL-delimited record mode.
pub fn watchesBinary(config: SearchConfig) bool {
    return config.binary != .none and !config.null_data;
}


pub fn binaryStatus(config: SearchConfig, nul: ?u64) sink_mod.BinaryStatus {
    if (nul == null or !watchesBinary(config)) return .none;
    return if (config.binary == .quit) .suppressed else .detected;
}


pub fn contextLineLimit(config: SearchConfig) u32 {
    const hard = SearchConfig.context_lines_hard_cap;
    return @min(config.max_context_lines orelse hard, hard);
}

pub fn rejectWideContext(config: SearchConfig) error{ContextLinesExceeded}!void {
    const limit = contextLineLimit(config);
    if (config.context > limit) return error.ContextLinesExceeded;
    if (config.before) |n| if (n > limit) return error.ContextLinesExceeded;
    if (config.after) |n| if (n > limit) return error.ContextLinesExceeded;
}

pub fn beforeCount(config: SearchConfig) u32 {
    return config.before orelse config.context;
}

pub fn afterCount(config: SearchConfig) u32 {
    return config.after orelse config.context;
}

pub fn beforeContextCapacity(config: SearchConfig) usize {
    return std.math.mul(usize, @as(usize, beforeCount(config)), config.max_line_len) catch std.math.maxInt(usize);
}

pub fn lineHoldLimit(config: SearchConfig) usize {
    return config.max_line_len + 1;
}

