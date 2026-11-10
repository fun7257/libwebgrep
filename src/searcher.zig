//! [Module] searcher.zig
//! [Layer] Layer 4 — Search Engine Orchestrator & Public Service Entry Points
//! [Role] Top-level orchestrator exposing `searchSlice`, `searchReader`, `searchFile`, `searchSourceSlice`,
//!        `resumeSourceSlice`, `searchSource`, `resumeSource`, and `openSourcePull`.
//! [Invariants]
//!   1. All search state is stack- or call-scoped; zero global mutable state exists.
//!   2. Service entry points (`searchSource*`, `resumeSource*`, `openSourcePull`) never accept filesystem paths
//!      or `std.Io.File` / `std.Io.Dir` handles, and enforce default multi-tenant budgets when left null.
//! [HotPath] Dispatches directly to `pipeline.searchPrepared` (in-memory slices) or `pipeline.drive` (streaming readers).

const std = @import("std");
const build_options = @import("build_options");
const platform = @import("io/platform.zig");
const matcher_mod = @import("matcher.zig");
const sink_mod = @import("sink.zig");

pub const config_mod = @import("search/config.zig");
pub const state_mod = @import("search/state.zig");
pub const context_ring_mod = @import("search/context_ring.zig");
pub const format_mod = @import("search/format.zig");
pub const line_matcher_mod = @import("search/line_matcher.zig");
pub const long_line_mod = @import("search/long_line.zig");
pub const pull_mod = @import("search/pull.zig");
pub const pipeline_mod = @import("search/pipeline.zig");

pub const Encoding = config_mod.Encoding;
pub const Compression = config_mod.Compression;
pub const BinaryPolicy = config_mod.BinaryPolicy;
pub const SearchConfig = config_mod.SearchConfig;
pub const Scratch = config_mod.Scratch;
pub const Outcome = config_mod.Outcome;
pub const Result = config_mod.Result;
pub const Line = config_mod.Line;
pub const Span = config_mod.Span;
pub const BinaryStatus = config_mod.BinaryStatus;
pub const Event = config_mod.Event;
pub const LineEvent = config_mod.LineEvent;
pub const EndEvent = config_mod.EndEvent;
pub const Flow = config_mod.Flow;
pub const Summary = config_mod.Summary;
pub const Progress = config_mod.Progress;
pub const Heartbeat = config_mod.Heartbeat;
pub const ResumeState = config_mod.ResumeState;
pub const SliceError = config_mod.SliceError;
pub const ReadError = config_mod.ReadError;
pub const PullEvent = pull_mod.PullEvent;
pub const SourcePull = pull_mod.SourcePull;
pub const openSourcePull = pull_mod.openSourcePull;
pub const ReaderPull = pull_mod.ReaderPull;
pub const openReaderPull = pull_mod.openReaderPull;

const serviceConfig = config_mod.serviceConfig;
const bufferWindow = config_mod.bufferWindow;
const resetStats = state_mod.resetStats;
const EventBridge = pull_mod.EventBridge;
const emitSummary = pull_mod.emitSummary;
const materialize = pipeline_mod.materialize;
const searchPrepared = pipeline_mod.searchPrepared;
const drive = pipeline_mod.drive;

/// Searches `haystack` without copying input bytes and without allocating when no transcoding or decompression is needed.
/// `name` is passed only to legacy `begin`. The service entry point is `searchSourceSlice`.
pub fn searchSlice(
    comptime S: type,
    sink: *S,
    haystack: []const u8,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) SliceError!Result {
    matcher_mod.validateMatcher(@TypeOf(matcher));
    var prepared = try materialize(haystack, config);
    defer prepared.deinit();
    var result = try searchPrepared(S, sink, &prepared, name, matcher, config);
    if (prepared.owned.len != 0 or prepared.transformed) result.bytes_read = haystack.len;
    return result;
}

/// Legacy callback entry point that searches from `reader`. Short reads are treated as EOF. The buffer is owned exclusively by this call on the current thread and freed upon return.
/// `name` is passed only to legacy `begin`. The service entry point is `searchSource`.
pub fn searchReader(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    reader: *std.Io.Reader,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) ReadError!Result {
    matcher_mod.validateMatcher(@TypeOf(matcher));
    resetStats(matcher);
    return drive(S, allocator, sink, matcher, config, name, struct {
        fn read(ctx: *anyopaque, dest: []u8) ReadError!usize {
            const r: *std.Io.Reader = @ptrCast(@alignCast(ctx));
            return r.readSliceShort(dest);
        }
    }.read, reader);
}

/// Reads from an already opened file owned by the caller; does not accept a file path.
/// Uses `readPositional` by default. Window mapping is compiled in only when enabled via build options and is not used in default builds.
/// Not exported from `src/root.zig`. The service entry points are `searchSource` and `searchSourceSlice`.
pub fn searchFile(
    comptime S: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: *S,
    file: std.Io.File,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) ReadError!Result {
    matcher_mod.validateMatcher(@TypeOf(matcher));
    resetStats(matcher);
    if (comptime build_options.window_map) {
        const window_map = @import("io/window_map.zig");
        if (try window_map.open(io, file, bufferWindow(config))) |opened| {
            var ctx = opened;
            defer ctx.close();
            return drive(S, allocator, sink, matcher, config, name, window_map.readBytes, &ctx);
        }
    }
    platform.adviseSequentialFile(file);
    const Ctx = struct { io: std.Io, file: std.Io.File, offset: u64 = 0 };
    var ctx = Ctx{ .io = io, .file = file };
    return drive(S, allocator, sink, matcher, config, name, struct {
        fn read(raw: *anyopaque, dest: []u8) ReadError!usize {
            const c: *Ctx = @ptrCast(@alignCast(raw));
            var iov = [_][]u8{dest};
            const n = try c.file.readPositional(c.io, &iov, c.offset);
            c.offset += n;
            return n;
        }
    }.read, &ctx);
}

/// Service entry point: searches an in-memory byte slice.
/// `source_id` is assigned by the caller and opaque to the library.
/// Line numbers start at 1 (or count records in NUL-delimited mode).
/// `S` provides `pub fn event(self: *S, ev: Event) bool` or returns `Flow`.
/// Returning false or `.stop` stops the search; `.pause` pauses so `resumeSourceSlice` can continue later.
/// Line bytes and match spans are valid only during the callback, which is invoked once per event.
/// Emits `summary` after the input is completely scanned; omitted when incomplete, paused, or on an open live stream.
pub fn searchSourceSlice(
    comptime S: type,
    sink: *S,
    source_id: []const u8,
    haystack: []const u8,
    matcher: anytype,
    config: SearchConfig,
) SliceError!Result {
    const cfg = serviceConfig(config);
    var bridge = EventBridge(S){
        .inner = sink,
        .source_id = source_id,
        .config = cfg,
    };
    const result = try searchSlice(EventBridge(S), &bridge, haystack, "", matcher, cfg);
    emitSummary(S, sink, source_id, cfg, result);
    return result;
}

/// Resumes searching the same in-memory slice from where it was previously paused, without re-emitting `begin`.
pub fn resumeSourceSlice(
    comptime S: type,
    sink: *S,
    source_id: []const u8,
    haystack: []const u8,
    matcher: anytype,
    config: SearchConfig,
    previous: Result,
) SliceError!Result {
    var saved = previous.resume_state;
    saved.skip_begin = true;
    var cfg = config;
    cfg.resume_from = previous.resume_at orelse 0;
    cfg.continuation = &saved;
    return searchSourceSlice(S, sink, source_id, haystack, matcher, cfg);
}

/// Service entry point: searches from a reader. Unless marked as a live stream, short reads are treated as EOF.
/// `source_id` is assigned by the caller and opaque to the library.
/// Line numbers start at 1 (or count records in NUL-delimited mode).
/// `S` provides `pub fn event(self: *S, ev: Event) bool` or returns `Flow`.
/// Returning false or `.stop` stops the search; `.pause` pauses it.
/// Line bytes and match spans are valid only during the callback, which is invoked once per event.
/// Emits `summary` after the input is completely scanned; omitted when incomplete, paused, or on an open live stream.
pub fn searchSource(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    reader: *std.Io.Reader,
    source_id: []const u8,
    matcher: anytype,
    config: SearchConfig,
) ReadError!Result {
    const cfg = serviceConfig(config);
    var bridge = EventBridge(S){
        .inner = sink,
        .source_id = source_id,
        .config = cfg,
    };
    const result = try searchReader(EventBridge(S), allocator, &bridge, reader, "", matcher, cfg);
    emitSummary(S, sink, source_id, cfg, result);
    return result;
}

/// Resumes searching from a reader after a previous pause, without re-emitting `begin`.
pub fn resumeSource(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    reader: *std.Io.Reader,
    source_id: []const u8,
    matcher: anytype,
    config: SearchConfig,
    previous: Result,
) ReadError!Result {
    var saved = previous.resume_state;
    saved.skip_begin = true;
    var cfg = config;
    cfg.resume_from = previous.resume_at orelse 0;
    cfg.continuation = &saved;
    return searchSource(S, allocator, sink, reader, source_id, matcher, cfg);
}

test {
    _ = config_mod;
    _ = state_mod;
    _ = context_ring_mod;
    _ = format_mod;
    _ = line_matcher_mod;
    _ = long_line_mod;
    _ = pull_mod;
    _ = pipeline_mod;
    _ = @import("search/tests.zig");
}
