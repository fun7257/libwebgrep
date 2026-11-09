//! [Module] search/pull.zig
//! [Layer] Layer 4 — Service Event Bridge & Pull-Based Event Iterator (`SourcePull`)
//! [Role] Adapts legacy line callbacks into structured service `Event` streams (`EventBridge`)
//!        and provides the pull-based `SourcePull` iterator (`openSourcePull`).
//! [Invariants]
//!   1. Sources with zero matches still emit `begin` and `end`.
//!   2. `summary` is emitted only when the source is completely scanned without pause or open live stream.

const std = @import("std");
const sink_mod = @import("../sink.zig");
const searcher = @import("../searcher.zig");
const cfg_mod = @import("config.zig");
const state_mod = @import("state.zig");

const SearchConfig = cfg_mod.SearchConfig;
const Event = cfg_mod.Event;
const Flow = cfg_mod.Flow;
const Line = cfg_mod.Line;
const Result = cfg_mod.Result;
const Summary = cfg_mod.Summary;
const Span = cfg_mod.Span;
const BinaryStatus = cfg_mod.BinaryStatus;
const Outcome = cfg_mod.Outcome;
const binaryStatus = cfg_mod.binaryStatus;
const liveIsClosed = state_mod.liveIsClosed;
const searchSourceSlice = searcher.searchSourceSlice;

pub fn eventFlow(inner: anytype, ev: Event) Flow {
    const Ret = @typeInfo(@TypeOf(@field(@TypeOf(inner.*), "event"))).@"fn".return_type.?;
    if (Ret == bool) return if (inner.event(ev)) .cont else .stop;
    if (Ret == Flow) return inner.event(ev);
    @compileError("event must return bool or Flow");
}

pub fn EventBridge(comptime S: type) type {
    return struct {
        inner: *S,
        source_id: []const u8,
        config: SearchConfig,
        last_flow: Flow = .cont,

        const Bridge = @This();

        pub fn control(self: *Bridge) Flow {
            return self.last_flow;
        }

        fn deliver(self: *Bridge, ev: Event) bool {
            const flow = eventFlow(self.inner, ev);
            self.last_flow = flow;
            return flow == .cont;
        }

        pub fn begin(self: *Bridge, _: []const u8) bool {
            if (self.config.continuation) |saved| if (saved.skip_begin) return true;
            return self.deliver(.{ .begin = .{ .source_id = self.source_id } });
        }

        pub fn matched(self: *Bridge, line: Line) bool {
            return self.deliver(.{ .match = lineEvent(self.source_id, line) });
        }

        pub fn context(self: *Bridge, line: Line) bool {
            return self.deliver(.{ .context = lineEvent(self.source_id, line) });
        }

        pub fn contextBreak(self: *Bridge) bool {
            return self.deliver(.{ .context_break = .{ .source_id = self.source_id } });
        }

        pub fn progress(self: *Bridge, bytes_searched: u64, match_count: u64, matched_lines: u64) bool {
            return self.deliver(.{ .progress = .{
                .source_id = self.source_id,
                .bytes_searched = bytes_searched,
                .matches = match_count,
                .matched_lines = matched_lines,
            } });
        }

        pub fn heartbeat(self: *Bridge, bytes_searched: u64, match_count: u64, matched_lines: u64) bool {
            return self.deliver(.{ .heartbeat = .{
                .source_id = self.source_id,
                .bytes_searched = bytes_searched,
                .matches = match_count,
                .matched_lines = matched_lines,
            } });
        }

        pub fn finish(self: *Bridge, result: Result) bool {
            if (result.paused) return true;
            return self.deliver(.{ .end = .{
                .source_id = self.source_id,
                .binary_status = binaryStatus(self.config, result.nul_offset),
                .binary_offset = result.binary_offset,
                .matched_lines = result.matched_lines,
                .matches = result.matches,
                .bytes_read = result.bytes_read,
                .outcome = result.outcome,
                .limit_hit = result.limit_hit,
                .partial = result.partial,
                .resume_at = result.resume_at,
                .soft_error = result.soft_error,
            } });
        }
    };
}

pub fn shouldSummarize(config: SearchConfig, result: Result) bool {
    if (result.paused or !result.scanned_all) return false;
    if (config.live and !liveIsClosed(config)) return false;
    return true;
}

pub fn makeSummary(source_id: []const u8, result: Result) Summary {
    return .{
        .source_id = source_id,
        .elapsed = result.elapsed_ns,
        .searches = 1,
        .searches_with_match = if (result.matched_lines > 0) 1 else 0,
        .bytes_searched = result.bytes_searched,
        .bytes_printed = result.output_bytes,
        .matched_lines = result.matched_lines,
        .matches = result.matches,
        .bytes_read_raw = result.bytes_read,
        .sources_failed = if (result.soft_error != null) 1 else 0,
    };
}

pub fn emitSummary(comptime S: type, sink: *S, source_id: []const u8, config: SearchConfig, result: Result) void {
    if (!shouldSummarize(config, result)) return;
    _ = eventFlow(sink, .{ .summary = makeSummary(source_id, result) });
}

/// A single event yielded by the pull iterator. Slices remain valid until `SourcePull.deinit`.
pub const PullEvent = struct {
    kind: enum { begin, match, context, context_break, progress, heartbeat, end, summary },
    source_id: []u8,
    line_number: u64 = 0,
    column: ?u64 = null,
    u16_column: ?u64 = null,
    absolute_offset: u64 = 0,
    raw_offset: u64 = 0,
    bytes: []u8 = &.{},
    replaced: ?[]u8 = null,
    spans: []Span = &.{},
    truncated: bool = false,
    line_len: u64 = 0,
    window_start: u64 = 0,
    binary_status: BinaryStatus = .none,
    binary_offset: ?u64 = null,
    outcome: Outcome = .complete,
    limit_hit: sink_mod.LimitHit = .none,
    partial: bool = false,
    resume_at: ?u64 = null,
    soft_error: ?sink_mod.SoftError = null,
    matched_lines: u64 = 0,
    matches: u64 = 0,
    bytes_read: u64 = 0,
    bytes_searched: u64 = 0,
    elapsed: u64 = 0,
    searches: u64 = 0,
    searches_with_match: u64 = 0,
    bytes_printed: u64 = 0,
    bytes_read_raw: u64 = 0,
    sources_failed: u64 = 0,

    pub fn deinit(self: *PullEvent, allocator: std.mem.Allocator) void {
        if (self.source_id.len != 0) allocator.free(self.source_id);
        if (self.bytes.len != 0) allocator.free(self.bytes);
        if (self.replaced) |r| if (r.len != 0) allocator.free(r);
        if (self.spans.len != 0) allocator.free(self.spans);
    }
};

/// Pull interface yielding `begin`, `context`, `match`, and `end` events.
/// By contrast, single-line `SliceIter` carries neither context nor source lifecycle events.
pub fn SourcePull(comptime M: type) type {
    return struct {
        allocator: std.mem.Allocator,
        matcher: M,
        source_id: []const u8,
        haystack: []const u8,
        config: SearchConfig,
        items: std.ArrayList(PullEvent) = .empty,
        index: usize = 0,
        loaded: bool = false,

        const Self = @This();

        pub fn deinit(self: *Self) void {
            for (self.items.items) |*item| item.deinit(self.allocator);
            self.items.deinit(self.allocator);
        }

        pub fn next(self: *Self) !?PullEvent {
            if (!self.loaded) {
                try self.load();
                self.loaded = true;
            }
            if (self.index >= self.items.items.len) return null;
            const ev = self.items.items[self.index];
            self.index += 1;
            return ev;
        }

        fn load(self: *Self) !void {
            const Collect = struct {
                pull: *Self,
                failed: bool = false,

                pub fn event(c: *@This(), ev: Event) bool {
                    const copied = copyPull(c.pull.allocator, ev) catch {
                        c.failed = true;
                        return false;
                    };
                    c.pull.items.append(c.pull.allocator, copied) catch {
                        var doomed = copied;
                        doomed.deinit(c.pull.allocator);
                        c.failed = true;
                        return false;
                    };
                    return true;
                }
            };
            var collect = Collect{ .pull = self };
            _ = searchSourceSlice(Collect, &collect, self.source_id, self.haystack, self.matcher, self.config) catch |err| return err;
            if (collect.failed) return error.OutOfMemory;
        }
    };
}

pub fn openSourcePull(
    allocator: std.mem.Allocator,
    matcher: anytype,
    source_id: []const u8,
    haystack: []const u8,
    config: SearchConfig,
) SourcePull(@TypeOf(matcher)) {
    return .{
        .allocator = allocator,
        .matcher = matcher,
        .source_id = source_id,
        .haystack = haystack,
        .config = config,
    };
}

pub fn copyPull(allocator: std.mem.Allocator, ev: Event) !PullEvent {
    switch (ev) {
        .begin => |b| return .{ .kind = .begin, .source_id = try allocator.dupe(u8, b.source_id) },
        .context_break => |b| return .{ .kind = .context_break, .source_id = try allocator.dupe(u8, b.source_id) },
        .progress => |p| return .{
            .kind = .progress,
            .source_id = try allocator.dupe(u8, p.source_id),
            .bytes_searched = p.bytes_searched,
            .matches = p.matches,
            .matched_lines = p.matched_lines,
        },
        .heartbeat => |h| return .{
            .kind = .heartbeat,
            .source_id = try allocator.dupe(u8, h.source_id),
            .bytes_searched = h.bytes_searched,
            .matches = h.matches,
            .matched_lines = h.matched_lines,
        },
        .end => |e| return .{
            .kind = .end,
            .source_id = try allocator.dupe(u8, e.source_id),
            .binary_status = e.binary_status,
            .binary_offset = e.binary_offset,
            .matched_lines = e.matched_lines,
            .matches = e.matches,
            .bytes_read = e.bytes_read,
            .outcome = e.outcome,
            .limit_hit = e.limit_hit,
            .partial = e.partial,
            .resume_at = e.resume_at,
            .soft_error = e.soft_error,
        },
        .summary => |s| return .{
            .kind = .summary,
            .source_id = try allocator.dupe(u8, s.source_id),
            .matched_lines = s.matched_lines,
            .matches = s.matches,
            .bytes_searched = s.bytes_searched,
            .elapsed = s.elapsed,
            .searches = s.searches,
            .searches_with_match = s.searches_with_match,
            .bytes_printed = s.bytes_printed,
            .bytes_read_raw = s.bytes_read_raw,
            .sources_failed = s.sources_failed,
        },
        .match, .context => |line| {
            const id = try allocator.dupe(u8, line.source_id);
            errdefer allocator.free(id);
            var bytes: []u8 = &.{};
            errdefer if (bytes.len != 0) allocator.free(bytes);
            if (line.bytes.len != 0) bytes = try allocator.dupe(u8, line.bytes);
            var replaced: ?[]u8 = null;
            errdefer if (replaced) |r| if (r.len != 0) allocator.free(r);
            if (line.replaced) |r| replaced = try allocator.dupe(u8, r);
            var spans: []Span = &.{};
            errdefer if (spans.len != 0) allocator.free(spans);
            if (line.matches.len != 0) spans = try allocator.dupe(Span, line.matches);
            return .{
                .kind = if (ev == .match) .match else .context,
                .source_id = id,
                .line_number = line.line_number,
                .column = line.column,
                .u16_column = line.u16_column,
                .absolute_offset = line.absolute_offset,
                .raw_offset = line.raw_offset,
                .bytes = bytes,
                .replaced = replaced,
                .spans = spans,
                .truncated = line.truncated,
                .line_len = line.line_len,
                .window_start = line.window_start,
                .binary_status = line.binary_status,
                .matched_lines = 0,
                .matches = @intCast(line.matches.len),
            };
        },
    }
}

pub fn lineEvent(source_id: []const u8, line: Line) sink_mod.LineEvent {
    const u16_column = if (line.matches.len > 0)
        @as(u64, line.matches[0].u16_start) + 1
    else
        line.u16_column;
    return .{
        .source_id = source_id,
        .line_number = line.number orelse 0,
        .column = line.column,
        .u16_column = u16_column,
        .absolute_offset = line.offset,
        .raw_offset = line.raw_offset,
        .bytes = line.bytes,
        .text = if (line.text.len == 0) line.bytes else line.text,
        .raw = if (line.raw.len == 0) line.bytes else line.raw,
        .replaced = line.replaced,
        .matches = line.matches,
        .truncated = line.truncated,
        .line_len = line.line_len,
        .window_start = line.window_start,
        .binary_status = line.binary_status,
    };
}

