//! [Module] c_api_ext.zig
//! [Layer] Layer 6 — Extended C ABI Exports (`F4`, Functions 21–52)
//! [Role] Exports 32 additional C ABI functions (`callconv(.c)`) matching `include/webgrep.h`:
//!        atomic cancellation tokens, regex captures & named group lookup, RandomAccess positional
//!        search/probe, pull-mode iterators, streaming archive reader, N-gram Bloom filters,
//!        seekable Zstd tables, and indexed Gzip random access.

const std = @import("std");
const api = @import("c_api.zig");
const matcher_mod = @import("matcher.zig");
const regex_mod = @import("regex.zig");
const sink_mod = @import("sink.zig");
const searcher = @import("searcher.zig");
const config_mod = @import("search/config.zig");
const pull_mod = @import("search/pull.zig");
const state_mod = @import("search/state.zig");
const archive_mod = @import("codec/archive.zig");
const decompress_mod = @import("codec/decompress.zig");
const probe_mod = @import("probe.zig");
const tree_mod = @import("search/tree.zig");
const bloom_mod = @import("finder/bloom.zig");
const seekable_mod = @import("codec/seekable.zig");

const c_alloc = api.c_alloc;

// ============================================================================
// Additional Opaque Handles & Extern Structs
// ============================================================================

pub const webgrep_pull_t = opaque {};
pub const webgrep_bloom_t = opaque {};
pub const webgrep_zstd_seek_table_t = opaque {};
pub const webgrep_gzip_index_t = opaque {};
pub const webgrep_resume_state_t = opaque {};

pub const WEBGREP_FLOW_CONT: c_int = 0;
pub const WEBGREP_FLOW_STOP: c_int = 1;
pub const WEBGREP_FLOW_PAUSE: c_int = 2;
pub const WEBGREP_FLOW_SKIP_TO: c_int = 3;

pub const webgrep_flow_t = extern struct {
    action: c_int = WEBGREP_FLOW_CONT,
    skip_to_offset: u64 = 0,
};

pub const webgrep_flow_line_cb = ?*const fn (
    ev: *const api.webgrep_line_event_t,
    userdata: ?*anyopaque,
    out_flow: *webgrep_flow_t,
) callconv(.c) void;

pub const WEBGREP_MAX_CAPTURE_GROUPS: usize = 32;

pub const webgrep_capture_group_t = extern struct {
    start: usize = 0,
    end: usize = 0,
    matched: u8 = 0,
};

pub const webgrep_captures_t = extern struct {
    full: webgrep_capture_group_t = .{},
    groups: [WEBGREP_MAX_CAPTURE_GROUPS]webgrep_capture_group_t = @splat(.{}),
    group_count: usize = 0,
};

pub const webgrep_bloom_config_t = extern struct {
    bit_count: u32 = 16384,
    num_hashes: u8 = 3,
    ngram_len: u8 = 3,
    ascii_lower: u8 = 1,
};

pub const webgrep_read_at_cb = ?*const fn (
    offset: u64,
    buf: [*c]u8,
    cap: usize,
    out_n: [*c]usize,
    userdata: ?*anyopaque,
) callconv(.c) c_int;

// ============================================================================
// Internal Boxes & I/O Adapters
// ============================================================================

const CRandomAccessAdapter = struct {
    cb: *const fn (u64, [*c]u8, usize, [*c]usize, ?*anyopaque) callconv(.c) c_int,
    userdata: ?*anyopaque,
    size: ?u64 = null,
    failed: bool = false,

    fn randomAccess(self: *CRandomAccessAdapter) probe_mod.RandomAccess {
        return .{
            .ctx = self,
            .read_at = readAtFn,
            .size = self.size,
        };
    }

    fn readAtFn(raw: ?*anyopaque, offset: u64, dest: []u8) anyerror!usize {
        const self: *CRandomAccessAdapter = @ptrCast(@alignCast(raw.?));
        if (dest.len == 0) return 0;
        var n: usize = 0;
        const rc = self.cb(offset, dest.ptr, dest.len, &n, self.userdata);
        if (rc != 0 or n > dest.len) {
            self.failed = true;
            return error.ReadFailed;
        }
        return n;
    }
};

const CStreamIoReader = struct {
    reader: std.Io.Reader = undefined,
    cb: *const fn ([*c]u8, usize, [*c]usize, ?*anyopaque) callconv(.c) c_int,
    userdata: ?*anyopaque,
    failed: bool = false,
    buf: [16384]u8 = undefined,

    const vtable: std.Io.Reader.VTable = .{
        .stream = streamFn,
    };

    fn initInPlace(
        self: *CStreamIoReader,
        cb: *const fn ([*c]u8, usize, [*c]usize, ?*anyopaque) callconv(.c) c_int,
        userdata: ?*anyopaque,
    ) void {
        self.cb = cb;
        self.userdata = userdata;
        self.failed = false;
        self.reader = .{
            .vtable = &vtable,
            .buffer = &self.buf,
            .seek = 0,
            .end = 0,
        };
    }

    fn streamFn(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *CStreamIoReader = @fieldParentPtr("reader", r);
        const dest = w.writableSliceGreedy(1) catch return error.WriteFailed;
        const max_want = limit.minInt(dest.len);
        if (max_want == 0) return 0;
        var n: usize = 0;
        const rc = self.cb(dest.ptr, max_want, &n, self.userdata);
        if (rc != 0 or n > max_want) {
            self.failed = true;
            return error.ReadFailed;
        }
        if (n == 0) return error.EndOfStream;
        w.advance(n);
        return n;
    }
};

const PullBox = struct {
    filter_bridge: api.CLineFilterBridge = undefined,
    cfg_guard: api.ConfigGuard = .{},
    c_reader: CStreamIoReader = undefined,
    kind: union(enum) {
        slice: pull_mod.SourcePull(*const matcher_mod.AnyMatcher),
        reader: pull_mod.ReaderPull(*const matcher_mod.AnyMatcher),
    } = undefined,
    cur_spans: std.ArrayList(api.webgrep_span_t) = .empty,
    summary: api.webgrep_summary_t = .{},
    had_soft_error: bool = false,
    saw_decompressed_limit: bool = false,
    eof_reached: bool = false,

    fn deinitAndFree(self: *PullBox) void {
        switch (self.kind) {
            .slice => |*sp| sp.deinit(),
            .reader => |*rp| rp.deinit(),
        }
        self.cur_spans.deinit(c_alloc);
        self.cfg_guard.deinit();
        c_alloc.destroy(self);
    }
};

const BloomBox = struct {
    bloom: bloom_mod.NgramBloom,
};

const ZstdSeekTableBox = struct {
    table: seekable_mod.ZstdSeekTable,
};

const GzipIndexBox = struct {
    index: seekable_mod.GzipIndex,
};

fn mapReadSearchError(err: config_mod.ReadError, read_failed: bool) c_int {
    if (read_failed) return api.WEBGREP_ERR_IO;
    return switch (err) {
        error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
        error.ContextLinesExceeded,
        error.DecodeLimit,
        error.BufferLimit,
        error.BudgetExceeded,
        => api.WEBGREP_ERR_BUDGET_EXCEEDED,
        else => api.WEBGREP_ERR_IO,
    };
}

fn finishSearchResult(
    out_summary: ?*api.webgrep_summary_t,
    res: sink_mod.Result,
    stopped_by_cb: bool,
    read_failed: bool,
) c_int {
    api.populateCSummary(out_summary, res, stopped_by_cb);
    if (read_failed or res.soft_error != null) return api.WEBGREP_ERR_IO;
    if (res.limit_hit == .decompressed_bytes) return api.WEBGREP_ERR_BUDGET_EXCEEDED;
    return api.WEBGREP_OK;
}

// ============================================================================
// Cancellation Token (Functions 21–24)
// ============================================================================

pub export fn webgrep_cancel_new() callconv(.c) ?*api.webgrep_cancel_t {
    const box = c_alloc.create(api.CancelBox) catch return null;
    box.* = .{};
    return @ptrCast(box);
}

pub export fn webgrep_cancel_trigger(cancel: ?*api.webgrep_cancel_t) callconv(.c) void {
    const ptr = cancel orelse return;
    const box: *api.CancelBox = @ptrCast(@alignCast(ptr));
    box.flag.store(true, .release);
}

pub export fn webgrep_cancel_reset(cancel: ?*api.webgrep_cancel_t) callconv(.c) void {
    const ptr = cancel orelse return;
    const box: *api.CancelBox = @ptrCast(@alignCast(ptr));
    box.flag.store(false, .release);
}

pub export fn webgrep_cancel_free(cancel: ?*api.webgrep_cancel_t) callconv(.c) void {
    const ptr = cancel orelse return;
    const box: *api.CancelBox = @ptrCast(@alignCast(ptr));
    c_alloc.destroy(box);
}

// ============================================================================
// Regex Captures & Named Group Lookup (Functions 25–26)
// ============================================================================

pub export fn webgrep_find_captures(
    matcher: ?*const api.webgrep_matcher_t,
    haystack_ptr: ?[*]const u8,
    haystack_len: usize,
    start_offset: usize,
    match_mode: c_int,
    scratch: ?*api.webgrep_scratch_t,
    out_captures: ?*webgrep_captures_t,
) callconv(.c) c_int {
    const out = out_captures orelse return api.WEBGREP_ERR_INVALID_ARG;
    out.* = .{};
    const m_ptr = matcher orelse return api.WEBGREP_ERR_INVALID_ARG;
    if (haystack_ptr == null and haystack_len > 0) return api.WEBGREP_ERR_INVALID_ARG;
    if (start_offset > haystack_len) return api.WEBGREP_ERR_INVALID_ARG;

    const mm: matcher_mod.MatchMode = switch (match_mode) {
        0 => .earliest,
        1 => .leftmost_first,
        else => return api.WEBGREP_ERR_INVALID_ARG,
    };

    const m_box: *const api.MatcherBox = @ptrCast(@alignCast(m_ptr));
    const re: *const regex_mod.Regex = switch (m_box.payload) {
        .regex => |*r| r,
        else => return api.WEBGREP_ERR_INVALID_ARG,
    };

    const hay: []const u8 = if (haystack_ptr) |p| p[0..haystack_len] else "";
    const maybe_cap = if (scratch) |s_ptr| blk: {
        const s_box: *api.ScratchBox = @ptrCast(@alignCast(s_ptr));
        break :blk re.findCapturesWithScratch(hay, start_offset, mm, &s_box.regex_scratch);
    } else re.findCaptures(hay, start_offset, mm);

    const cap = maybe_cap orelse return 0;
    out.full = .{
        .start = cap.match.start,
        .end = cap.match.end,
        .matched = 1,
    };
    const gcount = @min(re.group_count, WEBGREP_MAX_CAPTURE_GROUPS);
    out.group_count = gcount;
    for (0..gcount) |i| {
        if (cap.groups[i]) |g| {
            out.groups[i] = .{
                .start = g.start,
                .end = g.end,
                .matched = 1,
            };
        }
    }
    return 1;
}

pub export fn webgrep_matcher_group_index(
    matcher: ?*const api.webgrep_matcher_t,
    name_ptr: ?[*]const u8,
    name_len: usize,
) callconv(.c) c_int {
    const m_ptr = matcher orelse return api.WEBGREP_ERR_INVALID_ARG;
    if (name_ptr == null and name_len > 0) return api.WEBGREP_ERR_INVALID_ARG;

    const m_box: *const api.MatcherBox = @ptrCast(@alignCast(m_ptr));
    const re: *const regex_mod.Regex = switch (m_box.payload) {
        .regex => |*r| r,
        else => return api.WEBGREP_ERR_INVALID_ARG,
    };

    const name: []const u8 = if (name_ptr) |p| p[0..name_len] else "";
    const idx = re.groupIndexByName(name) orelse return 0;
    return @intCast(idx);
}

// ============================================================================
// RandomAccess Positional Search & Probe (Functions 27–29)
// ============================================================================

pub export fn webgrep_search_range(
    matcher: ?*const api.webgrep_matcher_t,
    read_at_cb: webgrep_read_at_cb,
    read_userdata: ?*anyopaque,
    total_size: u64,
    has_total_size: u8,
    range_start: u64,
    range_end: u64,
    has_range_end: u8,
    cfg: ?*const api.webgrep_config_t,
    on_line: api.webgrep_line_cb,
    line_userdata: ?*anyopaque,
    out_summary: ?*api.webgrep_summary_t,
) callconv(.c) c_int {
    if (out_summary) |s| s.* = .{};
    const m_ptr = matcher orelse return api.WEBGREP_ERR_INVALID_ARG;
    const r_cb = read_at_cb orelse return api.WEBGREP_ERR_INVALID_ARG;

    var filter_bridge: api.CLineFilterBridge = undefined;
    var cfg_guard: api.ConfigGuard = .{};
    defer cfg_guard.deinit();
    const z_cfg = api.buildSearchConfig(cfg, &filter_bridge, &cfg_guard) catch |err| return switch (err) {
        error.InvalidArg => api.WEBGREP_ERR_INVALID_ARG,
        error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
    };

    var adapter = CRandomAccessAdapter{
        .cb = r_cb,
        .userdata = read_userdata,
        .size = if (has_total_size != 0) total_size else null,
    };
    const box: *const api.MatcherBox = @ptrCast(@alignCast(m_ptr));
    var sink = api.CLineEventSink{
        .on_line = on_line,
        .userdata = line_userdata,
    };

    const res = searcher.searchSourceRange(
        api.CLineEventSink,
        c_alloc,
        &sink,
        adapter.randomAccess(),
        .{
            .start = range_start,
            .end = if (has_range_end != 0) range_end else null,
        },
        "",
        &box.any_matcher,
        z_cfg,
    ) catch |err| return mapReadSearchError(err, adapter.failed);

    return finishSearchResult(out_summary, res, sink.stopped, adapter.failed);
}

pub export fn webgrep_search_reverse_at(
    matcher: ?*const api.webgrep_matcher_t,
    read_at_cb: webgrep_read_at_cb,
    read_userdata: ?*anyopaque,
    total_size: u64,
    has_total_size: u8,
    cfg: ?*const api.webgrep_config_t,
    on_line: api.webgrep_line_cb,
    line_userdata: ?*anyopaque,
    out_summary: ?*api.webgrep_summary_t,
) callconv(.c) c_int {
    if (out_summary) |s| s.* = .{};
    const m_ptr = matcher orelse return api.WEBGREP_ERR_INVALID_ARG;
    const r_cb = read_at_cb orelse return api.WEBGREP_ERR_INVALID_ARG;

    var filter_bridge: api.CLineFilterBridge = undefined;
    var cfg_guard: api.ConfigGuard = .{};
    defer cfg_guard.deinit();
    const z_cfg = api.buildSearchConfig(cfg, &filter_bridge, &cfg_guard) catch |err| return switch (err) {
        error.InvalidArg => api.WEBGREP_ERR_INVALID_ARG,
        error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
    };

    var adapter = CRandomAccessAdapter{
        .cb = r_cb,
        .userdata = read_userdata,
        .size = if (has_total_size != 0) total_size else null,
    };
    const box: *const api.MatcherBox = @ptrCast(@alignCast(m_ptr));
    var sink = api.CLineEventSink{
        .on_line = on_line,
        .userdata = line_userdata,
    };

    const res = searcher.searchSourceReverseAt(
        api.CLineEventSink,
        c_alloc,
        &sink,
        adapter.randomAccess(),
        "",
        &box.any_matcher,
        z_cfg,
    ) catch |err| return mapReadSearchError(err, adapter.failed);

    return finishSearchResult(out_summary, res, sink.stopped, adapter.failed);
}

pub export fn webgrep_probe_line_at(
    read_at_cb: webgrep_read_at_cb,
    read_userdata: ?*anyopaque,
    total_size: u64,
    has_total_size: u8,
    offset: u64,
    buf_ptr: ?[*]u8,
    buf_cap: usize,
    opts: ?*const api.webgrep_probe_options_t,
    out_probe: ?*api.webgrep_line_probe_t,
) callconv(.c) c_int {
    const out = out_probe orelse return api.WEBGREP_ERR_INVALID_ARG;
    out.* = .{};
    const r_cb = read_at_cb orelse return api.WEBGREP_ERR_INVALID_ARG;
    if (buf_ptr == null and buf_cap > 0) return api.WEBGREP_ERR_INVALID_ARG;

    var adapter = CRandomAccessAdapter{
        .cb = r_cb,
        .userdata = read_userdata,
        .size = if (has_total_size != 0) total_size else null,
    };
    var empty_buf: [0]u8 = .{};
    const dest_buf: []u8 = if (buf_ptr) |p| p[0..buf_cap] else empty_buf[0..];
    const z_opts: probe_mod.ProbeOptions = if (opts) |o| .{
        .delimiter = o.delimiter,
        .strip_crlf = o.strip_crlf != 0,
        .max_line_bytes = if (o.max_line_bytes > 0) o.max_line_bytes else 2 * 1024 * 1024,
    } else .{};

    const lp = (probe_mod.probeLineAtBuf(adapter.randomAccess(), offset, dest_buf, z_opts) catch {
        return api.WEBGREP_ERR_IO;
    }) orelse {
        if (adapter.failed) return api.WEBGREP_ERR_IO;
        return 0;
    };

    out.* = .{
        .start_offset = lp.start_offset,
        .end_offset = lp.end_offset,
        .raw_end_offset = lp.raw_end_offset,
        .bytes_ptr = if (lp.bytes.len > 0) lp.bytes.ptr else buf_ptr,
        .bytes_len = lp.bytes.len,
        .truncated_left = if (lp.truncated_left) 1 else 0,
        .truncated_right = if (lp.truncated_right) 1 else 0,
    };
    return 1;
}

// ============================================================================
// Pull-Mode Iterators (Functions 30–33)
// ============================================================================

pub export fn webgrep_pull_open_slice(
    matcher: ?*const api.webgrep_matcher_t,
    data_ptr: ?[*]const u8,
    data_len: usize,
    cfg: ?*const api.webgrep_config_t,
    out_pull: ?*?*webgrep_pull_t,
) callconv(.c) c_int {
    const out = out_pull orelse return api.WEBGREP_ERR_INVALID_ARG;
    out.* = null;
    const m_ptr = matcher orelse return api.WEBGREP_ERR_INVALID_ARG;
    if (data_ptr == null and data_len > 0) return api.WEBGREP_ERR_INVALID_ARG;

    const box = c_alloc.create(PullBox) catch return api.WEBGREP_ERR_OUT_OF_MEMORY;
    box.* = .{};
    var keep = false;
    errdefer if (!keep) {
        box.cfg_guard.deinit();
        c_alloc.destroy(box);
    };

    const z_cfg = api.buildSearchConfig(cfg, &box.filter_bridge, &box.cfg_guard) catch |err| return switch (err) {
        error.InvalidArg => api.WEBGREP_ERR_INVALID_ARG,
        error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
    };

    const hay: []const u8 = if (data_ptr) |p| p[0..data_len] else "";
    const m_box: *const api.MatcherBox = @ptrCast(@alignCast(m_ptr));
    box.kind = .{ .slice = pull_mod.openSourcePull(c_alloc, &m_box.any_matcher, "", hay, z_cfg) };
    keep = true;
    out.* = @ptrCast(box);
    return api.WEBGREP_OK;
}

pub export fn webgrep_pull_open_reader(
    matcher: ?*const api.webgrep_matcher_t,
    read_cb: api.webgrep_read_cb,
    read_userdata: ?*anyopaque,
    cfg: ?*const api.webgrep_config_t,
    out_pull: ?*?*webgrep_pull_t,
) callconv(.c) c_int {
    const out = out_pull orelse return api.WEBGREP_ERR_INVALID_ARG;
    out.* = null;
    const m_ptr = matcher orelse return api.WEBGREP_ERR_INVALID_ARG;
    const r_cb = read_cb orelse return api.WEBGREP_ERR_INVALID_ARG;

    const box = c_alloc.create(PullBox) catch return api.WEBGREP_ERR_OUT_OF_MEMORY;
    box.* = .{};
    var keep = false;
    errdefer if (!keep) {
        box.cfg_guard.deinit();
        c_alloc.destroy(box);
    };

    box.c_reader.initInPlace(r_cb, read_userdata);
    const z_cfg = api.buildSearchConfig(cfg, &box.filter_bridge, &box.cfg_guard) catch |err| return switch (err) {
        error.InvalidArg => api.WEBGREP_ERR_INVALID_ARG,
        error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
    };

    const m_box: *const api.MatcherBox = @ptrCast(@alignCast(m_ptr));
    const pull = pull_mod.openReaderPull(c_alloc, &m_box.any_matcher, "", &box.c_reader.reader, z_cfg) catch |err| {
        return mapReadSearchError(err, box.c_reader.failed);
    };
    box.kind = .{ .reader = pull };
    box.kind.reader.state.offset_map = &box.kind.reader.offset_map;
    box.kind.reader.state.decompress_map = &box.kind.reader.decompress_map;
    box.kind.reader.decoder.offset_map = &box.kind.reader.offset_map;
    box.kind.reader.decompressor.decompress_map = &box.kind.reader.decompress_map;

    keep = true;
    out.* = @ptrCast(box);
    return api.WEBGREP_OK;
}

pub export fn webgrep_pull_next(
    pull: ?*webgrep_pull_t,
    out_event: ?*api.webgrep_line_event_t,
    out_summary: ?*api.webgrep_summary_t,
) callconv(.c) c_int {
    const p_ptr = pull orelse return api.WEBGREP_ERR_INVALID_ARG;
    const out_ev = out_event orelse return api.WEBGREP_ERR_INVALID_ARG;
    out_ev.* = .{};

    const box: *PullBox = @ptrCast(@alignCast(p_ptr));
    if (box.eof_reached) {
        if (out_summary) |s| s.* = box.summary;
        return 0;
    }

    while (true) {
        const next_ev: ?pull_mod.PullEvent = switch (box.kind) {
            .slice => |*sp| sp.next() catch |err| return mapReadSearchError(err, false),
            .reader => |*rp| rp.next() catch |err| return mapReadSearchError(err, box.c_reader.failed),
        };
        const ev = next_ev orelse {
            box.eof_reached = true;
            if (box.kind == .reader and box.summary.bytes_searched == 0) {
                box.summary.bytes_searched = box.kind.reader.state.bytes_searched;
            }
            if (out_summary) |s| s.* = box.summary;
            if ((box.kind == .reader and box.c_reader.failed) or box.had_soft_error) return api.WEBGREP_ERR_IO;
            if (box.saw_decompressed_limit) return api.WEBGREP_ERR_BUDGET_EXCEEDED;
            return 0;
        };

        switch (ev.kind) {
            .match, .context => {
                box.cur_spans.clearRetainingCapacity();
                if (ev.spans.len > 0) {
                    box.cur_spans.ensureTotalCapacity(c_alloc, ev.spans.len) catch return api.WEBGREP_ERR_OUT_OF_MEMORY;
                    for (ev.spans) |src| {
                        box.cur_spans.appendAssumeCapacity(.{
                            .start = src.start,
                            .end = src.end,
                            .pattern_id = if (src.pattern_id) |pid| @as(i32, @intCast(pid)) else -1,
                            .u16_start = src.u16_start,
                            .u16_end = src.u16_end,
                        });
                    }
                }
                out_ev.* = .{
                    .path_ptr = if (ev.source_id.len > 0) ev.source_id.ptr else null,
                    .path_len = ev.source_id.len,
                    .line_number = ev.line_number,
                    .byte_offset = ev.absolute_offset,
                    .column = ev.column orelse 0,
                    .u16_column = ev.u16_column orelse 0,
                    .text_ptr = ev.bytes.ptr,
                    .text_len = ev.bytes.len,
                    .bytes_ptr = ev.bytes.ptr,
                    .bytes_len = ev.bytes.len,
                    .replaced_ptr = if (ev.replaced) |r| r.ptr else null,
                    .replaced_len = if (ev.replaced) |r| r.len else 0,
                    .matches_ptr = if (box.cur_spans.items.len > 0) box.cur_spans.items.ptr else (&api.empty_spans)[0..0].ptr,
                    .matches_len = box.cur_spans.items.len,
                    .is_context = if (ev.kind == .context) 1 else 0,
                    .truncated = if (ev.truncated) 1 else 0,
                    .line_number_known = if (ev.line_number_known) 1 else 0,
                };
                return 1;
            },
            .end => {
                box.summary.matched_lines = ev.matched_lines;
                box.summary.matches = ev.matches;
                box.summary.bytes_read = ev.bytes_read;
                box.summary.stopped = if (ev.outcome == .stopped) 1 else 0;
                box.summary.partial = if (ev.partial) 1 else 0;
                box.summary.binary_detected = if (ev.binary_offset != null or ev.outcome == .binary_quit or ev.outcome == .binary_matched) 1 else 0;
                box.summary.limit_hit = @intFromEnum(ev.limit_hit);
                box.summary.resume_at = ev.resume_at orelse 0;
                box.summary.has_resume_at = if (ev.resume_at != null) 1 else 0;
                if (ev.soft_error != null) box.had_soft_error = true;
                if (ev.limit_hit == .decompressed_bytes) box.saw_decompressed_limit = true;
            },
            .summary => {
                box.summary.matched_lines = ev.matched_lines;
                box.summary.matches = ev.matches;
                box.summary.bytes_searched = ev.bytes_searched;
                box.summary.elapsed_ns = ev.elapsed;
            },
            .begin, .context_break, .progress, .heartbeat => {},
        }
    }
}

pub export fn webgrep_pull_free(pull: ?*webgrep_pull_t) callconv(.c) void {
    const ptr = pull orelse return;
    const box: *PullBox = @ptrCast(@alignCast(ptr));
    box.deinitAndFree();
}

// ============================================================================
// Streaming Archive Reader (Function 34)
// ============================================================================

pub export fn webgrep_search_archive_reader(
    matcher: ?*const api.webgrep_matcher_t,
    read_cb: api.webgrep_read_cb,
    read_userdata: ?*anyopaque,
    tree_cfg: ?*const api.webgrep_tree_config_t,
    on_line: api.webgrep_line_cb,
    line_userdata: ?*anyopaque,
    out_summary: ?*api.webgrep_tree_summary_t,
) callconv(.c) c_int {
    if (out_summary) |s| s.* = .{};
    const m_ptr = matcher orelse return api.WEBGREP_ERR_INVALID_ARG;
    const r_cb = read_cb orelse return api.WEBGREP_ERR_INVALID_ARG;

    const c_tcfg = if (tree_cfg) |tc| tc.* else api.webgrep_tree_config_default();
    var filter_bridge: api.CLineFilterBridge = undefined;
    var cfg_guard: api.ConfigGuard = .{};
    defer cfg_guard.deinit();
    const z_search_cfg = api.buildSearchConfig(&c_tcfg.search, &filter_bridge, &cfg_guard) catch |err| return switch (err) {
        error.InvalidArg => api.WEBGREP_ERR_INVALID_ARG,
        error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
    };

    var entry_bridge: api.CArchiveFilterBridge = undefined;
    const z_tcfg = api.buildTreeConfig(c_tcfg, z_search_cfg, &entry_bridge) orelse return api.WEBGREP_ERR_INVALID_ARG;

    var c_reader: CStreamIoReader = undefined;
    c_reader.initInPlace(r_cb, read_userdata);

    var prefix_buf: [4]u8 = undefined;
    var prefix_len: usize = 0;
    if (z_tcfg.archive.format == .auto) {
        while (prefix_len < prefix_buf.len) {
            const rn = c_reader.reader.readSliceShort(prefix_buf[prefix_len..]) catch {
                return api.WEBGREP_ERR_IO;
            };
            if (rn == 0) break;
            prefix_len += rn;
        }
        if (c_reader.failed) return api.WEBGREP_ERR_IO;
    }

    var prefixed = pull_mod.PrefixedReader.init(&c_reader.reader, prefix_buf[0..prefix_len]);
    prefixed.reader.buffer = &prefixed.read_buf;
    const stream_reader: *std.Io.Reader = if (z_tcfg.archive.format == .auto) &prefixed.reader else &c_reader.reader;

    const is_zip = z_tcfg.archive.format == .zip or (z_tcfg.archive.format == .auto and prefix_len >= 4 and
        prefix_buf[0] == 'P' and prefix_buf[1] == 'K' and
        ((prefix_buf[2] == 3 and prefix_buf[3] == 4) or (prefix_buf[2] == 5 and prefix_buf[3] == 6)));

    const box: *const api.MatcherBox = @ptrCast(@alignCast(m_ptr));
    var sink = api.CLineEventSink{
        .on_line = on_line,
        .userdata = line_userdata,
    };

    const sum = (if (is_zip)
        tree_mod.searchArchive(api.CLineEventSink, c_alloc, std.Io.failing, &sink, stream_reader, &box.any_matcher, z_tcfg)
    else
        tree_mod.searchTarStream(api.CLineEventSink, c_alloc, std.Io.failing, &sink, stream_reader, &box.any_matcher, z_tcfg)) catch |err| {
        if (c_reader.failed) return api.WEBGREP_ERR_IO;
        return switch (err) {
            error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
            error.ArchiveLimit => api.WEBGREP_ERR_ARCHIVE_LIMIT,
            error.ContextLinesExceeded,
            error.BudgetExceeded,
            error.BufferLimit,
            error.DecodeLimit,
            error.GlobCountExceeded,
            error.GlobTooLong,
            error.GlobBraceDepthExceeded,
            => api.WEBGREP_ERR_BUDGET_EXCEEDED,
            else => api.WEBGREP_ERR_CORRUPT_ARCHIVE,
        };
    };

    if (out_summary) |s| {
        s.* = .{
            .files_searched = sum.searches,
            .matched_files = sum.searches_with_match,
            .matched_lines = sum.matched_lines,
            .matches = sum.matches,
            .bytes_searched = sum.bytes_searched,
            .files_skipped_binary = sink.binary_skipped,
            .files_failed = sum.sources_failed,
            .stopped = if (sink.stopped) 1 else 0,
        };
    }
    return api.WEBGREP_OK;
}

// ============================================================================
// N-gram Bloom Filter (Functions 35–42)
// ============================================================================

pub export fn webgrep_bloom_config_default() callconv(.c) webgrep_bloom_config_t {
    return .{};
}

pub export fn webgrep_bloom_new(
    cfg: ?*const webgrep_bloom_config_t,
    out_bloom: ?*?*webgrep_bloom_t,
) callconv(.c) c_int {
    const out = out_bloom orelse return api.WEBGREP_ERR_INVALID_ARG;
    out.* = null;
    const c_cfg = if (cfg) |p| p.* else webgrep_bloom_config_t{};
    const z_cfg = bloom_mod.BloomConfig{
        .bit_count = c_cfg.bit_count,
        .num_hashes = c_cfg.num_hashes,
        .ngram_len = c_cfg.ngram_len,
        .ascii_lower = c_cfg.ascii_lower != 0,
    };
    var bloom = bloom_mod.NgramBloom.init(c_alloc, z_cfg) catch |err| return switch (err) {
        error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
        else => api.WEBGREP_ERR_INVALID_ARG,
    };
    const box = c_alloc.create(BloomBox) catch {
        bloom.deinit();
        return api.WEBGREP_ERR_OUT_OF_MEMORY;
    };
    box.* = .{ .bloom = bloom };
    out.* = @ptrCast(box);
    return api.WEBGREP_OK;
}

pub export fn webgrep_bloom_free(bloom: ?*webgrep_bloom_t) callconv(.c) void {
    const ptr = bloom orelse return;
    const box: *BloomBox = @ptrCast(@alignCast(ptr));
    box.bloom.deinit();
    c_alloc.destroy(box);
}

pub export fn webgrep_bloom_add(
    bloom: ?*webgrep_bloom_t,
    data_ptr: ?[*]const u8,
    data_len: usize,
) callconv(.c) c_int {
    const ptr = bloom orelse return api.WEBGREP_ERR_INVALID_ARG;
    if (data_ptr == null and data_len > 0) return api.WEBGREP_ERR_INVALID_ARG;
    const box: *BloomBox = @ptrCast(@alignCast(ptr));
    const slice: []const u8 = if (data_ptr) |p| p[0..data_len] else "";
    box.bloom.addSlice(slice);
    return api.WEBGREP_OK;
}

pub export fn webgrep_bloom_merge(
    dst: ?*webgrep_bloom_t,
    src: ?*const webgrep_bloom_t,
) callconv(.c) c_int {
    const d_ptr = dst orelse return api.WEBGREP_ERR_INVALID_ARG;
    const s_ptr = src orelse return api.WEBGREP_ERR_INVALID_ARG;
    const d_box: *BloomBox = @ptrCast(@alignCast(d_ptr));
    const s_box: *const BloomBox = @ptrCast(@alignCast(s_ptr));
    d_box.bloom.merge(&s_box.bloom) catch return api.WEBGREP_ERR_INVALID_ARG;
    return api.WEBGREP_OK;
}

pub export fn webgrep_bloom_may_contain(
    bloom: ?*const webgrep_bloom_t,
    matcher: ?*const api.webgrep_matcher_t,
) callconv(.c) c_int {
    const b_ptr = bloom orelse return api.WEBGREP_ERR_INVALID_ARG;
    const m_ptr = matcher orelse return api.WEBGREP_ERR_INVALID_ARG;
    const b_box: *const BloomBox = @ptrCast(@alignCast(b_ptr));
    const m_box: *const api.MatcherBox = @ptrCast(@alignCast(m_ptr));

    const hit = switch (m_box.payload) {
        .literal => |*lit| b_box.bloom.mayContainFinder(&lit.finder),
        .multi => |*m| b_box.bloom.mayContainMulti(&m.engine),
        .regex => |*re| b_box.bloom.mayContainRegex(re),
        .regex_set => |*rs| b_box.bloom.mayContainRegexSet(rs),
    };
    return if (hit) 1 else 0;
}

pub export fn webgrep_bloom_serialize(
    bloom: ?*const webgrep_bloom_t,
    out_buf: ?[*]u8,
    out_cap: usize,
    out_len: ?*usize,
) callconv(.c) c_int {
    const out_l = out_len orelse return api.WEBGREP_ERR_INVALID_ARG;
    const b_ptr = bloom orelse return api.WEBGREP_ERR_INVALID_ARG;
    if (out_buf == null and out_cap > 0) return api.WEBGREP_ERR_INVALID_ARG;

    const b_box: *const BloomBox = @ptrCast(@alignCast(b_ptr));
    const encoded = b_box.bloom.serializeAlloc(c_alloc) catch return api.WEBGREP_ERR_OUT_OF_MEMORY;
    defer c_alloc.free(encoded);

    out_l.* = encoded.len;
    const dst_ptr = out_buf orelse return api.WEBGREP_OK;
    if (out_cap < encoded.len) return api.WEBGREP_ERR_TOO_LARGE;
    @memcpy(dst_ptr[0..encoded.len], encoded);
    return api.WEBGREP_OK;
}

pub export fn webgrep_bloom_deserialize(
    data_ptr: ?[*]const u8,
    data_len: usize,
    out_bloom: ?*?*webgrep_bloom_t,
) callconv(.c) c_int {
    const out = out_bloom orelse return api.WEBGREP_ERR_INVALID_ARG;
    out.* = null;
    if (data_ptr == null and data_len > 0) return api.WEBGREP_ERR_INVALID_ARG;
    const data: []const u8 = if (data_ptr) |p| p[0..data_len] else "";

    var bloom = bloom_mod.NgramBloom.deserialize(c_alloc, data) catch |err| return switch (err) {
        error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
        else => api.WEBGREP_ERR_INVALID_ARG,
    };
    const box = c_alloc.create(BloomBox) catch {
        bloom.deinit();
        return api.WEBGREP_ERR_OUT_OF_MEMORY;
    };
    box.* = .{ .bloom = bloom };
    out.* = @ptrCast(box);
    return api.WEBGREP_OK;
}

// ============================================================================
// Seekable Zstd Table (Functions 43–46)
// ============================================================================

pub export fn webgrep_zstd_seek_table_parse(
    read_at_cb: webgrep_read_at_cb,
    read_userdata: ?*anyopaque,
    total_size: u64,
    out_table: ?*?*webgrep_zstd_seek_table_t,
) callconv(.c) c_int {
    const out = out_table orelse return api.WEBGREP_ERR_INVALID_ARG;
    out.* = null;
    const r_cb = read_at_cb orelse return api.WEBGREP_ERR_INVALID_ARG;

    var adapter = CRandomAccessAdapter{
        .cb = r_cb,
        .userdata = read_userdata,
        .size = total_size,
    };
    var table = seekable_mod.ZstdSeekTable.parseFromRandomAccess(c_alloc, adapter.randomAccess()) catch |err| {
        if (adapter.failed) return api.WEBGREP_ERR_IO;
        return switch (err) {
            error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
            else => api.WEBGREP_ERR_CORRUPT_ARCHIVE,
        };
    };
    const box = c_alloc.create(ZstdSeekTableBox) catch {
        table.deinit(c_alloc);
        return api.WEBGREP_ERR_OUT_OF_MEMORY;
    };
    box.* = .{ .table = table };
    out.* = @ptrCast(box);
    return api.WEBGREP_OK;
}

pub export fn webgrep_zstd_seek_table_free(table: ?*webgrep_zstd_seek_table_t) callconv(.c) void {
    const ptr = table orelse return;
    const box: *ZstdSeekTableBox = @ptrCast(@alignCast(ptr));
    box.table.deinit(c_alloc);
    c_alloc.destroy(box);
}

pub export fn webgrep_zstd_seek_table_uncompressed_size(table: ?*const webgrep_zstd_seek_table_t) callconv(.c) u64 {
    const ptr = table orelse return 0;
    const box: *const ZstdSeekTableBox = @ptrCast(@alignCast(ptr));
    return box.table.total_uncompressed_size;
}

pub export fn webgrep_zstd_seek_table_read_at(
    table: ?*const webgrep_zstd_seek_table_t,
    read_at_cb: webgrep_read_at_cb,
    read_userdata: ?*anyopaque,
    total_size: u64,
    uncomp_offset: u64,
    out_buf: ?[*]u8,
    out_cap: usize,
    max_ratio: u64,
    out_n: ?*usize,
) callconv(.c) c_int {
    const out_count = out_n orelse return api.WEBGREP_ERR_INVALID_ARG;
    out_count.* = 0;
    const t_ptr = table orelse return api.WEBGREP_ERR_INVALID_ARG;
    const r_cb = read_at_cb orelse return api.WEBGREP_ERR_INVALID_ARG;
    if (out_buf == null and out_cap > 0) return api.WEBGREP_ERR_INVALID_ARG;

    const t_box: *const ZstdSeekTableBox = @ptrCast(@alignCast(t_ptr));
    var adapter = CRandomAccessAdapter{
        .cb = r_cb,
        .userdata = read_userdata,
        .size = total_size,
    };
    var empty_buf: [0]u8 = .{};
    const dest: []u8 = if (out_buf) |p| p[0..out_cap] else empty_buf[0..];
    const ratio_opt: ?u64 = if (max_ratio > 0) max_ratio else null;

    const n = t_box.table.readAt(c_alloc, adapter.randomAccess(), uncomp_offset, dest, ratio_opt) catch |err| {
        if (adapter.failed) return api.WEBGREP_ERR_IO;
        return switch (err) {
            error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
            error.DecompressLimit => api.WEBGREP_ERR_BUDGET_EXCEEDED,
            else => api.WEBGREP_ERR_CORRUPT_ARCHIVE,
        };
    };
    out_count.* = n;
    return api.WEBGREP_OK;
}

// ============================================================================
// Indexed Gzip (Functions 47–52)
// ============================================================================

pub export fn webgrep_gzip_index_build(
    read_cb: api.webgrep_read_cb,
    read_userdata: ?*anyopaque,
    checkpoint_interval: u64,
    out_index: ?*?*webgrep_gzip_index_t,
) callconv(.c) c_int {
    const out = out_index orelse return api.WEBGREP_ERR_INVALID_ARG;
    out.* = null;
    const r_cb = read_cb orelse return api.WEBGREP_ERR_INVALID_ARG;

    var c_reader: CStreamIoReader = undefined;
    c_reader.initInPlace(r_cb, read_userdata);

    var index = seekable_mod.GzipIndex.buildFromReader(c_alloc, &c_reader.reader, checkpoint_interval) catch |err| {
        if (c_reader.failed) return api.WEBGREP_ERR_IO;
        return switch (err) {
            error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
            else => api.WEBGREP_ERR_CORRUPT_ARCHIVE,
        };
    };
    const box = c_alloc.create(GzipIndexBox) catch {
        index.deinit(c_alloc);
        return api.WEBGREP_ERR_OUT_OF_MEMORY;
    };
    box.* = .{ .index = index };
    out.* = @ptrCast(box);
    return api.WEBGREP_OK;
}

pub export fn webgrep_gzip_index_free(index: ?*webgrep_gzip_index_t) callconv(.c) void {
    const ptr = index orelse return;
    const box: *GzipIndexBox = @ptrCast(@alignCast(ptr));
    box.index.deinit(c_alloc);
    c_alloc.destroy(box);
}

pub export fn webgrep_gzip_index_uncompressed_size(index: ?*const webgrep_gzip_index_t) callconv(.c) u64 {
    const ptr = index orelse return 0;
    const box: *const GzipIndexBox = @ptrCast(@alignCast(ptr));
    return box.index.total_uncompressed_size;
}

pub export fn webgrep_gzip_index_serialize(
    index: ?*const webgrep_gzip_index_t,
    out_buf: ?[*]u8,
    out_cap: usize,
    out_len: ?*usize,
) callconv(.c) c_int {
    const out_l = out_len orelse return api.WEBGREP_ERR_INVALID_ARG;
    const idx_ptr = index orelse return api.WEBGREP_ERR_INVALID_ARG;
    if (out_buf == null and out_cap > 0) return api.WEBGREP_ERR_INVALID_ARG;

    const idx_box: *const GzipIndexBox = @ptrCast(@alignCast(idx_ptr));
    const encoded = idx_box.index.serializeAlloc(c_alloc) catch return api.WEBGREP_ERR_OUT_OF_MEMORY;
    defer c_alloc.free(encoded);

    out_l.* = encoded.len;
    const dst_ptr = out_buf orelse return api.WEBGREP_OK;
    if (out_cap < encoded.len) return api.WEBGREP_ERR_TOO_LARGE;
    @memcpy(dst_ptr[0..encoded.len], encoded);
    return api.WEBGREP_OK;
}

pub export fn webgrep_gzip_index_deserialize(
    data_ptr: ?[*]const u8,
    data_len: usize,
    out_index: ?*?*webgrep_gzip_index_t,
) callconv(.c) c_int {
    const out = out_index orelse return api.WEBGREP_ERR_INVALID_ARG;
    out.* = null;
    if (data_ptr == null and data_len > 0) return api.WEBGREP_ERR_INVALID_ARG;
    const data: []const u8 = if (data_ptr) |p| p[0..data_len] else "";

    var index = seekable_mod.GzipIndex.deserialize(c_alloc, data) catch |err| return switch (err) {
        error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
        else => api.WEBGREP_ERR_CORRUPT_ARCHIVE,
    };
    const box = c_alloc.create(GzipIndexBox) catch {
        index.deinit(c_alloc);
        return api.WEBGREP_ERR_OUT_OF_MEMORY;
    };
    box.* = .{ .index = index };
    out.* = @ptrCast(box);
    return api.WEBGREP_OK;
}

pub export fn webgrep_gzip_index_read_at(
    index: ?*const webgrep_gzip_index_t,
    read_at_cb: webgrep_read_at_cb,
    read_userdata: ?*anyopaque,
    total_size: u64,
    has_total_size: u8,
    uncomp_offset: u64,
    out_buf: ?[*]u8,
    out_cap: usize,
    out_n: ?*usize,
) callconv(.c) c_int {
    const out_count = out_n orelse return api.WEBGREP_ERR_INVALID_ARG;
    out_count.* = 0;
    const idx_ptr = index orelse return api.WEBGREP_ERR_INVALID_ARG;
    const r_cb = read_at_cb orelse return api.WEBGREP_ERR_INVALID_ARG;
    if (out_buf == null and out_cap > 0) return api.WEBGREP_ERR_INVALID_ARG;

    const idx_box: *const GzipIndexBox = @ptrCast(@alignCast(idx_ptr));
    var adapter = CRandomAccessAdapter{
        .cb = r_cb,
        .userdata = read_userdata,
        .size = if (has_total_size != 0) total_size else null,
    };
    var empty_buf: [0]u8 = .{};
    const dest: []u8 = if (out_buf) |p| p[0..out_cap] else empty_buf[0..];

    const n = idx_box.index.readAt(c_alloc, adapter.randomAccess(), uncomp_offset, dest) catch |err| {
        if (adapter.failed) return api.WEBGREP_ERR_IO;
        return switch (err) {
            error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
            else => api.WEBGREP_ERR_CORRUPT_ARCHIVE,
        };
    };
    out_count.* = n;
    return api.WEBGREP_OK;
}

// ============================================================================
// Unit Tests (Leak-Checked via std.testing.allocator)
// ============================================================================

test "c_api_ext: cancel token lifecycle and search interruption" {
    const tok = webgrep_cancel_new() orelse return error.OutOfMemory;
    defer webgrep_cancel_free(tok);

    const pat = "ERR";
    var m: ?*api.webgrep_matcher_t = null;
    try std.testing.expectEqual(api.WEBGREP_OK, api.webgrep_matcher_compile_literal(pat.ptr, pat.len, null, &m));
    defer api.webgrep_matcher_free(m);

    const doc = "ERR 1\nERR 2\n";
    webgrep_cancel_trigger(tok);

    var cfg = api.webgrep_config_default();
    cfg.cancel = tok;
    var sum: api.webgrep_summary_t = .{};
    try std.testing.expectEqual(api.WEBGREP_OK, api.webgrep_search_slice(m, doc.ptr, doc.len, &cfg, null, null, &sum));
    try std.testing.expectEqual(@as(u64, 0), sum.matches);

    webgrep_cancel_reset(tok);
    sum = .{};
    try std.testing.expectEqual(api.WEBGREP_OK, api.webgrep_search_slice(m, doc.ptr, doc.len, &cfg, null, null, &sum));
    try std.testing.expectEqual(@as(u64, 2), sum.matches);
}

test "c_api_ext: extended webgrep_config_t contains, excludes, charset, and resume_from" {
    const pat = "match";
    var m: ?*api.webgrep_matcher_t = null;
    try std.testing.expectEqual(api.WEBGREP_OK, api.webgrep_matcher_compile_literal(pat.ptr, pat.len, null, &m));
    defer api.webgrep_matcher_free(m);

    const doc = "match keep Alpha\nmatch drop Beta\nmatch keep Gamma\n";
    const c_pat = api.webgrep_pattern_t{ .ptr = "alpha", .len = 5 };
    const x_pat = api.webgrep_pattern_t{ .ptr = "beta", .len = 4 };
    const cs = "UTF-8";

    var cfg = api.webgrep_config_default();
    cfg.contains_ptr = @ptrCast(&c_pat);
    cfg.contains_len = 1;
    cfg.excludes_ptr = @ptrCast(&x_pat);
    cfg.excludes_len = 1;
    cfg.filter_case_insensitive = 1;
    cfg.charset_ptr = cs.ptr;
    cfg.charset_len = cs.len;

    var sum: api.webgrep_summary_t = .{};
    try std.testing.expectEqual(api.WEBGREP_OK, api.webgrep_search_slice(m, doc.ptr, doc.len, &cfg, null, null, &sum));
    try std.testing.expectEqual(@as(u64, 1), sum.matched_lines);

    // resume_from skips first line (len 17)
    var cfg2 = api.webgrep_config_default();
    cfg2.resume_from = 17;
    sum = .{};
    try std.testing.expectEqual(api.WEBGREP_OK, api.webgrep_search_slice(m, doc.ptr, doc.len, &cfg2, null, null, &sum));
    try std.testing.expectEqual(@as(u64, 2), sum.matched_lines);
}

test "c_api_ext: captures, named groups, and RandomAccess search/probe" {
    const regex_pat = "(?P<user>[a-z]+)@(?<host>[a-z]+\\.[a-z]+)";
    var m: ?*api.webgrep_matcher_t = null;
    var diag: api.webgrep_compile_diag_t = .{};
    try std.testing.expectEqual(api.WEBGREP_OK, api.webgrep_matcher_compile_regex(regex_pat.ptr, regex_pat.len, null, &diag, &m));
    defer api.webgrep_matcher_free(m);

    try std.testing.expectEqual(@as(c_int, 1), webgrep_matcher_group_index(m, "user", 4));
    try std.testing.expectEqual(@as(c_int, 2), webgrep_matcher_group_index(m, "host", 4));
    try std.testing.expectEqual(@as(c_int, 0), webgrep_matcher_group_index(m, "missing", 7));

    const scratch = api.webgrep_scratch_new() orelse return error.OutOfMemory;
    defer api.webgrep_scratch_free(scratch);

    const hay = "mail alice@example.org now";
    var caps: webgrep_captures_t = .{};
    try std.testing.expectEqual(@as(c_int, 1), webgrep_find_captures(m, hay.ptr, hay.len, 0, 1, scratch, &caps));
    try std.testing.expectEqual(@as(usize, 2), caps.group_count);
    try std.testing.expectEqualStrings("alice@example.org", hay[caps.full.start..caps.full.end]);
    try std.testing.expectEqualStrings("alice", hay[caps.groups[0].start..caps.groups[0].end]);
    try std.testing.expectEqualStrings("example.org", hay[caps.groups[1].start..caps.groups[1].end]);

    const SliceRA = struct {
        data: []const u8,
        fn readAt(offset: u64, buf: [*c]u8, cap: usize, out_n: [*c]usize, userdata: ?*anyopaque) callconv(.c) c_int {
            const self: *const @This() = @ptrCast(@alignCast(userdata.?));
            if (offset >= self.data.len or cap == 0) {
                out_n.* = 0;
                return 0;
            }
            const off: usize = @intCast(offset);
            const n = @min(cap, self.data.len - off);
            @memcpy(buf[0..n], self.data[off .. off + n]);
            out_n.* = n;
            return 0;
        }
    };

    const doc = "line0 a@b.c\nline1 c@d.e\nline2 f@g.h\n";
    var ra = SliceRA{ .data = doc };
    var sum: api.webgrep_summary_t = .{};
    try std.testing.expectEqual(api.WEBGREP_OK, webgrep_search_range(m, SliceRA.readAt, &ra, doc.len, 1, 12, 25, 1, null, null, null, &sum));
    try std.testing.expectEqual(@as(u64, 1), sum.matched_lines);

    const RevCap = struct {
        first_line: u64 = 0,
        count: usize = 0,
        fn onLine(ev: *const api.webgrep_line_event_t, userdata: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            if (self.count == 0) self.first_line = ev.line_number;
            self.count += 1;
            return 0;
        }
    };
    var rev = RevCap{};
    var cfg = api.webgrep_config_default();
    cfg.initial_line_number = 3;
    try std.testing.expectEqual(api.WEBGREP_OK, webgrep_search_reverse_at(m, SliceRA.readAt, &ra, doc.len, 1, &cfg, RevCap.onLine, &rev, &sum));
    try std.testing.expectEqual(@as(usize, 3), rev.count);
    try std.testing.expectEqual(@as(u64, 3), rev.first_line);

    var pbuf: [64]u8 = undefined;
    var lp: api.webgrep_line_probe_t = .{};
    try std.testing.expectEqual(@as(c_int, 1), webgrep_probe_line_at(SliceRA.readAt, &ra, doc.len, 1, 14, &pbuf, pbuf.len, null, &lp));
    try std.testing.expectEqualStrings("line1 c@d.e", lp.bytes_ptr.?[0..lp.bytes_len]);
}

test "c_api_ext: pull iterators and streaming archive reader" {
    const pat = "HIT";
    var m: ?*api.webgrep_matcher_t = null;
    try std.testing.expectEqual(api.WEBGREP_OK, api.webgrep_matcher_compile_literal(pat.ptr, pat.len, null, &m));
    defer api.webgrep_matcher_free(m);

    const text = "alpha\nHIT 1\nbeta\nHIT 2\n";
    // 1. Slice pull
    {
        var p: ?*webgrep_pull_t = null;
        try std.testing.expectEqual(api.WEBGREP_OK, webgrep_pull_open_slice(m, text.ptr, text.len, null, &p));
        defer webgrep_pull_free(p);

        var ev: api.webgrep_line_event_t = .{};
        var sum: api.webgrep_summary_t = .{};
        try std.testing.expectEqual(@as(c_int, 1), webgrep_pull_next(p, &ev, &sum));
        try std.testing.expectEqualStrings("HIT 1", ev.bytes_ptr.?[0..ev.bytes_len]);
        try std.testing.expectEqual(@as(c_int, 1), webgrep_pull_next(p, &ev, &sum));
        try std.testing.expectEqualStrings("HIT 2", ev.bytes_ptr.?[0..ev.bytes_len]);
        try std.testing.expectEqual(@as(c_int, 0), webgrep_pull_next(p, &ev, &sum));
        try std.testing.expectEqual(@as(u64, 2), sum.matched_lines);
    }

    const SliceStream = struct {
        data: []const u8,
        pos: usize = 0,
        fn read(buf: [*c]u8, cap: usize, out_n: [*c]usize, userdata: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            if (self.pos >= self.data.len) {
                out_n.* = 0;
                return 0;
            }
            const n = @min(@min(cap, 7), self.data.len - self.pos);
            @memcpy(buf[0..n], self.data[self.pos .. self.pos + n]);
            self.pos += n;
            out_n.* = n;
            return 0;
        }
    };

    // 2. Reader pull
    {
        var st = SliceStream{ .data = text };
        var p: ?*webgrep_pull_t = null;
        try std.testing.expectEqual(api.WEBGREP_OK, webgrep_pull_open_reader(m, SliceStream.read, &st, null, &p));
        defer webgrep_pull_free(p);

        var ev: api.webgrep_line_event_t = .{};
        var sum: api.webgrep_summary_t = .{};
        var hits: usize = 0;
        while (webgrep_pull_next(p, &ev, &sum) == 1) hits += 1;
        try std.testing.expectEqual(@as(usize, 2), hits);
        try std.testing.expectEqual(@as(u64, 2), sum.matched_lines);
    }

    // 3. Streaming archive reader (.tar + .zip)
    const tar_bytes = try archive_mod.buildTestTarAlloc(std.testing.allocator, &.{
        .{ .path = "a.log", .data = "no\nHIT tar\n" },
        .{ .path = "b.log", .data = "clean\n" },
    });
    defer std.testing.allocator.free(tar_bytes);
    {
        var st = SliceStream{ .data = tar_bytes };
        var tsum: api.webgrep_tree_summary_t = .{};
        try std.testing.expectEqual(api.WEBGREP_OK, webgrep_search_archive_reader(m, SliceStream.read, &st, null, null, null, &tsum));
        try std.testing.expectEqual(@as(u64, 2), tsum.files_searched);
        try std.testing.expectEqual(@as(u64, 1), tsum.matched_files);
    }

    const zip_bytes = try archive_mod.buildTestZipAlloc(std.testing.allocator, &.{
        .{ .path = "z.txt", .data = "HIT zip\n" },
    });
    defer std.testing.allocator.free(zip_bytes);
    {
        var st = SliceStream{ .data = zip_bytes };
        var tsum: api.webgrep_tree_summary_t = .{};
        try std.testing.expectEqual(api.WEBGREP_OK, webgrep_search_archive_reader(m, SliceStream.read, &st, null, null, null, &tsum));
        try std.testing.expectEqual(@as(u64, 1), tsum.matched_files);
    }
}

test "c_api_ext: bloom filter, seekable zstd table, and indexed gzip" {
    // 1. N-gram Bloom filter
    const bcfg = webgrep_bloom_config_default();
    var b1: ?*webgrep_bloom_t = null;
    var b2: ?*webgrep_bloom_t = null;
    try std.testing.expectEqual(api.WEBGREP_OK, webgrep_bloom_new(&bcfg, &b1));
    defer webgrep_bloom_free(b1);
    try std.testing.expectEqual(api.WEBGREP_OK, webgrep_bloom_new(&bcfg, &b2));
    defer webgrep_bloom_free(b2);

    const hay = "service timeout at shard 07";
    try std.testing.expectEqual(api.WEBGREP_OK, webgrep_bloom_add(b1, hay.ptr, hay.len));
    try std.testing.expectEqual(api.WEBGREP_OK, webgrep_bloom_merge(b2, b1));

    var m_yes: ?*api.webgrep_matcher_t = null;
    try std.testing.expectEqual(api.WEBGREP_OK, api.webgrep_matcher_compile_literal("timeout", 7, null, &m_yes));
    defer api.webgrep_matcher_free(m_yes);
    var m_no: ?*api.webgrep_matcher_t = null;
    try std.testing.expectEqual(api.WEBGREP_OK, api.webgrep_matcher_compile_literal("qxzwv9", 6, null, &m_no));
    defer api.webgrep_matcher_free(m_no);

    try std.testing.expectEqual(@as(c_int, 1), webgrep_bloom_may_contain(b2, m_yes));
    try std.testing.expectEqual(@as(c_int, 0), webgrep_bloom_may_contain(b2, m_no));

    var need: usize = 0;
    try std.testing.expectEqual(api.WEBGREP_OK, webgrep_bloom_serialize(b2, null, 0, &need));
    const ser_buf = try std.testing.allocator.alloc(u8, need);
    defer std.testing.allocator.free(ser_buf);
    try std.testing.expectEqual(api.WEBGREP_OK, webgrep_bloom_serialize(b2, ser_buf.ptr, ser_buf.len, &need));
    var b3: ?*webgrep_bloom_t = null;
    try std.testing.expectEqual(api.WEBGREP_OK, webgrep_bloom_deserialize(ser_buf.ptr, need, &b3));
    defer webgrep_bloom_free(b3);
    try std.testing.expectEqual(@as(c_int, 1), webgrep_bloom_may_contain(b3, m_yes));

    const SliceMem = struct {
        data: []const u8,
        pos: usize = 0,
        fn read(buf: [*c]u8, cap: usize, out_n: [*c]usize, userdata: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            if (self.pos >= self.data.len) {
                out_n.* = 0;
                return 0;
            }
            const n = @min(cap, self.data.len - self.pos);
            @memcpy(buf[0..n], self.data[self.pos .. self.pos + n]);
            self.pos += n;
            out_n.* = n;
            return 0;
        }
        fn readAt(offset: u64, buf: [*c]u8, cap: usize, out_n: [*c]usize, userdata: ?*anyopaque) callconv(.c) c_int {
            const self: *const @This() = @ptrCast(@alignCast(userdata.?));
            if (offset >= self.data.len or cap == 0) {
                out_n.* = 0;
                return 0;
            }
            const off: usize = @intCast(offset);
            const n = @min(cap, self.data.len - off);
            @memcpy(buf[0..n], self.data[off .. off + n]);
            out_n.* = n;
            return 0;
        }
    };

    // 2. Seekable Zstd Table
    const payload = "0123456789ABCDEF_seekable_zstd_payload_block_one_and_two";
    const zst_bytes = try seekable_mod.compressSeekableZstdAlloc(std.testing.allocator, payload, 20);
    defer std.testing.allocator.free(zst_bytes);
    {
        var src = SliceMem{ .data = zst_bytes };
        var tbl: ?*webgrep_zstd_seek_table_t = null;
        try std.testing.expectEqual(api.WEBGREP_OK, webgrep_zstd_seek_table_parse(SliceMem.readAt, &src, zst_bytes.len, &tbl));
        defer webgrep_zstd_seek_table_free(tbl);
        try std.testing.expectEqual(@as(u64, payload.len), webgrep_zstd_seek_table_uncompressed_size(tbl));

        var out: [16]u8 = undefined;
        var got: usize = 0;
        try std.testing.expectEqual(api.WEBGREP_OK, webgrep_zstd_seek_table_read_at(tbl, SliceMem.readAt, &src, zst_bytes.len, 17, &out, out.len, 0, &got));
        try std.testing.expectEqualStrings(payload[17 .. 17 + got], out[0..got]);
    }

    // 3. Indexed Gzip
    const gz_bytes = try decompress_mod.compressGzipStoredAlloc(std.testing.allocator, payload);
    defer std.testing.allocator.free(gz_bytes);
    {
        var src = SliceMem{ .data = gz_bytes };
        var idx: ?*webgrep_gzip_index_t = null;
        try std.testing.expectEqual(api.WEBGREP_OK, webgrep_gzip_index_build(SliceMem.read, &src, 16, &idx));
        defer webgrep_gzip_index_free(idx);
        try std.testing.expectEqual(@as(u64, payload.len), webgrep_gzip_index_uncompressed_size(idx));

        var gz_need: usize = 0;
        try std.testing.expectEqual(api.WEBGREP_OK, webgrep_gzip_index_serialize(idx, null, 0, &gz_need));
        const gz_ser = try std.testing.allocator.alloc(u8, gz_need);
        defer std.testing.allocator.free(gz_ser);
        try std.testing.expectEqual(api.WEBGREP_OK, webgrep_gzip_index_serialize(idx, gz_ser.ptr, gz_ser.len, &gz_need));

        var idx2: ?*webgrep_gzip_index_t = null;
        try std.testing.expectEqual(api.WEBGREP_OK, webgrep_gzip_index_deserialize(gz_ser.ptr, gz_need, &idx2));
        defer webgrep_gzip_index_free(idx2);

        var out: [14]u8 = undefined;
        var got: usize = 0;
        try std.testing.expectEqual(api.WEBGREP_OK, webgrep_gzip_index_read_at(idx2, SliceMem.readAt, &src, gz_bytes.len, 1, 17, &out, out.len, &got));
        try std.testing.expectEqualStrings(payload[17 .. 17 + got], out[0..got]);
    }
}

// ============================================================================
// Flow Control (skipTo / pause) & Stateless ResumeState (Functions 53–59)
// ============================================================================

const ResumeStateBox = struct {
    last_result: searcher.Result = .{},
    has_result: bool = false,
};

const CFlowEventSink = struct {
    on_line: webgrep_flow_line_cb,
    userdata: ?*anyopaque,
    stopped: bool = false,
    paused: bool = false,

    pub fn event(self: *CFlowEventSink, ev: sink_mod.Event) sink_mod.FlowAction {
        return switch (ev) {
            .match => |le| self.emitLine(le, false),
            .context => |le| self.emitLine(le, true),
            else => .cont,
        };
    }

    fn emitLine(self: *CFlowEventSink, le: sink_mod.LineEvent, is_context: bool) sink_mod.FlowAction {
        const cb = self.on_line orelse return .cont;

        var stack_spans: [64]api.webgrep_span_t = undefined;
        var heap_spans: ?[]api.webgrep_span_t = null;
        defer if (heap_spans) |hs| c_alloc.free(hs);

        var c_spans: []api.webgrep_span_t = stack_spans[0..0];
        if (le.matches.len > 0) {
            if (le.matches.len <= stack_spans.len) {
                c_spans = stack_spans[0..le.matches.len];
            } else if (c_alloc.alloc(api.webgrep_span_t, le.matches.len)) |allocated| {
                heap_spans = allocated;
                c_spans = allocated;
            } else |_| {
                c_spans = stack_spans[0..stack_spans.len];
            }
            for (c_spans, 0..) |*dst, idx| {
                const sp = le.matches[idx];
                dst.* = .{
                    .start = sp.start,
                    .end = sp.end,
                    .pattern_id = if (sp.pattern_id) |pid| @intCast(pid) else -1,
                    .u16_start = sp.u16_start,
                    .u16_end = sp.u16_end,
                };
            }
        }

        const text_slice = if (le.text.len > 0) le.text else le.bytes;
        const c_ev = api.webgrep_line_event_t{
            .path_ptr = if (le.source_id.len > 0) le.source_id.ptr else null,
            .path_len = le.source_id.len,
            .line_number = le.line_number,
            .byte_offset = le.absolute_offset,
            .column = le.column orelse 0,
            .u16_column = le.u16_column orelse 0,
            .text_ptr = text_slice.ptr,
            .text_len = text_slice.len,
            .bytes_ptr = le.bytes.ptr,
            .bytes_len = le.bytes.len,
            .replaced_ptr = if (le.replaced) |r| r.ptr else null,
            .replaced_len = if (le.replaced) |r| r.len else 0,
            .matches_ptr = if (c_spans.len > 0) c_spans.ptr else (&api.empty_spans)[0..0].ptr,
            .matches_len = c_spans.len,
            .is_context = if (is_context) 1 else 0,
            .truncated = if (le.truncated) 1 else 0,
            .line_number_known = if (le.line_number_known) 1 else 0,
        };

        var flow = webgrep_flow_t{};
        cb(&c_ev, self.userdata, &flow);
        return switch (flow.action) {
            WEBGREP_FLOW_STOP => {
                self.stopped = true;
                return .stop;
            },
            WEBGREP_FLOW_PAUSE => {
                self.paused = true;
                return .pause;
            },
            WEBGREP_FLOW_SKIP_TO => .{ .skip_to = flow.skip_to_offset },
            else => .cont,
        };
    }
};

pub export fn webgrep_resume_state_new() callconv(.c) ?*webgrep_resume_state_t {
    const box = c_alloc.create(ResumeStateBox) catch return null;
    box.* = .{};
    return @ptrCast(box);
}

pub export fn webgrep_resume_state_free(state: ?*webgrep_resume_state_t) callconv(.c) void {
    const ptr = state orelse return;
    const box: *ResumeStateBox = @ptrCast(@alignCast(ptr));
    c_alloc.destroy(box);
}

pub export fn webgrep_resume_state_reset(state: ?*webgrep_resume_state_t) callconv(.c) void {
    const ptr = state orelse return;
    const box: *ResumeStateBox = @ptrCast(@alignCast(ptr));
    box.* = .{};
}

pub export fn webgrep_resume_state_offset(state: ?*const webgrep_resume_state_t) callconv(.c) u64 {
    const ptr = state orelse return 0;
    const box: *const ResumeStateBox = @ptrCast(@alignCast(ptr));
    if (!box.has_result) return 0;
    return box.last_result.resume_at orelse 0;
}

pub export fn webgrep_resume_state_is_paused(state: ?*const webgrep_resume_state_t) callconv(.c) u8 {
    const ptr = state orelse return 0;
    const box: *const ResumeStateBox = @ptrCast(@alignCast(ptr));
    if (!box.has_result) return 0;
    return if (box.last_result.paused) 1 else 0;
}

pub export fn webgrep_search_slice_flow(
    matcher: ?*const api.webgrep_matcher_t,
    data_ptr: ?[*]const u8,
    data_len: usize,
    cfg: ?*const api.webgrep_config_t,
    resume_state: ?*webgrep_resume_state_t,
    on_line: webgrep_flow_line_cb,
    userdata: ?*anyopaque,
    out_summary: ?*api.webgrep_summary_t,
) callconv(.c) c_int {
    if (out_summary) |s| s.* = .{};
    const m_ptr = matcher orelse return api.WEBGREP_ERR_INVALID_ARG;
    if (data_ptr == null and data_len > 0) return api.WEBGREP_ERR_INVALID_ARG;

    const m_box: *const api.MatcherBox = @ptrCast(@alignCast(m_ptr));
    const haystack: []const u8 = if (data_ptr) |p| p[0..data_len] else "";

    var filter_bridge: api.CLineFilterBridge = undefined;
    var guard = api.ConfigGuard{};
    defer guard.deinit();
    const z_cfg = api.buildSearchConfig(cfg, &filter_bridge, &guard) catch |err| return switch (err) {
        error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
        error.InvalidArg => api.WEBGREP_ERR_INVALID_ARG,
    };

    var c_sink = CFlowEventSink{ .on_line = on_line, .userdata = userdata };
    const r_box: ?*ResumeStateBox = if (resume_state) |rs| @ptrCast(@alignCast(rs)) else null;
    const res = if (r_box != null and r_box.?.has_result and r_box.?.last_result.paused)
        (searcher.resumeSourceSlice(CFlowEventSink, &c_sink, "", haystack, &m_box.any_matcher, z_cfg, r_box.?.last_result) catch |err| return switch (err) {
            error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
            error.ContextLinesExceeded, error.BudgetExceeded, error.BufferLimit, error.DecodeLimit => api.WEBGREP_ERR_BUDGET_EXCEEDED,
        })
    else
        (searcher.searchSourceSlice(CFlowEventSink, &c_sink, "", haystack, &m_box.any_matcher, z_cfg) catch |err| return switch (err) {
            error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
            error.ContextLinesExceeded, error.BudgetExceeded, error.BufferLimit, error.DecodeLimit => api.WEBGREP_ERR_BUDGET_EXCEEDED,
        });

    if (r_box) |rb| {
        rb.last_result = res;
        rb.has_result = true;
    }
    api.populateCSummary(out_summary, res, c_sink.stopped or c_sink.paused);
    return api.WEBGREP_OK;
}

pub export fn webgrep_search_reader_flow(
    matcher: ?*const api.webgrep_matcher_t,
    read_cb: api.webgrep_read_cb,
    read_userdata: ?*anyopaque,
    cfg: ?*const api.webgrep_config_t,
    resume_state: ?*webgrep_resume_state_t,
    on_line: webgrep_flow_line_cb,
    userdata: ?*anyopaque,
    out_summary: ?*api.webgrep_summary_t,
) callconv(.c) c_int {
    if (out_summary) |s| s.* = .{};
    const m_ptr = matcher orelse return api.WEBGREP_ERR_INVALID_ARG;
    const r_cb = read_cb orelse return api.WEBGREP_ERR_INVALID_ARG;

    const m_box: *const api.MatcherBox = @ptrCast(@alignCast(m_ptr));

    var filter_bridge: api.CLineFilterBridge = undefined;
    var guard = api.ConfigGuard{};
    defer guard.deinit();
    const z_cfg = api.buildSearchConfig(cfg, &filter_bridge, &guard) catch |err| return switch (err) {
        error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
        error.InvalidArg => api.WEBGREP_ERR_INVALID_ARG,
    };

    var c_reader: CStreamIoReader = undefined;
    c_reader.initInPlace(r_cb, read_userdata);
    var c_sink = CFlowEventSink{ .on_line = on_line, .userdata = userdata };

    const r_box: ?*ResumeStateBox = if (resume_state) |rs| @ptrCast(@alignCast(rs)) else null;
    const res = if (r_box != null and r_box.?.has_result and r_box.?.last_result.paused)
        (searcher.resumeSource(CFlowEventSink, c_alloc, &c_sink, &c_reader.reader, "", &m_box.any_matcher, z_cfg, r_box.?.last_result) catch |err| return switch (err) {
            error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
            error.ContextLinesExceeded, error.BudgetExceeded, error.BufferLimit, error.DecodeLimit => api.WEBGREP_ERR_BUDGET_EXCEEDED,
            else => api.WEBGREP_ERR_IO,
        })
    else
        (searcher.searchSource(CFlowEventSink, c_alloc, &c_sink, &c_reader.reader, "", &m_box.any_matcher, z_cfg) catch |err| return switch (err) {
            error.OutOfMemory => api.WEBGREP_ERR_OUT_OF_MEMORY,
            error.ContextLinesExceeded, error.BudgetExceeded, error.BufferLimit, error.DecodeLimit => api.WEBGREP_ERR_BUDGET_EXCEEDED,
            else => api.WEBGREP_ERR_IO,
        });

    if (r_box) |rb| {
        rb.last_result = res;
        rb.has_result = true;
    }
    api.populateCSummary(out_summary, res, c_sink.stopped or c_sink.paused);
    if (c_reader.failed or res.soft_error != null) return api.WEBGREP_ERR_IO;
    return api.WEBGREP_OK;
}

test "c_api_ext v0.8: contains_regexes, excludes_regexes, unicode_classes, Flow.skipTo, and stateless ResumeState" {
    // 1. unicode_classes in C ABI regex compilation
    var ropts = api.webgrep_regex_options_default();
    ropts.unicode_classes = 1;
    var m_uni: ?*api.webgrep_matcher_t = null;
    const pat_uni = "\\d+";
    try std.testing.expectEqual(api.WEBGREP_OK, api.webgrep_matcher_compile_regex(pat_uni.ptr, pat_uni.len, &ropts, null, &m_uni));
    defer api.webgrep_matcher_free(m_uni);
    const arabic_digits = "num:\xd9\xa4\xd9\xa2!";
    var mat: api.webgrep_match_t = .{};
    try std.testing.expectEqual(@as(c_int, 1), api.webgrep_find(m_uni, arabic_digits.ptr, arabic_digits.len, 0, &mat));
    try std.testing.expectEqual(@as(usize, 4), mat.start);
    try std.testing.expectEqual(@as(usize, 8), mat.end);

    // 2. contains_regexes & excludes_regexes
    var m_main: ?*api.webgrep_matcher_t = null;
    try std.testing.expectEqual(api.WEBGREP_OK, api.webgrep_matcher_compile_literal("ERROR", 5, null, &m_main));
    defer api.webgrep_matcher_free(m_main);
    var m_inc: ?*api.webgrep_matcher_t = null;
    try std.testing.expectEqual(api.WEBGREP_OK, api.webgrep_matcher_compile_regex("db-[0-9]+", 9, null, null, &m_inc));
    defer api.webgrep_matcher_free(m_inc);
    var m_exc: ?*api.webgrep_matcher_t = null;
    try std.testing.expectEqual(api.WEBGREP_OK, api.webgrep_matcher_compile_regex("healthcheck", 11, null, null, &m_exc));
    defer api.webgrep_matcher_free(m_exc);

    const inc_arr = [_]?*const api.webgrep_matcher_t{m_inc};
    const exc_arr = [_]?*const api.webgrep_matcher_t{m_exc};
    var cfg = api.webgrep_config_default();
    cfg.contains_regexes_ptr = &inc_arr;
    cfg.contains_regexes_len = inc_arr.len;
    cfg.excludes_regexes_ptr = &exc_arr;
    cfg.excludes_regexes_len = exc_arr.len;

    const logs =
        "ERROR db-12 timeout\n" ++
        "ERROR db-99 healthcheck\n" ++
        "ERROR cache miss\n" ++
        "ERROR db-07 deadlock\n";
    var sum: api.webgrep_summary_t = .{};
    try std.testing.expectEqual(api.WEBGREP_OK, api.webgrep_search_slice(m_main, logs.ptr, logs.len, &cfg, null, null, &sum));
    try std.testing.expectEqual(@as(u64, 2), sum.matched_lines);

    // 3. Flow.pause + webgrep_resume_state_t pagination across slice
    const doc = "hit 1\nhit 2\nhit 3\n";
    var m_hit: ?*api.webgrep_matcher_t = null;
    try std.testing.expectEqual(api.WEBGREP_OK, api.webgrep_matcher_compile_literal("hit", 3, null, &m_hit));
    defer api.webgrep_matcher_free(m_hit);

    const PauseCtx = struct {
        seen_lines: [4]u64 = .{ 0, 0, 0, 0 },
        count: usize = 0,
        pause_after_one: bool = true,
        fn cb(ev: *const api.webgrep_line_event_t, userdata: ?*anyopaque, out_flow: *webgrep_flow_t) callconv(.c) void {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            if (self.count < 4) self.seen_lines[self.count] = ev.line_number;
            self.count += 1;
            if (self.pause_after_one) {
                out_flow.action = WEBGREP_FLOW_PAUSE;
            }
        }
    };

    const rs = webgrep_resume_state_new().?;
    defer webgrep_resume_state_free(rs);
    var pctx = PauseCtx{};
    var s1: api.webgrep_summary_t = .{};
    try std.testing.expectEqual(api.WEBGREP_OK, webgrep_search_slice_flow(m_hit, doc.ptr, doc.len, null, rs, PauseCtx.cb, &pctx, &s1));
    try std.testing.expectEqual(@as(u8, 1), webgrep_resume_state_is_paused(rs));
    try std.testing.expectEqual(@as(u64, 6), webgrep_resume_state_offset(rs));
    try std.testing.expectEqual(@as(usize, 1), pctx.count);
    try std.testing.expectEqual(@as(u64, 1), pctx.seen_lines[0]);

    // Resume to completion
    pctx.pause_after_one = false;
    var s2: api.webgrep_summary_t = .{};
    try std.testing.expectEqual(api.WEBGREP_OK, webgrep_search_slice_flow(m_hit, doc.ptr, doc.len, null, rs, PauseCtx.cb, &pctx, &s2));
    try std.testing.expectEqual(@as(u8, 0), webgrep_resume_state_is_paused(rs));
    try std.testing.expectEqual(@as(usize, 3), pctx.count);
    try std.testing.expectEqual(@as(u64, 2), pctx.seen_lines[1]);
    try std.testing.expectEqual(@as(u64, 3), pctx.seen_lines[2]);

    // 4. Flow.skipTo(offset)
    const SkipCtx = struct {
        count: usize = 0,
        last_line: u64 = 0,
        fn cb(ev: *const api.webgrep_line_event_t, userdata: ?*anyopaque, out_flow: *webgrep_flow_t) callconv(.c) void {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.count += 1;
            self.last_line = ev.line_number;
            if (self.count == 1) {
                out_flow.action = WEBGREP_FLOW_SKIP_TO;
                out_flow.skip_to_offset = 12; // skip "hit 2\n" directly to "hit 3\n"
            }
        }
    };
    var sk = SkipCtx{};
    var s3: api.webgrep_summary_t = .{};
    try std.testing.expectEqual(api.WEBGREP_OK, webgrep_search_slice_flow(m_hit, doc.ptr, doc.len, null, null, SkipCtx.cb, &sk, &s3));
    try std.testing.expectEqual(@as(usize, 2), sk.count);
    try std.testing.expectEqual(@as(u64, 3), sk.last_line);
}
