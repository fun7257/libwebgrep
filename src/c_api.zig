//! [Module] c_api.zig
//! [Layer] Layer 6 — C ABI & Cross-Language FFI Exports (`F4`)
//! [Role] Exports 17 C ABI functions (`callconv(.c)`) matching `include/webgrep.h` for embedding
//!        `libwebgrep` in C, C++, Rust, Go, Python, and Node.js.
//! [Invariants]
//!   1. Zero mutable global state; compiled `webgrep_matcher_t` handles are immutable during search
//!      and safe to share concurrently across threads without locking.
//!   2. Reusable `webgrep_scratch_t` handles encapsulate per-worker `searcher.Scratch` pools.
//!   3. All borrowed pointers in `webgrep_line_event_t` are valid for the duration of `webgrep_line_cb`.

const std = @import("std");
const matcher_mod = @import("matcher.zig");
const finder_mod = @import("finder/finder.zig");
const multi_mod = @import("finder/multi.zig");
const regex_mod = @import("regex.zig");
const sink_mod = @import("sink.zig");
const searcher = @import("searcher.zig");
const config_mod = @import("search/config.zig");
const pull_mod = @import("search/pull.zig");
const pipeline_mod = @import("search/pipeline.zig");
const state_mod = @import("search/state.zig");
const archive_mod = @import("codec/archive.zig");
const tree_mod = @import("search/tree.zig");

const builtin = @import("builtin");
const c_alloc = if (builtin.is_test)
    std.testing.allocator
else if (builtin.link_libc)
    std.heap.c_allocator
else
    std.heap.smp_allocator;

// ============================================================================
// Status & Error Codes
// ============================================================================

pub const WEBGREP_OK: c_int = 0;
pub const WEBGREP_ERR_INVALID_ARG: c_int = -1;
pub const WEBGREP_ERR_OUT_OF_MEMORY: c_int = -2;
pub const WEBGREP_ERR_SYNTAX: c_int = -3;
pub const WEBGREP_ERR_TOO_LARGE: c_int = -4;
pub const WEBGREP_ERR_BUDGET_EXCEEDED: c_int = -5;
pub const WEBGREP_ERR_LIMIT_EXCEEDED: c_int = -5;
pub const WEBGREP_ERR_IO: c_int = -6;
pub const WEBGREP_ERR_CORRUPT_ARCHIVE: c_int = -7;
pub const WEBGREP_ERR_ARCHIVE_LIMIT: c_int = -8;

// ============================================================================
// Opaque Handles & Extern Structs
// ============================================================================

pub const webgrep_matcher_t = opaque {};
pub const webgrep_scratch_t = opaque {};

pub const webgrep_pattern_t = extern struct {
    ptr: ?[*]const u8 = null,
    len: usize = 0,
};

pub const webgrep_find_options_t = extern struct {
    case_mode: c_int = 0,
    unicode_case: u8 = 1,
    max_patterns: usize = 0,
    max_pattern_bytes: usize = 0,
    max_unicode_variants: usize = 0,
};

pub const webgrep_regex_options_t = extern struct {
    case_mode: c_int = 0,
    unicode_case: u8 = 1,
    multiline: u8 = 0,
    dot_all: u8 = 0,
    max_inst: usize = 0,
    max_multiline_window: usize = 64 * 1024,
    max_dfa_states: u16 = 256,
    max_repeat: usize = 0,
    max_recursion_depth: usize = 0,
    max_patterns: usize = 0,
    max_pattern_bytes: usize = 0,
};

pub const webgrep_compile_diag_t = extern struct {
    code: c_int = 0,
    offset: usize = 0,
    line: usize = 1,
    column: usize = 1,
    pattern_index: usize = 0,
    has_pattern_index: u8 = 0,
    message: [128]u8 = @splat(0),
};

pub const webgrep_match_t = extern struct {
    start: usize = 0,
    end: usize = 0,
    pattern_id: u32 = 0,
    has_pattern_id: u8 = 0,
};

pub const webgrep_span_t = extern struct {
    start: usize = 0,
    end: usize = 0,
    pattern_id: i32 = -1,
    u16_start: usize = 0,
    u16_end: usize = 0,
};

const empty_spans = [1]webgrep_span_t{.{}};

pub const webgrep_line_event_t = extern struct {
    path_ptr: ?[*]const u8 = null,
    path_len: usize = 0,
    line_number: u64 = 0,
    byte_offset: u64 = 0,
    column: u64 = 0,
    u16_column: u64 = 0,
    text_ptr: ?[*]const u8 = null,
    text_len: usize = 0,
    bytes_ptr: ?[*]const u8 = null,
    bytes_len: usize = 0,
    replaced_ptr: ?[*]const u8 = null,
    replaced_len: usize = 0,
    matches_ptr: [*]const webgrep_span_t = (&empty_spans)[0..0].ptr,
    matches_len: usize = 0,
    is_context: u8 = 0,
    truncated: u8 = 0,
};

pub const webgrep_config_t = extern struct {
    scratch: ?*webgrep_scratch_t = null,
    replacement_ptr: ?[*]const u8 = null,
    replacement_len: usize = 0,
    before_context: u32 = 0,
    after_context: u32 = 0,
    max_count: u64 = 0,
    max_results: u64 = 0,
    max_bytes: u64 = 0,
    max_decode_bytes: usize = 0,
    buffer_size: usize = 0,
    max_line_len: usize = 0,
    encoding: c_int = 0,
    compression: c_int = 0,
    binary_mode: c_int = 0,
    match_mode: c_int = 0,
    invert_match: u8 = 0,
    passthru: u8 = 0,
    line_number: u8 = 1,
    column: u8 = 0,
    whole_word: u8 = 0,
    line_regexp: u8 = 0,
    max_context_lines: u32 = 0,
    max_compression_ratio: u64 = 0,
    time_budget_ns: u64 = 0,
    max_output_bytes: u64 = 0,
};

pub const webgrep_summary_t = extern struct {
    matched_lines: u64 = 0,
    matches: u64 = 0,
    bytes_searched: u64 = 0,
    bytes_read: u64 = 0,
    elapsed_ns: u64 = 0,
    stopped: u8 = 0,
    partial: u8 = 0,
    binary_detected: u8 = 0,
    limit_hit: c_int = 0,
};

pub const webgrep_tree_config_t = extern struct {
    search: webgrep_config_t = .{},
    format: c_int = 0,
    max_entries: usize = 10_000,
    max_entry_bytes: u64 = 64 * 1024 * 1024,
    max_total_bytes: u64 = 256 * 1024 * 1024,
    max_compression_ratio: u64 = 100,
    max_depth: usize = 256,
    max_concurrency: usize = 1,
    hidden: u8 = 0,
    skip_git: u8 = 1,
    respect_gitignore: u8 = 1,
    respect_ignore: u8 = 1,
    max_ignore_file_bytes: usize = 0,
    max_glob_rules: usize = 0,
    max_glob_rule_len: usize = 0,
    max_glob_brace_depth: usize = 0,
};

pub const webgrep_tree_summary_t = extern struct {
    files_searched: u64 = 0,
    matched_files: u64 = 0,
    matched_lines: u64 = 0,
    matches: u64 = 0,
    bytes_searched: u64 = 0,
    files_skipped_binary: u64 = 0,
    files_failed: u64 = 0,
    stopped: u8 = 0,
};

pub const webgrep_line_cb = ?*const fn (ev: *const webgrep_line_event_t, userdata: ?*anyopaque) callconv(.c) c_int;
pub const webgrep_read_cb = ?*const fn (buf: [*c]u8, cap: usize, out_n: [*c]usize, userdata: ?*anyopaque) callconv(.c) c_int;

// ============================================================================
// Internal Handle Wrappers & Conversion Helpers
// ============================================================================

const MatcherPayload = union(enum) {
    literal: struct {
        owned_pattern: []u8,
        finder: finder_mod.Finder,
    },
    multi: struct {
        owned_patterns: [][]u8,
        pattern_slices: [][]const u8,
        engine: multi_mod.Multi,
    },
    regex: regex_mod.Regex,
    regex_set: regex_mod.RegexSet,
};

const MatcherBox = struct {
    payload: MatcherPayload,
    any_matcher: matcher_mod.AnyMatcher = undefined,

    fn bindAnyMatcher(self: *MatcherBox) void {
        self.any_matcher = switch (self.payload) {
            .literal => |*lit| matcher_mod.AnyMatcher.init(finder_mod.Finder, &lit.finder),
            .multi => |*m| matcher_mod.AnyMatcher.init(multi_mod.Multi, &m.engine),
            .regex => |*re| matcher_mod.AnyMatcher.init(regex_mod.Regex, re),
            .regex_set => |*rs| matcher_mod.AnyMatcher.init(regex_mod.RegexSet, rs),
        };
    }

    fn deinit(self: *MatcherBox) void {
        switch (self.payload) {
            .literal => |*lit| {
                if (lit.owned_pattern.len > 0) c_alloc.free(lit.owned_pattern);
            },
            .multi => |*m| {
                m.engine.deinit();
                for (m.owned_patterns) |p| {
                    if (p.len > 0) c_alloc.free(p);
                }
                if (m.owned_patterns.len > 0) c_alloc.free(m.owned_patterns);
                if (m.pattern_slices.len > 0) c_alloc.free(m.pattern_slices);
            },
            .regex => |*re| re.deinit(),
            .regex_set => |*rs| rs.deinit(),
        }
    }
};

const ScratchBox = struct {
    scratch: searcher.Scratch,
};

fn toCaseMode(v: c_int) ?matcher_mod.CaseMode {
    return switch (v) {
        0 => .sensitive,
        1 => .insensitive,
        2 => .smart,
        else => null,
    };
}

fn toFindOptions(opts: ?*const webgrep_find_options_t) ?matcher_mod.FindOptions {
    const o = opts orelse return matcher_mod.FindOptions{};
    const cm = toCaseMode(o.case_mode) orelse return null;
    return .{
        .case = cm,
        .unicode_case = o.unicode_case != 0,
        .max_pattern_count = if (o.max_patterns > 0) o.max_patterns else null,
        .max_pattern_bytes = if (o.max_pattern_bytes > 0) o.max_pattern_bytes else null,
        .max_unicode_variants = if (o.max_unicode_variants > 0) o.max_unicode_variants else 64,
    };
}

fn toRegexOptions(opts: ?*const webgrep_regex_options_t) ?regex_mod.RegexOptions {
    const o = opts orelse return regex_mod.RegexOptions{};
    const cm = toCaseMode(o.case_mode) orelse return null;
    return .{
        .case = cm,
        .unicode_case = o.unicode_case != 0,
        .multiline = o.multiline != 0,
        .dot_all = o.dot_all != 0,
        .max_inst = if (o.max_inst > 0) o.max_inst else null,
        .max_multiline_window = if (o.max_multiline_window > 0) o.max_multiline_window else regex_mod.default_multiline_window,
        .max_dfa_states = if (o.max_dfa_states > 0) o.max_dfa_states else 256,
        .max_repeat = if (o.max_repeat > 0) o.max_repeat else regex_mod.default_max_repeat,
        .max_recursion_depth = if (o.max_recursion_depth > 0) o.max_recursion_depth else regex_mod.default_max_recursion_depth,
        .max_pattern_count = if (o.max_patterns > 0) o.max_patterns else null,
        .max_pattern_bytes = if (o.max_pattern_bytes > 0) o.max_pattern_bytes else null,
    };
}

fn fillCDiag(out_diag: ?*webgrep_compile_diag_t, z_diag: regex_mod.CompileDiagnostic) void {
    const d = out_diag orelse return;
    d.* = .{
        .code = @intFromEnum(z_diag.code),
        .offset = z_diag.offset,
        .line = z_diag.line,
        .column = z_diag.column,
        .pattern_index = z_diag.pattern_index orelse 0,
        .has_pattern_index = if (z_diag.pattern_index != null) 1 else 0,
    };
    const copy_len = @min(z_diag.message.len, d.message.len - 1);
    if (copy_len > 0) {
        @memcpy(d.message[0..copy_len], z_diag.message[0..copy_len]);
    }
    d.message[copy_len] = 0;
}

fn mapRegexError(err: regex_mod.Error) c_int {
    return switch (err) {
        error.OutOfMemory => WEBGREP_ERR_OUT_OF_MEMORY,
        error.RegexTooLarge,
        error.PatternCountExceeded,
        error.PatternBytesExceeded,
        error.InvalidMultilineWindow,
        => WEBGREP_ERR_TOO_LARGE,
        error.RegexSyntax,
        error.PatternHasNewline,
        => WEBGREP_ERR_SYNTAX,
    };
}

fn toSearchConfig(cfg: ?*const webgrep_config_t) ?searcher.SearchConfig {
    var z_cfg: searcher.SearchConfig = .{
        .allocator = c_alloc,
        .decode_allocator = c_alloc,
        .line_numbers = true,
    };
    const c = cfg orelse return z_cfg;

    if (c.scratch) |s_ptr| {
        const s_box: *ScratchBox = @ptrCast(@alignCast(s_ptr));
        z_cfg.scratch_pool = &s_box.scratch;
    }
    if (c.replacement_ptr) |rp| {
        z_cfg.replacement = rp[0..c.replacement_len];
    } else if (c.replacement_len > 0) {
        return null;
    }

    if (c.before_context > 0) z_cfg.before = c.before_context;
    if (c.after_context > 0) z_cfg.after = c.after_context;
    if (c.max_count > 0) z_cfg.max_count = c.max_count;
    if (c.max_results > 0) z_cfg.max_results = c.max_results;
    if (c.max_bytes > 0) {
        z_cfg.max_source_bytes = c.max_bytes;
        z_cfg.max_request_bytes = c.max_bytes;
    }
    if (c.max_decode_bytes > 0) {
        z_cfg.max_decode_bytes = c.max_decode_bytes;
        z_cfg.max_decompressed_bytes = c.max_decode_bytes;
    }
    if (c.buffer_size > 0) z_cfg.buffer_size = c.buffer_size;
    if (c.max_line_len > 0) z_cfg.max_line_len = c.max_line_len;
    if (c.max_context_lines > 0) z_cfg.max_context_lines = c.max_context_lines;
    if (c.max_compression_ratio > 0) z_cfg.max_compression_ratio = c.max_compression_ratio;
    if (c.time_budget_ns > 0) z_cfg.time_budget_ns = c.time_budget_ns;
    if (c.max_output_bytes > 0) z_cfg.max_output_bytes = c.max_output_bytes;

    z_cfg.encoding = switch (c.encoding) {
        0 => .auto,
        1 => .utf8,
        2 => .utf16le,
        3 => .utf16be,
        4 => .gbk,
        5 => .latin1,
        6 => .none,
        else => return null,
    };
    z_cfg.compression = switch (c.compression) {
        0 => .none,
        1 => .auto,
        2 => .gzip,
        3 => .zstd,
        4 => .xz,
        else => return null,
    };
    z_cfg.binary = switch (c.binary_mode) {
        0 => .quit,
        1 => .report,
        2 => .none,
        else => return null,
    };
    z_cfg.match_mode = switch (c.match_mode) {
        0 => .earliest,
        1 => .leftmost_first,
        else => return null,
    };

    z_cfg.invert = c.invert_match != 0;
    z_cfg.passthru = c.passthru != 0;
    z_cfg.line_numbers = c.line_number != 0;
    z_cfg.whole_word = c.whole_word != 0;
    z_cfg.whole_line = c.line_regexp != 0;
    return z_cfg;
}

const CLineEventSink = struct {
    on_line: webgrep_line_cb,
    userdata: ?*anyopaque,
    stopped: bool = false,
    binary_skipped: u64 = 0,

    pub fn event(self: *CLineEventSink, ev: sink_mod.Event) sink_mod.Flow {
        switch (ev) {
            .match => |le| return self.emitLine(le, false),
            .context => |le| return self.emitLine(le, true),
            .end => |e| {
                if (e.outcome == .binary_quit) self.binary_skipped += 1;
                return .cont;
            },
            else => return .cont,
        }
    }

    fn emitLine(self: *CLineEventSink, le: sink_mod.LineEvent, is_context: bool) sink_mod.Flow {
        const cb = self.on_line orelse return .cont;

        var stack_spans: [64]webgrep_span_t = undefined;
        var heap_spans: ?[]webgrep_span_t = null;
        defer if (heap_spans) |hs| c_alloc.free(hs);

        var c_spans: []webgrep_span_t = stack_spans[0..0];
        if (le.matches.len > 0) {
            if (le.matches.len <= stack_spans.len) {
                c_spans = stack_spans[0..le.matches.len];
            } else if (c_alloc.alloc(webgrep_span_t, le.matches.len)) |allocated| {
                heap_spans = allocated;
                c_spans = allocated;
            } else |_| {
                c_spans = stack_spans[0..stack_spans.len];
            }
            for (c_spans, le.matches[0..c_spans.len]) |*dst, src| {
                dst.* = .{
                    .start = src.start,
                    .end = src.end,
                    .pattern_id = if (src.pattern_id) |pid| @as(i32, @intCast(pid)) else -1,
                    .u16_start = src.u16_start,
                    .u16_end = src.u16_end,
                };
            }
        }

        const text_slice = if (le.text.len > 0) le.text else le.bytes;
        const c_ev = webgrep_line_event_t{
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
            .matches_ptr = if (c_spans.len > 0) c_spans.ptr else (&empty_spans)[0..0].ptr,
            .matches_len = c_spans.len,
            .is_context = if (is_context) 1 else 0,
            .truncated = if (le.truncated) 1 else 0,
        };

        const rc = cb(&c_ev, self.userdata);
        if (rc != 0) {
            self.stopped = true;
            return .stop;
        }
        return .cont;
    }
};

fn populateCSummary(out_summary: ?*webgrep_summary_t, res: sink_mod.Result, stopped_by_cb: bool) void {
    const s = out_summary orelse return;
    s.* = .{
        .matched_lines = res.matched_lines,
        .matches = res.matches,
        .bytes_searched = res.bytes_searched,
        .bytes_read = res.bytes_read,
        .elapsed_ns = res.elapsed_ns,
        .stopped = if (stopped_by_cb or res.outcome == .stopped) 1 else 0,
        .partial = if (res.partial) 1 else 0,
        .binary_detected = if (res.binary_offset != null or res.outcome == .binary_quit or res.outcome == .binary_matched) 1 else 0,
        .limit_hit = @intFromEnum(res.limit_hit),
    };
}

// ============================================================================
// Exported C ABI Functions (17 Functions)
// ============================================================================

pub export fn webgrep_version() callconv(.c) [*:0]const u8 {
    return "0.5.0";
}

pub export fn webgrep_find_options_default() callconv(.c) webgrep_find_options_t {
    return .{};
}

pub export fn webgrep_regex_options_default() callconv(.c) webgrep_regex_options_t {
    return .{};
}

pub export fn webgrep_config_default() callconv(.c) webgrep_config_t {
    return .{};
}

pub export fn webgrep_tree_config_default() callconv(.c) webgrep_tree_config_t {
    return .{};
}

pub export fn webgrep_matcher_compile_literal(
    pattern_ptr: ?[*]const u8,
    pattern_len: usize,
    opts: ?*const webgrep_find_options_t,
    out_matcher: ?*?*webgrep_matcher_t,
) callconv(.c) c_int {
    const out = out_matcher orelse return WEBGREP_ERR_INVALID_ARG;
    out.* = null;
    if (pattern_ptr == null and pattern_len > 0) return WEBGREP_ERR_INVALID_ARG;

    const find_opts = toFindOptions(opts) orelse return WEBGREP_ERR_INVALID_ARG;
    const pat: []const u8 = if (pattern_ptr) |p| p[0..pattern_len] else "";

    const owned = if (pat.len > 0)
        c_alloc.dupe(u8, pat) catch return WEBGREP_ERR_OUT_OF_MEMORY
    else
        @as([]u8, &.{});
    errdefer if (owned.len > 0) c_alloc.free(owned);

    const f = finder_mod.Finder.init(owned, find_opts) catch |err| return switch (err) {
        error.PatternHasNewline => WEBGREP_ERR_SYNTAX,
        error.PatternCountExceeded, error.PatternBytesExceeded => WEBGREP_ERR_TOO_LARGE,
    };

    const box = c_alloc.create(MatcherBox) catch return WEBGREP_ERR_OUT_OF_MEMORY;
    box.* = .{
        .payload = .{
            .literal = .{
                .owned_pattern = owned,
                .finder = f,
            },
        },
    };
    box.bindAnyMatcher();
    out.* = @ptrCast(box);
    return WEBGREP_OK;
}

pub export fn webgrep_matcher_compile_multi(
    patterns_ptr: ?[*]const webgrep_pattern_t,
    patterns_len: usize,
    opts: ?*const webgrep_find_options_t,
    out_matcher: ?*?*webgrep_matcher_t,
) callconv(.c) c_int {
    const out = out_matcher orelse return WEBGREP_ERR_INVALID_ARG;
    out.* = null;
    if (patterns_ptr == null and patterns_len > 0) return WEBGREP_ERR_INVALID_ARG;

    const find_opts = toFindOptions(opts) orelse return WEBGREP_ERR_INVALID_ARG;

    if (patterns_len > 0) {
        const c_pats = patterns_ptr.?[0..patterns_len];
        for (c_pats) |cp| {
            if (cp.ptr == null and cp.len > 0) return WEBGREP_ERR_INVALID_ARG;
        }
    }

    const owned_patterns = if (patterns_len > 0)
        c_alloc.alloc([]u8, patterns_len) catch return WEBGREP_ERR_OUT_OF_MEMORY
    else
        @as([][]u8, &.{});
    var initialized_count: usize = 0;
    errdefer {
        for (owned_patterns[0..initialized_count]) |p| {
            if (p.len > 0) c_alloc.free(p);
        }
        if (owned_patterns.len > 0) c_alloc.free(owned_patterns);
    }

    const pattern_slices = if (patterns_len > 0)
        c_alloc.alloc([]const u8, patterns_len) catch return WEBGREP_ERR_OUT_OF_MEMORY
    else
        @as([][]const u8, &.{});
    errdefer if (pattern_slices.len > 0) c_alloc.free(pattern_slices);

    if (patterns_len > 0) {
        const c_pats = patterns_ptr.?[0..patterns_len];
        for (c_pats, 0..) |cp, i| {
            const raw: []const u8 = if (cp.ptr) |p| p[0..cp.len] else "";
            const duped = if (raw.len > 0)
                c_alloc.dupe(u8, raw) catch return WEBGREP_ERR_OUT_OF_MEMORY
            else
                @as([]u8, &.{});
            owned_patterns[i] = duped;
            pattern_slices[i] = duped;
            initialized_count += 1;
        }
    }

    var m = multi_mod.Multi.init(c_alloc, pattern_slices, find_opts) catch |err| return switch (err) {
        error.OutOfMemory => WEBGREP_ERR_OUT_OF_MEMORY,
        error.PatternHasNewline => WEBGREP_ERR_SYNTAX,
        error.PatternCountExceeded, error.PatternBytesExceeded => WEBGREP_ERR_TOO_LARGE,
    };
    errdefer m.deinit();

    const box = c_alloc.create(MatcherBox) catch return WEBGREP_ERR_OUT_OF_MEMORY;
    box.* = .{
        .payload = .{
            .multi = .{
                .owned_patterns = owned_patterns,
                .pattern_slices = pattern_slices,
                .engine = m,
            },
        },
    };
    box.bindAnyMatcher();
    out.* = @ptrCast(box);
    return WEBGREP_OK;
}

pub export fn webgrep_matcher_compile_regex(
    pattern_ptr: ?[*]const u8,
    pattern_len: usize,
    opts: ?*const webgrep_regex_options_t,
    out_diag: ?*webgrep_compile_diag_t,
    out_matcher: ?*?*webgrep_matcher_t,
) callconv(.c) c_int {
    if (out_diag) |d| d.* = .{};
    const out = out_matcher orelse return WEBGREP_ERR_INVALID_ARG;
    out.* = null;
    if (pattern_ptr == null and pattern_len > 0) return WEBGREP_ERR_INVALID_ARG;

    const re_opts = toRegexOptions(opts) orelse return WEBGREP_ERR_INVALID_ARG;
    const pat: []const u8 = if (pattern_ptr) |p| p[0..pattern_len] else "";

    var z_diag: regex_mod.CompileDiagnostic = .{};
    var re = regex_mod.Regex.initDiagnostic(c_alloc, pat, re_opts, &z_diag) catch |err| {
        fillCDiag(out_diag, z_diag);
        return mapRegexError(err);
    };
    errdefer re.deinit();

    const box = c_alloc.create(MatcherBox) catch return WEBGREP_ERR_OUT_OF_MEMORY;
    box.* = .{
        .payload = .{ .regex = re },
    };
    box.bindAnyMatcher();
    out.* = @ptrCast(box);
    return WEBGREP_OK;
}

pub export fn webgrep_matcher_compile_regex_set(
    patterns_ptr: ?[*]const webgrep_pattern_t,
    patterns_len: usize,
    opts: ?*const webgrep_regex_options_t,
    out_diag: ?*webgrep_compile_diag_t,
    out_matcher: ?*?*webgrep_matcher_t,
) callconv(.c) c_int {
    if (out_diag) |d| d.* = .{};
    const out = out_matcher orelse return WEBGREP_ERR_INVALID_ARG;
    out.* = null;
    if (patterns_ptr == null and patterns_len > 0) return WEBGREP_ERR_INVALID_ARG;

    const re_opts = toRegexOptions(opts) orelse return WEBGREP_ERR_INVALID_ARG;

    const slices = c_alloc.alloc([]const u8, patterns_len) catch return WEBGREP_ERR_OUT_OF_MEMORY;
    defer c_alloc.free(slices);

    if (patterns_len > 0) {
        const c_pats = patterns_ptr.?[0..patterns_len];
        for (c_pats, 0..) |cp, i| {
            if (cp.ptr == null and cp.len > 0) return WEBGREP_ERR_INVALID_ARG;
            slices[i] = if (cp.ptr) |p| p[0..cp.len] else "";
        }
    }

    var z_diag: regex_mod.CompileDiagnostic = .{};
    var rs = regex_mod.RegexSet.initDiagnostic(c_alloc, slices, re_opts, &z_diag) catch |err| {
        fillCDiag(out_diag, z_diag);
        return mapRegexError(err);
    };
    errdefer rs.deinit();

    const box = c_alloc.create(MatcherBox) catch return WEBGREP_ERR_OUT_OF_MEMORY;
    box.* = .{
        .payload = .{ .regex_set = rs },
    };
    box.bindAnyMatcher();
    out.* = @ptrCast(box);
    return WEBGREP_OK;
}

pub export fn webgrep_matcher_free(matcher: ?*webgrep_matcher_t) callconv(.c) void {
    const ptr = matcher orelse return;
    const box: *MatcherBox = @ptrCast(@alignCast(ptr));
    box.deinit();
    c_alloc.destroy(box);
}

pub export fn webgrep_scratch_new() callconv(.c) ?*webgrep_scratch_t {
    const box = c_alloc.create(ScratchBox) catch return null;
    box.* = .{
        .scratch = searcher.Scratch.init(c_alloc),
    };
    return @ptrCast(box);
}

pub export fn webgrep_scratch_free(scratch: ?*webgrep_scratch_t) callconv(.c) void {
    const ptr = scratch orelse return;
    const box: *ScratchBox = @ptrCast(@alignCast(ptr));
    box.scratch.deinit();
    c_alloc.destroy(box);
}

pub export fn webgrep_find(
    matcher: ?*const webgrep_matcher_t,
    haystack_ptr: ?[*]const u8,
    haystack_len: usize,
    start_offset: usize,
    out_match: ?*webgrep_match_t,
) callconv(.c) c_int {
    const m_ptr = matcher orelse return WEBGREP_ERR_INVALID_ARG;
    const out = out_match orelse return WEBGREP_ERR_INVALID_ARG;
    out.* = .{};

    if (haystack_ptr == null and haystack_len > 0) return WEBGREP_ERR_INVALID_ARG;
    if (start_offset > haystack_len) return WEBGREP_ERR_INVALID_ARG;

    const hay: []const u8 = if (haystack_ptr) |p| p[0..haystack_len] else "";
    const box: *const MatcherBox = @ptrCast(@alignCast(m_ptr));

    if (box.any_matcher.find(hay, start_offset, .earliest)) |hit| {
        out.* = .{
            .start = hit.start,
            .end = hit.end,
            .pattern_id = hit.pattern_id orelse 0,
            .has_pattern_id = if (hit.pattern_id != null) 1 else 0,
        };
        return 1;
    }
    return 0;
}

pub export fn webgrep_regex_set_matches(
    matcher: ?*const webgrep_matcher_t,
    haystack_ptr: ?[*]const u8,
    haystack_len: usize,
    out_ids_ptr: ?[*]u32,
    out_ids_cap: usize,
    out_count: ?*usize,
) callconv(.c) c_int {
    const m_ptr = matcher orelse return WEBGREP_ERR_INVALID_ARG;
    const count_ptr = out_count orelse return WEBGREP_ERR_INVALID_ARG;
    count_ptr.* = 0;

    if (haystack_ptr == null and haystack_len > 0) return WEBGREP_ERR_INVALID_ARG;
    if (out_ids_ptr == null and out_ids_cap > 0) return WEBGREP_ERR_INVALID_ARG;

    const box: *const MatcherBox = @ptrCast(@alignCast(m_ptr));
    const rs: *const regex_mod.RegexSet = switch (box.payload) {
        .regex_set => |*set| set,
        else => return WEBGREP_ERR_INVALID_ARG,
    };

    const hay: []const u8 = if (haystack_ptr) |p| p[0..haystack_len] else "";
    var empty_ids: [0]u32 = .{};
    const out_slice: []u32 = if (out_ids_ptr) |p| p[0..out_ids_cap] else empty_ids[0..];
    count_ptr.* = rs.matches(hay, out_slice);
    return WEBGREP_OK;
}

pub export fn webgrep_search_slice(
    matcher: ?*const webgrep_matcher_t,
    data_ptr: ?[*]const u8,
    data_len: usize,
    cfg: ?*const webgrep_config_t,
    on_line: webgrep_line_cb,
    userdata: ?*anyopaque,
    out_summary: ?*webgrep_summary_t,
) callconv(.c) c_int {
    if (out_summary) |s| s.* = .{};
    const m_ptr = matcher orelse return WEBGREP_ERR_INVALID_ARG;
    if (data_ptr == null and data_len > 0) return WEBGREP_ERR_INVALID_ARG;

    const z_cfg = toSearchConfig(cfg) orelse return WEBGREP_ERR_INVALID_ARG;
    const hay: []const u8 = if (data_ptr) |p| p[0..data_len] else "";
    const box: *const MatcherBox = @ptrCast(@alignCast(m_ptr));

    var sink = CLineEventSink{
        .on_line = on_line,
        .userdata = userdata,
    };

    const res = searcher.searchSourceSlice(
        CLineEventSink,
        &sink,
        "",
        hay,
        &box.any_matcher,
        z_cfg,
    ) catch |err| return switch (err) {
        error.OutOfMemory => WEBGREP_ERR_OUT_OF_MEMORY,
        error.ContextLinesExceeded,
        error.DecodeLimit,
        error.BufferLimit,
        error.BudgetExceeded,
        => WEBGREP_ERR_BUDGET_EXCEEDED,
    };

    populateCSummary(out_summary, res, sink.stopped);
    if (res.soft_error != null) return WEBGREP_ERR_IO;
    if (res.limit_hit == .decompressed_bytes) return WEBGREP_ERR_BUDGET_EXCEEDED;
    return WEBGREP_OK;
}

pub export fn webgrep_search_reader(
    matcher: ?*const webgrep_matcher_t,
    read_cb: webgrep_read_cb,
    read_userdata: ?*anyopaque,
    cfg: ?*const webgrep_config_t,
    on_line: webgrep_line_cb,
    line_userdata: ?*anyopaque,
    out_summary: ?*webgrep_summary_t,
) callconv(.c) c_int {
    if (out_summary) |s| s.* = .{};
    const m_ptr = matcher orelse return WEBGREP_ERR_INVALID_ARG;
    const r_cb = read_cb orelse return WEBGREP_ERR_INVALID_ARG;

    const raw_cfg = toSearchConfig(cfg) orelse return WEBGREP_ERR_INVALID_ARG;
    const z_cfg = config_mod.serviceConfig(raw_cfg);
    const box: *const MatcherBox = @ptrCast(@alignCast(m_ptr));

    var sink = CLineEventSink{
        .on_line = on_line,
        .userdata = line_userdata,
    };
    var bridge = pull_mod.EventBridge(CLineEventSink){
        .inner = &sink,
        .source_id = "",
        .config = z_cfg,
    };

    const CReadCtx = struct {
        cb: *const fn (buf: [*c]u8, cap: usize, out_n: [*c]usize, userdata: ?*anyopaque) callconv(.c) c_int,
        userdata: ?*anyopaque,
        failed: bool = false,

        fn read(raw: *anyopaque, dest: []u8) config_mod.ReadError!usize {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (dest.len == 0) return 0;
            var n: usize = 0;
            const rc = self.cb(dest.ptr, dest.len, &n, self.userdata);
            if (rc != 0 or n > dest.len) {
                self.failed = true;
                return error.ReadFailed;
            }
            return n;
        }
    };

    var rctx = CReadCtx{
        .cb = r_cb,
        .userdata = read_userdata,
    };

    state_mod.resetStats(&box.any_matcher);
    const res = pipeline_mod.drive(
        pull_mod.EventBridge(CLineEventSink),
        c_alloc,
        &bridge,
        &box.any_matcher,
        z_cfg,
        "",
        CReadCtx.read,
        &rctx,
    ) catch |err| return switch (err) {
        error.OutOfMemory => WEBGREP_ERR_OUT_OF_MEMORY,
        error.ContextLinesExceeded,
        error.DecodeLimit,
        error.BufferLimit,
        error.BudgetExceeded,
        => WEBGREP_ERR_BUDGET_EXCEEDED,
        else => WEBGREP_ERR_IO,
    };

    pull_mod.emitSummary(CLineEventSink, &sink, "", z_cfg, res);
    populateCSummary(out_summary, res, sink.stopped);
    if (rctx.failed or res.soft_error != null) return WEBGREP_ERR_IO;
    if (res.limit_hit == .decompressed_bytes) return WEBGREP_ERR_BUDGET_EXCEEDED;
    return WEBGREP_OK;
}

pub export fn webgrep_search_archive_slice(
    matcher: ?*const webgrep_matcher_t,
    archive_ptr: ?[*]const u8,
    archive_len: usize,
    tree_cfg: ?*const webgrep_tree_config_t,
    on_line: webgrep_line_cb,
    userdata: ?*anyopaque,
    out_summary: ?*webgrep_tree_summary_t,
) callconv(.c) c_int {
    if (out_summary) |s| s.* = .{};
    const m_ptr = matcher orelse return WEBGREP_ERR_INVALID_ARG;
    if (archive_ptr == null and archive_len > 0) return WEBGREP_ERR_INVALID_ARG;

    const c_tcfg = if (tree_cfg) |tc| tc.* else webgrep_tree_config_default();
    const z_search_cfg = toSearchConfig(&c_tcfg.search) orelse return WEBGREP_ERR_INVALID_ARG;

    const fmt: archive_mod.ArchiveFormat = switch (c_tcfg.format) {
        0 => .auto,
        1 => .tar,
        2 => .tar_gz,
        3 => .tar_zst,
        4 => .tar_xz,
        5 => .zip,
        else => return WEBGREP_ERR_INVALID_ARG,
    };

    const archive_opts = archive_mod.ArchiveOptions{
        .format = fmt,
        .max_entries = if (c_tcfg.max_entries > 0) c_tcfg.max_entries else 10_000,
        .max_entry_bytes = if (c_tcfg.max_entry_bytes > 0) c_tcfg.max_entry_bytes else 64 * 1024 * 1024,
        .max_total_bytes = if (c_tcfg.max_total_bytes > 0) c_tcfg.max_total_bytes else 256 * 1024 * 1024,
        .max_compression_ratio = if (c_tcfg.max_compression_ratio > 0) c_tcfg.max_compression_ratio else 100,
    };

    const z_tcfg = tree_mod.TreeConfig{
        .search = z_search_cfg,
        .archive = archive_opts,
        .hidden = c_tcfg.hidden != 0,
        .skip_git = c_tcfg.skip_git != 0,
        .respect_gitignore = c_tcfg.respect_gitignore != 0,
        .respect_ignore = c_tcfg.respect_ignore != 0,
        .max_depth = if (c_tcfg.max_depth > 0) c_tcfg.max_depth else tree_mod.max_depth_hard_cap,
        .max_entries = if (c_tcfg.max_entries > 0) @intCast(c_tcfg.max_entries) else tree_mod.default_max_entries,
        .max_filesize = archive_opts.max_entry_bytes,
        .max_concurrency = if (c_tcfg.max_concurrency > 0) c_tcfg.max_concurrency else 1,
        .max_ignore_file_bytes = if (c_tcfg.max_ignore_file_bytes > 0) c_tcfg.max_ignore_file_bytes else tree_mod.max_ignore_file_bytes,
        .max_glob_rules = if (c_tcfg.max_glob_rules > 0) c_tcfg.max_glob_rules else null,
        .max_glob_rule_len = if (c_tcfg.max_glob_rule_len > 0) c_tcfg.max_glob_rule_len else null,
        .max_glob_brace_depth = if (c_tcfg.max_glob_brace_depth > 0) c_tcfg.max_glob_brace_depth else null,
    };

    const archive_bytes: []const u8 = if (archive_ptr) |p| p[0..archive_len] else "";
    const box: *const MatcherBox = @ptrCast(@alignCast(m_ptr));

    var tree = archive_mod.ArchiveTree.initFromSlice(c_alloc, archive_bytes, archive_opts) catch |err| return switch (err) {
        error.OutOfMemory => WEBGREP_ERR_OUT_OF_MEMORY,
        error.ArchiveLimit => WEBGREP_ERR_ARCHIVE_LIMIT,
        error.UnsupportedFormat,
        error.CorruptArchive,
        error.PathTraversal,
        => WEBGREP_ERR_CORRUPT_ARCHIVE,
    };
    defer tree.deinit();

    var sink = CLineEventSink{
        .on_line = on_line,
        .userdata = userdata,
    };

    const sum = tree_mod.searchTree(
        CLineEventSink,
        c_alloc,
        undefined,
        &sink,
        tree.source(),
        "",
        &box.any_matcher,
        z_tcfg,
    ) catch |err| return switch (err) {
        error.OutOfMemory => WEBGREP_ERR_OUT_OF_MEMORY,
        error.ContextLinesExceeded,
        error.BudgetExceeded,
        error.BufferLimit,
        error.DecodeLimit,
        error.GlobCountExceeded,
        error.GlobTooLong,
        error.GlobBraceDepthExceeded,
        => WEBGREP_ERR_BUDGET_EXCEEDED,
        else => WEBGREP_ERR_CORRUPT_ARCHIVE,
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
    return WEBGREP_OK;
}

// ============================================================================
// Unit Tests
// ============================================================================

test "c_api: version and options default" {
    const ver = std.mem.span(webgrep_version());
    try std.testing.expectEqualStrings("0.5.0", ver);

    const fopts = webgrep_find_options_default();
    try std.testing.expectEqual(@as(c_int, 0), fopts.case_mode);
    try std.testing.expectEqual(@as(u8, 1), fopts.unicode_case);
    try std.testing.expectEqual(@as(usize, 0), fopts.max_patterns);
    try std.testing.expectEqual(@as(usize, 0), fopts.max_pattern_bytes);
    try std.testing.expectEqual(@as(usize, 0), fopts.max_unicode_variants);

    const ropts = webgrep_regex_options_default();
    try std.testing.expectEqual(@as(c_int, 0), ropts.case_mode);
    try std.testing.expectEqual(@as(u8, 1), ropts.unicode_case);
    try std.testing.expectEqual(@as(u8, 0), ropts.multiline);
    try std.testing.expectEqual(@as(usize, 0), ropts.max_repeat);
    try std.testing.expectEqual(@as(usize, 0), ropts.max_recursion_depth);
    try std.testing.expectEqual(@as(usize, 0), ropts.max_patterns);
    try std.testing.expectEqual(@as(usize, 0), ropts.max_pattern_bytes);

    const cfg = webgrep_config_default();
    try std.testing.expect(cfg.scratch == null);
    try std.testing.expectEqual(@as(u8, 1), cfg.line_number);
    try std.testing.expectEqual(@as(u32, 0), cfg.max_context_lines);
    try std.testing.expectEqual(@as(u64, 0), cfg.max_compression_ratio);
    try std.testing.expectEqual(@as(u64, 0), cfg.time_budget_ns);
    try std.testing.expectEqual(@as(u64, 0), cfg.max_output_bytes);

    const tcfg = webgrep_tree_config_default();
    try std.testing.expectEqual(@as(c_int, 0), tcfg.format);
    try std.testing.expectEqual(@as(u8, 1), tcfg.skip_git);
    try std.testing.expectEqual(@as(usize, 0), tcfg.max_ignore_file_bytes);
    try std.testing.expectEqual(@as(usize, 0), tcfg.max_glob_rules);
    try std.testing.expectEqual(@as(usize, 0), tcfg.max_glob_rule_len);
    try std.testing.expectEqual(@as(usize, 0), tcfg.max_glob_brace_depth);
}

test "c_api: custom limits exceeding former hard caps" {
    var ropts = webgrep_regex_options_default();
    ropts.max_repeat = 2000;
    ropts.max_inst = 15000;
    var diag: webgrep_compile_diag_t = .{};
    var re_m: ?*webgrep_matcher_t = null;
    try std.testing.expectEqual(WEBGREP_OK, webgrep_matcher_compile_regex("a{1200}", 7, &ropts, &diag, &re_m));
    defer webgrep_matcher_free(re_m);

    var high_ctx_cfg = webgrep_config_default();
    high_ctx_cfg.max_context_lines = 25;
    high_ctx_cfg.before_context = 20;
    var sum: webgrep_summary_t = .{};
    const slice_text = "ctx before\nhello user_42 world\nctx after\n";
    try std.testing.expectEqual(WEBGREP_OK, webgrep_search_slice(
        re_m,
        slice_text.ptr,
        slice_text.len,
        &high_ctx_cfg,
        null,
        null,
        &sum,
    ));
}

test "c_api: compile literal, multi, regex, regex_set and find" {
    const fopts = webgrep_find_options_default();
    var lit_m: ?*webgrep_matcher_t = null;
    try std.testing.expectEqual(WEBGREP_OK, webgrep_matcher_compile_literal("needle", 6, &fopts, &lit_m));
    defer webgrep_matcher_free(lit_m);

    var cm: webgrep_match_t = .{};
    const hay = "xx needle yy";
    try std.testing.expectEqual(@as(c_int, 1), webgrep_find(lit_m, hay.ptr, hay.len, 0, &cm));
    try std.testing.expectEqual(@as(usize, 3), cm.start);
    try std.testing.expectEqual(@as(usize, 9), cm.end);

    const pats = [_]webgrep_pattern_t{
        .{ .ptr = "alpha", .len = 5 },
        .{ .ptr = "beta", .len = 4 },
    };
    var multi_m: ?*webgrep_matcher_t = null;
    try std.testing.expectEqual(WEBGREP_OK, webgrep_matcher_compile_multi(&pats, pats.len, &fopts, &multi_m));
    defer webgrep_matcher_free(multi_m);

    const hay2 = "zz beta alpha";
    try std.testing.expectEqual(@as(c_int, 1), webgrep_find(multi_m, hay2.ptr, hay2.len, 0, &cm));
    try std.testing.expectEqual(@as(u32, 1), cm.pattern_id);
    try std.testing.expectEqual(@as(u8, 1), cm.has_pattern_id);

    const ropts = webgrep_regex_options_default();
    var diag: webgrep_compile_diag_t = .{};
    var re_m: ?*webgrep_matcher_t = null;
    try std.testing.expectEqual(WEBGREP_OK, webgrep_matcher_compile_regex("id_[0-9]+", 9, &ropts, &diag, &re_m));
    defer webgrep_matcher_free(re_m);

    const hay3 = "user id_42 ok";
    try std.testing.expectEqual(@as(c_int, 1), webgrep_find(re_m, hay3.ptr, hay3.len, 0, &cm));
    try std.testing.expectEqual(@as(usize, 5), cm.start);
    try std.testing.expectEqual(@as(usize, 10), cm.end);

    var set_m: ?*webgrep_matcher_t = null;
    try std.testing.expectEqual(WEBGREP_OK, webgrep_matcher_compile_regex_set(&pats, pats.len, &ropts, &diag, &set_m));
    defer webgrep_matcher_free(set_m);

    var ids: [4]u32 = undefined;
    var count: usize = 0;
    try std.testing.expectEqual(WEBGREP_OK, webgrep_regex_set_matches(set_m, hay2.ptr, hay2.len, &ids, ids.len, &count));
    try std.testing.expectEqual(@as(usize, 2), count);
    try std.testing.expectEqual(@as(u32, 0), ids[0]);
    try std.testing.expectEqual(@as(u32, 1), ids[1]);
}

test "c_api: scratch pool allocation" {
    const scratch = webgrep_scratch_new();
    try std.testing.expect(scratch != null);
    webgrep_scratch_free(scratch);
    webgrep_scratch_free(null);
}

test "c_api: search_slice with callback and scratch" {
    const ropts = webgrep_regex_options_default();
    var diag: webgrep_compile_diag_t = .{};
    var re_m: ?*webgrep_matcher_t = null;
    try std.testing.expectEqual(WEBGREP_OK, webgrep_matcher_compile_regex("val=([0-9]+)", 12, &ropts, &diag, &re_m));
    defer webgrep_matcher_free(re_m);

    const scratch = webgrep_scratch_new();
    defer webgrep_scratch_free(scratch);

    var cfg = webgrep_config_default();
    cfg.scratch = scratch;
    const rep = "num:$1";
    cfg.replacement_ptr = rep.ptr;
    cfg.replacement_len = rep.len;

    const Ctx = struct {
        lines: usize = 0,
        saw_rep: bool = false,
        fn onLine(ev: *const webgrep_line_event_t, userdata: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            if (ev.is_context == 0) {
                self.lines += 1;
                if (ev.replaced_ptr) |rp| {
                    if (std.mem.indexOf(u8, rp[0..ev.replaced_len], "num:99") != null) {
                        self.saw_rep = true;
                    }
                }
            }
            return 0;
        }
    };

    var ctx = Ctx{};
    var sum: webgrep_summary_t = .{};
    const data = "first line\nrow val=99 done\n";
    try std.testing.expectEqual(WEBGREP_OK, webgrep_search_slice(re_m, data.ptr, data.len, &cfg, Ctx.onLine, &ctx, &sum));
    try std.testing.expectEqual(@as(usize, 1), ctx.lines);
    try std.testing.expect(ctx.saw_rep);
    try std.testing.expectEqual(@as(u64, 1), sum.matched_lines);
}

test "c_api: search_reader streaming" {
    var m: ?*webgrep_matcher_t = null;
    try std.testing.expectEqual(WEBGREP_OK, webgrep_matcher_compile_literal("HIT", 3, null, &m));
    defer webgrep_matcher_free(m);

    const Stream = struct {
        payload: []const u8 = "a\nb HIT 1\nc HIT 2\n",
        pos: usize = 0,
        hits: usize = 0,
        fn onRead(buf: [*c]u8, cap: usize, out_n: [*c]usize, userdata: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            if (self.pos >= self.payload.len) {
                out_n.* = 0;
                return 0;
            }
            const n = @min(@min(cap, 5), self.payload.len - self.pos);
            @memcpy(buf[0..n], self.payload[self.pos .. self.pos + n]);
            self.pos += n;
            out_n.* = n;
            return 0;
        }
        fn onLine(ev: *const webgrep_line_event_t, userdata: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            if (ev.is_context == 0) self.hits += 1;
            return 0;
        }
    };

    var st = Stream{};
    var sum: webgrep_summary_t = .{};
    const cfg = webgrep_config_default();
    try std.testing.expectEqual(WEBGREP_OK, webgrep_search_reader(m, Stream.onRead, &st, &cfg, Stream.onLine, &st, &sum));
    try std.testing.expectEqual(@as(usize, 2), st.hits);
    try std.testing.expectEqual(@as(u64, 2), sum.matched_lines);
}

fn writeTestTarHeader(block: *[512]u8, name: []const u8, size: usize, typeflag: u8) void {
    @memset(block, 0);
    @memcpy(block[0..name.len], name);
    _ = std.fmt.bufPrint(block[100..107], "{o:0>7}", .{@as(u32, 0o644)}) catch unreachable;
    _ = std.fmt.bufPrint(block[124..135], "{o:0>11}", .{size}) catch unreachable;
    @memset(block[148..156], ' ');
    block[156] = typeflag;
    @memcpy(block[257..263], "ustar\x00");
    @memcpy(block[263..265], "00");
    var chksum: u32 = 0;
    for (block) |b| chksum += b;
    _ = std.fmt.bufPrint(block[148..154], "{o:0>6}", .{chksum}) catch unreachable;
    block[154] = 0;
    block[155] = ' ';
}

test "c_api: search_archive_slice on in-memory tar" {
    var m: ?*webgrep_matcher_t = null;
    try std.testing.expectEqual(WEBGREP_OK, webgrep_matcher_compile_literal("TAR_MATCH", 9, null, &m));
    defer webgrep_matcher_free(m);

    const content = "hello TAR_MATCH world\n";
    var tar_buf: [2048]u8 = @splat(0);
    writeTestTarHeader(tar_buf[0..512], "dir/test.txt", content.len, '0');
    @memcpy(tar_buf[512 .. 512 + content.len], content);

    const tcfg = webgrep_tree_config_default();
    var tsum: webgrep_tree_summary_t = .{};
    try std.testing.expectEqual(WEBGREP_OK, webgrep_search_archive_slice(m, &tar_buf, tar_buf.len, &tcfg, null, null, &tsum));
    try std.testing.expectEqual(@as(u64, 1), tsum.matched_files);
    try std.testing.expectEqual(@as(u64, 1), tsum.matched_lines);
}

test "c_api: adversarial streaming reader callbacks and corrupt archives" {
    var m: ?*webgrep_matcher_t = null;
    try std.testing.expectEqual(WEBGREP_OK, webgrep_matcher_compile_literal("HIT", 3, null, &m));
    defer webgrep_matcher_free(m);

    const BadReader = struct {
        fn overflowRead(_: [*c]u8, cap: usize, out_n: [*c]usize, _: ?*anyopaque) callconv(.c) c_int {
            out_n.* = cap + 1;
            return 0;
        }
        fn failRead(_: [*c]u8, _: usize, _: [*c]usize, _: ?*anyopaque) callconv(.c) c_int {
            return -1;
        }
    };

    var sum: webgrep_summary_t = .{};
    try std.testing.expectEqual(WEBGREP_ERR_IO, webgrep_search_reader(m, BadReader.overflowRead, null, null, null, null, &sum));
    try std.testing.expectEqual(WEBGREP_ERR_IO, webgrep_search_reader(m, BadReader.failRead, null, null, null, null, &sum));

    const corrupt = "PK\x03\x04corrupt_zip_payload";
    var tsum: webgrep_tree_summary_t = .{};
    try std.testing.expectEqual(WEBGREP_ERR_CORRUPT_ARCHIVE, webgrep_search_archive_slice(m, corrupt.ptr, corrupt.len, null, null, null, &tsum));
}
