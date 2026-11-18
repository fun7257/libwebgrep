//! [Module] search/reverse.zig
//! [Layer] Layer 4 — Reverse Tail Search Engine (`searchReverseSlice`, `searchReverseAt`)
//! [Role] Scans backward from the end of an in-memory slice or `probe.RandomAccess` source in bounded chunks,
//!        yielding matching lines newest-first (highest byte offset first) in O(tail) reads and CPU time.
//! [Invariants]
//!   1. Zero filesystem path, file-handle, or directory-handle references; all positional I/O uses `probe.RandomAccess`.
//!   2. Pre-quota `line_filter`, `max_count`, `max_results`, and `FlowAction` (`cont`, `pause`, `stop`, `skip_to`)
//!      are evaluated strictly in reverse (newest-first) order.
//!   3. When `max_results` or `Flow.pause` stops on a line starting at `line_abs`, `Result.resume_at` is set to `line_abs`
//!      so callers can paginate further backward with `byte_range = .{ .start = start, .end = res.resume_at }`.

const std = @import("std");
const matcher_mod = @import("../matcher.zig");
const memchr = @import("../finder/memchr.zig");
const probe_mod = @import("../probe.zig");
const regex_mod = @import("../regex.zig");
const sink_mod = @import("../sink.zig");
const cfg_mod = @import("config.zig");
const state_mod = @import("state.zig");
const ring_mod = @import("context_ring.zig");
const format_mod = @import("format.zig");
const line_matcher_mod = @import("line_matcher.zig");
const pull_mod = @import("pull.zig");

pub const RandomAccess = probe_mod.RandomAccess;
pub const SearchConfig = cfg_mod.SearchConfig;
pub const SliceError = cfg_mod.SliceError;
pub const ReadError = cfg_mod.ReadError;
pub const Result = cfg_mod.Result;
pub const Span = cfg_mod.Span;

const width = cfg_mod.width;
const State = state_mod.State;
const Range = state_mod.Range;
const BufMatch = state_mod.BufMatch;

const RevCandidate = struct {
    start: usize,
    end: usize,
    mstart: usize,
    mend: usize,
    mpid: ?u32 = null,
    single_match: bool = false,
};

fn isAnyMatcherRegex(any_m: matcher_mod.AnyMatcher) bool {
    if (any_m.vtable.is_capture_regex) return true;
    var dummy: regex_mod.Regex = undefined;
    const ptr_mut: *regex_mod.Regex = &dummy;
    const ptr_const: *const regex_mod.Regex = &dummy;
    return any_m.vtable == matcher_mod.AnyMatcher.init(regex_mod.Regex, ptr_mut).vtable or
        any_m.vtable == matcher_mod.AnyMatcher.init(regex_mod.Regex, ptr_const).vtable or
        any_m.vtable == matcher_mod.AnyMatcher.init(*regex_mod.Regex, ptr_mut).vtable or
        any_m.vtable == matcher_mod.AnyMatcher.init(*const regex_mod.Regex, ptr_const).vtable;
}

fn bindCaptureRegex(state: *State, matcher: anytype) void {
    const MChild = state_mod.MatcherType(@TypeOf(matcher));
    if (MChild == regex_mod.Regex) {
        state.capture_regex = if (@typeInfo(@TypeOf(matcher)) == .pointer) matcher else &matcher;
    } else if (MChild == matcher_mod.AnyMatcher) {
        const any_m: matcher_mod.AnyMatcher = if (@typeInfo(@TypeOf(matcher)) == .pointer) matcher.* else matcher;
        if (isAnyMatcherRegex(any_m)) {
            state.capture_regex = @ptrCast(@alignCast(any_m.ctx));
        }
    }
}

fn linesInSlice(bytes: []const u8, sep: u8) u64 {
    if (bytes.len == 0) return 0;
    const nls = memchr.count(width, bytes, 0, bytes.len, sep);
    return if (bytes[bytes.len - 1] == sep) nls else nls + 1;
}

fn adjustLastLineForJump(haystack: []const u8, start_idx: usize, clamped: usize, cursor_end: usize, last_ln: u64, sep: u8) u64 {
    if (clamped >= cursor_end) return last_ln;
    if (clamped <= start_idx) return 1;
    const raw_lines = linesInSlice(haystack[clamped..cursor_end], sep);
    const mid_line: u64 = @intFromBool(haystack[clamped - 1] != sep);
    return last_ln -| (raw_lines -| mid_line);
}

fn appendCandidate(
    alloc: ?std.mem.Allocator,
    inline_buf: []RevCandidate,
    heap_buf: *[]RevCandidate,
    len: *usize,
    item: RevCandidate,
) SliceError![]RevCandidate {
    var cur = if (heap_buf.len > 0) heap_buf.* else inline_buf;
    if (len.* == cur.len) {
        const a = alloc orelse return error.OutOfMemory;
        const new_cap = @max(cur.len * 2, 512);
        if (heap_buf.len == 0) {
            const grown = try a.alloc(RevCandidate, new_cap);
            @memcpy(grown[0..len.*], inline_buf[0..len.*]);
            heap_buf.* = grown;
        } else {
            heap_buf.* = try a.realloc(heap_buf.*, new_cap);
        }
        cur = heap_buf.*;
    }
    cur[len.*] = item;
    len.* += 1;
    return cur;
}

const ReverseAction = union(enum) {
    cont,
    stopped,
    jump_back: u64,
};

fn emitReverseMatched(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    chunk: []const u8,
    chunk_abs_origin: u64,
    cand: RevCandidate,
    line_num: ?u64,
    state: *State,
    config: SearchConfig,
) SliceError!ReverseAction {
    const line = Range{ .start = cand.start, .end = cand.end };
    const line_abs = chunk_abs_origin + @as(u64, cand.start);
    const known: ?BufMatch = if (config.invert)
        null
    else
        .{ .start = cand.mstart, .end = cand.mend, .pattern_id = cand.mpid, .single_match = cand.single_match };

    state.abs_base = chunk_abs_origin;
    state.line_number = line_num;
    state.last_line_counted = cand.end;

    if (comptime !@hasDecl(S, "matched")) {
        const withheld = config.binary == .report and state.nul_offset != null;
        if (!withheld and (config.max_queued_event_bytes != null or config.max_output_bytes != null)) {
            const content_end = state_mod.contentEnd(chunk, line, config);
            const raw_len = content_end - line.start;
            const capped_len = if (config.max_line_len == 0 or raw_len <= config.max_line_len) raw_len else config.max_line_len;
            if (!try state_mod.guardLine(state, config, capped_len)) return .stopped;
        }
        state_mod.releaseQueue(state);
        state.has_sunk = true;
        state.matched_lines += 1;
        state.matches += 1;
        state.results_out += 1;
        if (!state_mod.maybeProgress(S, sink, state, config)) {
            if (state.paused) {
                state.resume_at = line_abs;
                state.resume_line = if (line_num) |ln| ln -| 1 else 0;
            }
            return .stopped;
        }
        if (!state_mod.noteHitLimit(state, config, line_abs)) {
            if (state.limit_hit == .max_results) {
                state.resume_at = line_abs;
                state.resume_line = if (line_num) |ln| ln -| 1 else 0;
            }
            return .stopped;
        }
        return .cont;
    }

    const preview = ring_mod.previewLine(chunk, line, known, config);
    const withheld = config.binary == .report and state.nul_offset != null;
    const bytes = if (withheld) chunk[line.start..line.start] else chunk[preview.start..preview.end];
    var inline_spans: [32]Span = undefined;
    const matches = if (withheld) inline_spans[0..0] else try format_mod.gatherSpans(
        state.text_alloc,
        &inline_spans,
        &state.span_buf,
        matcher,
        chunk,
        line,
        preview,
        known,
        state,
        config,
    );
    if (!try state_mod.guardLine(state, config, bytes.len)) return .stopped;
    const action = format_mod.sinkLineAction(
        S,
        "matched",
        sink,
        state,
        bytes,
        if (withheld) bytes else chunk,
        if (withheld) 0 else preview.start,
        if (withheld) 0 else line.end,
        config.match_mode,
        if (withheld) null else preview.span,
        matches,
        line_abs,
        line_num,
        preview.truncated and !withheld,
        preview.line_len,
        if (withheld) 0 else preview.window_start,
        if (withheld) null else config.replacement,
    );
    state_mod.releaseQueue(state);
    state.has_sunk = true;
    state.matched_lines += 1;
    state.matches += if (matches.len > 0) @as(u64, @intCast(matches.len)) else 1;
    state.results_out += 1;

    var jump_target: ?u64 = null;
    switch (action) {
        .cont => {},
        .skip_to => |target| {
            if (target < line_abs) jump_target = target;
        },
        .pause => {
            state.paused = true;
            state.resume_at = line_abs;
            state.resume_line = if (line_num) |ln| ln -| 1 else 0;
            state.stopped = true;
            return .stopped;
        },
        .stop => {
            state.stopped = true;
            return .stopped;
        },
    }

    if (!state_mod.maybeProgress(S, sink, state, config)) {
        if (state.paused) {
            state.resume_at = line_abs;
            state.resume_line = if (line_num) |ln| ln -| 1 else 0;
        }
        return .stopped;
    }
    if (!state_mod.noteHitLimit(state, config, line_abs)) {
        if (state.limit_hit == .max_results) {
            state.resume_at = line_abs;
            state.resume_line = if (line_num) |ln| ln -| 1 else 0;
        }
        return .stopped;
    }
    if (jump_target) |jt| return .{ .jump_back = jt };
    return .cont;
}

/// Processes a single window `chunk` (`[overlap_lo .. cursor_end)`) where `rel_commit = commit_lo - overlap_lo`.
/// May lower `commit_lo_io.*` if a cross-line match straddles `commit_lo`.
fn processReverseWindow(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    chunk: []const u8,
    overlap_lo: u64,
    commit_lo_io: *u64,
    cur_last_ln: *?u64,
    state: *State,
    config: SearchConfig,
    alloc: ?std.mem.Allocator,
    heap_cands: *[]RevCandidate,
) SliceError!ReverseAction {
    var rel_commit: usize = @intCast(commit_lo_io.* - overlap_lo);
    if (rel_commit >= chunk.len) return .cont;

    const sep = cfg_mod.recordSep(config);
    var binary_quit_rel: ?usize = null;
    var binary_abs: ?u64 = null;
    var report_nul_line_end: ?usize = null;
    var report_nul_abs: ?u64 = null;

    if (cfg_mod.watchesBinary(config) and state.nul_offset == null) {
        if (memchr.findLast(width, chunk, rel_commit, chunk.len, 0)) |last_nul| {
            const nul_abs = overlap_lo + @as(u64, last_nul);
            const after_nul_line = state_mod.lineEnd(chunk, last_nul, config);
            if (config.binary == .quit) {
                binary_abs = nul_abs;
                binary_quit_rel = after_nul_line;
            } else {
                report_nul_abs = nul_abs;
                report_nul_line_end = after_nul_line;
            }
        }
    }

    const effective_rel_commit = if (binary_quit_rel) |bqr| @max(rel_commit, bqr) else rel_commit;

    var inline_cands: [256]RevCandidate = undefined;
    var cand_len: usize = 0;
    var cands: []RevCandidate = &inline_cands;

    if (effective_rel_commit < chunk.len) {
        var scan_cfg = config;
        scan_cfg.max_count = null;
        scan_cfg.line_filter = null;

        var scan_state = State{};
        scan_state.abs_base = overlap_lo;
        scan_state.pos = if (binary_quit_rel != null) effective_rel_commit else 0;

        if (!config.invert) {
            while (scan_state.pos < chunk.len) {
                if (state_mod.stopInMatch(state, config)) return .stopped;
                const fl = (try line_matcher_mod.findLineLimitOpts(matcher, chunk, &scan_state, chunk.len, scan_cfg, true)) orelse break;
                scan_state.pos = fl.end;
                if (fl.end <= effective_rel_commit) continue;
                if (fl.start < effective_rel_commit) {
                    if (binary_quit_rel != null) continue;
                    rel_commit = fl.start;
                    commit_lo_io.* = overlap_lo + @as(u64, fl.start);
                }
                cands = try appendCandidate(alloc, &inline_cands, heap_cands, &cand_len, .{
                    .start = fl.start,
                    .end = fl.end,
                    .mstart = fl.mstart,
                    .mend = fl.mend,
                    .mpid = fl.mpid,
                    .single_match = fl.single_match,
                });
            }
        } else {
            while (scan_state.pos < chunk.len) {
                if (state_mod.stopInMatch(state, config)) return .stopped;
                const maybe_excl = try line_matcher_mod.findLineLimitOpts(matcher, chunk, &scan_state, chunk.len, scan_cfg, true);
                const gap_start = scan_state.pos;
                const gap_end = if (maybe_excl) |ex| blk: {
                    if (ex.start < effective_rel_commit and ex.end > effective_rel_commit and binary_quit_rel == null) {
                        rel_commit = ex.start;
                        commit_lo_io.* = overlap_lo + @as(u64, ex.start);
                    }
                    scan_state.pos = ex.end;
                    break :blk ex.start;
                } else blk: {
                    scan_state.pos = chunk.len;
                    break :blk chunk.len;
                };
                var cur = @max(gap_start, @max(rel_commit, effective_rel_commit));
                while (state_mod.nextLine(chunk, cur, gap_end, config)) |ln_r| {
                    cur = ln_r.end;
                    const ce = state_mod.contentEnd(chunk, ln_r, config);
                    if (!line_matcher_mod.linePassesFilters(chunk, ln_r.start, ce, config)) continue;
                    cands = try appendCandidate(alloc, &inline_cands, heap_cands, &cand_len, .{
                        .start = ln_r.start,
                        .end = ln_r.end,
                        .mstart = ln_r.start,
                        .mend = ln_r.start,
                        .mpid = null,
                        .single_match = true,
                    });
                }
            }
        }
    }

    const committed_slice = chunk[rel_commit..];
    const total_lines_in_commit = if (cur_last_ln.* != null) linesInSlice(committed_slice, sep) else 0;
    const chunk_first_ln: ?u64 = if (cur_last_ln.*) |last_ln|
        if (total_lines_in_commit == 0) last_ln else (last_ln + 1) -| total_lines_in_commit
    else
        null;

    var idx = cand_len;
    while (idx > 0) {
        idx -= 1;
        const cand = cands[idx];
        if (state_mod.flagIsSet(config)) {
            state.stopped = true;
            return .stopped;
        }
        if (state_mod.stopInMatch(state, config)) return .stopped;

        const ce = state_mod.contentEnd(chunk, .{ .start = cand.start, .end = cand.end }, config);
        if (config.line_filter != null) {
            const first_sp: Span = if (!config.invert) blk: {
                const rs = @min(@max(cand.mstart, cand.start), ce) - cand.start;
                const re = @max(rs, @min(@max(cand.mend, cand.start), ce) - cand.start);
                break :blk .{ .start = rs, .end = re, .pattern_id = cand.mpid };
            } else .{ .start = 0, .end = 0 };
            state.abs_base = overlap_lo;
            if (!line_matcher_mod.linePassesUserFilter(chunk, cand.start, ce, cand.end, first_sp, config.invert, state, config)) {
                continue;
            }
        }

        if (config.files_without_match) {
            state.limit_count += 1;
            state.matched_lines += 1;
            state.matches += 1;
            state.results_out += 1;
            state.stopped = true;
            state.need_close = true;
            return .stopped;
        }

        const line_num: ?u64 = if (chunk_first_ln) |base_ln|
            base_ln + memchr.count(width, chunk, rel_commit, cand.start, sep)
        else
            null;

        if (report_nul_line_end) |rnle| {
            if (state.nul_offset == null and cand.start < rnle) {
                state_mod.noteBinary(state, config, report_nul_abs.?);
                if (!state_mod.callOpt(S, "binary", sink, .{state.nul_offset.?})) {
                    state.stopped = true;
                    return .stopped;
                }
            }
        }

        state.limit_count += 1;
        const act = try emitReverseMatched(S, sink, matcher, chunk, overlap_lo, cand, line_num, state, config);
        switch (act) {
            .cont => {},
            .stopped => return .stopped,
            .jump_back => |target| {
                while (idx > 0) {
                    const prev_cand = cands[idx - 1];
                    if (overlap_lo + @as(u64, prev_cand.end) <= target) break;
                    idx -= 1;
                }
                if (target < commit_lo_io.*) {
                    return .{ .jump_back = target };
                }
            },
        }
        if (state.exceeded(config)) {
            state.stopped = true;
            state.need_close = true;
            return .stopped;
        }
    }

    if (report_nul_abs) |r_abs| {
        if (state.nul_offset == null) {
            state_mod.noteBinary(state, config, r_abs);
            if (!state_mod.callOpt(S, "binary", sink, .{state.nul_offset.?})) {
                state.stopped = true;
                return .stopped;
            }
        }
    }

    if (binary_abs) |b_abs| {
        state_mod.noteBinary(state, config, b_abs);
        _ = state_mod.callOpt(S, "binary", sink, .{state.nul_offset.?});
        state.stopped = true;
        return .stopped;
    }

    if (chunk_first_ln) |first_ln| {
        cur_last_ln.* = first_ln -| 1;
    }
    return .cont;
}

fn finalizeReverse(comptime S: type, sink: *S, state: *State, config: SearchConfig, bytes_scanned: u64, bytes_read: u64, scanned_all: bool) Result {
    const base_s: u64 = if (config.continuation) |s| s.bytes_searched else 0;
    const base_r: u64 = if (config.continuation) |s| s.bytes_read else 0;
    state.bytes_searched = base_s + bytes_scanned;
    state.bytes_read = base_r + bytes_read;
    state.scanned_all = scanned_all and !state.output_blocked and state.soft_error == null and !state.paused;
    state.abs_base = 0;
    state.pos = 0;
    return state_mod.finishSink(S, sink, state, config);
}

/// Searches `haystack` backward from the end of `haystack` (or `config.byte_range`), emitting matches newest-first.
pub fn searchReverseSlice(
    comptime S: type,
    sink: *S,
    haystack: []const u8,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) SliceError!Result {
    matcher_mod.validateMatcher(@TypeOf(matcher));
    cfg_mod.validateBudgets(config) catch |err| {
        state_mod.logDetail(config, name, err);
        return err;
    };
    state_mod.resetStats(matcher);

    var state = State{};
    bindCaptureRegex(&state, matcher);
    state.label = name;
    state_mod.armClock(&state, config);
    const pool_alloc = if (config.scratch_pool) |sp| sp.allocator else cfg_mod.effectiveAllocator(config);
    state.text_alloc = pool_alloc;
    if (config.scratch_pool) |sp| {
        state.text_buf = sp.text_buf;
        state.replace_buf = sp.replace_buf;
        state.span_buf = sp.span_buf;
    }
    defer {
        if (config.scratch_pool) |sp| {
            sp.text_buf = state.text_buf;
            sp.replace_buf = state.replace_buf;
            sp.span_buf = state.span_buf;
        } else if (state.text_alloc) |alloc| {
            if (state.text_buf.len != 0) alloc.free(state.text_buf);
            if (state.replace_buf.len != 0) alloc.free(state.replace_buf);
            if (state.span_buf.len != 0) alloc.free(state.span_buf);
        }
    }

    var heap_cands: []RevCandidate = &.{};
    defer if (heap_cands.len != 0) if (pool_alloc) |alloc| alloc.free(heap_cands);

    const sep = cfg_mod.recordSep(config);
    var start_idx: usize = if (config.byte_range) |br| @intCast(@min(br.start, @as(u64, haystack.len))) else 0;
    var end_idx: usize = if (config.byte_range) |br|
        (if (br.end) |be| @intCast(@min(be, @as(u64, haystack.len))) else haystack.len)
    else
        haystack.len;

    if (config.range_align_lines) {
        if (start_idx > 0 and start_idx < haystack.len and haystack[start_idx - 1] != sep) {
            start_idx = if (memchr.find(width, haystack, start_idx, sep)) |d| d + 1 else haystack.len;
        }
        if (end_idx <= start_idx) {
            end_idx = start_idx;
        } else if (end_idx < haystack.len and haystack[end_idx - 1] != sep) {
            end_idx = if (memchr.find(width, haystack, end_idx, sep)) |d| d + 1 else haystack.len;
        }
    } else if (end_idx < start_idx) {
        end_idx = start_idx;
    }

    if (cfg_mod.scanCap(config)) |cap| {
        if (@as(u64, end_idx - start_idx) > cap) {
            start_idx = end_idx - @as(usize, @intCast(cap));
            state.hit_byte_cap = true;
        }
    }

    state_mod.restoreCounters(&state, config);
    var cur_last_ln: ?u64 = switch (config.line_number_mode) {
        .unknown => null,
        .from_one => if (config.initial_line_number) |n| n else if (end_idx > start_idx) linesInSlice(haystack[start_idx..end_idx], sep) else 1,
        .auto => config.initial_line_number,
    };

    var cursor_end: usize = end_idx;
    switch (state_mod.callSinkAction(S, "begin", sink, .{name})) {
        .cont => {},
        .skip_to => |target| {
            if (target < @as(u64, cursor_end)) {
                const clamped: usize = @intCast(@max(@as(u64, start_idx), target));
                if (cur_last_ln) |lln| {
                    cur_last_ln = adjustLastLineForJump(haystack, start_idx, clamped, cursor_end, lln, sep);
                }
                cursor_end = clamped;
            }
        },
        .pause => {
            state.paused = true;
            state.stopped = true;
            state.resume_at = @intCast(cursor_end);
            state.resume_line = cur_last_ln orelse 0;
            return finalizeReverse(S, sink, &state, config, 0, 0, false);
        },
        .stop => {
            state.stopped = true;
            return finalizeReverse(S, sink, &state, config, 0, 0, false);
        },
    }

    if (state_mod.rejectEmptyResults(&state, config)) {
        state.resume_at = @intCast(cursor_end);
        return finalizeReverse(S, sink, &state, config, 0, 0, false);
    }
    if (state_mod.stopForBudget(&state, config)) {
        return finalizeReverse(S, sink, &state, config, 0, 0, false);
    }

    const is_ml = state_mod.effectiveMultiline(matcher, config);
    const ml_win = if (is_ml) state_mod.effectiveMultilineWindow(matcher, config) else 0;
    const step_sz = @max(cfg_mod.bufferWindow(config), if (is_ml) @max(ml_win *| 2, 64) else 64);

    var bytes_scanned: u64 = 0;
    while (cursor_end > start_idx and !state.stopped) {
        var commit_lo_idx: usize = if (cursor_end - start_idx <= step_sz) start_idx else cursor_end - step_sz;
        if (commit_lo_idx > start_idx and haystack[commit_lo_idx - 1] != sep) {
            if (memchr.find(width, haystack[0..cursor_end], commit_lo_idx, sep)) |nl_at| {
                if (nl_at + 1 < cursor_end) {
                    commit_lo_idx = nl_at + 1;
                } else if (memchr.findLast(width, haystack, start_idx, commit_lo_idx, sep)) |prev_nl| {
                    commit_lo_idx = prev_nl + 1;
                } else {
                    commit_lo_idx = start_idx;
                }
            } else if (memchr.findLast(width, haystack, start_idx, commit_lo_idx, sep)) |prev_nl| {
                commit_lo_idx = prev_nl + 1;
            } else {
                commit_lo_idx = start_idx;
            }
        }

        const overlap_lo_idx: usize = if (is_ml and ml_win > 0 and commit_lo_idx > start_idx) blk: {
            const raw_ov = if (commit_lo_idx - start_idx <= ml_win) start_idx else commit_lo_idx - ml_win;
            if (raw_ov > start_idx and haystack[raw_ov - 1] != sep) {
                if (memchr.findLast(width, haystack, start_idx, raw_ov, sep)) |pnl| break :blk pnl + 1;
                break :blk start_idx;
            }
            break :blk raw_ov;
        } else commit_lo_idx;

        var commit_lo_u64: u64 = @intCast(commit_lo_idx);
        const chunk = haystack[overlap_lo_idx..cursor_end];
        const act = try processReverseWindow(
            S,
            sink,
            matcher,
            chunk,
            @intCast(overlap_lo_idx),
            &commit_lo_u64,
            &cur_last_ln,
            &state,
            config,
            pool_alloc,
            &heap_cands,
        );
        const actual_commit: usize = @intCast(commit_lo_u64);
        bytes_scanned += @intCast(cursor_end - actual_commit);
        switch (act) {
            .cont => {
                cursor_end = actual_commit;
            },
            .stopped => break,
            .jump_back => |target| {
                const clamped: usize = @intCast(@max(@as(u64, start_idx), target));
                const next_end = @min(clamped, actual_commit);
                if (cur_last_ln) |lln| {
                    cur_last_ln = adjustLastLineForJump(haystack, start_idx, next_end, cursor_end, lln, sep);
                }
                cursor_end = next_end;
            },
        }
    }

    const reached_start = (cursor_end <= start_idx) and !state.stopped;
    if (reached_start and state.hit_byte_cap) state_mod.noteLimit(&state, .max_bytes);
    return finalizeReverse(S, sink, &state, config, bytes_scanned, bytes_scanned, reached_start and !state.hit_byte_cap);
}

/// Service entry point: reverse tail search over an in-memory byte slice.
pub fn searchSourceReverseSlice(
    comptime S: type,
    sink: *S,
    source_id: []const u8,
    haystack: []const u8,
    matcher: anytype,
    config: SearchConfig,
) SliceError!Result {
    const cfg = cfg_mod.serviceConfig(config);
    var bridge = pull_mod.EventBridge(S){
        .inner = sink,
        .source_id = source_id,
        .config = cfg,
    };
    const result = try searchReverseSlice(pull_mod.EventBridge(S), &bridge, haystack, "", matcher, cfg);
    pull_mod.emitSummary(S, sink, source_id, cfg, result);
    return result;
}

fn discoverSourceEnd(source: RandomAccess, start_hint: u64, bytes_read: *u64) ?u64 {
    if (source.size) |sz| return sz;
    var probe_buf: [16384]u8 = undefined;
    var off = start_hint;
    while (true) {
        const n = source.readAtFull(off, &probe_buf) catch return null;
        bytes_read.* += n;
        off += n;
        if (n < probe_buf.len) return off;
    }
}

/// Searches backward over a handle-free, path-free `probe.RandomAccess` source in O(tail) positional reads.
pub fn searchReverseAt(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    source: RandomAccess,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) ReadError!Result {
    matcher_mod.validateMatcher(@TypeOf(matcher));
    cfg_mod.validateBudgets(config) catch |err| {
        state_mod.logDetail(config, name, err);
        return err;
    };
    state_mod.resetStats(matcher);

    const pool_alloc = if (config.scratch_pool) |sp| sp.allocator else (cfg_mod.effectiveAllocator(config) orelse allocator);
    const stream_alloc = if (config.scratch == null and config.scratch_pool != null)
        config.scratch_pool.?.allocator
    else
        allocator;

    var state = State{};
    bindCaptureRegex(&state, matcher);
    state.label = name;
    state.from_reader = true;
    state_mod.armClock(&state, config);
    state.text_alloc = pool_alloc;
    if (config.scratch_pool) |sp| {
        state.text_buf = sp.text_buf;
        state.replace_buf = sp.replace_buf;
        state.span_buf = sp.span_buf;
    }
    defer {
        if (config.scratch_pool) |sp| {
            sp.text_buf = state.text_buf;
            sp.replace_buf = state.replace_buf;
            sp.span_buf = state.span_buf;
        } else {
            if (state.text_buf.len != 0) pool_alloc.free(state.text_buf);
            if (state.replace_buf.len != 0) pool_alloc.free(state.replace_buf);
            if (state.span_buf.len != 0) pool_alloc.free(state.span_buf);
        }
    }

    var heap_cands: []RevCandidate = &.{};
    defer if (heap_cands.len != 0) pool_alloc.free(heap_cands);

    const is_ml = state_mod.effectiveMultiline(matcher, config);
    const ml_win = if (is_ml) state_mod.effectiveMultilineWindow(matcher, config) else 0;
    const step_sz = @max(cfg_mod.bufferWindow(config), if (is_ml) @max(ml_win *| 2, 64) else 64);
    const align_cap = @max(step_sz, 256);
    const hold_limit = if (is_ml and ml_win > 0) state_mod.multilineHoldLimit(config, ml_win) else cfg_mod.lineHoldLimit(config);
    const buf_cap0 = @max(step_sz +| ml_win +| align_cap, 512);

    const stream_slot: ?*[]u8 = if (config.scratch_pool) |sp|
        &sp.stream_buf
    else if (config.scratch) |slot|
        slot
    else
        null;

    var buf: []u8 = undefined;
    if (stream_slot) |slot| {
        if (slot.len < buf_cap0) {
            if (slot.len == 0) {
                slot.* = try stream_alloc.alloc(u8, buf_cap0);
            } else {
                slot.* = try stream_alloc.realloc(slot.*, buf_cap0);
            }
        }
        buf = slot.*;
    } else {
        buf = try stream_alloc.alloc(u8, buf_cap0);
    }
    defer {
        if (stream_slot) |slot| {
            slot.* = buf;
        } else {
            stream_alloc.free(buf);
        }
    }

    var total_bytes_read: u64 = 0;
    const sep = cfg_mod.recordSep(config);

    var start_off: u64 = if (config.byte_range) |br| br.start else 0;
    var end_off: u64 = if (config.byte_range) |br|
        (if (br.end) |be| (if (source.size) |sz| @min(be, sz) else be) else (discoverSourceEnd(source, start_off, &total_bytes_read) orelse {
            state.soft_error = .read_failed;
            _ = state_mod.callOpt(S, "begin", sink, .{name});
            return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
        }))
    else
        (discoverSourceEnd(source, start_off, &total_bytes_read) orelse {
            state.soft_error = .read_failed;
            _ = state_mod.callOpt(S, "begin", sink, .{name});
            return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
        });

    if (source.size) |sz| {
        if (start_off > sz) start_off = sz;
    }

    if (config.range_align_lines) {
        if (start_off > 0 and start_off < end_off) {
            var prev_b: [1]u8 = undefined;
            const pn = source.readAtFull(start_off - 1, prev_b[0..1]) catch |err| {
                state.soft_error = .read_failed;
                state_mod.logDetail(config, name, err);
                _ = state_mod.callOpt(S, "begin", sink, .{name});
                return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
            };
            total_bytes_read += pn;
            if (pn == 0) {
                end_off = start_off;
            } else if (prev_b[0] != sep) {
                var cur = start_off;
                while (cur < end_off) {
                    const want: usize = @intCast(@min(@as(u64, 4096), end_off - cur));
                    const rn = source.readAtFull(cur, buf[0..want]) catch |err| {
                        state.soft_error = .read_failed;
                        state_mod.logDetail(config, name, err);
                        _ = state_mod.callOpt(S, "begin", sink, .{name});
                        return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
                    };
                    total_bytes_read += rn;
                    if (rn == 0) {
                        start_off = cur;
                        end_off = cur;
                        break;
                    }
                    if (memchr.find(width, buf[0..rn], 0, sep)) |nl_rel| {
                        start_off = cur + nl_rel + 1;
                        break;
                    }
                    cur += rn;
                }
                if (start_off > end_off) end_off = start_off;
            }
        }
        if (end_off > start_off) {
            var last_b: [1]u8 = undefined;
            const ln_n = source.readAtFull(end_off - 1, last_b[0..1]) catch |err| {
                state.soft_error = .read_failed;
                state_mod.logDetail(config, name, err);
                _ = state_mod.callOpt(S, "begin", sink, .{name});
                return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
            };
            total_bytes_read += ln_n;
            if (ln_n > 0 and last_b[0] != sep) {
                var cur = end_off;
                while (true) {
                    const rn = source.readAtFull(cur, buf[0..4096]) catch |err| {
                        state.soft_error = .read_failed;
                        state_mod.logDetail(config, name, err);
                        _ = state_mod.callOpt(S, "begin", sink, .{name});
                        return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
                    };
                    total_bytes_read += rn;
                    if (rn == 0) {
                        end_off = cur;
                        break;
                    }
                    if (memchr.find(width, buf[0..rn], 0, sep)) |nl_rel| {
                        end_off = cur + nl_rel + 1;
                        break;
                    }
                    cur += rn;
                }
            }
        }
    } else if (end_off < start_off) {
        end_off = start_off;
    }

    if (cfg_mod.scanCap(config)) |cap| {
        if (end_off - start_off > cap) {
            start_off = end_off - cap;
            state.hit_byte_cap = true;
        }
    }

    state_mod.restoreCounters(&state, config);
    var cur_last_ln: ?u64 = switch (config.line_number_mode) {
        .unknown => null,
        .auto => config.initial_line_number,
        .from_one => if (config.initial_line_number) |n| n else blk: {
            if (end_off <= start_off) break :blk @as(?u64, 1);
            var nls: u64 = 0;
            var last_seen_byte: u8 = sep;
            var cur = start_off;
            while (cur < end_off) {
                const want: usize = @intCast(@min(@as(u64, buf.len), end_off - cur));
                const rn = source.readAtFull(cur, buf[0..want]) catch |err| {
                    state.soft_error = .read_failed;
                    state_mod.logDetail(config, name, err);
                    _ = state_mod.callOpt(S, "begin", sink, .{name});
                    return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
                };
                total_bytes_read += rn;
                if (rn == 0) {
                    end_off = cur;
                    break;
                }
                nls += memchr.count(width, buf[0..rn], 0, rn, sep);
                last_seen_byte = buf[rn - 1];
                cur += rn;
            }
            break :blk if (end_off == start_off) @as(?u64, 1) else if (last_seen_byte == sep) nls else nls + 1;
        },
    };

    var cursor_end = end_off;
    switch (state_mod.callSinkAction(S, "begin", sink, .{name})) {
        .cont => {},
        .skip_to => |target| {
            if (target < cursor_end) {
                cursor_end = @max(start_off, target);
                if (config.line_number_mode == .auto or cur_last_ln != null) {
                    cur_last_ln = null;
                }
            }
        },
        .pause => {
            state.paused = true;
            state.stopped = true;
            state.resume_at = cursor_end;
            state.resume_line = cur_last_ln orelse 0;
            return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
        },
        .stop => {
            state.stopped = true;
            return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
        },
    }

    if (state_mod.rejectEmptyResults(&state, config)) {
        state.resume_at = cursor_end;
        return finalizeReverse(S, sink, &state, config, 0, total_bytes_read, false);
    }

    var bytes_scanned: u64 = 0;
    var cur_step_sz: u64 = @intCast(step_sz);
    while (cursor_end > start_off and !state.stopped) {
        state.bytes_read = total_bytes_read;
        if (state_mod.stopForBudget(&state, config)) break;

        const target_lo: u64 = if (cursor_end - start_off <= cur_step_sz) start_off else cursor_end - cur_step_sz;
        const overlap_lo: u64 = if (is_ml and ml_win > 0 and target_lo > start_off)
            (if (target_lo - start_off <= @as(u64, ml_win)) start_off else target_lo - @as(u64, ml_win))
        else
            target_lo;

        // Ensure `buf` can hold `cursor_end - overlap_lo` (+ room to align backward to line boundary)
        const extra_align: u64 = if (overlap_lo > start_off) @min(overlap_lo - start_off, @as(u64, align_cap)) else 0;
        while (true) {
            const read_lo_cand: u64 = overlap_lo - extra_align;
            const want_u64 = cursor_end - read_lo_cand;
            if (want_u64 > @as(u64, buf.len)) {
                if (try state_mod.growWithLimit(stream_alloc, buf, @max(hold_limit, @as(usize, @intCast(@min(want_u64, hold_limit)))))) |grown| {
                    buf = grown;
                    if (stream_slot) |slot| slot.* = buf;
                } else {
                    // Clamp read_lo if single line exceeds hold_limit
                    break;
                }
            } else break;
        }

        const max_window: u64 = @intCast(buf.len);
        var read_lo: u64 = overlap_lo - extra_align;
        if (cursor_end - read_lo > max_window) read_lo = cursor_end - max_window;

        const want_len: usize = @intCast(cursor_end - read_lo);
        const got_len = source.readAtFull(read_lo, buf[0..want_len]) catch |err| {
            state.soft_error = .read_failed;
            state_mod.logDetail(config, name, err);
            state.need_close = true;
            break;
        };
        total_bytes_read += got_len;
        if (got_len == 0) {
            cursor_end = read_lo;
            continue;
        }
        if (got_len < want_len) {
            cursor_end = read_lo + got_len;
        }
        const raw_window = buf[0..got_len];

        // Align `overlap_lo` and `commit_lo` inside `raw_window`
        var rel_overlap: usize = 0;
        if (read_lo > start_off) {
            if (memchr.find(width, raw_window, 0, sep)) |first_nl| {
                if (first_nl + 1 < raw_window.len) {
                    rel_overlap = first_nl + 1;
                }
            }
        }
        const aligned_overlap_lo = read_lo + @as(u64, rel_overlap);

        var rel_commit: usize = if (target_lo <= aligned_overlap_lo)
            rel_overlap
        else
            @intCast(@min(@as(u64, raw_window.len), target_lo - read_lo));

        if (read_lo + @as(u64, rel_commit) > start_off and rel_commit > 0 and rel_commit < raw_window.len and raw_window[rel_commit - 1] != sep) {
            if (memchr.find(width, raw_window, rel_commit, sep)) |nl_at| {
                if (nl_at + 1 < raw_window.len) {
                    rel_commit = nl_at + 1;
                } else if (memchr.findLast(width, raw_window, rel_overlap, rel_commit, sep)) |prev_nl| {
                    rel_commit = prev_nl + 1;
                } else {
                    rel_commit = rel_overlap;
                }
            } else if (memchr.findLast(width, raw_window, rel_overlap, rel_commit, sep)) |prev_nl| {
                rel_commit = prev_nl + 1;
            } else {
                rel_commit = rel_overlap;
            }
        }

        // If the entire window has no newline and read_lo > start_off (a single line exceeding step_sz),
        // expand left up to `max_line_len` so normal lines <= max_line_len are never split!
        if (rel_commit == rel_overlap and read_lo > start_off and memchr.find(width, raw_window, 0, sep) == null) {
            const line_span_so_far = cursor_end - read_lo;
            if (line_span_so_far <= @as(u64, config.max_line_len) and buf.len < hold_limit) {
                if (try state_mod.growWithLimit(stream_alloc, buf, hold_limit)) |grown| {
                    buf = grown;
                    if (stream_slot) |slot| slot.* = buf;
                    cur_step_sz = @min(@as(u64, hold_limit), @max(cur_step_sz * 2, @as(u64, buf.len)));
                    continue;
                }
            }
        }

        cur_step_sz = @intCast(step_sz);
        const chunk = raw_window[rel_overlap..];
        var commit_lo_u64 = read_lo + @as(u64, rel_commit);
        const act = try processReverseWindow(
            S,
            sink,
            matcher,
            chunk,
            aligned_overlap_lo,
            &commit_lo_u64,
            &cur_last_ln,
            &state,
            config,
            pool_alloc,
            &heap_cands,
        );
        bytes_scanned += cursor_end -| commit_lo_u64;
        switch (act) {
            .cont => {
                cursor_end = commit_lo_u64;
            },
            .stopped => break,
            .jump_back => |target| {
                const clamped = @max(start_off, target);
                if (clamped < commit_lo_u64) {
                    cur_last_ln = null;
                    cursor_end = clamped;
                } else {
                    cursor_end = commit_lo_u64;
                }
            },
        }
    }

    const reached_start = (cursor_end <= start_off) and !state.stopped and state.soft_error == null;
    if (reached_start and state.hit_byte_cap) state_mod.noteLimit(&state, .max_bytes);
    return finalizeReverse(S, sink, &state, config, bytes_scanned, total_bytes_read, reached_start and !state.hit_byte_cap);
}

/// Service entry point: reverse tail search over a `probe.RandomAccess` source.
pub fn searchSourceReverseAt(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    source: RandomAccess,
    source_id: []const u8,
    matcher: anytype,
    config: SearchConfig,
) ReadError!Result {
    const cfg = cfg_mod.serviceConfig(config);
    var bridge = pull_mod.EventBridge(S){
        .inner = sink,
        .source_id = source_id,
        .config = cfg,
    };
    const result = try searchReverseAt(pull_mod.EventBridge(S), allocator, &bridge, source, "", matcher, cfg);
    pull_mod.emitSummary(S, sink, source_id, cfg, result);
    return result;
}
