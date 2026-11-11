//! [Module] search/tree.zig
//! [Layer] Layer 4 — Virtual Source Tree & In-Memory Archive Search Entry Points (`F14`)
//! [Role] Traverses virtual `source.Source` trees and zero-disk-landing `ArchiveTree` instances,
//!        applying `.gitignore`/`.ignore`/`.rgignore` rules, `ignore_texts`, globs, and file-type filters,
//!        and streaming matching files through the search pipeline.
//! [Invariants]
//!   1. Public entry points (`searchTree`, `searchArchiveSlice`, `searchArchive`) never accept
//!      `std.Io.File` or `std.Io.Dir` handles (`checkSearchFn` redline).
//!   2. Enforces traversal caps (`max_depth`, `max_entries`) and request-level search budgets
//!      (`max_results`, `max_request_bytes`, `max_output_bytes`, `time_budget_ns`, `cancel`) across files.
//!   3. Virtual file open/read errors are isolated per file (`sources_failed += 1`) without aborting traversal.

const std = @import("std");
const source_mod = @import("../source.zig");
const sink_mod = @import("../sink.zig");
const matcher_mod = @import("../matcher.zig");
const config_mod = @import("config.zig");
const state_mod = @import("state.zig");
const pull_mod = @import("pull.zig");
const pipeline_mod = @import("pipeline.zig");
const archive_mod = @import("../codec/archive.zig");
const glob_mod = @import("../walk/glob.zig");
const ignore_mod = @import("../walk/ignore.zig");
const types_mod = @import("../walk/types.zig");

pub const TypeDef = types_mod.Type;

pub const max_depth_hard_cap: usize = 256;
pub const default_max_entries: u64 = 100_000;
pub const max_entries_hard_cap: u64 = 1_000_000;
pub const max_ignore_file_bytes: usize = 1024 * 1024;

pub const TreeConfig = struct {
    search: config_mod.SearchConfig = .{},
    archive: archive_mod.ArchiveOptions = .{},
    globs: []const []const u8 = &.{},
    iglobs: []const []const u8 = &.{},
    iglob: bool = false,
    types: []const []const u8 = &.{},
    types_not: []const []const u8 = &.{},
    custom_types: []const types_mod.Type = &.{},
    ignore_texts: []const []const u8 = &.{},
    read_ignore: bool = true,
    respect_gitignore: bool = true,
    respect_ignore: bool = true,
    respect_rgignore: bool = true,
    ignore_case_insensitive: bool = false,
    hidden: bool = false,
    skip_git: bool = true,
    max_depth: usize = max_depth_hard_cap,
    max_entries: u64 = default_max_entries,
    max_filesize: ?u64 = null,
    max_concurrency: usize = 1,
    files: bool = false,
};

fn markSummaryIncomplete(summary: *sink_mod.Summary) void {
    if (@hasField(sink_mod.Summary, "incomplete")) {
        @field(summary, "incomplete") = true;
    }
    if (@hasField(sink_mod.Summary, "partial")) {
        @field(summary, "partial") = true;
    }
}

fn noteSummaryError(summary: *sink_mod.Summary) void {
    summary.sources_failed += 1;
    if (@hasField(sink_mod.Summary, "errors_encountered")) {
        @field(summary, "errors_encountered") += 1;
    }
    markSummaryIncomplete(summary);
}

fn noteSummaryBinarySkipped(summary: *sink_mod.Summary) void {
    if (@hasField(sink_mod.Summary, "binary_files_skipped")) {
        @field(summary, "binary_files_skipped") += 1;
    }
}

fn accumulateResult(summary: *sink_mod.Summary, res: sink_mod.Result) void {
    summary.searches += 1;
    if (@hasField(sink_mod.Summary, "files_searched")) {
        @field(summary, "files_searched") += 1;
    }
    const matched_lines = if (res.outcome == .binary_matched and res.matched_lines == 0)
        @as(u64, 1)
    else
        res.matched_lines;
    const matches = if (res.outcome == .binary_matched and res.matches == 0)
        @as(u64, 1)
    else
        res.matches;

    if (matched_lines > 0 or res.outcome == .binary_matched) {
        summary.searches_with_match += 1;
        if (@hasField(sink_mod.Summary, "files_with_matches")) {
            @field(summary, "files_with_matches") += 1;
        }
    }
    if (res.outcome == .binary_quit) {
        noteSummaryBinarySkipped(summary);
    }
    summary.matched_lines += matched_lines;
    summary.matches += matches;
    summary.bytes_searched += res.bytes_searched;
    summary.bytes_printed += res.output_bytes;
    summary.bytes_read_raw += res.bytes_read;
    if (res.soft_error != null) {
        noteSummaryError(summary);
    }
    if (res.partial or res.limit_hit != .none or res.paused) {
        markSummaryIncomplete(summary);
    }
}

fn normalizeRootPath(root_path: []const u8) []const u8 {
    var s = root_path;
    while (std.mem.startsWith(u8, s, "./")) {
        s = s[2..];
    }
    if (std.mem.eql(u8, s, ".")) return "";
    s = std.mem.trim(u8, s, "/");
    return s;
}

fn joinPath(allocator: std.mem.Allocator, base: []const u8, name: []const u8) ![]u8 {
    if (base.len == 0) return allocator.dupe(u8, name);
    var out = try allocator.alloc(u8, base.len + 1 + name.len);
    @memcpy(out[0..base.len], base);
    out[base.len] = '/';
    @memcpy(out[base.len + 1 ..], name);
    return out;
}

fn readVirtualFileBounded(
    allocator: std.mem.Allocator,
    io: std.Io,
    src: source_mod.Source,
    path: []const u8,
    max_bytes: usize,
) ?[]u8 {
    const h = src.open(io, path) catch return null;
    defer src.close(io, h);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);

    var buf: [4096]u8 = undefined;
    while (out.items.len < max_bytes) {
        const rem = max_bytes - out.items.len;
        const want = @min(buf.len, rem);
        const n = src.read(io, h, buf[0..want]) catch {
            out.deinit(allocator);
            return null;
        };
        if (n == 0) break;
        out.appendSlice(allocator, buf[0..n]) catch {
            out.deinit(allocator);
            return null;
        };
        if (n < want) break;
    }
    return out.toOwnedSlice(allocator) catch {
        out.deinit(allocator);
        return null;
    };
}

fn loadDirectoryIgnoreSet(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    src: source_mod.Source,
    dir_full_path: []const u8,
    dir_rel_path: []const u8,
    parent: ?*const ignore_mod.Set,
    is_root: bool,
    config: TreeConfig,
) !?*const ignore_mod.Set {
    const read_any_files = config.read_ignore and (config.respect_gitignore or config.respect_ignore or config.respect_rgignore);
    const has_root_texts = is_root and config.ignore_texts.len > 0;
    if (!read_any_files and !has_root_texts) return parent;

    var gitignore_bytes: ?[]u8 = null;
    defer if (gitignore_bytes) |b| gpa.free(b);
    var ignore_bytes: ?[]u8 = null;
    defer if (ignore_bytes) |b| gpa.free(b);
    var rgignore_bytes: ?[]u8 = null;
    defer if (rgignore_bytes) |b| gpa.free(b);

    if (read_any_files) {
        if (config.respect_gitignore) {
            const p = try joinPath(gpa, dir_full_path, ".gitignore");
            defer gpa.free(p);
            gitignore_bytes = readVirtualFileBounded(gpa, io, src, p, max_ignore_file_bytes);
        }
        if (config.respect_ignore) {
            const p = try joinPath(gpa, dir_full_path, ".ignore");
            defer gpa.free(p);
            ignore_bytes = readVirtualFileBounded(gpa, io, src, p, max_ignore_file_bytes);
        }
        if (config.respect_rgignore) {
            const p = try joinPath(gpa, dir_full_path, ".rgignore");
            defer gpa.free(p);
            rgignore_bytes = readVirtualFileBounded(gpa, io, src, p, max_ignore_file_bytes);
        }
    }

    if (gitignore_bytes == null and ignore_bytes == null and rgignore_bytes == null and !has_root_texts) {
        return parent;
    }

    var ig_list: std.ArrayList(glob_mod.Glob) = .empty;

    if (gitignore_bytes != null or ignore_bytes != null or rgignore_bytes != null) {
        try ignore_mod.parseLayerInto(
            arena,
            .{
                .gitignore = gitignore_bytes,
                .ignore = ignore_bytes,
                .rgignore = rgignore_bytes,
            },
            .{
                .vcs = config.respect_gitignore,
                .dot = config.respect_ignore or config.respect_rgignore,
                .exclude = false,
                .case_insensitive = config.ignore_case_insensitive,
            },
            &ig_list,
        );
    }

    if (has_root_texts) {
        try ignore_mod.parseTextsInto(
            arena,
            config.ignore_texts,
            &ig_list,
            .{ .case_insensitive = config.ignore_case_insensitive },
        );
    }

    if (ig_list.items.len == 0) return parent;

    const set_ptr = try arena.create(ignore_mod.Set);
    set_ptr.* = try ignore_mod.build(
        arena,
        gpa,
        parent,
        dir_rel_path.len,
        &.{},
        ig_list.items,
    );
    return set_ptr;
}

fn isHiddenName(name: []const u8) bool {
    return name.len > 0 and name[0] == '.' and !std.mem.eql(u8, name, ".") and !std.mem.eql(u8, name, "..");
}

fn blockDirectoryByGlobs(user_globs: []const glob_mod.Glob, rel: []const u8) bool {
    if (user_globs.len == 0) return false;
    const base = glob_mod.basename(rel);
    var decision: ?bool = null;
    for (user_globs) |item| {
        if (glob_mod.matches(item, rel, base, true)) decision = !item.negated;
    }
    return if (decision) |kept| !kept else false;
}

fn allowFileByGlobsAndTypes(
    user_globs: []const glob_mod.Glob,
    config: TreeConfig,
    rel: []const u8,
) bool {
    const base = glob_mod.basename(rel);
    if (!types_mod.matchesWithTable(config.custom_types, config.types, config.types_not, base)) {
        return false;
    }
    if (user_globs.len == 0) return true;
    var any_positive = false;
    var decision: ?bool = null;
    for (user_globs) |item| {
        if (!item.negated) any_positive = true;
        if (glob_mod.matches(item, rel, base, false)) decision = !item.negated;
    }
    if (decision) |kept| return kept;
    return !any_positive;
}

const WalkItem = struct {
    full_path: []const u8,
    rel_path: []const u8,
};

fn walkVirtualDir(
    arena: std.mem.Allocator,
    gpa: std.mem.Allocator,
    io: std.Io,
    src: source_mod.Source,
    dir_full_path: []const u8,
    dir_rel_path: []const u8,
    depth: usize,
    max_depth: usize,
    max_entries: u64,
    seen_entries: *u64,
    parent_ignore: ?*const ignore_mod.Set,
    user_globs: []const glob_mod.Glob,
    config: TreeConfig,
    files_out: *std.ArrayList(WalkItem),
    summary: *sink_mod.Summary,
    incomplete: *bool,
) !void {
    if (state_mod.cancelIsSet(config.search) or state_mod.flagIsSet(config.search)) {
        incomplete.* = true;
        markSummaryIncomplete(summary);
        return;
    }

    const active_ignore = try loadDirectoryIgnoreSet(
        arena,
        gpa,
        io,
        src,
        dir_full_path,
        dir_rel_path,
        parent_ignore,
        depth == 0,
        config,
    );

    const open_path = if (dir_full_path.len == 0) "" else dir_full_path;
    const dir_h = src.open(io, open_path) catch {
        noteSummaryError(summary);
        incomplete.* = true;
        return;
    };
    defer src.close(io, dir_h);

    var dir_entries: std.ArrayList(source_mod.Entry) = .empty;
    defer dir_entries.deinit(gpa);

    var batch: [64]source_mod.Entry = undefined;
    var prev_first_name: ?[]const u8 = null;
    while (true) {
        const n = src.list(io, dir_h, &batch) catch {
            noteSummaryError(summary);
            incomplete.* = true;
            break;
        };
        if (n == 0) break;
        if (prev_first_name) |prev| {
            if (std.mem.eql(u8, prev, batch[0].name)) break;
        }
        prev_first_name = batch[0].name;

        for (batch[0..n]) |entry| {
            try dir_entries.append(gpa, .{
                .name = try arena.dupe(u8, entry.name),
                .kind = entry.kind,
            });
        }
        if (n < batch.len) break;
    }

    for (dir_entries.items) |entry| {
        if (state_mod.cancelIsSet(config.search) or state_mod.flagIsSet(config.search)) {
            incomplete.* = true;
            markSummaryIncomplete(summary);
            return;
        }
        if (std.mem.eql(u8, entry.name, ".") or std.mem.eql(u8, entry.name, "..")) continue;
        if (entry.kind == .other) continue;

        if (seen_entries.* >= max_entries) {
            incomplete.* = true;
            markSummaryIncomplete(summary);
            return;
        }
        seen_entries.* += 1;

        if (config.skip_git and entry.kind == .directory and std.mem.eql(u8, entry.name, ".git")) {
            continue;
        }
        if (!config.hidden and isHiddenName(entry.name)) {
            continue;
        }

        const child_full = try joinPath(arena, dir_full_path, entry.name);
        const child_rel = try joinPath(arena, dir_rel_path, entry.name);
        const is_dir = (entry.kind == .directory);

        if (is_dir and blockDirectoryByGlobs(user_globs, child_rel)) {
            continue;
        }

        if (active_ignore) |ig_set| {
            var scratch: [4096]u8 = undefined;
            if (ignore_mod.isIgnored(ig_set, child_rel, is_dir, &scratch)) {
                continue;
            }
        }

        if (is_dir) {
            if (depth + 1 > max_depth) {
                incomplete.* = true;
                markSummaryIncomplete(summary);
                continue;
            }
            try walkVirtualDir(
                arena,
                gpa,
                io,
                src,
                child_full,
                child_rel,
                depth + 1,
                max_depth,
                max_entries,
                seen_entries,
                active_ignore,
                user_globs,
                config,
                files_out,
                summary,
                incomplete,
            );
        } else if (entry.kind == .file) {
            if (!allowFileByGlobsAndTypes(user_globs, config, child_rel)) {
                continue;
            }
            try files_out.append(gpa, .{
                .full_path = child_full,
                .rel_path = child_rel,
            });
        }
    }
}

const EmptySink = struct {};

/// Sink wrapper that intercepts callbacks for a single file in `searchTree`:
/// - For Event sinks (`@hasDecl(S, "event")`), uses `EventBridge(S)` so `begin`, `match`, `context`, `end` carry `source_id = rel_path` (without emitting a per-file `summary`).
/// - For Legacy sinks (`matched`, `context`, `begin`, `finish`), forwards directly and tracks whether the sink requested early stop.
fn FileSinkAdapter(comptime S: type) type {
    const is_event = @hasDecl(S, "event");
    return struct {
        inner: *S,
        bridge: if (is_event) pull_mod.EventBridge(S) else void,
        stopped_by_sink: bool = false,

        const Self = @This();

        pub fn init(sink: *S, source_id: []const u8, cfg: config_mod.SearchConfig) Self {
            return .{
                .inner = sink,
                .bridge = if (is_event) .{
                    .inner = sink,
                    .source_id = source_id,
                    .config = cfg,
                } else {},
            };
        }

        pub fn control(self: *Self) sink_mod.Flow {
            if (is_event) return self.bridge.control();
            if (@hasDecl(S, "control")) return self.inner.control();
            return if (self.stopped_by_sink) .stop else .cont;
        }

        pub fn begin(self: *Self, name: []const u8) bool {
            if (is_event) {
                const keep = self.bridge.begin(name);
                if (!keep) self.stopped_by_sink = true;
                return keep;
            }
            if (@hasDecl(S, "begin")) {
                const keep = self.inner.begin(name);
                if (!keep) self.stopped_by_sink = true;
                return keep;
            }
            return true;
        }

        pub fn matched(self: *Self, line: sink_mod.Line) bool {
            if (is_event) {
                const keep = self.bridge.matched(line);
                if (!keep) self.stopped_by_sink = true;
                return keep;
            }
            if (@hasDecl(S, "matched")) {
                const keep = self.inner.matched(line);
                if (!keep) self.stopped_by_sink = true;
                return keep;
            }
            return true;
        }

        pub fn context(self: *Self, line: sink_mod.Line) bool {
            if (is_event) {
                const keep = self.bridge.context(line);
                if (!keep) self.stopped_by_sink = true;
                return keep;
            }
            if (@hasDecl(S, "context")) {
                const keep = self.inner.context(line);
                if (!keep) self.stopped_by_sink = true;
                return keep;
            }
            return true;
        }

        pub fn contextBreak(self: *Self) bool {
            if (is_event) {
                const keep = self.bridge.contextBreak();
                if (!keep) self.stopped_by_sink = true;
                return keep;
            }
            if (@hasDecl(S, "contextBreak")) {
                const keep = self.inner.contextBreak();
                if (!keep) self.stopped_by_sink = true;
                return keep;
            }
            return true;
        }

        pub fn binary(self: *Self, offset: u64) bool {
            if (!is_event and @hasDecl(S, "binary")) {
                const keep = self.inner.binary(offset);
                if (!keep) self.stopped_by_sink = true;
                return keep;
            }
            return true;
        }

        pub fn progress(self: *Self, bytes_searched: u64, match_count: u64, matched_lines: u64) bool {
            if (is_event) {
                const keep = self.bridge.progress(bytes_searched, match_count, matched_lines);
                if (!keep) self.stopped_by_sink = true;
                return keep;
            }
            if (@hasDecl(S, "progress")) {
                const keep = self.inner.progress(bytes_searched, match_count, matched_lines);
                if (!keep) self.stopped_by_sink = true;
                return keep;
            }
            return true;
        }

        pub fn heartbeat(self: *Self, bytes_searched: u64, match_count: u64, matched_lines: u64) bool {
            if (is_event) {
                const keep = self.bridge.heartbeat(bytes_searched, match_count, matched_lines);
                if (!keep) self.stopped_by_sink = true;
                return keep;
            }
            if (@hasDecl(S, "heartbeat")) {
                const keep = self.inner.heartbeat(bytes_searched, match_count, matched_lines);
                if (!keep) self.stopped_by_sink = true;
                return keep;
            }
            return true;
        }

        pub fn finish(self: *Self, result: sink_mod.Result) bool {
            if (is_event) {
                const keep = self.bridge.finish(result);
                if (!keep) self.stopped_by_sink = true;
                return keep;
            }
            if (@hasDecl(S, "finish")) {
                const Ret = @typeInfo(@TypeOf(@field(S, "finish"))).@"fn".return_type.?;
                if (Ret == bool) {
                    const keep = self.inner.finish(result);
                    if (!keep) self.stopped_by_sink = true;
                    return keep;
                } else {
                    self.inner.finish(result);
                    return true;
                }
            }
            return true;
        }
    };
}

const VirtualReadCtx = struct {
    src: source_mod.Source,
    io: std.Io,
    handle: usize,
    max_filesize: ?u64 = null,
    total_read: u64 = 0,
    exceeded_filesize: bool = false,
    at_eof: bool = false,

    fn read(raw: *anyopaque, dest: []u8) config_mod.ReadError!usize {
        const self: *VirtualReadCtx = @ptrCast(@alignCast(raw));
        if (self.at_eof or dest.len == 0) return 0;
        const n = self.src.read(self.io, self.handle, dest) catch return error.ReadFailed;
        if (n == 0) {
            self.at_eof = true;
            return 0;
        }
        self.total_read += n;
        if (self.max_filesize) |limit| {
            if (self.total_read > limit) {
                self.exceeded_filesize = true;
                self.at_eof = true;
                return 0;
            }
        }
        // Short read into a large pipeline buffer means the virtual source reached EOF
        // (also guards against stateless mock VTable.read implementations that do not advance an offset).
        if (n < dest.len) {
            self.at_eof = true;
        }
        return n;
    }
};

fn emitOpenErrorEvents(comptime S: type, sink: *S, rel_path: []const u8) bool {
    if (@hasDecl(S, "event")) {
        if (pull_mod.eventFlow(sink, .{ .begin = .{ .source_id = rel_path } }) != .cont) return false;
        if (pull_mod.eventFlow(sink, .{ .end = .{
            .source_id = rel_path,
            .outcome = .complete,
            .soft_error = .read_failed,
        } }) != .cont) return false;
    }
    return true;
}

fn searchSingleVirtualFile(
    comptime S: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: *S,
    src: source_mod.Source,
    item: WalkItem,
    matcher_ptr: anytype,
    file_cfg: config_mod.SearchConfig,
    max_filesize: ?u64,
    summary: *sink_mod.Summary,
    incomplete: *bool,
    stopped_by_sink: *bool,
) !void {
    const file_h = src.open(io, item.full_path) catch {
        noteSummaryError(summary);
        incomplete.* = true;
        if (!emitOpenErrorEvents(S, sink, item.rel_path)) {
            stopped_by_sink.* = true;
        }
        return;
    };
    defer src.close(io, file_h);

    const is_event = @hasDecl(S, "event");
    const effective_cfg = if (is_event) config_mod.serviceConfig(file_cfg) else file_cfg;

    var adapter = FileSinkAdapter(S).init(sink, item.rel_path, effective_cfg);
    var rctx = VirtualReadCtx{
        .src = src,
        .io = io,
        .handle = file_h,
        .max_filesize = max_filesize,
    };

    matcher_mod.validateMatcher(@TypeOf(matcher_ptr));
    state_mod.resetStats(matcher_ptr);

    const res = try pipeline_mod.drive(
        FileSinkAdapter(S),
        allocator,
        &adapter,
        matcher_ptr,
        effective_cfg,
        item.rel_path,
        VirtualReadCtx.read,
        &rctx,
    );

    if (rctx.exceeded_filesize) {
        return;
    }

    accumulateResult(summary, res);
    if (adapter.stopped_by_sink) {
        stopped_by_sink.* = true;
        if (adapter.control() == .pause) {
            incomplete.* = true;
        }
    }
}

/// Traverses a virtual `source.Source` starting at `root_path`, honoring `.gitignore`, `.ignore`,
/// `.rgignore`, `config.ignore_texts`, `globs`, `iglobs`, `types`, `types_not`, `max_depth`, and `max_entries`,
/// and searches each matching file.
/// Never accepts `std.Io.File` or `std.Io.Dir`.
pub fn searchTree(
    comptime S: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: *S,
    src: source_mod.Source,
    root_path: []const u8,
    matcher_ptr: anytype,
    config: TreeConfig,
) !sink_mod.Summary {
    const SinkType = if (S == void) EmptySink else S;
    var empty_sink = EmptySink{};
    const eff_sink: *SinkType = if (S == void) &empty_sink else sink;

    matcher_mod.validateMatcher(@TypeOf(matcher_ptr));
    try config_mod.validateBudgets(config.search);

    const started_ns = state_mod.readClock(config.search);
    var summary: sink_mod.Summary = .{
        .source_id = root_path,
    };
    var incomplete = false;
    var stopped_by_sink = false;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Compile globs and iglobs
    const regular_globs = try glob_mod.compileGlobs(arena, config.globs, .{ .case_insensitive = config.iglob });
    const insensitive_globs = try glob_mod.compileGlobs(arena, config.iglobs, .{ .case_insensitive = true });
    var user_globs = try arena.alloc(glob_mod.Glob, regular_globs.len + insensitive_globs.len);
    if (regular_globs.len > 0) @memcpy(user_globs[0..regular_globs.len], regular_globs);
    if (insensitive_globs.len > 0) @memcpy(user_globs[regular_globs.len..], insensitive_globs);

    const max_depth = @min(config.max_depth, max_depth_hard_cap);
    const max_entries = @min(config.max_entries, max_entries_hard_cap);
    var seen_entries: u64 = 0;

    var files_list: std.ArrayList(WalkItem) = .empty;
    defer files_list.deinit(allocator);

    const norm_root = normalizeRootPath(root_path);
    try walkVirtualDir(
        arena,
        allocator,
        io,
        src,
        norm_root,
        "",
        0,
        max_depth,
        max_entries,
        &seen_entries,
        null,
        user_globs,
        config,
        &files_list,
        &summary,
        &incomplete,
    );

    if (config.files) {
        for (files_list.items) |item| {
            if (state_mod.cancelIsSet(config.search) or state_mod.flagIsSet(config.search)) {
                incomplete = true;
                markSummaryIncomplete(&summary);
                break;
            }
            if (config.search.max_results) |max_res| {
                if (summary.matched_lines >= max_res) {
                    incomplete = true;
                    markSummaryIncomplete(&summary);
                    break;
                }
            }
            summary.searches += 1;
            summary.searches_with_match += 1;
            summary.matched_lines += 1;
            summary.matches += 1;
            if (@hasDecl(SinkType, "write")) {
                if (!eff_sink.write(item.rel_path)) {
                    stopped_by_sink = true;
                    break;
                }
            } else if (@hasDecl(SinkType, "event")) {
                if (pull_mod.eventFlow(eff_sink, .{ .begin = .{ .source_id = item.rel_path } }) != .cont) {
                    stopped_by_sink = true;
                    break;
                }
                if (pull_mod.eventFlow(eff_sink, .{ .end = .{ .source_id = item.rel_path, .matched_lines = 1, .matches = 1 } }) != .cont) {
                    stopped_by_sink = true;
                    break;
                }
            }
        }
    } else {
        var scratch = config_mod.Scratch.init(allocator);
        defer scratch.deinit();

        for (files_list.items) |item| {
            if (stopped_by_sink) break;

            if (state_mod.cancelIsSet(config.search) or state_mod.flagIsSet(config.search)) {
                incomplete = true;
                markSummaryIncomplete(&summary);
                break;
            }

            var file_cfg = config.search;
            if (file_cfg.buffer_size == config_mod.SearchConfig.default_buffer_size and config.max_concurrency > 1) {
                file_cfg.buffer_size = config_mod.SearchConfig.optimalBufferSize(@intCast(@min(config.max_concurrency, std.math.maxInt(u32))));
            }
            if (file_cfg.scratch_pool == null) {
                file_cfg.scratch_pool = &scratch;
            }

            // Enforce request-level time budget across files
            if (config.search.time_budget_ns) |budget_ns| {
                const now_ns = state_mod.readClock(config.search);
                const elapsed_ns: u64 = if (now_ns > started_ns) @intCast(now_ns - started_ns) else 0;
                if (elapsed_ns >= budget_ns) {
                    incomplete = true;
                    markSummaryIncomplete(&summary);
                    break;
                }
                file_cfg.time_budget_ns = budget_ns - elapsed_ns;
            }

            // Enforce request-level max_results across files
            if (config.search.max_results) |max_res| {
                if (summary.matched_lines >= max_res) {
                    incomplete = true;
                    markSummaryIncomplete(&summary);
                    break;
                }
                file_cfg.max_results = max_res - summary.matched_lines;
            }

            // Enforce request-level max_request_bytes across files
            if (config.search.max_request_bytes) |max_req| {
                if (summary.bytes_read_raw >= max_req) {
                    incomplete = true;
                    markSummaryIncomplete(&summary);
                    break;
                }
                file_cfg.max_request_bytes = max_req - summary.bytes_read_raw;
            }

            // Enforce request-level max_output_bytes across files
            if (config.search.max_output_bytes) |max_out| {
                if (summary.bytes_printed >= max_out) {
                    incomplete = true;
                    markSummaryIncomplete(&summary);
                    break;
                }
                file_cfg.max_output_bytes = max_out - summary.bytes_printed;
            }

            const prev_matches = summary.matched_lines;
            try searchSingleVirtualFile(
                SinkType,
                allocator,
                io,
                eff_sink,
                src,
                item,
                matcher_ptr,
                file_cfg,
                config.max_filesize,
                &summary,
                &incomplete,
                &stopped_by_sink,
            );

            if (config.search.exists and summary.matched_lines > prev_matches) {
                break;
            }
        }
    }

    const end_ns = state_mod.readClock(config.search);
    summary.elapsed = if (end_ns > started_ns) @intCast(end_ns - started_ns) else 0;

    if (@hasDecl(SinkType, "event") and !incomplete and !stopped_by_sink) {
        _ = pull_mod.eventFlow(eff_sink, .{ .summary = summary });
    }

    return summary;
}

/// Unpacks an in-memory archive byte slice (`.tar`, `.tar.gz`/`.tgz`, `.tar.zst`, `.tar.xz`, `.zip`)
/// into a zero-disk-landing `ArchiveTree` and searches it with `searchTree`.
/// Never accepts `std.Io.File` or `std.Io.Dir`.
pub fn searchArchiveSlice(
    comptime S: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: *S,
    archive_bytes: []const u8,
    matcher_ptr: anytype,
    config: TreeConfig,
) !sink_mod.Summary {
    var tree = try archive_mod.ArchiveTree.initFromSlice(allocator, archive_bytes, config.archive);
    defer tree.deinit();
    return searchTree(S, allocator, io, sink, tree.source(), "", matcher_ptr, config);
}

/// Unpacks a streaming archive reader (`.tar`, `.tar.gz`/`.tgz`, `.tar.zst`, `.tar.xz`, `.zip`)
/// into a zero-disk-landing `ArchiveTree` and searches it with `searchTree`.
/// Never accepts `std.Io.File` or `std.Io.Dir`.
pub fn searchArchive(
    comptime S: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: *S,
    reader: *std.Io.Reader,
    matcher_ptr: anytype,
    config: TreeConfig,
) !sink_mod.Summary {
    var tree = try archive_mod.ArchiveTree.initFromReader(allocator, reader, config.archive);
    defer tree.deinit();
    return searchTree(S, allocator, io, sink, tree.source(), "", matcher_ptr, config);
}

// ============================================================================
// Unit Tests
// ============================================================================

fn writeTarOctal(field: []u8, val: u64) void {
    @memset(field, '0');
    if (field.len > 0) field[field.len - 1] = 0;
    var v = val;
    var idx: usize = if (field.len >= 2) field.len - 2 else 0;
    while (v > 0) {
        field[idx] = @intCast('0' + (v & 7));
        v >>= 3;
        if (idx == 0) break;
        idx -= 1;
    }
}

fn finalizeTarHeader(header: *[512]u8) void {
    @memcpy(header[257..263], "ustar\x00");
    @memcpy(header[263..265], "00");
    @memset(header[148..156], ' ');
    var sum: u64 = 0;
    for (header) |b| sum += b;
    writeTarOctal(header[148..155], sum);
    header[155] = ' ';
}

fn appendTarEntry(out: *std.ArrayList(u8), allocator: std.mem.Allocator, path: []const u8, typeflag: u8, data: []const u8) !void {
    var header: [512]u8 = @splat(0);
    const name_len = @min(path.len, 100);
    @memcpy(header[0..name_len], path[0..name_len]);
    writeTarOctal(header[100..108], 0o644);
    writeTarOctal(header[108..116], 0);
    writeTarOctal(header[116..124], 0);
    writeTarOctal(header[124..136], if (typeflag == '0') data.len else 0);
    writeTarOctal(header[136..148], 0);
    header[156] = typeflag;
    finalizeTarHeader(&header);
    try out.appendSlice(allocator, &header);
    if (typeflag == '0' and data.len > 0) {
        try out.appendSlice(allocator, data);
        const rem = data.len % 512;
        if (rem != 0) {
            const pad = 512 - rem;
            try out.appendNTimes(allocator, 0, pad);
        }
    }
}

test "searchTree over virtual Memory respects .gitignore and globs" {
    const f_gitignore = source_mod.Node{ .name = ".gitignore", .kind = .file, .bytes = "ignored.txt\nbuild/\n" };
    const f_ignored = source_mod.Node{ .name = "ignored.txt", .kind = .file, .bytes = "needle in ignored\n" };
    const f_keep = source_mod.Node{ .name = "keep.zig", .kind = .file, .bytes = "const needle = 1;\n" };
    const f_skip = source_mod.Node{ .name = "skip.md", .kind = .file, .bytes = "needle in markdown\n" };
    const f_out = source_mod.Node{ .name = "out.zig", .kind = .file, .bytes = "needle in build dir\n" };
    const d_build = source_mod.Node{
        .name = "build",
        .kind = .directory,
        .children = &.{&f_out},
    };
    const f_main = source_mod.Node{ .name = "main.zig", .kind = .file, .bytes = "pub fn needle() void {}\n" };
    const d_src = source_mod.Node{
        .name = "src",
        .kind = .directory,
        .children = &.{&f_main},
    };
    const root_node = source_mod.Node{
        .name = "",
        .kind = .directory,
        .children = &.{ &f_gitignore, &f_ignored, &f_keep, &f_skip, &d_build, &d_src },
    };

    var mem = source_mod.Memory{ .root = &root_node };
    const finder = try @import("../finder/finder.zig").Finder.init("needle", .{});

    const TestSink = struct {
        alloc: std.mem.Allocator,
        paths: std.ArrayList([]u8) = .empty,
        matches: usize = 0,

        pub fn event(self: *@This(), ev: sink_mod.Event) bool {
            switch (ev) {
                .match => |m| {
                    self.matches += 1;
                    if (self.paths.items.len == 0 or !std.mem.eql(u8, self.paths.items[self.paths.items.len - 1], m.source_id)) {
                        const copy = self.alloc.dupe(u8, m.source_id) catch return false;
                        self.paths.append(self.alloc, copy) catch {
                            self.alloc.free(copy);
                            return false;
                        };
                    }
                },
                else => {},
            }
            return true;
        }

        pub fn deinit(self: *@This()) void {
            for (self.paths.items) |p| self.alloc.free(p);
            self.paths.deinit(self.alloc);
        }
    };

    var sink = TestSink{ .alloc = std.testing.allocator };
    defer sink.deinit();

    const summary = try searchTree(
        TestSink,
        std.testing.allocator,
        std.testing.io,
        &sink,
        mem.source(),
        "",
        &finder,
        .{
            .globs = &.{"*.zig"},
        },
    );

    try std.testing.expectEqual(@as(u64, 2), summary.matched_lines);
    try std.testing.expectEqual(@as(usize, 2), sink.matches);
    try std.testing.expectEqual(@as(usize, 2), sink.paths.items.len);
    try std.testing.expectEqualStrings("keep.zig", sink.paths.items[0]);
    try std.testing.expectEqualStrings("src/main.zig", sink.paths.items[1]);
}

test "searchArchiveSlice on .tar with file types" {
    var tar_bytes: std.ArrayList(u8) = .empty;
    defer tar_bytes.deinit(std.testing.allocator);

    try appendTarEntry(&tar_bytes, std.testing.allocator, "src/lib.zig", '0', "const target = 42;\n");
    try appendTarEntry(&tar_bytes, std.testing.allocator, "README.md", '0', "target in readme\n");
    try tar_bytes.appendNTimes(std.testing.allocator, 0, 1024);

    const finder = try @import("../finder/finder.zig").Finder.init("target", .{});

    const CountSink = struct {
        matched_lines: u64 = 0,
        pub fn event(self: *@This(), ev: sink_mod.Event) bool {
            if (ev == .match) self.matched_lines += 1;
            return true;
        }
    };
    var sink = CountSink{};
    const summary = try searchArchiveSlice(
        CountSink,
        std.testing.allocator,
        std.testing.io,
        &sink,
        tar_bytes.items,
        &finder,
        .{
            .types = &.{"zig"},
        },
    );

    try std.testing.expectEqual(@as(u64, 1), summary.matched_lines);
    try std.testing.expectEqual(@as(u64, 1), sink.matched_lines);

    var reader = std.Io.Reader.fixed(tar_bytes.items);
    var stream_sink = CountSink{};
    const stream_summary = try searchArchive(
        CountSink,
        std.testing.allocator,
        std.testing.io,
        &stream_sink,
        &reader,
        &finder,
        .{ .types = &.{"zig"} },
    );
    try std.testing.expectEqual(@as(u64, 1), stream_summary.matched_lines);
}


