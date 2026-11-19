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

const builtin = @import("builtin");
const std = @import("std");
const source_mod = @import("../source.zig");
const sink_mod = @import("../sink.zig");
const matcher_mod = @import("../matcher.zig");
const config_mod = @import("config.zig");
const state_mod = @import("state.zig");
const pull_mod = @import("pull.zig");
const pipeline_mod = @import("pipeline.zig");
const archive_mod = @import("../codec/archive.zig");
const decompress_mod = @import("../codec/decompress.zig");
const scheduler_mod = @import("../scheduler.zig");
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
    max_ignore_file_bytes: usize = max_ignore_file_bytes,
    max_glob_rules: ?usize = null,
    max_glob_rule_len: ?usize = null,
    max_glob_brace_depth: ?usize = null,
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
            gitignore_bytes = readVirtualFileBounded(gpa, io, src, p, config.max_ignore_file_bytes);
        }
        if (config.respect_ignore) {
            const p = try joinPath(gpa, dir_full_path, ".ignore");
            defer gpa.free(p);
            ignore_bytes = readVirtualFileBounded(gpa, io, src, p, config.max_ignore_file_bytes);
        }
        if (config.respect_rgignore) {
            const p = try joinPath(gpa, dir_full_path, ".rgignore");
            defer gpa.free(p);
            rgignore_bytes = readVirtualFileBounded(gpa, io, src, p, config.max_ignore_file_bytes);
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
                .max_rules = config.max_glob_rules,
                .max_rule_len = config.max_glob_rule_len,
                .max_brace_depth = config.max_glob_brace_depth,
            },
            &ig_list,
        );
    }

    if (has_root_texts) {
        try ignore_mod.parseTextsInto(
            arena,
            config.ignore_texts,
            &ig_list,
            .{
                .case_insensitive = config.ignore_case_insensitive,
                .max_rules = config.max_glob_rules,
                .max_rule_len = config.max_glob_rule_len,
                .max_brace_depth = config.max_glob_brace_depth,
            },
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
        last_action: sink_mod.FlowAction = .cont,
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
            return self.controlAction().toFlow();
        }

        pub fn controlAction(self: *Self) sink_mod.FlowAction {
            if (is_event) return self.bridge.controlAction();
            if (@hasDecl(S, "controlAction")) return self.inner.controlAction();
            if (@hasDecl(S, "control")) return sink_mod.FlowAction.fromFlow(self.inner.control());
            return self.last_action;
        }

        fn recordAction(self: *Self, action: sink_mod.FlowAction) bool {
            self.last_action = action;
            switch (action) {
                .cont => return true,
                .skip_to => return false,
                .pause, .stop => {
                    self.stopped_by_sink = true;
                    return false;
                },
            }
        }

        pub fn begin(self: *Self, name: []const u8) bool {
            if (is_event) {
                _ = self.bridge.begin(name);
                return self.recordAction(self.bridge.controlAction());
            }
            if (@hasDecl(S, "begin")) {
                return self.recordAction(state_mod.callSinkAction(S, "begin", self.inner, .{name}));
            }
            return true;
        }

        pub fn matched(self: *Self, line: sink_mod.Line) bool {
            if (is_event) {
                _ = self.bridge.matched(line);
                return self.recordAction(self.bridge.controlAction());
            }
            if (@hasDecl(S, "matched")) {
                return self.recordAction(state_mod.callSinkAction(S, "matched", self.inner, .{line}));
            }
            return true;
        }

        pub fn context(self: *Self, line: sink_mod.Line) bool {
            if (is_event) {
                _ = self.bridge.context(line);
                return self.recordAction(self.bridge.controlAction());
            }
            if (@hasDecl(S, "context")) {
                return self.recordAction(state_mod.callSinkAction(S, "context", self.inner, .{line}));
            }
            return true;
        }

        pub fn contextBreak(self: *Self) bool {
            if (is_event) {
                _ = self.bridge.contextBreak();
                return self.recordAction(self.bridge.controlAction());
            }
            if (@hasDecl(S, "contextBreak")) {
                return self.recordAction(state_mod.callSinkAction(S, "contextBreak", self.inner, .{}));
            }
            return true;
        }

        pub fn binary(self: *Self, offset: u64) bool {
            if (!is_event and @hasDecl(S, "binary")) {
                return self.recordAction(state_mod.callSinkAction(S, "binary", self.inner, .{offset}));
            }
            return true;
        }

        pub fn progress(self: *Self, bytes_searched: u64, match_count: u64, matched_lines: u64) bool {
            if (is_event) {
                _ = self.bridge.progress(bytes_searched, match_count, matched_lines);
                return self.recordAction(self.bridge.controlAction());
            }
            if (@hasDecl(S, "progress")) {
                return self.recordAction(state_mod.callSinkAction(S, "progress", self.inner, .{ bytes_searched, match_count, matched_lines }));
            }
            return true;
        }

        pub fn heartbeat(self: *Self, bytes_searched: u64, match_count: u64, matched_lines: u64) bool {
            if (is_event) {
                _ = self.bridge.heartbeat(bytes_searched, match_count, matched_lines);
                return self.recordAction(self.bridge.controlAction());
            }
            if (@hasDecl(S, "heartbeat")) {
                return self.recordAction(state_mod.callSinkAction(S, "heartbeat", self.inner, .{ bytes_searched, match_count, matched_lines }));
            }
            return true;
        }

        pub fn finish(self: *Self, result: sink_mod.Result) bool {
            if (is_event) {
                _ = self.bridge.finish(result);
                return self.recordAction(self.bridge.controlAction());
            }
            if (@hasDecl(S, "finish")) {
                const Ret = @typeInfo(@TypeOf(@field(S, "finish"))).@"fn".return_type.?;
                if (Ret == void) {
                    self.inner.finish(result);
                    return true;
                }
                return self.recordAction(state_mod.callSinkAction(S, "finish", self.inner, .{result}));
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

fn compileUserGlobs(arena: std.mem.Allocator, config: TreeConfig) ![]glob_mod.Glob {
    const max_glob_rules = config.max_glob_rules orelse glob_mod.rule_count_hard_cap;
    const regular_globs = try glob_mod.compileGlobs(arena, config.globs, .{
        .case_insensitive = config.iglob,
        .max_rules = max_glob_rules,
        .max_rule_len = config.max_glob_rule_len,
        .max_brace_depth = config.max_glob_brace_depth,
    });
    if (config.iglobs.len > 0 and regular_globs.len >= max_glob_rules) return error.GlobCountExceeded;
    const insensitive_globs = if (config.iglobs.len > 0) try glob_mod.compileGlobs(arena, config.iglobs, .{
        .case_insensitive = true,
        .max_rules = max_glob_rules - regular_globs.len,
        .max_rule_len = config.max_glob_rule_len,
        .max_brace_depth = config.max_glob_brace_depth,
    }) else &.{};
    const user_globs = try arena.alloc(glob_mod.Glob, regular_globs.len + insensitive_globs.len);
    if (regular_globs.len > 0) @memcpy(user_globs[0..regular_globs.len], regular_globs);
    if (insensitive_globs.len > 0) @memcpy(user_globs[regular_globs.len..], insensitive_globs);
    return user_globs;
}

fn applyRemainingBudgets(
    file_cfg: *config_mod.SearchConfig,
    base_cfg: config_mod.SearchConfig,
    started_ns: i128,
    summary: *sink_mod.Summary,
    incomplete: *bool,
) bool {
    if (base_cfg.time_budget_ns) |budget_ns| {
        const now_ns = state_mod.readClock(base_cfg);
        const elapsed_ns: u64 = if (now_ns > started_ns) @intCast(now_ns - started_ns) else 0;
        if (elapsed_ns >= budget_ns) {
            incomplete.* = true;
            markSummaryIncomplete(summary);
            return false;
        }
        file_cfg.time_budget_ns = budget_ns - elapsed_ns;
    }

    if (base_cfg.max_results) |max_res| {
        if (summary.matched_lines >= max_res) {
            incomplete.* = true;
            markSummaryIncomplete(summary);
            return false;
        }
        file_cfg.max_results = max_res - summary.matched_lines;
    }

    if (base_cfg.max_request_bytes) |max_req| {
        if (summary.bytes_read_raw >= max_req) {
            incomplete.* = true;
            markSummaryIncomplete(summary);
            return false;
        }
        file_cfg.max_request_bytes = max_req - summary.bytes_read_raw;
    }

    if (base_cfg.max_output_bytes) |max_out| {
        if (summary.bytes_printed >= max_out) {
            incomplete.* = true;
            markSummaryIncomplete(summary);
            return false;
        }
        file_cfg.max_output_bytes = max_out - summary.bytes_printed;
    }

    return true;
}

fn cloneCapturedLine(arena: std.mem.Allocator, line: sink_mod.Line) !sink_mod.Line {
    var copy = line;
    const duped_bytes = if (line.bytes.len > 0) try arena.dupe(u8, line.bytes) else &.{};
    copy.bytes = duped_bytes;

    if (line.text.len == 0) {
        copy.text = &.{};
    } else if (line.text.ptr == line.bytes.ptr and line.text.len == line.bytes.len) {
        copy.text = duped_bytes;
    } else {
        copy.text = try arena.dupe(u8, line.text);
    }

    if (line.raw.len == 0) {
        copy.raw = &.{};
    } else if (line.raw.ptr == line.bytes.ptr and line.raw.len == line.bytes.len) {
        copy.raw = duped_bytes;
    } else {
        copy.raw = try arena.dupe(u8, line.raw);
    }

    if (line.replaced) |r| {
        copy.replaced = try arena.dupe(u8, r);
    }

    if (line.matches.len > 0) {
        const spans = try arena.dupe(sink_mod.Span, line.matches);
        for (spans) |*sp| {
            if (sp.replacement) |r| {
                sp.replacement = try arena.dupe(u8, r);
            }
        }
        copy.matches = spans;
    } else {
        copy.matches = &.{};
    }

    if (copy.match) |*m| {
        if (m.replacement) |r| {
            m.replacement = try arena.dupe(u8, r);
        }
    }

    return copy;
}

const CapturedEvent = union(enum) {
    begin: []const u8,
    matched: sink_mod.Line,
    context: sink_mod.Line,
    context_break,
    binary: u64,
    progress: struct { bytes: u64, matches: u64, matched_lines: u64 },
    heartbeat: struct { bytes: u64, matches: u64, matched_lines: u64 },
    finish: sink_mod.Result,
};

const FileCaptureSink = struct {
    arena: std.mem.Allocator,
    events: std.ArrayList(CapturedEvent) = .empty,
    oom: bool = false,

    pub fn control(self: *FileCaptureSink) sink_mod.Flow {
        return self.controlAction().toFlow();
    }

    pub fn controlAction(self: *FileCaptureSink) sink_mod.FlowAction {
        return if (self.oom) .stop else .cont;
    }

    pub fn begin(self: *FileCaptureSink, name: []const u8) bool {
        const duped = self.arena.dupe(u8, name) catch {
            self.oom = true;
            return false;
        };
        self.events.append(self.arena, .{ .begin = duped }) catch {
            self.oom = true;
            return false;
        };
        return true;
    }

    pub fn matched(self: *FileCaptureSink, line: sink_mod.Line) bool {
        const copy = cloneCapturedLine(self.arena, line) catch {
            self.oom = true;
            return false;
        };
        self.events.append(self.arena, .{ .matched = copy }) catch {
            self.oom = true;
            return false;
        };
        return true;
    }

    pub fn context(self: *FileCaptureSink, line: sink_mod.Line) bool {
        const copy = cloneCapturedLine(self.arena, line) catch {
            self.oom = true;
            return false;
        };
        self.events.append(self.arena, .{ .context = copy }) catch {
            self.oom = true;
            return false;
        };
        return true;
    }

    pub fn contextBreak(self: *FileCaptureSink) bool {
        self.events.append(self.arena, .context_break) catch {
            self.oom = true;
            return false;
        };
        return true;
    }

    pub fn binary(self: *FileCaptureSink, offset: u64) bool {
        self.events.append(self.arena, .{ .binary = offset }) catch {
            self.oom = true;
            return false;
        };
        return true;
    }

    pub fn progress(self: *FileCaptureSink, bytes_searched: u64, match_count: u64, matched_lines: u64) bool {
        self.events.append(self.arena, .{ .progress = .{
            .bytes = bytes_searched,
            .matches = match_count,
            .matched_lines = matched_lines,
        } }) catch {
            self.oom = true;
            return false;
        };
        return true;
    }

    pub fn heartbeat(self: *FileCaptureSink, bytes_searched: u64, match_count: u64, matched_lines: u64) bool {
        self.events.append(self.arena, .{ .heartbeat = .{
            .bytes = bytes_searched,
            .matches = match_count,
            .matched_lines = matched_lines,
        } }) catch {
            self.oom = true;
            return false;
        };
        return true;
    }

    pub fn finish(self: *FileCaptureSink, result: sink_mod.Result) bool {
        self.events.append(self.arena, .{ .finish = result }) catch {
            self.oom = true;
            return false;
        };
        return true;
    }
};

fn ParallelTreeContext(comptime SinkType: type, comptime MatcherPtrType: type) type {
    return struct {
        allocator: std.mem.Allocator,
        io: std.Io,
        sink: *SinkType,
        src: source_mod.Source,
        files: []const WalkItem,
        matcher_ptr: MatcherPtrType,
        config: TreeConfig,
        worker_count: u32,
        started_ns: i128,
        scratches: []config_mod.Scratch,
        sink_mu: std.Io.Mutex = .init,
        internal_stop: std.atomic.Value(bool) = .init(false),
        summary: *sink_mod.Summary,
        incomplete: *bool,
        stopped_by_sink: *bool,

        const Self = @This();

        pub fn run(self: *Self, file_idx: usize, handle: *scheduler_mod.Scheduler(usize, Self).Handle) !void {
            if (self.internal_stop.load(.acquire) or handle.isStopped() or
                state_mod.cancelIsSet(self.config.search) or state_mod.flagIsSet(self.config.search))
            {
                return;
            }

            if (self.config.search.time_budget_ns) |budget_ns| {
                const now_ns = state_mod.readClock(self.config.search);
                const elapsed_ns: u64 = if (now_ns > self.started_ns) @intCast(now_ns - self.started_ns) else 0;
                if (elapsed_ns >= budget_ns) {
                    self.sink_mu.lockUncancelable(self.io);
                    self.incomplete.* = true;
                    markSummaryIncomplete(self.summary);
                    self.sink_mu.unlock(self.io);
                    self.internal_stop.store(true, .release);
                    handle.stop();
                    return;
                }
            }

            const item = self.files[file_idx];
            const file_h = self.src.open(self.io, item.full_path) catch {
                self.sink_mu.lockUncancelable(self.io);
                defer self.sink_mu.unlock(self.io);
                if (self.internal_stop.load(.acquire) or self.stopped_by_sink.*) return;
                noteSummaryError(self.summary);
                self.incomplete.* = true;
                if (!emitOpenErrorEvents(SinkType, self.sink, item.rel_path)) {
                    self.stopped_by_sink.* = true;
                    self.internal_stop.store(true, .release);
                    handle.stop();
                }
                return;
            };
            defer self.src.close(self.io, file_h);

            const is_event = @hasDecl(SinkType, "event");
            var file_cfg = self.config.search;
            if (file_cfg.buffer_size == config_mod.SearchConfig.default_buffer_size and self.worker_count > 1) {
                file_cfg.buffer_size = config_mod.SearchConfig.optimalBufferSize(self.worker_count);
            }
            if (file_cfg.scratch_pool == null) {
                file_cfg.scratch_pool = &self.scratches[handle.worker_index];
            }
            if (self.config.search.time_budget_ns) |budget_ns| {
                const now_ns = state_mod.readClock(self.config.search);
                const elapsed_ns: u64 = if (now_ns > self.started_ns) @intCast(now_ns - self.started_ns) else 0;
                if (elapsed_ns >= budget_ns) {
                    self.sink_mu.lockUncancelable(self.io);
                    self.incomplete.* = true;
                    markSummaryIncomplete(self.summary);
                    self.sink_mu.unlock(self.io);
                    self.internal_stop.store(true, .release);
                    handle.stop();
                    return;
                }
                file_cfg.time_budget_ns = budget_ns - elapsed_ns;
            }
            if (file_cfg.stop == null) {
                file_cfg.stop = &self.internal_stop;
            }
            const effective_cfg = if (is_event) config_mod.serviceConfig(file_cfg) else file_cfg;

            var file_arena = std.heap.ArenaAllocator.init(self.allocator);
            defer file_arena.deinit();

            var capture = FileCaptureSink{ .arena = file_arena.allocator() };
            var rctx = VirtualReadCtx{
                .src = self.src,
                .io = self.io,
                .handle = file_h,
                .max_filesize = self.config.max_filesize,
            };

            const res = try pipeline_mod.drive(
                FileCaptureSink,
                self.allocator,
                &capture,
                self.matcher_ptr,
                effective_cfg,
                item.rel_path,
                VirtualReadCtx.read,
                &rctx,
            );
            if (capture.oom) return error.OutOfMemory;
            if (rctx.exceeded_filesize) return;

            self.sink_mu.lockUncancelable(self.io);
            defer self.sink_mu.unlock(self.io);

            if (self.stopped_by_sink.* or self.internal_stop.load(.acquire)) return;
            if (state_mod.cancelIsSet(self.config.search) or state_mod.flagIsSet(self.config.search)) {
                self.incomplete.* = true;
                markSummaryIncomplete(self.summary);
                self.internal_stop.store(true, .release);
                handle.stop();
                return;
            }
            if (self.config.search.time_budget_ns) |budget_ns| {
                const now_ns = state_mod.readClock(self.config.search);
                const elapsed_ns: u64 = if (now_ns > self.started_ns) @intCast(now_ns - self.started_ns) else 0;
                if (elapsed_ns >= budget_ns) {
                    self.incomplete.* = true;
                    markSummaryIncomplete(self.summary);
                    self.internal_stop.store(true, .release);
                    handle.stop();
                    return;
                }
            }
            if (self.config.search.max_results) |max_res| {
                if (self.summary.matched_lines >= max_res) {
                    self.incomplete.* = true;
                    markSummaryIncomplete(self.summary);
                    self.internal_stop.store(true, .release);
                    handle.stop();
                    return;
                }
            }
            if (self.config.search.max_request_bytes) |max_req| {
                if (self.summary.bytes_read_raw >= max_req) {
                    self.incomplete.* = true;
                    markSummaryIncomplete(self.summary);
                    self.internal_stop.store(true, .release);
                    handle.stop();
                    return;
                }
            }
            if (self.config.search.max_output_bytes) |max_out| {
                if (self.summary.bytes_printed >= max_out) {
                    self.incomplete.* = true;
                    markSummaryIncomplete(self.summary);
                    self.internal_stop.store(true, .release);
                    handle.stop();
                    return;
                }
            }

            var adapter = FileSinkAdapter(SinkType).init(self.sink, item.rel_path, effective_cfg);
            var effective_res = res;
            var replayed_matched_lines: u64 = 0;
            var replayed_matches: u64 = 0;
            var finish_called = false;
            var capped_by_results = false;

            for (capture.events.items) |ev| {
                switch (ev) {
                    .begin => |name| {
                        if (!adapter.begin(name)) break;
                    },
                    .matched => |line| {
                        if (self.config.search.max_results) |max_res| {
                            if (self.summary.matched_lines + replayed_matched_lines >= max_res) {
                                capped_by_results = true;
                                break;
                            }
                        }
                        replayed_matched_lines += 1;
                        replayed_matches += @max(@as(u64, 1), @as(u64, @intCast(line.matches.len)));
                        if (!adapter.matched(line)) break;
                    },
                    .context => |line| {
                        if (!adapter.context(line)) break;
                    },
                    .context_break => {
                        if (!adapter.contextBreak()) break;
                    },
                    .binary => |off| {
                        if (!adapter.binary(off)) break;
                    },
                    .progress => |p| {
                        if (!adapter.progress(p.bytes, p.matches, p.matched_lines)) break;
                    },
                    .heartbeat => |hb| {
                        if (!adapter.heartbeat(hb.bytes, hb.matches, hb.matched_lines)) break;
                    },
                    .finish => |fin| {
                        effective_res = fin;
                        finish_called = true;
                        _ = adapter.finish(effective_res);
                    },
                }
            }

            if (capped_by_results) {
                effective_res.matched_lines = replayed_matched_lines;
                effective_res.matches = replayed_matches;
                effective_res.partial = true;
                effective_res.limit_hit = .max_results;
                effective_res.scanned_all = false;
                self.incomplete.* = true;
                self.internal_stop.store(true, .release);
                handle.stop();
            }
            if (adapter.stopped_by_sink) {
                effective_res.outcome = .stopped;
                if (adapter.control() == .pause) {
                    effective_res.paused = true;
                    self.incomplete.* = true;
                }
                self.stopped_by_sink.* = true;
                self.internal_stop.store(true, .release);
                handle.stop();
            }
            if (!finish_called) {
                _ = adapter.finish(effective_res);
            }

            accumulateResult(self.summary, effective_res);

            if (self.config.search.exists and effective_res.matched_lines > 0) {
                self.internal_stop.store(true, .release);
                handle.stop();
            }
            if (self.config.search.max_results) |max_res| {
                if (self.summary.matched_lines >= max_res) {
                    self.incomplete.* = true;
                    markSummaryIncomplete(self.summary);
                    self.internal_stop.store(true, .release);
                    handle.stop();
                }
            }
            if (self.config.search.max_request_bytes) |max_req| {
                if (self.summary.bytes_read_raw >= max_req) {
                    self.incomplete.* = true;
                    markSummaryIncomplete(self.summary);
                    self.internal_stop.store(true, .release);
                    handle.stop();
                }
            }
            if (self.config.search.max_output_bytes) |max_out| {
                if (self.summary.bytes_printed >= max_out) {
                    self.incomplete.* = true;
                    markSummaryIncomplete(self.summary);
                    self.internal_stop.store(true, .release);
                    handle.stop();
                }
            }
        }
    };
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
    const user_globs = try compileUserGlobs(arena, config);

    const max_depth = config.max_depth;
    const max_entries = config.max_entries;
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
        var ran_parallel = false;
        if (config.max_concurrency > 1 and files_list.items.len > 1 and !builtin.single_threaded) {
            const req_workers: u32 = @intCast(@min(config.max_concurrency, std.math.maxInt(u32)));
            const worker_count = scheduler_mod.resolveWorkerCount(req_workers);
            if (worker_count > 1) {
                const scratches = try allocator.alloc(config_mod.Scratch, worker_count);
                for (scratches) |*sc| sc.* = config_mod.Scratch.init(allocator);
                defer {
                    for (scratches) |*sc| sc.deinit();
                    allocator.free(scratches);
                }

                const task_indices = try allocator.alloc(usize, files_list.items.len);
                defer allocator.free(task_indices);
                for (task_indices, 0..) |*slot, idx| slot.* = idx;

                state_mod.resetStats(matcher_ptr);
                const CtxType = ParallelTreeContext(SinkType, @TypeOf(matcher_ptr));
                var ctx = CtxType{
                    .allocator = allocator,
                    .io = io,
                    .sink = eff_sink,
                    .src = src,
                    .files = files_list.items,
                    .matcher_ptr = matcher_ptr,
                    .config = config,
                    .worker_count = worker_count,
                    .started_ns = started_ns,
                    .scratches = scratches,
                    .summary = &summary,
                    .incomplete = &incomplete,
                    .stopped_by_sink = &stopped_by_sink,
                };
                if (scheduler_mod.Scheduler(usize, CtxType).run(allocator, io, .{
                    .max_threads = worker_count,
                    .stop = config.search.stop,
                    .cancel = config.search.cancel,
                }, &ctx, task_indices)) |_| {
                    ran_parallel = true;
                } else |err| switch (err) {
                    error.ConcurrencyUnavailable => {
                        if (summary.searches > 0 or stopped_by_sink or incomplete) return err;
                    },
                    else => return err,
                }
            }
        }

        if (!ran_parallel) {
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

                if (!applyRemainingBudgets(&file_cfg, config.search, started_ns, &summary, &incomplete)) {
                    break;
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

const TarPrefixReader = struct {
    reader: std.Io.Reader,
    upstream: *std.Io.Reader,
    prefix: [512]u8 = undefined,
    prefix_len: usize = 0,
    prefix_pos: usize = 0,
    io_buf: [16384]u8 = undefined,

    const vtable: std.Io.Reader.VTable = .{
        .stream = streamFn,
    };

    fn streamFn(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *TarPrefixReader = @fieldParentPtr("reader", r);
        if (self.prefix_pos < self.prefix_len) {
            const avail = self.prefix[self.prefix_pos..self.prefix_len];
            const max_len = limit.minInt(avail.len);
            if (max_len == 0) return 0;
            const n = try w.write(avail[0..max_len]);
            self.prefix_pos += n;
            return n;
        }
        return self.upstream.stream(w, limit);
    }
};

const DecompIoReader = struct {
    reader: std.Io.Reader,
    decomp: *pull_mod.StreamDecompressor,
    io_buf: [16384]u8 = undefined,
    limit_hit: bool = false,
    corrupt: bool = false,

    const vtable: std.Io.Reader.VTable = .{
        .stream = streamFn,
    };

    fn streamFn(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *DecompIoReader = @fieldParentPtr("reader", r);
        if (limit.toInt()) |lim| {
            if (lim == 0) return 0;
        }
        const dest = try w.writableSliceGreedy(1);
        const max_len = limit.minInt(dest.len);
        if (max_len == 0) return 0;
        const n = self.decomp.read(dest[0..max_len]) catch |err| switch (err) {
            error.DecompressLimit => {
                self.limit_hit = true;
                return error.ReadFailed;
            },
            else => {
                self.corrupt = true;
                return error.ReadFailed;
            },
        };
        if (n == 0) return error.EndOfStream;
        w.advance(n);
        return n;
    }
};

const TarEntryReadCtx = struct {
    it: *std.tar.Iterator,
    max_filesize: ?u64 = null,
    total_read: u64 = 0,
    exceeded_filesize: bool = false,
    premature_eof: bool = false,

    fn read(raw: *anyopaque, dest: []u8) config_mod.ReadError!usize {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (self.it.unread_file_bytes == 0 or dest.len == 0) return 0;
        const want: usize = @intCast(@min(@as(u64, dest.len), self.it.unread_file_bytes));
        const n = self.it.reader.readSliceShort(dest[0..want]) catch {
            return error.ReadFailed;
        };
        if (n == 0 and self.it.unread_file_bytes > 0) {
            self.premature_eof = true;
            return error.ReadFailed;
        }
        self.it.unread_file_bytes -= n;
        self.total_read += n;
        if (self.max_filesize) |limit| {
            if (self.total_read > limit) {
                self.exceeded_filesize = true;
                return 0;
            }
        }
        return n;
    }
};

fn shouldSkipArchivePath(
    clean: []const u8,
    is_leaf_dir: bool,
    user_globs: []const glob_mod.Glob,
    root_ignore: ?*const ignore_mod.Set,
    config: TreeConfig,
    depth_exceeded: *bool,
) bool {
    var depth: usize = 0;
    var start: usize = 0;
    var scratch: [4096]u8 = undefined;

    while (start < clean.len) {
        const maybe_slash = std.mem.indexOfScalarPos(u8, clean, start, '/');
        const end = maybe_slash orelse clean.len;
        const is_component_dir = (maybe_slash != null) or is_leaf_dir;
        const seg = clean[start..end];
        const prefix = clean[0..end];

        if (depth > config.max_depth) {
            depth_exceeded.* = true;
            return true;
        }
        if (is_component_dir and config.skip_git and std.mem.eql(u8, seg, ".git")) {
            return true;
        }
        if (!config.hidden and isHiddenName(seg)) {
            return true;
        }
        if (is_component_dir and blockDirectoryByGlobs(user_globs, prefix)) {
            return true;
        }
        if (root_ignore) |ig| {
            if (ignore_mod.isIgnored(ig, prefix, is_component_dir, &scratch)) {
                return true;
            }
        }

        if (maybe_slash == null) break;
        start = end + 1;
        depth += 1;
    }
    return false;
}

/// Streams a `.tar`, `.tar.gz`/`.tgz`, `.tar.zst`, or `.tar.xz` archive in a single pass with
/// constant O(buffer_size) memory, without buffering the full archive or entries in RAM.
/// Rejects `.zip` archives with `error.UnsupportedFormat`.
/// Never accepts `std.Io.File` or `std.Io.Dir`.
pub fn searchTarStream(
    comptime S: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: *S,
    reader: *std.Io.Reader,
    matcher_ptr: anytype,
    config: TreeConfig,
) !sink_mod.Summary {
    _ = io;
    const SinkType = if (S == void) EmptySink else S;
    var empty_sink = EmptySink{};
    const eff_sink: *SinkType = if (S == void) &empty_sink else sink;

    matcher_mod.validateMatcher(@TypeOf(matcher_ptr));
    try config_mod.validateBudgets(config.search);
    if (config.archive.format == .zip) return error.UnsupportedFormat;

    const started_ns = state_mod.readClock(config.search);
    var summary: sink_mod.Summary = .{};
    var incomplete = false;
    var stopped_by_sink = false;

    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const user_globs = try compileUserGlobs(arena, config);
    var root_ignore: ?*const ignore_mod.Set = null;
    if (config.ignore_texts.len > 0) {
        var ig_list: std.ArrayList(glob_mod.Glob) = .empty;
        try ignore_mod.parseTextsInto(arena, config.ignore_texts, &ig_list, .{
            .case_insensitive = config.ignore_case_insensitive,
            .max_rules = config.max_glob_rules,
            .max_rule_len = config.max_glob_rule_len,
            .max_brace_depth = config.max_glob_brace_depth,
        });
        if (ig_list.items.len > 0) {
            const set_ptr = try arena.create(ignore_mod.Set);
            set_ptr.* = try ignore_mod.build(arena, allocator, null, 0, &.{}, ig_list.items);
            root_ignore = set_ptr;
        }
    }

    var sniff_buf: [512]u8 = undefined;
    var sniff_len: usize = 0;
    while (sniff_len < 6) {
        const rn = reader.readSliceShort(sniff_buf[sniff_len..6]) catch return error.CorruptArchive;
        if (rn == 0) break;
        sniff_len += rn;
    }

    if (sniff_len == 0) {
        const end_ns = state_mod.readClock(config.search);
        summary.elapsed = if (end_ns > started_ns) @intCast(end_ns - started_ns) else 0;
        if (@hasDecl(SinkType, "event")) {
            _ = pull_mod.eventFlow(eff_sink, .{ .summary = summary });
        }
        return summary;
    }

    if (sniff_len >= 4 and (std.mem.eql(u8, sniff_buf[0..4], "PK\x03\x04") or
        std.mem.eql(u8, sniff_buf[0..4], "PK\x05\x06") or
        std.mem.eql(u8, sniff_buf[0..4], "PK\x07\x08")))
    {
        return error.UnsupportedFormat;
    }

    const fmt: archive_mod.ArchiveFormat = if (config.archive.format != .auto)
        config.archive.format
    else blk: {
        const sniffed = decompress_mod.sniff(sniff_buf[0..sniff_len], sniff_len < 6);
        switch (sniffed) {
            .gzip => break :blk .tar_gz,
            .zstd => break :blk .tar_zst,
            .xz => break :blk .tar_xz,
            else => {
                while (sniff_len < 512) {
                    const rn = reader.readSliceShort(sniff_buf[sniff_len..512]) catch return error.CorruptArchive;
                    if (rn == 0) break;
                    sniff_len += rn;
                }
                break :blk try archive_mod.detectFormat(sniff_buf[0..sniff_len], .auto);
            },
        }
    };

    const comp_mode: config_mod.Compression = switch (fmt) {
        .tar => .none,
        .tar_gz => .gzip,
        .tar_zst => .zstd,
        .tar_xz => .xz,
        .zip => return error.UnsupportedFormat,
        .auto => unreachable,
    };

    var tar_prefix = TarPrefixReader{
        .reader = .{
            .vtable = &TarPrefixReader.vtable,
            .buffer = &.{},
            .seek = 0,
            .end = 0,
        },
        .upstream = reader,
        .prefix_len = sniff_len,
    };
    @memcpy(tar_prefix.prefix[0..sniff_len], sniff_buf[0..sniff_len]);
    tar_prefix.reader.buffer = &tar_prefix.io_buf;

    var decomp_ptr: ?*pull_mod.StreamDecompressor = null;
    defer if (decomp_ptr) |d| d.deinit();
    var decomp_io: DecompIoReader = undefined;

    if (comp_mode != .none) {
        decomp_ptr = try pull_mod.StreamDecompressor.init(
            allocator,
            &tar_prefix.reader,
            comp_mode,
            0,
            config.archive.max_total_bytes,
            config.archive.max_compression_ratio,
            null,
        );
        decomp_io = .{
            .reader = .{
                .vtable = &DecompIoReader.vtable,
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },
            .decomp = decomp_ptr.?,
        };
        decomp_io.reader.buffer = &decomp_io.io_buf;
    }

    const tar_reader: *std.Io.Reader = if (comp_mode == .none) &tar_prefix.reader else &decomp_io.reader;

    const file_name_buf = try arena.alloc(u8, 4096);
    const link_name_buf = try arena.alloc(u8, 4096);
    var diag = std.tar.Diagnostics{ .allocator = arena };
    var it = std.tar.Iterator.init(tar_reader, .{
        .file_name_buffer = file_name_buf,
        .link_name_buffer = link_name_buf,
        .diagnostics = &diag,
    });

    var scratch = config_mod.Scratch.init(allocator);
    defer scratch.deinit();

    const is_event = @hasDecl(SinkType, "event");
    var entry_count: usize = 0;
    var total_uncompressed: u64 = 0;
    var seen_entries: u64 = 0;

    state_mod.resetStats(matcher_ptr);

    while (!stopped_by_sink) {
        if (state_mod.cancelIsSet(config.search) or state_mod.flagIsSet(config.search)) {
            incomplete = true;
            markSummaryIncomplete(&summary);
            break;
        }
        if (config.search.time_budget_ns) |budget_ns| {
            const now_ns = state_mod.readClock(config.search);
            const elapsed_ns: u64 = if (now_ns > started_ns) @intCast(now_ns - started_ns) else 0;
            if (elapsed_ns >= budget_ns) {
                incomplete = true;
                markSummaryIncomplete(&summary);
                break;
            }
        }
        if (config.search.max_results) |max_res| {
            if (summary.matched_lines >= max_res) {
                incomplete = true;
                markSummaryIncomplete(&summary);
                break;
            }
        }
        if (config.search.max_request_bytes) |max_req| {
            if (summary.bytes_read_raw >= max_req) {
                incomplete = true;
                markSummaryIncomplete(&summary);
                break;
            }
        }
        if (config.search.max_output_bytes) |max_out| {
            if (summary.bytes_printed >= max_out) {
                incomplete = true;
                markSummaryIncomplete(&summary);
                break;
            }
        }

        const maybe_file = it.next() catch |err| switch (err) {
            error.PaxNullInValue, error.PaxNullInKeyword => return error.PathTraversal,
            else => {
                if (comp_mode != .none and decomp_io.limit_hit) return error.ArchiveLimit;
                return error.CorruptArchive;
            },
        };
        const file = maybe_file orelse break;

        if (file.kind == .sym_link) continue;

        const clean = (try archive_mod.sanitizeArchivePath(file.name)) orelse continue;
        const entry_kind: source_mod.Kind = switch (file.kind) {
            .directory => .directory,
            .file => .file,
            .sym_link => unreachable,
        };
        const mtime_val = archive_mod.extractTarMtime(&it.header_buffer);

        if (config.archive.entry_filter) |filter_fn| {
            const meta = archive_mod.ArchiveEntryMeta{
                .path = clean,
                .kind = entry_kind,
                .size = file.size,
                .compressed_size = file.size,
                .mtime = mtime_val,
            };
            if (!filter_fn(config.archive.entry_filter_ctx, meta)) {
                continue;
            }
        }

        entry_count += 1;
        if (entry_count > config.archive.max_entries) return error.ArchiveLimit;
        if (file.size > config.archive.max_entry_bytes) return error.ArchiveLimit;
        total_uncompressed = std.math.add(u64, total_uncompressed, file.size) catch return error.ArchiveLimit;
        if (total_uncompressed > config.archive.max_total_bytes) return error.ArchiveLimit;

        if (seen_entries >= config.max_entries) {
            incomplete = true;
            markSummaryIncomplete(&summary);
            break;
        }
        seen_entries += 1;

        var depth_exceeded = false;
        if (shouldSkipArchivePath(clean, entry_kind == .directory, user_globs, root_ignore, config, &depth_exceeded)) {
            if (depth_exceeded) {
                incomplete = true;
                markSummaryIncomplete(&summary);
            }
            continue;
        }

        if (entry_kind != .file) continue;

        if (!allowFileByGlobsAndTypes(user_globs, config, clean)) continue;
        if (config.max_filesize) |cap| {
            if (file.size > cap) continue;
        }

        if (config.files) {
            summary.searches += 1;
            summary.searches_with_match += 1;
            summary.matched_lines += 1;
            summary.matches += 1;
            if (@hasDecl(SinkType, "write")) {
                if (!eff_sink.write(clean)) {
                    stopped_by_sink = true;
                    break;
                }
            } else if (is_event) {
                if (pull_mod.eventFlow(eff_sink, .{ .begin = .{ .source_id = clean } }) != .cont) {
                    stopped_by_sink = true;
                    break;
                }
                if (pull_mod.eventFlow(eff_sink, .{ .end = .{ .source_id = clean, .matched_lines = 1, .matches = 1 } }) != .cont) {
                    stopped_by_sink = true;
                    break;
                }
            }
            continue;
        }

        var file_cfg = config.search;
        if (file_cfg.scratch_pool == null) {
            file_cfg.scratch_pool = &scratch;
        }
        if (!applyRemainingBudgets(&file_cfg, config.search, started_ns, &summary, &incomplete)) {
            break;
        }

        const effective_cfg = if (is_event) config_mod.serviceConfig(file_cfg) else file_cfg;
        var adapter = FileSinkAdapter(SinkType).init(eff_sink, clean, effective_cfg);
        var rctx = TarEntryReadCtx{
            .it = &it,
            .max_filesize = config.max_filesize,
        };

        const prev_matches = summary.matched_lines;
        const res = try pipeline_mod.drive(
            FileSinkAdapter(SinkType),
            allocator,
            &adapter,
            matcher_ptr,
            effective_cfg,
            clean,
            TarEntryReadCtx.read,
            &rctx,
        );

        if (comp_mode != .none) {
            if (decomp_io.limit_hit) return error.ArchiveLimit;
            if (decomp_io.corrupt) return error.CorruptArchive;
        }
        if (rctx.premature_eof) return error.CorruptArchive;
        if (rctx.exceeded_filesize) continue;

        accumulateResult(&summary, res);
        if (adapter.stopped_by_sink) {
            stopped_by_sink = true;
            if (adapter.control() == .pause) {
                incomplete = true;
            }
            break;
        }
        if (config.search.exists and summary.matched_lines > prev_matches) {
            break;
        }
    }

    const end_ns = state_mod.readClock(config.search);
    summary.elapsed = if (end_ns > started_ns) @intCast(end_ns - started_ns) else 0;

    if (is_event and !incomplete and !stopped_by_sink) {
        _ = pull_mod.eventFlow(eff_sink, .{ .summary = summary });
    }

    return summary;
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

fn appendLeb128(out: *std.ArrayList(u8), allocator: std.mem.Allocator, val: u64) !void {
    var v = val;
    while (true) {
        var b: u8 = @intCast(v & 0x7F);
        v >>= 7;
        if (v != 0) b |= 0x80;
        try out.append(allocator, b);
        if (v == 0) break;
    }
}

fn compressXzStoredAlloc(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    const Crc32 = std.hash.crc.@"CRC-32/ISO-HDLC";
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    // 1. Stream Header (magic + 2-byte flags check=.none + CRC32(flags))
    try out.appendSlice(allocator, &.{ 0xFD, '7', 'z', 'X', 'Z', 0x00, 0x00, 0x00 });
    var hdr_crc_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &hdr_crc_buf, Crc32.hash(&.{ 0x00, 0x00 }), .little);
    try out.appendSlice(allocator, &hdr_crc_buf);

    // 2. Single LZMA2 uncompressed block
    const block_hdr = [_]u8{ 0x02, 0x00, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00 };
    try out.appendSlice(allocator, &block_hdr);
    var bh_crc_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &bh_crc_buf, Crc32.hash(&block_hdr), .little);
    try out.appendSlice(allocator, &bh_crc_buf);

    var packed_len: u64 = 0;
    var off: usize = 0;
    while (off < payload.len) {
        const chunk_len = @min(payload.len - off, 65536);
        const enc_len: u16 = @intCast(chunk_len - 1);
        try out.append(allocator, 0x01); // uncompressed chunk, reset dict
        try out.append(allocator, @intCast(enc_len >> 8));
        try out.append(allocator, @intCast(enc_len & 0xFF));
        try out.appendSlice(allocator, payload[off .. off + chunk_len]);
        packed_len += 3 + chunk_len;
        off += chunk_len;
    }
    try out.append(allocator, 0x00); // LZMA2 end marker
    packed_len += 1;

    const blk_pad: usize = @intCast((4 - (packed_len % 4)) % 4);
    try out.appendNTimes(allocator, 0, blk_pad);

    // 3. Index (0x00 + record_count=1 + unpadded_size + uncompressed_size + pad + CRC32)
    const idx_start = out.items.len;
    try out.append(allocator, 0x00);
    try appendLeb128(&out, allocator, 1);
    try appendLeb128(&out, allocator, 12 + packed_len);
    try appendLeb128(&out, allocator, payload.len);
    const idx_raw_len = out.items.len - idx_start;
    const idx_pad = (4 - (idx_raw_len % 4)) % 4;
    try out.appendNTimes(allocator, 0, idx_pad);
    var idx_crc_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &idx_crc_buf, Crc32.hash(out.items[idx_start..]), .little);
    try out.appendSlice(allocator, &idx_crc_buf);
    const idx_total_len: u32 = @intCast(out.items.len - idx_start);

    // 4. Stream Footer (CRC32 + backward_size + flags + "YZ")
    var ftr_body: [6]u8 = undefined;
    std.mem.writeInt(u32, ftr_body[0..4], (idx_total_len / 4) - 1, .little);
    ftr_body[4] = 0x00;
    ftr_body[5] = 0x00;
    var ftr_crc_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &ftr_crc_buf, Crc32.hash(&ftr_body), .little);
    try out.appendSlice(allocator, &ftr_crc_buf);
    try out.appendSlice(allocator, &ftr_body);
    try out.appendSlice(allocator, "YZ");

    return out.toOwnedSlice(allocator);
}

test "v0.7.0: searchTree parallel Scheduler execution guarantees non-interleaved events and global budgets" {
    const alloc = std.testing.allocator;
    const Finder = @import("../finder/finder.zig").Finder;

    const num_files: usize = 64;
    var nodes: [num_files]source_mod.Node = undefined;
    var node_ptrs: [num_files]*const source_mod.Node = undefined;
    var names: [num_files][]u8 = undefined;
    var bodies: [num_files][]u8 = undefined;
    defer {
        for (0..num_files) |i| {
            alloc.free(names[i]);
            alloc.free(bodies[i]);
        }
    }

    for (0..num_files) |i| {
        names[i] = try std.fmt.allocPrint(alloc, "file_{d:02}.log", .{i});
        if (i % 2 == 0) {
            bodies[i] = try std.fmt.allocPrint(alloc, "info ok\nNEEDLE hit A in {d}\nother line\nNEEDLE hit B in {d}\n", .{ i, i });
        } else {
            bodies[i] = try std.fmt.allocPrint(alloc, "nothing interesting in file {d}\n", .{i});
        }
        nodes[i] = .{ .name = names[i], .kind = .file, .bytes = bodies[i] };
        node_ptrs[i] = &nodes[i];
    }

    const root = source_mod.Node{ .name = "", .kind = .directory, .children = &node_ptrs };
    var mem = source_mod.Memory{ .root = &root };
    const finder = try Finder.init("NEEDLE", .{});

    const StrictOrderSink = struct {
        alloc: std.mem.Allocator,
        active_source: ?[]u8 = null,
        begins: usize = 0,
        ends: usize = 0,
        matched_lines: u64 = 0,
        saw_summary: bool = false,
        interleaved: bool = false,

        pub fn event(self: *@This(), ev: sink_mod.Event) bool {
            switch (ev) {
                .begin => |b| {
                    if (self.active_source != null) self.interleaved = true;
                    self.active_source = self.alloc.dupe(u8, b.source_id) catch return false;
                    self.begins += 1;
                },
                .match => |m| {
                    if (self.active_source == null or !std.mem.eql(u8, self.active_source.?, m.source_id)) {
                        self.interleaved = true;
                    }
                    self.matched_lines += 1;
                },
                .context => |c| {
                    if (self.active_source == null or !std.mem.eql(u8, self.active_source.?, c.source_id)) {
                        self.interleaved = true;
                    }
                },
                .end => |e| {
                    if (self.active_source) |act| {
                        if (!std.mem.eql(u8, act, e.source_id)) self.interleaved = true;
                        self.alloc.free(act);
                        self.active_source = null;
                    } else {
                        self.interleaved = true;
                    }
                    self.ends += 1;
                },
                .summary => self.saw_summary = true,
                else => {},
            }
            return true;
        }

        pub fn deinit(self: *@This()) void {
            if (self.active_source) |act| self.alloc.free(act);
        }
    };

    // 1. Parallel run (max_concurrency = 4) vs sequential parity & strict non-interleaving
    var seq_sink = StrictOrderSink{ .alloc = alloc };
    defer seq_sink.deinit();
    const seq_sum = try searchTree(StrictOrderSink, alloc, std.testing.io, &seq_sink, mem.source(), "", &finder, .{
        .max_concurrency = 1,
    });

    var par_sink = StrictOrderSink{ .alloc = alloc };
    defer par_sink.deinit();
    const par_sum = try searchTree(StrictOrderSink, alloc, std.testing.io, &par_sink, mem.source(), "", &finder, .{
        .max_concurrency = 4,
    });

    try std.testing.expect(!par_sink.interleaved);
    try std.testing.expect(par_sink.saw_summary);
    try std.testing.expectEqual(@as(u64, 64), par_sum.matched_lines);
    try std.testing.expectEqual(seq_sum.matched_lines, par_sum.matched_lines);
    try std.testing.expectEqual(seq_sum.searches, par_sum.searches);
    try std.testing.expectEqual(seq_sum.searches_with_match, par_sum.searches_with_match);
    try std.testing.expectEqual(@as(usize, num_files), par_sink.begins);
    try std.testing.expectEqual(@as(usize, num_files), par_sink.ends);

    // 2. Global max_results budget respected across concurrent workers
    var cap_sink = StrictOrderSink{ .alloc = alloc };
    defer cap_sink.deinit();
    const cap_sum = try searchTree(StrictOrderSink, alloc, std.testing.io, &cap_sink, mem.source(), "", &finder, .{
        .max_concurrency = 4,
        .search = .{ .max_results = 5 },
    });
    try std.testing.expect(!cap_sink.interleaved);
    try std.testing.expect(cap_sum.matched_lines <= 5);
    try std.testing.expect(cap_sink.matched_lines <= 5);
    try std.testing.expect(!cap_sink.saw_summary);

    // 3. exists = true early stop across concurrent workers
    var ex_sink = StrictOrderSink{ .alloc = alloc };
    defer ex_sink.deinit();
    const ex_sum = try searchTree(StrictOrderSink, alloc, std.testing.io, &ex_sink, mem.source(), "", &finder, .{
        .max_concurrency = 4,
        .search = .{ .exists = true },
    });
    try std.testing.expect(!ex_sink.interleaved);
    try std.testing.expectEqual(@as(u64, 1), ex_sum.matched_lines);

    // 4. Cooperative cancel token stops immediately
    var cancel = std.atomic.Value(bool).init(true);
    var cancel_sink = StrictOrderSink{ .alloc = alloc };
    defer cancel_sink.deinit();
    const cancel_sum = try searchTree(StrictOrderSink, alloc, std.testing.io, &cancel_sink, mem.source(), "", &finder, .{
        .max_concurrency = 4,
        .search = .{ .cancel = &cancel },
    });
    try std.testing.expectEqual(@as(u64, 0), cancel_sum.searches);
    try std.testing.expect(!cancel_sink.saw_summary);
}

test "v0.7.0: searchTarStream constant-memory streaming across .tar, .tar.gz, .tar.zst, .tar.xz and adversarial guards" {
    const alloc = std.testing.allocator;
    const Finder = @import("../finder/finder.zig").Finder;
    const finder = try Finder.init("TOKEN", .{});

    const tar_bytes = try archive_mod.buildTestTarAlloc(alloc, &.{
        .{ .path = "src/keep.zig", .data = "const a = TOKEN_1;\n", .mtime = 1_718_461_330 },
        .{ .path = ".hidden/secret.zig", .data = "const h = TOKEN_HIDDEN;\n" },
        .{ .path = "link_to_etc", .kind = .symlink, .link_target = "/etc/passwd" },
        .{ .path = "notes.md", .data = "TOKEN in markdown\n" },
        .{ .path = "src/skip_filter.zig", .data = "TOKEN skipped by entry_filter\n", .mtime = 100 },
    });
    defer alloc.free(tar_bytes);

    const CollectSink = struct {
        alloc: std.mem.Allocator,
        matched_lines: u64 = 0,
        paths: std.ArrayList([]u8) = .empty,
        stop_after_first: bool = false,
        saw_summary: bool = false,

        pub fn event(self: *@This(), ev: sink_mod.Event) bool {
            switch (ev) {
                .match => |m| {
                    self.matched_lines += 1;
                    const copy = self.alloc.dupe(u8, m.source_id) catch return false;
                    self.paths.append(self.alloc, copy) catch {
                        self.alloc.free(copy);
                        return false;
                    };
                    if (self.stop_after_first) return false;
                },
                .summary => self.saw_summary = true,
                else => {},
            }
            return true;
        }

        pub fn deinit(self: *@This()) void {
            for (self.paths.items) |p| self.alloc.free(p);
            self.paths.deinit(self.alloc);
        }
    };

    const FilterCtx = struct {
        saw_mtime: bool = false,
        fn cb(raw: ?*anyopaque, meta: archive_mod.ArchiveEntryMeta) bool {
            const self: *@This() = @ptrCast(@alignCast(raw.?));
            if (std.mem.eql(u8, meta.path, "src/keep.zig") and meta.mtime == 1_718_461_330) {
                self.saw_mtime = true;
            }
            return !std.mem.endsWith(u8, meta.path, "skip_filter.zig");
        }
    };

    // 1. Plain .tar with types, mtime, symlink skip, hidden skip, and entry_filter
    {
        var r = std.Io.Reader.fixed(tar_bytes);
        var sink = CollectSink{ .alloc = alloc };
        defer sink.deinit();
        var fctx = FilterCtx{};
        const sum = try searchTarStream(CollectSink, alloc, std.testing.io, &sink, &r, &finder, .{
            .types = &.{"zig"},
            .archive = .{
                .entry_filter = FilterCtx.cb,
                .entry_filter_ctx = &fctx,
            },
        });
        try std.testing.expect(fctx.saw_mtime);
        try std.testing.expect(sink.saw_summary);
        try std.testing.expectEqual(@as(u64, 1), sum.matched_lines);
        try std.testing.expectEqual(@as(usize, 1), sink.paths.items.len);
        try std.testing.expectEqualStrings("src/keep.zig", sink.paths.items[0]);
    }

    // 2. .tar.gz
    {
        const tgz = try decompress_mod.compressGzipStoredAlloc(alloc, tar_bytes);
        defer alloc.free(tgz);
        var r = std.Io.Reader.fixed(tgz);
        var sink = CollectSink{ .alloc = alloc };
        defer sink.deinit();
        const sum = try searchTarStream(CollectSink, alloc, std.testing.io, &sink, &r, &finder, .{
            .globs = &.{"*.zig"},
        });
        try std.testing.expectEqual(@as(u64, 2), sum.matched_lines);
    }

    // 3. .tar.zst
    {
        const tzst = try decompress_mod.compressZstdRawAlloc(alloc, tar_bytes);
        defer alloc.free(tzst);
        var r = std.Io.Reader.fixed(tzst);
        var sink = CollectSink{ .alloc = alloc };
        defer sink.deinit();
        const sum = try searchTarStream(CollectSink, alloc, std.testing.io, &sink, &r, &finder, .{
            .globs = &.{"*.zig"},
        });
        try std.testing.expectEqual(@as(u64, 2), sum.matched_lines);
    }

    // 4. .tar.xz
    {
        const txz = try compressXzStoredAlloc(alloc, tar_bytes);
        defer alloc.free(txz);
        var r = std.Io.Reader.fixed(txz);
        var sink = CollectSink{ .alloc = alloc };
        defer sink.deinit();
        const sum = try searchTarStream(CollectSink, alloc, std.testing.io, &sink, &r, &finder, .{
            .globs = &.{"*.zig"},
        });
        try std.testing.expectEqual(@as(u64, 2), sum.matched_lines);
    }

    // 5. Early stop from sink
    {
        var r = std.Io.Reader.fixed(tar_bytes);
        var sink = CollectSink{ .alloc = alloc, .stop_after_first = true };
        defer sink.deinit();
        const sum = try searchTarStream(CollectSink, alloc, std.testing.io, &sink, &r, &finder, .{});
        try std.testing.expectEqual(@as(u64, 1), sum.matched_lines);
        try std.testing.expect(!sink.saw_summary);
    }

    // 6. Zip-Slip PathTraversal rejected
    {
        const bad_tar = try archive_mod.buildTestTarAlloc(alloc, &.{
            .{ .path = "../evil.txt", .data = "TOKEN\n" },
        });
        defer alloc.free(bad_tar);
        var r = std.Io.Reader.fixed(bad_tar);
        var sink = CollectSink{ .alloc = alloc };
        defer sink.deinit();
        try std.testing.expectError(
            error.PathTraversal,
            searchTarStream(CollectSink, alloc, std.testing.io, &sink, &r, &finder, .{}),
        );
    }

    // 7. Archive bomb / max_entry_bytes rejected with ArchiveLimit
    {
        var r = std.Io.Reader.fixed(tar_bytes);
        var sink = CollectSink{ .alloc = alloc };
        defer sink.deinit();
        try std.testing.expectError(
            error.ArchiveLimit,
            searchTarStream(CollectSink, alloc, std.testing.io, &sink, &r, &finder, .{
                .archive = .{ .max_entry_bytes = 8 },
            }),
        );
    }

    // 8. .zip rejected with UnsupportedFormat
    {
        const zip_bytes = try archive_mod.buildTestZipAlloc(alloc, &.{
            .{ .path = "a.txt", .data = "TOKEN\n" },
        });
        defer alloc.free(zip_bytes);
        var r = std.Io.Reader.fixed(zip_bytes);
        var sink = CollectSink{ .alloc = alloc };
        defer sink.deinit();
        try std.testing.expectError(
            error.UnsupportedFormat,
            searchTarStream(CollectSink, alloc, std.testing.io, &sink, &r, &finder, .{}),
        );
    }
}


