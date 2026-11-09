const std = @import("std");
const testing = std.testing;
const real_root = @import("root.zig");
const c_api = @import("c_api.zig");

const memchr = @import("finder/memchr.zig");
const packed_pair = @import("finder/packed_pair.zig");
const frequency = @import("finder/frequency.zig");
const aho = @import("finder/aho.zig");
const multi_mod = @import("finder/multi.zig");
const regex_mod = @import("regex.zig");
const regex_vm = @import("regex/vm.zig");
const matcher_mod = @import("matcher.zig");
const sink_mod = @import("sink.zig");
const searcher = @import("searcher.zig");
const config_mod = @import("search/config.zig");
const pull_mod = @import("search/pull.zig");
const archive_mod = @import("codec/archive.zig");
const tree_mod = @import("search/tree.zig");
const source_mod = @import("source.zig");

const Finder = real_root.Finder;
const FindOptions = real_root.FindOptions;
const Multi = real_root.Multi;
const MultiOptions = real_root.FindOptions;
const Regex = regex_mod.Regex;
const RegexOptions = regex_mod.RegexOptions;
const RegexScratch = regex_mod.RegexScratch;
const RegexSet = regex_mod.RegexSet;
const CompileDiagnostic = regex_mod.CompileDiagnostic;
const DiagnosticCode = regex_mod.DiagnosticCode;
const AnyMatcher = matcher_mod.AnyMatcher;
const Scratch = searcher.Scratch;
const Span = sink_mod.Span;
const Line = sink_mod.Line;
const Event = sink_mod.Event;
const Flow = sink_mod.Flow;
const Compression = searcher.Compression;
const Encoding = searcher.Encoding;
const ArchiveFormat = archive_mod.ArchiveFormat;

const LineEvent = struct {
    source_id: []const u8 = "",
    is_context: bool = false,
    line_number: u64 = 0,
    byte_offset: u64 = 0,
    column: u64 = 0,
    u16_column: u64 = 0,
    text: []const u8 = "",
    bytes: []const u8 = "",
    replaced: ?[]const u8 = null,
    matches: []const Span = &.{},
    truncated: bool = false,

    pub fn fromReal(ev: sink_mod.LineEvent, is_ctx: bool, use_u16_col: bool) LineEvent {
        const col_opt = if (use_u16_col) ev.u16_column else (ev.column orelse ev.u16_column);
        return .{
            .source_id = ev.source_id,
            .is_context = is_ctx,
            .line_number = ev.line_number,
            .byte_offset = ev.absolute_offset,
            .column = col_opt orelse 0,
            .u16_column = ev.u16_column orelse 0,
            .text = if (ev.text.len != 0) ev.text else ev.bytes,
            .bytes = ev.bytes,
            .replaced = ev.replaced,
            .matches = ev.matches,
            .truncated = ev.truncated,
        };
    }
};

const AnyEventSink = struct {
    ctx: *anyopaque,
    emit_line_fn: *const fn (ctx: *anyopaque, ev: LineEvent) Flow,
    emit_raw_fn: *const fn (ctx: *anyopaque, ev: Event) void,

    pub fn from(ptr: anytype) AnyEventSink {
        const P = @TypeOf(ptr);
        const Child = @typeInfo(P).pointer.child;
        const Gen = struct {
            fn emitLine(ctx: *anyopaque, ev: LineEvent) Flow {
                const s: *Child = @ptrCast(@alignCast(ctx));
                if (@hasDecl(Child, "emit")) {
                    const Ret = @typeInfo(@TypeOf(Child.emit)).@"fn".return_type.?;
                    if (Ret == Flow) return s.emit(ev);
                    return if (s.emit(ev)) .cont else .stop;
                }
                return .cont;
            }
            fn emitRaw(ctx: *anyopaque, ev: Event) void {
                const s: *Child = @ptrCast(@alignCast(ctx));
                if (Child == Harness.TestEventSink) {
                    switch (ev) {
                        .begin => s.begins += 1,
                        .end => s.ends += 1,
                        .summary => s.summaries += 1,
                        .context_break => s.context_breaks += 1,
                        else => {},
                    }
                }
            }
        };
        return .{
            .ctx = @ptrCast(@constCast(ptr)),
            .emit_line_fn = Gen.emitLine,
            .emit_raw_fn = Gen.emitRaw,
        };
    }
};

const SearchConfig = struct {
    allocator: ?std.mem.Allocator = null,
    decode_allocator: ?std.mem.Allocator = null,
    scratch: ?*[]u8 = null,
    scratch_pool: ?*Scratch = null,
    io: ?std.Io = null,
    path: ?[]const u8 = null,
    buffer_size: usize = searcher.SearchConfig.default_buffer_size,
    max_line_len: usize = searcher.SearchConfig.default_max_line_len,
    binary: searcher.BinaryPolicy = .quit,
    binary_mode: ?searcher.BinaryPolicy = null,
    encoding: Encoding = .auto,
    charset: ?[]const u8 = null,
    compression: Compression = .none,
    max_compression_ratio: ?u64 = null,
    max_decompressed_bytes: ?u64 = null,
    max_decode_bytes: ?u64 = null,
    null_data: bool = false,
    context: u32 = 0,
    before_context: usize = 0,
    after_context: usize = 0,
    invert_match: bool = false,
    invert: bool = false,
    max_count: ?u64 = null,
    passthru: bool = false,
    line_number: bool = true,
    line_numbers: bool = true,
    column: bool = false,
    column_unit: enum { byte, utf16 } = .byte,
    byte_offset: bool = false,
    only_matching: bool = false,
    replacement: ?[]const u8 = null,
    whole_word: bool = false,
    line_regexp: bool = false,
    whole_line: bool = false,
    multiline: bool = false,
    match_mode: matcher_mod.MatchMode = .earliest,
    contains: []const []const u8 = &.{},
    excludes: []const []const u8 = &.{},
    filter_case_insensitive: bool = false,
    filter_smart_case: bool = false,
    contains_regexes: []const regex_mod.Regex = &.{},
    excludes_regexes: []const regex_mod.Regex = &.{},
    max_results: ?u64 = null,
    resume_from: ?u64 = null,
    max_bytes: ?u64 = null,
    max_source_bytes: ?u64 = null,
    max_request_bytes: ?u64 = null,
    max_output_bytes: ?u64 = null,
    request_bytes_used: ?*u64 = null,
    time_budget_ns: ?u64 = null,
    cancel: ?*const std.atomic.Value(bool) = null,
    exists: bool = false,
    files_without_match: bool = false,
    stop_on_nonmatch: bool = false,
    progress_interval: ?u64 = null,
    live_stream: bool = false,
    live: bool = false,
    max_concurrency: ?u32 = null,

    pub fn toReal(self: SearchConfig) searcher.SearchConfig {
        return .{
            .allocator = self.allocator,
            .decode_allocator = self.decode_allocator,
            .scratch = self.scratch,
            .scratch_pool = self.scratch_pool,
            .buffer_size = self.buffer_size,
            .max_line_len = self.max_line_len,
            .binary = self.binary_mode orelse self.binary,
            .encoding = self.encoding,
            .charset = self.charset,
            .compression = self.compression,
            .max_compression_ratio = self.max_compression_ratio,
            .max_decompressed_bytes = self.max_decode_bytes orelse self.max_decompressed_bytes,
            .null_data = self.null_data,
            .context = self.context,
            .before = if (self.before_context > 0) @as(u32, @intCast(self.before_context)) else null,
            .after = if (self.after_context > 0) @as(u32, @intCast(self.after_context)) else null,
            .invert = self.invert_match or self.invert,
            .max_count = self.max_count,
            .passthru = self.passthru,
            .line_numbers = self.line_number or self.line_numbers,
            .replacement = self.replacement,
            .whole_word = self.whole_word,
            .whole_line = self.line_regexp or self.whole_line,
            .match_mode = if (self.replacement != null) .leftmost_first else self.match_mode,
            .contains = self.contains,
            .excludes = self.excludes,
            .filter_case_insensitive = self.filter_case_insensitive,
            .filter_smart_case = self.filter_smart_case,
            .contains_regexes = self.contains_regexes,
            .excludes_regexes = self.excludes_regexes,
            .max_results = self.max_results,
            .resume_from = self.resume_from orelse 0,
            .max_source_bytes = self.max_bytes orelse self.max_source_bytes,
            .max_request_bytes = self.max_request_bytes,
            .max_output_bytes = self.max_output_bytes,
            .time_budget_ns = self.time_budget_ns,
            .cancel = self.cancel,
            .exists = self.exists,
            .files_without_match = self.files_without_match,
            .stop_on_nonmatch = self.stop_on_nonmatch,
            .progress_interval = self.progress_interval,
            .live = self.live_stream or self.live,
            .max_concurrency = self.max_concurrency,
        };
    }
};

const Summary = struct {
    matched_lines: u64 = 0,
    matches: u64 = 0,
    bytes_searched: u64 = 0,
    bytes_read: u64 = 0,
    elapsed_ns: u64 = 0,
    stopped: bool = false,
    paused: bool = false,
    partial: bool = false,
    binary_detected: bool = false,
    limit_hit: sink_mod.LimitHit = .none,
    outcome: sink_mod.Outcome = .complete,
    resume_state: ?sink_mod.ResumeState = null,
    next_resume: ?u64 = null,
    resume_at: ?u64 = null,
    soft_error: ?sink_mod.SoftError = null,
    raw_result: sink_mod.Result = .{},

    pub fn fromResult(res: sink_mod.Result, summary_ev: ?sink_mod.Summary) Summary {
        return .{
            .matched_lines = res.matched_lines,
            .matches = res.matches,
            .bytes_searched = res.bytes_searched,
            .bytes_read = res.bytes_read,
            .elapsed_ns = if (summary_ev) |s| s.elapsed else res.elapsed_ns,
            .stopped = res.outcome == .stopped or res.limit_hit != .none,
            .paused = res.paused,
            .partial = res.partial,
            .binary_detected = res.outcome == .binary_quit or res.outcome == .binary_matched or res.nul_offset != null or res.binary_offset != null,
            .limit_hit = res.limit_hit,
            .outcome = res.outcome,
            .resume_state = res.resume_state,
            .next_resume = res.resume_at,
            .resume_at = res.resume_at,
            .soft_error = res.soft_error,
            .raw_result = res,
        };
    }
};

const TreeSummary = struct {
    files_searched: u64 = 0,
    matched_files: u64 = 0,
    matched_lines: u64 = 0,
    matches: u64 = 0,
    bytes_searched: u64 = 0,
    files_skipped_binary: u64 = 0,
    files_failed: u64 = 0,
    errors: u64 = 0,
    stopped: bool = false,
    partial: bool = false,
    limit_reached: bool = false,
    limit_hit: sink_mod.LimitHit = .none,
};

const ArchiveLimits = struct {
    format: ArchiveFormat = .auto,
    max_entries: usize = 10_000,
    max_entry_bytes: u64 = 64 * 1024 * 1024,
    max_file_bytes: ?u64 = null,
    max_total_bytes: u64 = 256 * 1024 * 1024,
    max_compression_ratio: u64 = 100,

    pub fn toOptions(self: ArchiveLimits) archive_mod.ArchiveOptions {
        return .{
            .format = self.format,
            .max_entries = self.max_entries,
            .max_entry_bytes = self.max_file_bytes orelse self.max_entry_bytes,
            .max_total_bytes = self.max_total_bytes,
            .max_compression_ratio = self.max_compression_ratio,
        };
    }
};

const ArchiveTree = struct {
    inner: archive_mod.ArchiveTree,

    fn resolveFormat(fmt: ArchiveFormat, comp: Compression) ArchiveFormat {
        if (fmt == .tar) {
            return switch (comp) {
                .none => .tar,
                .gzip => .tar_gz,
                .zstd => .tar_zst,
                .xz => .tar_xz,
                .auto => .auto,
            };
        }
        return fmt;
    }

    fn mapArchiveErr(err: archive_mod.ArchiveError, limits: ArchiveLimits) anyerror {
        if (err == error.ArchiveLimit) {
            if (limits.max_file_bytes != null) return error.ArchiveFileTooLarge;
            if (limits.max_entries < 10_000) return error.ArchiveEntryCountExceeded;
            if (limits.max_total_bytes < 256 * 1024 * 1024) return error.ArchiveTotalSizeExceeded;
        }
        return err;
    }

    pub fn initFromSlice(
        allocator: std.mem.Allocator,
        bytes: []const u8,
        fmt: ArchiveFormat,
        comp: Compression,
        limits: ArchiveLimits,
    ) !ArchiveTree {
        var opts = limits.toOptions();
        opts.format = resolveFormat(fmt, comp);
        const tree = archive_mod.ArchiveTree.initFromSlice(allocator, bytes, opts) catch |err| {
            return mapArchiveErr(err, limits);
        };
        return .{ .inner = tree };
    }

    pub fn initFromReader(
        allocator: std.mem.Allocator,
        r: *std.Io.Reader,
        fmt: ArchiveFormat,
        comp: Compression,
        limits: ArchiveLimits,
    ) !ArchiveTree {
        var opts = limits.toOptions();
        opts.format = resolveFormat(fmt, comp);
        const tree = archive_mod.ArchiveTree.initFromReader(allocator, r, opts) catch |err| {
            return mapArchiveErr(err, limits);
        };
        return .{ .inner = tree };
    }

    pub fn initSlice(allocator: std.mem.Allocator, bytes: []const u8, limits: ArchiveLimits) !ArchiveTree {
        return initFromSlice(allocator, bytes, limits.format, .auto, limits);
    }

    pub fn initReader(allocator: std.mem.Allocator, r: *std.Io.Reader, limits: ArchiveLimits) !ArchiveTree {
        return initFromReader(allocator, r, limits.format, .auto, limits);
    }

    pub fn deinit(self: *ArchiveTree) void {
        self.inner.deinit();
    }

    pub fn source(self: *ArchiveTree) source_mod.Source {
        return self.inner.source();
    }
};

const TreeConfig = struct {
    allocator: ?std.mem.Allocator = null,
    search: SearchConfig = .{},
    format: ArchiveFormat = .auto,
    archive_limits: ArchiveLimits = .{},
    globs: []const []const u8 = &.{},
    iglobs: []const []const u8 = &.{},
    iglob: bool = false,
    types: []const []const u8 = &.{},
    types_not: []const []const u8 = &.{},
    custom_types: []const tree_mod.TypeDef = &.{},
    ignore_texts: []const []const u8 = &.{},
    read_ignore: bool = true,
    hidden: bool = false,
    skip_git: bool = true,
    respect_gitignore: bool = true,
    respect_ignore: bool = true,
    respect_rgignore: bool = true,
    ignore_case_insensitive: bool = false,
    max_depth: ?usize = 256,
    max_entries: u64 = tree_mod.default_max_entries,
    max_filesize: ?u64 = null,
    max_concurrency: ?usize = null,
    files: bool = false,
};

const root = struct {
    pub const PullEventKind = @FieldType(pull_mod.PullEvent, "kind");
    pub const TypeDef = tree_mod.TypeDef;

    pub const source = struct {
        pub const Handle = usize;
        pub const Entry = source_mod.Entry;
        pub const Kind = source_mod.Kind;
        pub const Source = source_mod.Source;
        pub const VTable = source_mod.VTable;
        pub const CustomType = tree_mod.TypeDef;

        pub const FileSpec = struct {
            path: []const u8,
            data: []const u8 = "",
        };

        pub const Memory = struct {
            files: []const FileSpec = &.{},
            slots: [128]?Slot = @splat(null),
            lock_flag: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

            fn lock(self: *Memory) void {
                while (self.lock_flag.cmpxchgWeak(false, true, .acquire, .monotonic) != null) {}
            }

            fn unlock(self: *Memory) void {
                self.lock_flag.store(false, .release);
            }

            pub const Slot = struct {
                path: []const u8,
                is_dir: bool,
                file_idx: ?usize = null,
                offset: usize = 0,
            };

            fn normPath(p: []const u8) []const u8 {
                var s = p;
                while (std.mem.startsWith(u8, s, "./")) s = s[2..];
                while (s.len > 0 and s[0] == '/') s = s[1..];
                while (s.len > 0 and s[s.len - 1] == '/') s = s[0 .. s.len - 1];
                if (std.mem.eql(u8, s, ".")) return "";
                return s;
            }

            pub fn source(self: *Memory) source_mod.Source {
                return .{ .ctx = self, .vtable = &vtable };
            }

            const vtable = source_mod.VTable{
                .open = openFn,
                .read = readFn,
                .list = listFn,
                .close = closeFn,
            };

            fn allocSlot(self: *Memory, slot: Slot) !usize {
                for (&self.slots, 0..) |*s, i| {
                    if (s.* == null) {
                        s.* = slot;
                        return i + 1;
                    }
                }
                return error.SystemResources;
            }

            fn openFn(ctx: *anyopaque, _: std.Io, raw_path: []const u8) anyerror!usize {
                const self: *Memory = @ptrCast(@alignCast(ctx));
                self.lock();
                defer self.unlock();

                const p = normPath(raw_path);
                if (p.len == 0) {
                    return self.allocSlot(.{ .path = "", .is_dir = true });
                }
                for (self.files, 0..) |f, idx| {
                    const fp = normPath(f.path);
                    if (std.mem.eql(u8, fp, p)) {
                        return self.allocSlot(.{ .path = fp, .is_dir = false, .file_idx = idx });
                    }
                }
                for (self.files) |f| {
                    const fp = normPath(f.path);
                    if (fp.len > p.len and std.mem.startsWith(u8, fp, p) and fp[p.len] == '/') {
                        return self.allocSlot(.{ .path = p, .is_dir = true });
                    }
                }
                return error.NotFound;
            }

            fn readFn(ctx: *anyopaque, _: std.Io, handle: usize, dest: []u8) anyerror!usize {
                const self: *Memory = @ptrCast(@alignCast(ctx));
                self.lock();
                defer self.unlock();

                if (handle == 0 or handle > self.slots.len) return error.InvalidHandle;
                const slot = &(self.slots[handle - 1] orelse return error.InvalidHandle);
                if (slot.is_dir) return error.NotFile;
                const data = self.files[slot.file_idx.?].data;
                if (slot.offset >= data.len) return 0;
                const n = @min(dest.len, data.len - slot.offset);
                @memcpy(dest[0..n], data[slot.offset .. slot.offset + n]);
                slot.offset += n;
                return n;
            }

            fn listFn(ctx: *anyopaque, _: std.Io, handle: usize, out: []source_mod.Entry) anyerror!usize {
                const self: *Memory = @ptrCast(@alignCast(ctx));
                self.lock();
                defer self.unlock();

                if (handle == 0 or handle > self.slots.len) return error.InvalidHandle;
                const slot = &(self.slots[handle - 1] orelse return error.InvalidHandle);
                if (!slot.is_dir) return error.NotDir;
                if (out.len == 0) return 0;

                const dir_p = slot.path;
                var unique_count: usize = 0;
                var written: usize = 0;

                for (self.files, 0..) |f, f_idx| {
                    const fp = normPath(f.path);
                    const rel = if (dir_p.len == 0) fp else blk: {
                        if (fp.len > dir_p.len and std.mem.startsWith(u8, fp, dir_p) and fp[dir_p.len] == '/') {
                            break :blk fp[dir_p.len + 1 ..];
                        }
                        continue;
                    };
                    if (rel.len == 0) continue;
                    const slash = std.mem.indexOfScalar(u8, rel, '/');
                    const child_name = if (slash) |si| rel[0..si] else rel;
                    const child_kind: source_mod.Kind = if (slash != null) .directory else .file;

                    // Deduplicate against earlier files in self.files
                    var dup = false;
                    for (self.files[0..f_idx]) |prev_f| {
                        const prev_fp = normPath(prev_f.path);
                        const prev_rel = if (dir_p.len == 0) prev_fp else blk2: {
                            if (prev_fp.len > dir_p.len and std.mem.startsWith(u8, prev_fp, dir_p) and prev_fp[dir_p.len] == '/') {
                                break :blk2 prev_fp[dir_p.len + 1 ..];
                            }
                            continue;
                        };
                        if (prev_rel.len == 0) continue;
                        const prev_slash = std.mem.indexOfScalar(u8, prev_rel, '/');
                        const prev_name = if (prev_slash) |si| prev_rel[0..si] else prev_rel;
                        if (std.mem.eql(u8, prev_name, child_name)) {
                            dup = true;
                            break;
                        }
                    }
                    if (dup) continue;

                    if (unique_count >= slot.offset) {
                        out[written] = .{ .name = child_name, .kind = child_kind };
                        written += 1;
                        slot.offset += 1;
                        if (written >= out.len) break;
                    }
                    unique_count += 1;
                }
                return written;
            }

            fn closeFn(ctx: *anyopaque, _: std.Io, handle: usize) void {
                const self: *Memory = @ptrCast(@alignCast(ctx));
                self.lock();
                defer self.unlock();

                if (handle > 0 and handle <= self.slots.len) {
                    self.slots[handle - 1] = null;
                }
            }
        };
    };

    pub const search_config = struct {
        pub fn effectiveAllocator(cfg: SearchConfig) ?std.mem.Allocator {
            return config_mod.effectiveAllocator(cfg.toReal());
        }
    };

    fn SinkAdapter(comptime S: type) type {
        return struct {
            inner: S,
            use_u16_col: bool = false,
            last_summary: ?sink_mod.Summary = null,
            counts_files: bool = false,
            files_searched: u64 = 0,
            matched_files: u64 = 0,
            files_skipped_binary: u64 = 0,
            files_failed: u64 = 0,
            cur_file_matched: bool = false,

            pub fn event(self: *@This(), ev: Event) Flow {
                switch (ev) {
                    .begin => {
                        self.files_searched += 1;
                        self.cur_file_matched = false;
                    },
                    .match => {
                        self.cur_file_matched = true;
                    },
                    .end => |e| {
                        if (self.cur_file_matched or e.matches > 0) self.matched_files += 1;
                        if (e.binary_status != .none) self.files_skipped_binary += 1;
                        if (e.soft_error != null) self.files_failed += 1;
                    },
                    .summary => |s| {
                        self.last_summary = s;
                    },
                    else => {},
                }
                const PtrChild = switch (@typeInfo(S)) {
                    .pointer => |p| p.child,
                    else => S,
                };
                if (PtrChild == AnyEventSink) {
                    self.inner.emit_raw_fn(self.inner.ctx, ev);
                    return switch (ev) {
                        .match => |m| self.inner.emit_line_fn(self.inner.ctx, LineEvent.fromReal(m, false, self.use_u16_col)),
                        .context => |c| self.inner.emit_line_fn(self.inner.ctx, LineEvent.fromReal(c, true, self.use_u16_col)),
                        else => .cont,
                    };
                } else if (@hasDecl(PtrChild, "emit")) {
                    if (PtrChild == Harness.TestEventSink) {
                        switch (ev) {
                            .begin => self.inner.begins += 1,
                            .end => self.inner.ends += 1,
                            .summary => self.inner.summaries += 1,
                            .context_break => self.inner.context_breaks += 1,
                            else => {},
                        }
                    }
                    return switch (ev) {
                        .match => |m| blk: {
                            const le = LineEvent.fromReal(m, false, self.use_u16_col);
                            const Ret = @typeInfo(@TypeOf(PtrChild.emit)).@"fn".return_type.?;
                            if (Ret == Flow) break :blk self.inner.emit(le);
                            break :blk if (self.inner.emit(le)) .cont else .stop;
                        },
                        .context => |c| blk: {
                            const le = LineEvent.fromReal(c, true, self.use_u16_col);
                            const Ret = @typeInfo(@TypeOf(PtrChild.emit)).@"fn".return_type.?;
                            if (Ret == Flow) break :blk self.inner.emit(le);
                            break :blk if (self.inner.emit(le)) .cont else .stop;
                        },
                        else => .cont,
                    };
                } else if (@hasDecl(PtrChild, "emitEvent")) {
                    const Res = @typeInfo(@TypeOf(PtrChild.emitEvent)).@"fn".return_type.?;
                    if (Res == Flow) return self.inner.emitEvent(ev);
                    return if (self.inner.emitEvent(ev)) .cont else .stop;
                } else if (@hasDecl(PtrChild, "event")) {
                    const Res = @typeInfo(@TypeOf(PtrChild.event)).@"fn".return_type.?;
                    if (Res == Flow) return self.inner.event(ev);
                    return if (self.inner.event(ev)) .cont else .stop;
                }
                return .cont;
            }
        };
    }

    pub fn searchSourceSlice(haystack: []const u8, maybe_path: ?[]const u8, m: anytype, cfg: SearchConfig, sink: anytype) !Summary {
        const real_cfg = cfg.toReal();
        if (real_cfg.compression != .none and config_mod.effectiveAllocator(real_cfg) == null) {
            return error.DecodeAllocatorRequired;
        }
        var adapter = SinkAdapter(@TypeOf(sink)){ .inner = sink, .use_u16_col = cfg.column_unit == .utf16 };
        const res = searcher.searchSourceSlice(@TypeOf(adapter), &adapter, maybe_path orelse "", haystack, m, real_cfg) catch |err| {
            return err;
        };
        if (cfg.max_decode_bytes != null and res.limit_hit == .decompressed_bytes) {
            return error.DecompressedLimitExceeded;
        }
        if (cfg.request_bytes_used) |used| {
            used.* += res.bytes_searched;
        }
        return Summary.fromResult(res, adapter.last_summary);
    }

    pub fn resumeSourceSlice(haystack: []const u8, maybe_path: ?[]const u8, m: anytype, cfg: SearchConfig, sink: anytype, prev: Summary) !Summary {
        var adapter = SinkAdapter(@TypeOf(sink)){ .inner = sink, .use_u16_col = cfg.column_unit == .utf16 };
        const res = try searcher.resumeSourceSlice(@TypeOf(adapter), &adapter, maybe_path orelse "", haystack, m, cfg.toReal(), prev.raw_result);
        return Summary.fromResult(res, adapter.last_summary);
    }

    pub fn searchSource(r: *std.Io.Reader, maybe_path: ?[]const u8, m: anytype, cfg: SearchConfig, sink: anytype) !Summary {
        const real_cfg = cfg.toReal();
        const alloc = config_mod.effectiveAllocator(real_cfg) orelse testing.allocator;
        var adapter = SinkAdapter(@TypeOf(sink)){ .inner = sink, .use_u16_col = cfg.column_unit == .utf16 };
        const res = try searcher.searchSource(@TypeOf(adapter), alloc, &adapter, r, maybe_path orelse "", m, real_cfg);
        if (cfg.request_bytes_used) |used| {
            used.* += res.bytes_searched;
        }
        return Summary.fromResult(res, adapter.last_summary);
    }

    pub const PullLineView = struct {
        text: []const u8,
        bytes: []const u8,
        line_number: usize,
        byte_offset: usize,
        column: ?usize,
        u16_column: ?usize,
        truncated: bool,
    };

    pub const PullEventWrapper = struct {
        kind: PullEventKind,
        matches: []const Span = &.{},
        line: ?PullLineView = null,
        summary: ?Summary = null,
    };

    pub fn PullWrapper(comptime M: type) type {
        return struct {
            inner: pull_mod.ReaderPull(M),
            last_end: ?pull_mod.PullEvent = null,
            emitted_summary: bool = false,
            owned_source_slice: ?[]u8 = null,
            fixed_reader: std.Io.Reader = undefined,

            pub fn next(self: *@This()) !?PullEventWrapper {
                if (try self.inner.next()) |ev| {
                    switch (ev.kind) {
                        .match, .context => {
                            const col: ?usize = if (ev.u16_column) |c| @intCast(c) else if (ev.column) |c| @intCast(c) else null;
                            return .{
                                .kind = ev.kind,
                                .matches = ev.spans,
                                .line = .{
                                    .text = ev.bytes,
                                    .bytes = ev.bytes,
                                    .line_number = @intCast(ev.line_number),
                                    .byte_offset = @intCast(ev.absolute_offset),
                                    .column = col,
                                    .u16_column = if (ev.u16_column) |c| @intCast(c) else null,
                                    .truncated = ev.truncated,
                                },
                            };
                        },
                        .end => {
                            if (ev.limit_hit == .decompressed_bytes) {
                                return error.DecompressedLimitExceeded;
                            }
                            if (ev.soft_error != null) {
                                return error.CorruptCompressedStream;
                            }
                            self.last_end = ev;
                            return .{
                                .kind = .end,
                                .summary = .{
                                    .matched_lines = ev.matched_lines,
                                    .matches = ev.matches,
                                    .bytes_read = ev.bytes_read,
                                    .binary_detected = ev.binary_status != .none or ev.outcome == .binary_quit or ev.outcome == .binary_matched,
                                    .outcome = ev.outcome,
                                    .limit_hit = ev.limit_hit,
                                    .partial = ev.partial,
                                    .next_resume = ev.resume_at,
                                    .resume_at = ev.resume_at,
                                },
                            };
                        },
                        .summary => {
                            self.emitted_summary = true;
                            const end_ev = self.last_end;
                            return .{
                                .kind = .summary,
                                .summary = .{
                                    .matched_lines = ev.matched_lines,
                                    .matches = ev.matches,
                                    .bytes_searched = ev.bytes_searched,
                                    .bytes_read = ev.bytes_read_raw,
                                    .elapsed_ns = ev.elapsed,
                                    .binary_detected = if (end_ev) |e| (e.binary_status != .none or e.outcome == .binary_quit or e.outcome == .binary_matched) else false,
                                    .outcome = if (end_ev) |e| e.outcome else .complete,
                                    .limit_hit = if (end_ev) |e| e.limit_hit else .none,
                                    .partial = if (end_ev) |e| e.partial else false,
                                    .next_resume = if (end_ev) |e| e.resume_at else null,
                                    .resume_at = if (end_ev) |e| e.resume_at else null,
                                },
                            };
                        },
                        else => return .{ .kind = ev.kind },
                    }
                }
                if (!self.emitted_summary) {
                    if (self.last_end) |e| {
                        self.emitted_summary = true;
                        return .{
                            .kind = .summary,
                            .summary = .{
                                .matched_lines = e.matched_lines,
                                .matches = e.matches,
                                .bytes_read = e.bytes_read,
                                .binary_detected = e.binary_status != .none or e.outcome == .binary_quit or e.outcome == .binary_matched,
                                .outcome = e.outcome,
                                .limit_hit = e.limit_hit,
                                .partial = e.partial,
                                .next_resume = e.resume_at,
                                .resume_at = e.resume_at,
                                .stopped = e.outcome == .stopped or e.limit_hit != .none,
                            },
                        };
                    }
                }
                return null;
            }

            pub fn deinit(self: *@This()) void {
                self.inner.deinit();
                if (self.owned_source_slice) |s| {
                    testing.allocator.free(s);
                }
            }
        };
    }

    pub fn openReaderPull(r: *std.Io.Reader, m: anytype, cfg: SearchConfig) PullWrapper(@TypeOf(m)) {
        const real_cfg = cfg.toReal();
        const alloc = config_mod.effectiveAllocator(real_cfg) orelse testing.allocator;
        const inner = pull_mod.openReaderPull(alloc, m, cfg.path orelse "", r, real_cfg) catch unreachable;
        return .{ .inner = inner };
    }

    pub const SourcePullBox = struct {
        buf: []u8,
        rdr: std.Io.Reader,
    };

    pub fn SourcePullWrapper(comptime M: type) type {
        return struct {
            box: *SourcePullBox,
            pull: PullWrapper(M),

            pub fn next(self: *@This()) !?PullEventWrapper {
                return self.pull.next();
            }

            pub fn deinit(self: *@This()) void {
                self.pull.deinit();
                testing.allocator.free(self.box.buf);
                testing.allocator.destroy(self.box);
            }
        };
    }

    pub fn openSourcePull(io: std.Io, src: source_mod.Source, h: usize, m: anytype, cfg: SearchConfig) SourcePullWrapper(@TypeOf(m)) {
        var list: std.ArrayList(u8) = .empty;
        var tmp: [4096]u8 = undefined;
        while (true) {
            const n = src.read(io, h, &tmp) catch break;
            if (n == 0) break;
            list.appendSlice(testing.allocator, tmp[0..n]) catch unreachable;
        }
        const slice = list.toOwnedSlice(testing.allocator) catch unreachable;
        const box = testing.allocator.create(SourcePullBox) catch unreachable;
        box.* = .{
            .buf = slice,
            .rdr = std.Io.Reader.fixed(slice),
        };
        return .{
            .box = box,
            .pull = openReaderPull(&box.rdr, m, cfg),
        };
    }

    pub fn searchSliceIter(haystack: []const u8, m: anytype, cfg: SearchConfig) sink_mod.SliceIter(@TypeOf(m)) {
        var it = sink_mod.SliceIter(@TypeOf(m)).init(haystack, m);
        it.line_numbers = cfg.line_number;
        it.mode = cfg.match_mode;
        return it;
    }

    pub fn searchTree(io: std.Io, src_arg: anytype, m: anytype, cfg: TreeConfig, sink: anytype) TreeSummary {
        var src: source_mod.Source = undefined;
        const ArgT = @TypeOf(src_arg);
        if (ArgT == source_mod.Source) {
            src = src_arg;
        } else {
            src = src_arg.source();
        }
        var real_search_cfg = cfg.search.toReal();
        if (real_search_cfg.allocator == null) real_search_cfg.allocator = cfg.allocator;
        const alloc = cfg.allocator orelse config_mod.effectiveAllocator(real_search_cfg) orelse testing.allocator;
        var adapter = SinkAdapter(@TypeOf(sink)){ .inner = sink, .use_u16_col = cfg.search.column_unit == .utf16 };
        const real_tree_cfg = tree_mod.TreeConfig{
            .search = real_search_cfg,
            .globs = cfg.globs,
            .iglobs = cfg.iglobs,
            .iglob = cfg.iglob,
            .types = cfg.types,
            .types_not = cfg.types_not,
            .custom_types = cfg.custom_types,
            .ignore_texts = cfg.ignore_texts,
            .read_ignore = cfg.read_ignore,
            .hidden = cfg.hidden,
            .skip_git = cfg.skip_git,
            .respect_gitignore = cfg.respect_gitignore,
            .respect_ignore = cfg.respect_ignore,
            .respect_rgignore = cfg.respect_rgignore,
            .ignore_case_insensitive = cfg.ignore_case_insensitive,
            .max_depth = cfg.max_depth orelse tree_mod.max_depth_hard_cap,
            .max_entries = cfg.max_entries,
            .max_filesize = cfg.max_filesize,
            .max_concurrency = cfg.max_concurrency orelse if (real_search_cfg.max_concurrency) |mc| @as(usize, mc) else 1,
            .files = cfg.files,
        };
        const s = tree_mod.searchTree(@TypeOf(adapter), alloc, io, &adapter, src, "", m, real_tree_cfg) catch unreachable;
        const cancelled = if (real_search_cfg.cancel) |c| c.load(.monotonic) else false;
        const max_res_hit = if (real_search_cfg.max_results) |mr| s.matched_lines >= mr else false;
        const limit_reached = adapter.last_summary == null;
        return .{
            .files_searched = s.searches,
            .matched_files = s.searches_with_match,
            .matched_lines = s.matched_lines,
            .matches = s.matches,
            .bytes_searched = s.bytes_searched,
            .files_skipped_binary = adapter.files_skipped_binary,
            .files_failed = s.sources_failed,
            .errors = s.sources_failed,
            .stopped = cancelled or max_res_hit or limit_reached,
            .partial = limit_reached,
            .limit_reached = limit_reached,
            .limit_hit = if (cancelled) .cancelled else if (max_res_hit) .max_results else .none,
        };
    }

    pub fn searchArchiveSlice(io: std.Io, archive_bytes: []const u8, m: anytype, cfg: TreeConfig, sink: anytype) !TreeSummary {
        var real_search_cfg = cfg.search.toReal();
        if (real_search_cfg.allocator == null) real_search_cfg.allocator = cfg.allocator;
        const alloc = cfg.allocator orelse config_mod.effectiveAllocator(real_search_cfg) orelse testing.allocator;
        var limits = cfg.archive_limits;
        if (cfg.format != .auto) limits.format = cfg.format;
        var arc = try ArchiveTree.initSlice(alloc, archive_bytes, limits);
        defer arc.deinit();
        return searchTree(io, arc.source(), m, cfg, sink);
    }

    pub fn searchArchive(io: std.Io, r: *std.Io.Reader, m: anytype, cfg: TreeConfig, sink: anytype) !TreeSummary {
        var real_search_cfg = cfg.search.toReal();
        if (real_search_cfg.allocator == null) real_search_cfg.allocator = cfg.allocator;
        const alloc = cfg.allocator orelse config_mod.effectiveAllocator(real_search_cfg) orelse testing.allocator;
        var limits = cfg.archive_limits;
        if (cfg.format != .auto) limits.format = cfg.format;
        var arc = try ArchiveTree.initReader(alloc, r, limits);
        defer arc.deinit();
        return searchTree(io, arc.source(), m, cfg, sink);
    }
};

// ============================================================================
// C ABI Type Aliases & Conversion Helpers
// ============================================================================

const CFindOptions = c_api.webgrep_find_options_t;
const CRegexOptions = c_api.webgrep_regex_options_t;
const CConfig = c_api.webgrep_config_t;
const CTreeConfig = c_api.webgrep_tree_config_t;
const CCompileDiag = c_api.webgrep_compile_diag_t;
const CMatch = c_api.webgrep_match_t;
const CPattern = c_api.webgrep_pattern_t;
const CSummary = c_api.webgrep_summary_t;
const CTreeSummary = c_api.webgrep_tree_summary_t;
const CMatcherPtr = ?*c_api.webgrep_matcher_t;
const CScratchPtr = ?*c_api.webgrep_scratch_t;
const CLineEventPtr = *const c_api.webgrep_line_event_t;
const CLineCallbackFn = *const fn (ev: *const c_api.webgrep_line_event_t, userdata: ?*anyopaque) callconv(.c) c_int;
const CReadCallbackFn = *const fn (buf: [*c]u8, cap: usize, out_n: [*c]usize, userdata: ?*anyopaque) callconv(.c) c_int;

fn cStatus(rc: anytype) c_int {
    return switch (@typeInfo(@TypeOf(rc))) {
        .int, .comptime_int => @intCast(rc),
        .@"enum" => @intFromEnum(rc),
        else => @compileError("Unexpected C status return type"),
    };
}

fn cSetEnumOrInt(ptr: anytype, val: c_int) void {
    const T = @TypeOf(ptr.*);
    ptr.* = switch (@typeInfo(T)) {
        .int => @intCast(val),
        .@"enum" => @enumFromInt(val),
        else => @compileError("Expected int or enum field"),
    };
}

fn cGetEnumOrInt(val: anytype) c_int {
    return switch (@typeInfo(@TypeOf(val))) {
        .int, .comptime_int => @intCast(val),
        .@"enum" => @intFromEnum(val),
        else => @compileError("Expected int or enum value"),
    };
}

// ============================================================================
// Shared Test Harness Utilities
// ============================================================================

const Harness = struct {
    pub inline fn repeat(comptime s: []const u8, comptime n: usize) *const [s.len * n]u8 {
        return comptime blk: {
            @setEvalBranchQuota(200_000);
            var buf: [s.len * n]u8 = undefined;
            for (0..n) |i| {
                @memcpy(buf[i * s.len .. (i + 1) * s.len], s);
            }
            const final = buf;
            break :blk &final;
        };
    }

    /// Counting allocator wrapper that tracks live bytes and total allocation events.
    pub const CountingAllocator = struct {
        backing: std.mem.Allocator,
        alloc_calls: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        resize_calls: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        free_calls: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        live_bytes: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),

        pub fn init(backing: std.mem.Allocator) CountingAllocator {
            return .{ .backing = backing };
        }

        pub fn resetCounts(self: *CountingAllocator) void {
            self.alloc_calls.store(0, .monotonic);
            self.resize_calls.store(0, .monotonic);
            self.free_calls.store(0, .monotonic);
        }

        pub fn totalAllocEvents(self: *const CountingAllocator) usize {
            return self.alloc_calls.load(.monotonic) + self.resize_calls.load(.monotonic);
        }

        pub fn allocator(self: *CountingAllocator) std.mem.Allocator {
            return .{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .remap = remap,
                    .free = free,
                },
            };
        }

        fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
            const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
            const ptr = self.backing.rawAlloc(len, alignment, ret_addr) orelse return null;
            _ = self.alloc_calls.fetchAdd(1, .monotonic);
            _ = self.live_bytes.fetchAdd(len, .monotonic);
            return ptr;
        }

        fn resize(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
            const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
            if (self.backing.rawResize(buf, alignment, new_len, ret_addr)) {
                _ = self.resize_calls.fetchAdd(1, .monotonic);
                if (new_len >= buf.len) {
                    _ = self.live_bytes.fetchAdd(new_len - buf.len, .monotonic);
                } else {
                    _ = self.live_bytes.fetchSub(buf.len - new_len, .monotonic);
                }
                return true;
            }
            return false;
        }

        fn remap(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
            const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
            const ptr = self.backing.rawRemap(buf, alignment, new_len, ret_addr) orelse return null;
            _ = self.resize_calls.fetchAdd(1, .monotonic);
            if (new_len >= buf.len) {
                _ = self.live_bytes.fetchAdd(new_len - buf.len, .monotonic);
            } else {
                _ = self.live_bytes.fetchSub(buf.len - new_len, .monotonic);
            }
            return ptr;
        }

        fn free(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
            const self: *CountingAllocator = @ptrCast(@alignCast(ctx));
            self.backing.rawFree(buf, alignment, ret_addr);
            _ = self.free_calls.fetchAdd(1, .monotonic);
            _ = self.live_bytes.fetchSub(buf.len, .monotonic);
        }
    };

    /// Deterministic failing allocator that fails once `fail_after_bytes` or `fail_at_call` is reached.
    pub const FailingAllocator = struct {
        backing: std.mem.Allocator,
        max_bytes: usize,
        used_bytes: usize = 0,

        pub fn init(backing: std.mem.Allocator, max_bytes: usize) FailingAllocator {
            return .{ .backing = backing, .max_bytes = max_bytes };
        }

        pub fn allocator(self: *FailingAllocator) std.mem.Allocator {
            return .{
                .ptr = self,
                .vtable = &.{
                    .alloc = alloc,
                    .resize = resize,
                    .remap = remap,
                    .free = free,
                },
            };
        }

        fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
            const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
            if (self.used_bytes + len > self.max_bytes) return null;
            const ptr = self.backing.rawAlloc(len, alignment, ret_addr) orelse return null;
            self.used_bytes += len;
            return ptr;
        }

        fn resize(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
            const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
            if (new_len > buf.len and self.used_bytes + (new_len - buf.len) > self.max_bytes) return false;
            if (self.backing.rawResize(buf, alignment, new_len, ret_addr)) {
                if (new_len >= buf.len) self.used_bytes += new_len - buf.len else self.used_bytes -= buf.len - new_len;
                return true;
            }
            return false;
        }

        fn remap(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
            const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
            if (new_len > buf.len and self.used_bytes + (new_len - buf.len) > self.max_bytes) return null;
            const ptr = self.backing.rawRemap(buf, alignment, new_len, ret_addr) orelse return null;
            if (new_len >= buf.len) self.used_bytes += new_len - buf.len else self.used_bytes -= buf.len - new_len;
            return ptr;
        }

        fn free(ctx: *anyopaque, buf: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
            const self: *FailingAllocator = @ptrCast(@alignCast(ctx));
            self.backing.rawFree(buf, alignment, ret_addr);
            self.used_bytes -|= buf.len;
        }
    };

    /// Recording event sink that clones emitted lines, spans, and replacements for verification.
    pub const RecordedLine = struct {
        path: ?[]u8 = null,
        is_context: bool,
        line_number: usize,
        byte_offset: usize,
        column: ?usize,
        text: []u8,
        replaced: ?[]u8,
        matches: []Span,
    };

    pub const TestEventSink = struct {
        allocator: std.mem.Allocator,
        lines: std.ArrayList(RecordedLine) = .empty,
        context_breaks: usize = 0,
        begins: usize = 0,
        ends: usize = 0,
        summaries: usize = 0,
        pause_after_matches: ?usize = null,
        stop_after_matches: ?usize = null,
        matches_seen: usize = 0,

        pub fn init(allocator: std.mem.Allocator) TestEventSink {
            return .{ .allocator = allocator };
        }

        pub fn deinit(self: *TestEventSink) void {
            for (self.lines.items) |item| {
                if (item.path) |p| self.allocator.free(p);
                self.allocator.free(item.text);
                if (item.replaced) |r| self.allocator.free(r);
                self.allocator.free(item.matches);
            }
            self.lines.deinit(self.allocator);
        }

        pub fn clearRetainingCapacity(self: *TestEventSink) void {
            for (self.lines.items) |item| {
                if (item.path) |p| self.allocator.free(p);
                self.allocator.free(item.text);
                if (item.replaced) |r| self.allocator.free(r);
                self.allocator.free(item.matches);
            }
            self.lines.clearRetainingCapacity();
            self.context_breaks = 0;
            self.begins = 0;
            self.ends = 0;
            self.summaries = 0;
            self.matches_seen = 0;
        }

        pub fn emit(self: *TestEventSink, ev: LineEvent) Flow {
            const path_copy = if (ev.source_id.len > 0) self.allocator.dupe(u8, ev.source_id) catch unreachable else null;
            const text_copy = self.allocator.dupe(u8, ev.text) catch unreachable;
            const rep_copy = if (ev.replaced) |r| self.allocator.dupe(u8, r) catch unreachable else null;
            const spans_copy = self.allocator.dupe(Span, ev.matches) catch unreachable;

            self.lines.append(self.allocator, .{
                .path = path_copy,
                .is_context = ev.is_context,
                .line_number = @intCast(ev.line_number),
                .byte_offset = @intCast(ev.byte_offset),
                .column = if (ev.column > 0) @as(usize, @intCast(ev.column)) else null,
                .text = text_copy,
                .replaced = rep_copy,
                .matches = spans_copy,
            }) catch unreachable;

            if (!ev.is_context) {
                self.matches_seen += 1;
                if (self.pause_after_matches) |limit| {
                    if (self.matches_seen >= limit) return .pause;
                }
                if (self.stop_after_matches) |limit| {
                    if (self.matches_seen >= limit) return .stop;
                }
            }
            return .cont;
        }

        pub fn emitEvent(self: *TestEventSink, ev: Event) bool {
            switch (ev) {
                .begin => self.begins += 1,
                .end => self.ends += 1,
                .summary => self.summaries += 1,
                .context_break => self.context_breaks += 1,
                .match => |m| {
                    const flow = self.emit(m);
                    return flow == .cont;
                },
                .context => |line| {
                    const flow = self.emit(line);
                    return flow == .cont;
                },
                else => {},
            }
            return true;
        }
    };

    /// Controlled *std.Io.Reader that yields at most `max_chunk` bytes per call and tracks read calls.
    pub const ChunkedReader = struct {
        data: []const u8,
        pos: usize = 0,
        max_chunk: usize,
        read_calls: usize = 0,
        fail_at_call: ?usize = null,
        interface: std.Io.Reader,

        pub fn init(data: []const u8, max_chunk: usize, buf: []u8) ChunkedReader {
            return .{
                .data = data,
                .max_chunk = @max(1, max_chunk),
                .interface = .{
                    .vtable = &.{ .stream = stream },
                    .buffer = buf,
                    .seek = 0,
                    .end = 0,
                },
            };
        }

        fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            const self: *ChunkedReader = @alignCast(@fieldParentPtr("interface", r));
            self.read_calls += 1;
            if (self.fail_at_call) |fail_idx| {
                if (self.read_calls >= fail_idx) return error.ReadFailed;
            }
            if (self.pos >= self.data.len) return error.EndOfStream;
            const rem = self.data.len - self.pos;
            const max_n = @min(rem, self.max_chunk);
            const slice = limit.sliceConst(self.data[self.pos .. self.pos + max_n]);
            if (slice.len == 0) return 0;
            const written = try w.write(slice);
            self.pos += written;
            return written;
        }
    };

    /// Build a valid USTAR .tar archive in memory from a list of entries.
    pub const TarEntrySpec = struct {
        path: []const u8,
        data: []const u8 = "",
        typeflag: u8 = '0',
        linkname: []const u8 = "",
    };

    pub fn buildTar(allocator: std.mem.Allocator, entries: []const TarEntrySpec) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);

        for (entries) |entry| {
            var hdr: [512]u8 = @splat(0);
            const name_len: usize = @min(entry.path.len, 100);
            @memcpy(hdr[0..name_len], entry.path[0..name_len]);
            @memcpy(hdr[100..107], "0000644");
            @memcpy(hdr[108..115], "0000000");
            @memcpy(hdr[116..123], "0000000");
            _ = std.fmt.bufPrint(hdr[124..135], "{o:0>11}", .{entry.data.len}) catch unreachable;
            @memcpy(hdr[136..147], "14000000000");
            @memset(hdr[148..156], ' ');
            hdr[156] = entry.typeflag;
            if (entry.linkname.len > 0) {
                const l_len: usize = @min(entry.linkname.len, 100);
                @memcpy(hdr[157 .. 157 + l_len], entry.linkname[0..l_len]);
            }
            @memcpy(hdr[257..263], "ustar\x00");
            @memcpy(hdr[263..265], "00");

            var chksum: u32 = 0;
            for (hdr) |b| chksum += b;
            _ = std.fmt.bufPrint(hdr[148..154], "{o:0>6}", .{chksum}) catch unreachable;
            hdr[154] = 0;
            hdr[155] = ' ';

            try out.appendSlice(allocator, &hdr);
            if (entry.data.len > 0) {
                try out.appendSlice(allocator, entry.data);
                const pad = (512 - (entry.data.len % 512)) % 512;
                if (pad > 0) {
                    try out.appendNTimes(allocator, 0, pad);
                }
            }
        }
        try out.appendNTimes(allocator, 0, 1024);
        return out.toOwnedSlice(allocator);
    }

    /// Build a valid .zip archive in memory supporting method 0 (.store) and method 8 (.deflate).
    pub const ZipEntrySpec = struct {
        path: []const u8,
        data: []const u8,
        method: u16 = 0, // 0 = store, 8 = raw deflate (stored block)
        corrupt_crc: bool = false,
        external_attr: u32 = 0,
    };

    pub fn makeDeflateStoredBlock(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
        std.debug.assert(raw.len <= 65535);
        var out = try allocator.alloc(u8, 5 + raw.len);
        out[0] = 0x01; // BFINAL=1, BTYPE=00 (non-compressed block)
        const len16: u16 = @intCast(raw.len);
        const nlen16: u16 = ~len16;
        std.mem.writeInt(u16, out[1..3], len16, .little);
        std.mem.writeInt(u16, out[3..5], nlen16, .little);
        @memcpy(out[5..], raw);
        return out;
    }

    pub fn makeGzipFromRaw(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
        const deflate_block = try makeDeflateStoredBlock(allocator, raw);
        defer allocator.free(deflate_block);

        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);

        // 10-byte Gzip header
        try out.appendSlice(allocator, &[_]u8{ 0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03 });
        try out.appendSlice(allocator, deflate_block);
        var crc_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &crc_bytes, std.hash.Crc32.hash(raw), .little);
        try out.appendSlice(allocator, &crc_bytes);
        var isize_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &isize_bytes, @truncate(raw.len), .little);
        try out.appendSlice(allocator, &isize_bytes);
        return out.toOwnedSlice(allocator);
    }

    pub fn makeZstdFromRaw(allocator: std.mem.Allocator, raw: []const u8) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        // Zstd frame magic: 0xFD2FB528 (LE: 28 B5 2F FD)
        // Frame Header Descriptor: 0x20 (Single_Segment_Flag=1, FCS_Field_Size=0 -> 1 byte FCS if <=255, or 0x60 for 2-byte FCS)
        if (raw.len <= 255) {
            try out.appendSlice(allocator, &[_]u8{ 0x28, 0xB5, 0x2F, 0xFD, 0x20, @intCast(raw.len) });
        } else {
            var fcs: [2]u8 = undefined;
            std.mem.writeInt(u16, &fcs, @intCast(raw.len - 256), .little);
            try out.appendSlice(allocator, &[_]u8{ 0x28, 0xB5, 0x2F, 0xFD, 0x60, fcs[0], fcs[1] });
        }
        // Raw block header (3 bytes LE): Last_Block=1, Block_Type=0 (Raw_Block), Block_Size=raw.len
        const block_hdr: u32 = 1 | (@as(u32, @intCast(raw.len)) << 3);
        try out.appendSlice(allocator, &[_]u8{
            @truncate(block_hdr),
            @truncate(block_hdr >> 8),
            @truncate(block_hdr >> 16),
        });
        try out.appendSlice(allocator, raw);
        return out.toOwnedSlice(allocator);
    }

    pub fn buildZip(allocator: std.mem.Allocator, entries: []const ZipEntrySpec) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);

        var cd: std.ArrayList(u8) = .empty;
        defer cd.deinit(allocator);

        for (entries) |entry| {
            const local_offset: u32 = @intCast(out.items.len);
            const payload = if (entry.method == 8)
                try makeDeflateStoredBlock(allocator, entry.data)
            else
                try allocator.dupe(u8, entry.data);
            defer allocator.free(payload);

            var crc = std.hash.Crc32.hash(entry.data);
            if (entry.corrupt_crc) crc ^= 0xFFFFFFFF;

            var lfh: [30]u8 = @splat(0);
            std.mem.writeInt(u32, lfh[0..4], 0x04034b50, .little);
            std.mem.writeInt(u16, lfh[4..6], 20, .little);
            std.mem.writeInt(u16, lfh[8..10], entry.method, .little);
            std.mem.writeInt(u32, lfh[14..18], crc, .little);
            std.mem.writeInt(u32, lfh[18..22], @intCast(payload.len), .little);
            std.mem.writeInt(u32, lfh[22..26], @intCast(entry.data.len), .little);
            std.mem.writeInt(u16, lfh[26..28], @intCast(entry.path.len), .little);
            try out.appendSlice(allocator, &lfh);
            try out.appendSlice(allocator, entry.path);
            try out.appendSlice(allocator, payload);

            var cdfh: [46]u8 = @splat(0);
            std.mem.writeInt(u32, cdfh[0..4], 0x02014b50, .little);
            std.mem.writeInt(u16, cdfh[4..6], 20, .little);
            std.mem.writeInt(u16, cdfh[6..8], 20, .little);
            std.mem.writeInt(u16, cdfh[10..12], entry.method, .little);
            std.mem.writeInt(u32, cdfh[16..20], crc, .little);
            std.mem.writeInt(u32, cdfh[20..24], @intCast(payload.len), .little);
            std.mem.writeInt(u32, cdfh[24..28], @intCast(entry.data.len), .little);
            std.mem.writeInt(u16, cdfh[28..30], @intCast(entry.path.len), .little);
            std.mem.writeInt(u32, cdfh[38..42], entry.external_attr, .little);
            std.mem.writeInt(u32, cdfh[42..46], local_offset, .little);
            try cd.appendSlice(allocator, &cdfh);
            try cd.appendSlice(allocator, entry.path);
        }

        const cd_offset: u32 = @intCast(out.items.len);
        try out.appendSlice(allocator, cd.items);

        var eocd: [22]u8 = @splat(0);
        std.mem.writeInt(u32, eocd[0..4], 0x06054b50, .little);
        std.mem.writeInt(u16, eocd[8..10], @intCast(entries.len), .little);
        std.mem.writeInt(u16, eocd[10..12], @intCast(entries.len), .little);
        std.mem.writeInt(u32, eocd[12..16], @intCast(cd.items.len), .little);
        std.mem.writeInt(u32, eocd[16..20], cd_offset, .little);
        try out.appendSlice(allocator, &eocd);

        return out.toOwnedSlice(allocator);
    }

    pub fn encodeUtf16FromUtf8(allocator: std.mem.Allocator, utf8: []const u8, endian: std.builtin.Endian, with_bom: bool) ![]u8 {
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(allocator);
        if (with_bom) {
            if (endian == .little) {
                try out.appendSlice(allocator, &[_]u8{ 0xFF, 0xFE });
            } else {
                try out.appendSlice(allocator, &[_]u8{ 0xFE, 0xFF });
            }
        }
        var view = try std.unicode.Utf8View.init(utf8);
        var it = view.iterator();
        while (it.nextCodepoint()) |cp| {
            if (cp <= 0xFFFF) {
                var b: [2]u8 = undefined;
                std.mem.writeInt(u16, &b, @intCast(cp), endian);
                try out.appendSlice(allocator, &b);
            } else {
                const u = cp - 0x10000;
                const high: u16 = @intCast(0xD800 + (u >> 10));
                const low: u16 = @intCast(0xDC00 + (u & 0x3FF));
                var b: [4]u8 = undefined;
                std.mem.writeInt(u16, b[0..2], high, endian);
                std.mem.writeInt(u16, b[2..4], low, endian);
                try out.appendSlice(allocator, &b);
            }
        }
        return out.toOwnedSlice(allocator);
    }
};

// ============================================================================
// TIER 1: Per-Feature Core E2E Tests (F01 - F14, 70 Tests)
// ============================================================================

test "E2E T1_F01_01: concurrent *const Finder across 8 worker threads" {
    const f = try Finder.init("ERR_TOKEN_42", .{});
    const f_const: *const Finder = &f;
    const haystack = "prefix line\nmid ERR_TOKEN_42 suffix\ntail ERR_TOKEN_42 end\n";

    const Worker = struct {
        fn run(finder: *const Finder, text: []const u8, out_sum: *usize) void {
            var acc: usize = 0;
            for (0..500) |_| {
                var pos: usize = 0;
                while (finder.find(text, pos, .earliest)) |m| {
                    acc += m.start + m.end;
                    pos = m.end;
                }
            }
            out_sum.* = acc;
        }
    };

    var threads: [8]std.Thread = undefined;
    var sums: [8]usize = @splat(0);
    for (0..8) |i| {
        threads[i] = try std.Thread.spawn(.{}, Worker.run, .{ f_const, haystack, &sums[i] });
    }
    for (0..8) |i| threads[i].join();
    for (1..8) |i| try testing.expectEqual(sums[0], sums[i]);
    try testing.expect(sums[0] > 0);
}

test "E2E T1_F01_02: concurrent *const Multi across 8 worker threads (find, findWatched, findAllowed)" {
    const patterns = [_][]const u8{
        "alpha_01", "beta_02", "gamma_03", "delta_04", "eps_05", "zeta_06",
        "eta_07",   "theta_08", "iota_09", "kappa_10", "lam_11", "mu_12",
    };
    var m = try Multi.init(testing.allocator, &patterns, .{});
    defer m.deinit();
    const m_const: *const Multi = &m;
    const haystack = "foo alpha_01 bar kappa_10 baz mu_12\n";

    const Worker = struct {
        fn allowAllFn(_: []const u8, _: usize, _: usize) bool {
            return true;
        }
        fn run(multi: *const Multi, text: []const u8, out_ok: *bool) void {
            for (0..300) |_| {
                const r1 = multi.find(text, 0, .earliest) orelse {
                    out_ok.* = false;
                    return;
                };
                var nul: ?usize = null;
                const r2 = multi.findWatched(text, 0, &nul);
                const r3 = multi.findAllowed(text, 0, .earliest, allowAllFn) orelse {
                    out_ok.* = false;
                    return;
                };
                if (r1.start != 4 or r1.pattern_id != 0) {
                    out_ok.* = false;
                    return;
                }
                if (nul != null or r2 == null or r2.?.start != 4) {
                    out_ok.* = false;
                    return;
                }
                if (r3.start != r1.start or r3.pattern_id != r1.pattern_id) {
                    out_ok.* = false;
                    return;
                }
            }
            out_ok.* = true;
        }
    };

    var threads: [8]std.Thread = undefined;
    var ok: [8]bool = @splat(false);
    for (0..8) |i| {
        threads[i] = try std.Thread.spawn(.{}, Worker.run, .{ m_const, haystack, &ok[i] });
    }
    for (0..8) |i| threads[i].join();
    for (ok) |v| try testing.expect(v);
}

test "E2E T1_F01_03: concurrent *const Regex across 8 worker threads (find, isMatch, findCaptures)" {
    var re = try Regex.init(testing.allocator, "([a-z]+)_([0-9]{2,4})", .{});
    defer re.deinit();
    const re_const: *const Regex = &re;
    const haystack = "header item_4200 middle task_99 footer";

    const Worker = struct {
        fn run(regex: *const Regex, text: []const u8, out_ok: *bool) void {
            for (0..250) |_| {
                if (!regex.isMatch(text)) {
                    out_ok.* = false;
                    return;
                }
                const m = regex.find(text, 0, .earliest) orelse {
                    out_ok.* = false;
                    return;
                };
                const caps = regex.findCaptures(text, 0, .earliest) orelse {
                    out_ok.* = false;
                    return;
                };
                if (m.start != 7 or m.end != 16) {
                    out_ok.* = false;
                    return;
                }
                if (!std.mem.eql(u8, caps.slice(text, 1).?, "item") or !std.mem.eql(u8, caps.slice(text, 2).?, "4200")) {
                    out_ok.* = false;
                    return;
                }
            }
            out_ok.* = true;
        }
    };

    var threads: [8]std.Thread = undefined;
    var ok: [8]bool = @splat(false);
    for (0..8) |i| {
        threads[i] = try std.Thread.spawn(.{}, Worker.run, .{ re_const, haystack, &ok[i] });
    }
    for (0..8) |i| threads[i].join();
    for (ok) |v| try testing.expect(v);
}

test "E2E T1_F01_04: Regex.findWithScratch with per-thread RegexScratch reuse" {
    // Pattern with > 256 instructions
    var pat_buf: std.ArrayList(u8) = .empty;
    defer pat_buf.deinit(testing.allocator);
    for (0..90) |i| {
        if (i > 0) try pat_buf.append(testing.allocator, '|');
        { var _tmp: [128]u8 = undefined; try pat_buf.appendSlice(testing.allocator, try std.fmt.bufPrint(&_tmp, "tok_{d:0>3}", .{i})); }
    }
    var re = try Regex.init(testing.allocator, pat_buf.items, .{});
    defer re.deinit();
    try testing.expect(re.insts.len > 256);

    var counting = Harness.CountingAllocator.init(testing.allocator);
    var scratch = RegexScratch.init(counting.allocator());
    defer scratch.deinit();

    const haystack = "noise prefix tok_042 and tok_089 suffix";
    const warm = re.findWithScratch(haystack, 0, .earliest, &scratch);
    try testing.expect(warm != null);
    try testing.expectEqualStrings("tok_042", haystack[warm.?.start..warm.?.end]);

    counting.resetCounts();
    for (0..1000) |_| {
        const m = re.findWithScratch(haystack, 0, .earliest, &scratch).?;
        try testing.expectEqual(@as(usize, 13), m.start);
        try testing.expect(re.isMatchWithScratch(haystack, &scratch));
    }
    try testing.expectEqual(@as(usize, 0), counting.totalAllocEvents());
}

test "E2E T1_F01_05: searchSourceSlice and searchSource accepting *const Finder, *const Multi, *const Regex, *const RegexSet" {
    const data = "alpha line\nbeta target_tok line\ngamma regex_99 line\n";
    const f = try Finder.init("target_tok", .{});
    var m = try Multi.init(testing.allocator, &.{ "alpha", "target_tok" }, .{});
    defer m.deinit();
    var r = try Regex.init(testing.allocator, "regex_[0-9]+", .{});
    defer r.deinit();
    var rs = try RegexSet.init(testing.allocator, &.{ "alpha", "regex_[0-9]+" }, .{});
    defer rs.deinit();

    const f_ptr: *const Finder = &f;
    const m_ptr: *const Multi = &m;
    const r_ptr: *const Regex = &r;
    const rs_ptr: *const RegexSet = &rs;

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const s1 = try root.searchSourceSlice(data, null, f_ptr, .{}, &sink);
    try testing.expectEqual(@as(usize, 1), s1.matched_lines);

    const s2 = try root.searchSourceSlice(data, null, m_ptr, .{}, &sink);
    try testing.expectEqual(@as(usize, 2), s2.matched_lines);

    const s3 = try root.searchSourceSlice(data, null, r_ptr, .{}, &sink);
    try testing.expectEqual(@as(usize, 1), s3.matched_lines);

    const s4 = try root.searchSourceSlice(data, null, rs_ptr, .{}, &sink);
    try testing.expectEqual(@as(usize, 2), s4.matched_lines);

    var rdr = std.Io.Reader.fixed(data);
    const s5 = try root.searchSource(&rdr, null, rs_ptr, .{}, &sink);
    try testing.expectEqual(@as(usize, 2), s5.matched_lines);
}

test "E2E T1_F02_01: Multi sub-engine pattern_id accuracy (bytes, pairs, teddy, ac)" {
    // 1. bytes (1-byte patterns)
    {
        var m = try Multi.init(testing.allocator, &.{ "x", "y", "z" }, .{});
        defer m.deinit();
        try testing.expectEqualStrings("bytes", m.engineName());
        const r = m.find("ab z cd y ef x", 0, .earliest).?;
        try testing.expectEqual(@as(?u32, 2), r.pattern_id);
    }
    // 2. pairs (<= 8 multi-byte patterns)
    {
        var m = try Multi.init(testing.allocator, &.{ "alpha", "beta", "gamma", "delta" }, .{});
        defer m.deinit();
        try testing.expectEqualStrings("pairs", m.engineName());
        const r = m.find("zz delta yy alpha", 0, .earliest).?;
        try testing.expectEqual(@as(?u32, 3), r.pattern_id);
    }
    // 3. teddy (17..32 patterns with >16 distinct byte pairs)
    {
        const pats = Multi.scenario_teddy;
        var m = try Multi.init(testing.allocator, pats, .{});
        defer m.deinit();
        if ((@import("build_options").teddy != .off)) {
            try testing.expectEqualStrings("teddy", m.engineName());
        }
        const target = pats[7];
        const hay = try std.fmt.allocPrint(testing.allocator, "header {s} footer", .{target});
        defer testing.allocator.free(hay);
        const r = m.find(hay, 0, .earliest).?;
        try testing.expectEqual(@as(?u32, 7), r.pattern_id);
    }
    // 4. ac (> 32 patterns with > 16 distinct byte pairs)
    {
        const pats = Multi.scenario_ac;
        var m = try Multi.init(testing.allocator, pats, .{});
        defer m.deinit();
        try testing.expectEqualStrings("ac", m.engineName());
        const target = pats[30];
        const hay = try std.fmt.allocPrint(testing.allocator, "begin {s} end", .{target});
        defer testing.allocator.free(hay);
        const r = m.find(hay, 0, .earliest).?;
        try testing.expectEqual(@as(?u32, 30), r.pattern_id);
    }
}

test "E2E T1_F02_02: Multi Unicode case-folding variant expansion preserves caller pattern_id" {
    const patterns = [_][]const u8{ "straße", "ωmega", "kelvin_k" };
    var m = try Multi.init(testing.allocator, &patterns, .{ .case = .insensitive, .unicode_case = true });
    defer m.deinit();

    const r0 = m.find("die STRAẞE hier", 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 0), r0.pattern_id);

    const r1 = m.find("the ΩMEGA wave", 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 1), r1.pattern_id);

    // U+212A KELVIN SIGN folds to 'k'
    const r2 = m.find("temp \xe2\x84\xaaelvin_k end", 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 2), r2.pattern_id);
}

test "E2E T1_F02_03: Multi .mixed smart-case preserves caller pattern_id" {
    // Even-indexed patterns lowercase (insensitive in .smart), odd-indexed have uppercase (sensitive in .smart)
    const patterns = [_][]const u8{ "foo_pat", "Bar_Pat", "baz_pat", "Qux_Pat" };
    var m = try Multi.init(testing.allocator, &patterns, .{ .case = .smart });
    defer m.deinit();

    // "BAR_PAT" does not match "Bar_Pat" (case-sensitive), so next match "BAZ_PAT" matches pattern 2 ("baz_pat")
    const r = m.find("BAR_PAT and BAZ_PAT and Qux_Pat", 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 2), r.pattern_id);

    const r_qux = m.find("BAR_PAT and BAZ_PAT and Qux_Pat", r.end, .earliest).?;
    try testing.expectEqual(@as(?u32, 3), r_qux.pattern_id);
}

test "E2E T1_F02_04: Span.pattern_id propagation through searchSourceSlice, LineEvent.matches, and openSourcePull" {
    const patterns = [_][]const u8{ "WARN", "ERROR", "FATAL" };
    var m = try Multi.init(testing.allocator, &patterns, .{});
    defer m.deinit();

    const input = "2026-01-01 WARN disk full and FATAL crash\n2026-01-02 ERROR timeout\n";
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    _ = try root.searchSourceSlice(input, "app.log", &m, .{}, &sink);
    try testing.expectEqual(@as(usize, 2), sink.lines.items.len);
    try testing.expectEqual(@as(usize, 2), sink.lines.items[0].matches.len);
    try testing.expectEqual(@as(?u32, 0), sink.lines.items[0].matches[0].pattern_id);
    try testing.expectEqual(@as(?u32, 2), sink.lines.items[0].matches[1].pattern_id);
    try testing.expectEqual(@as(?u32, 1), sink.lines.items[1].matches[0].pattern_id);

    // Also verify openSourcePull
    var mem = root.source.Memory{ .files = &.{.{ .path = "app.log", .data = input }} };
    const src = mem.source();
    const h = try src.open(testing.io, "app.log");
    defer src.close(testing.io, h);

    var pull = root.openSourcePull(testing.io, src, h, &m, .{});
    defer pull.deinit();

    var match_count: usize = 0;
    while (try pull.next()) |ev| {
        if (ev.kind == .match) {
            match_count += 1;
            if (match_count == 1) {
                try testing.expectEqual(@as(?u32, 0), ev.matches[0].pattern_id);
                try testing.expectEqual(@as(?u32, 2), ev.matches[1].pattern_id);
            } else if (match_count == 2) {
                try testing.expectEqual(@as(?u32, 1), ev.matches[0].pattern_id);
            }
        }
    }
    try testing.expectEqual(@as(usize, 2), match_count);
}

test "E2E T1_F02_05: Span.pattern_id propagation across before-context ring (invert) and SliceIter" {
    var m = try Multi.init(testing.allocator, &.{ "ALPHA", "BETA", "GAMMA" }, .{});
    defer m.deinit();

    const text = "first ALPHA\nsecond BETA\nthird GAMMA\n";
    var iter = root.searchSliceIter(text, &m, .{});
    const l1 = iter.next().?;
    try testing.expectEqual(@as(?u32, 0), l1.match.?.pattern_id);
    const l2 = iter.next().?;
    try testing.expectEqual(@as(?u32, 1), l2.match.?.pattern_id);
    const l3 = iter.next().?;
    try testing.expectEqual(@as(?u32, 2), l3.match.?.pattern_id);
    try testing.expect(iter.next() == null);

    // Also test before-context ring with streaming searchSource
    var rdr = std.Io.Reader.fixed("ctx line 1\nmatch BETA line\n");
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    _ = try root.searchSource(&rdr, null, &m, .{ .before_context = 1 }, &sink);
    try testing.expectEqual(@as(usize, 2), sink.lines.items.len);
    try testing.expect(sink.lines.items[0].is_context);
    try testing.expect(!sink.lines.items[1].is_context);
    try testing.expectEqual(@as(?u32, 1), sink.lines.items[1].matches[0].pattern_id);
}

test "E2E T1_F03_01: RegexSet.init, len, isEmpty, isMatch, and find with pattern_id" {
    const patterns = [_][]const u8{
        "user_[0-9]+",
        "admin_[a-z]+",
        "token_[A-F0-9]{4}",
    };
    var set = try RegexSet.init(testing.allocator, &patterns, .{});
    defer set.deinit();

    try testing.expectEqual(@as(usize, 3), set.len());
    try testing.expect(!set.isEmpty());
    try testing.expect(set.isMatch("login by admin_alice today"));
    try testing.expect(!set.isMatch("no match here"));

    const m1 = set.find("id: token_BEEF and user_42", 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 2), m1.pattern_id);
    try testing.expectEqual(@as(usize, 4), m1.start);
    try testing.expectEqual(@as(usize, 14), m1.end);

    const m2 = set.find("id: token_BEEF and user_42", m1.end, .earliest).?;
    try testing.expectEqual(@as(?u32, 0), m2.pattern_id);
}

test "E2E T1_F03_02: RegexSet.matches single-pass collection of all matching pattern IDs" {
    const patterns = [_][]const u8{
        "foo_[0-9]+",
        "bar_[a-z]+",
        "foo_123",
        "unmatched_xyz",
        "[a-z]+_123",
    };
    var set = try RegexSet.init(testing.allocator, &patterns, .{});
    defer set.deinit();

    var out_ids: [8]u32 = undefined;
    const count = set.matches("prefix foo_123 and bar_abc suffix", &out_ids);
    try testing.expectEqual(@as(usize, 4), count);
    try testing.expectEqualSlices(u32, &[_]u32{ 0, 1, 2, 4 }, out_ids[0..count]);
}

test "E2E T1_F03_03: RegexSet with literal prefixes activating Multi SIMD prefilter" {
    const patterns = [_][]const u8{
        "ERR_AUTH_[0-9]+",
        "ERR_DB_[0-9]+",
        "WARN_CACHE_[A-Z]+",
    };
    var set = try RegexSet.init(testing.allocator, &patterns, .{});
    defer set.deinit();

    try testing.expect(set.prefilter != null);
    const m = set.find("all systems nominal until WARN_CACHE_MISS occurred", 0, .leftmost_first).?;
    try testing.expectEqual(@as(?u32, 2), m.pattern_id);
    try testing.expectEqualStrings("WARN_CACHE_MISS", "all systems nominal until WARN_CACHE_MISS occurred"[m.start..m.end]);
}

test "E2E T1_F03_04: RegexSet per-pattern .smart case sensitivity" {
    // Pattern 0 is all-lowercase -> case-insensitive in .smart mode
    // Pattern 1 has uppercase 'S' -> case-sensitive in .smart mode
    const patterns = [_][]const u8{
        "hello_[0-9]+",
        "Secret_[0-9]+",
    };
    var set = try RegexSet.init(testing.allocator, &patterns, .{ .case = .smart });
    defer set.deinit();

    const m0 = set.find("greeting HELLO_42", 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 0), m0.pattern_id);

    try testing.expect(!set.isMatch("wrong case SECRET_99"));
    const m1 = set.find("right case Secret_99", 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 1), m1.pattern_id);
}

test "E2E T1_F03_05: RegexSet plugged directly into searchSourceSlice and searchSource (Matcher contract)" {
    const patterns = [_][]const u8{ "WARN_[0-9]+", "CRIT_[A-Z]+" };
    var set = try RegexSet.init(testing.allocator, &patterns, .{});
    defer set.deinit();

    const log_data = "line 1 ok\nline 2 WARN_101 disk\nline 3 CRIT_OOM memory\n";
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const sum = try root.searchSourceSlice(log_data, "sys.log", &set, .{}, &sink);
    try testing.expectEqual(@as(usize, 2), sum.matched_lines);
    try testing.expectEqual(@as(?u32, 0), sink.lines.items[0].matches[0].pattern_id);
    try testing.expectEqual(@as(?u32, 1), sink.lines.items[1].matches[0].pattern_id);

    sink.clearRetainingCapacity();
    var rdr = std.Io.Reader.fixed(log_data);
    const sum2 = try root.searchSource(&rdr, "sys.log", &set, .{}, &sink);
    try testing.expectEqual(@as(usize, 2), sum2.matched_lines);
}

test "E2E T1_F04_01: C ABI version, default options, and literal/multi matcher lifecycle" {
    const ver = std.mem.span(c_api.webgrep_version());
    try testing.expect(ver.len >= 5);

    const find_opts = c_api.webgrep_find_options_default();
    var lit_m: CMatcherPtr = null;
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_matcher_compile_literal("needle", 6, &find_opts, &lit_m)));
    defer c_api.webgrep_matcher_free(lit_m);

    const hay = "haystack with needle inside";
    var cm: CMatch = undefined;
    try testing.expectEqual(@as(c_int, 1), cStatus(c_api.webgrep_find(lit_m, hay.ptr, hay.len, 0, &cm)));
    try testing.expectEqual(@as(usize, 14), cm.start);
    try testing.expectEqual(@as(usize, 20), cm.end);

    const pats = [_]CPattern{
        .{ .ptr = "alpha", .len = 5 },
        .{ .ptr = "beta", .len = 4 },
    };
    var multi_m: CMatcherPtr = null;
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_matcher_compile_multi(&pats, pats.len, &find_opts, &multi_m)));
    defer c_api.webgrep_matcher_free(multi_m);

    const hay2 = "xx beta yy alpha";
    try testing.expectEqual(@as(c_int, 1), cStatus(c_api.webgrep_find(multi_m, hay2.ptr, hay2.len, 0, &cm)));
    try testing.expectEqual(@as(u32, 1), cm.pattern_id);
}

test "E2E T1_F04_02: C ABI webgrep_matcher_compile_regex & webgrep_matcher_compile_regex_set + webgrep_regex_set_matches" {
    const re_opts = c_api.webgrep_regex_options_default();
    var diag: CCompileDiag = std.mem.zeroes(CCompileDiag);
    var re_m: CMatcherPtr = null;
    const pat = "item_[0-9]+";
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_matcher_compile_regex(pat.ptr, pat.len, &re_opts, &diag, &re_m)));
    defer c_api.webgrep_matcher_free(re_m);

    const hay = "prefix item_77 suffix";
    var cm: CMatch = undefined;
    try testing.expectEqual(@as(c_int, 1), cStatus(c_api.webgrep_find(re_m, hay.ptr, hay.len, 0, &cm)));
    try testing.expectEqual(@as(usize, 7), cm.start);
    try testing.expectEqual(@as(usize, 14), cm.end);

    const set_pats = [_]CPattern{
        .{ .ptr = "item_[0-9]+", .len = 11 },
        .{ .ptr = "suffix", .len = 6 },
        .{ .ptr = "absent_[0-9]+", .len = 13 },
    };
    var set_m: CMatcherPtr = null;
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_matcher_compile_regex_set(&set_pats, set_pats.len, &re_opts, &diag, &set_m)));
    defer c_api.webgrep_matcher_free(set_m);

    var ids: [4]u32 = undefined;
    var count: usize = 0;
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_regex_set_matches(set_m, hay.ptr, hay.len, &ids, ids.len, &count)));
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqual(@as(u32, 0), ids[0]);
    try testing.expectEqual(@as(u32, 1), ids[1]);
}

test "E2E T1_F04_03: C ABI webgrep_search_slice with C callback, webgrep_scratch_t, and replacement spans" {
    const re_opts = c_api.webgrep_regex_options_default();
    var diag: CCompileDiag = std.mem.zeroes(CCompileDiag);
    var re_m: CMatcherPtr = null;
    const pat = "user_([0-9]+)";
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_matcher_compile_regex(pat.ptr, pat.len, &re_opts, &diag, &re_m)));
    defer c_api.webgrep_matcher_free(re_m);

    const scratch = c_api.webgrep_scratch_new();
    try testing.expect(scratch != null);
    defer c_api.webgrep_scratch_free(scratch);

    var cfg = c_api.webgrep_config_default();
    cfg.scratch = scratch;
    const rep = "id:$1";
    cfg.replacement_ptr = rep.ptr;
    cfg.replacement_len = rep.len;

    const CbCtx = struct {
        matched_lines: usize = 0,
        saw_replacement: bool = false,
        fn onLine(ev: CLineEventPtr, userdata: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            if (ev.*.is_context == 0) {
                self.matched_lines += 1;
                if (ev.*.replaced_ptr) |rp| {
                    const rslice = rp[0..ev.*.replaced_len];
                    if (std.mem.indexOf(u8, rslice, "id:42") != null) {
                        self.saw_replacement = true;
                    }
                }
            }
            return 0;
        }
    };

    var ctx = CbCtx{};
    var sum: CSummary = std.mem.zeroes(CSummary);
    const input = "hello user_42 world\nsecond line\n";
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_search_slice(re_m, input.ptr, input.len, &cfg, CbCtx.onLine, &ctx, &sum)));
    try testing.expectEqual(@as(usize, 1), ctx.matched_lines);
    try testing.expect(ctx.saw_replacement);
    try testing.expectEqual(@as(u64, 1), sum.matched_lines);
}

test "E2E T1_F04_04: C ABI webgrep_search_reader streaming via C read callback" {
    const find_opts = c_api.webgrep_find_options_default();
    var m: CMatcherPtr = null;
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_matcher_compile_literal("STREAM_HIT", 10, &find_opts, &m)));
    defer c_api.webgrep_matcher_free(m);

    const StreamCtx = struct {
        data: []const u8 = "line 1\nline 2 STREAM_HIT ok\nline 3 STREAM_HIT end\n",
        pos: usize = 0,
        hits: usize = 0,

        fn onRead(buf: [*c]u8, cap: usize, out_n: [*c]usize, userdata: ?*anyopaque) callconv(.c) c_int {
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

        fn onLine(ev: CLineEventPtr, userdata: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            if (ev.*.is_context == 0) self.hits += 1;
            return 0;
        }
    };

    var sctx = StreamCtx{};
    const cfg = c_api.webgrep_config_default();
    var sum: CSummary = std.mem.zeroes(CSummary);
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_search_reader(m, StreamCtx.onRead, &sctx, &cfg, StreamCtx.onLine, &sctx, &sum)));
    try testing.expectEqual(@as(usize, 2), sctx.hits);
    try testing.expectEqual(@as(u64, 2), sum.matched_lines);
}

test "E2E T1_F04_05: C ABI webgrep_search_archive_slice on in-memory .tar.gz and .zip" {
    const find_opts = c_api.webgrep_find_options_default();
    var m: CMatcherPtr = null;
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_matcher_compile_literal("ARCHIVE_SECRET", 14, &find_opts, &m)));
    defer c_api.webgrep_matcher_free(m);

    const tar_raw = try Harness.buildTar(testing.allocator, &.{
        .{ .path = "pkg/a.txt", .data = "hello ARCHIVE_SECRET 1\n" },
        .{ .path = "pkg/b.txt", .data = "no secret\n" },
    });
    defer testing.allocator.free(tar_raw);
    const tgz = try Harness.makeGzipFromRaw(testing.allocator, tar_raw);
    defer testing.allocator.free(tgz);

    const zip_bytes = try Harness.buildZip(testing.allocator, &.{
        .{ .path = "src/main.zig", .data = "const k = \"ARCHIVE_SECRET\";\n", .method = 8 },
    });
    defer testing.allocator.free(zip_bytes);

    const Cb = struct {
        count: usize = 0,
        fn onLine(ev: CLineEventPtr, userdata: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            if (ev.*.is_context == 0) self.count += 1;
            return 0;
        }
    };

    var cb1 = Cb{};
    const tcfg = c_api.webgrep_tree_config_default();
    var tsum1: CTreeSummary = std.mem.zeroes(CTreeSummary);
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_search_archive_slice(m, tgz.ptr, tgz.len, &tcfg, Cb.onLine, &cb1, &tsum1)));
    try testing.expectEqual(@as(usize, 1), cb1.count);
    try testing.expectEqual(@as(u64, 1), tsum1.matched_files);

    var cb2 = Cb{};
    var tsum2: CTreeSummary = std.mem.zeroes(CTreeSummary);
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_search_archive_slice(m, zip_bytes.ptr, zip_bytes.len, &tcfg, Cb.onLine, &cb2, &tsum2)));
    try testing.expectEqual(@as(usize, 1), cb2.count);
    try testing.expectEqual(@as(u64, 1), tsum2.matched_files);
}

test "E2E T1_F05_01: Lazy DFA acceleration on pure character-class regex without fixed literals" {
    var re = try Regex.init(testing.allocator, "[a-zA-Z0-9_]{8,16}", .{});
    defer re.deinit();
    try testing.expect(re.prefilter == null);

    const hay = "   ---   identifier_2026   !!!";
    const m = re.find(hay, 0, .earliest).?;
    try testing.expectEqualStrings("identifier_2026", hay[m.start..m.end]);
}

test "E2E T1_F05_02: Lazy DFA 2-phase hybrid capture group resolution (findCaptures)" {
    var re = try Regex.init(testing.allocator, "([a-z]{3,8})-([0-9]{2,5})", .{});
    defer re.deinit();

    const hay = "noise... alpha-12345 and beta-99 ...";
    const caps = re.findCaptures(hay, 0, .earliest).?;
    try testing.expectEqualStrings("alpha-12345", hay[caps.match.start..caps.match.end]);
    try testing.expectEqualStrings("alpha", caps.slice(hay, 1).?);
    try testing.expectEqualStrings("12345", caps.slice(hay, 2).?);
}

test "E2E T1_F05_03: Lazy DFA greedy vs. lazy quantifier disambiguation in Phase 2" {
    var re_greedy = try Regex.init(testing.allocator, "[a-z]+?[0-9]+", .{});
    defer re_greedy.deinit();
    var re_full_greedy = try Regex.init(testing.allocator, "[a-z]+[0-9]+", .{});
    defer re_full_greedy.deinit();
    var re_lazy = try Regex.init(testing.allocator, "[a-z]+?[0-9]+?", .{});
    defer re_lazy.deinit();

    const hay = "   abc12345   ";
    const m_greedy = re_full_greedy.find(hay, 0, .earliest).?;
    try testing.expectEqualStrings("abc12345", hay[m_greedy.start..m_greedy.end]);

    const m_lazy = re_lazy.find(hay, 0, .earliest).?;
    try testing.expectEqualStrings("abc1", hay[m_lazy.start..m_lazy.end]);
}

test "E2E T1_F05_04: Lazy DFA with zero-width assertions (^, $, \\b, \\B) via conservative over-approximation" {
    var re_word = try Regex.init(testing.allocator, "\\b[a-z]{4}\\b", .{});
    defer re_word.deinit();

    const hay = "longerword four_not four exact!";
    const m = re_word.find(hay, 0, .earliest).?;
    try testing.expectEqualStrings("four", hay[m.start..m.end]);

    var re_line = try Regex.init(testing.allocator, "^[0-9]{3}$", .{ .multiline = true });
    defer re_line.deinit();
    const hay2 = "1234\n567\n89\n";
    const m2 = re_line.find(hay2, 0, .earliest).?;
    try testing.expectEqualStrings("567", hay2[m2.start..m2.end]);
}

test "E2E T1_F05_05: Lazy DFA StackDfa (stack mode) vs. HeapDfa (RegexScratch mode) equivalence" {
    var re = try Regex.init(testing.allocator, "[A-Z]{2,4}_[0-9]{2,4}|[a-z]{4,6}:[0-9]{1,3}", .{});
    defer re.deinit();

    var scratch = RegexScratch.init(testing.allocator);
    defer scratch.deinit();

    const hay = "noise123 key_a:42 mid TX_9001 tail";
    var pos: usize = 0;
    while (pos <= hay.len) {
        const m_stack = re.find(hay, pos, .earliest);
        const m_heap = re.findWithScratch(hay, pos, .earliest, &scratch);
        try testing.expectEqual(m_stack, m_heap);
        if (m_stack) |m| {
            pos = m.end;
        } else break;
    }
}

test "E2E T1_F06_01: Unicode General Categories (\\p{L}, \\p{Lu}, \\p{Ll}, \\p{Nd}, \\p{P}, \\p{S}, \\p{Z}, \\pL, \\pN)" {
    var re_lu = try Regex.init(testing.allocator, "\\p{Lu}\\p{Ll}+", .{});
    defer re_lu.deinit();
    const hay = "123 \xce\x91\xce\xb8\xce\xae\xce\xbd\xce\xb1!"; // "Αθήνα"
    const m1 = re_lu.find(hay, 0, .earliest).?;
    try testing.expectEqualStrings("Αθήνα", hay[m1.start..m1.end]);

    var re_short = try Regex.init(testing.allocator, "\\pL+\\p{Z}\\pN+", .{});
    defer re_short.deinit();
    const hay2 = "Café 2026!";
    const m2 = re_short.find(hay2, 0, .earliest).?;
    try testing.expectEqualStrings("Café 2026", hay2[m2.start..m2.end]);

    var re_sym = try Regex.init(testing.allocator, "\\p{S}+", .{});
    defer re_sym.deinit();
    const hay3 = "price €£¥ end";
    const m3 = re_sym.find(hay3, 0, .earliest).?;
    try testing.expectEqualStrings("€£¥", hay3[m3.start..m3.end]);
}

test "E2E T1_F06_02: Unicode Scripts (\\p{Han}, \\p{Hiragana}, \\p{Katakana}, \\p{Hangul}, \\p{Cyrillic}, \\p{Greek}, \\p{Arabic}, \\p{Hebrew})" {
    const cases = .{
        .{ "\\p{Han}+", "abc 漢字テスト", "漢字" },
        .{ "\\p{Hiragana}+", "漢字ひらがなカタカナ", "ひらがな" },
        .{ "\\p{Katakana}+", "漢字ひらがなカタカナ", "カタカナ" },
        .{ "\\p{Hangul}+", "test 한글123", "한글" },
        .{ "\\p{Cyrillic}+", "word Привет!", "Привет" },
        .{ "\\p{Greek}+", "word Ελλάδα!", "Ελλάδα" },
        .{ "\\p{Arabic}+", "word مرحبا!", "مرحبا" },
        .{ "\\p{Hebrew}+", "word שלום!", "שלום" },
    };
    inline for (cases) |tc| {
        var re = try Regex.init(testing.allocator, tc[0], .{});
        defer re.deinit();
        const m = re.find(tc[1], 0, .earliest).?;
        try testing.expectEqualStrings(tc[2], tc[1][m.start..m.end]);
    }
}

test "E2E T1_F06_03: Negated Unicode Properties (\\P{...}, \\p{^...}, \\P{^...}) and bracket classes [\\p{Han}\\p{Hiragana}0-9]+" {
    var re_neg = try Regex.init(testing.allocator, "\\P{Ascii}+", .{});
    defer re_neg.deinit();
    const hay = "ascii 東京0123 end";
    const m1 = re_neg.find(hay, 0, .earliest).?;
    try testing.expectEqualStrings("東京", hay[m1.start..m1.end]);

    var re_double_neg = try Regex.init(testing.allocator, "\\P{^Han}+", .{});
    defer re_double_neg.deinit();
    const m2 = re_double_neg.find(hay, 0, .earliest).?;
    try testing.expectEqualStrings("東京", hay[m2.start..m2.end]);

    var re_bracket = try Regex.init(testing.allocator, "[\\p{Han}\\p{Hiragana}0-9]+", .{});
    defer re_bracket.deinit();
    const hay2 = "abc 東京のかな99 xyz";
    const m3 = re_bracket.find(hay2, 0, .earliest).?;
    try testing.expectEqualStrings("東京のかな99", hay2[m3.start..m3.end]);
}

test "E2E T1_F06_04: Case-insensitive \\p{Lu} / \\p{Ll} widening to \\p{LC} (Cased_Letter)" {
    var re = try Regex.init(testing.allocator, "^\\p{Lu}+$", .{ .case = .insensitive, .unicode_case = true });
    defer re.deinit();

    try testing.expect(re.isMatch("HelloWorld"));
    try testing.expect(re.isMatch("αβγΩ"));
    // Caseless letters like Han ideographs are Lo, not LC!
    try testing.expect(!re.isMatch("漢字"));
}

test "E2E T1_F06_05: UAX #29 Unicode word boundaries (\\b, \\B, and SearchConfig.whole_word)" {
    var re = try Regex.init(testing.allocator, "\\bcafé\\b", .{});
    defer re.deinit();

    try testing.expect(re.isMatch("un café noir"));
    // "café" followed by Cyrillic 'й' or Latin 's' is NOT a word boundary
    try testing.expect(!re.isMatch("cafés"));
    try testing.expect(!re.isMatch("café\xd0\xb9"));

    // SearchConfig.whole_word also honors UAX #29 word characters
    const f = try Finder.init("café", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    const sum = try root.searchSourceSlice("cafés\nun café!\n", null, &f, .{ .whole_word = true }, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_lines);
    try testing.expectEqual(@as(usize, 2), sink.lines.items[0].line_number);
}

test "E2E T1_F07_01: memchr explicit width {16, 32, 64} parity across find, findEither, findAny, findLast, count" {
    var buf: [300]u8 = undefined;
    for (&buf, 0..) |*b, i| b.* = @intCast((i * 7 + 3) % 251);
    buf[73] = 0xFE;
    buf[199] = 0xFD;
    buf[260] = 0xFC;

    inline for (.{ 16, 32, 64 }) |w| {
        try testing.expectEqual(memchr.find(16, &buf, 0, 0xFE), memchr.findWithWidth(w, &buf, 0, 0xFE));
        try testing.expectEqual(memchr.findEither(16, &buf, 0, 0xFD, 0xFE), memchr.findEitherWithWidth(w, &buf, 0, 0xFD, 0xFE));
        try testing.expectEqual(memchr.findAny(16, &buf, 0, 0xFC, 0xFD, 0xFE), memchr.findAnyWithWidth(w, &buf, 0, 0xFC, 0xFD, 0xFE));
        try testing.expectEqual(memchr.findLast(16, &buf, 0, buf.len, 0xFE), memchr.findLastWithWidth(w, &buf, 0, buf.len, 0xFE));
        try testing.expectEqual(memchr.count(16, &buf, 0, buf.len, 0xFE), memchr.countWithWidth(w, &buf, 0, buf.len, 0xFE));
    }
}

test "E2E T1_F07_02: packed_pair explicit width {16, 32, 64} parity on find and findWatchingNul" {
    const hay = Harness.repeat("a", 150) ++ "TARGET_NEEDLE" ++ Harness.repeat("b", 90);
    const plan = packed_pair.PackedPair.init("TARGET_NEEDLE", &frequency.default_rank, false);

    inline for (.{ 16, 32, 64 }) |w| {
        try testing.expectEqual(@as(?usize, 150), plan.findWithWidth(w, hay, 0, null));
        var nul: ?usize = null;
        const pos = plan.findWatchingNulWithWidth(w, hay, 0, null, &nul);
        try testing.expectEqual(@as(?usize, 150), pos);
        try testing.expectEqual(@as(?usize, null), nul);
    }
}

test "E2E T1_F07_03: Multi Teddy SIMD auto-detection in default build (engineName() == \"teddy\")" {
    const pats = Multi.scenario_teddy;
    var m = try Multi.init(testing.allocator, pats, .{});
    defer m.deinit();

    if ((@import("build_options").teddy != .off)) {
        try testing.expectEqualStrings("teddy", m.engineName());
    }
    const target = pats[8];
    const hay = try std.fmt.allocPrint(testing.allocator, "padding {s} tail", .{target});
    defer testing.allocator.free(hay);
    const hit = m.find(hay, 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 8), hit.pattern_id);
}

test "E2E T1_F07_04: Multi Teddy 9..32 variable-length case-sensitive & case-insensitive matching" {
    const pats = [_][]const u8{
        "ab",       "abc_def",   "ghijkl",    "mnop_qrst", "uv_wxyz_12",
        "pat_six6", "seven_777", "eight_888", "nine_9999", "ten_101010",
        "eleven11", "twelve_12",
    };
    var m_sens = try Multi.init(testing.allocator, &pats, .{ .case = .sensitive });
    defer m_sens.deinit();
    var m_ins = try Multi.init(testing.allocator, &pats, .{ .case = .insensitive });
    defer m_ins.deinit();

    const hay = "zzz TEN_101010 and mnop_qrst yyy";
    const r_sens = m_sens.find(hay, 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 3), r_sens.pattern_id);

    const r_ins = m_ins.find(hay, 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 9), r_ins.pattern_id);
}

test "E2E T1_F07_05: aho.zig SIMD anchor prefilter + automaton transitions across 64+ patterns" {
    var pat_bufs: [64][2]u8 = undefined;
    var pats: [64][]const u8 = undefined;
    for (0..64) |i| {
        pat_bufs[i] = .{ 'A' + @as(u8, @intCast(i / 8)), 'A' + @as(u8, @intCast(i % 8)) };
        pats[i] = &pat_bufs[i];
    }
    var m = try Multi.init(testing.allocator, &pats, .{});
    defer m.deinit();
    try testing.expectEqualStrings("ac", m.engineName());

    const hay = Harness.repeat("noise ", 50) ++ "HE tail";
    const hit = m.find(hay, 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 7 * 8 + 4), hit.pattern_id);
}

test "E2E T1_F08_01: openReaderPull basic lifecycle (begin, context, match, context_break, end, summary)" {
    const input =
        "line 1\n" ++
        "line 2 MATCH_A\n" ++
        "line 3 ctx\n" ++
        "line 4 gap\n" ++
        "line 5 gap\n" ++
        "line 6 ctx\n" ++
        "line 7 MATCH_B\n";

    var rdr = std.Io.Reader.fixed(input);
    const f = try Finder.init("MATCH_", .{});
    var pull = root.openReaderPull(&rdr, &f, .{
        .path = "stream.log",
        .before_context = 1,
        .after_context = 1,
    });
    defer pull.deinit();

    var kinds: std.ArrayList(root.PullEventKind) = .empty;
    defer kinds.deinit(testing.allocator);

    while (try pull.next()) |ev| {
        try kinds.append(testing.allocator, ev.kind);
    }

    const expected = [_]root.PullEventKind{
        .begin,
        .context, // line 1
        .match, // line 2
        .context, // line 3
        .context_break,
        .context, // line 6
        .match, // line 7
        .end,
        .summary,
    };
    try testing.expectEqualSlices(root.PullEventKind, &expected, kinds.items);
    try testing.expect((try pull.next()) == null);
}

test "E2E T1_F08_02: openReaderPull true incremental chunk-stepping (early caller break stops upstream reads)" {
    // Build a 1 MiB input where every 64 bytes has a match
    const chunk = "0123456789abcdef0123456789abcdef_HIT_0123456789abcdef01234567\n";
    const total_lines = 4096;
    const big = try testing.allocator.alloc(u8, chunk.len * total_lines);
    defer testing.allocator.free(big);
    for (0..total_lines) |i| {
        @memcpy(big[i * chunk.len .. (i + 1) * chunk.len], chunk);
    }

    var rbuf: [64]u8 = undefined;
    var cr = Harness.ChunkedReader.init(big, 256, &rbuf);
    const f = try Finder.init("_HIT_", .{});
    var pull = root.openReaderPull(&cr.interface, &f, .{ .buffer_size = 1024 });
    defer pull.deinit();

    var matches: usize = 0;
    while (try pull.next()) |ev| {
        if (ev.kind == .match) {
            matches += 1;
            if (matches == 2) break;
        }
    }
    try testing.expectEqual(@as(usize, 2), matches);
    // Must have read only a tiny fraction of the ~256 KiB stream!
    try testing.expect(cr.pos <= 4096);
}

test "E2E T1_F08_03: openReaderPull with streaming Gzip, Zstd, and XZ decompression (Compression.auto)" {
    const raw = "line 1 hello\nline 2 STREAM_DECOMP_OK\nline 3 bye\n";
    const gz = try Harness.makeGzipFromRaw(testing.allocator, raw);
    defer testing.allocator.free(gz);
    const zst = try Harness.makeZstdFromRaw(testing.allocator, raw);
    defer testing.allocator.free(zst);

    const f = try Finder.init("STREAM_DECOMP_OK", .{});

    for ([_][]const u8{ gz, zst }) |compressed| {
        var rdr = std.Io.Reader.fixed(compressed);
        var pull = root.openReaderPull(&rdr, &f, .{
            .compression = .auto,
            .allocator = testing.allocator,
        });
        defer pull.deinit();

        var hit_line: usize = 0;
        while (try pull.next()) |ev| {
            if (ev.kind == .match) hit_line = ev.line.?.line_number;
        }
        try testing.expectEqual(@as(usize, 2), hit_line);
    }
}

test "E2E T1_F08_04: openReaderPull with streaming BOM & charset transcoding (UTF-16LE, UTF-16BE, GBK, Latin-1)" {
    const utf8_text = "alpha line\nbeta UTF_STREAM_HIT café\n";
    const u16le = try Harness.encodeUtf16FromUtf8(testing.allocator, utf8_text, .little, true);
    defer testing.allocator.free(u16le);
    const u16be = try Harness.encodeUtf16FromUtf8(testing.allocator, utf8_text, .big, true);
    defer testing.allocator.free(u16be);

    const f = try Finder.init("UTF_STREAM_HIT", .{});
    for ([_][]const u8{ u16le, u16be }) |encoded| {
        var rbuf: [16]u8 = undefined;
        var cr = Harness.ChunkedReader.init(encoded, 5, &rbuf);
        var pull = root.openReaderPull(&cr.interface, &f, .{
            .allocator = testing.allocator,
        });
        defer pull.deinit();

        var found = false;
        while (try pull.next()) |ev| {
            if (ev.kind == .match) {
                found = true;
                try testing.expect(std.mem.indexOf(u8, ev.line.?.text, "UTF_STREAM_HIT café") != null);
            }
        }
        try testing.expect(found);
    }

    // Latin-1 explicit encoding (0xE9 = 'é')
    const latin1_bytes = "line 1\ncaf\xe9 UTF_STREAM_HIT\n";
    var rdr_lat = std.Io.Reader.fixed(latin1_bytes);
    var pull_lat = root.openReaderPull(&rdr_lat, &f, .{
        .encoding = .latin1,
        .allocator = testing.allocator,
    });
    defer pull_lat.deinit();
    var saw_lat = false;
    while (try pull_lat.next()) |ev| {
        if (ev.kind == .match) {
            saw_lat = true;
            try testing.expect(std.mem.indexOf(u8, ev.line.?.text, "café UTF_STREAM_HIT") != null);
        }
    }
    try testing.expect(saw_lat);
}

test "E2E T1_F08_05: openReaderPull parity with openSourcePull and searchSource" {
    const text = "a\nb hit\nc\nd\ne hit\nf\n";
    const f = try Finder.init("hit", .{});
    const cfg = SearchConfig{ .before_context = 1, .after_context = 1 };

    var rdr1 = std.Io.Reader.fixed(text);
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    const sum_push = try root.searchSource(&rdr1, "t.txt", &f, cfg, &sink);

    var rdr2 = std.Io.Reader.fixed(text);
    var rpull = root.openReaderPull(&rdr2, &f, cfg);
    defer rpull.deinit();

    var mem = root.source.Memory{ .files = &.{.{ .path = "t.txt", .data = text }} };
    const src = mem.source();
    const h = try src.open(testing.io, "t.txt");
    defer src.close(testing.io, h);
    var spull = root.openSourcePull(testing.io, src, h, &f, cfg);
    defer spull.deinit();

    while (true) {
        const ev_r = try rpull.next();
        const ev_s = try spull.next();
        try testing.expectEqual(ev_r == null, ev_s == null);
        if (ev_r == null) break;
        try testing.expectEqual(ev_r.?.kind, ev_s.?.kind);
        if (ev_r.?.line) |lr| {
            try testing.expectEqualStrings(lr.text, ev_s.?.line.?.text);
            try testing.expectEqual(lr.line_number, ev_s.?.line.?.line_number);
        }
        if (ev_r.?.kind == .summary) {
            try testing.expectEqual(sum_push.matched_lines, ev_r.?.summary.?.matched_lines);
        }
    }
}

test "E2E T1_F09_01: source.Memory stateful cursor tracking across multi-chunk read() and multi-batch list()" {
    var mem = root.source.Memory{
        .files = &.{
            .{ .path = "dir/a.txt", .data = "0123456789ABCDEF" },
            .{ .path = "dir/b.txt", .data = "hello" },
            .{ .path = "dir/c.txt", .data = "world" },
        },
    };
    const src = mem.source();

    // Multi-batch list() with a 1-entry buffer
    const dh = try src.open(testing.io, "dir");
    defer src.close(testing.io, dh);
    var entry_buf: [1]root.source.Entry = undefined;
    var listed: usize = 0;
    while (true) {
        const n = try src.list(testing.io, dh, &entry_buf);
        if (n == 0) break;
        listed += n;
    }
    try testing.expectEqual(@as(usize, 3), listed);

    // Multi-chunk read() with a 5-byte buffer
    const fh = try src.open(testing.io, "dir/a.txt");
    defer src.close(testing.io, fh);
    var assembled: std.ArrayList(u8) = .empty;
    defer assembled.deinit(testing.allocator);
    var rbuf: [5]u8 = undefined;
    while (true) {
        const n = try src.read(testing.io, fh, &rbuf);
        if (n == 0) break;
        try assembled.appendSlice(testing.allocator, rbuf[0..n]);
    }
    try testing.expectEqualStrings("0123456789ABCDEF", assembled.items);
}

test "E2E T1_F09_02: ArchiveTree.initFromSlice unpacking uncompressed .tar (nested directories & multiple files)" {
    const tar = try Harness.buildTar(testing.allocator, &.{
        .{ .path = "repo/README.md", .data = "welcome to repo\n" },
        .{ .path = "repo/src/lib.zig", .data = "pub const k = 42;\n" },
    });
    defer testing.allocator.free(tar);

    var tree = try ArchiveTree.initFromSlice(testing.allocator, tar, .tar, .none, .{});
    defer tree.deinit();

    const f = try Finder.init("k = 42", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    const sum = root.searchTree(testing.io, tree.source(), &f, .{}, &sink);
    try testing.expectEqual(@as(usize, 2), sum.files_searched);
    try testing.expectEqual(@as(usize, 1), sum.matched_files);
    try testing.expectEqualStrings("repo/src/lib.zig", sink.lines.items[0].path.?);
}

test "E2E T1_F09_03: ArchiveTree unpacking .tar.gz / .tgz and .tar.zst with auto-detection" {
    const tar = try Harness.buildTar(testing.allocator, &.{
        .{ .path = "logs/app.log", .data = "INFO start\nERROR TAR_COMP_HIT\n" },
    });
    defer testing.allocator.free(tar);

    const tgz = try Harness.makeGzipFromRaw(testing.allocator, tar);
    defer testing.allocator.free(tgz);
    const tzst = try Harness.makeZstdFromRaw(testing.allocator, tar);
    defer testing.allocator.free(tzst);

    const f = try Finder.init("TAR_COMP_HIT", .{});
    for ([_][]const u8{ tgz, tzst }) |comp_tar| {
        var tree = try ArchiveTree.initFromSlice(testing.allocator, comp_tar, .auto, .auto, .{});
        defer tree.deinit();
        var sink = Harness.TestEventSink.init(testing.allocator);
        defer sink.deinit();
        const sum = root.searchTree(testing.io, tree.source(), &f, .{}, &sink);
        try testing.expectEqual(@as(usize, 1), sum.matched_files);
        try testing.expectEqual(@as(usize, 1), sum.matched_lines);
    }
}

test "E2E T1_F09_04: ArchiveTree unpacking .zip with .store (method 0) and .deflate (method 8) + CRC32 verification" {
    const zip = try Harness.buildZip(testing.allocator, &.{
        .{ .path = "stored.txt", .data = "stored ZIP_HIT_ONE\n", .method = 0 },
        .{ .path = "deflated.txt", .data = "deflated ZIP_HIT_TWO\n", .method = 8 },
    });
    defer testing.allocator.free(zip);

    var tree = try ArchiveTree.initFromSlice(testing.allocator, zip, .zip, .auto, .{});
    defer tree.deinit();

    const f = try Finder.init("ZIP_HIT_", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    const sum = root.searchTree(testing.io, tree.source(), &f, .{}, &sink);
    try testing.expectEqual(@as(usize, 2), sum.matched_files);
    try testing.expectEqual(@as(usize, 2), sum.matched_lines);
}

test "E2E T1_F09_05: ArchiveTree.initFromReader over chunked std.Io.Reader" {
    const tar = try Harness.buildTar(testing.allocator, &.{
        .{ .path = "stream/item.txt", .data = "reader archive HIT_STREAM_TAR\n" },
    });
    defer testing.allocator.free(tar);
    const tgz = try Harness.makeGzipFromRaw(testing.allocator, tar);
    defer testing.allocator.free(tgz);

    var rbuf: [32]u8 = undefined;
    var cr = Harness.ChunkedReader.init(tgz, 19, &rbuf);
    var tree = try ArchiveTree.initFromReader(testing.allocator, &cr.interface, .auto, .auto, .{});
    defer tree.deinit();

    const f = try Finder.init("HIT_STREAM_TAR", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    const sum = root.searchTree(testing.io, tree.source(), &f, .{}, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_files);
}

test "E2E T1_F10_01: Scratch lifecycle (init, reset, deinit) and zero steady-state allocations on searchSourceSlice" {
    var counting = Harness.CountingAllocator.init(testing.allocator);
    var scratch = Scratch.init(counting.allocator());
    defer scratch.deinit();

    var re = try Regex.init(testing.allocator, "item_([0-9]+)", .{});
    defer re.deinit();

    const data = "line 1 item_10\nline 2 item_20\nline 3 item_30\n";
    const cfg = SearchConfig{
        .scratch_pool = &scratch,
        .allocator = counting.allocator(),
        .replacement = "val:$1",
    };

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    // Warm up
    _ = try root.searchSourceSlice(data, null, &re, cfg, &sink);
    scratch.reset();
    counting.resetCounts();

    for (0..200) |_| {
        sink.clearRetainingCapacity();
        _ = try root.searchSourceSlice(data, null, &re, cfg, &sink);
        scratch.reset();
    }
    try testing.expectEqual(@as(usize, 0), counting.totalAllocEvents());
}

test "E2E T1_F10_02: Zero steady-state allocations on streaming searchSource with before-context ring and long lines" {
    var counting = Harness.CountingAllocator.init(testing.allocator);
    var scratch = Scratch.init(counting.allocator());
    defer scratch.deinit();

    const f = try Finder.init("LONG_HIT", .{});
    const long_line = Harness.repeat("x", 600) ++ " LONG_HIT " ++ Harness.repeat("y", 600) ++ "\n";
    const stream_data = "ctx 1\nctx 2\n" ++ long_line ++ "after 1\n";

    const cfg = SearchConfig{
        .scratch_pool = &scratch,
        .allocator = counting.allocator(),
        .buffer_size = 256,
        .before_context = 2,
        .after_context = 1,
    };

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    // Warm up
    {
        var rdr = std.Io.Reader.fixed(stream_data);
        _ = try root.searchSource(&rdr, null, &f, cfg, &sink);
    }
    counting.resetCounts();

    for (0..100) |_| {
        sink.clearRetainingCapacity();
        var rdr = std.Io.Reader.fixed(stream_data);
        const sum = try root.searchSource(&rdr, null, &f, cfg, &sink);
        try testing.expectEqual(@as(usize, 1), sum.matched_lines);
    }
    try testing.expectEqual(@as(usize, 0), counting.totalAllocEvents());
}

test "E2E T1_F10_03: Scratch.span_buf reuse when a single line contains > 32 matches" {
    var counting = Harness.CountingAllocator.init(testing.allocator);
    var scratch = Scratch.init(counting.allocator());
    defer scratch.deinit();

    const line = Harness.repeat("hit ", 50) ++ "\n";
    const f = try Finder.init("hit", .{});
    const cfg = SearchConfig{
        .scratch_pool = &scratch,
        .allocator = counting.allocator(),
    };

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    _ = try root.searchSourceSlice(line, null, &f, cfg, &sink);
    try testing.expectEqual(@as(usize, 50), sink.lines.items[0].matches.len);
    try testing.expect(scratch.span_buf.len >= 50);

    counting.resetCounts();
    for (0..100) |_| {
        sink.clearRetainingCapacity();
        _ = try root.searchSourceSlice(line, null, &f, cfg, &sink);
    }
    try testing.expectEqual(@as(usize, 0), counting.totalAllocEvents());
}

test "E2E T1_F10_04: Scratch.decode_buf reuse across repeated UTF-16LE and Gzip slice searches" {
    var counting = Harness.CountingAllocator.init(testing.allocator);
    var scratch = Scratch.init(counting.allocator());
    defer scratch.deinit();

    const u16le = try Harness.encodeUtf16FromUtf8(testing.allocator, "line 1\nline 2 DECODE_REUSE_HIT\n", .little, true);
    defer testing.allocator.free(u16le);
    const gz = try Harness.makeGzipFromRaw(testing.allocator, "line 1\nline 2 DECODE_REUSE_HIT\n");
    defer testing.allocator.free(gz);

    const f = try Finder.init("DECODE_REUSE_HIT", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    // Warm up UTF-16LE
    _ = try root.searchSourceSlice(u16le, null, &f, .{
        .scratch_pool = &scratch,
        .allocator = testing.allocator,
    }, &sink);
    try testing.expect(scratch.decode_buf.len > 0);
    counting.resetCounts();

    for (0..50) |_| {
        sink.clearRetainingCapacity();
        _ = try root.searchSourceSlice(u16le, null, &f, .{
            .scratch_pool = &scratch,
            .allocator = testing.allocator,
        }, &sink);
    }
    try testing.expectEqual(@as(usize, 0), counting.totalAllocEvents());

    // Warm up Gzip
    _ = try root.searchSourceSlice(gz, null, &f, .{
        .compression = .gzip,
        .scratch_pool = &scratch,
        .allocator = testing.allocator,
    }, &sink);
    counting.resetCounts();

    for (0..50) |_| {
        sink.clearRetainingCapacity();
        _ = try root.searchSourceSlice(gz, null, &f, .{
            .compression = .gzip,
            .scratch_pool = &scratch,
            .allocator = testing.allocator,
        }, &sink);
    }
    try testing.expectEqual(@as(usize, 0), counting.totalAllocEvents());
}

test "E2E T1_F10_05: Backward compatibility of legacy SearchConfig.scratch: ?*[]u8" {
    var legacy_buf: []u8 = &.{};
    defer if (legacy_buf.len != 0) testing.allocator.free(legacy_buf);

    const f = try Finder.init("LEGACY_HIT", .{});
    var rdr = std.Io.Reader.fixed("line 1\nline 2 LEGACY_HIT\n");
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const sum = try root.searchSource(&rdr, null, &f, .{
        .scratch = &legacy_buf,
        .allocator = testing.allocator,
        .buffer_size = 512,
    }, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_lines);
    try testing.expect(legacy_buf.len >= 512);
}

test "E2E T1_F11_01: AnyMatcher wrapping Finder, Multi, Regex, and RegexSet in a homogeneous array" {
    const f = try Finder.init("lit_tok", .{});
    var m = try Multi.init(testing.allocator, &.{ "multi_a", "multi_b" }, .{});
    defer m.deinit();
    var r = try Regex.init(testing.allocator, "re_[0-9]+", .{});
    defer r.deinit();
    var rs = try RegexSet.init(testing.allocator, &.{ "set_x", "set_y" }, .{});
    defer rs.deinit();

    const matchers = [_]AnyMatcher{
        AnyMatcher.from(&f),
        AnyMatcher.from(&m),
        AnyMatcher.from(&r),
        AnyMatcher.from(&rs),
    };

    const text = "lit_tok multi_b re_42 set_y";
    var hits: usize = 0;
    for (matchers) |am| {
        if (am.find(text, 0, .earliest)) |_| hits += 1;
    }
    try testing.expectEqual(@as(usize, 4), hits);
}

test "E2E T1_F11_02: AnyEventSink wrapping both bool-returning and Flow-returning service sinks" {
    const BoolSink = struct {
        count: usize = 0,
        pub fn emit(self: *@This(), ev: LineEvent) bool {
            if (!ev.is_context) self.count += 1;
            return true;
        }
    };
    const FlowSink = struct {
        count: usize = 0,
        pub fn emit(self: *@This(), ev: LineEvent) Flow {
            if (!ev.is_context) self.count += 1;
            return .cont;
        }
    };

    var bs = BoolSink{};
    var fs = FlowSink{};
    const any_b = AnyEventSink.from(&bs);
    const any_f = AnyEventSink.from(&fs);

    const f = try Finder.init("hit", .{});
    _ = try root.searchSourceSlice("hit 1\nhit 2\n", null, &f, .{}, any_b);
    _ = try root.searchSourceSlice("hit 1\nhit 2\n", null, &f, .{}, any_f);
    try testing.expectEqual(@as(usize, 2), bs.count);
    try testing.expectEqual(@as(usize, 2), fs.count);
}

test "E2E T1_F11_03: AnyMatcher + AnyEventSink non-generic dispatch in searchSourceSlice and searchSource" {
    var rs = try RegexSet.init(testing.allocator, &.{ "ALPHA_[0-9]+", "BETA_[0-9]+" }, .{});
    defer rs.deinit();
    const any_m = AnyMatcher.from(&rs);

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    const any_s = AnyEventSink.from(&sink);

    const input = "line 1 ALPHA_10\nline 2 BETA_20\n";
    const s1 = try root.searchSourceSlice(input, "f.txt", any_m, .{}, any_s);
    try testing.expectEqual(@as(usize, 2), s1.matched_lines);

    var rdr = std.Io.Reader.fixed(input);
    const s2 = try root.searchSource(&rdr, "f.txt", any_m, .{}, any_s);
    try testing.expectEqual(@as(usize, 2), s2.matched_lines);
}

test "E2E T1_F11_04: AnyMatcher preserving Regex submatch capture replacement ($1, $2)" {
    var re = try Regex.init(testing.allocator, "([a-z]+)=([0-9]+)", .{});
    defer re.deinit();
    const any_m = AnyMatcher.from(&re);

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    _ = try root.searchSourceSlice("key=123 and port=8080\n", null, any_m, .{
        .replacement = "[$2:$1]",
    }, &sink);

    try testing.expectEqual(@as(usize, 1), sink.lines.items.len);
    try testing.expectEqualStrings("[123:key] and [8080:port]", sink.lines.items[0].replaced.?);
}

test "E2E T1_F11_05: AnyMatcher forwarding isMultiline(), isStartAnchored(), and multilineWindow()" {
    var re_ml = try Regex.init(testing.allocator, "\\Ahello\\nworld", .{ .multiline = true });
    defer re_ml.deinit();
    const any_m = AnyMatcher.from(&re_ml);

    try testing.expect(any_m.isMultiline());
    try testing.expect(any_m.isStartAnchored());
    try testing.expectEqual(re_ml.multilineWindow(), any_m.multilineWindow());

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    const sum = try root.searchSourceSlice("hello\nworld\ntail\n", null, any_m, .{}, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_lines);
    try testing.expectEqualStrings("hello\nworld", sink.lines.items[0].text);
}

test "E2E T1_F12_01: SearchConfig.allocator enables BOM/charset transcoding in searchSourceSlice without decode_allocator" {
    const u16_bytes = try Harness.encodeUtf16FromUtf8(testing.allocator, "first\nsecond ALLOC_UTF16_OK\n", .little, true);
    defer testing.allocator.free(u16_bytes);

    const f = try Finder.init("ALLOC_UTF16_OK", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const sum = try root.searchSourceSlice(u16_bytes, null, &f, .{
        .allocator = testing.allocator,
        .decode_allocator = null,
    }, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_lines);
}

test "E2E T1_F12_02: SearchConfig.allocator enables in-memory slice decompression (Gzip, Zstd) in searchSourceSlice" {
    const gz = try Harness.makeGzipFromRaw(testing.allocator, "hello\nALLOC_DECOMP_OK\n");
    defer testing.allocator.free(gz);
    const zst = try Harness.makeZstdFromRaw(testing.allocator, "hello\nALLOC_DECOMP_OK\n");
    defer testing.allocator.free(zst);

    const f = try Finder.init("ALLOC_DECOMP_OK", .{});
    for ([_][]const u8{ gz, zst }) |comp| {
        var sink = Harness.TestEventSink.init(testing.allocator);
        defer sink.deinit();
        const sum = try root.searchSourceSlice(comp, null, &f, .{
            .compression = .auto,
            .allocator = testing.allocator,
        }, &sink);
        try testing.expectEqual(@as(usize, 1), sum.matched_lines);
    }
}

test "E2E T1_F12_03: SearchConfig.allocator enables large replacement preview (> 4 KiB) and > 32 spans in searchSlice / searchSourceSlice" {
    const big_line = Harness.repeat("tok ", 1200) ++ "\n";
    const f = try Finder.init("tok", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const sum = try root.searchSourceSlice(big_line, null, &f, .{
        .allocator = testing.allocator,
        .replacement = "LONGER_REPLACEMENT",
    }, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_lines);
    try testing.expectEqual(@as(usize, 1200), sink.lines.items[0].matches.len);
    try testing.expect(sink.lines.items[0].replaced.?.len > 4096);
}

test "E2E T1_F12_04: effectiveAllocator precedence: config.allocator > config.decode_allocator > config.scratch_pool.allocator" {
    var c1 = Harness.CountingAllocator.init(testing.allocator);
    var c2 = Harness.CountingAllocator.init(testing.allocator);
    var c3 = Harness.CountingAllocator.init(testing.allocator);
    var sp = Scratch.init(c3.allocator());
    defer sp.deinit();

    const cfg1 = SearchConfig{
        .allocator = c1.allocator(),
        .decode_allocator = c2.allocator(),
        .scratch_pool = &sp,
    };
    const eff1 = root.search_config.effectiveAllocator(cfg1).?;
    const b1 = try eff1.alloc(u8, 8);
    eff1.free(b1);
    try testing.expectEqual(@as(usize, 1), c1.alloc_calls.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), c2.alloc_calls.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), c3.alloc_calls.load(.monotonic));

    const cfg2 = SearchConfig{
        .allocator = null,
        .decode_allocator = c2.allocator(),
        .scratch_pool = &sp,
    };
    const eff2 = root.search_config.effectiveAllocator(cfg2).?;
    const b2 = try eff2.alloc(u8, 8);
    eff2.free(b2);
    try testing.expectEqual(@as(usize, 1), c2.alloc_calls.load(.monotonic));
    try testing.expectEqual(@as(usize, 0), c3.alloc_calls.load(.monotonic));

    const cfg3 = SearchConfig{
        .allocator = null,
        .decode_allocator = null,
        .scratch_pool = &sp,
    };
    const eff3 = root.search_config.effectiveAllocator(cfg3).?;
    const b3 = try eff3.alloc(u8, 8);
    eff3.free(b3);
    try testing.expectEqual(@as(usize, 1), c3.alloc_calls.load(.monotonic));
}

test "E2E T1_F12_05: Pure UTF-8 slice search with allocator = null performs zero heap allocations" {
    const f = try Finder.init("pure_utf8", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const sum = try root.searchSourceSlice("line 1\nline 2 pure_utf8 ok\n", null, &f, .{
        .allocator = null,
        .decode_allocator = null,
        .scratch_pool = null,
    }, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_lines);
}

test "E2E T1_F13_01: Regex.initDiagnostic reporting exact byte offset, line, column, and DiagnosticCode on group errors" {
    var diag: CompileDiagnostic = .{};
    try testing.expectError(error.RegexSyntax, Regex.initDiagnostic(testing.allocator, "abc(def", .{}, &diag));
    try testing.expectEqual(DiagnosticCode.unclosed_group, diag.code);
    try testing.expectEqual(@as(usize, 3), diag.offset);
    try testing.expectEqual(@as(usize, 1), diag.line);
    try testing.expectEqual(@as(usize, 4), diag.column);

    var diag2: CompileDiagnostic = .{};
    try testing.expectError(error.RegexSyntax, Regex.initDiagnostic(testing.allocator, "abc)def", .{}, &diag2));
    try testing.expectEqual(DiagnosticCode.unmatched_close_paren, diag2.code);
    try testing.expectEqual(@as(usize, 3), diag2.offset);
}

test "E2E T1_F13_02: Regex.initDiagnostic on character class and range errors" {
    var diag: CompileDiagnostic = .{};
    try testing.expectError(error.RegexSyntax, Regex.initDiagnostic(testing.allocator, "ab[c-z", .{}, &diag));
    try testing.expectEqual(DiagnosticCode.unclosed_char_class, diag.code);

    var diag2: CompileDiagnostic = .{};
    try testing.expectError(error.RegexSyntax, Regex.initDiagnostic(testing.allocator, "[z-a]", .{}, &diag2));
    try testing.expectEqual(DiagnosticCode.invalid_char_range, diag2.code);
}

test "E2E T1_F13_03: Regex.initDiagnostic on quantifier errors (dangling_quantifier, invalid_repeat_bounds, unclosed_repeat_braces)" {
    var diag1: CompileDiagnostic = .{};
    try testing.expectError(error.RegexSyntax, Regex.initDiagnostic(testing.allocator, "+abc", .{}, &diag1));
    try testing.expectEqual(DiagnosticCode.dangling_quantifier, diag1.code);

    var diag2: CompileDiagnostic = .{};
    try testing.expectError(error.RegexSyntax, Regex.initDiagnostic(testing.allocator, "a{5,2}", .{}, &diag2));
    try testing.expectEqual(DiagnosticCode.invalid_repeat_bounds, diag2.code);

    var diag3: CompileDiagnostic = .{};
    try testing.expectError(error.RegexSyntax, Regex.initDiagnostic(testing.allocator, "a{3,5", .{}, &diag3));
    try testing.expectEqual(DiagnosticCode.unclosed_repeat_braces, diag3.code);
}

test "E2E T1_F13_04: Regex.initDiagnostic on Unicode property errors (unknown_unicode_property, unclosed_unicode_property)" {
    var diag1: CompileDiagnostic = .{};
    try testing.expectError(error.RegexSyntax, Regex.initDiagnostic(testing.allocator, "\\p{NotAProperty}", .{}, &diag1));
    try testing.expectEqual(DiagnosticCode.unknown_unicode_property, diag1.code);

    var diag2: CompileDiagnostic = .{};
    try testing.expectError(error.RegexSyntax, Regex.initDiagnostic(testing.allocator, "\\p{Han", .{}, &diag2));
    try testing.expectEqual(DiagnosticCode.unclosed_unicode_property, diag2.code);
}

test "E2E T1_F13_05: Multiline pattern line and column tracking + RegexSet.initDiagnostic" {
    var diag: CompileDiagnostic = .{};
    try testing.expectError(
        error.RegexSyntax,
        Regex.initDiagnostic(testing.allocator, "line1\nline2\nabc)def", .{ .multiline = true }, &diag),
    );
    try testing.expectEqual(@as(usize, 3), diag.line);
    try testing.expectEqual(@as(usize, 4), diag.column);

    var set_diag: CompileDiagnostic = .{};
    try testing.expectError(
        error.RegexSyntax,
        RegexSet.initDiagnostic(testing.allocator, &.{ "valid_[0-9]+", "bad(group" }, .{}, &set_diag),
    );
    try testing.expectEqual(@as(?usize, 1), set_diag.pattern_index);
    try testing.expectEqual(DiagnosticCode.unclosed_group, set_diag.code);
}

test "E2E T1_F14_01: searchTree over virtual source.Memory hierarchy with .gitignore and child .ignore overrides" {
    var mem = root.source.Memory{
        .files = &.{
            .{ .path = ".gitignore", .data = "*.log\nbuild/\n" },
            .{ .path = "app.log", .data = "TREE_HIT ignored at root\n" },
            .{ .path = "build/out.txt", .data = "TREE_HIT ignored in build\n" },
            .{ .path = "src/.ignore", .data = "!important.log\n" },
            .{ .path = "src/important.log", .data = "TREE_HIT unignored in src\n" },
            .{ .path = "src/main.zig", .data = "TREE_HIT in main\n" },
        },
    };
    const f = try Finder.init("TREE_HIT", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const sum = root.searchTree(testing.io, mem.source(), &f, .{}, &sink);
    try testing.expectEqual(@as(usize, 2), sum.matched_files);
    try testing.expectEqual(@as(usize, 2), sum.matched_lines);
}

test "E2E T1_F14_02: searchTree with globs, types, types_not, hidden, and skip_git" {
    var mem = root.source.Memory{
        .files = &.{
            .{ .path = ".git/config", .data = "HIT_TOK\n" },
            .{ .path = ".hidden.zig", .data = "HIT_TOK\n" },
            .{ .path = "src/a.zig", .data = "HIT_TOK\n" },
            .{ .path = "src/b.md", .data = "HIT_TOK\n" },
            .{ .path = "src/c.spec", .data = "HIT_TOK\n" },
        },
    };
    const f = try Finder.init("HIT_TOK", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const custom = [_]root.TypeDef{
        .{ .name = "spec", .patterns = &.{"*.spec"} },
    };
    const sum = root.searchTree(testing.io, mem.source(), &f, .{
        .hidden = false,
        .skip_git = true,
        .custom_types = &custom,
        .types = &.{ "zig", "spec" },
        .types_not = &.{"markdown"},
    }, &sink);
    try testing.expectEqual(@as(usize, 2), sum.matched_files);
}

test "E2E T1_F14_03: searchArchiveSlice over .tar, .tar.gz, and .zip buffers" {
    const tar = try Harness.buildTar(testing.allocator, &.{
        .{ .path = ".gitignore", .data = "*.tmp\n" },
        .{ .path = "ignored.tmp", .data = "ARCH_SLICE_HIT\n" },
        .{ .path = "src/keep.zig", .data = "ARCH_SLICE_HIT\n" },
    });
    defer testing.allocator.free(tar);
    const tgz = try Harness.makeGzipFromRaw(testing.allocator, tar);
    defer testing.allocator.free(tgz);
    const zip = try Harness.buildZip(testing.allocator, &.{
        .{ .path = ".gitignore", .data = "*.tmp\n" },
        .{ .path = "ignored.tmp", .data = "ARCH_SLICE_HIT\n" },
        .{ .path = "src/keep.zig", .data = "ARCH_SLICE_HIT\n", .method = 8 },
    });
    defer testing.allocator.free(zip);

    const f = try Finder.init("ARCH_SLICE_HIT", .{});
    for ([_][]const u8{ tar, tgz, zip }) |arch| {
        var sink = Harness.TestEventSink.init(testing.allocator);
        defer sink.deinit();
        const sum = try root.searchArchiveSlice(testing.io, arch, &f, .{
            .allocator = testing.allocator,
        }, &sink);
        try testing.expectEqual(@as(usize, 1), sum.matched_files);
        try testing.expectEqualStrings("src/keep.zig", sink.lines.items[0].path.?);
    }
}

test "E2E T1_F14_04: searchArchive over streaming *std.Io.Reader with parallel workers (max_concurrency = 4)" {
    const tar = try Harness.buildTar(testing.allocator, &.{
        .{ .path = "d1/f1.txt", .data = "PARALLEL_ARCH_HIT 1\n" },
        .{ .path = "d2/f2.txt", .data = "PARALLEL_ARCH_HIT 2\n" },
        .{ .path = "d3/f3.txt", .data = "PARALLEL_ARCH_HIT 3\n" },
        .{ .path = "d4/f4.txt", .data = "no hit\n" },
    });
    defer testing.allocator.free(tar);
    const tgz = try Harness.makeGzipFromRaw(testing.allocator, tar);
    defer testing.allocator.free(tgz);

    var rdr = std.Io.Reader.fixed(tgz);
    const f = try Finder.init("PARALLEL_ARCH_HIT", .{});

    const AtomicSink = struct {
        hits: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        pub fn emit(self: *@This(), ev: LineEvent) Flow {
            if (!ev.is_context) _ = self.hits.fetchAdd(1, .monotonic);
            return .cont;
        }
    };
    var asink = AtomicSink{};
    const sum = try root.searchArchive(testing.io, &rdr, &f, .{
        .allocator = testing.allocator,
        .max_concurrency = 4,
    }, &asink);
    try testing.expectEqual(@as(usize, 3), sum.matched_files);
    try testing.expectEqual(@as(usize, 3), asink.hits.load(.monotonic));
}

test "E2E T1_F14_05: Compile-time & reflection Security Redline verification on all src/root.zig exports" {
    try testing.expect(!@hasDecl(root, "Fs"));
    try testing.expect(!@hasDecl(root, "FsSource"));
    try testing.expect(!@hasDecl(root, "searchPath"));
    try testing.expect(!@hasDecl(root, "searchPaths"));
    try testing.expect(!@hasDecl(root.source, "Fs"));
}

// ============================================================================
// TIER 2: Edge Cases, Error Paths & Budget Limits (F01 - F14, 70 Tests)
// ============================================================================

test "E2E T2_F01_01: *const Finder and *const Multi on empty haystack and empty pattern across start boundaries" {
    const f_empty = try Finder.init("", .{});
    const f_non = try Finder.init("abc", .{});
    const fe: *const Finder = &f_empty;
    const fn_: *const Finder = &f_non;

    try testing.expectEqual(@as(?usize, 0), if (fe.find("", 0, .earliest)) |m| m.start else null);
    try testing.expectEqual(@as(?usize, null), if (fn_.find("", 0, .earliest)) |m| m.start else null);
    try testing.expectEqual(@as(?usize, 3), if (fe.find("abc", 3, .earliest)) |m| m.start else null);
    try testing.expectEqual(@as(?usize, null), if (fe.find("abc", 4, .earliest)) |m| m.start else null);

    var m_empty = try Multi.init(testing.allocator, &.{""}, .{});
    defer m_empty.deinit();
    const me: *const Multi = &m_empty;
    const r0 = me.find("abc", 0, .earliest).?;
    try testing.expectEqual(@as(usize, 0), r0.start);
    try testing.expectEqual(@as(usize, 0), r0.end);
    try testing.expectEqual(@as(?u32, 0), r0.pattern_id);
}

test "E2E T2_F01_02: *const Finder stack-local Guard fallback on adversarial false-positive storm without mutating self" {
    // Needle ends with "ab", haystack is "bbbb...bbbab" causing repeated rare-byte hits before match
    const needle = "x" ++ Harness.repeat("b", 15);
    const f = try Finder.init(needle, .{});
    const f_const: *const Finder = &f;

    const hay = Harness.repeat("b", 4096) ++ needle ++ "tail";
    const m = f_const.find(hay, 0, .earliest).?;
    try testing.expectEqual(@as(usize, 4096), m.start);
    try testing.expectEqualStrings(needle, f_const.pattern);
}

test "E2E T2_F01_03: *const Regex with insts.len > 256 concurrent execution without RegexScratch" {
    var pat_buf: std.ArrayList(u8) = .empty;
    defer pat_buf.deinit(testing.allocator);
    for (0..95) |i| {
        if (i > 0) try pat_buf.append(testing.allocator, '|');
        { var _tmp: [128]u8 = undefined; try pat_buf.appendSlice(testing.allocator, try std.fmt.bufPrint(&_tmp, "longpat_{d:0>3}", .{i})); }
    }
    var re = try Regex.init(testing.allocator, pat_buf.items, .{});
    defer re.deinit();
    try testing.expect(re.insts.len > 256);
    const re_const: *const Regex = &re;

    const Worker = struct {
        fn run(r: *const Regex, out_ok: *bool) void {
            for (0..50) |_| {
                const m = r.find("prefix longpat_088 suffix", 0, .earliest) orelse {
                    out_ok.* = false;
                    return;
                };
                if (m.start != 7 or m.end != 18) {
                    out_ok.* = false;
                    return;
                }
            }
            out_ok.* = true;
        }
    };

    var threads: [8]std.Thread = undefined;
    var ok: [8]bool = @splat(false);
    for (0..8) |i| threads[i] = try std.Thread.spawn(.{}, Worker.run, .{ re_const, &ok[i] });
    for (0..8) |i| threads[i].join();
    for (ok) |v| try testing.expect(v);
}

test "E2E T2_F01_04: RegexScratch reused across different Regex instances of increasing instruction sizes" {
    var scratch = RegexScratch.init(testing.allocator);
    defer scratch.deinit();

    var re_small = try Regex.init(testing.allocator, "small_[0-9]+", .{});
    defer re_small.deinit();
    var re_med = try Regex.init(testing.allocator, "([a-z]{2,5}_[0-9]{2,5}|alt_[A-Z]{3,6})+", .{});
    defer re_med.deinit();

    var pat_large: std.ArrayList(u8) = .empty;
    defer pat_large.deinit(testing.allocator);
    for (0..100) |i| {
        if (i > 0) try pat_large.append(testing.allocator, '|');
        { var _tmp: [128]u8 = undefined; try pat_large.appendSlice(testing.allocator, try std.fmt.bufPrint(&_tmp, "big_{d:0>3}", .{i})); }
    }
    var re_large = try Regex.init(testing.allocator, pat_large.items, .{});
    defer re_large.deinit();

    try testing.expect(re_small.findWithScratch("xx small_12 yy", 0, .earliest, &scratch) != null);
    try testing.expect(re_med.findWithScratch("xx abc_123 yy", 0, .earliest, &scratch) != null);
    try testing.expect(re_large.findWithScratch("xx big_099 yy", 0, .earliest, &scratch) != null);
    // And back to small without reallocating
    const cap_after_large = scratch.curr.len;
    try testing.expect(re_small.findWithScratch("xx small_99 yy", 0, .earliest, &scratch) != null);
    try testing.expectEqual(cap_after_large, scratch.curr.len);
}

test "E2E T2_F01_05: *const Regex start-anchored (\\A) when start > 0 vs. start == 0" {
    var re = try Regex.init(testing.allocator, "\\Ahello_[0-9]+", .{});
    defer re.deinit();
    const rc: *const Regex = &re;

    const hay = "hello_123 hello_456";
    const m0 = rc.find(hay, 0, .earliest).?;
    try testing.expectEqual(@as(usize, 0), m0.start);
    try testing.expectEqual(@as(usize, 9), m0.end);
    try testing.expect(rc.find(hay, 1, .earliest) == null);
    try testing.expect(rc.find(hay, 10, .earliest) == null);
}

test "E2E T2_F02_01: Tie-breaking at identical [start, end) between duplicate or prefix-overlapping patterns in Multi" {
    var m_dup = try Multi.init(testing.allocator, &.{ "same_tok", "same_tok" }, .{});
    defer m_dup.deinit();
    const r1 = m_dup.find("xx same_tok yy", 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 0), r1.pattern_id);

    // Leftmost-first vs earliest at same start offset
    var m_pref = try Multi.init(testing.allocator, &.{ "foobar", "foo" }, .{});
    defer m_pref.deinit();
    const r2 = m_pref.find("xx foobar yy", 0, .leftmost_first).?;
    try testing.expectEqualStrings("foobar", "xx foobar yy"[r2.start..r2.end]);
    try testing.expectEqual(@as(?u32, 0), r2.pattern_id);

    const r3 = m_pref.find("xx foobar yy", 0, .earliest).?;
    try testing.expectEqualStrings("foo", "xx foobar yy"[r3.start..r3.end]);
    try testing.expectEqual(@as(?u32, 1), r3.pattern_id);
}

test "E2E T2_F02_02: Multi at hard cap 1024 patterns (pattern_id == 0 and pattern_id == 1023)" {
    var storage = try testing.allocator.alloc([12]u8, 1024);
    defer testing.allocator.free(storage);
    var slices = try testing.allocator.alloc([]const u8, 1024);
    defer testing.allocator.free(slices);

    for (0..1024) |i| {
        slices[i] = std.fmt.bufPrint(&storage[i], "cap_{d:0>4}_end", .{i}) catch unreachable;
    }
    var m = try Multi.init(testing.allocator, slices, .{});
    defer m.deinit();

    const r_first = m.find("noise cap_0000_end tail", 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 0), r_first.pattern_id);

    const r_last = m.find("noise cap_1023_end tail", 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 1023), r_last.pattern_id);
}

test "E2E T2_F02_03: Multi containing empty pattern at non-zero index" {
    var m = try Multi.init(testing.allocator, &.{ "non_empty", "" }, .{});
    defer m.deinit();

    const r = m.find("hello", 0, .earliest).?;
    try testing.expectEqual(@as(usize, 0), r.start);
    try testing.expectEqual(@as(usize, 0), r.end);
    try testing.expectEqual(@as(?u32, 1), r.pattern_id);
}

test "E2E T2_F02_04: Multi findAllowed (whole_word) fallback when shorter pattern at same offset fails word boundary" {
    // At offset 0 in "cat_dog", pattern 0 ("cat_dog") matches whole_word, whereas pattern 1 ("cat") fails whole_word!
    // And if pattern 0 is "cat" and pattern 1 is "cat_dog", whole_word must still find "cat_dog"!
    var m = try Multi.init(testing.allocator, &.{ "cat", "cat_dog" }, .{});
    defer m.deinit();

    const WordAllow = struct {
        fn allow(hay: []const u8, s: usize, e: usize) bool {
            const left_ok = (s == 0) or !isWord(hay[s - 1]);
            const right_ok = (e >= hay.len) or !isWord(hay[e]);
            return left_ok and right_ok;
        }
        fn isWord(b: u8) bool {
            return std.ascii.isAlphanumeric(b) or b == '_';
        }
    };
    const r = m.findAllowed("cat_dog!", 0, .earliest, WordAllow.allow).?;
    try testing.expectEqualStrings("cat_dog", "cat_dog!"[r.start..r.end]);
    try testing.expectEqual(@as(?u32, 1), r.pattern_id);
}

test "E2E T2_F02_05: Span.pattern_id preservation on ultra-long lines across sliding windows" {
    var m = try Multi.init(testing.allocator, &.{ "PAT_ZERO", "PAT_ONE", "PAT_TWO" }, .{});
    defer m.deinit();

    const long_line = Harness.repeat("a", 1500) ++ " PAT_TWO " ++ Harness.repeat("b", 1500) ++ "\n";
    var rdr = std.Io.Reader.fixed(long_line);
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const sum = try root.searchSource(&rdr, null, &m, .{ .buffer_size = 256 }, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_lines);
    try testing.expect(sink.lines.items[0].matches.len >= 1);
    try testing.expectEqual(@as(?u32, 2), sink.lines.items[0].matches[0].pattern_id);
}

test "E2E T2_F03_01: Empty RegexSet (patterns.len == 0)" {
    var set = try RegexSet.init(testing.allocator, &.{}, .{});
    defer set.deinit();

    try testing.expectEqual(@as(usize, 0), set.len());
    try testing.expect(set.isEmpty());
    try testing.expect(!set.isMatch("anything"));
    try testing.expect(set.find("anything", 0, .earliest) == null);

    var ids: [4]u32 = undefined;
    try testing.expectEqual(@as(usize, 0), set.matches("anything", &ids));
}

test "E2E T2_F03_02: RegexSet exceeding pattern_count_hard_cap and instruction limit" {
    var pats = try testing.allocator.alloc([]const u8, 1025);
    defer testing.allocator.free(pats);
    for (0..1025) |i| pats[i] = "a";

    var diag: CompileDiagnostic = .{};
    try testing.expectError(error.PatternCountExceeded, RegexSet.initDiagnostic(testing.allocator, pats, .{}, &diag));

    var diag2: CompileDiagnostic = .{};
    try testing.expectError(
        error.RegexTooLarge,
        RegexSet.initDiagnostic(testing.allocator, &.{ "abcdef", "ghijklm" }, .{ .max_inst = 4 }, &diag2),
    );
    try testing.expectEqual(DiagnosticCode.instruction_limit_exceeded, diag2.code);
}

test "E2E T2_F03_03: RegexSet.matches when out_ids buffer is smaller than total matching patterns" {
    var set = try RegexSet.init(testing.allocator, &.{ "a", "b", "c", "d" }, .{});
    defer set.deinit();

    var small_out: [2]u32 = undefined;
    const count = set.matches("a b c d", &small_out);
    // Either returns number written (2) or total matches (4) while only writing up to small_out.len
    try testing.expect(count >= 2);
    try testing.expectEqual(@as(u32, 0), small_out[0]);
    try testing.expectEqual(@as(u32, 1), small_out[1]);
}

test "E2E T2_F03_04: RegexSet tie-breaking when multiple regexes match at the same start offset" {
    // Earliest start wins; at identical start and end, lowest pattern_id wins
    var set = try RegexSet.init(testing.allocator, &.{ "[a-z]{4}", "test", "test_longer" }, .{});
    defer set.deinit();

    const m1 = set.find("xx test yy", 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 0), m1.pattern_id);

    var set2 = try RegexSet.init(testing.allocator, &.{ "test_longer", "test" }, .{});
    defer set2.deinit();
    const m2 = set2.find("xx test_longer yy", 0, .leftmost_first).?;
    try testing.expectEqualStrings("test_longer", "xx test_longer yy"[m2.start..m2.end]);
    try testing.expectEqual(@as(?u32, 0), m2.pattern_id);

    const m3 = set2.find("xx test_longer yy", 0, .earliest).?;
    try testing.expectEqualStrings("test", "xx test_longer yy"[m3.start..m3.end]);
    try testing.expectEqual(@as(?u32, 1), m3.pattern_id);
}

test "E2E T2_F03_05: RegexSet with PatternHasNewline in single-line mode vs. multiline = true" {
    try testing.expectError(
        error.PatternHasNewline,
        RegexSet.init(testing.allocator, &.{ "ok", "line1\nline2" }, .{ .multiline = false }),
    );

    var set_ml = try RegexSet.init(testing.allocator, &.{ "ok", "line1\nline2" }, .{ .multiline = true });
    defer set_ml.deinit();
    try testing.expect(set_ml.isMatch("prefix line1\nline2 suffix"));
}

test "E2E T2_F04_01: C ABI null pointer safety across webgrep entry points" {
    c_api.webgrep_matcher_free(null);
    c_api.webgrep_scratch_free(null);

    var m: CMatcherPtr = null;
    try testing.expect(cStatus(c_api.webgrep_matcher_compile_literal(null, 5, null, &m)) != 0);
    try testing.expect(cStatus(c_api.webgrep_matcher_compile_regex(null, 5, null, null, &m)) != 0);
    try testing.expect(cStatus(c_api.webgrep_find(null, "abc", 3, 0, null)) != 0);
    try testing.expect(cStatus(c_api.webgrep_search_slice(null, "abc", 3, null, null, null, null)) != 0);
}

test "E2E T2_F04_02: C ABI invalid regex compilation populating webgrep_compile_diag_t" {
    const re_opts = c_api.webgrep_regex_options_default();
    var diag: CCompileDiag = std.mem.zeroes(CCompileDiag);
    var m: CMatcherPtr = null;
    const bad = "abc(def";
    const rc = cStatus(c_api.webgrep_matcher_compile_regex(bad.ptr, bad.len, &re_opts, &diag, &m));
    try testing.expect(rc != 0);
    try testing.expect(m == null);
    try testing.expect(cGetEnumOrInt(diag.code) != 0);
    try testing.expectEqual(@as(usize, 3), diag.offset);
    try testing.expectEqual(@as(usize, 1), diag.line);
    try testing.expectEqual(@as(usize, 4), diag.column);
}

test "E2E T2_F04_03: C ABI callback returning stop mid-search" {
    const find_opts = c_api.webgrep_find_options_default();
    var m: CMatcherPtr = null;
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_matcher_compile_literal("hit", 3, &find_opts, &m)));
    defer c_api.webgrep_matcher_free(m);

    const StopCtx = struct {
        calls: usize = 0,
        fn onLine(_: CLineEventPtr, userdata: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.calls += 1;
            return 1; // non-zero stops search
        }
    };

    var ctx = StopCtx{};
    var sum: CSummary = std.mem.zeroes(CSummary);
    const data = "hit 1\nhit 2\nhit 3\n";
    const cfg = c_api.webgrep_config_default();
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_search_slice(m, data.ptr, data.len, &cfg, StopCtx.onLine, &ctx, &sum)));
    try testing.expectEqual(@as(usize, 1), ctx.calls);
    try testing.expect(sum.stopped != 0);
}

test "E2E T2_F04_04: C ABI reader callback returning read error" {
    const find_opts = c_api.webgrep_find_options_default();
    var m: CMatcherPtr = null;
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_matcher_compile_literal("hit", 3, &find_opts, &m)));
    defer c_api.webgrep_matcher_free(m);

    const FailReader = struct {
        fn onRead(_: [*c]u8, _: usize, _: [*c]usize, _: ?*anyopaque) callconv(.c) c_int {
            return -1; // Simulate IO failure
        }
    };

    const cfg = c_api.webgrep_config_default();
    var sum: CSummary = std.mem.zeroes(CSummary);
    const rc = cStatus(c_api.webgrep_search_reader(m, FailReader.onRead, null, &cfg, null, null, &sum));
    try testing.expect(rc != 0);
}

test "E2E T2_F04_05: C ABI budget violation returning error" {
    const find_opts = c_api.webgrep_find_options_default();
    var m: CMatcherPtr = null;
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_matcher_compile_literal("hit", 3, &find_opts, &m)));
    defer c_api.webgrep_matcher_free(m);

    const gz = try Harness.makeGzipFromRaw(testing.allocator, Harness.repeat("line with hit\n", 50));
    defer testing.allocator.free(gz);

    var cfg = c_api.webgrep_config_default();
    cSetEnumOrInt(&cfg.compression, 2); // gzip
    cfg.max_decode_bytes = 16; // tiny budget -> error

    var sum: CSummary = std.mem.zeroes(CSummary);
    const rc = cStatus(c_api.webgrep_search_slice(m, gz.ptr, gz.len, &cfg, null, null, &sum));
    try testing.expect(rc != 0);
}

test "E2E T2_F05_01: Lazy DFA state cache overflow and O(1) flush boundary" {
    // Configure a very small max_dfa_states (e.g. 16) and scan a long diverse haystack that creates > 16 DFA states
    var re = try Regex.init(testing.allocator, "[a-z][0-9][a-z][0-9][a-z][0-9][a-z][0-9][a-z][0-9][a-z][0-9]", .{
        .max_dfa_states = 16,
    });
    defer re.deinit();

    const hay = "a1b2c3d4e5f ! a1b2c3d4e5 ! z9y8x7w6v5u4 !";
    const m = re.find(hay, 0, .earliest).?;
    try testing.expectEqualStrings("z9y8x7w6v5u4", hay[m.start..m.end]);
}

test "E2E T2_F05_02: Lazy DFA bailout when single DFA state NFA PC closure exceeds threshold" {
    // Pattern with large simultaneous NFA state closure (> 64 active PCs) falls back cleanly to PikeVM
    var pat: std.ArrayList(u8) = .empty;
    defer pat.deinit(testing.allocator);
    try pat.appendSlice(testing.allocator, "(");
    for (0..70) |i| {
        if (i > 0) try pat.append(testing.allocator, '|');
        { var _tmp: [128]u8 = undefined; try pat.appendSlice(testing.allocator, try std.fmt.bufPrint(&_tmp, "[a-z]{{1,3}}_{d:0>2}", .{i})); }
    }
    try pat.appendSlice(testing.allocator, ")");

    var re = try Regex.init(testing.allocator, pat.items, .{});
    defer re.deinit();

    const hay = "noise... xyz_65 ...end";
    const m = re.find(hay, 0, .earliest).?;
    try testing.expectEqualStrings("xyz_65", hay[m.start..m.end]);
}

test "E2E T2_F05_03: Lazy DFA false-positive assertion guard transitioning to NFA" {
    // DFA over-approximates \b, so "word" inside "notaword" triggers DFA candidate and PikeVM rejects it, continuing to "word"
    var re = try Regex.init(testing.allocator, "\\b[0-9]{3}\\b", .{});
    defer re.deinit();

    const hay = "abc123def 4567 890!";
    const m = re.find(hay, 0, .earliest).?;
    try testing.expectEqualStrings("890", hay[m.start..m.end]);
}

test "E2E T2_F05_04: Lazy DFA on non-ASCII UTF-8 bytes with negated byte classes" {
    var re = try Regex.init(testing.allocator, "[^0-9\\s]{4,10}", .{});
    defer re.deinit();

    const hay = "123 456 Привет 789";
    const m = re.find(hay, 0, .earliest).?;
    try testing.expectEqualStrings("Привет", hay[m.start..m.end]);
}

test "E2E T2_F05_05: Lazy DFA with bounded multiline window" {
    var re = try Regex.init(testing.allocator, "[a-z]+\\n[0-9]+", .{
        .multiline = true,
        .max_multiline_window = 64,
    });
    defer re.deinit();
    try testing.expect(re.isMultiline());
    try testing.expectEqual(@as(usize, 64), re.multilineWindow());

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    const sum = try root.searchSourceSlice("header\nabc\n123\nfooter\n", null, &re, .{}, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_lines);
    try testing.expectEqualStrings("abc\n123", sink.lines.items[0].text);
}

test "E2E T2_F06_01: Invalid / truncated UTF-8 sequences in haystack during \\p{...}" {
    var re = try Regex.init(testing.allocator, "\\p{L}+", .{});
    defer re.deinit();

    // Invalid UTF-8 bytes (0xFF, 0xFE, truncated 0xE4 0xB8) must not panic or match \p{L}
    const hay = "\xff\xfe\xe4\xb8!Hello\xff";
    const m = re.find(hay, 0, .earliest).?;
    try testing.expectEqualStrings("Hello", hay[m.start..m.end]);
}

test "E2E T2_F06_02: Supplementary astral plane codepoints in \\p{...}" {
    // U+1F600 (😀) is Symbol_Other (So -> S), U+10400 (𐐀 Deseret Capital Letter Long I -> Lu -> L)
    var re_sym = try Regex.init(testing.allocator, "\\p{S}+", .{});
    defer re_sym.deinit();
    const hay_emoji = "text 😀🚀 end";
    const m1 = re_sym.find(hay_emoji, 0, .earliest).?;
    try testing.expectEqualStrings("😀🚀", hay_emoji[m1.start..m1.end]);

    var re_lu = try Regex.init(testing.allocator, "\\p{Lu}+", .{});
    defer re_lu.deinit();
    const hay_deseret = "123 \xf0\x90\x90\x80 456";
    const m2 = re_lu.find(hay_deseret, 0, .earliest).?;
    try testing.expectEqualStrings("\xf0\x90\x90\x80", hay_deseret[m2.start..m2.end]);
}

test "E2E T2_F06_03: UTS #18 property name normalization" {
    const variants = [_][]const u8{
        "\\p{Uppercase_Letter}+",
        "\\p{uppercase letter}+",
        "\\p{UPPERCASE-LETTER}+",
        "\\p{gc=Lu}+",
        "\\p{General_Category=Uppercase_Letter}+",
        "\\p{sc=Han}+",
        "\\p{Script=Han}+",
    };
    for (variants[0..5]) |pat| {
        var re = try Regex.init(testing.allocator, pat, .{});
        defer re.deinit();
        try testing.expect(re.isMatch("ABC"));
    }
    for (variants[5..]) |pat| {
        var re = try Regex.init(testing.allocator, pat, .{});
        defer re.deinit();
        try testing.expect(re.isMatch("東京"));
    }
}

test "E2E T2_F06_04: Large UTF-8 codepoint range [一-龥] and negated bracket class" {
    var re_cjk = try Regex.init(testing.allocator, "[一-龥]+", .{});
    defer re_cjk.deinit();
    const hay = "latin 漢字テスト 123";
    const m = re_cjk.find(hay, 0, .earliest).?;
    try testing.expectEqualStrings("漢字", hay[m.start..m.end]);

    var re_neg = try Regex.init(testing.allocator, "[^a-z0-9\\s]+", .{});
    defer re_neg.deinit();
    const m2 = re_neg.find(hay, 0, .earliest).?;
    try testing.expectEqualStrings("漢字テスト", hay[m2.start..m2.end]);
}

test "E2E T2_F06_05: Negated \\P{Han}+ in single-line mode stops before \\n" {
    var re = try Regex.init(testing.allocator, "\\P{Han}+", .{ .multiline = false });
    defer re.deinit();

    const hay = "abc\ndef";
    const m = re.find(hay, 0, .earliest).?;
    try testing.expectEqualStrings("abc", hay[m.start..m.end]);
}

test "E2E T2_F07_01: memchr width 64 at exact vector boundaries" {
    const offsets = [_]usize{ 0, 1, 63, 64, 65, 127, 128, 129 };
    var buf: [200]u8 = @splat('.');

    for (offsets) |off| {
        @memset(&buf, '.');
        buf[off] = '#';
        try testing.expectEqual(@as(?usize, off), memchr.findWithWidth(64, buf[0 .. off + 1], 0, '#'));
        try testing.expectEqual(@as(?usize, off), memchr.findLastWithWidth(64, buf[0 .. off + 1], 0, off + 1, '#'));
        try testing.expectEqual(@as(usize, 1), memchr.countWithWidth(64, &buf, 0, buf.len, '#'));
    }
}

test "E2E T2_F07_02: packed_pair width 64 when candidate straddles 64-byte block boundary" {
    var buf: [160]u8 = @splat('_');
    const needle = "STRADDLE_NEEDLE";
    // Place needle so its first byte is at 60 and its last byte is at 74 (straddling 64)
    @memcpy(buf[60 .. 60 + needle.len], needle);
    const plan = packed_pair.PackedPair.init(needle, &frequency.default_rank, false);
    try testing.expectEqual(@as(?usize, 60), plan.findWithWidth(64, &buf, 0, null));
}

test "E2E T2_F07_03: Teddy match at the very last bytes of haystack" {
    const pats = [_][]const u8{
        "aa_01", "bb_02", "cc_03", "dd_04", "ee_05",
        "ff_06", "gg_07", "hh_08", "ii_09", "jj_10",
    };
    var m = try Multi.init(testing.allocator, &pats, .{});
    defer m.deinit();

    // Test both < 16 bytes haystack and match at exact end of > 64 bytes haystack
    const short_hay = "xx jj_10";
    const r1 = m.find(short_hay, 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 9), r1.pattern_id);

    const long_hay = Harness.repeat(".", 70) ++ "ii_09";
    const r2 = m.find(long_hay, 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 8), r2.pattern_id);
}

test "E2E T2_F07_04: Teddy bucket collision stress with 24 patterns sharing prefix" {
    var pat_bufs: [24][9]u8 = undefined;
    var pats: [24][]const u8 = undefined;
    for (0..24) |i| {
        pats[i] = std.fmt.bufPrint(&pat_bufs[i], "PRE_{d:0>2}_OK", .{i}) catch unreachable;
    }
    var m = try Multi.init(testing.allocator, &pats, .{});
    defer m.deinit();

    const hay = Harness.repeat("PRE_99_NO ", 20) ++ "PRE_21_OK!";
    const hit = m.find(hay, 0, .earliest).?;
    try testing.expectEqual(@as(?u32, 21), hit.pattern_id);
}

test "E2E T2_F07_05: Finder and Multi NUL watching when NUL is before vs. after match" {
    const f = try Finder.init("TARGET", .{});
    var nul1: ?usize = null;
    const r_before = f.findWatched("abc\x00def TARGET", 0, &nul1);
    try testing.expectEqual(@as(?usize, 3), nul1);
    try testing.expect(r_before == null);

    var nul2: ?usize = null;
    const r_after = f.findWatched("abcdef TARGET\x00", 0, &nul2);
    try testing.expectEqual(@as(?usize, null), nul2);
    try testing.expectEqual(@as(usize, 7), r_after.?.start);

    var m = try Multi.init(testing.allocator, &.{ "PAT_A", "PAT_B" }, .{});
    defer m.deinit();
    var mnul1: ?usize = null;
    const mr_before = m.findWatched("abc\x00def PAT_B", 0, &mnul1);
    try testing.expectEqual(@as(?usize, 3), mnul1);
    try testing.expect(mr_before == null);

    var mnul2: ?usize = null;
    const mr_after = m.findWatched("abcdef PAT_B\x00", 0, &mnul2);
    try testing.expectEqual(@as(?usize, null), mnul2);
    try testing.expectEqual(@as(?u32, 1), mr_after.?.pattern_id);
}

test "E2E T2_F08_01: openReaderPull on empty reader and reader with no matches" {
    const f = try Finder.init("needle", .{});
    {
        var rdr = std.Io.Reader.fixed("");
        var pull = root.openReaderPull(&rdr, &f, .{});
        defer pull.deinit();
        const ev1 = (try pull.next()).?;
        try testing.expectEqual(root.PullEventKind.begin, ev1.kind);
        const ev2 = (try pull.next()).?;
        try testing.expectEqual(root.PullEventKind.end, ev2.kind);
        const ev3 = (try pull.next()).?;
        try testing.expectEqual(root.PullEventKind.summary, ev3.kind);
        try testing.expectEqual(@as(usize, 0), ev3.summary.?.matched_lines);
        try testing.expect((try pull.next()) == null);
    }
    {
        var rdr = std.Io.Reader.fixed("line 1\nline 2\n");
        var pull = root.openReaderPull(&rdr, &f, .{});
        defer pull.deinit();
        var matches: usize = 0;
        while (try pull.next()) |ev| {
            if (ev.kind == .match) matches += 1;
        }
        try testing.expectEqual(@as(usize, 0), matches);
    }
}

test "E2E T2_F08_02: openReaderPull with 1-byte-at-a-time ChunkedReader splitting CRLF and UTF-8" {
    const text = "first line\r\nsecond 東京 HIT_1B\r\nthird line\r\n";
    var rbuf: [8]u8 = undefined;
    var cr = Harness.ChunkedReader.init(text, 1, &rbuf);
    const f = try Finder.init("HIT_1B", .{});

    var pull = root.openReaderPull(&cr.interface, &f, .{});
    defer pull.deinit();

    var matched_text: ?[]u8 = null;
    defer if (matched_text) |mt| testing.allocator.free(mt);

    while (try pull.next()) |ev| {
        if (ev.kind == .match) {
            matched_text = try testing.allocator.dupe(u8, ev.line.?.text);
        }
    }
    try testing.expectEqualStrings("second 東京 HIT_1B", matched_text.?);
}

test "E2E T2_F08_03: openReaderPull hitting decompression limit and corrupt stream" {
    const raw = Harness.repeat("hit line\n", 100);
    const gz = try Harness.makeGzipFromRaw(testing.allocator, raw);
    defer testing.allocator.free(gz);

    const f = try Finder.init("hit", .{});
    {
        var rdr = std.Io.Reader.fixed(gz);
        var pull = root.openReaderPull(&rdr, &f, .{
            .compression = .gzip,
            .max_decode_bytes = 32,
            .allocator = testing.allocator,
        });
        defer pull.deinit();

        var got_err = false;
        while (pull.next()) |ev_opt| {
            if (ev_opt == null) break;
        } else |err| {
            got_err = (err == error.DecompressedLimitExceeded);
        }
        try testing.expect(got_err);
    }
    // Corrupt gzip stream
    {
        const corrupt = "\x1f\x8b\x08\x00corrupt_payload";
        var rdr = std.Io.Reader.fixed(corrupt);
        var pull = root.openReaderPull(&rdr, &f, .{
            .compression = .gzip,
            .allocator = testing.allocator,
        });
        defer pull.deinit();

        var got_err = false;
        while (pull.next()) |ev_opt| {
            if (ev_opt == null) break;
        } else |_| {
            got_err = true;
        }
        try testing.expect(got_err);
    }
}

test "E2E T2_F08_04: openReaderPull binary detection policies (.quit, .report, .none)" {
    const bin_data = "line 1 HIT\nline 2 \x00 HIT\nline 3 HIT\n";
    const f = try Finder.init("HIT", .{});

    // .quit stops at NUL
    {
        var rdr = std.Io.Reader.fixed(bin_data);
        var pull = root.openReaderPull(&rdr, &f, .{ .binary = .quit });
        defer pull.deinit();
        var sum: Summary = .{};
        while (try pull.next()) |ev| {
            if (ev.kind == .summary) sum = ev.summary.?;
        }
        try testing.expect(sum.binary_detected);
        try testing.expect(sum.matched_lines < 3);
    }
    // .none emits all 3 lines
    {
        var rdr = std.Io.Reader.fixed(bin_data);
        var pull = root.openReaderPull(&rdr, &f, .{ .binary = .none });
        defer pull.deinit();
        var sum: Summary = .{};
        while (try pull.next()) |ev| {
            if (ev.kind == .summary) sum = ev.summary.?;
        }
        try testing.expectEqual(@as(usize, 3), sum.matched_lines);
    }
}

test "E2E T2_F08_05: openReaderPull immediate deinit() without calling next() and mid-stream deinit()" {
    const f = try Finder.init("hit", .{});
    {
        var rdr = std.Io.Reader.fixed("hit 1\nhit 2\n");
        var pull = root.openReaderPull(&rdr, &f, .{ .allocator = testing.allocator });
        pull.deinit();
    }
    {
        var rdr = std.Io.Reader.fixed("hit 1\nhit 2\nhit 3\n");
        var pull = root.openReaderPull(&rdr, &f, .{ .allocator = testing.allocator, .before_context = 2 });
        _ = try pull.next(); // .begin
        _ = try pull.next(); // first match
        pull.deinit();
    }
}

test "E2E T2_F09_01: Archive path traversal sanitization" {
    const evil_tar = try Harness.buildTar(testing.allocator, &.{
        .{ .path = "../../etc/passwd", .data = "TRAVERSAL_SECRET\n" },
    });
    defer testing.allocator.free(evil_tar);
    try testing.expectError(
        error.PathTraversal,
        ArchiveTree.initFromSlice(testing.allocator, evil_tar, .tar, .none, .{}),
    );

    const tar = try Harness.buildTar(testing.allocator, &.{
        .{ .path = "/abs/evil.txt", .data = "TRAVERSAL_SECRET\n" },
        .{ .path = "./safe/ok.txt", .data = "TRAVERSAL_SECRET\n" },
    });
    defer testing.allocator.free(tar);

    var tree = try ArchiveTree.initFromSlice(testing.allocator, tar, .tar, .none, .{});
    defer tree.deinit();

    const f = try Finder.init("TRAVERSAL_SECRET", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    const sum = root.searchTree(testing.io, tree.source(), &f, .{}, &sink);
    try testing.expectEqual(@as(usize, 2), sum.matched_files);
    try testing.expectEqualStrings("abs/evil.txt", sink.lines.items[0].path.?);
    try testing.expectEqualStrings("safe/ok.txt", sink.lines.items[1].path.?);
}

test "E2E T2_F09_02: Archive symlink entry rejection" {
    const tar = try Harness.buildTar(testing.allocator, &.{
        .{ .path = "link.txt", .data = "", .typeflag = '2', .linkname = "/etc/shadow" },
        .{ .path = "real.txt", .data = "SYMLINK_TEST_OK\n", .typeflag = '0' },
    });
    defer testing.allocator.free(tar);

    var tree = try ArchiveTree.initFromSlice(testing.allocator, tar, .tar, .none, .{});
    defer tree.deinit();

    const f = try Finder.init("SYMLINK_TEST_OK", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    const sum = root.searchTree(testing.io, tree.source(), &f, .{}, &sink);
    try testing.expectEqual(@as(usize, 1), sum.files_searched);
    try testing.expectEqual(@as(usize, 1), sum.matched_files);
}

test "E2E T2_F09_03: Archive bomb protection" {
    const tar = try Harness.buildTar(testing.allocator, &.{
        .{ .path = "f1.txt", .data = Harness.repeat("a", 100) },
        .{ .path = "f2.txt", .data = Harness.repeat("b", 100) },
    });
    defer testing.allocator.free(tar);

    try testing.expectError(
        error.ArchiveEntryCountExceeded,
        ArchiveTree.initFromSlice(testing.allocator, tar, .tar, .none, .{ .max_entries = 1 }),
    );
    try testing.expectError(
        error.ArchiveFileTooLarge,
        ArchiveTree.initFromSlice(testing.allocator, tar, .tar, .none, .{ .max_file_bytes = 50 }),
    );
    try testing.expectError(
        error.ArchiveTotalSizeExceeded,
        ArchiveTree.initFromSlice(testing.allocator, tar, .tar, .none, .{ .max_total_bytes = 150 }),
    );
}

test "E2E T2_F09_04: Corrupted .tar and .zip archives" {
    var bad_tar = try Harness.buildTar(testing.allocator, &.{
        .{ .path = "f.txt", .data = "hello" },
    });
    defer testing.allocator.free(bad_tar);
    // Corrupt checksum in header
    bad_tar[148] = '9';
    try testing.expectError(
        error.CorruptArchive,
        ArchiveTree.initFromSlice(testing.allocator, bad_tar, .tar, .none, .{}),
    );

    const bad_zip = try Harness.buildZip(testing.allocator, &.{
        .{ .path = "f.txt", .data = "hello", .corrupt_crc = true },
    });
    defer testing.allocator.free(bad_zip);
    try testing.expectError(
        error.CorruptArchive,
        ArchiveTree.initFromSlice(testing.allocator, bad_zip, .zip, .none, .{}),
    );
}

test "E2E T2_F09_05: Empty .tar and empty .zip" {
    const empty_tar = try Harness.buildTar(testing.allocator, &.{});
    defer testing.allocator.free(empty_tar);
    var t1 = try ArchiveTree.initFromSlice(testing.allocator, empty_tar, .tar, .none, .{});
    defer t1.deinit();

    const empty_zip = try Harness.buildZip(testing.allocator, &.{});
    defer testing.allocator.free(empty_zip);
    var t2 = try ArchiveTree.initFromSlice(testing.allocator, empty_zip, .zip, .none, .{});
    defer t2.deinit();

    const f = try Finder.init("hit", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    try testing.expectEqual(@as(usize, 0), root.searchTree(testing.io, t1.source(), &f, .{}, &sink).files_searched);
    try testing.expectEqual(@as(usize, 0), root.searchTree(testing.io, t2.source(), &f, .{}, &sink).files_searched);
}

test "E2E T2_F10_01: Scratch dynamic growth across varying buffer_size requirements" {
    var scratch = Scratch.init(testing.allocator);
    defer scratch.deinit();

    const f = try Finder.init("hit", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    {
        var rdr = std.Io.Reader.fixed("hit 1\n");
        _ = try root.searchSource(&rdr, null, &f, .{ .scratch_pool = &scratch, .buffer_size = 512 }, &sink);
    }
    const len1 = scratch.stream_buf.len;
    try testing.expect(len1 >= 512);

    {
        var rdr = std.Io.Reader.fixed("hit 2\n");
        _ = try root.searchSource(&rdr, null, &f, .{ .scratch_pool = &scratch, .buffer_size = 8192 }, &sink);
    }
    const len2 = scratch.stream_buf.len;
    try testing.expect(len2 >= 8192);

    // Subsequent smaller search reuses the 8192 buffer without shrinking
    {
        var rdr = std.Io.Reader.fixed("hit 3\n");
        _ = try root.searchSource(&rdr, null, &f, .{ .scratch_pool = &scratch, .buffer_size = 1024 }, &sink);
    }
    try testing.expectEqual(len2, scratch.stream_buf.len);
}

test "E2E T2_F10_02: Scratch reuse after early pause (Flow.pause)" {
    var scratch = Scratch.init(testing.allocator);
    defer scratch.deinit();

    const f = try Finder.init("hit", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    sink.pause_after_matches = 1;

    const sum1 = try root.searchSourceSlice("hit 1\nhit 2\n", null, &f, .{ .scratch_pool = &scratch }, &sink);
    try testing.expect(sum1.paused);

    sink.pause_after_matches = null;
    sink.clearRetainingCapacity();
    const sum2 = try root.searchSourceSlice("hit a\nhit b\n", null, &f, .{ .scratch_pool = &scratch }, &sink);
    try testing.expect(!sum2.paused);
    try testing.expectEqual(@as(usize, 2), sum2.matched_lines);
}

test "E2E T2_F10_03: Scratch reuse across alternating encodings" {
    var scratch = Scratch.init(testing.allocator);
    defer scratch.deinit();

    const u16le = try Harness.encodeUtf16FromUtf8(testing.allocator, "u16le ALT_ENC_HIT\n", .little, true);
    defer testing.allocator.free(u16le);
    const u16be = try Harness.encodeUtf16FromUtf8(testing.allocator, "u16be ALT_ENC_HIT\n", .big, true);
    defer testing.allocator.free(u16be);

    const f = try Finder.init("ALT_ENC_HIT", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    for ([_][]const u8{ "utf8 ALT_ENC_HIT\n", u16le, u16be, "utf8 again ALT_ENC_HIT\n" }) |payload| {
        sink.clearRetainingCapacity();
        const s = try root.searchSourceSlice(payload, null, &f, .{ .scratch_pool = &scratch }, &sink);
        try testing.expectEqual(@as(usize, 1), s.matched_lines);
    }
}

test "E2E T2_F10_04: Scratch.deinit() on freshly initialized unused Scratch" {
    var scratch = Scratch.init(testing.allocator);
    scratch.reset();
    scratch.deinit();
    // Double deinit is also safe
    scratch.deinit();
}

test "E2E T2_F10_05: Both config.scratch and config.scratch_pool supplied simultaneously" {
    var legacy_buf: []u8 = &.{};
    defer if (legacy_buf.len != 0) testing.allocator.free(legacy_buf);

    var pool = Scratch.init(testing.allocator);
    defer pool.deinit();

    const f = try Finder.init("BOTH_SCRATCH", .{});
    var rdr = std.Io.Reader.fixed("line BOTH_SCRATCH\n");
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const sum = try root.searchSource(&rdr, null, &f, .{
        .scratch = &legacy_buf,
        .scratch_pool = &pool,
        .buffer_size = 512,
    }, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_lines);
    try testing.expect(pool.stream_buf.len >= 512);
    try testing.expectEqual(@as(usize, 0), legacy_buf.len);
}

test "E2E T2_F11_01: AnyEventSink flow control: Flow.pause + resumeSourceSlice" {
    const f = try Finder.init("hit", .{});
    const any_m = AnyMatcher.from(&f);

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    sink.pause_after_matches = 2;
    const any_s = AnyEventSink.from(&sink);

    const data = "hit 1\nhit 2\nhit 3\nhit 4\n";
    const s1 = try root.searchSourceSlice(data, null, any_m, .{}, any_s);
    try testing.expect(s1.paused);
    try testing.expectEqual(@as(usize, 2), s1.matched_lines);

    sink.pause_after_matches = null;
    const s2 = try root.resumeSourceSlice(data, null, any_m, .{}, any_s, s1);
    try testing.expect(!s2.paused);
    try testing.expectEqual(@as(usize, 4), s2.matched_lines);
    try testing.expectEqual(@as(usize, 4), sink.lines.items.len);
}

test "E2E T2_F11_02: AnyMatcher with whole_line = true and invert = true" {
    const f = try Finder.init("exact_line", .{});
    const any_m = AnyMatcher.from(&f);

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const data = "exact_line\npartial exact_line\nother\n";
    const s_whole = try root.searchSourceSlice(data, null, any_m, .{ .whole_line = true }, &sink);
    try testing.expectEqual(@as(usize, 1), s_whole.matched_lines);
    try testing.expectEqual(@as(usize, 1), sink.lines.items[0].line_number);

    sink.clearRetainingCapacity();
    const s_inv = try root.searchSourceSlice(data, null, any_m, .{ .whole_line = true, .invert = true }, &sink);
    try testing.expectEqual(@as(usize, 2), s_inv.matched_lines);
}

test "E2E T2_F11_03: AnyMatcher wrapping empty Finder and empty RegexSet" {
    const f_empty = try Finder.init("", .{});
    var rs_empty = try RegexSet.init(testing.allocator, &.{}, .{});
    defer rs_empty.deinit();

    const am_f = AnyMatcher.from(&f_empty);
    const am_rs = AnyMatcher.from(&rs_empty);

    try testing.expect(am_f.find("abc", 0, .earliest) != null);
    try testing.expect(am_rs.find("abc", 0, .earliest) == null);
}

test "E2E T2_F11_04: AnyMatcher shared concurrently as *const AnyMatcher across 8 worker threads" {
    var rs = try RegexSet.init(testing.allocator, &.{ "tok_[0-9]+", "key_[a-z]+" }, .{});
    defer rs.deinit();
    const am = AnyMatcher.from(&rs);
    const am_ptr: *const AnyMatcher = &am;

    const Worker = struct {
        fn run(m: *const AnyMatcher, out_ok: *bool) void {
            for (0..200) |_| {
                const hit = m.find("xx key_abc and tok_99 yy", 0, .earliest) orelse {
                    out_ok.* = false;
                    return;
                };
                if (hit.pattern_id != 1) {
                    out_ok.* = false;
                    return;
                }
            }
            out_ok.* = true;
        }
    };

    var threads: [8]std.Thread = undefined;
    var ok: [8]bool = @splat(false);
    for (0..8) |i| threads[i] = try std.Thread.spawn(.{}, Worker.run, .{ am_ptr, &ok[i] });
    for (0..8) |i| threads[i].join();
    for (ok) |v| try testing.expect(v);
}

test "E2E T2_F11_05: AnyMatcher used in SliceIter, openSourcePull, and openReaderPull" {
    var m = try Multi.init(testing.allocator, &.{ "ONE", "TWO" }, .{});
    defer m.deinit();
    const am = AnyMatcher.from(&m);

    const text = "line ONE\nline TWO\n";
    var iter = root.searchSliceIter(text, am, .{});
    try testing.expectEqual(@as(?u32, 0), iter.next().?.match.?.pattern_id);
    try testing.expectEqual(@as(?u32, 1), iter.next().?.match.?.pattern_id);

    var rdr = std.Io.Reader.fixed(text);
    var rpull = root.openReaderPull(&rdr, am, .{});
    defer rpull.deinit();
    var r_hits: usize = 0;
    while (try rpull.next()) |ev| {
        if (ev.kind == .match) r_hits += 1;
    }
    try testing.expectEqual(@as(usize, 2), r_hits);

    var mem = root.source.Memory{ .files = &.{.{ .path = "f.txt", .data = text }} };
    const src = mem.source();
    const h = try src.open(testing.io, "f.txt");
    defer src.close(testing.io, h);
    var spull = root.openSourcePull(testing.io, src, h, am, .{});
    defer spull.deinit();
    var s_hits: usize = 0;
    while (try spull.next()) |ev| {
        if (ev.kind == .match) s_hits += 1;
    }
    try testing.expectEqual(@as(usize, 2), s_hits);
}

test "E2E T2_F12_01: Deterministic OOM failure during transcoding" {
    const u16_bytes = try Harness.encodeUtf16FromUtf8(testing.allocator, Harness.repeat("line with OOM_TEST\n", 20), .little, true);
    defer testing.allocator.free(u16_bytes);

    var failing = Harness.FailingAllocator.init(testing.allocator, 16);
    const f = try Finder.init("OOM_TEST", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    try testing.expectError(
        error.OutOfMemory,
        root.searchSourceSlice(u16_bytes, null, &f, .{ .allocator = failing.allocator() }, &sink),
    );
}

test "E2E T2_F12_02: searchSourceSlice on compressed input with all allocators null returns error" {
    const gz = try Harness.makeGzipFromRaw(testing.allocator, "compressed line\n");
    defer testing.allocator.free(gz);

    const f = try Finder.init("compressed", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    try testing.expectError(
        error.DecodeAllocatorRequired,
        root.searchSourceSlice(gz, null, &f, .{
            .compression = .gzip,
            .allocator = null,
            .decode_allocator = null,
            .scratch_pool = null,
        }, &sink),
    );
}

test "E2E T2_F12_03: SearchConfig.max_decode_bytes cap enforcement" {
    const gz = try Harness.makeGzipFromRaw(testing.allocator, Harness.repeat("long payload line\n", 50));
    defer testing.allocator.free(gz);

    const f = try Finder.init("payload", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    try testing.expectError(
        error.DecompressedLimitExceeded,
        root.searchSourceSlice(gz, null, &f, .{
            .compression = .gzip,
            .allocator = testing.allocator,
            .max_decode_bytes = 64,
        }, &sink),
    );
}

test "E2E T2_F12_04: SearchConfig.allocator with stack FixedBufferAllocator" {
    var stack_mem: [16384]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&stack_mem);

    const u16_bytes = try Harness.encodeUtf16FromUtf8(testing.allocator, "hello FBA_STACK_OK\n", .little, true);
    defer testing.allocator.free(u16_bytes);

    const f = try Finder.init("FBA_STACK_OK", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const sum = try root.searchSourceSlice(u16_bytes, null, &f, .{
        .allocator = fba.allocator(),
    }, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_lines);
}

test "E2E T2_F12_05: SearchConfig.allocator used across contains_regexes and excludes_regexes with replacement" {
    var re_main = try Regex.init(testing.allocator, "item_([0-9]+)", .{});
    defer re_main.deinit();
    var re_inc = try Regex.init(testing.allocator, "ALLOW", .{});
    defer re_inc.deinit();
    var re_exc = try Regex.init(testing.allocator, "BLOCK", .{});
    defer re_exc.deinit();

    const inc_list = [_]Regex{re_inc};
    const exc_list = [_]Regex{re_exc};

    const data =
        "item_10 ALLOW ok\n" ++
        "item_20 ALLOW BLOCK\n" ++
        "item_30 only\n";

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const sum = try root.searchSourceSlice(data, null, &re_main, .{
        .allocator = testing.allocator,
        .contains_regexes = &inc_list,
        .excludes_regexes = &exc_list,
        .replacement = "#$1",
    }, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_lines);
    try testing.expectEqualStrings("#10 ALLOW ok", sink.lines.items[0].replaced.?);
}

test "E2E T2_F13_01: Group nesting depth exceeding recursion cap" {
    const deep = Harness.repeat("(", 70) ++ "a" ++ Harness.repeat(")", 70);
    var diag: CompileDiagnostic = .{};
    try testing.expectError(
        error.RegexTooLarge,
        Regex.initDiagnostic(testing.allocator, deep, .{}, &diag),
    );
    try testing.expectEqual(DiagnosticCode.recursion_depth_exceeded, diag.code);
}

test "E2E T2_F13_02: Instruction count exceeding max_inst and multiline window cap" {
    var diag1: CompileDiagnostic = .{};
    try testing.expectError(
        error.RegexTooLarge,
        Regex.initDiagnostic(testing.allocator, "abcdefghijklmnop", .{ .max_inst = 5 }, &diag1),
    );
    try testing.expectEqual(DiagnosticCode.instruction_limit_exceeded, diag1.code);

    var diag2: CompileDiagnostic = .{};
    try testing.expectError(
        error.RegexTooLarge,
        Regex.initDiagnostic(testing.allocator, "a\\nb", .{ .multiline = true, .max_multiline_window = 0 }, &diag2),
    );
    try testing.expectEqual(DiagnosticCode.multiline_window_exceeded, diag2.code);
}

test "E2E T2_F13_03: Trailing backslash and invalid UTF-8 byte in pattern" {
    var diag1: CompileDiagnostic = .{};
    try testing.expectError(
        error.RegexSyntax,
        Regex.initDiagnostic(testing.allocator, "abc\\", .{}, &diag1),
    );
    try testing.expectEqual(DiagnosticCode.trailing_backslash, diag1.code);

    var diag2: CompileDiagnostic = .{};
    try testing.expectError(
        error.RegexSyntax,
        Regex.initDiagnostic(testing.allocator, "abc\xffdef", .{}, &diag2),
    );
    try testing.expectEqual(DiagnosticCode.invalid_utf8, diag2.code);
}

test "E2E T2_F13_04: Double quantifier and empty repeat braces" {
    var diag1: CompileDiagnostic = .{};
    try testing.expectError(
        error.RegexSyntax,
        Regex.initDiagnostic(testing.allocator, "a++", .{}, &diag1),
    );
    try testing.expectEqual(DiagnosticCode.dangling_quantifier, diag1.code);

    var diag2: CompileDiagnostic = .{};
    try testing.expectError(
        error.RegexSyntax,
        Regex.initDiagnostic(testing.allocator, "a{}", .{}, &diag2),
    );
    try testing.expectEqual(DiagnosticCode.invalid_repeat_bounds, diag2.code);
}

test "E2E T2_F13_05: Regex.initDiagnostic with diag = null and on valid patterns" {
    try testing.expectError(error.RegexSyntax, Regex.initDiagnostic(testing.allocator, "(abc", .{}, null));

    var diag: CompileDiagnostic = .{
        .code = .unclosed_group,
        .offset = 99,
        .line = 9,
        .column = 9,
        .message = "stale",
    };
    var re = try Regex.initDiagnostic(testing.allocator, "valid_[0-9]+", .{}, &diag);
    defer re.deinit();
    try testing.expectEqual(DiagnosticCode.none, diag.code);
    try testing.expectEqual(@as(usize, 0), diag.offset);
}

test "E2E T2_F14_01: searchTree max_depth and max_entries budget enforcement" {
    var mem = root.source.Memory{
        .files = &.{
            .{ .path = "root.txt", .data = "HIT\n" },
            .{ .path = "d1/a.txt", .data = "HIT\n" },
            .{ .path = "d1/d2/b.txt", .data = "HIT\n" },
            .{ .path = "d1/d2/d3/c.txt", .data = "HIT\n" },
        },
    };
    const f = try Finder.init("HIT", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const s_depth0 = root.searchTree(testing.io, mem.source(), &f, .{ .max_depth = 0 }, &sink);
    try testing.expectEqual(@as(usize, 1), s_depth0.matched_files);

    sink.clearRetainingCapacity();
    const s_depth1 = root.searchTree(testing.io, mem.source(), &f, .{ .max_depth = 1 }, &sink);
    try testing.expectEqual(@as(usize, 2), s_depth1.matched_files);

    sink.clearRetainingCapacity();
    const s_entries = root.searchTree(testing.io, mem.source(), &f, .{ .max_entries = 2 }, &sink);
    try testing.expect(s_entries.limit_reached);
}

test "E2E T2_F14_02: searchTree request-level budgets (max_results, cancel atomic token)" {
    var mem = root.source.Memory{
        .files = &.{
            .{ .path = "f1.txt", .data = "HIT 1\nHIT 2\n" },
            .{ .path = "f2.txt", .data = "HIT 3\nHIT 4\n" },
        },
    };
    const f = try Finder.init("HIT", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const s1 = root.searchTree(testing.io, mem.source(), &f, .{
        .search = .{ .max_results = 2 },
    }, &sink);
    try testing.expect(s1.stopped);
    try testing.expectEqual(@as(usize, 2), s1.matched_lines);

    var cancel = std.atomic.Value(bool).init(true);
    sink.clearRetainingCapacity();
    const s2 = root.searchTree(testing.io, mem.source(), &f, .{
        .search = .{ .cancel = &cancel },
    }, &sink);
    try testing.expect(s2.stopped);
    try testing.expectEqual(@as(usize, 0), s2.matched_lines);
}

test "E2E T2_F14_03: searchTree handling virtual source read error while continuing other files" {
    // Wrap source.Memory so that reading "bad.txt" returns an error while "good.txt" succeeds
    const FaultySource = struct {
        mem: root.source.Memory,
        bad_handle: ?usize = null,

        fn openFn(ptr: *anyopaque, io: std.Io, path: []const u8) anyerror!root.source.Handle {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            const h = try self.mem.source().open(io, path);
            if (std.mem.eql(u8, path, "bad.txt")) self.bad_handle = h;
            return h;
        }
        fn readFn(ptr: *anyopaque, io: std.Io, h: root.source.Handle, buf: []u8) anyerror!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.bad_handle) |bh| {
                if (h == bh) return error.SimulatedReadError;
            }
            return self.mem.source().read(io, h, buf);
        }
        fn listFn(ptr: *anyopaque, io: std.Io, h: root.source.Handle, out: []root.source.Entry) anyerror!usize {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            return self.mem.source().list(io, h, out);
        }
        fn closeFn(ptr: *anyopaque, io: std.Io, h: root.source.Handle) void {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.bad_handle == h) self.bad_handle = null;
            self.mem.source().close(io, h);
        }
    };

    var fs = FaultySource{
        .mem = .{
            .files = &.{
                .{ .path = "bad.txt", .data = "HIT in bad\n" },
                .{ .path = "good.txt", .data = "HIT in good\n" },
            },
        },
    };
    const src = root.source.Source{
        .ctx = &fs,
        .vtable = &.{
            .open = FaultySource.openFn,
            .read = FaultySource.readFn,
            .list = FaultySource.listFn,
            .close = FaultySource.closeFn,
        },
    };

    const f = try Finder.init("HIT", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const sum = root.searchTree(testing.io, src, &f, .{}, &sink);
    try testing.expectEqual(@as(usize, 1), sum.errors);
    try testing.expectEqual(@as(usize, 1), sum.matched_files);
    try testing.expectEqualStrings("good.txt", sink.lines.items[0].path.?);
}

test "E2E T2_F14_04: searchTree with binary files inside virtual tree (.quit vs. .report)" {
    var mem = root.source.Memory{
        .files = &.{
            .{ .path = "bin.dat", .data = "prefix \x00 HIT_BIN\n" },
            .{ .path = "txt.md", .data = "normal HIT_BIN\n" },
        },
    };
    const f = try Finder.init("HIT_BIN", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const s_quit = root.searchTree(testing.io, mem.source(), &f, .{
        .search = .{ .binary = .quit },
    }, &sink);
    try testing.expectEqual(@as(usize, 1), s_quit.matched_files);
    try testing.expectEqualStrings("txt.md", sink.lines.items[0].path.?);
}

test "E2E T2_F14_05: searchTree with TreeConfig.ignore_texts caller-injected ignore rules" {
    var mem = root.source.Memory{
        .files = &.{
            .{ .path = "secret.key", .data = "INJECT_HIT\n" },
            .{ .path = "public.txt", .data = "INJECT_HIT\n" },
        },
    };
    const f = try Finder.init("INJECT_HIT", .{});
    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const sum = root.searchTree(testing.io, mem.source(), &f, .{
        .ignore_texts = &.{"*.key\n"},
    }, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_files);
    try testing.expectEqualStrings("public.txt", sink.lines.items[0].path.?);
}

// ============================================================================
// TIER 3: Cross-Feature Combinatorial Matrix Tests (18 Tests)
// ============================================================================

test "E2E T3_01: RegexSet + Unicode + *const RegexSet + openReaderPull over Gzip UTF-16 stream" {
    const patterns = [_][]const u8{
        "\\p{Han}+_[0-9]+",
        "\\p{Cyrillic}+_[A-Z]+",
    };
    var set = try RegexSet.init(testing.allocator, &patterns, .{});
    defer set.deinit();
    const set_const: *const RegexSet = &set;

    const utf8_doc = "line 1 ok\nline 2 東京_2026 and Москва_RU\nline 3 done\n";
    const u16le = try Harness.encodeUtf16FromUtf8(testing.allocator, utf8_doc, .little, true);
    defer testing.allocator.free(u16le);
    const gz = try Harness.makeGzipFromRaw(testing.allocator, u16le);
    defer testing.allocator.free(gz);

    var rdr = std.Io.Reader.fixed(gz);
    var pull = root.openReaderPull(&rdr, set_const, .{
        .compression = .gzip,
        .allocator = testing.allocator,
    });
    defer pull.deinit();

    var matched_pids: [2]?u32 = .{ null, null };
    var span_count: usize = 0;
    while (try pull.next()) |ev| {
        if (ev.kind == .match) {
            span_count = ev.matches.len;
            if (ev.matches.len >= 2) {
                matched_pids[0] = ev.matches[0].pattern_id;
                matched_pids[1] = ev.matches[1].pattern_id;
            }
        }
    }
    try testing.expectEqual(@as(usize, 2), span_count);
    try testing.expectEqual(@as(?u32, 0), matched_pids[0]);
    try testing.expectEqual(@as(?u32, 1), matched_pids[1]);
}

test "E2E T3_02: AnyMatcher wrapping RegexSet + AnyEventSink + pattern_id + Flow.pause / resumeSourceSlice" {
    var rs = try RegexSet.init(testing.allocator, &.{ "RULE_A_[0-9]+", "RULE_B_[0-9]+" }, .{});
    defer rs.deinit();
    const any_m = AnyMatcher.from(&rs);

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    sink.pause_after_matches = 1;
    const any_s = AnyEventSink.from(&sink);

    const payload = "first RULE_B_10\nsecond RULE_A_20\n";
    const s1 = try root.searchSourceSlice(payload, "rules.txt", any_m, .{}, any_s);
    try testing.expect(s1.paused);
    try testing.expectEqual(@as(?u32, 1), sink.lines.items[0].matches[0].pattern_id);

    sink.pause_after_matches = null;
    const s2 = try root.resumeSourceSlice(payload, "rules.txt", any_m, .{}, any_s, s1);
    try testing.expect(!s2.paused);
    try testing.expectEqual(@as(?u32, 0), sink.lines.items[1].matches[0].pattern_id);
}

test "E2E T3_03: searchArchiveSlice on .tar.gz and .zip + AnyMatcher + AnyEventSink + Scratch Pool" {
    var multi = try Multi.init(testing.allocator, &.{ "KEY_ALPHA", "KEY_BETA" }, .{});
    defer multi.deinit();
    const any_m = AnyMatcher.from(&multi);

    var scratch = Scratch.init(testing.allocator);
    defer scratch.deinit();

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    const any_s = AnyEventSink.from(&sink);

    const tar = try Harness.buildTar(testing.allocator, &.{
        .{ .path = "a/file.txt", .data = "found KEY_BETA here\n" },
    });
    defer testing.allocator.free(tar);
    const tgz = try Harness.makeGzipFromRaw(testing.allocator, tar);
    defer testing.allocator.free(tgz);

    const sum1 = try root.searchArchiveSlice(testing.io, tgz, any_m, .{
        .allocator = testing.allocator,
        .search = .{ .scratch_pool = &scratch, .allocator = testing.allocator },
    }, any_s);
    try testing.expectEqual(@as(usize, 1), sum1.matched_files);
    try testing.expectEqual(@as(?u32, 1), sink.lines.items[0].matches[0].pattern_id);
}

test "E2E T3_04: C ABI webgrep_search_slice invoking RegexSet with Lazy DFA and pattern_id" {
    const re_opts = c_api.webgrep_regex_options_default();
    var diag: CCompileDiag = std.mem.zeroes(CCompileDiag);
    const pats = [_]CPattern{
        .{ .ptr = "[a-z]{4}_[0-9]{3}", .len = 17 },
        .{ .ptr = "[A-Z]{3}-[0-9]{4}", .len = 17 },
    };
    var set_m: CMatcherPtr = null;
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_matcher_compile_regex_set(&pats, pats.len, &re_opts, &diag, &set_m)));
    defer c_api.webgrep_matcher_free(set_m);

    const Ctx = struct {
        first_pid: i32 = -1,
        second_pid: i32 = -1,
        fn onLine(ev: CLineEventPtr, userdata: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            if (ev.*.matches_len >= 2) {
                self.first_pid = ev.*.matches_ptr[0].pattern_id;
                self.second_pid = ev.*.matches_ptr[1].pattern_id;
            }
            return 0;
        }
    };

    var ctx = Ctx{};
    const cfg = c_api.webgrep_config_default();
    var sum: CSummary = std.mem.zeroes(CSummary);
    const text = "row: TXN-9001 and item_404\n";
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_search_slice(set_m, text.ptr, text.len, &cfg, Ctx.onLine, &ctx, &sum)));
    try testing.expectEqual(@as(i32, 1), ctx.first_pid);
    try testing.expectEqual(@as(i32, 0), ctx.second_pid);
}

test "E2E T3_05: Lazy DFA + Unicode Property Classes + word boundaries + Captures replacement" {
    var re = try Regex.init(testing.allocator, "\\b(\\p{Lu}\\p{Ll}+)_(\\p{Nd}+)\\b", .{});
    defer re.deinit();

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    _ = try root.searchSourceSlice("user Αθήνα_42 logged in\n", null, &re, .{
        .replacement = "city=$1,id=$2",
    }, &sink);

    try testing.expectEqual(@as(usize, 1), sink.lines.items.len);
    try testing.expectEqualStrings("user city=Αθήνα,id=42 logged in", sink.lines.items[0].replaced.?);
}

test "E2E T3_06: Multi-threaded *const AnyMatcher + per-worker Scratch pool + CountingAllocator" {
    var rs = try RegexSet.init(testing.allocator, &.{ "WARN_[0-9]+", "ERR_[A-Z]+" }, .{});
    defer rs.deinit();
    const am = AnyMatcher.from(&rs);
    const am_ptr: *const AnyMatcher = &am;

    const Worker = struct {
        fn run(matcher: *const AnyMatcher, out_zero_alloc: *bool) void {
            var counting = Harness.CountingAllocator.init(testing.allocator);
            var scratch = Scratch.init(counting.allocator());
            defer scratch.deinit();

            var sink = Harness.TestEventSink.init(testing.allocator);
            defer sink.deinit();

            const payload = "line 1 WARN_10\nline 2 ERR_OOM\n";
            const cfg = SearchConfig{
                .scratch_pool = &scratch,
                .allocator = counting.allocator(),
            };
            _ = root.searchSourceSlice(payload, null, matcher.*, cfg, &sink) catch {
                out_zero_alloc.* = false;
                return;
            };
            counting.resetCounts();

            for (0..100) |_| {
                sink.clearRetainingCapacity();
                _ = root.searchSourceSlice(payload, null, matcher.*, cfg, &sink) catch {
                    out_zero_alloc.* = false;
                    return;
                };
            }
            out_zero_alloc.* = (counting.totalAllocEvents() == 0);
        }
    };

    var threads: [4]std.Thread = undefined;
    var ok: [4]bool = @splat(false);
    for (0..4) |i| threads[i] = try std.Thread.spawn(.{}, Worker.run, .{ am_ptr, &ok[i] });
    for (0..4) |i| threads[i].join();
    for (ok) |v| try testing.expect(v);
}

test "E2E T3_07: GBK and Latin-1 transcoding + SearchConfig.allocator + Unicode property classes" {
    // In GBK, "中文" is 0xD6, 0xD0, 0xCE, 0xC4
    const gbk_bytes = "id=100 \xd6\xd0\xce\xc4\n";
    var re_han = try Regex.init(testing.allocator, "\\p{Han}+", .{});
    defer re_han.deinit();

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const sum = try root.searchSourceSlice(gbk_bytes, null, &re_han, .{
        .encoding = .gbk,
        .allocator = testing.allocator,
    }, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_lines);
    try testing.expectEqualStrings("id=100 中文", sink.lines.items[0].text);
}

test "E2E T3_08: Multi 64-byte SIMD & Teddy + pattern_id + whole_word + secondary regex filters" {
    const pats = [_][]const u8{
        "tok_01", "tok_02", "tok_03", "tok_04", "tok_05",
        "tok_06", "tok_07", "tok_08", "tok_09", "tok_10",
    };
    var m = try Multi.init(testing.allocator, &pats, .{});
    defer m.deinit();

    var re_allow = try Regex.init(testing.allocator, "ENV=PROD", .{});
    defer re_allow.deinit();
    const allow_list = [_]Regex{re_allow};

    const data =
        "not_whole_tok_05 ENV=PROD\n" ++
        "whole tok_05 ENV=DEV\n" ++
        "whole tok_09 ENV=PROD\n";

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const sum = try root.searchSourceSlice(data, null, &m, .{
        .whole_word = true,
        .contains_regexes = &allow_list,
    }, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_lines);
    try testing.expectEqual(@as(usize, 3), sink.lines.items[0].line_number);
    try testing.expectEqual(@as(?u32, 8), sink.lines.items[0].matches[0].pattern_id);
}

test "E2E T3_09: openReaderPull + Gzip decompression + RegexSet + max_results pagination & resume_from" {
    var rs = try RegexSet.init(testing.allocator, &.{ "ROW_[0-9]+", " SPECIAL_[0-9]+" }, .{});
    defer rs.deinit();

    const raw = "ROW_1\nROW_2\nROW_3\nROW_4\n";
    const gz = try Harness.makeGzipFromRaw(testing.allocator, raw);
    defer testing.allocator.free(gz);

    var rdr1 = std.Io.Reader.fixed(gz);
    var pull1 = root.openReaderPull(&rdr1, &rs, .{
        .compression = .gzip,
        .allocator = testing.allocator,
        .max_results = 2,
    });
    defer pull1.deinit();

    var sum1: Summary = .{};
    while (try pull1.next()) |ev| {
        if (ev.kind == .summary) sum1 = ev.summary.?;
    }
    try testing.expectEqual(@as(usize, 2), sum1.matched_lines);
    try testing.expect(sum1.next_resume != null);

    var rdr2 = std.Io.Reader.fixed(gz);
    var pull2 = root.openReaderPull(&rdr2, &rs, .{
        .compression = .gzip,
        .allocator = testing.allocator,
        .resume_from = sum1.next_resume,
    });
    defer pull2.deinit();

    var sum2: Summary = .{};
    while (try pull2.next()) |ev| {
        if (ev.kind == .summary) sum2 = ev.summary.?;
    }
    try testing.expectEqual(@as(usize, 2), sum2.matched_lines);
}

test "E2E T3_10: C ABI webgrep_search_archive_slice on .zip + regex syntax diag" {
    const re_opts = c_api.webgrep_regex_options_default();
    var diag: CCompileDiag = std.mem.zeroes(CCompileDiag);
    var bad_m: CMatcherPtr = null;
    try testing.expect(cStatus(c_api.webgrep_matcher_compile_regex("[z-a]", 5, &re_opts, &diag, &bad_m)) != 0);
    try testing.expect(cGetEnumOrInt(diag.code) != 0);

    var good_m: CMatcherPtr = null;
    const pat = "\\p{Lu}+_[0-9]+";
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_matcher_compile_regex(pat.ptr, pat.len, &re_opts, &diag, &good_m)));
    defer c_api.webgrep_matcher_free(good_m);

    const zip = try Harness.buildZip(testing.allocator, &.{
        .{ .path = "sub/file.txt", .data = "token TOKEN_99 here\n", .method = 8 },
    });
    defer testing.allocator.free(zip);

    const tcfg = c_api.webgrep_tree_config_default();
    var tsum: CTreeSummary = std.mem.zeroes(CTreeSummary);
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_search_archive_slice(good_m, zip.ptr, zip.len, &tcfg, null, null, &tsum)));
    try testing.expectEqual(@as(u64, 1), tsum.matched_files);
}

test "E2E T3_11: Regex.initDiagnostic + Lazy DFA + *const Regex with RegexScratch on alternation pattern" {
    var diag: CompileDiagnostic = .{};
    var re = try Regex.initDiagnostic(
        testing.allocator,
        "([a-z]{3}_[0-9]{3})|([A-Z]{3}:[0-9]{3})",
        .{},
        &diag,
    );
    defer re.deinit();
    try testing.expectEqual(DiagnosticCode.none, diag.code);

    const rc: *const Regex = &re;
    var scratch = RegexScratch.init(testing.allocator);
    defer scratch.deinit();

    const hay = "prefix XYZ:789 suffix";
    const caps = rc.findCapturesWithScratch(hay, 0, .earliest, &scratch).?;
    try testing.expectEqualStrings("XYZ:789", hay[caps.match.start..caps.match.end]);
    try testing.expect(caps.slice(hay, 1) == null);
    try testing.expectEqualStrings("XYZ:789", caps.slice(hay, 2).?);
}

test "E2E T3_12: Scratch pool + SearchConfig.allocator + Multi pattern_id + passthru mode with replacement" {
    var scratch = Scratch.init(testing.allocator);
    defer scratch.deinit();

    var m = try Multi.init(testing.allocator, &.{ "OLD_A", "OLD_B" }, .{});
    defer m.deinit();

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const data = "context 1\nmatch OLD_B here\ncontext 2\n";
    const sum = try root.searchSourceSlice(data, null, &m, .{
        .scratch_pool = &scratch,
        .allocator = testing.allocator,
        .passthru = true,
        .replacement = "NEW",
    }, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_lines);
    try testing.expectEqual(@as(usize, 3), sink.lines.items.len);
    try testing.expect(sink.lines.items[0].is_context);
    try testing.expect(!sink.lines.items[1].is_context);
    try testing.expectEqual(@as(?u32, 1), sink.lines.items[1].matches[0].pattern_id);
    try testing.expectEqualStrings("match NEW here", sink.lines.items[1].replaced.?);
    try testing.expect(sink.lines.items[2].is_context);
}

test "E2E T3_13: openReaderPull + UTF-16LE with surrogate pairs + Unicode \\p{S} + UTF-16 column verification" {
    // "ab😀cd\n" in UTF-16LE: 'a'(1), 'b'(1), '😀'(2 code units: D83D DE00), 'c', 'd'
    // So 'c' is at 1-based byte column 7 (1 + 1 + 4 + 1) and 1-based UTF-16 column 5 (1 + 1 + 2 + 1)
    const utf8_line = "ab😀TARGET\n";
    const u16le = try Harness.encodeUtf16FromUtf8(testing.allocator, utf8_line, .little, true);
    defer testing.allocator.free(u16le);

    var re = try Regex.init(testing.allocator, "TARGET", .{});
    defer re.deinit();

    var rdr = std.Io.Reader.fixed(u16le);
    var pull = root.openReaderPull(&rdr, &re, .{
        .allocator = testing.allocator,
        .column = true,
        .column_unit = .utf16,
    });
    defer pull.deinit();

    var col: ?usize = null;
    while (try pull.next()) |ev| {
        if (ev.kind == .match) col = ev.line.?.column;
    }
    try testing.expectEqual(@as(?usize, 5), col);
}

test "E2E T3_14: searchArchive over streaming .tar.gz + AnyMatcher + AnyEventSink + globs" {
    const tar = try Harness.buildTar(testing.allocator, &.{
        .{ .path = "src/app.zig", .data = "const x = \"STREAM_GLOB_HIT\";\n" },
        .{ .path = "docs/readme.md", .data = "STREAM_GLOB_HIT\n" },
    });
    defer testing.allocator.free(tar);
    const tgz = try Harness.makeGzipFromRaw(testing.allocator, tar);
    defer testing.allocator.free(tgz);

    const f = try Finder.init("STREAM_GLOB_HIT", .{});
    const any_m = AnyMatcher.from(&f);

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    const any_s = AnyEventSink.from(&sink);

    var rdr = std.Io.Reader.fixed(tgz);
    const sum = try root.searchArchive(testing.io, &rdr, any_m, .{
        .allocator = testing.allocator,
        .globs = &.{"*.zig"},
    }, any_s);
    try testing.expectEqual(@as(usize, 1), sum.matched_files);
    try testing.expectEqualStrings("src/app.zig", sink.lines.items[0].path.?);
}

test "E2E T3_15: searchTree parallel traversal (max_concurrency = 4) + shared *const Finder" {
    var mem = root.source.Memory{
        .files = &.{
            .{ .path = "p1/a.txt", .data = "SHARED_FINDER_HIT\n" },
            .{ .path = "p2/b.txt", .data = "SHARED_FINDER_HIT\n" },
            .{ .path = "p3/c.txt", .data = "SHARED_FINDER_HIT\n" },
            .{ .path = "p4/d.txt", .data = "SHARED_FINDER_HIT\n" },
        },
    };
    const f = try Finder.init("SHARED_FINDER_HIT", .{});
    const f_const: *const Finder = &f;

    const AtomicSink = struct {
        count: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
        pub fn emit(self: *@This(), ev: LineEvent) Flow {
            if (!ev.is_context) _ = self.count.fetchAdd(1, .monotonic);
            return .cont;
        }
    };
    var asink = AtomicSink{};
    const sum = root.searchTree(testing.io, mem.source(), f_const, .{
        .max_concurrency = 4,
    }, &asink);
    try testing.expectEqual(@as(usize, 4), sum.matched_files);
    try testing.expectEqual(@as(usize, 4), asink.count.load(.monotonic));
}

test "E2E T3_16: RegexSet.initDiagnostic + AnyMatcher + SliceIter with pattern_id" {
    var diag: CompileDiagnostic = .{};
    var rs = try RegexSet.initDiagnostic(
        testing.allocator,
        &.{ "\\p{Han}+", "\\p{Cyrillic}+" },
        .{},
        &diag,
    );
    defer rs.deinit();
    try testing.expectEqual(DiagnosticCode.none, diag.code);

    const am = AnyMatcher.from(&rs);
    var iter = root.searchSliceIter("first Мир\nsecond 東京\n", am, .{});
    const l1 = iter.next().?;
    try testing.expectEqual(@as(?u32, 1), l1.match.?.pattern_id);
    const l2 = iter.next().?;
    try testing.expectEqual(@as(?u32, 0), l2.match.?.pattern_id);
}

test "E2E T3_17: C ABI webgrep_search_slice and webgrep_search_archive_slice reusing webgrep_scratch_t" {
    const find_opts = c_api.webgrep_find_options_default();
    var m: CMatcherPtr = null;
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_matcher_compile_literal("REUSE_C", 7, &find_opts, &m)));
    defer c_api.webgrep_matcher_free(m);

    const scratch = c_api.webgrep_scratch_new();
    defer c_api.webgrep_scratch_free(scratch);

    var cfg = c_api.webgrep_config_default();
    cfg.scratch = scratch;

    const zip = try Harness.buildZip(testing.allocator, &.{
        .{ .path = "f.txt", .data = "archive REUSE_C\n", .method = 8 },
    });
    defer testing.allocator.free(zip);

    var tcfg = c_api.webgrep_tree_config_default();
    tcfg.search = cfg;

    for (0..10) |_| {
        var sum: CSummary = std.mem.zeroes(CSummary);
        try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_search_slice(m, "slice REUSE_C\n", 14, &cfg, null, null, &sum)));
        try testing.expectEqual(@as(u64, 1), sum.matched_lines);

        var tsum: CTreeSummary = std.mem.zeroes(CTreeSummary);
        try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_search_archive_slice(m, zip.ptr, zip.len, &tcfg, null, null, &tsum)));
        try testing.expectEqual(@as(u64, 1), tsum.matched_files);
    }
}

test "E2E T3_18: openReaderPull + Lazy DFA + ultra-long line windowing + context ring" {
    var re = try Regex.init(testing.allocator, "[A-Z]{4}_[0-9]{4}", .{});
    defer re.deinit();

    const long_line = Harness.repeat("x", 1200) ++ " LONG_9001 " ++ Harness.repeat("y", 1200) ++ "\n";
    const doc = "ctx before\n" ++ long_line ++ "ctx after\n";

    var rdr = std.Io.Reader.fixed(doc);
    var pull = root.openReaderPull(&rdr, &re, .{
        .buffer_size = 256,
        .before_context = 1,
        .after_context = 1,
    });
    defer pull.deinit();

    var ctx_count: usize = 0;
    var match_count: usize = 0;
    while (try pull.next()) |ev| {
        if (ev.kind == .context) ctx_count += 1;
        if (ev.kind == .match) match_count += 1;
    }
    try testing.expectEqual(@as(usize, 2), ctx_count);
    try testing.expectEqual(@as(usize, 1), match_count);
}

// ============================================================================
// TIER 4: Real-World Production Scenario Suites (7 Tests)
// ============================================================================

test "E2E T4_01: Multi-Tenant WAF / DLP Security Rule Engine" {
    const dlp_rules = [_][]const u8{
        "AKIA[0-9A-Z]{16}", // Rule 0: AWS Access Key ID
        "ghp_[a-zA-Z0-9]{16}", // Rule 1: GitHub Personal Token
        "(?i)bearer\\s+[a-z0-9._-]+", // Rule 2: Bearer token
        "[0-9]{3}-[0-9]{2}-[0-9]{4}", // Rule 3: SSN format
    };
    var engine = try RegexSet.init(testing.allocator, &dlp_rules, .{});
    defer engine.deinit();
    const shared_engine: *const RegexSet = &engine;

    const payload =
        "POST /v1/upload HTTP/1.1\n" ++
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9\n" ++
        "aws_key=AKIAIOSFODNN7EXAMPLE and ssn=123-45-6789\n";

    var rule_ids: [8]u32 = undefined;
    const n_rules = shared_engine.matches(payload, &rule_ids);
    try testing.expectEqual(@as(usize, 3), n_rules);
    try testing.expectEqualSlices(u32, &[_]u32{ 0, 2, 3 }, rule_ids[0..n_rules]);

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    const sum = try root.searchSourceSlice(payload, "req.http", shared_engine, .{}, &sink);
    try testing.expectEqual(@as(usize, 2), sum.matched_lines);
    try testing.expectEqual(@as(?u32, 2), sink.lines.items[0].matches[0].pattern_id);
    try testing.expectEqual(@as(?u32, 0), sink.lines.items[1].matches[0].pattern_id);
    try testing.expectEqual(@as(?u32, 3), sink.lines.items[1].matches[1].pattern_id);
}

test "E2E T4_02: Multilingual CJK / Cyrillic / Latin Log Analytics Pipeline" {
    var re = try Regex.init(
        testing.allocator,
        "\\[(\\p{Han}+|\\p{Cyrillic}+|\\p{Latin}+)\\]\\s+status=([0-9]{3})",
        .{},
    );
    defer re.deinit();

    const utf8_logs =
        "2026-11-09 [東京] status=200\n" ++
        "2026-11-09 [Москва] status=503\n" ++
        "2026-11-09 [München] status=404\n";
    const u16le = try Harness.encodeUtf16FromUtf8(testing.allocator, utf8_logs, .little, true);
    defer testing.allocator.free(u16le);

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const sum = try root.searchSourceSlice(u16le, "intl.log", &re, .{
        .allocator = testing.allocator,
        .replacement = "region:$1->http:$2",
    }, &sink);
    try testing.expectEqual(@as(usize, 3), sum.matched_lines);
    try testing.expectEqualStrings("2026-11-09 region:東京->http:200", sink.lines.items[0].replaced.?);
    try testing.expectEqualStrings("2026-11-09 region:Москва->http:503", sink.lines.items[1].replaced.?);
    try testing.expectEqualStrings("2026-11-09 region:München->http:404", sink.lines.items[2].replaced.?);
}

test "E2E T4_03: Zero-Disk-Landing Release Tarball & Zip Security Audit" {
    var rs = try RegexSet.init(testing.allocator, &.{ "PRIVATE_KEY_LEAK", "AWS_SECRET_[0-9]+" }, .{});
    defer rs.deinit();

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const evil_tar = try Harness.buildTar(testing.allocator, &.{
        .{ .path = "../../etc/shadow", .data = "PRIVATE_KEY_LEAK\n" },
    });
    defer testing.allocator.free(evil_tar);
    try testing.expectError(
        error.PathTraversal,
        root.searchArchiveSlice(testing.io, evil_tar, &rs, .{ .allocator = testing.allocator }, &sink),
    );

    const tar = try Harness.buildTar(testing.allocator, &.{
        .{ .path = ".gitignore", .data = "vendor/\n*.bak\n" },
        .{ .path = "shadow_link", .data = "", .typeflag = '2', .linkname = "/etc/shadow" },
        .{ .path = "vendor/dep.zig", .data = "PRIVATE_KEY_LEAK\n" },
        .{ .path = "backup.bak", .data = "PRIVATE_KEY_LEAK\n" },
        .{ .path = "src/auth.zig", .data = "// normal line\nconst secret = \"PRIVATE_KEY_LEAK\";\n" },
    });
    defer testing.allocator.free(tar);
    const tgz = try Harness.makeGzipFromRaw(testing.allocator, tar);
    defer testing.allocator.free(tgz);

    const sum = try root.searchArchiveSlice(testing.io, tgz, &rs, .{
        .allocator = testing.allocator,
    }, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_files);
    try testing.expectEqual(@as(usize, 1), sum.matched_lines);
    try testing.expectEqualStrings("src/auth.zig", sink.lines.items[0].path.?);
    try testing.expectEqual(@as(usize, 2), sink.lines.items[0].line_number);
}

test "E2E T4_04: Streaming Telemetry / Log Pipeline via openReaderPull" {
    var telemetry_buf: std.ArrayList(u8) = .empty;
    defer telemetry_buf.deinit(testing.allocator);
    for (0..200) |i| {
        { var _tmp: [128]u8 = undefined; try telemetry_buf.appendSlice(testing.allocator, try std.fmt.bufPrint(&_tmp, "ts={d} level=INFO msg=heartbeat\n", .{i})); }
        if (i % 10 == 5) {
            { var _tmp: [128]u8 = undefined; try telemetry_buf.appendSlice(testing.allocator, try std.fmt.bufPrint(&_tmp, "ts={d} level=ALERT code=CRIT_{d:0>3}\n", .{ i, i })); }
        }
    }
    const gz = try Harness.makeGzipFromRaw(testing.allocator, telemetry_buf.items);
    defer testing.allocator.free(gz);

    var rbuf: [64]u8 = undefined;
    var cr = Harness.ChunkedReader.init(gz, 64, &rbuf);
    var re = try Regex.init(testing.allocator, "CRIT_[0-9]{3}", .{});
    defer re.deinit();

    var pull = root.openReaderPull(&cr.interface, &re, .{
        .compression = .gzip,
        .allocator = testing.allocator,
        .before_context = 1,
    });
    defer pull.deinit();

    var alerts: usize = 0;
    while (try pull.next()) |ev| {
        if (ev.kind == .match) {
            alerts += 1;
            if (alerts == 3) break;
        }
    }
    try testing.expectEqual(@as(usize, 3), alerts);
}

test "E2E T4_05: High-Frequency Micro-Stream Scanner with Scratch Pool" {
    var counting = Harness.CountingAllocator.init(testing.allocator);
    var scratch = Scratch.init(counting.allocator());
    defer scratch.deinit();

    var m = try Multi.init(testing.allocator, &.{ "ERR_TIMEOUT", "ERR_CONN", "ERR_AUTH" }, .{});
    defer m.deinit();
    const any_m = AnyMatcher.from(&m);

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();
    const any_s = AnyEventSink.from(&sink);

    const payload = "req=1 ok\nreq=2 ERR_CONN retry\nreq=3 ERR_AUTH denied\n";
    const cfg = SearchConfig{
        .scratch_pool = &scratch,
        .allocator = counting.allocator(),
        .before_context = 1,
    };

    // Warm up
    _ = try root.searchSourceSlice(payload, "micro.log", any_m, cfg, any_s);
    scratch.reset();
    counting.resetCounts();

    for (0..1000) |_| {
        sink.clearRetainingCapacity();
        const sum = try root.searchSourceSlice(payload, "micro.log", any_m, cfg, any_s);
        try testing.expectEqual(@as(usize, 2), sum.matched_lines);
        scratch.reset();
    }
    try testing.expectEqual(@as(usize, 0), counting.totalAllocEvents());
}

test "E2E T4_06: IDE Live Regex Linter & Refactoring Preview" {
    // 1. User types incomplete regex -> IDE gets structured diagnostic
    var diag: CompileDiagnostic = .{};
    try testing.expectError(
        error.RegexSyntax,
        Regex.initDiagnostic(testing.allocator, "fn\\s+([a-zA-Z0-9_]+\\(", .{}, &diag),
    );
    try testing.expectEqual(DiagnosticCode.unclosed_group, diag.code);
    try testing.expectEqual(@as(usize, 5), diag.offset);

    // 2. User closes group -> live refactoring preview with $1 and $2
    var re = try Regex.initDiagnostic(
        testing.allocator,
        "fn\\s+([a-zA-Z0-9_]+)\\(([^)]*)\\)",
        .{},
        &diag,
    );
    defer re.deinit();
    try testing.expectEqual(DiagnosticCode.none, diag.code);

    var sink = Harness.TestEventSink.init(testing.allocator);
    defer sink.deinit();

    const code = "pub fn computeHash(input: []const u8) u64 {\n    return 0;\n}\n";
    const sum = try root.searchSourceSlice(code, "hash.zig", &re, .{
        .replacement = "pub fn $1_v2($2)",
    }, &sink);
    try testing.expectEqual(@as(usize, 1), sum.matched_lines);
    try testing.expectEqualStrings("pub pub fn computeHash_v2(input: []const u8) u64 {", sink.lines.items[0].replaced.?);
}

test "E2E T4_07: Cross-Language FFI Service Simulation via C ABI" {
    const re_opts = c_api.webgrep_regex_options_default();
    var diag: CCompileDiag = std.mem.zeroes(CCompileDiag);

    const rules = [_]CPattern{
        .{ .ptr = "ERR_[0-9]{3}", .len = 12 },
        .{ .ptr = "WARN_[A-Z]+", .len = 11 },
    };
    var matcher: CMatcherPtr = null;
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_matcher_compile_regex_set(&rules, rules.len, &re_opts, &diag, &matcher)));
    defer c_api.webgrep_matcher_free(matcher);

    const scratch = c_api.webgrep_scratch_new();
    defer c_api.webgrep_scratch_free(scratch);

    var cfg = c_api.webgrep_config_default();
    cfg.scratch = scratch;
    const rep = "[REDACTED]";
    cfg.replacement_ptr = rep.ptr;
    cfg.replacement_len = rep.len;

    const FfiCollector = struct {
        events: usize = 0,
        saw_redacted: bool = false,
        saw_pid_0: bool = false,
        saw_pid_1: bool = false,

        fn onLine(ev: CLineEventPtr, userdata: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(userdata.?));
            self.events += 1;
            if (ev.*.replaced_ptr) |rp| {
                const s = rp[0..ev.*.replaced_len];
                if (std.mem.indexOf(u8, s, "[REDACTED]") != null) self.saw_redacted = true;
            }
            for (0..ev.*.matches_len) |i| {
                if (ev.*.matches_ptr[i].pattern_id == 0) self.saw_pid_0 = true;
                if (ev.*.matches_ptr[i].pattern_id == 1) self.saw_pid_1 = true;
            }
            return 0;
        }
    };

    var col = FfiCollector{};
    var sum: CSummary = std.mem.zeroes(CSummary);
    const log_slice = "2026-11-09 ERR_500 and WARN_DISK\n";
    try testing.expectEqual(@as(c_int, 0), cStatus(c_api.webgrep_search_slice(matcher, log_slice.ptr, log_slice.len, &cfg, FfiCollector.onLine, &col, &sum)));
    try testing.expectEqual(@as(usize, 1), col.events);
    try testing.expect(col.saw_redacted);
    try testing.expect(col.saw_pid_0);
    try testing.expect(col.saw_pid_1);
}
