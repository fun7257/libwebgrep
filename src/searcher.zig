//! 单个输入上的行语义。
//!
//! 先在缓冲里找匹配，命中后再向两侧找 `\n`。没有命中的区域不逐行扫描。
//! 模式里的换行由 Finder 拒绝；这里假定匹配器不会跨行。
//! 默认行终止符是 LF。交给 Sink 的行内容去掉结尾的 `\n`，再去掉紧挨着的一个 `\r`。
//! `null_data` 改用 NUL 分隔记录，记录里的 LF 不断行，NUL 也不当成二进制。
//!
//! `encoding = .auto` 只在流开头嗅探 BOM。UTF-16 先转成 UTF-8 再搜索，非法序列换成
//! U+FFFD。没有 BOM 就不猜测。`.none` 不嗅探、不转码。
//!
//! 没有 BOM 时切片搜索不分配。需要转码的切片用 `decode_allocator`。Reader 和文件搜索
//! 使用调用方传入的分配器。读缓冲从 `buffer_size` 涨到单行上限，不再为了装下整行继续涨。
//! 超过上限的行仍按流查找，交出去的是匹配附近的窗口。前置上下文放在环形缓冲里，不回退读取。
//!
//! 预算、取消和截止时间都由调用方传入。服务入口在缺省时填上单输入默认值，不能超过硬顶。
//! 库不读环境变量，也不自己选租户配额。停止原因写在 `limit_hit` 上。
//! 输入没扫完时 `partial` 为真。来源读失败是软错误，和致命错误、有匹配、无匹配分开。
//! 返回给调用方的错误不含路径；路径只交给调用方提供的日志函数。

const std = @import("std");
const build_options = @import("build_options");
const encoding = @import("encoding.zig");
const matcher_mod = @import("matcher.zig");
const memchr = @import("finder/memchr.zig");
const sink_mod = @import("sink.zig");

pub const Encoding = encoding.Encoding;

pub const BinaryPolicy = enum {
    /// 跳过。遇到 NUL 就停止读取。这是默认。
    quit,
    /// 继续搜索，直到知道有没有匹配，但是不返回行内容。
    report,
    /// 按文本处理，不把 NUL 当成二进制。
    none,
};

pub const SearchConfig = struct {
    /// 起始块大小。128 MiB 文件上四档里 1 MiB 最快，见 `BENCHMARKS.md`。默认 1 MiB。
    pub const default_buffer_size: usize = 1024 * 1024;
    /// 单行字节上限。读缓冲不超过这个值加一个换行字节。更长的行改走窗口。
    pub const default_max_line_len: usize = 2 * 1024 * 1024;
    /// 上下文行数硬顶。调用方可以把实际上限调低，不能超过这里。
    pub const context_lines_hard_cap: u32 = 10;
    /// 单行字节硬顶。调用方可以在这之下覆盖 `max_line_len`。
    pub const max_line_len_hard_cap: usize = 8 * 1024 * 1024;
    /// 服务入口没写扫描上限时用这个。旧入口保持不限，直到调用方传入。
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
    /// 对称上下文。`before` 或 `after` 不是 null 时，对应的一侧改用那个值。
    context: u32 = 0,
    /// null 表示跟 `context` 走。
    before: ?u32 = null,
    /// null 表示跟 `context` 走。
    after: ?u32 = null,
    /// 服务层可以把上下文行数上限调得比硬顶更低。比硬顶大时仍按硬顶。
    max_context_lines: ?u32 = null,
    /// 这个输入上最多报告多少条匹配行。null 表示不限。
    /// 计入上限的是主循环找到的命中。`-A` 窗口里额外抬成匹配的行不占用额度，
    /// 但仍然调用 `matched`，因此计数打印器会把它们算进去。这和 ripgrep 15 一致。
    /// 达到上限后不再读下一块。缓冲里已经读入的 after 行仍会交出去。
    max_count: ?u64 = null,
    /// 整词。只看匹配外侧那个字节是不是 ASCII 单词字符（字母、数字、下划线）。
    /// 这是半边界：`-2` 能命中 `(-2)`，不能命中 `x-2` 或 `-2y`。
    /// 和 `whole_line` 同时打开时不检查词边界。
    whole_word: bool = false,
    /// 整行。去掉 LF 和紧挨着的一个 CR 之后，行内容必须和某一条模式相同。
    whole_line: bool = false,
    /// 行内容必须包含这里的每一条才输出。按字节比较，不折叠大小写。空表示不额外要求。
    contains: []const []const u8 = &.{},
    /// 行内容必须不含这里的每一条。按字节比较。和 `invert` 是两个开关。
    excludes: []const []const u8 = &.{},
    /// 匹配行数达到 `max_count` 时调用，用来关闭上游。没提供就不调用。
    close_input: ?*const fn (?*anyopaque) void = null,
    close_ctx: ?*anyopaque = null,
    binary: BinaryPolicy = .quit,
    /// 用 NUL 分隔记录。记录内部的 LF 不断行，NUL 也不当成二进制信号。
    null_data: bool = false,
    /// 默认只在流开头嗅探 BOM。`.none` 关掉嗅探和转码。
    encoding: Encoding = .auto,
    /// 切片上需要转码，或有损文本放不进栈缓冲时使用。流式搜索用函数上的分配器。
    decode_allocator: ?std.mem.Allocator = null,
    buffer_size: usize = default_buffer_size,
    max_line_len: usize = default_max_line_len,
    match_mode: matcher_mod.MatchMode = .earliest,
    /// 非 null 时复用这块缓冲。扩容后把新切片写回去。null 时这次调用自己分配、自己释放。
    scratch: ?*[]u8 = null,
    /// 非 null 且为真时，下一块开始前停止。遍历用它做提前结束。
    /// 这不是取消令牌：不关闭上游，也不写成 `limit_hit = cancelled`。
    stop: ?*const std.atomic.Value(bool) = null,
    /// 这个来源最多扫描多少字节。达到后不再读。null 表示旧入口不另加来源上限。
    max_source_bytes: ?u64 = null,
    /// 这次请求最多扫描多少字节。和来源上限同时生效，先到的那个停。
    max_request_bytes: ?u64 = null,
    /// 请求级最多交出多少条匹配行。达到后 end 事件带 `resume_at`。
    /// 和 `max_count` 不同：`max_count` 是单个来源的行数上限，不带续查位置。
    max_results: ?u64 = null,
    /// 从可搜索字节流的这个偏移继续。之前的字节不再产出匹配。
    resume_from: u64 = 0,
    /// 行事件（匹配和上下文）累计字节上限。窗口里的字节算进这一个上限。
    max_output_bytes: ?u64 = null,
    /// 从搜索开始允许的最长时间，纳秒。null 表示旧入口不限。
    time_budget_ns: ?u64 = null,
    /// 非 null 时用它代替单调时钟。测试靠它断言「超时后停止」，不看具体毫秒。
    clock: ?*const fn (?*anyopaque) i128 = null,
    clock_ctx: ?*anyopaque = null,
    /// 取消令牌。置位后停止搜索，并关闭上游。
    cancel: ?*const std.atomic.Value(bool) = null,
    /// 已经计入的解压字节。解压器落地之前保持调用方传入的值。
    decompressed_bytes: u64 = 0,
    /// 解压字节上限。达到后 `limit_hit = decompressed_bytes`。
    max_decompressed_bytes: ?u64 = null,
    /// 前置上下文缓冲的字节上限。null 时用硬顶。
    max_before_bytes: ?usize = null,
    /// 解码输入缓冲的字节上限。null 时用硬顶。
    max_decode_bytes: ?usize = null,
    /// 等回调取走的那一条行事件的字节上限。同步回调不攒队列。
    max_queued_event_bytes: ?usize = null,
    /// 调用方注入的并发上限。单输入搜索不据此创建线程，也不改写这个数。
    max_concurrency: ?u32 = null,
    /// 存在性查询。找到第一条匹配就返回，并关闭上游。不是有匹配来源列表。
    exists: bool = false,
    /// 只要没有匹配的来源。找到第一条匹配就停止这个来源，并且不把行交出去。
    /// 和 `invert` 不同：反选仍逐行交出不包含模式的行。
    files_without_match: bool = false,
    /// 每扫描这么多可搜索字节发一条 progress。null 或 0 表示不发。
    progress_interval: ?u64 = null,
    /// 调用方把输入标成实时流。空读是空闲，不是错误，也不是结束。
    live: bool = false,
    /// 实时流空闲超过这个时间就发心跳。
    idle_timeout_ns: ?u64 = null,
    /// 置位后，实时流的下一次空读才是结束。
    live_closed: ?*const std.atomic.Value(bool) = null,
    /// 暂停后续搜。`resumeSourceSlice` 填入。
    continuation: ?*const sink_mod.ResumeState = null,
    /// 有序输入在首条匹配之后遇到不匹配行立即停止并关闭上游。
    stop_on_nonmatch: bool = false,
    /// 全文高亮模式：输出所有行，不匹配行作为上下文事件交出，匹配行作为匹配事件交出。
    passthru: bool = false,
    /// 只读替换预览模板。非 null 时在 Span.replacement 与 Line.replaced / LineEvent.replaced 中给出替换后预览，不修改原输入。
    replacement: ?[]const u8 = null,
    /// 细节日志。消息可以含路径；返回的错误不含。库不把这些消息交给终端。
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

const width = memchr.native_width;

const Range = struct {
    start: usize,
    end: usize,
};

const BufMatch = struct {
    start: usize,
    end: usize,
};

const State = struct {
    pos: usize = 0,
    abs_base: u64 = 0,
    /// 非 null 时，它是 `last_line_counted` 处的行号（从 1 开始）。
    line_number: ?u64 = null,
    last_line_counted: usize = 0,
    last_line_visited: usize = 0,
    after_left: u32 = 0,
    has_sunk: bool = false,
    /// 占用 max_count 的命中数。上下文里被抬成匹配的行不加。
    limit_count: u64 = 0,
    matched_lines: u64 = 0,
    matches: u64 = 0,
    bytes_read: u64 = 0,
    bytes_searched: u64 = 0,
    nul_offset: ?u64 = null,
    binary_status: sink_mod.BinaryStatus = .none,
    stopped: bool = false,
    /// 已经交给 Sink 的最后一行的终点绝对偏移（含换行）。断点用它判断，不看缓冲下标。
    last_abs_end: u64 = 0,
    /// 这一位之前的完整行，要么已经交过，要么已经放进前置环。
    remembered_until: usize = 0,
    ring: BeforeRing = .{},
    long_active: bool = false,
    long_origin: u64 = 0,
    long_dropped: u64 = 0,
    long_number: ?u64 = null,
    long_has_match: bool = false,
    long_excluded: bool = false,
    long_hold_len: usize = 0,
    long_window_start: u64 = 0,
    long_line_len: u64 = 0,
    long_match_start: usize = 0,
    long_match_end: usize = 0,
    /// 0 没有留窗口，1 行首窗口，2 匹配窗口。
    long_hold_kind: u2 = 0,
    /// 这一块里很早就有匹配。后面的块改回先扫 NUL，避免每个密集块搜两遍。
    prefer_prepass: bool = false,
    /// 有损文本放不进栈缓冲时用。只在回调返回前有效。
    text_alloc: ?std.mem.Allocator = null,
    text_buf: []u8 = &.{},
    replace_buf: []u8 = &.{},
    /// 日志里用的来源名。不放进返回的错误。
    label: []const u8 = "",
    started_ns: i128 = 0,
    deadline_armed: bool = false,
    limit_hit: sink_mod.LimitHit = .none,
    resume_at: ?u64 = null,
    soft_error: ?sink_mod.SoftError = null,
    need_close: bool = false,
    closed: bool = false,
    output_bytes: u64 = 0,
    output_blocked: bool = false,
    results_out: u64 = 0,
    queued_bytes: usize = 0,
    hit_byte_cap: bool = false,
    scanned_all: bool = false,
    decompressed_bytes: u64 = 0,
    from_reader: bool = false,
    paused: bool = false,
    resume_line: u64 = 1,
    next_progress: u64 = 0,
    last_input_ns: i128 = 0,
    idle_sent: bool = false,

    fn exceeded(self: *const State, config: SearchConfig) bool {
        const limit = config.max_count orelse return false;
        return self.limit_count >= limit;
    }
};

const Prepared = struct {
    bytes: []const u8,
    owned: []u8 = &.{},
    alloc: ?std.mem.Allocator = null,

    fn deinit(self: *const Prepared) void {
        if (self.owned.len != 0) if (self.alloc) |alloc| alloc.free(self.owned);
    }
};

fn materialize(haystack: []const u8, config: SearchConfig) SliceError!Prepared {
    if (config.encoding != .auto) return .{ .bytes = haystack };
    const cap = decodeCap(config);
    switch (encoding.sniff(haystack, true)) {
        .raw, .need_more => return .{ .bytes = haystack },
        .utf8 => {
            const rest = if (haystack.len >= 3) haystack[3..] else haystack[0..0];
            if (encoding.validUtf8(rest)) return .{ .bytes = rest };
            if (encoding.decodedSize(.utf8, rest) > cap) return error.DecodeLimit;
            const alloc = config.decode_allocator orelse return error.OutOfMemory;
            const owned = try encoding.convertAlloc(alloc, .utf8, rest);
            return .{ .bytes = owned, .owned = owned, .alloc = alloc };
        },
        .utf16le, .utf16be => |kind| {
            if (encoding.decodedSize(kind, if (haystack.len >= 2) haystack[2..] else haystack[0..0]) > cap) {
                return error.DecodeLimit;
            }
            const alloc = config.decode_allocator orelse return error.OutOfMemory;
            const payload = if (haystack.len >= 2) haystack[2..] else haystack[0..0];
            const owned = try encoding.convertAlloc(alloc, kind, payload);
            return .{ .bytes = owned, .owned = owned, .alloc = alloc };
        },
    }
}

/// 旧回调入口，在 `haystack` 上搜索。没有 BOM 时行切片直接指向 `haystack`。
/// `name` 只传给旧的 `begin`。服务入口是 `searchSourceSlice`。
pub fn searchSlice(
    comptime S: type,
    sink: *S,
    haystack: []const u8,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) SliceError!Result {
    const view = try materialize(haystack, config);
    defer view.deinit();
    return searchPrepared(S, sink, view.bytes, name, matcher, config);
}

fn searchPrepared(
    comptime S: type,
    sink: *S,
    haystack: []const u8,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) SliceError!Result {
    validateBudgets(config) catch |err| {
        logDetail(config, name, err);
        return err;
    };
    resetStats(matcher);
    var state = State{};
    state.label = name;
    state.decompressed_bytes = config.decompressed_bytes;
    armClock(&state, config);
    state.text_alloc = config.decode_allocator;
    defer if (state.text_buf.len != 0) if (state.text_alloc) |alloc| alloc.free(state.text_buf);
    defer if (state.replace_buf.len != 0) if (state.text_alloc) |alloc| alloc.free(state.replace_buf);
    state.ring.cap = beforeCount(config);
    state.ring.stride = config.max_line_len;
    if (config.line_numbers) state.line_number = 1;
    restoreCounters(&state, config);
    const view = budgetView(haystack, &state, config);
    if (!callOpt(S, "begin", sink, .{name})) {
        noteRejected(S, &state, sink);
        if (state.paused) {
            state.resume_at = state.abs_base;
            state.resume_line = state.line_number orelse 1;
        }
        return finishSink(S, sink, &state, config);
    }
    if (rejectEmptyResults(&state, config)) return finishSink(S, sink, &state, config);
    if (stopForBudget(&state, config)) return finishSink(S, sink, &state, config);

    var skip_match = false;
    if (watchesBinary(config)) {
        var nul_at: ?usize = null;
        if (view.len > 0 and canFuse(matcher, config, &state)) {
            const found = matcher.findWatched(view, 0, &nul_at);
            if (nul_at == null) {
                if (found) |hit| {
                    if (memchr.find(width, view[hit.start..], 0, 0)) |rel| {
                        nul_at = hit.start + rel;
                    } else if (config.progress_interval == null or config.progress_interval.? == 0) {
                        state.pos = lineStart(view, hit.start, config);
                    }
                } else {
                    skip_match = true;
                    state.pos = view.len;
                }
            }
        } else {
            nul_at = memchr.find(width, view, 0, 0);
        }
        if (nul_at) |nul| {
            noteBinary(&state, config, state.abs_base + nul);
            const cont = callOpt(S, "binary", sink, .{state.nul_offset.?});
            if (config.binary == .quit) {
                const window = bufferWindow(config);
                if (nul < @min(view.len, window)) {
                    if (state.hit_byte_cap) noteLimit(&state, .max_bytes);
                    return finishSink(S, sink, &state, config);
                }
                const boundary = (nul / window) * window;
                if (!try matchBuffer(S, sink, matcher, view[0..boundary], &state, config)) {
                    state.stopped = true;
                }
                if (state.hit_byte_cap) noteLimit(&state, .max_bytes);
                return finishSink(S, sink, &state, config);
            }
            if (!cont) state.stopped = true;
        }
    }

    if (!state.stopped) {
        if (skip_match) {
            if (stopInMatch(&state, config) or !maybeProgress(S, sink, &state, config)) state.stopped = true;
        } else {
            if (!try matchBuffer(S, sink, matcher, view, &state, config)) state.stopped = true;
        }
    }
    const consumed = (!state.stopped or state.pos >= view.len) and !state.output_blocked;
    if (consumed and !state.hit_byte_cap and state.soft_error == null) state.scanned_all = true;
    if (state.hit_byte_cap) noteLimit(&state, .max_bytes);
    return finishSink(S, sink, &state, config);
}

/// 旧回调入口，从 `reader` 搜索。短读视为 EOF。缓冲在线程内由这一次调用独占，结束时释放。
/// `name` 只传给旧的 `begin`。服务入口是 `searchSource`。
pub fn searchReader(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    reader: *std.Io.Reader,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) ReadError!Result {
    resetStats(matcher);
    return drive(S, allocator, sink, matcher, config, name, struct {
        fn read(ctx: *anyopaque, dest: []u8) ReadError!usize {
            const r: *std.Io.Reader = @ptrCast(@alignCast(ctx));
            return r.readSliceShort(dest);
        }
    }.read, reader);
}

/// 从已经打开的文件里读。调用方自己持有文件，这里不接收路径。
/// 默认用 `readPositional`。窗口映射只在构建选项打开时才会编译进来，默认构建不走那条路径。
/// 本函数不从 `src/root.zig` 导出。服务入口是 `searchSource` 和 `searchSourceSlice`。
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
    resetStats(matcher);
    if (comptime build_options.window_map) {
        const window_map = @import("io/window_map.zig");
        if (try window_map.open(io, file, bufferWindow(config))) |opened| {
            var ctx = opened;
            defer ctx.close();
            return drive(S, allocator, sink, matcher, config, name, window_map.readBytes, &ctx);
        }
    }
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

/// 服务入口：搜索一段内存里的字节。
/// `source_id` 由调用方分配，库不解释。
/// 行号从 1 开始。NUL 记录模式计的是记录号。
/// `S` 提供 `pub fn event(self: *S, ev: Event) bool` 或返回 `Flow`。
/// 返回 false 或 `.stop` 就停止。`.pause` 先停住，`resumeSourceSlice` 再继续。
/// 行字节和匹配区间只在这次回调期间有效。每产生一个事件就调用一次。
/// 输入扫完之后再发 summary。没扫完、暂停、或实时流还开着时不发。
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

/// 从上次暂停的地方继续搜同一段内存。不重复 begin。
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

/// 服务入口：从 reader 搜索。没有标成实时流时，短读视为结束。
/// `source_id` 由调用方分配，库不解释。
/// 行号从 1 开始。NUL 记录模式计的是记录号。
/// `S` 提供 `pub fn event(self: *S, ev: Event) bool` 或返回 `Flow`。
/// 返回 false 或 `.stop` 就停止。`.pause` 先停住。
/// 行字节和匹配区间只在这次回调期间有效。每产生一个事件就调用一次。
/// 输入扫完之后再发 summary。没扫完、暂停、或实时流还开着时不发。
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

fn serviceConfig(config: SearchConfig) SearchConfig {
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

fn eventFlow(inner: anytype, ev: Event) Flow {
    const Ret = @typeInfo(@TypeOf(@field(@TypeOf(inner.*), "event"))).@"fn".return_type.?;
    if (Ret == bool) return if (inner.event(ev)) .cont else .stop;
    if (Ret == Flow) return inner.event(ev);
    @compileError("event 必须返回 bool 或 Flow");
}

fn EventBridge(comptime S: type) type {
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

fn shouldSummarize(config: SearchConfig, result: Result) bool {
    if (result.paused or !result.scanned_all) return false;
    if (config.live and !liveIsClosed(config)) return false;
    return true;
}

fn makeSummary(source_id: []const u8, result: Result) Summary {
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

fn emitSummary(comptime S: type, sink: *S, source_id: []const u8, config: SearchConfig, result: Result) void {
    if (!shouldSummarize(config, result)) return;
    _ = eventFlow(sink, .{ .summary = makeSummary(source_id, result) });
}

/// 拉式迭代器交出的一条事件。切片在 `SourcePull.deinit` 之前有效。
pub const PullEvent = struct {
    kind: enum { begin, match, context, context_break, progress, heartbeat, end, summary },
    source_id: []u8,
    line_number: u64 = 0,
    column: ?u64 = null,
    absolute_offset: u64 = 0,
    bytes: []u8 = &.{},
    spans: []Span = &.{},
    matched_lines: u64 = 0,
    matches: u64 = 0,
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
        if (self.spans.len != 0) allocator.free(self.spans);
    }
};

/// 能取出 begin、context、match、end 这一组事件的拉式接口。
/// 单行的 `SliceIter` 没有上下文，也不带来源事件。
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

fn copyPull(allocator: std.mem.Allocator, ev: Event) !PullEvent {
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
            .matched_lines = e.matched_lines,
            .matches = e.matches,
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
            var spans: []Span = &.{};
            errdefer if (spans.len != 0) allocator.free(spans);
            if (line.matches.len != 0) spans = try allocator.dupe(Span, line.matches);
            return .{
                .kind = if (ev == .match) .match else .context,
                .source_id = id,
                .line_number = line.line_number,
                .column = line.column,
                .absolute_offset = line.absolute_offset,
                .bytes = bytes,
                .spans = spans,
                .matched_lines = 0,
                .matches = @intCast(line.matches.len),
            };
        },
    }
}

fn lineEvent(source_id: []const u8, line: Line) sink_mod.LineEvent {
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

fn drive(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    matcher: anytype,
    config: SearchConfig,
    name: []const u8,
    comptime readFn: anytype,
    read_ctx: *anyopaque,
) ReadError!Result {
    validateBudgets(config) catch |err| {
        logDetail(config, name, err);
        return err;
    };
    var state = State{};
    state.label = name;
    state.decompressed_bytes = config.decompressed_bytes;
    armClock(&state, config);
    state.from_reader = true;
    state.text_alloc = allocator;
    defer if (state.text_buf.len != 0) allocator.free(state.text_buf);
    defer if (state.replace_buf.len != 0) allocator.free(state.replace_buf);
    state.ring.cap = beforeCount(config);
    state.ring.stride = config.max_line_len;
    if (state.ring.cap > 0) {
        const bytes = beforeContextCapacity(config);
        if (bytes > 0) state.ring.storage = try allocator.alloc(u8, bytes);
        state.ring.owned = true;
    }
    defer if (state.ring.storage.len != 0) allocator.free(state.ring.storage);
    var hold: []u8 = &.{};
    defer if (hold.len != 0) allocator.free(hold);
    var seen: []bool = &.{};
    defer if (seen.len != 0) allocator.free(seen);
    if (config.line_numbers) state.line_number = 1;
    restoreCounters(&state, config);
    if (!callOpt(S, "begin", sink, .{name})) {
        noteRejected(S, &state, sink);
        if (state.paused) {
            state.resume_at = state.abs_base;
            state.resume_line = state.line_number orelse 1;
        }
        return finishSink(S, sink, &state, config);
    }
    if (rejectEmptyResults(&state, config)) return finishSink(S, sink, &state, config);

    const initial = if (isMultilineMatcher(matcher))
        @max(bufferWindow(config), multilineWindow(matcher, config))
    else
        bufferWindow(config);
    const cap0 = @max(initial, 1);
    const borrowed = config.scratch != null;
    var buf: []u8 = undefined;
    if (config.scratch) |slot| {
        if (slot.len < cap0) {
            if (slot.len == 0) {
                slot.* = try allocator.alloc(u8, cap0);
            } else {
                slot.* = try allocator.realloc(slot.*, cap0);
            }
        }
        buf = slot.*;
    } else {
        buf = try allocator.alloc(u8, cap0);
    }
    defer if (!borrowed) allocator.free(buf);
    var filled: usize = 0;
    var decoder = encoding.Decoder.init(config.encoding);
    decoder.max_in = decodeCap(config);
    defer decoder.deinit(allocator);
    var upstream = Upstream{
        .inner = read_ctx,
        .state = &state,
        .config = config,
        .sink = @ptrCast(sink),
    };

    while (!state.stopped) {
        if (state.exceeded(config)) {
            state.stopped = true;
            break;
        }
        if (flagIsSet(config)) {
            state.stopped = true;
            break;
        }
        if (stopForBudget(&state, config)) break;
        if (filled == buf.len) {
            if (try grow(allocator, buf, config)) |next| {
                buf = next;
                if (config.scratch) |slot| slot.* = buf;
            } else if (!try makeRoom(S, allocator, sink, matcher, &buf, &filled, &hold, &seen, &state, config)) {
                state.stopped = true;
                break;
            } else if (config.scratch) |slot| slot.* = buf;
        }
        var dest = buf[filled..];
        if (scanRemaining(&state, config)) |left| {
            if (left == 0) {
                noteLimit(&state, .max_bytes);
                break;
            }
            if (dest.len > left) dest = dest[0..left];
        }
        const pulled = decoder.pull(allocator, struct {
            fn read(ctx: *anyopaque, out: []u8) readRet(readFn) {
                return readUpstream(S, readFn, ctx, out);
            }
        }.read, &upstream, bufferWindow(config), dest, &state.bytes_read) catch |err| {
            if (err == error.OutOfMemory) return error.OutOfMemory;
            if (err == error.DecodeLimit) return error.DecodeLimit;
            state.soft_error = .read_failed;
            logDetail(config, name, err);
            state.need_close = true;
            break;
        };
        const eof = pulled.eof;
        if (pulled.n == 0 and !eof and filled == 0) continue;
        var chunk_at = filled;
        if (pulled.n != 0) filled += pulled.n;

        if (state.long_active or longTail(buf[0..filled], eof, config)) {
            const cont = try pumpLong(
                S,
                allocator,
                sink,
                matcher,
                &buf,
                &filled,
                &hold,
                &seen,
                chunk_at,
                eof,
                &state,
                config,
            );
            if (config.scratch) |slot| slot.* = buf;
            if (!cont) {
                state.stopped = true;
                break;
            }
            if (state.long_active) {
                if (eof) break;
                continue;
            }
            chunk_at = 0;
        }

        const search_end = if (eof) filled else lastComplete(buf[0..filled], config);
        const view_end = if (eof) filled else search_end;
        // 文本快路径把 NUL 检查并进查找。单独再扫一遍 NUL，1 GiB 热文件大约要 19 ms，
        // 单字节模式会因此慢过 rg。上下文和密集匹配仍走原来的先扫 NUL。
        const fuse = search_end > state.pos and canFuse(matcher, config, &state);
        var skip_match = false;
        if (fuse) {
            var nul_rel: ?usize = null;
            const found = matcher.findWatched(buf[0..search_end], state.pos, &nul_rel);
            if (nul_rel == null and search_end < filled) {
                if (memchr.find(width, buf[search_end..filled], 0, 0)) |rel| nul_rel = search_end + rel;
            }
            if (nul_rel == null) {
                if (found) |hit| {
                    if (memchr.find(width, buf[hit.start..filled], 0, 0)) |rel| {
                        nul_rel = hit.start + rel;
                    } else {
                        if (hit.start < state.pos + 4096) {
                            state.prefer_prepass = true;
                        }
                        if (config.progress_interval == null or config.progress_interval.? == 0) {
                            state.pos = lineStart(buf[0..view_end], hit.start, config);
                        }
                    }
                } else {
                    skip_match = true;
                    state.pos = view_end;
                }
            }
            if (nul_rel) |rel| {
                noteBinary(&state, config, state.abs_base + rel);
                const cont = callOpt(S, "binary", sink, .{state.nul_offset.?});
                if (config.binary == .quit or !cont) {
                    filled = chunk_at;
                    state.stopped = true;
                    break;
                }
                skip_match = false;
            }
        } else if (!eof and watchesBinary(config) and state.nul_offset == null) {
            if (memchr.find(width, buf[chunk_at..filled], 0, 0)) |rel| {
                noteBinary(&state, config, state.abs_base + chunk_at + rel);
                const cont = callOpt(S, "binary", sink, .{state.nul_offset.?});
                if (config.binary == .quit or !cont) {
                    filled = chunk_at;
                    state.stopped = true;
                    break;
                }
            }
        }

        const is_ml = isMultilineMatcher(matcher);
        const ml_win = if (is_ml) multilineWindow(matcher, config) else 0;
        if (is_ml and !eof and filled < ml_win and !config.passthru and !config.invert) {
            if (matcher.find(buf[0..search_end], state.pos, config.match_mode) == null) {
                continue;
            }
        }

        if (!skip_match and (search_end > state.pos or eof)) {
            if (!try matchBuffer(S, sink, matcher, buf[0..view_end], &state, config)) {
                state.stopped = true;
                if (eof and state.pos >= view_end and !state.output_blocked) state.scanned_all = true;
                break;
            }
        }

        if (is_ml and isStartAnchoredMatcher(matcher) and state.abs_base + filled >= ml_win) {
            state.stopped = true;
            state.need_close = true;
            break;
        }

        if (eof) {
            state.scanned_all = !state.output_blocked and state.soft_error == null;
            break;
        }
        if (state.stopped) break;

        const consumed = if (is_ml and search_end > ml_win)
            @max(state.last_line_visited, lineEnd(buf[0..search_end], search_end - ml_win, config))
        else
            search_end;
        if (is_ml and consumed < search_end) {
            state.pos = consumed;
        }
        rememberBefore(matcher, buf, &state, config, consumed);
        countLines(buf, consumed, &state, config);
        const remain = filled - consumed;
        if (consumed > 0 and remain > 0) {
            std.mem.copyForwards(u8, buf[0..remain], buf[consumed..filled]);
        }
        filled = remain;
        state.pos = if (state.pos >= consumed) state.pos - consumed else 0;
        state.last_line_visited = 0;
        state.last_line_counted = 0;
        state.abs_base += consumed;
    }

    return finishSink(S, sink, &state, config);
}

fn flagIsSet(config: SearchConfig) bool {
    const flag = config.stop orelse return false;
    return flag.load(.acquire);
}

fn cancelIsSet(config: SearchConfig) bool {
    const flag = config.cancel orelse return false;
    return flag.load(.acquire);
}

fn logDetail(config: SearchConfig, label: []const u8, err: anyerror) void {
    const log = config.log orelse return;
    var buf: [192]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "{s}: {s}", .{ label, @errorName(err) }) catch label;
    log(config.log_ctx, msg);
}

fn monotonicNs() i128 {
    var ts: std.posix.timespec = undefined;
    switch (std.posix.errno(std.posix.system.clock_gettime(std.posix.CLOCK.MONOTONIC, &ts))) {
        .SUCCESS => {
            const sec: i128 = ts.sec;
            const nsec: i128 = ts.nsec;
            return sec * std.time.ns_per_s + nsec;
        },
        else => return 0,
    }
}

fn readClock(config: SearchConfig) i128 {
    if (config.clock) |clock| return clock(config.clock_ctx);
    return monotonicNs();
}

fn armClock(state: *State, config: SearchConfig) void {
    if (config.continuation) |saved| {
        state.started_ns = saved.started_ns;
        state.deadline_armed = saved.deadline_armed;
        state.last_input_ns = saved.started_ns;
        return;
    }
    state.started_ns = readClock(config);
    state.last_input_ns = state.started_ns;
    if (config.time_budget_ns != null) state.deadline_armed = true;
}

fn restoreCounters(state: *State, config: SearchConfig) void {
    const saved = config.continuation orelse return;
    state.matched_lines = saved.matched_lines;
    state.matches = saved.matches;
    state.bytes_read = saved.bytes_read;
    state.bytes_searched = saved.bytes_searched;
    state.output_bytes = saved.output_bytes;
    state.results_out = saved.results_out;
    state.limit_count = saved.limit_count;
    if (config.line_numbers) state.line_number = saved.line_number;
}

fn liveIsClosed(config: SearchConfig) bool {
    if (!config.live) return true;
    const flag = config.live_closed orelse return false;
    return flag.load(.acquire);
}

const Upstream = struct {
    inner: *anyopaque,
    state: *State,
    config: SearchConfig,
    sink: *anyopaque,
    spins: u8 = 0,
    spin_at: i128 = 0,
    have_spin: bool = false,
};

fn readRet(comptime readFn: anytype) type {
    return @typeInfo(@TypeOf(readFn)).@"fn".return_type.?;
}

fn readUpstream(comptime S: type, comptime readFn: anytype, ctx: *anyopaque, dest: []u8) readRet(readFn) {
    const box: *Upstream = @ptrCast(@alignCast(ctx));
    if (!box.config.live) return readFn(box.inner, dest);
    const sink: *S = @ptrCast(@alignCast(box.sink));
    while (!box.state.stopped) {
        const n = try readFn(box.inner, dest);
        if (n != 0) {
            box.state.last_input_ns = readClock(box.config);
            box.state.idle_sent = false;
            box.spins = 0;
            box.have_spin = false;
            return n;
        }
        if (liveIsClosed(box.config)) return 0;
        const now = readClock(box.config);
        if (box.have_spin and now == box.spin_at) {
            box.spins += 1;
            if (box.spins > 8) return 0;
        } else {
            box.spin_at = now;
            box.have_spin = true;
            box.spins = 0;
        }
        const timeout: i128 = @intCast(box.config.idle_timeout_ns orelse 0);
        if (!box.state.idle_sent and now - box.state.last_input_ns >= timeout) {
            const at = box.state.abs_base + @as(u64, box.state.pos);
            const keep = callOpt(S, "heartbeat", sink, .{ at, box.state.matches, box.state.matched_lines });
            box.state.idle_sent = true;
            if (!keep) {
                noteRejected(S, box.state, sink);
                return 0;
            }
        }
        if (stopForBudget(box.state, box.config)) return 0;
    }
    return 0;
}

fn noteRejected(comptime S: type, state: *State, sink: *S) void {
    if (@hasDecl(S, "control") and sink.control() == .pause) state.paused = true;
    state.stopped = true;
}

fn isPause(comptime S: type, sink: *S) bool {
    return @hasDecl(S, "control") and sink.control() == .pause;
}

fn pastDeadline(state: *const State, config: SearchConfig) bool {
    if (!state.deadline_armed) return false;
    const budget = config.time_budget_ns orelse return false;
    return readClock(config) - state.started_ns >= @as(i128, budget);
}

fn scanCap(config: SearchConfig) ?u64 {
    var cap: ?u64 = null;
    if (config.max_source_bytes) |n| cap = n;
    if (config.max_request_bytes) |n| cap = if (cap) |cur| @min(cur, n) else n;
    return cap;
}

fn overBytes(state: *const State, config: SearchConfig) bool {
    const cap = scanCap(config) orelse return false;
    return state.bytes_read >= cap;
}

fn scanRemaining(state: *const State, config: SearchConfig) ?usize {
    const cap = scanCap(config) orelse return null;
    if (state.bytes_read >= cap) return 0;
    const left = cap - state.bytes_read;
    if (left > std.math.maxInt(usize)) return std.math.maxInt(usize);
    return @intCast(left);
}

fn overDecompressed(state: *const State, config: SearchConfig) bool {
    const cap = config.max_decompressed_bytes orelse return false;
    return state.decompressed_bytes >= cap;
}

fn noteLimit(state: *State, reason: sink_mod.LimitHit) void {
    if (state.limit_hit == .none) state.limit_hit = reason;
    state.stopped = true;
    state.need_close = true;
}

fn stopForBudget(state: *State, config: SearchConfig) bool {
    if (pastDeadline(state, config)) {
        noteLimit(state, .deadline);
        return true;
    }
    if (cancelIsSet(config)) {
        noteLimit(state, .cancelled);
        return true;
    }
    if (overBytes(state, config)) {
        noteLimit(state, .max_bytes);
        return true;
    }
    if (overDecompressed(state, config)) {
        noteLimit(state, .decompressed_bytes);
        return true;
    }
    return false;
}

fn stopInMatch(state: *State, config: SearchConfig) bool {
    if (pastDeadline(state, config)) {
        noteLimit(state, .deadline);
        return true;
    }
    if (cancelIsSet(config)) {
        noteLimit(state, .cancelled);
        return true;
    }
    return false;
}

fn rejectEmptyResults(state: *State, config: SearchConfig) bool {
    const cap = config.max_results orelse return false;
    if (cap != 0) return false;
    state.resume_at = state.abs_base;
    noteLimit(state, .max_results);
    return true;
}

fn closeOnce(state: *State, config: SearchConfig) void {
    if (state.closed or !state.need_close) return;
    state.closed = true;
    if (config.close_input) |close| close(config.close_ctx);
}

fn decodeCap(config: SearchConfig) usize {
    return config.max_decode_bytes orelse SearchConfig.max_decode_bytes_hard_cap;
}

fn budgetView(haystack: []const u8, state: *State, config: SearchConfig) []const u8 {
    var bytes = haystack;
    if (config.resume_from > 0) {
        const off: usize = if (config.resume_from >= haystack.len) haystack.len else @intCast(config.resume_from);
        state.abs_base = off;
        bytes = haystack[off..];
    }
    if (scanCap(config)) |cap| {
        if (@as(u64, bytes.len) > cap) {
            bytes = bytes[0..@intCast(cap)];
            state.hit_byte_cap = true;
        }
    }
    return bytes;
}

fn validateBudgets(config: SearchConfig) error{ ContextLinesExceeded, BudgetExceeded, BufferLimit }!void {
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
    const before_cap = config.max_before_bytes orelse SearchConfig.max_before_bytes_hard_cap;
    if (beforeContextCapacity(config) > before_cap) return error.BufferLimit;
}

fn releaseQueue(state: *State) void {
    state.queued_bytes = 0;
}

fn guardLine(state: *State, config: SearchConfig, nbytes: usize) error{BufferLimit}!bool {
    if (config.max_queued_event_bytes) |cap| {
        if (nbytes > cap) {
            logDetail(config, state.label, error.BufferLimit);
            return error.BufferLimit;
        }
        state.queued_bytes = nbytes;
    }
    if (config.max_output_bytes) |cap| {
        const used = state.output_bytes;
        if (used >= cap or @as(u64, nbytes) > cap - used) {
            state.output_blocked = true;
            state.stopped = true;
            state.need_close = true;
            state.queued_bytes = 0;
            return false;
        }
        state.output_bytes = used + nbytes;
    }
    return true;
}

/// 找到的匹配已经交出去了。返回 false 表示不要再找下一条。
fn noteHitLimit(state: *State, config: SearchConfig, end_abs: u64) bool {
    if (config.exists) {
        state.stopped = true;
        state.need_close = true;
        return false;
    }
    if (config.max_results) |cap| {
        if (state.results_out >= cap) {
            state.resume_at = end_abs;
            noteLimit(state, .max_results);
            return false;
        }
    }
    return true;
}

fn grow(allocator: std.mem.Allocator, buf: []u8, config: SearchConfig) error{OutOfMemory}!?[]u8 {
    const limit = lineHoldLimit(config);
    if (buf.len >= limit) return null;
    const doubled = if (buf.len > limit / 2) limit else buf.len * 2;
    const next = @min(limit, @max(doubled, buf.len + 1));
    if (next <= buf.len) return null;
    return try allocator.realloc(buf, next);
}

fn isMultilineMatcher(matcher: anytype) bool {
    const T = @TypeOf(matcher.*);
    if (@hasDecl(T, "isMultiline")) return matcher.isMultiline();
    return false;
}

fn isStartAnchoredMatcher(matcher: anytype) bool {
    const T = @TypeOf(matcher.*);
    if (@hasDecl(T, "isStartAnchored")) return matcher.isStartAnchored();
    return false;
}

fn multilineWindow(matcher: anytype, config: SearchConfig) usize {
    const T = @TypeOf(matcher.*);
    const cap = if (config.max_line_len == 0) 1 else config.max_line_len;
    if (@hasDecl(T, "multilineWindow")) return @min(matcher.multilineWindow(), cap);
    return cap;
}

fn canFuse(matcher: anytype, config: SearchConfig, state: *const State) bool {
    if (config.null_data) return false;
    if (isMultilineMatcher(matcher)) return false;
    if (config.passthru or config.stop_on_nonmatch) return false;
    if (state.prefer_prepass or state.nul_offset != null) return false;
    if (config.binary == .none or config.invert or beforeCount(config) != 0 or afterCount(config) != 0) return false;
    if (config.whole_word or config.whole_line or config.contains.len != 0 or config.excludes.len != 0) return false;
    return @hasDecl(@TypeOf(matcher.*), "findWatched");
}

fn bufferWindow(config: SearchConfig) usize {
    if (config.buffer_size == 0) return SearchConfig.default_buffer_size;
    return config.buffer_size;
}

fn recordSep(config: SearchConfig) u8 {
    return if (config.null_data) 0 else '\n';
}

/// NUL 只在 LF 分行、并且不是 NUL 记录模式时当成二进制信号。
fn watchesBinary(config: SearchConfig) bool {
    return config.binary != .none and !config.null_data;
}

fn noteBinary(state: *State, config: SearchConfig, offset: u64) void {
    if (state.nul_offset == null) state.nul_offset = offset;
    state.binary_status = binaryStatus(config, state.nul_offset);
}

fn binaryStatus(config: SearchConfig, nul: ?u64) sink_mod.BinaryStatus {
    if (nul == null or !watchesBinary(config)) return .none;
    return if (config.binary == .quit) .suppressed else .detected;
}

fn lastComplete(buf: []const u8, config: SearchConfig) usize {
    if (memchr.findLast(width, buf, 0, buf.len, recordSep(config))) |i| return i + 1;
    return 0;
}

/// 返回 false 表示停止，但不是错误。
fn matchBuffer(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    while (state.pos < buf.len) {
        if (state.stopped) return false;
        if (stopInMatch(state, config)) return false;
        if (!maybeProgress(S, sink, state, config)) return false;
        if (config.invert) {
            if (!try matchInvert(S, sink, matcher, buf, state, config)) break;
        } else if (try findLine(matcher, buf, state, config)) |line| {
            if (state.abs_base + @as(u64, line.start) < config.resume_from) {
                state.pos = line.end;
                continue;
            }
            if (config.stop_on_nonmatch and state.matched_lines > 0 and line.start > state.pos) {
                state.pos = lineEnd(buf, state.pos, config);
                state.stopped = true;
                state.need_close = true;
                return false;
            }
            if (config.files_without_match) {
                state.limit_count += 1;
                state.matched_lines += 1;
                state.matches += 1;
                state.results_out += 1;
                state.pos = line.end;
                state.stopped = true;
                state.need_close = true;
                return false;
            }
            state.limit_count += 1;
            if (config.passthru) {
                if (!try passthruTo(S, sink, matcher, buf, line.start, state, config)) return false;
            } else if (beforeCount(config) > 0 or afterCount(config) > 0) {
                if (!try afterContext(S, sink, matcher, buf, line.start, state, config)) return false;
                if (!try beforeContext(S, sink, matcher, buf, line.start, state, config)) return false;
            }
            state.pos = line.end;
            const known = BufMatch{ .start = line.mstart, .end = line.mend };
            if (!try sinkMatched(S, sink, matcher, buf, line.range(), known, state, config)) return false;
        } else {
            if (config.stop_on_nonmatch and state.matched_lines > 0) {
                state.pos = lineEnd(buf, state.pos, config);
                state.stopped = true;
                state.need_close = true;
                return false;
            }
            break;
        }
    }
    if (state.stopped) return false;
    if (!maybeProgress(S, sink, state, config)) return false;
    if (config.passthru and !state.exceeded(config)) {
        if (!try passthruTo(S, sink, matcher, buf, buf.len, state, config)) return false;
    } else {
        if (!try afterContext(S, sink, matcher, buf, buf.len, state, config)) return false;
    }
    // 上限已经达到时，缓冲里的 after 行刚才交过了，不能再为后面的行去读。
    if (state.exceeded(config)) return false;
    state.pos = buf.len;
    return !state.stopped;
}

const FoundLine = struct {
    start: usize,
    end: usize,
    mstart: usize,
    mend: usize,

    fn range(self: FoundLine) Range {
        return .{ .start = self.start, .end = self.end };
    }
};

fn findLine(matcher: anytype, buf: []const u8, state: *State, config: SearchConfig) SliceError!?FoundLine {
    if (state.exceeded(config)) return null;
    var pos = state.pos;
    while (pos < buf.len) {
        const found = if (config.whole_line)
            matcher.find(buf, pos, config.match_mode)
        else
            nextMatch(matcher, buf, pos, config);
        const hit = found orelse return null;
        if (hit.start > buf.len or hit.start < pos) return null;
        const start = lineStart(buf, hit.start, config);
        if (start == buf.len) {
            pos = buf.len;
            continue;
        }
        const end = lineEnd(buf, @max(hit.end, start), config);
        if (end == start) {
            pos = @min(buf.len, start + 1);
            continue;
        }
        const content_end = contentEnd(buf, .{ .start = start, .end = end }, config);
        if (config.whole_line and !acceptsWholeLine(matcher, buf, start, content_end)) {
            pos = end;
            continue;
        }
        if (!linePassesFilters(buf, start, content_end, config)) {
            pos = end;
            continue;
        }
        return .{
            .start = start,
            .end = end,
            .mstart = if (config.whole_line) start else hit.start,
            .mend = if (config.whole_line) content_end else hit.end,
        };
    }
    return null;
}

fn nextMatch(matcher: anytype, buf: []const u8, pos: usize, config: SearchConfig) ?matcher_mod.Match {
    if (config.whole_word and @hasDecl(@TypeOf(matcher.*), "findAllowed")) {
        return matcher.findAllowed(buf, pos, config.match_mode, wordBounded);
    }
    return matcher.find(buf, pos, config.match_mode);
}

fn acceptsWholeLine(matcher: anytype, buf: []const u8, start: usize, end: usize) bool {
    if (end < start or end > buf.len) return false;
    const T = @TypeOf(matcher.*);
    if (@hasDecl(T, "acceptsSpan")) return matcher.acceptsSpan(buf, start, end);
    const found = matcher.find(buf[start..end], 0, .leftmost_first) orelse return false;
    return found.start == 0 and found.end == end - start;
}

fn linePassesFilters(buf: []const u8, start: usize, end: usize, config: SearchConfig) bool {
    if (config.contains.len == 0 and config.excludes.len == 0) return true;
    if (end < start or end > buf.len) return false;
    const text = buf[start..end];
    for (config.contains) |pat| {
        if (std.mem.indexOf(u8, text, pat) == null) return false;
    }
    for (config.excludes) |pat| {
        if (std.mem.indexOf(u8, text, pat) != null) return false;
    }
    return true;
}

fn isWordByte(b: u8) bool {
    return switch (b) {
        '0'...'9', 'A'...'Z', 'a'...'z', '_' => true,
        else => false,
    };
}

/// 半边界：只看匹配外侧的字节，不要求匹配两端自身是单词字符。
fn wordBounded(haystack: []const u8, start: usize, end: usize) bool {
    if (start > haystack.len or end > haystack.len or start > end) return false;
    if (start > 0 and isWordByte(haystack[start - 1])) return false;
    if (end < haystack.len and isWordByte(haystack[end])) return false;
    return true;
}

fn matchInvert(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    var found_nonmatch = false;
    var nonmatch_range: Range = .{ .start = 0, .end = 0 };
    const gap: Range = if (try findLine(matcher, buf, state, config)) |line| blk: {
        const g = Range{ .start = state.pos, .end = line.start };
        state.pos = line.end;
        found_nonmatch = true;
        nonmatch_range = line.range();
        break :blk g;
    } else blk: {
        const g = Range{ .start = state.pos, .end = buf.len };
        state.pos = buf.len;
        break :blk g;
    };
    if (gap.start < gap.end) {
        if (config.passthru) {
            if (!try passthruTo(S, sink, matcher, buf, gap.start, state, config)) return false;
        } else if (beforeCount(config) > 0 or afterCount(config) > 0) {
            if (!try afterContext(S, sink, matcher, buf, gap.start, state, config)) return false;
            if (!try beforeContext(S, sink, matcher, buf, gap.start, state, config)) return false;
        }
        var cursor = gap.start;
        while (nextLine(buf, cursor, gap.end, config)) |line| {
            cursor = line.end;
            const content_end = contentEnd(buf, line, config);
            if (!linePassesFilters(buf, line.start, content_end, config)) {
                if (config.stop_on_nonmatch and state.matched_lines > 0) {
                    state.pos = line.end;
                    state.stopped = true;
                    state.need_close = true;
                    return false;
                }
                if (config.passthru) {
                    if (!try sinkContext(S, sink, matcher, buf, line, .after, state, config)) return false;
                }
                continue;
            }
            state.limit_count += 1;
            if (!try sinkMatched(S, sink, matcher, buf, line, null, state, config)) return false;
            if (state.exceeded(config)) return false;
        }
    }
    if (found_nonmatch) {
        if (config.stop_on_nonmatch and state.matched_lines > 0) {
            state.stopped = true;
            state.need_close = true;
            return false;
        }
        if (config.passthru) {
            if (!try sinkContext(S, sink, matcher, buf, nonmatch_range, .after, state, config)) return false;
        }
    }
    return true;
}

fn passthruTo(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    upto: usize,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    var cursor = state.last_line_visited;
    if (cursor > upto) return true;
    while (nextLine(buf, cursor, upto, config)) |line| {
        cursor = line.end;
        if (!try sinkContext(S, sink, matcher, buf, line, .after, state, config)) return false;
    }
    return true;
}

fn afterContext(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    upto: usize,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    if (state.after_left == 0) return true;
    const exceeded = state.exceeded(config);
    var cursor = state.last_line_visited;
    if (cursor > upto) return true;
    while (nextLine(buf, cursor, upto, config)) |line| {
        cursor = line.end;
        if (exceeded and lineIsReportedHit(matcher, buf, line, config)) {
            const saved = state.after_left;
            state.pos = line.end;
            const known = matchInLine(matcher, buf, line, config);
            if (!try sinkMatched(S, sink, matcher, buf, line, known, state, config)) return false;
            state.after_left = saved - 1;
        } else if (!try sinkContext(S, sink, matcher, buf, line, .after, state, config)) return false;
        if (state.after_left == 0) break;
    }
    return true;
}

fn beforeContext(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    upto: usize,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    if (beforeCount(config) == 0) return true;
    // 匹配可能落在本块开头，前置行已经在上一块推进环里。
    // 那种情况下 last_line_visited == upto，仍然要把环交出去。
    if (state.last_line_visited < upto) {
        rememberBefore(matcher, buf, state, config, upto);
    }
    return emitRing(S, sink, buf, state, config);
}

const ContextKind = enum { before, after };

fn spanBefore(_: void, a: Span, b: Span) bool {
    if (a.start == b.start) return a.end < b.end;
    return a.start < b.start;
}

fn growSpans(alloc: ?std.mem.Allocator, store: []Span, heap: *[]Span, n: usize) SliceError![]Span {
    const a = alloc orelse return error.OutOfMemory;
    const bigger_n = @max(store.len * 2, n + 1);
    if (heap.len == 0) {
        const bigger = try a.alloc(Span, bigger_n);
        @memcpy(bigger[0..n], store[0..n]);
        heap.* = bigger;
        return bigger;
    }
    heap.* = try a.realloc(heap.*, bigger_n);
    return heap.*;
}

/// 这一行里不重叠的匹配，相对预览窗口，按起点排序。
/// 空模式只留一个零宽区间，避免按每个字节空转。
fn gatherSpans(
    alloc: ?std.mem.Allocator,
    inline_buf: []Span,
    heap: *[]Span,
    matcher: anytype,
    buf: []const u8,
    line: Range,
    preview: Preview,
    known: ?BufMatch,
    config: SearchConfig,
) SliceError![]Span {
    if (known == null) return inline_buf[0..0];
    var store = inline_buf;
    var n: usize = 0;
    if (config.whole_line) {
        if (preview.span) |span| {
            store[0] = span;
            n = 1;
        }
        return store[0..n];
    }
    const content_end = contentEnd(buf, line, config);
    const win_lo = preview.start;
    const win_hi = preview.end;
    var pos = line.start;
    while (pos <= content_end and pos <= buf.len) {
        const found = nextMatch(matcher, buf, pos, config) orelse break;
        if (found.start < pos or found.start > buf.len or found.start > content_end) break;
        if (found.start == content_end and found.end > content_end) break;
        const mend = @min(found.end, content_end);
        const empty = found.start == mend;
        const in_window = found.start >= win_lo and found.start < win_hi;
        const empty_at_point = empty and found.start == win_lo and win_lo == win_hi;
        if (in_window or empty_at_point) {
            if (n == store.len) store = try growSpans(alloc, store, heap, n);
            if (empty_at_point) {
                store[n] = .{ .start = 0, .end = 0 };
            } else {
                store[n] = .{
                    .start = found.start - win_lo,
                    .end = @min(mend, win_hi) - win_lo,
                };
            }
            n += 1;
        }
        if (empty or found.end <= pos) break;
        pos = found.end;
    }
    if (n == 0) {
        if (preview.span) |span| {
            if (store.len == 0) store = try growSpans(alloc, store, heap, 0);
            store[0] = span;
            n = 1;
        }
    }
    std.mem.sort(Span, store[0..n], {}, spanBefore);
    return store[0..n];
}

fn sinkLine(
    comptime S: type,
    comptime name: []const u8,
    sink: *S,
    state: *State,
    bytes: []const u8,
    span: ?Span,
    matches: []Span,
    offset: u64,
    number: ?u64,
    truncated: bool,
    line_len: u64,
    window_start: u64,
    replacement: ?[]const u8,
) bool {
    var one: [1]Span = undefined;
    var multi = matches;
    if (multi.len == 0) {
        if (span) |found| {
            one[0] = .{ .start = found.start, .end = found.end };
            multi = &one;
        }
    }
    var scratch: [1024]u8 = undefined;
    var replace_scratch: [4096]u8 = undefined;
    const line = buildLine(state, &scratch, &replace_scratch, bytes, span, multi, offset, number, truncated, line_len, window_start, replacement);
    return callOpt(S, name, sink, .{line});
}

fn buildLine(
    state: *State,
    scratch: []u8,
    replace_scratch: []u8,
    bytes: []const u8,
    span: ?Span,
    matches: []Span,
    offset: u64,
    number: ?u64,
    truncated: bool,
    line_len: u64,
    window_start: u64,
    replacement: ?[]const u8,
) Line {
    const text = lossyText(state, scratch, bytes);
    for (matches) |*item| {
        const from = @min(item.start, bytes.len);
        const to = @min(@max(item.end, from), bytes.len);
        const units = encoding.utf16Span(bytes, from, to);
        item.u16_start = units.start;
        item.u16_end = units.end;
        item.replacement = replacement;
    }
    var match = span;
    var u16_column: ?u64 = null;
    if (span) |found| {
        const from = @min(found.start, bytes.len);
        const to = @min(@max(found.end, from), bytes.len);
        const units = encoding.utf16Span(bytes, from, to);
        match = .{
            .start = found.start,
            .end = found.end,
            .u16_start = units.start,
            .u16_end = units.end,
            .replacement = replacement,
        };
        u16_column = units.start + 1;
    }
    const replaced: ?[]const u8 = if (replacement) |repl|
        if (matches.len > 0) buildReplaced(state, replace_scratch, bytes, matches, repl) else null
    else
        null;
    const column: ?u64 = if (matches.len > 0) @as(u64, matches[0].start) + 1 else null;
    return .{
        .bytes = bytes,
        .text = text,
        .raw = bytes,
        .replaced = replaced,
        .offset = offset,
        .number = number,
        .match = match,
        .matches = matches,
        .column = column,
        .u16_column = u16_column,
        .binary_status = state.binary_status,
        .truncated = truncated,
        .line_len = line_len,
        .window_start = window_start,
    };
}

fn buildReplaced(
    state: *State,
    scratch: []u8,
    bytes: []const u8,
    matches: []const Span,
    repl: []const u8,
) ?[]const u8 {
    var need: usize = 0;
    var cursor: usize = 0;
    for (matches) |item| {
        const from = @min(item.start, bytes.len);
        const to = @min(@max(item.end, from), bytes.len);
        if (from > cursor) need += from - cursor;
        need += repl.len;
        cursor = @max(cursor, to);
    }
    if (cursor < bytes.len) need += bytes.len - cursor;
    const dest = replaceDest(state, scratch, need) orelse return null;
    cursor = 0;
    var out: usize = 0;
    for (matches) |item| {
        const from = @min(item.start, bytes.len);
        const to = @min(@max(item.end, from), bytes.len);
        if (from > cursor) {
            const seg = bytes[cursor..from];
            @memcpy(dest[out .. out + seg.len], seg);
            out += seg.len;
        }
        if (repl.len > 0) {
            @memcpy(dest[out .. out + repl.len], repl);
            out += repl.len;
        }
        cursor = @max(cursor, to);
    }
    if (cursor < bytes.len) {
        const tail = bytes[cursor..];
        @memcpy(dest[out .. out + tail.len], tail);
        out += tail.len;
    }
    return dest[0..out];
}

fn replaceDest(state: *State, scratch: []u8, need: usize) ?[]u8 {
    if (need <= scratch.len) return scratch[0..need];
    const alloc = state.text_alloc orelse return null;
    if (state.replace_buf.len < need) {
        if (state.replace_buf.len == 0) {
            state.replace_buf = alloc.alloc(u8, need) catch return null;
        } else {
            state.replace_buf = alloc.realloc(state.replace_buf, need) catch return null;
        }
    }
    if (state.replace_buf.len < need) return null;
    return state.replace_buf[0..need];
}

fn lossyText(state: *State, scratch: []u8, bytes: []const u8) []const u8 {
    if (encoding.validUtf8(bytes)) return bytes;
    const need = encoding.lossyLen(bytes);
    const dest = lossyDest(state, scratch, need) orelse return bytes;
    return dest[0..encoding.writeLossy(bytes, dest)];
}

fn lossyDest(state: *State, scratch: []u8, need: usize) ?[]u8 {
    if (need <= scratch.len) return scratch[0..need];
    const alloc = state.text_alloc orelse return null;
    if (state.text_buf.len < need) {
        if (state.text_buf.len == 0) {
            state.text_buf = alloc.alloc(u8, need) catch return null;
        } else {
            state.text_buf = alloc.realloc(state.text_buf, need) catch return null;
        }
    }
    if (state.text_buf.len < need) return null;
    return state.text_buf[0..need];
}

fn nextLineNumber(state: *const State, buf: []const u8, line: Range, config: SearchConfig) u64 {
    var n = state.line_number orelse 1;
    if (line.end > line.start and line.end <= buf.len and buf[line.end - 1] == recordSep(config)) n += 1;
    return n;
}

fn maybeProgress(comptime S: type, sink: *S, state: *State, config: SearchConfig) bool {
    const step = config.progress_interval orelse return true;
    if (step == 0) return true;
    const at = state.abs_base + @as(u64, state.pos);
    if (state.next_progress == 0) state.next_progress = step;
    if (at < state.next_progress) return true;
    state.next_progress = at + step;
    const keep = callOpt(S, "progress", sink, .{ at, state.matches, state.matched_lines });
    if (!keep) {
        noteRejected(S, state, sink);
        return false;
    }
    return true;
}

fn sinkMatched(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    line: Range,
    known: ?BufMatch,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    const preview = previewLine(buf, line, known, config);
    const line_abs = state.abs_base + line.start;
    if (!try sinkBreakAt(S, sink, line_abs, state, config)) return false;
    countLines(buf, line.start, state, config);
    const withheld = config.binary == .report and state.nul_offset != null;
    const bytes = if (withheld) buf[line.start..line.start] else buf[preview.start..preview.end];
    var inline_spans: [32]Span = undefined;
    var span_heap: []Span = &.{};
    defer if (span_heap.len != 0) if (state.text_alloc) |alloc| alloc.free(span_heap);
    const matches = if (withheld) inline_spans[0..0] else try gatherSpans(
        state.text_alloc,
        &inline_spans,
        &span_heap,
        matcher,
        buf,
        line,
        preview,
        known,
        config,
    );
    if (!try guardLine(state, config, bytes.len)) return false;
    const keep = sinkLine(
        S,
        "matched",
        sink,
        state,
        bytes,
        if (withheld) null else preview.span,
        matches,
        line_abs,
        state.line_number,
        preview.truncated and !withheld,
        preview.line_len,
        if (withheld) 0 else preview.window_start,
        if (withheld) null else config.replacement,
    );
    releaseQueue(state);
    state.last_line_visited = line.end;
    state.last_abs_end = state.abs_base + line.end;
    state.remembered_until = @max(state.remembered_until, line.end);
    state.after_left = afterCount(config);
    state.has_sunk = true;
    state.matched_lines += 1;
    state.matches += if (matches.len > 0) @as(u64, @intCast(matches.len)) else 1;
    state.results_out += 1;
    if (!keep) {
        if (isPause(S, sink)) {
            state.resume_at = state.abs_base + @as(u64, line.end);
            state.resume_line = nextLineNumber(state, buf, line, config);
        }
        noteRejected(S, state, sink);
    }
    if (state.paused) return false;
    if (!maybeProgress(S, sink, state, config)) return false;
    if (!noteHitLimit(state, config, state.abs_base + line.end)) return false;
    return keep and !state.paused;
}

fn sinkContext(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    line: Range,
    kind: ContextKind,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    const known = if (config.invert) matchInLine(matcher, buf, line, config) else null;
    const preview = previewLine(buf, line, known, config);
    const line_abs = state.abs_base + line.start;
    if (!try sinkBreakAt(S, sink, line_abs, state, config)) return false;
    countLines(buf, line.start, state, config);
    const withheld = config.binary == .report and state.nul_offset != null;
    const bytes = if (withheld) buf[line.start..line.start] else buf[preview.start..preview.end];
    var inline_spans: [32]Span = undefined;
    var span_heap: []Span = &.{};
    defer if (span_heap.len != 0) if (state.text_alloc) |alloc| alloc.free(span_heap);
    const matches = if (withheld) inline_spans[0..0] else try gatherSpans(
        state.text_alloc,
        &inline_spans,
        &span_heap,
        matcher,
        buf,
        line,
        preview,
        known,
        config,
    );
    if (!try guardLine(state, config, bytes.len)) return false;
    const keep = sinkLine(
        S,
        "context",
        sink,
        state,
        bytes,
        if (withheld) null else preview.span,
        matches,
        line_abs,
        state.line_number,
        preview.truncated and !withheld,
        preview.line_len,
        if (withheld) 0 else preview.window_start,
        if (withheld) null else config.replacement,
    );
    releaseQueue(state);
    state.last_line_visited = line.end;
    state.last_abs_end = state.abs_base + line.end;
    state.remembered_until = @max(state.remembered_until, line.end);
    if (kind == .after and state.after_left > 0) state.after_left -= 1;
    state.has_sunk = true;
    if (!keep) noteRejected(S, state, sink);
    return keep and !state.paused;
}

fn sinkBreakAt(
    comptime S: type,
    sink: *S,
    line_abs: u64,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    if (config.passthru) return true;
    const any_context = beforeCount(config) > 0 or afterCount(config) > 0;
    if (!any_context or !state.has_sunk or line_abs <= state.last_abs_end) return true;
    const keep = callOpt(S, "contextBreak", sink, .{});
    if (!keep) noteRejected(S, state, sink);
    return keep and !state.paused;
}

fn lineIsReportedHit(matcher: anytype, buf: []const u8, line: Range, config: SearchConfig) bool {
    const content_end = contentEnd(buf, line, config);
    if (!linePassesFilters(buf, line.start, content_end, config)) return false;
    const hit = matchInLine(matcher, buf, line, config) != null;
    return if (config.invert) !hit else hit;
}

fn matchInLine(matcher: anytype, buf: []const u8, line: Range, config: SearchConfig) ?BufMatch {
    const end = contentEnd(buf, line, config);
    if (config.whole_line) {
        if (!acceptsWholeLine(matcher, buf, line.start, end)) return null;
        return .{ .start = line.start, .end = end };
    }
    const found = nextMatch(matcher, buf, line.start, config) orelse return null;
    // 空行的内容终点和起点重合，空模式在这里仍算命中。
    if (found.start < line.start or found.start > end or found.end > line.end) return null;
    if (found.start == end and found.end > end) return null;
    if (found.start >= line.end) return null;
    return .{ .start = found.start, .end = @min(found.end, end) };
}

fn spanFrom(buf: []const u8, line: Range, content_end: usize, known: ?BufMatch) ?Span {
    const m = known orelse return null;
    _ = buf;
    if (m.start < line.start or m.start > content_end) return null;
    return .{
        .start = m.start - line.start,
        .end = @min(m.end, content_end) - line.start,
    };
}

fn contentEnd(buf: []const u8, line: Range, config: SearchConfig) usize {
    var end = line.end;
    const sep = recordSep(config);
    if (end > line.start and end <= buf.len and buf[end - 1] == sep) end -= 1;
    if (!config.null_data and end > line.start and end <= buf.len and buf[end - 1] == '\r') end -= 1;
    return end;
}

fn countLines(buf: []const u8, upto: usize, state: *State, config: SearchConfig) void {
    if (state.line_number == null) return;
    if (state.last_line_counted >= upto) return;
    const n = memchr.count(width, buf, state.last_line_counted, upto, recordSep(config));
    state.line_number = (state.line_number orelse return) + n;
    state.last_line_counted = upto;
}

fn rollConsumed(buf: []const u8, state: *const State, config: SearchConfig) usize {
    _ = state;
    _ = config;
    return buf.len;
}

fn lineStart(buf: []const u8, pos: usize, config: SearchConfig) usize {
    const upto = @min(pos, buf.len);
    if (memchr.findLast(width, buf, 0, upto, recordSep(config))) |i| return i + 1;
    return 0;
}

fn lineEnd(buf: []const u8, from: usize, config: SearchConfig) usize {
    if (from >= buf.len) return buf.len;
    if (memchr.find(width, buf, from, recordSep(config))) |i| return i + 1;
    return buf.len;
}

fn nextLine(buf: []const u8, pos: usize, end: usize, config: SearchConfig) ?Range {
    if (pos >= end or pos >= buf.len) return null;
    const limit = @min(end, buf.len);
    if (memchr.find(width, buf, pos, recordSep(config))) |i| {
        if (i >= limit) return .{ .start = pos, .end = limit };
        return .{ .start = pos, .end = i + 1 };
    }
    return .{ .start = pos, .end = limit };
}

/// `count` 为 0 时返回最后一行的起点。
fn preceding(bytes: []const u8, count: usize) usize {
    if (bytes.len == 0) return 0;
    var pos: usize = bytes.len;
    var left = count;
    if (bytes[pos - 1] == '\n') pos -= 1;
    while (true) {
        const at = memchr.findLast(width, bytes, 0, pos, '\n') orelse return 0;
        if (left == 0) return at + 1;
        if (at == 0) return 0;
        left -= 1;
        pos = at;
    }
}

fn finishSink(comptime S: type, sink: *S, state: *State, config: SearchConfig) Result {
    const cursor = state.abs_base + @as(u64, state.pos);
    if (cursor > state.bytes_searched) state.bytes_searched = cursor;
    if (!state.from_reader) state.bytes_read = @max(state.bytes_read, state.bytes_searched);
    const elapsed = elapsedOf(state, config);
    const resume_state = ResumeState{
        .matched_lines = state.matched_lines,
        .matches = state.matches,
        .bytes_read = state.bytes_read,
        .bytes_searched = state.bytes_searched,
        .output_bytes = state.output_bytes,
        .results_out = state.results_out,
        .limit_count = state.limit_count,
        .line_number = state.resume_line,
        .started_ns = state.started_ns,
        .deadline_armed = state.deadline_armed,
        .skip_begin = true,
    };
    if (state.paused) {
        if (state.resume_at == null) state.resume_at = cursor;
        return .{
            .outcome = .stopped,
            .paused = true,
            .matched_lines = state.matched_lines,
            .matches = state.matches,
            .nul_offset = state.nul_offset,
            .binary_offset = state.nul_offset,
            .bytes_read = state.bytes_read,
            .bytes_searched = state.bytes_searched,
            .output_bytes = state.output_bytes,
            .elapsed_ns = elapsed,
            .resume_at = state.resume_at,
            .resume_state = resume_state,
            .limit_hit = .none,
            .partial = false,
            .scanned_all = false,
        };
    }
    if (state.exceeded(config)) state.need_close = true;
    closeOnce(state, config);
    var outcome: Outcome = if (state.stopped) .stopped else .complete;
    if (state.nul_offset != null and config.binary == .quit) outcome = .binary_quit;
    if (state.nul_offset != null and config.binary == .report and state.matched_lines > 0) {
        outcome = .binary_matched;
    }
    const partial = (state.limit_hit != .none or state.output_blocked) and !state.scanned_all;
    const result = Result{
        .outcome = outcome,
        .matched_lines = state.matched_lines,
        .matches = state.matches,
        .nul_offset = state.nul_offset,
        .binary_offset = state.nul_offset,
        .bytes_read = state.bytes_read,
        .bytes_searched = state.bytes_searched,
        .output_bytes = state.output_bytes,
        .elapsed_ns = elapsed,
        .limit_hit = state.limit_hit,
        .partial = partial,
        .resume_at = state.resume_at,
        .soft_error = state.soft_error,
        .scanned_all = state.scanned_all,
        .resume_state = resume_state,
    };
    _ = callOpt(S, "finish", sink, .{result});
    return result;
}

fn elapsedOf(state: *const State, config: SearchConfig) u64 {
    const now = readClock(config);
    const delta = now - state.started_ns;
    if (delta <= 0) return 0;
    if (delta > std.math.maxInt(u64)) return std.math.maxInt(u64);
    return @intCast(delta);
}

fn resetStats(matcher: anytype) void {
    const T = @TypeOf(matcher);
    const Child = switch (@typeInfo(T)) {
        .pointer => |p| if (p.size == .one) p.child else return,
        else => return,
    };
    if (@hasDecl(Child, "resetStats")) matcher.resetStats();
}

fn callOpt(comptime S: type, comptime name: []const u8, sink: *S, args: anytype) bool {
    if (!@hasDecl(S, name)) return true;
    return @call(.auto, @field(S, name), .{sink} ++ args);
}

fn contextLineLimit(config: SearchConfig) u32 {
    const hard = SearchConfig.context_lines_hard_cap;
    return @min(config.max_context_lines orelse hard, hard);
}

fn rejectWideContext(config: SearchConfig) error{ContextLinesExceeded}!void {
    const limit = contextLineLimit(config);
    if (config.context > limit) return error.ContextLinesExceeded;
    if (config.before) |n| if (n > limit) return error.ContextLinesExceeded;
    if (config.after) |n| if (n > limit) return error.ContextLinesExceeded;
}

fn beforeCount(config: SearchConfig) u32 {
    return config.before orelse config.context;
}

fn afterCount(config: SearchConfig) u32 {
    return config.after orelse config.context;
}

fn beforeContextCapacity(config: SearchConfig) usize {
    return std.math.mul(usize, @as(usize, beforeCount(config)), config.max_line_len) catch std.math.maxInt(usize);
}

fn lineHoldLimit(config: SearchConfig) usize {
    return config.max_line_len + 1;
}

fn longTail(buf: []const u8, eof: bool, config: SearchConfig) bool {
    if (eof or buf.len == 0) return false;
    const end = lastComplete(buf, config);
    return buf.len - end > config.max_line_len;
}

const Preview = struct {
    start: usize,
    end: usize,
    truncated: bool,
    line_len: u64,
    window_start: u64,
    span: ?Span,
};

/// 窗口尽量包住整个匹配。匹配比上限长时，从匹配起点开始。
fn windowOrigin(raw: usize, limit: usize, match_at: usize, match_end: usize) usize {
    if (limit == 0 or raw <= limit) return 0;
    const mend = @min(match_end, raw);
    const mstart = @min(match_at, mend);
    const mlen = mend - mstart;
    if (mlen >= limit) {
        if (mstart + limit > raw) return raw - limit;
        return mstart;
    }
    const mid = mstart + mlen / 2;
    var rel: usize = if (mid > limit / 2) mid - limit / 2 else 0;
    if (rel + limit > raw) rel = raw - limit;
    if (mstart < rel) rel = mstart;
    const tail = mstart + mlen;
    if (tail > rel + limit) rel = tail - limit;
    if (rel + limit > raw) rel = raw - limit;
    return rel;
}

fn previewLine(buf: []const u8, line: Range, known: ?BufMatch, config: SearchConfig) Preview {
    const content_end = contentEnd(buf, line, config);
    const raw = content_end - line.start;
    const limit = config.max_line_len;
    if (limit == 0 or raw <= limit) {
        return .{
            .start = line.start,
            .end = content_end,
            .truncated = false,
            .line_len = raw,
            .window_start = 0,
            .span = spanFrom(buf, line, content_end, known),
        };
    }
    var rel: usize = 0;
    if (known) |m| {
        const at = if (m.start > line.start) m.start - line.start else 0;
        const mend = if (m.end > line.start) @min(m.end - line.start, raw) else at;
        rel = windowOrigin(raw, limit, at, mend);
    }
    const win_end = rel + limit;
    var span: ?Span = null;
    if (known) |m| {
        const abs_s = line.start + rel;
        const abs_e = line.start + win_end;
        if (m.start >= abs_s and m.start < abs_e) {
            span = .{
                .start = m.start - abs_s,
                .end = @min(m.end, abs_e) - abs_s,
            };
        }
    }
    return .{
        .start = line.start + rel,
        .end = line.start + win_end,
        .truncated = true,
        .line_len = raw,
        .window_start = rel,
        .span = span,
    };
}

const RingSlot = struct {
    len: u32 = 0,
    abs: u64 = 0,
    end_abs: u64 = 0,
    number: ?u64 = null,
    truncated: bool = false,
    line_len: u64 = 0,
    window_start: u64 = 0,
    mstart: u32 = 0,
    mend: u32 = 0,
    has_match: bool = false,
    src_start: usize = 0,
    src_end: usize = 0,
};

const BeforeRing = struct {
    slots: [SearchConfig.context_lines_hard_cap]RingSlot = undefined,
    storage: []u8 = &.{},
    stride: usize = 0,
    cap: u32 = 0,
    count: u32 = 0,
    head: u32 = 0,
    owned: bool = false,

    fn clear(self: *BeforeRing) void {
        self.count = 0;
        self.head = 0;
    }

    fn index(self: *const BeforeRing, oldest_i: u32) u32 {
        return (self.head + self.cap - self.count + oldest_i) % self.cap;
    }

    fn push(self: *BeforeRing, buf: []const u8, preview: Preview, abs: u64, end_abs: u64, number: ?u64) void {
        const slice = if (preview.end >= preview.start) buf[preview.start..preview.end] else buf[0..0];
        self.pushBytes(slice, preview, abs, end_abs, number);
    }

    fn pushBytes(self: *BeforeRing, slice: []const u8, preview: Preview, abs: u64, end_abs: u64, number: ?u64) void {
        if (self.cap == 0) return;
        const idx = self.head;
        if (self.count < self.cap) self.count += 1;
        const len = slice.len;
        self.slots[idx] = .{
            .len = std.math.cast(u32, len) orelse std.math.maxInt(u32),
            .abs = abs,
            .end_abs = end_abs,
            .number = number,
            .truncated = preview.truncated,
            .line_len = preview.line_len,
            .window_start = preview.window_start,
            .has_match = preview.span != null,
            .mstart = if (preview.span) |s| std.math.cast(u32, s.start) orelse 0 else 0,
            .mend = if (preview.span) |s| std.math.cast(u32, s.end) orelse 0 else 0,
            .src_start = preview.start,
            .src_end = preview.end,
        };
        if (self.owned and self.stride > 0 and len > 0) {
            const at = @as(usize, idx) * self.stride;
            const n = @min(len, self.stride);
            @memcpy(self.storage[at..][0..n], slice[0..n]);
            self.slots[idx].len = std.math.cast(u32, n) orelse 0;
        }
        self.head = (self.head + 1) % self.cap;
    }

    fn bytes(self: *const BeforeRing, idx: u32, buf: []const u8) []const u8 {
        const slot = self.slots[idx];
        if (self.owned) {
            if (self.stride == 0 or slot.len == 0) return &.{};
            const at = @as(usize, idx) * self.stride;
            return self.storage[at..][0..slot.len];
        }
        if (slot.src_end < slot.src_start or slot.src_end > buf.len) return &.{};
        return buf[slot.src_start..slot.src_end];
    }
};

fn rememberBefore(matcher: anytype, buf: []const u8, state: *State, config: SearchConfig, upto: usize) void {
    const limit_end = @min(upto, buf.len);
    if (state.ring.cap == 0) {
        state.remembered_until = @max(state.remembered_until, limit_end);
        return;
    }
    var cursor = @max(state.remembered_until, state.last_line_visited);
    if (cursor > limit_end) cursor = limit_end;
    while (nextLine(buf, cursor, limit_end, config)) |line| {
        if (line.end <= state.last_line_visited) {
            cursor = line.end;
            continue;
        }
        const known = if (config.invert) matchInLine(matcher, buf, line, config) else null;
        const preview = previewLine(buf, line, known, config);
        countLines(buf, line.start, state, config);
        state.ring.push(buf, preview, state.abs_base + line.start, state.abs_base + line.end, state.line_number);
        cursor = line.end;
    }
    state.remembered_until = limit_end;
}

fn emitRing(
    comptime S: type,
    sink: *S,
    buf: []const u8,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    var i: u32 = 0;
    while (i < state.ring.count) : (i += 1) {
        const idx = state.ring.index(i);
        const slot = state.ring.slots[idx];
        if (!try sinkBreakAt(S, sink, slot.abs, state, config)) {
            state.ring.clear();
            return false;
        }
        const raw = state.ring.bytes(idx, buf);
        const withheld = config.binary == .report and state.nul_offset != null;
        const span: ?Span = if (withheld or !slot.has_match) null else .{
            .start = slot.mstart,
            .end = slot.mend,
        };
        var none: [0]Span = .{};
        const shown = if (withheld) raw[0..0] else raw;
        if (!try guardLine(state, config, shown.len)) {
            state.ring.clear();
            return false;
        }
        const keep = sinkLine(
            S,
            "context",
            sink,
            state,
            shown,
            span,
            &none,
            slot.abs,
            slot.number,
            slot.truncated and !withheld,
            slot.line_len,
            if (withheld) 0 else slot.window_start,
            if (withheld) null else config.replacement,
        );
        releaseQueue(state);
        state.last_abs_end = slot.end_abs;
        state.has_sunk = true;
        if (!keep) {
            noteRejected(S, state, sink);
            state.ring.clear();
            return false;
        }
    }
    state.ring.clear();
    return true;
}

fn needleLen(matcher: anytype) usize {
    const T = @TypeOf(matcher.*);
    if (@hasField(T, "pattern")) return matcher.pattern.len;
    if (@hasField(T, "patterns")) {
        var max: usize = 0;
        for (matcher.patterns) |pat| max = @max(max, pat.len);
        return max;
    }
    return 1;
}

fn overlapKeep(matcher: anytype, config: SearchConfig) usize {
    var n = needleLen(matcher);
    for (config.contains) |pat| n = @max(n, pat.len);
    for (config.excludes) |pat| n = @max(n, pat.len);
    if (config.whole_word) n += 1;
    if (n == 0) n = 1;
    const cap = if (config.max_line_len == 0) 1 else config.max_line_len;
    return @min(n, cap);
}

fn containsDone(seen: []const bool, config: SearchConfig) bool {
    if (config.contains.len == 0) return true;
    if (seen.len < config.contains.len) return false;
    for (seen[0..config.contains.len]) |ok| if (!ok) return false;
    return true;
}

fn ensureHold(allocator: std.mem.Allocator, hold: *[]u8, n: usize) error{OutOfMemory}!void {
    if (n == 0 or hold.len >= n) return;
    if (hold.len == 0) {
        hold.* = try allocator.alloc(u8, n);
    } else {
        hold.* = try allocator.realloc(hold.*, n);
    }
}

fn compactBuf(buf: []u8, filled: *usize, drop: usize, state: *State) void {
    if (drop == 0 or drop > filled.*) return;
    const remain = filled.* - drop;
    if (remain > 0) std.mem.copyForwards(u8, buf[0..remain], buf[drop..filled.*]);
    filled.* = remain;
    state.pos = if (state.pos >= drop) state.pos - drop else 0;
    state.last_line_visited = if (state.last_line_visited >= drop) state.last_line_visited - drop else 0;
    state.last_line_counted = if (state.last_line_counted >= drop) state.last_line_counted - drop else 0;
    state.remembered_until = if (state.remembered_until >= drop) state.remembered_until - drop else 0;
    state.abs_base += drop;
}

fn noteLong(
    allocator: std.mem.Allocator,
    matcher: anytype,
    bytes: []const u8,
    hold: *[]u8,
    seen: *[]bool,
    state: *State,
    config: SearchConfig,
    commit: bool,
) error{OutOfMemory}!void {
    if (!state.long_excluded) {
        for (config.excludes) |pat| {
            if (std.mem.indexOf(u8, bytes, pat) != null) {
                state.long_excluded = true;
                break;
            }
        }
    }
    if (seen.len >= config.contains.len) {
        for (config.contains, 0..) |pat, i| {
            if (!seen.*[i] and std.mem.indexOf(u8, bytes, pat) != null) seen.*[i] = true;
        }
    }
    if (state.long_has_match or config.whole_line) return;
    const keep = if (commit) 0 else overlapKeep(matcher, config);
    const stable = if (bytes.len > keep) bytes.len - keep else 0;
    var pos: usize = 0;
    while (pos < stable) {
        const hit = nextMatch(matcher, bytes, pos, config) orelse break;
        if (hit.start >= stable) break;
        if (config.whole_word and hit.end >= bytes.len and !commit) {
            pos = @min(bytes.len, hit.start + 1);
            continue;
        }
        if (config.whole_word and state.long_dropped > 0 and hit.start == 0 and !commit) {
            pos = @min(bytes.len, hit.start + 1);
            continue;
        }
        try saveMatchWindow(allocator, bytes, hit, hold, state, config);
        state.long_has_match = true;
        break;
    }
}

fn saveMatchWindow(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    hit: matcher_mod.Match,
    hold: *[]u8,
    state: *State,
    config: SearchConfig,
) error{OutOfMemory}!void {
    const limit = config.max_line_len;
    if (limit == 0) return;
    try ensureHold(allocator, hold, limit);
    const avail = bytes.len;
    const local = windowOrigin(avail, limit, hit.start, @min(hit.end, avail));
    const end = @min(avail, local + limit);
    if (end < local) return;
    if (hit.start >= end) return;
    const n = end - local;
    @memcpy(hold.*[0..n], bytes[local..end]);
    state.long_hold_len = n;
    state.long_window_start = state.long_dropped + local;
    state.long_match_start = hit.start - local;
    state.long_match_end = @min(hit.end, end) - local;
    state.long_hold_kind = 2;
}

fn savePrefix(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    hold: *[]u8,
    state: *State,
    config: SearchConfig,
) error{OutOfMemory}!void {
    const limit = config.max_line_len;
    if (limit == 0 or state.long_hold_kind == 2) return;
    const n = @min(limit, bytes.len);
    if (n == 0) return;
    try ensureHold(allocator, hold, limit);
    @memcpy(hold.*[0..n], bytes[0..n]);
    state.long_hold_len = n;
    state.long_window_start = state.long_dropped;
    state.long_hold_kind = 1;
}

fn slideLong(buf: *[]u8, filled: *usize, matcher: anytype, state: *State, config: SearchConfig) void {
    const keep = overlapKeep(matcher, config);
    if (filled.* <= keep) return;
    const drop = filled.* - keep;
    std.mem.copyForwards(u8, buf.*[0..keep], buf.*[drop..filled.*]);
    filled.* = keep;
    state.long_dropped += drop;
    state.abs_base += drop;
}

fn emitHold(
    comptime S: type,
    sink: *S,
    hold: []const u8,
    state: *State,
    config: SearchConfig,
    as_match: bool,
    end_abs: u64,
) SliceError!bool {
    const withheld = config.binary == .report and state.nul_offset != null;
    const n = @min(state.long_hold_len, hold.len);
    const raw = hold[0..n];
    const span: ?Span = if (withheld or state.long_hold_kind != 2) null else .{
        .start = state.long_match_start,
        .end = state.long_match_end,
    };
    if (!try sinkBreakAt(S, sink, state.long_origin, state, config)) return false;
    const bytes = if (withheld) raw[0..0] else raw;
    if (!try guardLine(state, config, bytes.len)) return false;
    const truncated = state.long_line_len > config.max_line_len and !withheld;
    const window = if (withheld) 0 else state.long_window_start;
    var none: [0]Span = .{};
    const repl = if (withheld) null else config.replacement;
    const keep = if (as_match)
        sinkLine(S, "matched", sink, state, bytes, span, &none, state.long_origin, state.long_number, truncated, state.long_line_len, window, repl)
    else
        sinkLine(S, "context", sink, state, bytes, span, &none, state.long_origin, state.long_number, truncated, state.long_line_len, window, repl);
    releaseQueue(state);
    if (as_match) {
        state.matched_lines += 1;
        state.matches += 1;
        state.results_out += 1;
    }
    state.last_abs_end = end_abs;
    state.has_sunk = true;
    if (!keep) noteRejected(S, state, sink);
    if (as_match and !noteHitLimit(state, config, end_abs)) return false;
    return keep;
}

fn finishLong(
    comptime S: type,
    sink: *S,
    buf: *[]u8,
    filled: *usize,
    hold: []const u8,
    seen: []const bool,
    state: *State,
    config: SearchConfig,
    content_in_buf: usize,
    drop_buf: usize,
) SliceError!bool {
    state.long_line_len = state.long_dropped + content_in_buf;
    const filters_ok = !state.long_excluded and containsDone(seen, config);
    const matched_pat = state.long_has_match and !config.whole_line;
    var is_hit = if (config.invert) !matched_pat else matched_pat;
    if (!filters_ok) is_hit = false;
    const end_abs = state.abs_base + drop_buf;
    if (is_hit and !state.exceeded(config)) {
        if (!config.passthru) {
            if (!try emitRing(S, sink, buf.*, state, config)) return false;
        }
        state.limit_count += 1;
        if (!try emitHold(S, sink, hold, state, config, true, end_abs)) return false;
        state.after_left = afterCount(config);
    } else if (!is_hit and config.stop_on_nonmatch and state.matched_lines > 0) {
        state.stopped = true;
        state.need_close = true;
    } else if (config.passthru and !state.exceeded(config)) {
        if (!try emitHold(S, sink, hold, state, config, false, end_abs)) return false;
    } else if (state.after_left > 0) {
        if (!try emitHold(S, sink, hold, state, config, is_hit, end_abs)) return false;
        if (state.after_left > 0) state.after_left -= 1;
    } else if (beforeCount(config) > 0) {
        const raw = hold[0..@min(state.long_hold_len, hold.len)];
        const preview = Preview{
            .start = 0,
            .end = raw.len,
            .truncated = state.long_line_len > config.max_line_len,
            .line_len = state.long_line_len,
            .window_start = state.long_window_start,
            .span = if (state.long_hold_kind == 2) .{
                .start = state.long_match_start,
                .end = state.long_match_end,
            } else null,
        };
        state.ring.pushBytes(raw, preview, state.long_origin, end_abs, state.long_number);
    }
    countLines(buf.*, @min(drop_buf, filled.*), state, config);
    compactBuf(buf.*, filled, @min(drop_buf, filled.*), state);
    state.pos = 0;
    state.last_line_visited = 0;
    state.remembered_until = 0;
    state.long_active = false;
    state.long_hold_kind = 0;
    state.long_has_match = false;
    return !state.stopped;
}

fn beginLong(
    allocator: std.mem.Allocator,
    matcher: anytype,
    buf: *[]u8,
    filled: *usize,
    hold: *[]u8,
    seen: *[]bool,
    state: *State,
    config: SearchConfig,
) error{OutOfMemory}!void {
    state.long_active = true;
    state.long_origin = state.abs_base;
    state.long_dropped = 0;
    state.long_has_match = false;
    state.long_excluded = false;
    state.long_hold_kind = 0;
    state.long_hold_len = 0;
    state.long_window_start = 0;
    state.long_number = state.line_number;
    if (config.contains.len > seen.len) {
        if (seen.len != 0) allocator.free(seen.*);
        seen.* = try allocator.alloc(bool, config.contains.len);
    }
    if (seen.len > 0) @memset(seen.*, false);
    const bytes = buf.*[0..filled.*];
    if (config.invert or config.passthru or beforeCount(config) > 0 or state.after_left > 0) {
        try savePrefix(allocator, bytes, hold, state, config);
    }
    try noteLong(allocator, matcher, bytes, hold, seen, state, config, false);
    slideLong(buf, filled, matcher, state, config);
}

fn makeRoom(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    matcher: anytype,
    buf: *[]u8,
    filled: *usize,
    hold: *[]u8,
    seen: *[]bool,
    state: *State,
    config: SearchConfig,
) ReadError!bool {
    if (state.long_active) {
        const before = filled.*;
        slideLong(buf, filled, matcher, state, config);
        return filled.* < buf.len and filled.* < before;
    }
    const end = lastComplete(buf.*[0..filled.*], config);
    if (end > 0) {
        if (!try matchBuffer(S, sink, matcher, buf.*[0..end], state, config)) return false;
        rememberBefore(matcher, buf.*, state, config, end);
        countLines(buf.*, end, state, config);
        compactBuf(buf.*, filled, end, state);
        return filled.* < buf.len;
    }
    if (filled.* > config.max_line_len) {
        try beginLong(allocator, matcher, buf, filled, hold, seen, state, config);
        return filled.* < buf.len;
    }
    return false;
}

fn pumpLong(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    matcher: anytype,
    buf: *[]u8,
    filled: *usize,
    hold: *[]u8,
    seen: *[]bool,
    new_at: usize,
    eof: bool,
    state: *State,
    config: SearchConfig,
) ReadError!bool {
    if (stopInMatch(state, config)) return false;
    if (watchesBinary(config) and state.nul_offset == null and new_at < filled.*) {
        if (memchr.find(width, buf.*[new_at..filled.*], 0, 0)) |rel| {
            noteBinary(state, config, state.abs_base + new_at + rel);
            const cont = callOpt(S, "binary", sink, .{state.nul_offset.?});
            if (config.binary == .quit or !cont) return false;
        }
    }
    if (!state.long_active) {
        if (eof) return true;
        const search_end = lastComplete(buf.*[0..filled.*], config);
        if (filled.* - search_end <= config.max_line_len) return true;
        if (search_end > 0) {
            if (!try matchBuffer(S, sink, matcher, buf.*[0..search_end], state, config)) return false;
            rememberBefore(matcher, buf.*, state, config, search_end);
            countLines(buf.*, search_end, state, config);
            compactBuf(buf.*, filled, search_end, state);
        }
        try beginLong(allocator, matcher, buf, filled, hold, seen, state, config);
        return !state.stopped;
    }
    const sep = recordSep(config);
    if (memchr.find(width, buf.*, 0, sep)) |nl| {
        var content_len = nl;
        if (!config.null_data and nl > 0 and buf.*[nl - 1] == '\r') content_len = nl - 1;
        try noteLong(allocator, matcher, buf.*[0..content_len], hold, seen, state, config, true);
        return finishLong(S, sink, buf, filled, hold.*, seen.*, state, config, content_len, nl + 1);
    }
    if (eof) {
        try noteLong(allocator, matcher, buf.*[0..filled.*], hold, seen, state, config, true);
        return finishLong(S, sink, buf, filled, hold.*, seen.*, state, config, filled.*, filled.*);
    }
    try noteLong(allocator, matcher, buf.*[0..filled.*], hold, seen, state, config, false);
    if (filled.* > config.max_line_len) slideLong(buf, filled, matcher, state, config);
    return !state.stopped;
}

const testing = std.testing;
const Finder = @import("finder/finder.zig").Finder;

const Rec = struct {
    text: std.ArrayList(u8) = .empty,
    matches: u64 = 0,
    breaks: u32 = 0,
    begun: []const u8 = "",
    nul: ?u64 = null,
    stop_after: ?u64 = null,
    suppress_lines: bool = false,

    fn deinit(self: *Rec, allocator: std.mem.Allocator) void {
        self.text.deinit(allocator);
    }

    pub fn begin(self: *Rec, path: []const u8) bool {
        self.begun = path;
        return true;
    }

    pub fn matched(self: *Rec, line: Line) bool {
        self.matches += 1;
        if (self.suppress_lines) return self.keepGoing();
        self.write(line, true);
        return self.keepGoing();
    }

    pub fn context(self: *Rec, line: Line) bool {
        if (self.suppress_lines) return true;
        self.write(line, false);
        return true;
    }

    pub fn contextBreak(self: *Rec) bool {
        if (self.suppress_lines) return true;
        self.breaks += 1;
        return true;
    }

    pub fn binary(self: *Rec, offset: u64) bool {
        self.nul = offset;
        self.suppress_lines = true;
        return self.matches == 0;
    }

    pub fn finish(self: *Rec, result: Result) bool {
        if (result.outcome == .binary_matched and self.matches > 0 and self.text.items.len == 0) {
            self.text.appendSlice(testing.allocator, "binary file matches\n") catch unreachable;
        }
        return true;
    }

    fn keepGoing(self: *Rec) bool {
        if (self.stop_after) |n| return self.matches < n;
        return true;
    }

    fn write(self: *Rec, line: Line, is_match: bool) void {
        const sep: u8 = if (is_match) ':' else '-';
        if (line.number) |n| {
            var tmp: [32]u8 = undefined;
            const s = std.fmt.bufPrint(&tmp, "{d}", .{n}) catch unreachable;
            self.text.appendSlice(testing.allocator, s) catch unreachable;
            self.text.append(testing.allocator, sep) catch unreachable;
        }
        self.text.appendSlice(testing.allocator, line.bytes) catch unreachable;
        self.text.append(testing.allocator, '\n') catch unreachable;
    }
};

fn run(hay: []const u8, pattern: []const u8, config: SearchConfig) !Rec {
    var finder = try Finder.init(pattern, .{});
    var rec = Rec{};
    errdefer rec.deinit(testing.allocator);
    _ = try searchSlice(Rec, &rec, hay, "f", &finder, config);
    return rec;
}

test "切片：行号、上下文和分隔" {
    var rec = try run("a\nb\nMATCH\nc\nd\ne\nMATCH2\nf\n", "MATCH", .{
        .line_numbers = true,
        .before = 1,
        .after = 1,
    });
    defer rec.deinit(testing.allocator);
    try testing.expectEqualStrings(
        \\2-b
        \\3:MATCH
        \\4-c
        \\6-e
        \\7:MATCH2
        \\8-f
        \\
    , rec.text.items);
    try testing.expectEqual(@as(u64, 2), rec.matches);
    try testing.expectEqual(@as(u32, 1), rec.breaks);
}

test "切片：max_count 仍吐出 after，窗口内的命中保持匹配格式" {
    var rec = try run("a\nb\nMATCH\nc\nd\ne\nMATCH2\nf\n", "MATCH", .{
        .line_numbers = true,
        .after = 4,
        .max_count = 1,
    });
    defer rec.deinit(testing.allocator);
    try testing.expectEqualStrings(
        \\3:MATCH
        \\4-c
        \\5-d
        \\6-e
        \\7:MATCH2
        \\
    , rec.text.items);
}

test "切片：反选和反选上下文" {
    var plain = try run("a\nb\nMATCH\nc\n", "MATCH", .{ .line_numbers = true, .invert = true });
    defer plain.deinit(testing.allocator);
    try testing.expectEqualStrings(
        \\1:a
        \\2:b
        \\4:c
        \\
    , plain.text.items);

    var ctx = try run("a\nb\nMATCH\nc\n", "MATCH", .{
        .line_numbers = true,
        .invert = true,
        .before = 1,
        .after = 1,
    });
    defer ctx.deinit(testing.allocator);
    try testing.expectEqualStrings(
        \\1:a
        \\2:b
        \\3-MATCH
        \\4:c
        \\
    , ctx.text.items);
}

test "切片：空行、无结尾换行、CRLF 去掉 CR" {
    var empty_lines = try run("a\n\nMATCH\n\nb\n", "MATCH", .{
        .line_numbers = true,
        .before = 1,
        .after = 1,
    });
    defer empty_lines.deinit(testing.allocator);
    try testing.expectEqualStrings(
        \\2-
        \\3:MATCH
        \\4-
        \\
    , empty_lines.text.items);

    var no_nl = try run("foo\nbar", "foo", .{ .line_numbers = true });
    defer no_nl.deinit(testing.allocator);
    try testing.expectEqualStrings("1:foo\n", no_nl.text.items);

    var crlf = try run("a\r\nMATCH\r\nb\r\n", "MATCH", .{ .line_numbers = true });
    defer crlf.deinit(testing.allocator);
    try testing.expectEqualStrings("2:MATCH\n", crlf.text.items);
}

test "切片：空模式匹配每一行，列号是第一个匹配的字节" {
    var all = try run("a\nb\n", "", .{ .line_numbers = true });
    defer all.deinit(testing.allocator);
    try testing.expectEqualStrings("1:a\n2:b\n", all.text.items);

    const Col = struct {
        start: usize = 0,
        pub fn matched(self: *@This(), line: Line) bool {
            self.start = line.match.?.start;
            return true;
        }
    };
    var finder = try Finder.init("MATCH", .{});
    var col = Col{};
    _ = try searchSlice(Col, &col, "xxMATCHyy\n", "", &finder, .{ .binary = .none });
    try testing.expectEqual(@as(usize, 2), col.start);
}

test "切片：二进制 report 和 quit" {
    var report = try run("xxMATCH\x00yy\n", "MATCH", .{ .binary = .report });
    defer report.deinit(testing.allocator);
    try testing.expectEqual(Outcome.binary_matched, (try finishOf("xxMATCH\x00yy\n", "MATCH", .report)).outcome);
    try testing.expectEqual(@as(?u64, 7), report.nul);
    try testing.expectEqualStrings("binary file matches\n", report.text.items);

    var quiet = try run("MATCH\nfoo\x00\n", "MATCH", .{ .binary = .quit, .buffer_size = 64 });
    defer quiet.deinit(testing.allocator);
    try testing.expectEqualStrings("", quiet.text.items);
    const q = try finishOf("MATCH\nfoo\x00\n", "MATCH", .quit);
    try testing.expectEqual(Outcome.binary_quit, q.outcome);
    try testing.expectEqual(@as(u64, 0), q.matched_lines);

    var text = try run("xxMATCH\x00yy\n", "MATCH", .{ .binary = .none, .line_numbers = true });
    defer text.deinit(testing.allocator);
    try testing.expectEqualStrings("1:xxMATCH\x00yy\n", text.text.items);
}

fn finishOf(hay: []const u8, pattern: []const u8, policy: BinaryPolicy) !Result {
    var finder = try Finder.init(pattern, .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    return searchSlice(Rec, &rec, hay, "", &finder, .{ .binary = policy, .buffer_size = 64 });
}

test "切片：超长匹配行交出窗口" {
    const Cap = struct {
        truncated: bool = false,
        line_len: u64 = 0,
        window_start: u64 = 0,
        offset: u64 = 0,
        bytes: [8]u8 = undefined,
        len: usize = 0,
        mstart: usize = 0,
        pub fn matched(self: *@This(), line: Line) bool {
            self.truncated = line.truncated;
            self.line_len = line.line_len;
            self.window_start = line.window_start;
            self.offset = line.offset;
            self.len = @min(line.bytes.len, self.bytes.len);
            @memcpy(self.bytes[0..self.len], line.bytes[0..self.len]);
            self.mstart = line.match.?.start;
            return true;
        }
    };
    var finder = try Finder.init("MATCH", .{});
    var cap = Cap{};
    const hay = "MATCHxxxxxxxxxxxxxxxxxxxx";
    const result = try searchSlice(Cap, &cap, hay, "", &finder, .{ .max_line_len = 8, .binary = .none });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expect(cap.truncated);
    try testing.expectEqual(@as(u64, hay.len), cap.line_len);
    try testing.expectEqual(@as(u64, 0), cap.offset);
    try testing.expectEqual(@as(usize, 8), cap.len);
    try testing.expectEqualStrings(hay[cap.window_start..][0..cap.len], cap.bytes[0..cap.len]);
    try testing.expectEqual(@as(u64, 0), cap.window_start + cap.mstart);
}

test "分块读把 NUL 并进查找" {
    // 按 LF 分行，且不是 NUL 记录模式，所以 NUL 仍是二进制信号。
    var reader = std.Io.Reader.fixed("ab\ncd\nMATCH\n");
    var finder = try Finder.init("MATCH", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = try searchReader(Rec, testing.allocator, &rec, &reader, "", &finder, .{
        .line_numbers = true,
        .buffer_size = 4,
        .max_line_len = 64,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqual(@as(?u64, null), result.nul_offset);
    try testing.expectEqualStrings("3:MATCH\n", rec.text.items);

    var bin_reader = std.Io.Reader.fixed("xxMATCH\x00yy\n");
    var bin_finder = try Finder.init("MATCH", .{});
    var bin = Rec{};
    defer bin.deinit(testing.allocator);
    const bin_result = try searchReader(Rec, testing.allocator, &bin, &bin_reader, "", &bin_finder, .{
        .buffer_size = 64,
        .max_line_len = 64,
        .binary = .report,
    });
    try testing.expectEqual(Outcome.binary_matched, bin_result.outcome);
    try testing.expectEqual(@as(?u64, 7), bin_result.nul_offset);
    try testing.expectEqualStrings("binary file matches\n", bin.text.items);

    var quit_reader = std.Io.Reader.fixed("MATCH\nfoo\x00\n");
    var quit_finder = try Finder.init("MATCH", .{});
    var quit = Rec{};
    defer quit.deinit(testing.allocator);
    const quit_result = try searchReader(Rec, testing.allocator, &quit, &quit_reader, "", &quit_finder, .{
        .binary = .quit,
        .buffer_size = 64,
        .max_line_len = 64,
    });
    try testing.expectEqual(Outcome.binary_quit, quit_result.outcome);
    try testing.expectEqual(@as(u64, 0), quit_result.matched_lines);
    try testing.expectEqualStrings("", quit.text.items);

    var byte_reader = std.Io.Reader.fixed("ab\ncd\nZ\n");
    var byte_finder = try Finder.init("Z", .{});
    var byte_rec = Rec{};
    defer byte_rec.deinit(testing.allocator);
    const byte_result = try searchReader(Rec, testing.allocator, &byte_rec, &byte_reader, "", &byte_finder, .{
        .line_numbers = true,
        .buffer_size = 3,
        .max_line_len = 64,
    });
    try testing.expectEqual(Outcome.complete, byte_result.outcome);
    try testing.expectEqualStrings("3:Z\n", byte_rec.text.items);
}

test "Reader 跨块保留半行" {
    const hay = "abcMATCH\nzzz\nMATCH\n";
    var reader = std.Io.Reader.fixed(hay);
    var finder = try Finder.init("MATCH", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = try searchReader(Rec, testing.allocator, &rec, &reader, "r", &finder, .{
        .line_numbers = true,
        .buffer_size = 8,
        .max_line_len = 64,
        .binary = .none,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqualStrings("1:abcMATCH\n3:MATCH\n", rec.text.items);
}

test "文件读取与切片一致" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const hay = "a\nMATCH\nb\n";
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "t.txt", .data = hay });
    const file = try tmp.dir.openFile(testing.io, "t.txt", .{});
    defer file.close(testing.io);

    var finder = try Finder.init("MATCH", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = try searchFile(Rec, testing.allocator, testing.io, &rec, file, "t.txt", &finder, .{
        .line_numbers = true,
        .before = 1,
        .after = 1,
        .binary = .none,
        .buffer_size = 4,
        .max_line_len = 64,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqualStrings("1-a\n2:MATCH\n3-b\n", rec.text.items);
    try testing.expectEqualStrings("t.txt", rec.begun);
}

test "分块读文件和切片一致" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var hay: [4096 + 64]u8 = @splat('a');
    hay[100] = '\n';
    const needle = "MATCH";
    @memcpy(hay[200..][0..needle.len], needle);
    hay[200 + needle.len] = '\n';
    @memcpy(hay[hay.len - needle.len ..], needle);
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "big.txt", .data = &hay });
    const file = try tmp.dir.openFile(testing.io, "big.txt", .{});
    defer file.close(testing.io);

    var finder = try Finder.init(needle, .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = try searchFile(Rec, testing.allocator, testing.io, &rec, file, "big.txt", &finder, .{
        .line_numbers = true,
        .buffer_size = 128,
        .max_line_len = hay.len,
        .binary = .none,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqual(@as(u64, 2), rec.matches);
    try testing.expect(std.mem.indexOf(u8, rec.text.items, "MATCH") != null);
}

test "Sink 返回 false 时停止" {
    var finder = try Finder.init("M", .{});
    var rec = Rec{ .stop_after = 1 };
    defer rec.deinit(testing.allocator);
    const result = try searchSlice(Rec, &rec, "M\nM\n", "", &finder, .{ .line_numbers = true, .binary = .none });
    try testing.expectEqual(Outcome.stopped, result.outcome);
    try testing.expectEqualStrings("1:M\n", rec.text.items);
}

test "忽略大小写" {
    var finder = try Finder.init("foo", .{ .case = .insensitive });
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    _ = try searchSlice(Rec, &rec, "Foo\nbar\nFOO\n", "", &finder, .{
        .line_numbers = true,
        .binary = .none,
    });
    try testing.expectEqualStrings("1:Foo\n3:FOO\n", rec.text.items);
}

test "Reader 上刚好达到单行上限的行可以读完" {
    var reader = std.Io.Reader.fixed("abcd\nzzz\n");
    var finder = try Finder.init("zzz", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = try searchReader(Rec, testing.allocator, &rec, &reader, "", &finder, .{
        .line_numbers = true,
        .buffer_size = 4,
        .max_line_len = 4,
        .binary = .none,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqualStrings("2:zzz\n", rec.text.items);
}

test "Reader 超过单行上限仍返回窗口" {
    var reader = std.Io.Reader.fixed("abcdef\n");
    var finder = try Finder.init("a", .{});
    const Cap = struct {
        truncated: bool = false,
        line_len: u64 = 0,
        text: [8]u8 = undefined,
        len: usize = 0,
        pub fn matched(self: *@This(), line: Line) bool {
            self.truncated = line.truncated;
            self.line_len = line.line_len;
            self.len = @min(line.bytes.len, self.text.len);
            @memcpy(self.text[0..self.len], line.bytes[0..self.len]);
            return true;
        }
    };
    var cap = Cap{};
    const result = try searchReader(Cap, testing.allocator, &cap, &reader, "", &finder, .{
        .buffer_size = 4,
        .max_line_len = 4,
        .binary = .none,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expect(cap.truncated);
    try testing.expectEqual(@as(u64, 6), cap.line_len);
    try testing.expectEqual(@as(usize, 4), cap.len);
    try testing.expectEqualStrings("abcd", cap.text[0..cap.len]);
}

test "拉式迭代器" {
    const Iter = sink_mod.SliceIter(*Finder);
    var finder = try Finder.init("ab", .{});
    var it = Iter{ .matcher = &finder, .haystack = "xxab\nab", .line_numbers = true };
    const first = it.next().?;
    try testing.expectEqualStrings("xxab", first.bytes);
    try testing.expectEqual(@as(usize, 2), first.match.?.start);
    try testing.expectEqual(@as(?u64, 1), first.number);
    const second = it.next().?;
    try testing.expectEqualStrings("ab", second.bytes);
    try testing.expectEqual(@as(?u64, 2), second.number);
    try testing.expect(it.next() == null);
}

test "外部停止标志让流式搜索不再读下一块" {
    var reader = std.Io.Reader.fixed("MATCH\nMATCH\n");
    var finder = try Finder.init("MATCH", .{});
    var flag = std.atomic.Value(bool).init(true);
    const Sink = struct {
        pub fn matched(_: *@This(), _: Line) bool {
            return true;
        }
    };
    var sink = Sink{};
    const result = try searchReader(Sink, testing.allocator, &sink, &reader, "", &finder, .{
        .stop = &flag,
    });
    try testing.expectEqual(Outcome.stopped, result.outcome);
    try testing.expectEqual(@as(u64, 0), result.matched_lines);
}

test "scratch 在两次搜索之间复用" {
    var scratch: []u8 = &.{};
    defer testing.allocator.free(scratch);
    const Sink = struct {
        pub fn matched(_: *@This(), _: Line) bool {
            return true;
        }
    };
    var sink = Sink{};
    var finder = try Finder.init("MATCH", .{});
    const cfg = SearchConfig{ .scratch = &scratch, .buffer_size = 32, .max_line_len = 64 };
    var first = std.Io.Reader.fixed("MATCH\n");
    _ = try searchReader(Sink, testing.allocator, &sink, &first, "", &finder, cfg);
    try testing.expect(scratch.len >= 32);
    const ptr = scratch.ptr;
    var second = std.Io.Reader.fixed("MATCH\n");
    _ = try searchReader(Sink, testing.allocator, &sink, &second, "", &finder, cfg);
    try testing.expectEqual(ptr, scratch.ptr);
}

test "多模式分块读和切片一致，NUL 在命中前会停" {
    const Multi = @import("finder/multi.zig").Multi;
    const pats = [_][]const u8{ "pq", "rs" };
    var multi = try Multi.init(testing.allocator, &pats, .{});
    defer multi.deinit();
    try testing.expect(multi.kind == .pairs);

    var hay: [103]u8 = @splat('x');
    hay[31] = '\n';
    @memset(hay[32..64], 'y');
    hay[64] = 'p';
    hay[65] = 'q';
    hay[66] = '\n';
    @memset(hay[67..99], 'z');
    hay[99] = '\n';
    hay[100] = 'r';
    hay[101] = 's';
    hay[102] = '\n';

    const cfg = SearchConfig{
        .line_numbers = true,
        .buffer_size = 32,
        .max_line_len = 128,
        .binary = .none,
        .match_mode = .leftmost_first,
    };
    var slice_rec = Rec{};
    defer slice_rec.deinit(testing.allocator);
    const slice_result = try searchSlice(Rec, &slice_rec, &hay, "f", &multi, cfg);

    var reader = std.Io.Reader.fixed(&hay);
    var read_rec = Rec{};
    defer read_rec.deinit(testing.allocator);
    const read_result = try searchReader(Rec, testing.allocator, &read_rec, &reader, "f", &multi, cfg);

    var expect: [42]u8 = undefined;
    @memcpy(expect[0..2], "2:");
    @memset(expect[2..34], 'y');
    @memcpy(expect[34..37], "pq\n");
    @memcpy(expect[37..42], "4:rs\n");
    try testing.expectEqualStrings(&expect, slice_rec.text.items);
    try testing.expectEqualStrings(&expect, read_rec.text.items);
    try testing.expectEqual(slice_result.matched_lines, read_result.matched_lines);
    try testing.expectEqual(@as(u64, 2), read_result.matched_lines);

    var raw: [32]u8 = @splat('x');
    raw[8] = 0;
    raw[16] = 'p';
    raw[17] = 'q';
    raw[18] = '\n';
    var nul_reader = std.Io.Reader.fixed(&raw);
    var nul_rec = Rec{};
    defer nul_rec.deinit(testing.allocator);
    const nul_result = try searchReader(Rec, testing.allocator, &nul_rec, &nul_reader, "f", &multi, .{
        .buffer_size = 32,
        .max_line_len = 64,
        .binary = .quit,
        .match_mode = .leftmost_first,
    });
    try testing.expectEqual(Outcome.binary_quit, nul_result.outcome);
    try testing.expectEqual(@as(?u64, 8), nul_result.nul_offset);
    try testing.expectEqual(@as(u64, 0), nul_result.matched_lines);
    try testing.expectEqualStrings("", nul_rec.text.items);
}

test "基准场景的切片命中和基准同一配置" {
    const multi = @import("finder/multi.zig");
    var hay: [256]u8 = undefined;
    multi.fillScenarioText(&hay);
    const Sink = struct {
        pub fn matched(_: *@This(), _: Line) bool {
            return true;
        }
    };
    var sink = Sink{};

    var sensitive = try Finder.init("NEEDLE", .{ .case = .sensitive });
    try testing.expectEqual(@as(u64, 1), (try searchSlice(Sink, &sink, &hay, "", &sensitive, .{})).matched_lines);

    var ignore = try Finder.init("needle", .{ .case = .insensitive });
    try testing.expectEqual(@as(u64, 1), (try searchSlice(Sink, &sink, &hay, "", &ignore, .{})).matched_lines);

    var smart = try Finder.init("needle", .{ .case = .smart });
    try testing.expectEqual(@as(u64, 1), (try searchSlice(Sink, &sink, &hay, "", &smart, .{})).matched_lines);

    const Group = struct { pats: []const []const u8, lines: u64 };
    const groups = [_]Group{
        .{ .pats = multi.scenario_bytes, .lines = 0 },
        .{ .pats = multi.scenario_pairs, .lines = 1 },
        .{ .pats = multi.scenario_teddy, .lines = 0 },
        .{ .pats = multi.scenario_ac, .lines = 0 },
    };
    for (groups) |group| {
        var many = try multi.Multi.init(testing.allocator, group.pats, .{});
        defer many.deinit();
        const result = try searchSlice(Sink, &sink, &hay, "", &many, .{});
        try testing.expectEqual(group.lines, result.matched_lines);
    }
}

test "CRLF 行内容不含 CR，整行匹配不把 CR 算进去" {
    var plain = try run("a\r\nMATCH\r\nb\r\n", "MATCH", .{ .line_numbers = true, .binary = .none });
    defer plain.deinit(testing.allocator);
    try testing.expectEqualStrings("2:MATCH\n", plain.text.items);
    try testing.expect(std.mem.indexOfScalar(u8, plain.text.items, '\r') == null);

    var whole = try run("a\r\nMATCH\r\nb\r\n", "MATCH", .{
        .line_numbers = true,
        .whole_line = true,
        .binary = .none,
    });
    defer whole.deinit(testing.allocator);
    try testing.expectEqualStrings("2:MATCH\n", whole.text.items);

    var with_cr = try run("MATCH\r\n", "MATCH\r", .{ .whole_line = true, .binary = .none });
    defer with_cr.deinit(testing.allocator);
    try testing.expectEqualStrings("", with_cr.text.items);

    var longer = try run("MATCHX\r\n", "MATCH", .{ .whole_line = true, .binary = .none });
    defer longer.deinit(testing.allocator);
    try testing.expectEqualStrings("", longer.text.items);
}

test "整词的半边界" {
    var paren = try run("(-2)\n", "-2", .{ .whole_word = true, .line_numbers = true, .binary = .none });
    defer paren.deinit(testing.allocator);
    try testing.expectEqualStrings("1:(-2)\n", paren.text.items);

    var left = try run("x-2\n", "-2", .{ .whole_word = true, .binary = .none });
    defer left.deinit(testing.allocator);
    try testing.expectEqualStrings("", left.text.items);

    var right = try run("-2y\n", "-2", .{ .whole_word = true, .binary = .none });
    defer right.deinit(testing.allocator);
    try testing.expectEqualStrings("", right.text.items);

    var word = try run("foo bar\nfoobar\n", "foo", .{ .whole_word = true, .line_numbers = true, .binary = .none });
    defer word.deinit(testing.allocator);
    try testing.expectEqualStrings("1:foo bar\n", word.text.items);

    const Multi = @import("finder/multi.zig").Multi;
    var multi = try Multi.init(testing.allocator, &.{ "fo", "foo" }, .{});
    defer multi.deinit();
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    _ = try searchSlice(Rec, &rec, "(foo)\nxfo\nfoo\n", "", &multi, .{
        .whole_word = true,
        .line_numbers = true,
        .binary = .none,
    });
    try testing.expectEqualStrings("1:(foo)\n3:foo\n", rec.text.items);
}

test "整行优先于整词" {
    const both = SearchConfig{
        .whole_word = true,
        .whole_line = true,
        .line_numbers = true,
        .binary = .none,
    };
    var word_only = try run("(-2)\n", "-2", .{ .whole_word = true, .line_numbers = true, .binary = .none });
    defer word_only.deinit(testing.allocator);
    try testing.expectEqualStrings("1:(-2)\n", word_only.text.items);

    var paren = try run("(-2)\n", "-2", both);
    defer paren.deinit(testing.allocator);
    try testing.expectEqualStrings("", paren.text.items);

    var exact = try run("-2\r\n", "-2", both);
    defer exact.deinit(testing.allocator);
    try testing.expectEqualStrings("1:-2\n", exact.text.items);

    var stuck = try run("x-2\n-2y\n", "-2", both);
    defer stuck.deinit(testing.allocator);
    try testing.expectEqualStrings("", stuck.text.items);
}

const LimitGate = struct { reads: usize = 0 };

fn searchOrReject(
    allocator: std.mem.Allocator,
    patterns: []const []const u8,
    options: matcher_mod.FindOptions,
    gate: *LimitGate,
) !Result {
    const Multi = @import("finder/multi.zig").Multi;
    var multi = try Multi.init(allocator, patterns, options);
    defer multi.deinit();
    const Sink = struct {
        pub fn matched(_: *@This(), _: Line) bool {
            return true;
        }
    };
    var sink = Sink{};
    return drive(Sink, allocator, &sink, &multi, .{
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 64,
    }, "", struct {
        fn read(raw: *anyopaque, dest: []u8) ReadError!usize {
            _ = dest;
            const ctx: *LimitGate = @ptrCast(@alignCast(raw));
            ctx.reads += 1;
            return 0;
        }
    }.read, gate);
}

test "模式条数和总长度在构造前被拒绝" {
    const Multi = @import("finder/multi.zig").Multi;
    var failing = std.testing.FailingAllocator.init(testing.allocator, .{ .fail_index = 0 });
    const alloc = failing.allocator();
    var gate = LimitGate{};

    var pats: [matcher_mod.pattern_count_hard_cap + 1][]const u8 = undefined;
    for (&pats) |*slot| slot.* = "a";
    try testing.expectError(error.PatternCountExceeded, searchOrReject(alloc, &pats, .{}, &gate));
    try testing.expectEqual(@as(usize, 0), gate.reads);
    try testing.expectEqual(@as(usize, 0), failing.allocations);

    try testing.expectError(error.PatternCountExceeded, searchOrReject(alloc, &pats, .{
        .max_pattern_count = matcher_mod.pattern_count_hard_cap + 50,
    }, &gate));
    try testing.expectEqual(@as(usize, 0), gate.reads);

    try testing.expectError(error.PatternCountExceeded, Multi.init(alloc, &.{ "a", "b" }, .{ .max_pattern_count = 1 }));
    try testing.expectError(error.PatternBytesExceeded, Multi.init(alloc, &.{"abcd"}, .{ .max_pattern_bytes = 3 }));
    try testing.expectError(error.PatternCountExceeded, Finder.init("a", .{ .max_pattern_count = 0 }));

    const big = try testing.allocator.alloc(u8, matcher_mod.pattern_bytes_hard_cap + 1);
    defer testing.allocator.free(big);
    @memset(big, 'b');
    try testing.expectError(error.PatternBytesExceeded, searchOrReject(alloc, &.{big}, .{
        .max_pattern_bytes = matcher_mod.pattern_bytes_hard_cap + 10,
    }, &gate));
    try testing.expectError(error.PatternBytesExceeded, Finder.init(big, .{}));
    try testing.expectEqual(@as(usize, 0), gate.reads);

    var ok = try Multi.init(testing.allocator, &.{ "foo", "bar" }, .{
        .max_pattern_count = 8,
        .max_pattern_bytes = 64,
    });
    defer ok.deinit();
    try testing.expect(ok.find("foo", 0, .leftmost_first) != null);
    try testing.expect(ok.find("bar", 0, .leftmost_first) != null);
    try testing.expect(ok.find("nope", 0, .leftmost_first) == null);
}

const CountedRead = struct {
    rest: []const u8,
    reads: usize = 0,
    closed: u32 = 0,

    fn read(raw: *anyopaque, dest: []u8) ReadError!usize {
        const self: *CountedRead = @ptrCast(@alignCast(raw));
        self.reads += 1;
        if (self.rest.len == 0) return 0;
        const n = @min(dest.len, self.rest.len);
        @memcpy(dest[0..n], self.rest[0..n]);
        self.rest = self.rest[n..];
        return n;
    }

    fn close(raw: ?*anyopaque) void {
        const self: *CountedRead = @ptrCast(@alignCast(raw.?));
        self.closed += 1;
    }
};

test "max_count 之后不再读上游" {
    const hay = "MATCH\nMATCH2\nbbbb\n";
    var ctx = CountedRead{ .rest = hay };
    var finder = try Finder.init("MATCH", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = try drive(Rec, testing.allocator, &rec, &finder, .{
        .max_count = 1,
        .after = 4,
        .line_numbers = true,
        .binary = .none,
        .buffer_size = 13,
        .max_line_len = 64,
        .close_input = CountedRead.close,
        .close_ctx = &ctx,
    }, "", CountedRead.read, &ctx);
    try testing.expectEqual(@as(usize, 1), ctx.reads);
    try testing.expectEqual(@as(u32, 1), ctx.closed);
    try testing.expectEqual(@as(u64, 13), result.bytes_read);
    try testing.expect(ctx.rest.len > 0);
    try testing.expectEqualStrings("1:MATCH\n2:MATCH2\n", rec.text.items);
    try testing.expectEqual(Outcome.stopped, result.outcome);

    var open = CountedRead{ .rest = "MATCH\n" };
    var again = Rec{};
    defer again.deinit(testing.allocator);
    const full = try drive(Rec, testing.allocator, &again, &finder, .{
        .max_count = 5,
        .line_numbers = true,
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 64,
        .close_input = CountedRead.close,
        .close_ctx = &open,
    }, "", CountedRead.read, &open);
    try testing.expectEqual(@as(u32, 0), open.closed);
    try testing.expect(open.reads >= 2);
    try testing.expectEqual(Outcome.complete, full.outcome);
    try testing.expectEqualStrings("1:MATCH\n", again.text.items);
}

test "AND 与 NOT 同时过滤，且与反选不同" {
    const hay =
        \\foo bar
        \\foo
        \\bar
        \\foo bar baz
        \\bar baz
        \\zzz
        \\foo qux bar
        \\
    ;
    const filtered = SearchConfig{
        .line_numbers = true,
        .binary = .none,
        .contains = &.{ "foo", "bar" },
        .excludes = &.{ "baz", "qux" },
    };
    var both = try run(hay, "foo", filtered);
    defer both.deinit(testing.allocator);
    try testing.expectEqualStrings("1:foo bar\n", both.text.items);

    var inverted = try run(hay, "foo", .{ .line_numbers = true, .binary = .none, .invert = true });
    defer inverted.deinit(testing.allocator);
    try testing.expectEqualStrings(
        \\3:bar
        \\5:bar baz
        \\6:zzz
        \\
    , inverted.text.items);

    var together = try run(hay, "foo", .{
        .line_numbers = true,
        .binary = .none,
        .invert = true,
        .contains = &.{"bar"},
        .excludes = &.{"baz"},
    });
    defer together.deinit(testing.allocator);
    try testing.expectEqualStrings("3:bar\n", together.text.items);
    try testing.expect(!std.mem.eql(u8, both.text.items, inverted.text.items));
    try testing.expect(!std.mem.eql(u8, together.text.items, inverted.text.items));
    try testing.expect(!std.mem.eql(u8, together.text.items, both.text.items));
}

const Win = struct {
    calls: u32 = 0,
    truncated: bool = false,
    line_len: u64 = 0,
    window_start: u64 = 0,
    offset: u64 = 0,
    mstart: usize = 0,
    bytes: []u8 = &.{},

    fn deinit(self: *Win) void {
        if (self.bytes.len != 0) testing.allocator.free(self.bytes);
    }

    pub fn matched(self: *Win, line: Line) bool {
        self.calls += 1;
        self.truncated = line.truncated;
        self.line_len = line.line_len;
        self.window_start = line.window_start;
        self.offset = line.offset;
        self.mstart = if (line.match) |span| span.start else 0;
        if (self.bytes.len != 0) testing.allocator.free(self.bytes);
        self.bytes = testing.allocator.dupe(u8, line.bytes) catch unreachable;
        return true;
    }
};

test "超长行只保留匹配窗口并且偏移精确" {
    const max_line: usize = 16;
    var hay = try testing.allocator.alloc(u8, 4001);
    defer testing.allocator.free(hay);
    @memset(hay, 'z');
    const match_at: usize = 2500;
    @memcpy(hay[match_at..][0..5], "MATCH");
    hay[4000] = '\n';

    var slice_finder = try Finder.init("MATCH", .{});
    var slice_win = Win{};
    defer slice_win.deinit();
    const slice_result = try searchSlice(Win, &slice_win, hay, "", &slice_finder, .{
        .max_line_len = max_line,
        .binary = .none,
    });
    try testing.expectEqual(Outcome.complete, slice_result.outcome);
    try testing.expectEqual(@as(u32, 1), slice_win.calls);
    try testing.expect(slice_win.truncated);
    try testing.expectEqual(@as(u64, 4000), slice_win.line_len);
    try testing.expectEqual(@as(u64, 0), slice_win.offset);
    try testing.expect(slice_win.bytes.len <= max_line);
    try testing.expect(slice_win.bytes.len > 0);
    try testing.expectEqualStrings(hay[slice_win.window_start..][0..slice_win.bytes.len], slice_win.bytes);
    try testing.expect(std.mem.indexOf(u8, slice_win.bytes, "MATCH") != null);
    try testing.expectEqual(@as(u64, match_at), slice_win.window_start + slice_win.mstart);

    var reader = std.Io.Reader.fixed(hay);
    var read_finder = try Finder.init("MATCH", .{});
    var read_win = Win{};
    defer read_win.deinit();
    const read_result = try searchReader(Win, testing.allocator, &read_win, &reader, "", &read_finder, .{
        .max_line_len = max_line,
        .buffer_size = 8,
        .binary = .none,
    });
    try testing.expectEqual(Outcome.complete, read_result.outcome);
    try testing.expectEqual(@as(u32, 1), read_win.calls);
    try testing.expect(read_win.truncated);
    try testing.expectEqual(@as(u64, 4000), read_win.line_len);
    try testing.expectEqual(@as(u64, 0), read_win.offset);
    try testing.expect(read_win.bytes.len <= max_line);
    try testing.expectEqualStrings(hay[read_win.window_start..][0..read_win.bytes.len], read_win.bytes);
    try testing.expect(std.mem.indexOf(u8, read_win.bytes, "MATCH") != null);
    try testing.expectEqual(@as(u64, match_at), read_win.window_start + read_win.mstart);
}

test "不匹配的超长行也不把缓冲涨过上限" {
    const max_line: usize = 32;
    const line_len: usize = 3000;
    var hay = try testing.allocator.alloc(u8, line_len + 1 + 6);
    defer testing.allocator.free(hay);
    @memset(hay[0..line_len], 'z');
    hay[line_len] = '\n';
    @memcpy(hay[line_len + 1 ..][0..6], "MATCH\n");

    var scratch: []u8 = &.{};
    defer testing.allocator.free(scratch);
    var finder = try Finder.init("MATCH", .{});
    var win = Win{};
    defer win.deinit();
    var reader = std.Io.Reader.fixed(hay);
    const result = try searchReader(Win, testing.allocator, &win, &reader, "", &finder, .{
        .scratch = &scratch,
        .buffer_size = 16,
        .max_line_len = max_line,
        .binary = .none,
        .line_numbers = true,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expect(scratch.len <= max_line + 1);
    try testing.expect(scratch.len < line_len);
    try testing.expectEqual(@as(u32, 1), win.calls);
    try testing.expect(!win.truncated);
    try testing.expectEqual(@as(u64, line_len + 1), win.offset);
    try testing.expectEqualStrings("MATCH", win.bytes);
}

test "二进制默认跳过并带 binary_offset" {
    var ctx = CountedRead{ .rest = "abc\x00MATCH\nMORE\n" };
    var finder = try Finder.init("MATCH", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = try drive(Rec, testing.allocator, &rec, &finder, .{
        .buffer_size = 8,
        .max_line_len = 64,
    }, "", CountedRead.read, &ctx);
    try testing.expectEqual(@as(?u64, 3), result.binary_offset);
    try testing.expectEqual(result.binary_offset, result.nul_offset);
    try testing.expectEqual(Outcome.binary_quit, result.outcome);
    try testing.expectEqual(@as(u64, 0), result.matched_lines);
    try testing.expectEqual(@as(usize, 1), ctx.reads);
    try testing.expect(ctx.rest.len > 0);
    try testing.expectEqualStrings("", rec.text.items);
}

test "搜索二进制但不返回行内容" {
    const Sink = struct {
        calls: u32 = 0,
        bytes: usize = 0,
        pub fn matched(self: *@This(), line: Line) bool {
            self.calls += 1;
            self.bytes += line.bytes.len;
            return true;
        }
    };
    var sink = Sink{};
    var finder = try Finder.init("MATCH", .{});
    const result = try searchSlice(Sink, &sink, "xxMATCH\x00yy\nMATCH2\n", "", &finder, .{
        .binary = .report,
    });
    try testing.expect(result.binary_offset != null);
    try testing.expectEqual(@as(?u64, 7), result.binary_offset);
    try testing.expect(result.matched_lines > 0);
    try testing.expect(sink.calls > 0);
    try testing.expectEqual(@as(usize, 0), sink.bytes);
    try testing.expectEqual(Outcome.binary_matched, result.outcome);
}

test "按文本处理的二进制仍走超长行窗口" {
    var hay = try testing.allocator.alloc(u8, 64);
    defer testing.allocator.free(hay);
    @memset(hay, 'q');
    @memcpy(hay[4..9], "MATCH");
    hay[20] = 0;
    hay[63] = '\n';
    var finder = try Finder.init("MATCH", .{});
    var win = Win{};
    defer win.deinit();
    const result = try searchSlice(Win, &win, hay, "", &finder, .{
        .max_line_len = 8,
        .binary = .none,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expect(win.truncated);
    try testing.expectEqual(@as(u64, 63), win.line_len);
    try testing.expect(std.mem.indexOf(u8, win.bytes, "MATCH") != null);
    try testing.expect(win.bytes.len <= 8);
}

test "前置上下文容量不超过行数上限乘单行上限" {
    const max_line: usize = 16;
    const before: u32 = 3;
    const cfg = SearchConfig{
        .before = before,
        .max_line_len = max_line,
        .max_context_lines = 4,
        .buffer_size = 32,
        .binary = .none,
        .line_numbers = true,
    };
    try testing.expectEqual(@as(usize, 48), beforeContextCapacity(cfg));
    try testing.expect(beforeContextCapacity(cfg) <= @as(usize, SearchConfig.context_lines_hard_cap) * max_line);

    const Sink = struct {
        text: [64]u8 = undefined,
        len: usize = 0,
        fn add(self: *@This(), line: Line, mark: u8) void {
            if (line.number) |n| {
                if (self.len < self.text.len) {
                    self.text[self.len] = '0' + @as(u8, @intCast(n));
                    self.len += 1;
                }
            }
            if (self.len < self.text.len) {
                self.text[self.len] = mark;
                self.len += 1;
            }
            const n = @min(line.bytes.len, self.text.len - self.len);
            @memcpy(self.text[self.len..][0..n], line.bytes[0..n]);
            self.len += n;
            if (self.len < self.text.len) {
                self.text[self.len] = '\n';
                self.len += 1;
            }
        }
        pub fn context(self: *@This(), line: Line) bool {
            self.add(line, '-');
            return true;
        }
        pub fn matched(self: *@This(), line: Line) bool {
            self.add(line, ':');
            return true;
        }
    };
    var sink = Sink{};
    var finder = try Finder.init("M", .{});
    var reader = std.Io.Reader.fixed("a\nb\nc\nd\ne\nM\n");
    var scratch: []u8 = &.{};
    defer testing.allocator.free(scratch);
    var counted = CountAlloc{ .parent = testing.allocator };
    const result = try searchReader(Sink, counted.allocator(), &sink, &reader, "", &finder, .{
        .before = before,
        .max_line_len = max_line,
        .max_context_lines = 4,
        .buffer_size = 32,
        .binary = .none,
        .line_numbers = true,
        .scratch = &scratch,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqualStrings("3-c\n4-d\n5-e\n6:M\n", sink.text[0..sink.len]);
    try testing.expect(counted.peak <= scratch.len + beforeContextCapacity(cfg) + 64);
    try testing.expect(counted.peak <= @as(usize, SearchConfig.context_lines_hard_cap) * max_line + scratch.len + 64);
}

const CountAlloc = struct {
    parent: std.mem.Allocator,
    peak: usize = 0,
    live: usize = 0,

    fn allocator(self: *CountAlloc) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{
            .alloc = alloc,
            .resize = resize,
            .remap = remap,
            .free = free,
        } };
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *CountAlloc = @ptrCast(@alignCast(ctx));
        const ptr = self.parent.rawAlloc(len, alignment, ret_addr) orelse return null;
        self.live += len;
        self.peak = @max(self.peak, self.live);
        return ptr;
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *CountAlloc = @ptrCast(@alignCast(ctx));
        if (!self.parent.rawResize(memory, alignment, new_len, ret_addr)) return false;
        self.live = self.live - memory.len + new_len;
        self.peak = @max(self.peak, self.live);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *CountAlloc = @ptrCast(@alignCast(ctx));
        const ptr = self.parent.rawRemap(memory, alignment, new_len, ret_addr) orelse return null;
        self.live = self.live - memory.len + new_len;
        self.peak = @max(self.peak, self.live);
        return ptr;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        const self: *CountAlloc = @ptrCast(@alignCast(ctx));
        self.parent.rawFree(memory, alignment, ret_addr);
        self.live -= memory.len;
    }
};

test "对称上下文可被单侧覆盖" {
    var both = try run("a\nb\nM\nc\n", "M", .{
        .line_numbers = true,
        .context = 1,
        .binary = .none,
    });
    defer both.deinit(testing.allocator);
    try testing.expectEqualStrings("2-b\n3:M\n4-c\n", both.text.items);

    var only_after = try run("a\nb\nM\nc\n", "M", .{
        .line_numbers = true,
        .context = 1,
        .before = 0,
        .binary = .none,
    });
    defer only_after.deinit(testing.allocator);
    try testing.expectEqualStrings("3:M\n4-c\n", only_after.text.items);

    var only_before = try run("a\nb\nM\nc\n", "M", .{
        .line_numbers = true,
        .context = 1,
        .after = 0,
        .binary = .none,
    });
    defer only_before.deinit(testing.allocator);
    try testing.expectEqualStrings("2-b\n3:M\n", only_before.text.items);

    var mixed = try run("a\nb\nM\nc\nd\n", "M", .{
        .line_numbers = true,
        .context = 2,
        .after = 1,
        .binary = .none,
    });
    defer mixed.deinit(testing.allocator);
    try testing.expectEqualStrings("1-a\n2-b\n3:M\n4-c\n", mixed.text.items);
}

test "断点是标记而不是两个减号" {
    var rec = try run("a\nb\nMATCH\nc\nd\ne\nMATCH2\nf\n", "MATCH", .{
        .line_numbers = true,
        .before = 1,
        .after = 1,
        .binary = .none,
    });
    defer rec.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 1), rec.breaks);
    try testing.expect(std.mem.indexOf(u8, rec.text.items, "--") == null);
    try testing.expectEqualStrings("2-b\n3:MATCH\n4-c\n6-e\n7:MATCH2\n8-f\n", rec.text.items);
}

test "上下文行数不能超过硬顶" {
    var finder = try Finder.init("M", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const over = SearchConfig.context_lines_hard_cap + 1;
    try testing.expectError(error.ContextLinesExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .context = over,
    }));
    try testing.expectError(error.ContextLinesExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .before = over,
    }));
    try testing.expectError(error.ContextLinesExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .after = over,
    }));
    try testing.expectError(error.ContextLinesExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .before = over,
        .max_context_lines = over + 5,
    }));
    try testing.expectError(error.ContextLinesExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .context = 3,
        .max_context_lines = 2,
    }));
    const ok = try searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .context = 2,
        .max_context_lines = 4,
        .binary = .none,
    });
    try testing.expectEqual(@as(u64, 1), ok.matched_lines);
}

fn writeUtf16(dst: []u8, little: bool, ascii: []const u8) []const u8 {
    dst[0] = if (little) 0xff else 0xfe;
    dst[1] = if (little) 0xfe else 0xff;
    var i: usize = 2;
    for (ascii) |b| {
        if (little) {
            dst[i] = b;
            dst[i + 1] = 0;
        } else {
            dst[i] = 0;
            dst[i + 1] = b;
        }
        i += 2;
    }
    return dst[0..i];
}

const Mark = struct {
    bytes: [32]u8 = undefined,
    len: usize = 0,
    raw: [32]u8 = undefined,
    raw_len: usize = 0,
    text: [32]u8 = undefined,
    text_len: usize = 0,
    b0: usize = 0,
    b1: usize = 0,
    u0: usize = 0,
    u1: usize = 0,
    column: ?u64 = null,
    number: ?u64 = null,
    offset: u64 = 0,

    pub fn matched(self: *Mark, line: Line) bool {
        self.len = @min(line.bytes.len, self.bytes.len);
        @memcpy(self.bytes[0..self.len], line.bytes[0..self.len]);
        self.raw_len = @min(line.raw.len, self.raw.len);
        @memcpy(self.raw[0..self.raw_len], line.raw[0..self.raw_len]);
        self.text_len = @min(line.text.len, self.text.len);
        @memcpy(self.text[0..self.text_len], line.text[0..self.text_len]);
        const span = line.match.?;
        self.b0 = span.start;
        self.b1 = span.end;
        self.u0 = span.u16_start;
        self.u1 = span.u16_end;
        self.column = line.u16_column;
        self.number = line.number;
        self.offset = line.offset;
        return true;
    }
};

test "NUL 分隔符按记录计数" {
    // 默认 binary 是 quit。NUL 记录模式里它只是分隔符，LF 不再断行。
    // NUL 作为二进制信号只在 LF 分行、且不是这种原始记录模式时生效。
    const hay = "a\nb\x00c\x00d\ne";
    var first = try run(hay, "b", .{ .line_numbers = true, .null_data = true });
    defer first.deinit(testing.allocator);
    try testing.expectEqualStrings("1:a\nb\n", first.text.items);

    var second = try run(hay, "c", .{ .line_numbers = true, .null_data = true });
    defer second.deinit(testing.allocator);
    try testing.expectEqualStrings("2:c\n", second.text.items);

    var third = try run(hay, "e", .{ .line_numbers = true, .null_data = true });
    defer third.deinit(testing.allocator);
    try testing.expectEqualStrings("3:d\ne\n", third.text.items);

    var finder = try Finder.init("e", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = try searchSlice(Rec, &rec, hay, "", &finder, .{
        .null_data = true,
        .line_numbers = true,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqual(@as(?u64, null), result.binary_offset);
    try testing.expectEqual(@as(?u64, null), result.nul_offset);
    try testing.expectEqual(@as(u64, 1), result.matched_lines);

    var reader = std.Io.Reader.fixed(hay);
    var streamed = Rec{};
    defer streamed.deinit(testing.allocator);
    var stream_finder = try Finder.init("e", .{});
    const streamed_result = try searchReader(Rec, testing.allocator, &streamed, &reader, "", &stream_finder, .{
        .null_data = true,
        .line_numbers = true,
        .buffer_size = 3,
        .max_line_len = 64,
    });
    try testing.expectEqual(Outcome.complete, streamed_result.outcome);
    try testing.expectEqual(@as(?u64, null), streamed_result.binary_offset);
    try testing.expectEqualStrings("3:d\ne\n", streamed.text.items);
}

test "UTF-8 BOM 被跳过且不参与匹配" {
    const hay = "\xEF\xBB\xBFfoo\nbar\n";
    var hit = try run(hay, "foo", .{ .line_numbers = true, .binary = .none });
    defer hit.deinit(testing.allocator);
    try testing.expectEqualStrings("1:foo\n", hit.text.items);

    var bom = try run(hay, "\xEF\xBB\xBF", .{ .binary = .none });
    defer bom.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 0), bom.matches);

    var byte = try run(hay, "\xEF", .{ .binary = .none });
    defer byte.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 0), byte.matches);

    const bad = "\xEF\xBB\xBFa\xffb\n";
    var replaced = Mark{};
    var rep_finder = try Finder.init("\u{FFFD}", .{});
    const rep = try searchSlice(Mark, &replaced, bad, "", &rep_finder, .{
        .binary = .none,
        .decode_allocator = testing.allocator,
    });
    try testing.expectEqual(@as(u64, 1), rep.matched_lines);
    try testing.expectEqualStrings("a\u{FFFD}b", replaced.bytes[0..replaced.len]);

    var raw_bad = try run(bad, "\xff", .{
        .binary = .none,
        .decode_allocator = testing.allocator,
    });
    defer raw_bad.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 0), raw_bad.matches);

    var reader = std.Io.Reader.fixed(hay);
    var finder = try Finder.init("foo", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const split = try searchReader(Rec, testing.allocator, &rec, &reader, "", &finder, .{
        .line_numbers = true,
        .binary = .none,
        .buffer_size = 2,
        .max_line_len = 64,
    });
    try testing.expectEqual(Outcome.complete, split.outcome);
    try testing.expectEqualStrings("1:foo\n", rec.text.items);
}

test "UTF-16LE 与 UTF-16BE 转成 UTF-8 后命中" {
    // 读缓冲比 BOM（2 字节）加一个 UTF-16 码元（2 字节）还小，码元会拆在两块里。
    const cap: usize = 3;
    try testing.expect(cap < 4);

    var le_buf: [10]u8 = undefined;
    const le = writeUtf16(&le_buf, true, "foo\n");
    var le_reader = std.Io.Reader.fixed(le);
    var le_finder = try Finder.init("foo", .{});
    var le_rec = Rec{};
    defer le_rec.deinit(testing.allocator);
    const le_result = try searchReader(Rec, testing.allocator, &le_rec, &le_reader, "", &le_finder, .{
        .line_numbers = true,
        .buffer_size = cap,
        .max_line_len = 64,
    });
    try testing.expectEqual(Outcome.complete, le_result.outcome);
    try testing.expectEqual(@as(?u64, null), le_result.binary_offset);
    try testing.expectEqualStrings("1:foo\n", le_rec.text.items);

    var be_buf: [10]u8 = undefined;
    const be = writeUtf16(&be_buf, false, "foo\n");
    var be_reader = std.Io.Reader.fixed(be);
    var be_finder = try Finder.init("foo", .{});
    var be_rec = Rec{};
    defer be_rec.deinit(testing.allocator);
    const be_result = try searchReader(Rec, testing.allocator, &be_rec, &be_reader, "", &be_finder, .{
        .line_numbers = true,
        .buffer_size = cap,
        .max_line_len = 64,
    });
    try testing.expectEqual(Outcome.complete, be_result.outcome);
    try testing.expectEqualStrings("1:foo\n", be_rec.text.items);

    var slice_mark = Mark{};
    var slice_finder = try Finder.init("foo", .{});
    const slice_result = try searchSlice(Mark, &slice_mark, le, "", &slice_finder, .{
        .decode_allocator = testing.allocator,
        .line_numbers = true,
    });
    try testing.expectEqual(Outcome.complete, slice_result.outcome);
    try testing.expectEqualStrings("foo", slice_mark.bytes[0..slice_mark.len]);
    try testing.expectEqual(@as(u64, 0), slice_mark.offset);
    try testing.expectEqual(@as(?u64, 1), slice_mark.number);
}

test "非法 UTF-16 变成 U+FFFD" {
    const lone = [_]u8{ 0xFF, 0xFE, 0x61, 0x00, 0x00, 0xD8, 0x62, 0x00, 0x0A, 0x00 };
    var mark = Mark{};
    var finder = try Finder.init("\u{FFFD}", .{});
    var reader = std.Io.Reader.fixed(&lone);
    const result = try searchReader(Mark, testing.allocator, &mark, &reader, "", &finder, .{
        .buffer_size = 3,
        .max_line_len = 64,
        .binary = .none,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqualStrings("a\u{FFFD}b", mark.bytes[0..mark.len]);

    const odd = [_]u8{ 0xFF, 0xFE, 0x61, 0x00, 0xFF };
    var odd_mark = Mark{};
    var odd_finder = try Finder.init("\u{FFFD}", .{});
    const odd_result = try searchSlice(Mark, &odd_mark, &odd, "", &odd_finder, .{
        .decode_allocator = testing.allocator,
        .binary = .none,
    });
    try testing.expectEqual(@as(u64, 1), odd_result.matched_lines);
    try testing.expectEqualStrings("a\u{FFFD}", odd_mark.bytes[0..odd_mark.len]);

    const be = [_]u8{ 0xFE, 0xFF, 0x00, 0x61, 0xD8, 0x00, 0x00, 0x0A };
    var be_mark = Mark{};
    var be_finder = try Finder.init("a", .{});
    const be_result = try searchSlice(Mark, &be_mark, &be, "", &be_finder, .{
        .decode_allocator = testing.allocator,
        .binary = .none,
    });
    try testing.expectEqual(@as(u64, 1), be_result.matched_lines);
    try testing.expectEqualStrings("a\u{FFFD}", be_mark.bytes[0..be_mark.len]);
}

test "原始字节模式不嗅探 BOM" {
    const hay = "\xEF\xBB\xBFfoo\n";
    var kept = try run(hay, "\xEF\xBB\xBF", .{
        .encoding = .none,
        .line_numbers = true,
        .binary = .none,
    });
    defer kept.deinit(testing.allocator);
    try testing.expectEqualStrings("1:\xEF\xBB\xBFfoo\n", kept.text.items);

    var text = try run(hay, "foo", .{
        .encoding = .none,
        .line_numbers = true,
        .binary = .none,
    });
    defer text.deinit(testing.allocator);
    try testing.expectEqualStrings("1:\xEF\xBB\xBFfoo\n", text.text.items);

    var le_buf: [10]u8 = undefined;
    const le = writeUtf16(&le_buf, true, "foo\n");
    var miss = try run(le, "foo", .{ .encoding = .none, .binary = .none });
    defer miss.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 0), miss.matches);

    var bom = try run(le, "\xFF\xFE", .{ .encoding = .none, .binary = .none });
    defer bom.deinit(testing.allocator);
    try testing.expectEqual(@as(u64, 1), bom.matches);
}

test "匹配的 UTF-16 偏移按码元计数" {
    const hay = "aé你😀x\n";
    var ex = Mark{};
    var ex_finder = try Finder.init("é", .{});
    _ = try searchSlice(Mark, &ex, hay, "", &ex_finder, .{ .binary = .none });
    try testing.expectEqual(@as(usize, 1), ex.b0);
    try testing.expectEqual(@as(usize, 3), ex.b1);
    try testing.expectEqual(@as(usize, 1), ex.u0);
    try testing.expectEqual(@as(usize, 2), ex.u1);
    try testing.expectEqual(@as(?u64, 2), ex.column);

    var face = Mark{};
    var face_finder = try Finder.init("😀", .{});
    _ = try searchSlice(Mark, &face, hay, "", &face_finder, .{ .binary = .none });
    try testing.expectEqual(@as(usize, 6), face.b0);
    try testing.expectEqual(@as(usize, 10), face.b1);
    try testing.expectEqual(@as(usize, 3), face.u0);
    try testing.expectEqual(@as(usize, 5), face.u1);
    try testing.expectEqual(@as(?u64, 4), face.column);

    var ex_x = Mark{};
    var x_finder = try Finder.init("x", .{});
    _ = try searchSlice(Mark, &ex_x, hay, "", &x_finder, .{ .binary = .none });
    try testing.expectEqual(@as(usize, 10), ex_x.b0);
    try testing.expectEqual(@as(usize, 11), ex_x.b1);
    try testing.expectEqual(@as(usize, 5), ex_x.u0);
    try testing.expectEqual(@as(usize, 6), ex_x.u1);
    try testing.expectEqual(@as(?u64, 6), ex_x.column);
}

test "非法 UTF-8 同时给出有损文本和原始字节" {
    const hay = "a\xffb\n";
    var letter = Mark{};
    var letter_finder = try Finder.init("b", .{});
    const found = try searchSlice(Mark, &letter, hay, "", &letter_finder, .{ .binary = .none });
    try testing.expectEqual(@as(u64, 1), found.matched_lines);
    try testing.expectEqualStrings("a\xffb", letter.bytes[0..letter.len]);
    try testing.expectEqualStrings("a\xffb", letter.raw[0..letter.raw_len]);
    try testing.expectEqualStrings("a\u{FFFD}b", letter.text[0..letter.text_len]);
    try testing.expectEqual(@as(usize, 2), letter.b0);
    try testing.expectEqual(@as(usize, 3), letter.b1);
    try testing.expectEqual(@as(usize, 2), letter.u0);
    try testing.expectEqual(@as(usize, 3), letter.u1);
    try testing.expectEqual(@as(?u64, 3), letter.column);

    var bad = Mark{};
    var bad_finder = try Finder.init("\xff", .{});
    _ = try searchSlice(Mark, &bad, hay, "", &bad_finder, .{ .binary = .none });
    try testing.expectEqual(@as(usize, 1), bad.b0);
    try testing.expectEqual(@as(usize, 2), bad.b1);
    try testing.expectEqual(@as(usize, 1), bad.u0);
    try testing.expectEqual(@as(usize, 2), bad.u1);
    try testing.expectEqualStrings("a\xffb", bad.raw[0..bad.raw_len]);
    try testing.expectEqualStrings("a\u{FFFD}b", bad.text[0..bad.text_len]);
}

const EvKind = enum { begin, match, context, brk, progress, heartbeat, end, summary };

const Saved = struct {
    kind: EvKind,
    id: []u8,
    line_number: u64 = 0,
    column: ?u64 = null,
    u16_column: ?u64 = null,
    offset: u64 = 0,
    bytes: []u8 = &.{},
    matches: []Span = &.{},
    truncated: bool = false,
    line_len: u64 = 0,
    window_start: u64 = 0,
    status: BinaryStatus = .none,
    matched_lines: u64 = 0,
    match_count: u64 = 0,
    bytes_searched: u64 = 0,
    bytes_printed: u64 = 0,
    bytes_read_raw: u64 = 0,
    elapsed: u64 = 0,
    searches: u64 = 0,
    searches_with_match: u64 = 0,
    sources_failed: u64 = 0,

    fn free(self: *Saved) void {
        const a = testing.allocator;
        if (self.id.len != 0) a.free(self.id);
        if (self.bytes.len != 0) a.free(self.bytes);
        if (self.matches.len != 0) a.free(self.matches);
    }
};

const Bag = struct {
    items: std.ArrayList(Saved) = .empty,

    fn deinit(self: *Bag) void {
        self.reset();
    }

    fn reset(self: *Bag) void {
        for (self.items.items) |*item| item.free();
        self.items.deinit(testing.allocator);
        self.items = .empty;
    }

    pub fn event(self: *Bag, ev: Event) bool {
        const saved: Saved = switch (ev) {
            .begin => |b| bare(.begin, b.source_id),
            .context_break => |b| bare(.brk, b.source_id),
            .progress => |p| blk: {
                var row = bare(.progress, p.source_id);
                row.bytes_searched = p.bytes_searched;
                row.match_count = p.matches;
                row.matched_lines = p.matched_lines;
                break :blk row;
            },
            .heartbeat => |h| blk: {
                var row = bare(.heartbeat, h.source_id);
                row.bytes_searched = h.bytes_searched;
                row.match_count = h.matches;
                row.matched_lines = h.matched_lines;
                break :blk row;
            },
            .end => |e| blk: {
                var row = bare(.end, e.source_id);
                row.status = e.binary_status;
                row.matched_lines = e.matched_lines;
                row.match_count = e.matches;
                break :blk row;
            },
            .summary => |s| blk: {
                var row = bare(.summary, s.source_id);
                row.elapsed = s.elapsed;
                row.searches = s.searches;
                row.searches_with_match = s.searches_with_match;
                row.bytes_searched = s.bytes_searched;
                row.bytes_printed = s.bytes_printed;
                row.matched_lines = s.matched_lines;
                row.match_count = s.matches;
                row.bytes_read_raw = s.bytes_read_raw;
                row.sources_failed = s.sources_failed;
                break :blk row;
            },
            .match => |line| fromLine(.match, line),
            .context => |line| fromLine(.context, line),
        };
        self.items.append(testing.allocator, saved) catch unreachable;
        return true;
    }

    fn kindCount(self: *const Bag, kind: EvKind) usize {
        var n: usize = 0;
        for (self.items.items) |item| {
            if (item.kind == kind) n += 1;
        }
        return n;
    }

    fn matchAt(self: *const Bag, n: usize) *const Saved {
        var seen: usize = 0;
        for (self.items.items) |*item| {
            if (item.kind != .match) continue;
            if (seen == n) return item;
            seen += 1;
        }
        unreachable;
    }

    fn find(self: *const Bag, kind: EvKind) *const Saved {
        var i = self.items.items.len;
        while (i > 0) {
            i -= 1;
            if (self.items.items[i].kind == kind) return &self.items.items[i];
        }
        unreachable;
    }
};

fn bare(kind: EvKind, id: []const u8) Saved {
    return .{
        .kind = kind,
        .id = testing.allocator.dupe(u8, id) catch unreachable,
    };
}

fn fromLine(kind: EvKind, line: LineEvent) Saved {
    const a = testing.allocator;
    return .{
        .kind = kind,
        .id = a.dupe(u8, line.source_id) catch unreachable,
        .line_number = line.line_number,
        .column = line.column,
        .u16_column = line.u16_column,
        .offset = line.absolute_offset,
        .bytes = if (line.bytes.len == 0) &.{} else a.dupe(u8, line.bytes) catch unreachable,
        .matches = if (line.matches.len == 0) &.{} else a.dupe(Span, line.matches) catch unreachable,
        .truncated = line.truncated,
        .line_len = line.line_len,
        .window_start = line.window_start,
        .status = line.binary_status,
    };
}

fn searchId(bag: *Bag, id: []const u8, hay: []const u8, pattern: []const u8, config: SearchConfig) !Result {
    var finder = try Finder.init(pattern, .{});
    return searchSourceSlice(Bag, bag, id, hay, &finder, config);
}

test "服务入口只接受来源 ID" {
    var bag = Bag{};
    defer bag.deinit();
    const slice_result = try searchId(&bag, "sid-7", "MATCH\n", "MATCH", .{});
    try testing.expectEqual(Outcome.complete, slice_result.outcome);
    try testing.expect(bag.kindCount(.begin) == 1);
    try testing.expect(bag.kindCount(.end) == 1);
    try testing.expect(bag.kindCount(.match) == 1);
    for (bag.items.items) |item| try testing.expectEqualStrings("sid-7", item.id);

    bag.reset();
    var reader = std.Io.Reader.fixed("MATCH\n");
    var finder = try Finder.init("MATCH", .{});
    const read_result = try searchSource(Bag, testing.allocator, &bag, &reader, "sid-8", &finder, .{});
    try testing.expectEqual(Outcome.complete, read_result.outcome);
    try testing.expect(bag.kindCount(.match) == 1);
    for (bag.items.items) |item| try testing.expectEqualStrings("sid-8", item.id);
    try testing.expect(bag.items.items[0].kind == .begin);
    try testing.expect(bag.find(.end).kind == .end);
    try testing.expect(bag.items.items[bag.items.items.len - 1].kind == .summary);
}

test "事件带行号、字节列号和绝对偏移" {
    var bag = Bag{};
    defer bag.deinit();
    _ = try searchId(&bag, "pos", "éMATCH\nzz\nMATCH\n", "MATCH", .{});
    const first = bag.matchAt(0);
    try testing.expectEqual(@as(u64, 1), first.line_number);
    try testing.expectEqual(@as(?u64, 3), first.column);
    try testing.expectEqual(@as(?u64, 2), first.u16_column);
    try testing.expectEqual(@as(u64, 0), first.offset);
    try testing.expect(first.column != first.u16_column);

    const second = bag.matchAt(1);
    try testing.expectEqual(@as(u64, 3), second.line_number);
    try testing.expectEqual(@as(?u64, 1), second.column);
    try testing.expectEqual(@as(u64, 11), second.offset);

    bag.reset();
    _ = try searchId(&bag, "rec", "a\nb\x00zzMATCH", "MATCH", .{ .null_data = true });
    const record = bag.matchAt(0);
    try testing.expectEqual(@as(u64, 2), record.line_number);
    try testing.expectEqual(@as(?u64, 3), record.column);
    try testing.expectEqual(@as(u64, 4), record.offset);
    try testing.expectEqualStrings("zzMATCH", record.bytes);
}

test "一行多个匹配区间按起点排序" {
    var bag = Bag{};
    defer bag.deinit();
    _ = try searchId(&bag, "many", "abXabYab\n", "ab", .{});
    const line = bag.matchAt(0);
    try testing.expectEqual(@as(usize, 3), line.matches.len);
    try testing.expectEqual(@as(usize, 0), line.matches[0].start);
    try testing.expectEqual(@as(usize, 2), line.matches[0].end);
    try testing.expectEqual(@as(usize, 3), line.matches[1].start);
    try testing.expectEqual(@as(usize, 5), line.matches[1].end);
    try testing.expectEqual(@as(usize, 6), line.matches[2].start);
    try testing.expectEqual(@as(usize, 8), line.matches[2].end);
    try testing.expect(line.matches[0].start <= line.matches[1].start);
    try testing.expect(line.matches[1].start <= line.matches[2].start);
    try testing.expectEqualStrings("ab", line.bytes[line.matches[0].start..line.matches[0].end]);
    try testing.expectEqualStrings("ab", line.bytes[line.matches[2].start..line.matches[2].end]);
    try testing.expectEqual(@as(?u64, 1), line.column);
    try testing.expect(std.mem.indexOfScalar(u8, line.bytes, 0x1b) == null);
}

test "每个事件只有来源 ID" {
    var bag = Bag{};
    defer bag.deinit();
    _ = try searchId(&bag, "id-9", "a\nb\nMATCH\nc\nd\ne\nMATCH2\nf\n", "MATCH", .{
        .before = 1,
        .after = 1,
        .binary = .none,
    });
    try testing.expect(bag.kindCount(.begin) == 1);
    try testing.expect(bag.kindCount(.match) == 2);
    try testing.expect(bag.kindCount(.context) >= 1);
    try testing.expect(bag.kindCount(.brk) == 1);
    try testing.expect(bag.kindCount(.end) == 1);
    for (bag.items.items) |item| try testing.expectEqualStrings("id-9", item.id);
}

test "二进制状态三种取值" {
    var bag = Bag{};
    defer bag.deinit();
    _ = try searchId(&bag, "plain", "MATCH\n", "MATCH", .{});
    try testing.expectEqual(BinaryStatus.none, bag.find(.end).status);

    bag.reset();
    _ = try searchId(&bag, "text", "xxMATCH\x00yy\n", "MATCH", .{ .binary = .none });
    try testing.expectEqual(BinaryStatus.none, bag.find(.end).status);
    try testing.expect(std.mem.indexOfScalar(u8, bag.matchAt(0).bytes, 0) != null);

    bag.reset();
    _ = try searchId(&bag, "seen", "xxMATCH\x00yy\n", "MATCH", .{ .binary = .report });
    try testing.expectEqual(BinaryStatus.detected, bag.find(.end).status);

    bag.reset();
    _ = try searchId(&bag, "skip", "ab\x00MATCH\n", "MATCH", .{ .binary = .quit });
    try testing.expectEqual(BinaryStatus.suppressed, bag.find(.end).status);
    try testing.expectEqual(@as(u64, 0), bag.find(.end).matched_lines);
    try testing.expectEqual(@as(usize, 0), bag.kindCount(.match));
}

test "截断字段来自超长行窗口" {
    var hay: [80]u8 = undefined;
    @memset(&hay, 'z');
    const match_at: usize = 40;
    @memcpy(hay[match_at..][0..5], "MATCH");
    var bag = Bag{};
    defer bag.deinit();
    _ = try searchId(&bag, "win", &hay, "MATCH", .{ .max_line_len = 16, .binary = .none });
    const line = bag.matchAt(0);
    try testing.expect(line.truncated);
    try testing.expectEqual(@as(u64, hay.len), line.line_len);
    try testing.expectEqual(@as(u64, 0), line.offset);
    try testing.expect(line.bytes.len <= 16);
    try testing.expect(line.bytes.len > 0);
    try testing.expectEqualStrings(hay[line.window_start..][0..line.bytes.len], line.bytes);
    try testing.expect(line.matches.len >= 1);
    try testing.expectEqual(@as(u64, match_at), line.window_start + line.matches[0].start);
}

test "未命中来源也有 begin 和 end" {
    var bag = Bag{};
    defer bag.deinit();
    const result = try searchId(&bag, "miss", "nope\n", "MATCH", .{});
    try testing.expectEqual(@as(u64, 0), result.matched_lines);
    try testing.expect(bag.items.items[0].kind == .begin);
    try testing.expect(bag.find(.end).kind == .end);
    try testing.expectEqualStrings("miss", bag.items.items[0].id);
    try testing.expectEqualStrings("miss", bag.find(.end).id);
    try testing.expectEqual(@as(u64, 0), bag.find(.end).matched_lines);
    try testing.expectEqual(@as(u64, 0), bag.find(.end).match_count);
    try testing.expectEqual(@as(usize, 0), bag.kindCount(.match));
}

test "行首空白原样返回" {
    var bag = Bag{};
    defer bag.deinit();
    _ = try searchId(&bag, "pad", "  MATCH\n", "MATCH", .{});
    const line = bag.matchAt(0);
    try testing.expectEqualStrings("  MATCH", line.bytes);
    try testing.expectEqual(@as(u64, 0), line.offset);
    try testing.expectEqual(@as(usize, 1), line.matches.len);
    try testing.expectEqual(@as(usize, 2), line.matches[0].start);
    try testing.expectEqual(@as(usize, 7), line.matches[0].end);
    try testing.expectEqual(@as(?u64, 3), line.column);
    try testing.expect(std.mem.indexOfScalar(u8, line.bytes, 0x1b) == null);
    try testing.expect(std.mem.indexOf(u8, line.bytes, "<") == null);
}

test "事件逐条回调" {
    var scratch: [8]u8 = undefined;
    var src = std.testing.Reader.init(&scratch, &.{.{ .buffer = "M\nM\n" }});
    src.artificial_limit = .limited(2);
    const Watch = struct {
        src: *std.testing.Reader,
        n: u32 = 0,
        offset_at_begin: usize = 99,
        offset_at_first: usize = 99,
        matches: u32 = 0,
        end_before_second: bool = false,

        pub fn event(self: *@This(), ev: Event) bool {
            self.n += 1;
            switch (ev) {
                .begin => self.offset_at_begin = self.src.next_offset,
                .match => {
                    self.matches += 1;
                    if (self.matches == 1) self.offset_at_first = self.src.next_offset;
                },
                .end => if (self.matches < 2) {
                    self.end_before_second = true;
                },
                else => {},
            }
            return true;
        }
    };
    var watch = Watch{ .src = &src };
    var finder = try Finder.init("M", .{});
    const result = try searchSource(Watch, testing.allocator, &watch, &src.interface, "stream", &finder, .{
        .buffer_size = 2,
        .max_line_len = 64,
        .binary = .none,
        .encoding = .none,
    });
    try testing.expectEqual(Outcome.complete, result.outcome);
    try testing.expectEqual(@as(usize, 0), watch.offset_at_begin);
    try testing.expectEqual(@as(usize, 2), watch.offset_at_first);
    try testing.expectEqual(@as(u32, 2), watch.matches);
    try testing.expectEqual(@as(u32, 5), watch.n);
    try testing.expect(!watch.end_before_second);
}

const Quiet = struct {
    pub fn event(_: *@This(), _: Event) bool {
        return true;
    }
};

fn badRead(_: *anyopaque, _: []u8) error{BrokenStream}!usize {
    return error.BrokenStream;
}

const CapLog = struct {
    buf: [160]u8 = undefined,
    len: usize = 0,

    fn write(ctx: ?*anyopaque, message: []const u8) void {
        const self: *@This() = @ptrCast(@alignCast(ctx.?));
        const n = @min(message.len, self.buf.len);
        @memcpy(self.buf[0..n], message[0..n]);
        self.len = n;
    }
};

fn driveCapped(finder: *Finder, hay: []const u8, source_cap: ?u64, request_cap: ?u64) !struct {
    result: Result,
    rest: usize,
    closed: u32,
} {
    var ctx = CountedRead{ .rest = hay };
    var sink = Quiet{};
    const result = try drive(Quiet, testing.allocator, &sink, finder, .{
        .max_source_bytes = source_cap,
        .max_request_bytes = request_cap,
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 64,
        .close_input = CountedRead.close,
        .close_ctx = &ctx,
    }, "", CountedRead.read, &ctx);
    return .{ .result = result, .rest = ctx.rest.len, .closed = ctx.closed };
}

test "来源字节上限和请求字节上限都会停" {
    const hay = "MATCH\nMATCH\nMORE\n";
    var finder = try Finder.init("MATCH", .{});
    const source = try driveCapped(&finder, hay, 6, null);
    try testing.expectEqual(@as(u64, 6), source.result.bytes_read);
    try testing.expect(source.rest > 0);
    try testing.expectEqual(@as(u32, 1), source.closed);
    try testing.expectEqual(sink_mod.LimitHit.max_bytes, source.result.limit_hit);
    try testing.expect(source.result.partial);

    const request = try driveCapped(&finder, hay, null, 6);
    try testing.expectEqual(@as(u64, 6), request.result.bytes_read);
    try testing.expect(request.rest > 0);
    try testing.expectEqual(sink_mod.LimitHit.max_bytes, request.result.limit_hit);
    try testing.expectEqual(@as(u32, 1), request.closed);

    const request_wins = try driveCapped(&finder, hay, 100, 6);
    try testing.expectEqual(@as(u64, 6), request_wins.result.bytes_read);
    const source_wins = try driveCapped(&finder, hay, 6, 100);
    try testing.expectEqual(@as(u64, 6), source_wins.result.bytes_read);

    const open = try driveCapped(&finder, hay, null, null);
    try testing.expectEqual(@as(u64, hay.len), open.result.bytes_read);
    try testing.expectEqual(@as(usize, 0), open.rest);
    try testing.expectEqual(sink_mod.LimitHit.none, open.result.limit_hit);
    try testing.expect(!open.result.partial);
    try testing.expectEqual(@as(u32, 0), open.closed);
}

const DeadlineGate = struct {
    rest: []const u8,
    reads: usize = 0,
    matches: u32 = 0,
    blocked: bool = false,

    fn read(raw: *anyopaque, dest: []u8) ReadError!usize {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.reads += 1;
        if (self.reads > 1) {
            self.blocked = true;
            return 0;
        }
        const n = @min(dest.len, @min(self.rest.len, 12));
        @memcpy(dest[0..n], self.rest[0..n]);
        self.rest = self.rest[n..];
        return n;
    }

    fn now(raw: ?*anyopaque) i128 {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        if (self.matches == 0) return 0;
        return 1_000_000;
    }

    pub fn matched(self: *@This(), _: Line) bool {
        self.matches += 1;
        return true;
    }
};

test "截止时间在匹配循环中生效" {
    var gate = DeadlineGate{ .rest = "MATCH\nMATCH\nTAIL\n" };
    var finder = try Finder.init("MATCH", .{});
    const result = try drive(DeadlineGate, testing.allocator, &gate, &finder, .{
        .binary = .none,
        .buffer_size = 64,
        .max_line_len = 64,
        .time_budget_ns = 1,
        .clock = DeadlineGate.now,
        .clock_ctx = &gate,
    }, "", DeadlineGate.read, &gate);
    try testing.expectEqual(@as(usize, 1), gate.reads);
    try testing.expect(!gate.blocked);
    try testing.expectEqual(@as(u32, 1), gate.matches);
    try testing.expectEqual(sink_mod.LimitHit.deadline, result.limit_hit);
    try testing.expect(result.partial);
    try testing.expectEqual(@as(u64, 1), result.matched_lines);
}

const CancelGate = struct {
    rest: []const u8,
    reads: usize = 0,
    matches: u32 = 0,
    closed: u32 = 0,
    flag: std.atomic.Value(bool) = .init(false),

    fn read(raw: *anyopaque, dest: []u8) ReadError!usize {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.reads += 1;
        if (self.reads > 1) return 0;
        const n = @min(dest.len, @min(self.rest.len, 12));
        @memcpy(dest[0..n], self.rest[0..n]);
        self.rest = self.rest[n..];
        return n;
    }

    fn close(raw: ?*anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        self.closed += 1;
    }

    pub fn matched(self: *@This(), _: Line) bool {
        self.matches += 1;
        self.flag.store(true, .release);
        return true;
    }
};

test "取消令牌关闭上游" {
    var gate = CancelGate{ .rest = "MATCH\nMATCH\nTAIL\n" };
    var finder = try Finder.init("MATCH", .{});
    const result = try drive(CancelGate, testing.allocator, &gate, &finder, .{
        .binary = .none,
        .buffer_size = 64,
        .max_line_len = 64,
        .cancel = &gate.flag,
        .close_input = CancelGate.close,
        .close_ctx = &gate,
    }, "", CancelGate.read, &gate);
    try testing.expectEqual(@as(u32, 1), gate.matches);
    try testing.expectEqual(@as(usize, 1), gate.reads);
    try testing.expectEqual(@as(u32, 1), gate.closed);
    try testing.expectEqual(sink_mod.LimitHit.cancelled, result.limit_hit);
    try testing.expect(result.partial);
}

const Page = struct {
    lines: std.ArrayList([]u8) = .empty,
    cursor: ?u64 = null,
    limit: sink_mod.LimitHit = .none,
    partial: bool = false,

    fn deinit(self: *Page) void {
        for (self.lines.items) |line| testing.allocator.free(line);
        self.lines.deinit(testing.allocator);
    }

    pub fn event(self: *Page, ev: Event) bool {
        switch (ev) {
            .match => |line| {
                const copy = testing.allocator.dupe(u8, line.bytes) catch unreachable;
                self.lines.append(testing.allocator, copy) catch unreachable;
            },
            .end => |end| {
                self.cursor = end.resume_at;
                self.limit = end.limit_hit;
                self.partial = end.partial;
            },
            else => {},
        }
        return true;
    }
};

test "最大结果数带继续位置" {
    const hay = "aa MATCH\nbb MATCH\ncc MATCH\n";
    var finder = try Finder.init("MATCH", .{});
    var first = Page{};
    defer first.deinit();
    const opened = try searchSourceSlice(Page, &first, "page", hay, &finder, .{
        .max_results = 1,
        .binary = .none,
    });
    try testing.expectEqual(sink_mod.LimitHit.max_results, opened.limit_hit);
    try testing.expectEqual(sink_mod.LimitHit.max_results, first.limit);
    try testing.expect(first.partial);
    try testing.expectEqual(@as(usize, 1), first.lines.items.len);
    try testing.expectEqualStrings("aa MATCH", first.lines.items[0]);
    const cursor = first.cursor orelse return error.TestExpectedEqual;
    try testing.expectEqual(cursor, opened.resume_at.?);

    var second = Page{};
    defer second.deinit();
    const continued = try searchSourceSlice(Page, &second, "page", hay, &finder, .{
        .resume_from = cursor,
        .binary = .none,
    });
    try testing.expectEqual(sink_mod.LimitHit.none, continued.limit_hit);
    try testing.expect(!continued.partial);
    try testing.expectEqual(@as(usize, 2), second.lines.items.len);
    try testing.expectEqualStrings("bb MATCH", second.lines.items[0]);
    try testing.expectEqualStrings("cc MATCH", second.lines.items[1]);
}

const OutCount = struct {
    matches: u32 = 0,
    contexts: u32 = 0,

    pub fn event(self: *OutCount, ev: Event) bool {
        switch (ev) {
            .match => self.matches += 1,
            .context => self.contexts += 1,
            else => {},
        }
        return true;
    }
};

test "输出字节上限停止再产生行事件" {
    var finder = try Finder.init("MATCH", .{});
    var lines = OutCount{};
    _ = try searchSourceSlice(OutCount, &lines, "out", "MATCH\nMATCH\n", &finder, .{
        .max_output_bytes = 5,
        .binary = .none,
    });
    try testing.expectEqual(@as(u32, 1), lines.matches);
    try testing.expectEqual(@as(u32, 0), lines.contexts);

    var around = OutCount{};
    _ = try searchSourceSlice(OutCount, &around, "ctx", "ab\nMATCH\n", &finder, .{
        .max_output_bytes = 2,
        .before = 1,
        .binary = .none,
    });
    try testing.expectEqual(@as(u32, 1), around.contexts);
    try testing.expectEqual(@as(u32, 0), around.matches);
}

const QueueSink = struct {
    called: bool = false,
    live: u32 = 0,
    max_live: u32 = 0,

    pub fn matched(self: *QueueSink, _: Line) bool {
        self.called = true;
        self.live += 1;
        self.max_live = @max(self.max_live, self.live);
        self.live -= 1;
        return true;
    }
};

const DecodeFeed = struct {
    left: usize = 8000,
    sent: usize = 0,
    reads: usize = 0,

    fn read(raw: *anyopaque, dest: []u8) ReadError!usize {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.reads += 1;
        var i: usize = 0;
        if (self.sent == 0 and dest.len >= 2) {
            dest[0] = 0xff;
            dest[1] = 0xfe;
            i = 2;
            self.sent = 2;
        }
        while (i < dest.len and self.left > 0) {
            dest[i] = 'a';
            i += 1;
            self.left -= 1;
            self.sent += 1;
        }
        return i;
    }
};

test "三种缓冲都有上限" {
    var finder = try Finder.init("MATCH", .{});
    var reads: usize = 0;
    const CountRead = struct {
        fn read(raw: *anyopaque, dest: []u8) ReadError!usize {
            _ = dest;
            const n: *usize = @ptrCast(@alignCast(raw));
            n.* += 1;
            return 0;
        }
    };
    var sink = Quiet{};
    try testing.expectError(error.BufferLimit, drive(Quiet, testing.allocator, &sink, &finder, .{
        .before = 4,
        .max_line_len = 64,
        .max_before_bytes = 8,
        .binary = .none,
        .buffer_size = 16,
    }, "", CountRead.read, &reads));
    try testing.expectEqual(@as(usize, 0), reads);

    var feed = DecodeFeed{};
    var counted = CountAlloc{ .parent = testing.allocator };
    try testing.expectError(error.DecodeLimit, drive(Quiet, counted.allocator(), &sink, &finder, .{
        .encoding = .auto,
        .max_decode_bytes = 8,
        .buffer_size = 32,
        .max_line_len = 64,
        .binary = .none,
    }, "", DecodeFeed.read, &feed));
    try testing.expect(feed.reads <= 2);
    try testing.expect(feed.left > 0);
    try testing.expect(counted.peak < 8192);

    var queued = QueueSink{};
    try testing.expectError(error.BufferLimit, searchSlice(QueueSink, &queued, "MATCH\n", "q", &finder, .{
        .max_queued_event_bytes = 2,
        .binary = .none,
    }));
    try testing.expect(!queued.called);

    queued = .{};
    _ = try searchSlice(QueueSink, &queued, "MATCH\nMATCH\n", "", &finder, .{
        .max_queued_event_bytes = 8,
        .binary = .none,
    });
    try testing.expect(queued.called);
    try testing.expectEqual(@as(u32, 1), queued.max_live);
}

test "预算来自调用方参数" {
    const hay = "MATCH\nMATCH\nMORE\n";
    var finder = try Finder.init("MATCH", .{});
    const tight = try driveCapped(&finder, hay, 4, null);
    const loose = try driveCapped(&finder, hay, 100, null);
    try testing.expect(tight.result.bytes_read < loose.result.bytes_read);
    try testing.expectEqual(@as(u64, hay.len), loose.result.bytes_read);

    const caller = SearchConfig{ .max_concurrency = 3 };
    try testing.expectEqual(@as(?u32, 3), caller.max_concurrency);
    try testing.expect((SearchConfig{}).max_source_bytes == null);

    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    try testing.expectError(error.BudgetExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .max_source_bytes = SearchConfig.max_source_bytes_hard_cap + 1,
    }));
    try testing.expectError(error.BudgetExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .time_budget_ns = SearchConfig.max_time_budget_ns + 1,
    }));

    var reader = std.Io.Reader.fixed(hay);
    var quiet = Quiet{};
    const served = try searchSource(Quiet, testing.allocator, &quiet, &reader, "tenant", &finder, .{
        .max_source_bytes = 6,
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 64,
    });
    try testing.expectEqual(@as(u64, 6), served.bytes_read);
    try testing.expectEqual(sink_mod.LimitHit.max_bytes, served.limit_hit);
}

test "直接传入的流也受来源大小上限约束" {
    var finder = try Finder.init("MATCH", .{});
    var sink = Quiet{};
    var reader = std.Io.Reader.fixed("MATCH\nMORE MATCH\n");
    const stopped = try searchSource(Quiet, testing.allocator, &sink, &reader, "direct", &finder, .{
        .max_source_bytes = 6,
        .max_request_bytes = SearchConfig.max_request_bytes_hard_cap,
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 64,
        .encoding = .none,
    });
    try testing.expectEqual(@as(u64, 6), stopped.bytes_read);
    try testing.expectEqual(sink_mod.LimitHit.max_bytes, stopped.limit_hit);
    try testing.expect(stopped.partial);
    try testing.expect(stopped.bytes_read < "MATCH\nMORE MATCH\n".len);

    const armed = serviceConfig(.{});
    try testing.expectEqual(SearchConfig.default_max_source_bytes, armed.max_source_bytes.?);
    try testing.expectEqual(SearchConfig.default_max_request_bytes, armed.max_request_bytes.?);
    try testing.expect(armed.max_source_bytes.? <= SearchConfig.max_source_bytes_hard_cap);
    try testing.expectEqual(SearchConfig.default_time_budget_ns, armed.time_budget_ns.?);
    try testing.expectEqual(BinaryPolicy.quit, (SearchConfig{}).binary);

    const total: usize = @intCast(SearchConfig.default_max_source_bytes + 32);
    const big = try testing.allocator.alloc(u8, total);
    defer testing.allocator.free(big);
    @memset(big, 'a');
    var at: usize = 15;
    while (at < big.len) : (at += 16) big[at] = '\n';
    @memcpy(big[0..5], "MATCH");
    var wide = std.Io.Reader.fixed(big);
    const capped = try searchSource(Quiet, testing.allocator, &sink, &wide, "direct-default", &finder, .{
        .binary = .none,
        .buffer_size = 64 * 1024,
        .max_line_len = 64,
        .encoding = .none,
    });
    try testing.expectEqual(SearchConfig.default_max_source_bytes, capped.bytes_read);
    try testing.expectEqual(sink_mod.LimitHit.max_bytes, capped.limit_hit);
    try testing.expect(capped.bytes_read < big.len);
}

test "默认构建不映射文件" {
    try testing.expect(!build_options.window_map);
}

test "软错误与有无匹配可区分" {
    var finder = try Finder.init("MATCH", .{});
    var sink = Quiet{};
    const matched = try searchSlice(Quiet, &sink, "MATCH\n", "", &finder, .{ .binary = .none });
    try testing.expect(matched.soft_error == null);
    try testing.expect(matched.matched_lines > 0);

    const missed = try searchSlice(Quiet, &sink, "nope\n", "", &finder, .{ .binary = .none });
    try testing.expect(missed.soft_error == null);
    try testing.expectEqual(@as(u64, 0), missed.matched_lines);
    try testing.expectEqual(Outcome.complete, missed.outcome);

    var raw: u8 = 0;
    const soft = try drive(Quiet, testing.allocator, &sink, &finder, .{
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 32,
    }, "src", badRead, &raw);
    try testing.expectEqual(sink_mod.SoftError.read_failed, soft.soft_error.?);
    try testing.expect(soft.soft_error != missed.soft_error);
    try testing.expectEqual(@as(u64, 0), soft.matched_lines);

    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    try testing.expectError(error.ContextLinesExceeded, searchSlice(Rec, &rec, "M\n", "", &finder, .{
        .context = SearchConfig.context_lines_hard_cap + 1,
    }));
}

test "返回的错误不含路径" {
    const secret = "/var/lib/secret/path.txt";
    var log = CapLog{};
    var finder = try Finder.init("MATCH", .{});
    var sink = Quiet{};
    try testing.expectError(error.BufferLimit, searchSlice(Quiet, &sink, "MATCH\n", secret, &finder, .{
        .max_queued_event_bytes = 1,
        .binary = .none,
        .log = CapLog.write,
        .log_ctx = &log,
    }));
    try testing.expect(std.mem.indexOf(u8, log.buf[0..log.len], secret) != null);
    try testing.expect(std.mem.indexOf(u8, @errorName(error.BufferLimit), secret) == null);

    log.len = 0;
    var raw: u8 = 0;
    const soft = try drive(Quiet, testing.allocator, &sink, &finder, .{
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 32,
        .log = CapLog.write,
        .log_ctx = &log,
    }, secret, badRead, &raw);
    try testing.expectEqual(sink_mod.SoftError.read_failed, soft.soft_error.?);
    try testing.expect(std.mem.indexOf(u8, log.buf[0..log.len], secret) != null);
    try testing.expect(std.mem.indexOf(u8, @tagName(soft.soft_error.?), "/") == null);
}

test "core 不读取环境变量" {
    var finder = try Finder.init("MATCH", .{});
    var sink = Quiet{};
    const open = try searchSlice(Quiet, &sink, "MATCH\n", "", &finder, .{});
    try testing.expectEqual(Outcome.complete, open.outcome);
    try testing.expectEqual(sink_mod.LimitHit.none, open.limit_hit);
    try testing.expectEqual(@as(u64, 1), open.matched_lines);
    const cfg = SearchConfig{ .max_concurrency = 2 };
    try testing.expectEqual(@as(?u32, 2), cfg.max_concurrency);
    try testing.expect(cfg.max_source_bytes == null);
    try testing.expect(cfg.time_budget_ns == null);
}

const ExistsGate = struct {
    rest: []const u8,
    reads: usize = 0,
    matches: u32 = 0,
    closed: u32 = 0,

    fn read(raw: *anyopaque, dest: []u8) ReadError!usize {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.reads += 1;
        if (self.reads > 1) return 0;
        const n = @min(dest.len, @min(self.rest.len, 6));
        @memcpy(dest[0..n], self.rest[0..n]);
        self.rest = self.rest[n..];
        return n;
    }

    fn close(raw: ?*anyopaque) void {
        const self: *@This() = @ptrCast(@alignCast(raw.?));
        self.closed += 1;
    }

    pub fn matched(self: *@This(), _: Line) bool {
        self.matches += 1;
        return true;
    }
};

test "存在性查询在第一条匹配后停止" {
    var gate = ExistsGate{ .rest = "MATCH\nMORE MATCH\n" };
    var finder = try Finder.init("MATCH", .{});
    const result = try drive(ExistsGate, testing.allocator, &gate, &finder, .{
        .exists = true,
        .binary = .none,
        .buffer_size = 32,
        .max_line_len = 64,
        .close_input = ExistsGate.close,
        .close_ctx = &gate,
    }, "", ExistsGate.read, &gate);
    try testing.expectEqual(@as(u32, 1), gate.matches);
    try testing.expectEqual(@as(usize, 1), gate.reads);
    try testing.expectEqual(@as(u32, 1), gate.closed);
    try testing.expectEqual(@as(u64, 1), result.matched_lines);
    try testing.expectEqual(sink_mod.LimitHit.none, result.limit_hit);
}

test "limit_hit 覆盖每种停止原因" {
    var seen: [@typeInfo(sink_mod.LimitHit).@"enum".field_names.len]bool = @splat(false);
    var finder = try Finder.init("MATCH", .{});
    var sink = Quiet{};

    const plain = try searchSlice(Quiet, &sink, "MATCH\n", "", &finder, .{ .binary = .none });
    seen[@backingInt(plain.limit_hit)] = true;

    const bytes = try driveCapped(&finder, "MATCH\nMATCH\nMORE\n", 6, null);
    seen[@backingInt(bytes.result.limit_hit)] = true;

    var deadline = DeadlineGate{ .rest = "MATCH\nMATCH\nTAIL\n" };
    const timed = try drive(DeadlineGate, testing.allocator, &deadline, &finder, .{
        .binary = .none,
        .buffer_size = 64,
        .max_line_len = 64,
        .time_budget_ns = 1,
        .clock = DeadlineGate.now,
        .clock_ctx = &deadline,
    }, "", DeadlineGate.read, &deadline);
    seen[@backingInt(timed.limit_hit)] = true;

    var cancel = CancelGate{ .rest = "MATCH\nMATCH\nTAIL\n" };
    const stopped = try drive(CancelGate, testing.allocator, &cancel, &finder, .{
        .binary = .none,
        .buffer_size = 64,
        .max_line_len = 64,
        .cancel = &cancel.flag,
        .close_input = CancelGate.close,
        .close_ctx = &cancel,
    }, "", CancelGate.read, &cancel);
    seen[@backingInt(stopped.limit_hit)] = true;

    var page = Page{};
    defer page.deinit();
    const capped = try searchSourceSlice(Page, &page, "p", "MATCH\nMATCH\n", &finder, .{
        .max_results = 1,
        .binary = .none,
    });
    seen[@backingInt(capped.limit_hit)] = true;

    var raw: u8 = 0;
    const inflated = try drive(Quiet, testing.allocator, &sink, &finder, .{
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 32,
        .decompressed_bytes = 8,
        .max_decompressed_bytes = 4,
    }, "", badRead, &raw);
    seen[@backingInt(inflated.limit_hit)] = true;

    for (std.enums.values(sink_mod.LimitHit)) |reason| {
        try testing.expect(seen[@backingInt(reason)]);
    }
}

test "未扫完的计数带 partial" {
    var finder = try Finder.init("MATCH", .{});
    var watch = Page{};
    defer watch.deinit();
    var reader = std.Io.Reader.fixed("MATCH\nMATCH\nMORE\n");
    const stopped = try searchSource(Page, testing.allocator, &watch, &reader, "count", &finder, .{
        .max_source_bytes = 6,
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 64,
    });
    try testing.expect(stopped.partial);
    try testing.expect(watch.partial);
    try testing.expect(stopped.matched_lines < 2);
    try testing.expectEqual(stopped.partial, watch.partial);

    var full_watch = Page{};
    defer full_watch.deinit();
    var full = std.Io.Reader.fixed("MATCH\nMATCH\n");
    const done = try searchSource(Page, testing.allocator, &full_watch, &full, "count", &finder, .{
        .binary = .none,
        .buffer_size = 8,
        .max_line_len = 64,
        .max_source_bytes = SearchConfig.default_max_source_bytes,
        .max_request_bytes = SearchConfig.default_max_request_bytes,
    });
    try testing.expect(!done.partial);
    try testing.expect(!full_watch.partial);
    try testing.expectEqual(@as(u64, 2), done.matched_lines);
}

test "匹配次数和匹配行数不同" {
    var bag = Bag{};
    defer bag.deinit();
    const result = try searchId(&bag, "g03", "MATCH MATCH\nMATCH\n", "MATCH", .{ .binary = .none });
    try testing.expectEqual(@as(u64, 2), result.matched_lines);
    try testing.expectEqual(@as(u64, 3), result.matches);
    try testing.expectEqual(@as(u64, 2), bag.find(.end).matched_lines);
    try testing.expectEqual(@as(u64, 3), bag.find(.end).match_count);
}

test "无匹配来源列表在第一条命中处停止" {
    const Watch = struct {
        matches: u32 = 0,
        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) self.matches += 1;
            return true;
        }
    };
    var scratch: [32]u8 = undefined;
    const hay = "MATCH\nMORE\n";
    var src = std.testing.Reader.init(&scratch, &.{.{ .buffer = hay }});
    src.artificial_limit = .limited(6);
    var watch = Watch{};
    var finder = try Finder.init("MATCH", .{});
    var closed = std.atomic.Value(bool).init(false);
    const result = try searchSource(Watch, testing.allocator, &watch, &src.interface, "miss-list", &finder, .{
        .files_without_match = true,
        .buffer_size = 6,
        .max_line_len = 64,
        .binary = .none,
        .encoding = .none,
        .close_input = struct {
            fn close(ctx: ?*anyopaque) void {
                const flag: *std.atomic.Value(bool) = @ptrCast(@alignCast(ctx.?));
                flag.store(true, .release);
            }
        }.close,
        .close_ctx = &closed,
    });
    try testing.expectEqual(@as(u32, 0), watch.matches);
    try testing.expectEqual(@as(u64, 1), result.matched_lines);
    try testing.expect(closed.load(.acquire));
    try testing.expect(src.next_offset < hay.len);

    var bag = Bag{};
    defer bag.deinit();
    const missed = try searchId(&bag, "none", "nope\n", "ZZ", .{ .files_without_match = true, .binary = .none });
    try testing.expectEqual(@as(u64, 0), missed.matched_lines);
    try testing.expectEqual(@as(u64, 0), bag.find(.end).matched_lines);
    try testing.expectEqual(@as(u64, 0), bag.find(.end).match_count);
    try testing.expectEqual(@as(usize, 0), bag.kindCount(.match));
}

test "零命中来源的 end 仍有计数" {
    var bag = Bag{};
    defer bag.deinit();
    const result = try searchId(&bag, "zero", "nothing\n", "MATCH", .{ .binary = .none });
    try testing.expectEqual(@as(u64, 0), result.matched_lines);
    try testing.expectEqual(@as(u64, 0), result.matches);
    const end = bag.find(.end);
    try testing.expectEqual(@as(u64, 0), end.matched_lines);
    try testing.expectEqual(@as(u64, 0), end.match_count);
    try testing.expectEqualStrings("zero", end.id);
}

test "计数：单文件、多文件、零次和二进制" {
    var one = Bag{};
    defer one.deinit();
    const single = try searchId(&one, "one", "MATCH\nno\nMATCH MATCH\n", "MATCH", .{ .binary = .none });
    try testing.expectEqual(@as(u64, 2), single.matched_lines);
    try testing.expectEqual(@as(u64, 3), single.matches);
    try testing.expectEqual(@as(u64, 2), one.find(.end).matched_lines);
    try testing.expectEqual(@as(u64, 3), one.find(.end).match_count);

    var multi = Bag{};
    defer multi.deinit();
    _ = try searchId(&multi, "a.txt", "MATCH\n", "MATCH", .{ .binary = .none });
    const a_end = multi.find(.end);
    try testing.expectEqual(@as(u64, 1), a_end.matched_lines);
    try testing.expectEqualStrings("a.txt", a_end.id);
    multi.reset();
    _ = try searchId(&multi, "b.txt", "no\n", "MATCH", .{ .binary = .none });
    try testing.expectEqual(@as(u64, 0), multi.find(.end).matched_lines);
    try testing.expectEqualStrings("b.txt", multi.find(.end).id);

    var zero = Bag{};
    defer zero.deinit();
    _ = try searchId(&zero, "t.txt", "no\n", "MATCH", .{ .binary = .none });
    try testing.expectEqual(@as(u64, 0), zero.find(.end).match_count);

    var bin = Bag{};
    defer bin.deinit();
    const binary = try searchId(&bin, "bin", "MATCH\na\x00\nMATCH2\n", "MATCH", .{ .binary = .report });
    try testing.expectEqual(@as(u64, 2), binary.matched_lines);
    try testing.expect(binary.matches >= 2);
    try testing.expectEqual(@as(u64, 2), bin.find(.end).matched_lines);
}

test "计数：max_count 的 after 窗口里抬成匹配的行也算" {
    const Nop = struct {
        pub fn matched(_: *@This(), _: Line) bool {
            return true;
        }
    };
    var nop = Nop{};
    var finder = try Finder.init("MATCH", .{});
    const result = try searchSlice(Nop, &nop, "a\nb\nMATCH\nc\nd\ne\nMATCH2\nf\n", "", &finder, .{
        .after = 4,
        .max_count = 1,
        .line_numbers = true,
        .binary = .none,
    });
    try testing.expectEqual(@as(u64, 2), result.matched_lines);
}

test "汇总字段齐全且未结束时没有 summary" {
    const Clock = struct {
        now: i128 = 0,
        fn tick(ctx: ?*anyopaque) i128 {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.now += 5;
            return self.now;
        }
    };
    var clock = Clock{};
    var bag = Bag{};
    defer bag.deinit();
    const hay = "MATCH MATCH\nMATCH\n";
    _ = try searchId(&bag, "sum", hay, "MATCH", .{
        .binary = .none,
        .clock = Clock.tick,
        .clock_ctx = &clock,
        .time_budget_ns = SearchConfig.max_time_budget_ns,
    });
    try testing.expectEqual(@as(usize, 1), bag.kindCount(.summary));
    const sum = bag.find(.summary);
    try testing.expect(sum.elapsed >= 5);
    try testing.expectEqual(@as(u64, 1), sum.searches);
    try testing.expectEqual(@as(u64, 1), sum.searches_with_match);
    try testing.expectEqual(@as(u64, hay.len), sum.bytes_searched);
    try testing.expect(sum.bytes_printed > 0);
    try testing.expectEqual(@as(u64, 2), sum.matched_lines);
    try testing.expectEqual(@as(u64, 3), sum.match_count);
    try testing.expectEqual(@as(u64, hay.len), sum.bytes_read_raw);
    try testing.expectEqual(@as(u64, 0), sum.sources_failed);
    try testing.expect(bag.find(.end).kind == .end);

    bag.reset();
    _ = try searchId(&bag, "part", "MATCH\nMATCH\nMORE\n", "MATCH", .{
        .max_source_bytes = 4,
        .binary = .none,
    });
    try testing.expectEqual(@as(usize, 0), bag.kindCount(.summary));
    try testing.expectEqual(@as(usize, 1), bag.kindCount(.end));
}

test "progress 含已扫描字节和匹配数" {
    var bag = Bag{};
    defer bag.deinit();
    _ = try searchId(&bag, "prog", "MATCH\nabcd\nMATCH\n", "MATCH", .{
        .progress_interval = 4,
        .binary = .none,
    });
    try testing.expect(bag.kindCount(.progress) >= 1);
    var saw_bytes = false;
    var saw_matches = false;
    for (bag.items.items) |item| {
        if (item.kind != .progress) continue;
        if (item.bytes_searched >= 4) saw_bytes = true;
        if (item.match_count >= 1) saw_matches = true;
    }
    try testing.expect(saw_bytes);
    try testing.expect(saw_matches);
}

test "回调可以暂停后继续" {
    const Gate = struct {
        hits: u32 = 0,
        ends: u32 = 0,
        begins: u32 = 0,
        pub fn event(self: *@This(), ev: Event) Flow {
            switch (ev) {
                .begin => self.begins += 1,
                .match => {
                    self.hits += 1;
                    if (self.hits == 1) return .pause;
                },
                .end => self.ends += 1,
                else => {},
            }
            return .cont;
        }
    };
    var gate = Gate{};
    var finder = try Finder.init("MATCH", .{});
    const hay = "MATCH\nno\nMATCH\n";
    const first = try searchSourceSlice(Gate, &gate, "pause", hay, &finder, .{ .binary = .none });
    try testing.expect(first.paused);
    try testing.expectEqual(@as(u32, 1), gate.hits);
    try testing.expectEqual(@as(u32, 1), gate.begins);
    try testing.expectEqual(@as(u32, 0), gate.ends);

    const second = try resumeSourceSlice(Gate, &gate, "pause", hay, &finder, .{ .binary = .none }, first);
    try testing.expect(!second.paused);
    try testing.expectEqual(@as(u32, 2), gate.hits);
    try testing.expectEqual(@as(u32, 1), gate.begins);
    try testing.expectEqual(@as(u32, 1), gate.ends);
    try testing.expectEqual(@as(u64, 2), second.matched_lines);
    try testing.expect(second.scanned_all);

    const Stop = struct {
        hits: u32 = 0,
        ends: u32 = 0,
        pub fn event(self: *@This(), ev: Event) Flow {
            switch (ev) {
                .match => {
                    self.hits += 1;
                    return .stop;
                },
                .end => self.ends += 1,
                else => {},
            }
            return .cont;
        }
    };
    var stop = Stop{};
    const stopped = try searchSourceSlice(Stop, &stop, "stop", hay, &finder, .{ .binary = .none });
    try testing.expect(!stopped.paused);
    try testing.expectEqual(@as(u32, 1), stop.hits);
    try testing.expectEqual(@as(u32, 1), stop.ends);
    try testing.expect(!stopped.scanned_all);
}

test "拉式接口取出 begin 到 end" {
    var finder = try Finder.init("MATCH", .{});
    var pull = openSourcePull(testing.allocator, &finder, "pull-1", "a\nMATCH\nb\n", .{
        .before = 1,
        .after = 1,
        .binary = .none,
    });
    defer pull.deinit();
    var saw_begin = false;
    var saw_context = false;
    var saw_match = false;
    var saw_end = false;
    while (try pull.next()) |ev| {
        switch (ev.kind) {
            .begin => {
                saw_begin = true;
                try testing.expectEqualStrings("pull-1", ev.source_id);
            },
            .context => {
                try testing.expect(saw_begin);
                try testing.expect(!saw_end);
                saw_context = true;
            },
            .match => {
                try testing.expect(saw_begin);
                try testing.expectEqualStrings("MATCH", ev.bytes);
                saw_match = true;
            },
            .end => {
                try testing.expect(saw_begin);
                try testing.expect(saw_match);
                saw_end = true;
            },
            else => {},
        }
    }
    try testing.expect(saw_begin);
    try testing.expect(saw_context);
    try testing.expect(saw_match);
    try testing.expect(saw_end);
}

test "实时流空闲时产生心跳" {
    const Src = struct {
        step: u8 = 0,
        now: i128 = 0,
        closed: std.atomic.Value(bool) = .init(false),
        heartbeats: u32 = 0,
        summary_before_heartbeat: bool = false,
        saw_summary: bool = false,
        saw_end: bool = false,

        fn clock(ctx: ?*anyopaque) i128 {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            return self.now;
        }

        fn read(ctx: *anyopaque, dest: []u8) ReadError!usize {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.step += 1;
            switch (self.step) {
                1 => {
                    const data = "idle\n";
                    @memcpy(dest[0..data.len], data);
                    return data.len;
                },
                2 => {
                    self.now = 1_000;
                    return 0;
                },
                3 => {
                    const data = "MATCH\n";
                    @memcpy(dest[0..data.len], data);
                    return data.len;
                },
                else => {
                    self.closed.store(true, .release);
                    return 0;
                },
            }
        }

        pub fn event(self: *@This(), ev: Event) bool {
            switch (ev) {
                .heartbeat => {
                    self.heartbeats += 1;
                    self.summary_before_heartbeat = self.saw_summary;
                },
                .summary => self.saw_summary = true,
                .end => self.saw_end = true,
                else => {},
            }
            return true;
        }
    };
    var src = Src{};
    var finder = try Finder.init("MATCH", .{});
    const cfg = SearchConfig{
        .live = true,
        .idle_timeout_ns = 1_000,
        .live_closed = &src.closed,
        .clock = Src.clock,
        .clock_ctx = &src,
        .time_budget_ns = SearchConfig.max_time_budget_ns,
        .binary = .none,
        .buffer_size = 64,
        .max_line_len = 64,
        .encoding = .none,
        .line_numbers = true,
    };
    var bridge = EventBridge(Src){
        .inner = &src,
        .source_id = "live",
        .config = cfg,
    };
    const result = try drive(EventBridge(Src), testing.allocator, &bridge, &finder, cfg, "live", Src.read, &src);
    try testing.expect(src.heartbeats >= 1);
    try testing.expect(!src.summary_before_heartbeat);
    try testing.expect(src.saw_end);
    try testing.expect(!src.saw_summary);
    try testing.expectEqual(sink_mod.LimitHit.none, result.limit_hit);
    try testing.expect(result.soft_error == null);
    try testing.expectEqual(@as(u64, 1), result.matched_lines);
    emitSummary(Src, &src, "live", cfg, result);
    try testing.expect(src.saw_summary);
}

test "命中一次就写出路径并停止" {
    const Stop = struct {
        id: []const u8 = "",
        hits: u32 = 0,
        pub fn event(self: *@This(), ev: Event) bool {
            switch (ev) {
                .begin => |b| self.id = b.source_id,
                .match => |line| {
                    self.hits += 1;
                    self.id = line.source_id;
                    return false;
                },
                else => {},
            }
            return true;
        }
    };
    var scratch: [32]u8 = undefined;
    const hay = "no\nMATCH\nMATCH\n";
    var src = std.testing.Reader.init(&scratch, &.{.{ .buffer = hay }});
    src.artificial_limit = .limited(9);
    var stop = Stop{};
    var finder = try Finder.init("MATCH", .{});
    const result = try searchSource(Stop, testing.allocator, &stop, &src.interface, "src-1", &finder, .{
        .buffer_size = 9,
        .max_line_len = 64,
        .binary = .none,
        .encoding = .none,
    });
    try testing.expectEqualStrings("src-1", stop.id);
    try testing.expectEqual(@as(u32, 1), stop.hits);
    try testing.expectEqual(@as(u64, 1), result.matched_lines);
    try testing.expect(src.next_offset < hay.len);
}

test "A03 空行模式匹配所有行且超限在构造前拒绝" {
    const Multi = @import("finder/multi.zig").Multi;
    var multi = try Multi.initFromText(testing.allocator, "alpha\r\n\nomega", .{});
    defer multi.deinit();
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const res = try searchSlice(Rec, &rec, "one\ntwo\nthree\n", "", &multi, .{ .line_numbers = true });
    try testing.expectEqual(@as(u64, 3), res.matched_lines);
}

test "B13 有序输入在首条不匹配行处停止并关闭上游" {
    const OrderedSrc = struct {
        reads: usize = 0,
        closed: bool = false,
        matched: u32 = 0,

        fn read(ctx: *anyopaque, dest: []u8) ReadError!usize {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.reads += 1;
            const chunk: []const u8 = switch (self.reads) {
                1 => "2026-01-01 skip\n2026-01-02 MATCH-1\n",
                2 => "2026-01-02 MATCH-2\n2026-01-03 after\n",
                3 => "2026-01-02 MATCH-LATE\n",
                else => "",
            };
            @memcpy(dest[0..chunk.len], chunk);
            return chunk.len;
        }

        fn close(ctx: ?*anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.closed = true;
        }

        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) self.matched += 1;
            return true;
        }
    };

    var src = OrderedSrc{};
    var finder = try Finder.init("2026-01-02", .{});
    const cfg = SearchConfig{
        .stop_on_nonmatch = true,
        .close_input = OrderedSrc.close,
        .close_ctx = &src,
        .buffer_size = 64,
        .max_line_len = 64,
        .binary = .none,
        .encoding = .none,
    };
    var bridge = EventBridge(OrderedSrc){
        .inner = &src,
        .source_id = "ordered",
        .config = cfg,
    };
    const result = try drive(EventBridge(OrderedSrc), testing.allocator, &bridge, &finder, cfg, "ordered", OrderedSrc.read, &src);
    try testing.expectEqual(@as(u64, 2), result.matched_lines);
    try testing.expectEqual(@as(u32, 2), src.matched);
    try testing.expectEqual(@as(usize, 2), src.reads);
    try testing.expect(src.closed);
}

test "E06 全文高亮输出全部行且受输出字节上限约束" {
    const PassSink = struct {
        match_lines: u32 = 0,
        context_lines: u32 = 0,
        breaks: u32 = 0,

        pub fn event(self: *@This(), ev: Event) bool {
            switch (ev) {
                .match => self.match_lines += 1,
                .context => self.context_lines += 1,
                .context_break => self.breaks += 1,
                else => {},
            }
            return true;
        }
    };

    var finder = try Finder.init("HIT", .{});
    const hay = "line1\nHIT-line2\nline3\nHIT-line4\nline5\n";

    var full = PassSink{};
    const res_full = try searchSourceSlice(PassSink, &full, "doc", hay, &finder, .{
        .passthru = true,
        .line_numbers = true,
    });
    try testing.expectEqual(@as(u64, 2), res_full.matched_lines);
    try testing.expectEqual(@as(u32, 2), full.match_lines);
    try testing.expectEqual(@as(u32, 3), full.context_lines);
    try testing.expectEqual(@as(u32, 0), full.breaks);
    try testing.expect(!res_full.partial);

    var capped = PassSink{};
    const res_capped = try searchSourceSlice(PassSink, &capped, "doc", hay, &finder, .{
        .passthru = true,
        .max_output_bytes = 16,
    });
    try testing.expect(res_capped.partial);
    try testing.expect(!res_capped.scanned_all);
    try testing.expectEqual(@as(u32, 1), capped.match_lines);
    try testing.expectEqual(@as(u32, 1), capped.context_lines);
}

test "B14 替换预览不修改输入且区间与替换文本一致" {
    const ReplSink = struct {
        saw_line: bool = false,
        replaced_copy: [64]u8 = undefined,
        replaced_len: usize = 0,
        span_count: usize = 0,
        first_repl: []const u8 = "",
        raw_ref: []const u8 = "",

        pub fn event(self: *@This(), ev: Event) bool {
            switch (ev) {
                .match => |line| {
                    self.saw_line = true;
                    self.raw_ref = line.bytes;
                    self.span_count = line.matches.len;
                    if (line.matches.len > 0) {
                        self.first_repl = line.matches[0].replacement orelse "";
                    }
                    if (line.replaced) |r| {
                        @memcpy(self.replaced_copy[0..r.len], r);
                        self.replaced_len = r.len;
                    }
                },
                else => {},
            }
            return true;
        }
    };

    var input_buf = "hello foo and foo!\n".*;
    var finder = try Finder.init("foo", .{});
    var sink = ReplSink{};
    const res = try searchSourceSlice(ReplSink, &sink, "repl", &input_buf, &finder, .{
        .replacement = "BAR_BAZ",
    });
    try testing.expectEqual(@as(u64, 1), res.matched_lines);
    try testing.expectEqual(@as(u64, 2), res.matches);
    try testing.expect(sink.saw_line);
    try testing.expectEqualStrings("hello foo and foo!\n", &input_buf);
    try testing.expectEqualStrings("hello foo and foo!", sink.raw_ref);
    try testing.expectEqual(@as(usize, 2), sink.span_count);
    try testing.expectEqualStrings("BAR_BAZ", sink.first_repl);
    try testing.expectEqualStrings("hello BAR_BAZ and BAR_BAZ!", sink.replaced_copy[0..sink.replaced_len]);
}

test "B16 正则与 Searcher 联动及替换预览" {
    const Regex = @import("regex.zig").Regex;
    const Collect = struct {
        hits: u32 = 0,
        replaced_buf: [64]u8 = undefined,
        replaced_len: usize = 0,

        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) {
                self.hits += 1;
                if (ev.match.replaced) |r| {
                    @memcpy(self.replaced_buf[0..r.len], r);
                    self.replaced_len = r.len;
                }
            }
            return true;
        }
    };

    var re = try Regex.init(testing.allocator, "ERR_[0-9]+", .{});
    defer re.deinit();

    var sink = Collect{};
    const res = try searchSourceSlice(Collect, &sink, "log", "ok\nfail ERR_502 and ERR_504!\n", &re, .{
        .replacement = "CODE",
    });
    try testing.expectEqual(@as(u64, 1), res.matched_lines);
    try testing.expectEqual(@as(u64, 2), res.matches);
    try testing.expectEqual(@as(u32, 1), sink.hits);
    try testing.expectEqualStrings("fail CODE and CODE!", sink.replaced_buf[0..sink.replaced_len]);
}

test "B17 跨行窗口耗尽后不再读上游" {
    const Regex = @import("regex.zig").Regex;
    const MlStream = struct {
        reads: usize = 0,
        closed: bool = false,
        hits: u32 = 0,

        fn read(ctx: *anyopaque, dest: []u8) ReadError!usize {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.reads += 1;
            const chunk: []const u8 = switch (self.reads) {
                1 => "BEGIN\n1234567890\n",
                2 => "12345678901234567890\n",
                3 => "END\n",
                else => "",
            };
            @memcpy(dest[0..chunk.len], chunk);
            return chunk.len;
        }

        fn close(ctx: ?*anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(ctx.?));
            self.closed = true;
        }

        pub fn event(self: *@This(), ev: Event) bool {
            if (ev == .match) self.hits += 1;
            return true;
        }
    };

    var src = MlStream{};
    var re = try Regex.init(testing.allocator, "\\ABEGIN.*END", .{
        .multiline = true,
        .dot_all = true,
        .max_multiline_window = 24,
    });
    defer re.deinit();

    const cfg = SearchConfig{
        .close_input = MlStream.close,
        .close_ctx = &src,
        .buffer_size = 64,
        .max_line_len = 64,
        .binary = .none,
        .encoding = .none,
    };
    var bridge = EventBridge(MlStream){
        .inner = &src,
        .source_id = "ml",
        .config = cfg,
    };
    const res = try drive(EventBridge(MlStream), testing.allocator, &bridge, &re, cfg, "ml", MlStream.read, &src);
    try testing.expectEqual(@as(u64, 0), res.matched_lines);
    try testing.expectEqual(@as(u32, 0), src.hits);
    try testing.expectEqual(@as(usize, 2), src.reads);
    try testing.expect(src.closed);
}
