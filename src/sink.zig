//! 推式输出。行切片指向 Searcher 的内部缓冲或调用方的 haystack，只在回调返回前有效。
//!
//! Sink 由 `search` 的 comptime 参数 `S` 决定。方法返回 false 表示停止这次搜索。
//! 除了这里列出的可选方法，Searcher 还会在第一次看到 NUL 时调用可选的
//! `pub fn binary(self: *S, offset: u64) bool`：返回 false 表示不要再读后面的数据。
//! 该方法必须是 `pub`，否则 `@hasDecl` 看不见。

const std = @import("std");
const matcher = @import("matcher.zig");

/// 匹配或上下文在行内的区间，相对 `Line.bytes` / `Line.raw`。
/// `u16_start`、`u16_end` 是同一段在有损文本上的 UTF-16 码元，半开，扫描时算好。
pub const Span = struct {
    start: usize,
    end: usize,
    u16_start: usize = 0,
    u16_end: usize = 0,
};

/// 回调对搜索的控制。`bool` 仍然表示继续或停止；服务入口也可以返回这个枚举。
pub const Flow = enum {
    cont,
    pause,
    stop,
};

/// 暂停后接着搜需要的计数。`resumeSourceSlice` 会带上它。
pub const ResumeState = struct {
    matched_lines: u64 = 0,
    matches: u64 = 0,
    bytes_read: u64 = 0,
    bytes_searched: u64 = 0,
    output_bytes: u64 = 0,
    results_out: u64 = 0,
    limit_count: u64 = 0,
    line_number: u64 = 1,
    started_ns: i128 = 0,
    deadline_armed: bool = false,
    skip_begin: bool = false,
};

/// 这次搜索为什么停下。`decompressed_bytes` 先留在这里，解压实现之前不会由扫描自己累计。
pub const LimitHit = enum {
    none,
    max_results,
    max_bytes,
    deadline,
    decompressed_bytes,
    cancelled,
};

/// 单个来源上的软错误。只有这一个标签，里面没有路径，也没有系统调用细节。
pub const SoftError = enum {
    read_failed,
};

/// 一次搜索的结果。`binary_offset` 和 `nul_offset` 都是这次输入里第一次看到 NUL 的绝对偏移。
/// 致命错误走函数的 error。软错误、有匹配、无匹配都是成功返回的结果，靠下面的字段区分。
pub const Result = struct {
    outcome: Outcome = .complete,
    /// 匹配行数。和 `matches` 不是同一个数。
    matched_lines: u64 = 0,
    /// 匹配次数。一行里可以有多次。
    matches: u64 = 0,
    /// 检测到 NUL 时的绝对偏移。没有 NUL 就是 null。
    binary_offset: ?u64 = null,
    /// 与 `binary_offset` 相同。
    nul_offset: ?u64 = null,
    /// 实际读过的字节。目录搜索用它记账，不再为了这个数对每个文件 `fstat`。
    bytes_read: u64 = 0,
    /// 预算或取消让搜索停下时的原因。正常扫完是 `none`。
    limit_hit: LimitHit = .none,
    /// 计数没有把输入扫完。预算或取消在看到结尾之前停下时为真。
    partial: bool = false,
    /// 下次可以从这个可搜索字节偏移接着搜。只在 `max_results` 停下时有值。
    resume_at: ?u64 = null,
    /// 这个来源读失败。搜索调用本身仍然成功返回。
    soft_error: ?SoftError = null,
    /// 回调要求暂停。还没有 end，也没有 summary。
    paused: bool = false,
    /// 输入已经扫完。没扫完时不把 summary 当成最终结果。
    scanned_all: bool = false,
    /// 从开始到这次返回的纳秒。测试时钟也可以驱动它。
    elapsed_ns: u64 = 0,
    /// 已经交给调用方的行字节。
    output_bytes: u64 = 0,
    /// 已经扫过的可搜索字节。
    bytes_searched: u64 = 0,
    /// 暂停后续搜用的计数。没暂停时也是这次结束时的快照。
    resume_state: ResumeState = .{},
};

/// 一个输入的结束原因。
pub const Outcome = enum {
    complete,
    /// Sink 返回 false，或达到 max_count。
    stopped,
    binary_quit,
    binary_matched,
};

/// 这一次来源上的二进制状态。
pub const BinaryStatus = enum {
    /// 没有按二进制处理。没看到 NUL，或者调用方要求按文本处理。
    none,
    /// 看到了 NUL。继续确认有没有匹配，但是不返回行内容。
    detected,
    /// 看到了 NUL。停止读取，后面的内容不再交给调用方。
    suppressed,
};

/// 服务入口上的一行。`bytes`、`text`、`raw`、`matches` 只在本次回调期间有效。
pub const LineEvent = struct {
    /// 调用方分配的来源标识。库不解释它。
    source_id: []const u8,
    /// 从 1 开始。NUL 记录模式是记录号。
    line_number: u64,
    /// 从 1 开始的字节列，按 `bytes` 计。没有匹配时为 null。和 `u16_column` 是两个数。
    column: ?u64 = null,
    /// 按起点排序后，第一个匹配的 UTF-16 列，从 1 开始。没有匹配时为 null。
    u16_column: ?u64 = null,
    /// 这一行起点在可搜索字节流里的绝对偏移。
    absolute_offset: u64,
    bytes: []const u8,
    text: []const u8 = &.{},
    raw: []const u8 = &.{},
    /// 半开字节区间，相对 `bytes`，按起点排序。
    /// 只显示命中片段时用这些区间切 `bytes`。没有单独的片段输出模式。
    /// core 只给出区间，不插入颜色码或标记。
    matches: []const Span = &.{},
    truncated: bool = false,
    /// 去掉分隔符之后的原始内容长度。
    line_len: u64 = 0,
    /// `bytes` 在原始行内容里的起点。
    window_start: u64 = 0,
    binary_status: BinaryStatus = .none,
};

/// 扫描过程中的进度。按调用方给的间隔产生。
pub const Progress = struct {
    source_id: []const u8,
    bytes_searched: u64 = 0,
    /// 到目前为止的匹配次数。
    matches: u64 = 0,
    matched_lines: u64 = 0,
};

/// 实时流空闲超时。不是错误，也不是结束。
pub const Heartbeat = struct {
    source_id: []const u8,
    bytes_searched: u64 = 0,
    matches: u64 = 0,
    matched_lines: u64 = 0,
};

/// 一次请求的汇总。流没结束时不会作为最终结果发出。
pub const Summary = struct {
    source_id: []const u8 = "",
    /// 纳秒。名字与清单字段一致。
    elapsed: u64 = 0,
    searches: u64 = 0,
    searches_with_match: u64 = 0,
    bytes_searched: u64 = 0,
    bytes_printed: u64 = 0,
    matched_lines: u64 = 0,
    matches: u64 = 0,
    bytes_read_raw: u64 = 0,
    sources_failed: u64 = 0,
};

/// 一个来源结束。没有命中时也会产生。
pub const EndEvent = struct {
    source_id: []const u8,
    binary_status: BinaryStatus = .none,
    binary_offset: ?u64 = null,
    matched_lines: u64 = 0,
    /// 匹配次数。零命中也是 0，不会省掉这个字段。
    matches: u64 = 0,
    bytes_read: u64 = 0,
    outcome: Outcome = .complete,
    limit_hit: LimitHit = .none,
    partial: bool = false,
    resume_at: ?u64 = null,
    soft_error: ?SoftError = null,
};

/// 服务入口的事件。每产生一个就回调一次，不把多行攒起来再交。
/// begin、match、context、progress、end、summary 都只带来源标识。
/// 断点仍然是 `context_break`。实时流的空闲是 `heartbeat`。
pub const Event = union(enum) {
    begin: struct { source_id: []const u8 },
    match: LineEvent,
    context: LineEvent,
    /// 上下文不连续。不是一段分隔文本。
    context_break: struct { source_id: []const u8 },
    progress: Progress,
    heartbeat: Heartbeat,
    end: EndEvent,
    summary: Summary,
};

/// 交给 Sink 的一行。
pub const Line = struct {
    /// 搜索用的行字节。不含记录分隔符；LF 模式下再去掉行尾的一个 `\r`。
    /// 只在本次回调期间有效。
    bytes: []const u8,
    /// 非法 UTF-8 换成 U+FFFD 之后的文本。合法时与 `bytes` 同一段。
    /// 只在本次回调期间有效。库不把这些字节做成 base64。
    text: []const u8 = &.{},
    /// 这一行的原始字节，字节偏移相对它。通常与 `bytes` 相同。
    /// 只在本次回调期间有效。
    raw: []const u8 = &.{},
    /// 该行第一个字节在可搜索字节流里的绝对偏移。转码之后从转码结果计。
    offset: u64,
    /// 从 1 开始。未打开行号时为 null。NUL 记录模式按记录计数。
    number: ?u64,
    /// 相对 `raw`。普通上下文行和反选命中行没有匹配区间。
    /// 反选时，被当作上下文印出的模式行会带上区间，供列号使用。
    /// 超长行时 `bytes` 是窗口，区间相对窗口。
    match: ?Span,
    /// 匹配起点的 UTF-16 列，从 1 开始。没有匹配时为 null。
    /// 这是发现这一行的那次匹配，和按起点排序后的字节列分开。
    u16_column: ?u64 = null,
    /// 这一行的全部匹配，相对 `bytes`，按起点排序。只在本次回调期间有效。
    /// 只显示命中片段时用这些区间。core 不另做片段输出，也不插入颜色或标记。
    matches: []const Span = &.{},
    /// 从 1 开始的字节列，按 `bytes` 计，取 `matches` 里起点最小的那次。没有匹配时为 null。
    column: ?u64 = null,
    /// 交出行时已经知道的二进制状态。
    binary_status: BinaryStatus = .none,
    /// 原始行长于单行上限时为真。`bytes` 只是窗口。
    truncated: bool = false,
    /// 去掉分隔符（以及 LF 模式下行尾一个 CR）之后的原始内容长度。
    line_len: u64 = 0,
    /// `bytes` 在原始行内容里的起点。
    window_start: u64 = 0,
};

/// 运行时多态的 Sink。本身满足 comptime Sink 的方法形状，可以直接传给 `search`。
pub const AnySink = struct {
    ctx: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        begin: *const fn (*anyopaque, []const u8) bool,
        matched: *const fn (*anyopaque, Line) bool,
        context: *const fn (*anyopaque, Line) bool,
        context_break: *const fn (*anyopaque) bool,
        binary: *const fn (*anyopaque, u64) bool,
        finish: *const fn (*anyopaque, Result) bool,
    };

    pub fn begin(self: *AnySink, path: []const u8) bool {
        return self.vtable.begin(self.ctx, path);
    }

    pub fn matched(self: *AnySink, line: Line) bool {
        return self.vtable.matched(self.ctx, line);
    }

    pub fn context(self: *AnySink, line: Line) bool {
        return self.vtable.context(self.ctx, line);
    }

    pub fn contextBreak(self: *AnySink) bool {
        return self.vtable.context_break(self.ctx);
    }

    pub fn binary(self: *AnySink, offset: u64) bool {
        return self.vtable.binary(self.ctx, offset);
    }

    pub fn finish(self: *AnySink, result: Result) bool {
        return self.vtable.finish(self.ctx, result);
    }
};

/// 为类型 `S` 生成虚表。缺的方法保持继续搜索。
pub fn anyVtable(comptime S: type) AnySink.VTable {
    return .{
        .begin = if (@hasDecl(S, "begin")) &adapt(S, "begin") else &noopPath,
        .matched = if (@hasDecl(S, "matched")) &adapt(S, "matched") else &noopLine,
        .context = if (@hasDecl(S, "context")) &adapt(S, "context") else &noopLine,
        .context_break = if (@hasDecl(S, "contextBreak")) &adapt(S, "contextBreak") else &noopCtx,
        .binary = if (@hasDecl(S, "binary")) &adapt(S, "binary") else &noopBinary,
        .finish = if (@hasDecl(S, "finish")) &adapt(S, "finish") else &noopFinish,
    };
}

fn castSink(comptime S: type, ctx: *anyopaque) *S {
    return @ptrCast(@alignCast(ctx));
}

/// 把 `S` 的方法收成虚表函数。方法本身是 comptime 名字，参数个数在这里定死。
fn adapt(comptime S: type, comptime name: []const u8) AdaptFn(S, name) {
    const types = @typeInfo(@TypeOf(@field(S, name))).@"fn".param_types;
    if (types.len == 1) {
        return struct {
            fn f(ctx: *anyopaque) bool {
                return @call(.auto, @field(S, name), .{castSink(S, ctx)});
            }
        }.f;
    }
    const Arg = types[1].?;
    return struct {
        fn f(ctx: *anyopaque, arg: Arg) bool {
            return @call(.auto, @field(S, name), .{ castSink(S, ctx), arg });
        }
    }.f;
}

fn AdaptFn(comptime S: type, comptime name: []const u8) type {
    const types = @typeInfo(@TypeOf(@field(S, name))).@"fn".param_types;
    if (types.len == 1) return fn (*anyopaque) bool;
    return fn (*anyopaque, types[1].?) bool;
}

fn noopPath(_: *anyopaque, _: []const u8) bool {
    return true;
}
fn noopLine(_: *anyopaque, _: Line) bool {
    return true;
}
fn noopCtx(_: *anyopaque) bool {
    return true;
}
fn noopBinary(_: *anyopaque, _: u64) bool {
    return true;
}
fn noopFinish(_: *anyopaque, _: Result) bool {
    return true;
}

/// 单输入、无上下文的拉式迭代器。`M` 是匹配器指针，例如 `*Finder`。
/// `Line.bytes` 指向 `haystack`，一直有效到 `haystack` 失效；下一次 `next` 不使上一次失效。
pub fn SliceIter(comptime M: type) type {
    return struct {
        matcher: M,
        haystack: []const u8,
        pos: usize = 0,
        mode: matcher.MatchMode = .earliest,
        line_numbers: bool = false,
        numbered_at: usize = 0,
        line_no: u64 = 1,
        done: bool = false,

        const Iter = @This();

        pub fn next(self: *Iter) ?Line {
            if (self.done or self.pos > self.haystack.len) return null;
            const found = self.matcher.find(self.haystack, self.pos, self.mode) orelse {
                self.done = true;
                return null;
            };
            const start = lineStart(self.haystack, found.start);
            if (start == self.haystack.len) {
                self.done = true;
                return null;
            }
            const end = lineEnd(self.haystack, @max(found.end, start));
            if (end == start) {
                self.done = true;
                return null;
            }
            const content_end = withoutNewlineEnd(self.haystack, start, end);
            var number: ?u64 = null;
            if (self.line_numbers) {
                const memchr = @import("finder/memchr.zig");
                self.line_no += memchr.count(memchr.native_width, self.haystack, self.numbered_at, start, '\n');
                self.numbered_at = start;
                number = self.line_no;
            }
            self.pos = end;
            const mstart = found.start - start;
            const mend = @min(found.end, content_end) - start;
            const raw = self.haystack[start..content_end];
            const units = @import("encoding.zig").utf16Span(raw, mstart, mend);
            return .{
                .bytes = raw,
                .text = raw,
                .raw = raw,
                .offset = start,
                .number = number,
                .match = .{
                    .start = mstart,
                    .end = mend,
                    .u16_start = units.start,
                    .u16_end = units.end,
                },
                .u16_column = units.start + 1,
                .line_len = content_end - start,
            };
        }
    };
}

fn lineStart(haystack: []const u8, pos: usize) usize {
    const memchr = @import("finder/memchr.zig");
    const upto = @min(pos, haystack.len);
    if (memchr.findLast(memchr.native_width, haystack, 0, upto, '\n')) |i| return i + 1;
    return 0;
}

fn lineEnd(haystack: []const u8, from: usize) usize {
    const memchr = @import("finder/memchr.zig");
    if (from >= haystack.len) return haystack.len;
    if (memchr.find(memchr.native_width, haystack, from, '\n')) |i| return i + 1;
    return haystack.len;
}

fn withoutNewlineEnd(haystack: []const u8, start: usize, end: usize) usize {
    var cut = end;
    if (cut > start and haystack[cut - 1] == '\n') cut -= 1;
    if (cut > start and haystack[cut - 1] == '\r') cut -= 1;
    return cut;
}

const testing = std.testing;

test "AnySink 缺省方法继续搜索" {
    const Bare = struct {};
    const vt = anyVtable(Bare);
    var bare: Bare = .{};
    var any: AnySink = .{ .ctx = @ptrCast(&bare), .vtable = &vt };
    try testing.expect(any.begin(""));
    try testing.expect(any.contextBreak());
    try testing.expect(any.binary(0));
    try testing.expect(any.finish(.{}));
}

test "AnySink 转发到具体类型" {
    const Rec = struct {
        hits: u32 = 0,
        path: []const u8 = "",
        pub fn begin(self: *@This(), path: []const u8) bool {
            self.path = path;
            return true;
        }
        pub fn matched(self: *@This(), line: Line) bool {
            self.hits += @intCast(line.bytes.len);
            return false;
        }
    };
    const vt = anyVtable(Rec);
    var rec: Rec = .{};
    var any: AnySink = .{ .ctx = @ptrCast(&rec), .vtable = &vt };
    try testing.expect(any.begin("a.txt"));
    try testing.expect(!any.matched(.{
        .bytes = "ab",
        .offset = 0,
        .number = null,
        .match = null,
    }));
    try testing.expectEqualStrings("a.txt", rec.path);
    try testing.expectEqual(@as(u32, 2), rec.hits);
}
