//! 推式输出。行切片指向 Searcher 的内部缓冲或调用方的 haystack，只在回调返回前有效。
//!
//! Sink 由 `search` 的 comptime 参数 `S` 决定。方法返回 false 表示停止这次搜索。
//! 除了这里列出的可选方法，Searcher 还会在第一次看到 NUL 时调用可选的
//! `pub fn binary(self: *S, offset: u64) bool`：返回 false 表示不要再读后面的数据。
//! 该方法必须是 `pub`，否则 `@hasDecl` 看不见。

const std = @import("std");
const matcher = @import("matcher.zig");

/// 匹配或上下文在行内的字节区间，相对 `Line.bytes`。
pub const Span = struct {
    start: usize,
    end: usize,
};

/// 一次搜索的结果。`nul_offset` 是这次输入里第一次看到 NUL 的绝对偏移。
pub const Result = struct {
    outcome: Outcome = .complete,
    /// `matched` 被调用的次数。计数打印器和退出码用它。
    matched_lines: u64 = 0,
    nul_offset: ?u64 = null,
    /// 实际读过的字节。目录搜索用它记账，不再为了这个数对每个文件 `fstat`。
    bytes_read: u64 = 0,
};

/// 一个输入的结束原因。
pub const Outcome = enum {
    complete,
    /// Sink 返回 false，或达到 max_count。
    stopped,
    binary_quit,
    binary_matched,
};

/// 交给 Sink 的一行。
pub const Line = struct {
    /// 不含结尾的 `\n`，并去掉行尾的一个 `\r`。只在本次回调期间有效。
    bytes: []const u8,
    /// 该行第一个字节在输入中的绝对偏移。
    offset: u64,
    /// 从 1 开始。未打开行号时为 null。
    number: ?u64,
    /// 相对 `bytes`。普通上下文行和反选命中行没有匹配区间。
    /// 反选时，被当作上下文印出的模式行会带上区间，供列号使用。
    match: ?Span,
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
            return .{
                .bytes = self.haystack[start..content_end],
                .offset = start,
                .number = number,
                .match = .{ .start = mstart, .end = mend },
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
