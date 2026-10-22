//! 单个输入上的行语义。
//!
//! 先在缓冲里找匹配，命中后再向两侧找 `\n`。没有命中的区域不逐行扫描。
//! 模式里的换行由 Finder 拒绝；这里假定匹配器不会跨行。
//!
//! 切片搜索不分配内存。Reader 和文件搜索使用调用方传入的分配器，缓冲从
//! `buffer_size` 倍增到 `max_line_len`，超过则返回 `error.LineTooLong`。

const std = @import("std");
const matcher_mod = @import("matcher.zig");
const memchr = @import("finder/memchr.zig");
const sink_mod = @import("sink.zig");

pub const BinaryPolicy = enum {
    /// 遇到 NUL 就停止这个输入，不再搜索当前这次读入。遍历发现的文件用这个。
    quit,
    /// 显式给出的文件用这个。看到 NUL 后继续找，直到知道有没有匹配。
    report,
    /// 不检测。
    none,
};

pub const SearchConfig = struct {
    /// 起始块大小。128 MiB 文件上 1 MiB 只比 256 KiB 快约 1.5%，默认保持 256 KiB。
    pub const default_buffer_size: usize = 256 * 1024;
    /// 单行字节上限。缓冲倍增到这里仍放不下一整行时返回 `error.LineTooLong`。
    pub const default_max_line_len: usize = 2 * 1024 * 1024;

    line_numbers: bool = false,
    invert: bool = false,
    before: u32 = 0,
    after: u32 = 0,
    /// 这个输入上最多报告多少条匹配行。null 表示不限。
    /// 计入上限的是主循环找到的命中。`-A` 窗口里额外抬成匹配的行不占用额度，
    /// 但仍然调用 `matched`，因此计数打印器会把它们算进去。这和 ripgrep 15 一致。
    max_count: ?u64 = null,
    binary: BinaryPolicy = .report,
    buffer_size: usize = default_buffer_size,
    max_line_len: usize = default_max_line_len,
    match_mode: matcher_mod.MatchMode = .earliest,
};

pub const Outcome = sink_mod.Outcome;
pub const Result = sink_mod.Result;
pub const Line = sink_mod.Line;
pub const Span = sink_mod.Span;

pub const SliceError = error{LineTooLong};
pub const ReadError = error{ LineTooLong, OutOfMemory, ReadFailed } || std.Io.File.ReadPositionalError;

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
    nul_offset: ?u64 = null,
    stopped: bool = false,

    fn exceeded(self: *const State, config: SearchConfig) bool {
        const limit = config.max_count orelse return false;
        return self.limit_count >= limit;
    }
};

/// 在 `haystack` 上搜索。行切片直接指向 `haystack`。`name` 传给 `begin`，可以是空串。
pub fn searchSlice(
    comptime S: type,
    sink: *S,
    haystack: []const u8,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) SliceError!Result {
    resetStats(matcher);
    var state = State{};
    if (config.line_numbers) state.line_number = 1;
    if (!callBegin(S, sink, name)) {
        state.stopped = true;
        return finishSink(S, sink, &state, config);
    }

    if (config.binary != .none) {
        if (memchr.find(width, haystack, 0, 0)) |nul| {
            state.nul_offset = nul;
            const cont = callBinary(S, sink, nul);
            if (config.binary == .quit) {
                const window = bufferWindow(config);
                if (nul < @min(haystack.len, window)) {
                    return finishSink(S, sink, &state, config);
                }
                const boundary = (nul / window) * window;
                if (!try matchBuffer(S, sink, matcher, haystack[0..boundary], &state, config)) {
                    state.stopped = true;
                }
                return finishSink(S, sink, &state, config);
            }
            if (!cont) state.stopped = true;
        }
    }

    if (!state.stopped) {
        if (!try matchBuffer(S, sink, matcher, haystack, &state, config)) state.stopped = true;
    }
    return finishSink(S, sink, &state, config);
}

/// 从 `reader` 搜索。短读视为 EOF。缓冲在线程内由这一次调用独占，结束时释放。
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

/// 从已打开的文件搜索。用 `readPositional`，不经过第二层缓冲。P0 不 mmap。
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
    var state = State{};
    if (config.line_numbers) state.line_number = 1;
    if (!callBegin(S, sink, name)) {
        state.stopped = true;
        return finishSink(S, sink, &state, config);
    }

    const initial = bufferWindow(config);
    const cap0 = @max(initial, 1);
    var buf = try allocator.alloc(u8, cap0);
    defer allocator.free(buf);
    var filled: usize = 0;

    while (!state.stopped) {
        if (filled == buf.len) {
            buf = try grow(allocator, buf, config);
        }
        const n = try readFn(read_ctx, buf[filled..]);
        const eof = n == 0;
        const new_at = filled;
        if (!eof) filled += n;

        if (!eof and config.binary != .none and state.nul_offset == null) {
            if (memchr.find(width, buf[new_at..filled], 0, 0)) |rel| {
                state.nul_offset = state.abs_base + new_at + rel;
                const cont = callBinary(S, sink, state.nul_offset.?);
                if (config.binary == .quit or !cont) {
                    filled = new_at;
                    state.stopped = true;
                    break;
                }
            }
        }

        const search_end = if (eof) filled else lastComplete(buf[0..filled]);
        // 换行符本身不计入单行上限，所以缓冲可以比上限多一个字节。
        const pending = filled - search_end;
        if (!eof and pending > config.max_line_len) return error.LineTooLong;
        if (eof and pending > config.max_line_len) return error.LineTooLong;

        if (search_end > state.pos or eof) {
            const view_end = if (eof) filled else search_end;
            if (!try matchBuffer(S, sink, matcher, buf[0..view_end], &state, config)) {
                state.stopped = true;
                break;
            }
        }

        if (eof) break;
        if (state.stopped) break;

        const consumed = rollConsumed(buf[0..search_end], &state, config);
        countLines(buf, consumed, &state);
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

fn grow(allocator: std.mem.Allocator, buf: []u8, config: SearchConfig) error{ LineTooLong, OutOfMemory }![]u8 {
    const limit = config.max_line_len + 1;
    if (buf.len >= limit) return error.LineTooLong;
    const doubled = if (buf.len > limit / 2) limit else buf.len * 2;
    const next = @min(limit, doubled);
    if (next <= buf.len) return error.LineTooLong;
    return allocator.realloc(buf, next);
}

fn bufferWindow(config: SearchConfig) usize {
    if (config.buffer_size == 0) return SearchConfig.default_buffer_size;
    return config.buffer_size;
}

fn lastComplete(buf: []const u8) usize {
    if (memchr.findLast(width, buf, 0, buf.len, '\n')) |i| return i + 1;
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
        if (config.invert) {
            if (!try matchInvert(S, sink, matcher, buf, state, config)) break;
        } else if (try findLine(matcher, buf, state, config)) |line| {
            state.limit_count += 1;
            if (config.before > 0 or config.after > 0) {
                if (!try afterContext(S, sink, matcher, buf, line.start, state, config)) return false;
                if (!try beforeContext(S, sink, matcher, buf, line.start, state, config)) return false;
            }
            state.pos = line.end;
            const known = BufMatch{ .start = line.mstart, .end = line.mend };
            if (!try sinkMatched(S, sink, matcher, buf, line.range(), known, state, config)) return false;
        } else break;
    }
    if (state.stopped) return false;
    if (!try afterContext(S, sink, matcher, buf, buf.len, state, config)) return false;
    if (state.exceeded(config) and state.after_left == 0) return false;
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
        const found = matcher.find(buf, pos, config.match_mode) orelse return null;
        if (found.start > buf.len) return null;
        const start = lineStart(buf, found.start);
        if (start == buf.len) {
            pos = buf.len;
            continue;
        }
        const end = lineEnd(buf, @max(found.end, start));
        if (end == start) {
            pos = @min(buf.len, start + 1);
            continue;
        }
        return .{
            .start = start,
            .end = end,
            .mstart = found.start,
            .mend = found.end,
        };
    }
    return null;
}

fn matchInvert(
    comptime S: type,
    sink: *S,
    matcher: anytype,
    buf: []const u8,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    const gap: Range = if (try findLine(matcher, buf, state, config)) |line| blk: {
        const g = Range{ .start = state.pos, .end = line.start };
        state.pos = line.end;
        break :blk g;
    } else blk: {
        const g = Range{ .start = state.pos, .end = buf.len };
        state.pos = buf.len;
        break :blk g;
    };
    if (gap.start == gap.end) return true;

    if (config.before > 0 or config.after > 0) {
        if (!try afterContext(S, sink, matcher, buf, gap.start, state, config)) return false;
        if (!try beforeContext(S, sink, matcher, buf, gap.start, state, config)) return false;
    }
    var cursor = gap.start;
    while (nextLine(buf, cursor, gap.end)) |line| {
        cursor = line.end;
        state.limit_count += 1;
        if (!try sinkMatched(S, sink, matcher, buf, line, null, state, config)) return false;
        if (state.exceeded(config)) return false;
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
    while (nextLine(buf, cursor, upto)) |line| {
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
    if (config.before == 0) return true;
    if (state.last_line_visited >= upto) return true;
    const slice = buf[state.last_line_visited..upto];
    const rel = preceding(slice, config.before - 1);
    var cursor = state.last_line_visited + rel;
    while (nextLine(buf, cursor, upto)) |line| {
        cursor = line.end;
        if (!try sinkBreak(S, sink, buf, line.start, state, config)) return false;
        if (!try sinkContext(S, sink, matcher, buf, line, .before, state, config)) return false;
    }
    return true;
}

const ContextKind = enum { before, after };

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
    const content_end = contentEnd(buf, line);
    if (content_end - line.start > config.max_line_len) return error.LineTooLong;
    if (!try sinkBreak(S, sink, buf, line.start, state, config)) return false;
    countLines(buf, line.start, state);
    const span = spanFrom(buf, line, content_end, known);
    const keep = callMatched(S, sink, .{
        .bytes = buf[line.start..content_end],
        .offset = state.abs_base + line.start,
        .number = state.line_number,
        .match = span,
    });
    state.last_line_visited = line.end;
    state.after_left = config.after;
    state.has_sunk = true;
    state.matched_lines += 1;
    if (!keep) state.stopped = true;
    _ = matcher;
    return keep;
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
    const content_end = contentEnd(buf, line);
    if (content_end - line.start > config.max_line_len) return error.LineTooLong;
    countLines(buf, line.start, state);
    const span = if (config.invert) spanFrom(buf, line, content_end, matchInLine(matcher, buf, line, config)) else null;
    const keep = callContext(S, sink, .{
        .bytes = buf[line.start..content_end],
        .offset = state.abs_base + line.start,
        .number = state.line_number,
        .match = span,
    });
    state.last_line_visited = line.end;
    if (kind == .after and state.after_left > 0) state.after_left -= 1;
    state.has_sunk = true;
    if (!keep) state.stopped = true;
    return keep;
}

fn sinkBreak(
    comptime S: type,
    sink: *S,
    buf: []const u8,
    start: usize,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    _ = buf;
    const any_context = config.before > 0 or config.after > 0;
    if (!any_context or !state.has_sunk or state.last_line_visited >= start) return true;
    const keep = callBreak(S, sink);
    if (!keep) state.stopped = true;
    return keep;
}

fn lineIsReportedHit(matcher: anytype, buf: []const u8, line: Range, config: SearchConfig) bool {
    const hit = matchInLine(matcher, buf, line, config) != null;
    return if (config.invert) !hit else hit;
}

fn matchInLine(matcher: anytype, buf: []const u8, line: Range, config: SearchConfig) ?BufMatch {
    const end = contentEnd(buf, line);
    const content = buf[line.start..end];
    const found = matcher.find(content, 0, config.match_mode) orelse return null;
    return .{ .start = line.start + found.start, .end = line.start + found.end };
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

fn contentEnd(buf: []const u8, line: Range) usize {
    if (line.end > line.start and line.end <= buf.len and buf[line.end - 1] == '\n') return line.end - 1;
    return line.end;
}

fn countLines(buf: []const u8, upto: usize, state: *State) void {
    if (state.line_number == null) return;
    if (state.last_line_counted >= upto) return;
    const n = memchr.count(width, buf, state.last_line_counted, upto, '\n');
    state.line_number = (state.line_number orelse return) + n;
    state.last_line_counted = upto;
}

fn rollConsumed(buf: []const u8, state: *const State, config: SearchConfig) usize {
    if (config.before == 0 and config.after == 0) return buf.len;
    const context_start = preceding(buf, config.before);
    return @max(context_start, state.last_line_visited);
}

fn lineStart(buf: []const u8, pos: usize) usize {
    const upto = @min(pos, buf.len);
    if (memchr.findLast(width, buf, 0, upto, '\n')) |i| return i + 1;
    return 0;
}

fn lineEnd(buf: []const u8, from: usize) usize {
    if (from >= buf.len) return buf.len;
    if (memchr.find(width, buf, from, '\n')) |i| return i + 1;
    return buf.len;
}

fn nextLine(buf: []const u8, pos: usize, end: usize) ?Range {
    if (pos >= end or pos >= buf.len) return null;
    const limit = @min(end, buf.len);
    if (memchr.find(width, buf, pos, '\n')) |i| {
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
    var outcome: Outcome = if (state.stopped) .stopped else .complete;
    if (state.nul_offset != null and config.binary == .quit) outcome = .binary_quit;
    if (state.nul_offset != null and config.binary == .report and state.matched_lines > 0) {
        outcome = .binary_matched;
    }
    const result = Result{
        .outcome = outcome,
        .matched_lines = state.matched_lines,
        .nul_offset = state.nul_offset,
    };
    _ = callFinish(S, sink, result);
    return result;
}

fn resetStats(matcher: anytype) void {
    const T = @TypeOf(matcher);
    const Child = switch (@typeInfo(T)) {
        .pointer => |p| if (p.size == .one) p.child else return,
        else => return,
    };
    if (@hasDecl(Child, "resetStats")) matcher.resetStats();
}

fn callBegin(comptime S: type, sink: *S, name: []const u8) bool {
    if (@hasDecl(S, "begin")) return sink.begin(name);
    return true;
}
fn callMatched(comptime S: type, sink: *S, line: Line) bool {
    if (@hasDecl(S, "matched")) return sink.matched(line);
    return true;
}
fn callContext(comptime S: type, sink: *S, line: Line) bool {
    if (@hasDecl(S, "context")) return sink.context(line);
    return true;
}
fn callBreak(comptime S: type, sink: *S) bool {
    if (@hasDecl(S, "contextBreak")) return sink.contextBreak();
    return true;
}
fn callBinary(comptime S: type, sink: *S, offset: u64) bool {
    if (@hasDecl(S, "binary")) return sink.binary(offset);
    return true;
}
fn callFinish(comptime S: type, sink: *S, result: Result) bool {
    if (@hasDecl(S, "finish")) return sink.finish(result);
    return true;
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
        self.text.appendSlice(testing.allocator, "--\n") catch unreachable;
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
        \\--
        \\6-e
        \\7:MATCH2
        \\8-f
        \\
    , rec.text.items);
    try testing.expectEqual(@as(u64, 2), rec.matches);
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

test "切片：空行、无结尾换行、CRLF 保留 CR" {
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
    try testing.expectEqualStrings("2:MATCH\r\n", crlf.text.items);
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

test "切片：超长匹配行报错" {
    var finder = try Finder.init("MATCH", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const hay = "MATCHxxxxxxxxxxxxxxxxxxxx";
    const result = searchSlice(Rec, &rec, hay, "", &finder, .{ .max_line_len = 8, .binary = .none });
    try testing.expectError(error.LineTooLong, result);
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

test "Reader 超过单行上限" {
    var reader = std.Io.Reader.fixed("abcdef\n");
    var finder = try Finder.init("a", .{});
    var rec = Rec{};
    defer rec.deinit(testing.allocator);
    const result = searchReader(Rec, testing.allocator, &rec, &reader, "", &finder, .{
        .buffer_size = 4,
        .max_line_len = 4,
        .binary = .none,
    });
    try testing.expectError(error.LineTooLong, result);
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
