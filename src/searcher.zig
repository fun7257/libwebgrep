//! 单个输入上的行语义。
//!
//! 先在缓冲里找匹配，命中后再向两侧找 `\n`。没有命中的区域不逐行扫描。
//! 模式里的换行由 Finder 拒绝；这里假定匹配器不会跨行。
//! 行终止符仍是 LF。交给 Sink 的行内容去掉结尾的 `\n`，再去掉紧挨着的一个 `\r`。
//!
//! 切片搜索不分配内存。Reader 和文件搜索使用调用方传入的分配器。读缓冲从
//! `buffer_size` 涨到单行上限，不再为了装下整行继续涨。超过上限的行仍按流查找，
//! 交出去的是匹配附近的窗口。前置上下文放在环形缓冲里，不回退读取。

const std = @import("std");
const build_options = @import("build_options");
const matcher_mod = @import("matcher.zig");
const memchr = @import("finder/memchr.zig");
const sink_mod = @import("sink.zig");

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
    buffer_size: usize = default_buffer_size,
    max_line_len: usize = default_max_line_len,
    match_mode: matcher_mod.MatchMode = .earliest,
    /// 非 null 时复用这块缓冲。扩容后把新切片写回去。null 时这次调用自己分配、自己释放。
    scratch: ?*[]u8 = null,
    /// 非 null 且为真时，下一块开始前停止。遍历用它做提前结束。
    stop: ?*const std.atomic.Value(bool) = null,
};

pub const Outcome = sink_mod.Outcome;
pub const Result = sink_mod.Result;
pub const Line = sink_mod.Line;
pub const Span = sink_mod.Span;

pub const SliceError = error{ContextLinesExceeded};
pub const ReadError = error{ OutOfMemory, ReadFailed, ContextLinesExceeded } || std.Io.File.ReadPositionalError;

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
    bytes_read: u64 = 0,
    nul_offset: ?u64 = null,
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
    try rejectWideContext(config);
    resetStats(matcher);
    var state = State{};
    state.ring.cap = beforeCount(config);
    state.ring.stride = config.max_line_len;
    if (config.line_numbers) state.line_number = 1;
    if (!callOpt(S, "begin", sink, .{name})) {
        state.stopped = true;
        return finishSink(S, sink, &state, config);
    }

    if (config.binary != .none) {
        if (memchr.find(width, haystack, 0, 0)) |nul| {
            state.nul_offset = nul;
            const cont = callOpt(S, "binary", sink, .{nul});
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

/// 从已打开的文件搜索。默认用 `readPositional` 分块读进调用方缓冲。
/// 整文件映射在这台机器的 1 GiB 热缓存上比分块读更慢，还把驻留撑到文件大小，所以不用。
/// `-Dmmap-windows` 才改走 8 MiB 窗口映射，默认关闭。
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
    if (comptime build_options.mmap_windows) {
        const mmap_window = @import("io/mmap_window.zig");
        if (try mmap_window.open(io, file, bufferWindow(config))) |opened| {
            var ctx = opened;
            defer ctx.close();
            return drive(S, allocator, sink, matcher, config, name, mmap_window.readBytes, &ctx);
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
    try rejectWideContext(config);
    var state = State{};
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
    if (!callOpt(S, "begin", sink, .{name})) {
        state.stopped = true;
        return finishSink(S, sink, &state, config);
    }

    const initial = bufferWindow(config);
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

    while (!state.stopped) {
        if (state.exceeded(config)) {
            state.stopped = true;
            break;
        }
        if (flagIsSet(config)) {
            state.stopped = true;
            break;
        }
        if (filled == buf.len) {
            if (try grow(allocator, buf, config)) |next| {
                buf = next;
                if (config.scratch) |slot| slot.* = buf;
            } else if (!try makeRoom(S, allocator, sink, matcher, &buf, &filled, &hold, &seen, &state, config)) {
                state.stopped = true;
                break;
            } else if (config.scratch) |slot| slot.* = buf;
        }
        const n = try readFn(read_ctx, buf[filled..]);
        state.bytes_read += n;
        const eof = n == 0;
        var chunk_at = filled;
        if (!eof) filled += n;

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

        const search_end = if (eof) filled else lastComplete(buf[0..filled]);
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
                    } else if (hit.start < state.pos + 4096) {
                        state.prefer_prepass = true;
                    }
                } else {
                    skip_match = true;
                    state.pos = view_end;
                }
            }
            if (nul_rel) |rel| {
                state.nul_offset = state.abs_base + rel;
                const cont = callOpt(S, "binary", sink, .{state.nul_offset.?});
                if (config.binary == .quit or !cont) {
                    filled = chunk_at;
                    state.stopped = true;
                    break;
                }
                skip_match = false;
            }
        } else if (!eof and config.binary != .none and state.nul_offset == null) {
            if (memchr.find(width, buf[chunk_at..filled], 0, 0)) |rel| {
                state.nul_offset = state.abs_base + chunk_at + rel;
                const cont = callOpt(S, "binary", sink, .{state.nul_offset.?});
                if (config.binary == .quit or !cont) {
                    filled = chunk_at;
                    state.stopped = true;
                    break;
                }
            }
        }

        if (!skip_match and (search_end > state.pos or eof)) {
            if (!try matchBuffer(S, sink, matcher, buf[0..view_end], &state, config)) {
                state.stopped = true;
                break;
            }
        }

        if (eof) break;
        if (state.stopped) break;

        const consumed = search_end;
        rememberBefore(matcher, buf, &state, config, consumed);
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

fn flagIsSet(config: SearchConfig) bool {
    const flag = config.stop orelse return false;
    return flag.load(.acquire);
}

fn grow(allocator: std.mem.Allocator, buf: []u8, config: SearchConfig) error{OutOfMemory}!?[]u8 {
    const limit = lineHoldLimit(config);
    if (buf.len >= limit) return null;
    const doubled = if (buf.len > limit / 2) limit else buf.len * 2;
    const next = @min(limit, @max(doubled, buf.len + 1));
    if (next <= buf.len) return null;
    return try allocator.realloc(buf, next);
}

fn canFuse(matcher: anytype, config: SearchConfig, state: *const State) bool {
    if (state.prefer_prepass or state.nul_offset != null) return false;
    if (config.binary == .none or config.invert or beforeCount(config) != 0 or afterCount(config) != 0) return false;
    if (config.whole_word or config.whole_line or config.contains.len != 0 or config.excludes.len != 0) return false;
    return @hasDecl(@TypeOf(matcher.*), "findWatched");
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
            if (beforeCount(config) > 0 or afterCount(config) > 0) {
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
        const start = lineStart(buf, hit.start);
        if (start == buf.len) {
            pos = buf.len;
            continue;
        }
        const end = lineEnd(buf, @max(hit.end, start));
        if (end == start) {
            pos = @min(buf.len, start + 1);
            continue;
        }
        const content_end = contentEnd(buf, .{ .start = start, .end = end });
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

    if (beforeCount(config) > 0 or afterCount(config) > 0) {
        if (!try afterContext(S, sink, matcher, buf, gap.start, state, config)) return false;
        if (!try beforeContext(S, sink, matcher, buf, gap.start, state, config)) return false;
    }
    var cursor = gap.start;
    while (nextLine(buf, cursor, gap.end)) |line| {
        cursor = line.end;
        const content_end = contentEnd(buf, line);
        if (!linePassesFilters(buf, line.start, content_end, config)) continue;
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
    if (beforeCount(config) == 0) return true;
    // 匹配可能落在本块开头，前置行已经在上一块推进环里。
    // 那种情况下 last_line_visited == upto，仍然要把环交出去。
    if (state.last_line_visited < upto) {
        rememberBefore(matcher, buf, state, config, upto);
    }
    return emitRing(S, sink, buf, state, config);
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
    const preview = previewLine(buf, line, known, config);
    const line_abs = state.abs_base + line.start;
    if (!try sinkBreakAt(S, sink, line_abs, state, config)) return false;
    countLines(buf, line.start, state);
    const withheld = config.binary == .report and state.nul_offset != null;
    const bytes = if (withheld) buf[line.start..line.start] else buf[preview.start..preview.end];
    const keep = callOpt(S, "matched", sink, .{Line{
        .bytes = bytes,
        .offset = line_abs,
        .number = state.line_number,
        .match = if (withheld) null else preview.span,
        .truncated = preview.truncated and !withheld,
        .line_len = preview.line_len,
        .window_start = if (withheld) 0 else preview.window_start,
    }});
    state.last_line_visited = line.end;
    state.last_abs_end = state.abs_base + line.end;
    state.remembered_until = @max(state.remembered_until, line.end);
    state.after_left = afterCount(config);
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
    const known = if (config.invert) matchInLine(matcher, buf, line, config) else null;
    const preview = previewLine(buf, line, known, config);
    const line_abs = state.abs_base + line.start;
    if (!try sinkBreakAt(S, sink, line_abs, state, config)) return false;
    countLines(buf, line.start, state);
    const withheld = config.binary == .report and state.nul_offset != null;
    const bytes = if (withheld) buf[line.start..line.start] else buf[preview.start..preview.end];
    const keep = callOpt(S, "context", sink, .{Line{
        .bytes = bytes,
        .offset = line_abs,
        .number = state.line_number,
        .match = if (withheld) null else preview.span,
        .truncated = preview.truncated and !withheld,
        .line_len = preview.line_len,
        .window_start = if (withheld) 0 else preview.window_start,
    }});
    state.last_line_visited = line.end;
    state.last_abs_end = state.abs_base + line.end;
    state.remembered_until = @max(state.remembered_until, line.end);
    if (kind == .after and state.after_left > 0) state.after_left -= 1;
    state.has_sunk = true;
    if (!keep) state.stopped = true;
    return keep;
}

fn sinkBreakAt(
    comptime S: type,
    sink: *S,
    line_abs: u64,
    state: *State,
    config: SearchConfig,
) SliceError!bool {
    const any_context = beforeCount(config) > 0 or afterCount(config) > 0;
    if (!any_context or !state.has_sunk or line_abs <= state.last_abs_end) return true;
    const keep = callOpt(S, "contextBreak", sink, .{});
    if (!keep) state.stopped = true;
    return keep;
}

fn lineIsReportedHit(matcher: anytype, buf: []const u8, line: Range, config: SearchConfig) bool {
    const content_end = contentEnd(buf, line);
    if (!linePassesFilters(buf, line.start, content_end, config)) return false;
    const hit = matchInLine(matcher, buf, line, config) != null;
    return if (config.invert) !hit else hit;
}

fn matchInLine(matcher: anytype, buf: []const u8, line: Range, config: SearchConfig) ?BufMatch {
    const end = contentEnd(buf, line);
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

fn contentEnd(buf: []const u8, line: Range) usize {
    var end = line.end;
    if (end > line.start and end <= buf.len and buf[end - 1] == '\n') end -= 1;
    if (end > line.start and end <= buf.len and buf[end - 1] == '\r') end -= 1;
    return end;
}

fn countLines(buf: []const u8, upto: usize, state: *State) void {
    if (state.line_number == null) return;
    if (state.last_line_counted >= upto) return;
    const n = memchr.count(width, buf, state.last_line_counted, upto, '\n');
    state.line_number = (state.line_number orelse return) + n;
    state.last_line_counted = upto;
}

fn rollConsumed(buf: []const u8, state: *const State, config: SearchConfig) usize {
    _ = state;
    _ = config;
    return buf.len;
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
    if (state.exceeded(config)) {
        if (config.close_input) |close| close(config.close_ctx);
    }
    var outcome: Outcome = if (state.stopped) .stopped else .complete;
    if (state.nul_offset != null and config.binary == .quit) outcome = .binary_quit;
    if (state.nul_offset != null and config.binary == .report and state.matched_lines > 0) {
        outcome = .binary_matched;
    }
    const result = Result{
        .outcome = outcome,
        .matched_lines = state.matched_lines,
        .nul_offset = state.nul_offset,
        .binary_offset = state.nul_offset,
        .bytes_read = state.bytes_read,
    };
    _ = callOpt(S, "finish", sink, .{result});
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
    const end = lastComplete(buf);
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
    const content_end = contentEnd(buf, line);
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
    while (nextLine(buf, cursor, limit_end)) |line| {
        if (line.end <= state.last_line_visited) {
            cursor = line.end;
            continue;
        }
        const known = if (config.invert) matchInLine(matcher, buf, line, config) else null;
        const preview = previewLine(buf, line, known, config);
        countLines(buf, line.start, state);
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
        const keep = callOpt(S, "context", sink, .{Line{
            .bytes = if (withheld) raw[0..0] else raw,
            .offset = slot.abs,
            .number = slot.number,
            .match = span,
            .truncated = slot.truncated and !withheld,
            .line_len = slot.line_len,
            .window_start = if (withheld) 0 else slot.window_start,
        }});
        state.last_abs_end = slot.end_abs;
        state.has_sunk = true;
        if (!keep) {
            state.stopped = true;
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
    const line = Line{
        .bytes = if (withheld) raw[0..0] else raw,
        .offset = state.long_origin,
        .number = state.long_number,
        .match = span,
        .truncated = state.long_line_len > config.max_line_len and !withheld,
        .line_len = state.long_line_len,
        .window_start = if (withheld) 0 else state.long_window_start,
    };
    const keep = if (as_match)
        callOpt(S, "matched", sink, .{line})
    else
        callOpt(S, "context", sink, .{line});
    if (as_match) state.matched_lines += 1;
    state.last_abs_end = end_abs;
    state.has_sunk = true;
    if (!keep) state.stopped = true;
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
        if (!try emitRing(S, sink, buf.*, state, config)) return false;
        state.limit_count += 1;
        if (!try emitHold(S, sink, hold, state, config, true, end_abs)) return false;
        state.after_left = afterCount(config);
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
    countLines(buf.*, @min(drop_buf, filled.*), state);
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
    if (config.invert or beforeCount(config) > 0 or state.after_left > 0) {
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
    const end = lastComplete(buf.*[0..filled.*]);
    if (end > 0) {
        if (!try matchBuffer(S, sink, matcher, buf.*[0..end], state, config)) return false;
        rememberBefore(matcher, buf.*, state, config, end);
        countLines(buf.*, end, state);
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
    if (config.binary != .none and state.nul_offset == null and new_at < filled.*) {
        if (memchr.find(width, buf.*[new_at..filled.*], 0, 0)) |rel| {
            state.nul_offset = state.abs_base + new_at + rel;
            const cont = callOpt(S, "binary", sink, .{state.nul_offset.?});
            if (config.binary == .quit or !cont) return false;
        }
    }
    if (!state.long_active) {
        if (eof) return true;
        const search_end = lastComplete(buf.*[0..filled.*]);
        if (filled.* - search_end <= config.max_line_len) return true;
        if (search_end > 0) {
            if (!try matchBuffer(S, sink, matcher, buf.*[0..search_end], state, config)) return false;
            rememberBefore(matcher, buf.*, state, config, search_end);
            countLines(buf.*, search_end, state);
            compactBuf(buf.*, filled, search_end, state);
        }
        try beginLong(allocator, matcher, buf, filled, hold, seen, state, config);
        return !state.stopped;
    }
    if (memchr.find(width, buf.*, 0, '\n')) |nl| {
        var content_len = nl;
        if (nl > 0 and buf.*[nl - 1] == '\r') content_len = nl - 1;
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
