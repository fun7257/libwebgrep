//! libwebgrep：可嵌入的字面量行搜索库。
//!
//! 会分配或做 I/O 的公共函数显式接收分配器和 `std.Io`。
//! 纯切片上的查找不需要这两者。库代码没有全局可变状态。
//! 调用方文档是 `docs/API.md`。

const std = @import("std");

/// 字面量约定：模式条数、总长度、大小写。大小写折叠只支持 ASCII。
pub const matcher = @import("matcher.zig");
/// 事件、行和结果。切片只在回调返回前有效。
pub const sink_mod = @import("sink.zig");
/// 搜索配置和服务入口的定义。根上再导出的函数才是调用入口。
pub const searcher = @import("searcher.zig");

/// `earliest` 取最早结束的匹配，`leftmost_first` 取最靠左的起点。
pub const MatchMode = matcher.MatchMode;
/// 一次 `find` 的半开区间，相对这次传入的 haystack。
pub const Match = matcher.Match;
/// 预留的必需字面量。正则尚未提供。字面量查找器返回模式本身。
pub const RequiredLiteral = matcher.RequiredLiteral;
/// `sensitive`、`insensitive`、`smart`。智能大小写按模式分别判断，这和 rg 整组判断不同。
pub const CaseMode = matcher.CaseMode;
/// 构造 `Finder` 或 `Multi` 的选项。条数和总长度只能往下调。
pub const FindOptions = matcher.FindOptions;

/// 半开区间。事件里相对行字节，并带扫描时算好的 UTF-16 端点。
pub const Span = sink_mod.Span;
/// 旧回调上的一行。`bytes`、`text`、`raw`、`matches` 只在回调返回前有效。
pub const Line = sink_mod.Line;
/// 二进制状态：`none`、`detected`、`suppressed`。
pub const BinaryStatus = sink_mod.BinaryStatus;
/// 服务入口的事件：begin、match、context、context_break、progress、heartbeat、end、summary。
pub const Event = sink_mod.Event;
/// 服务入口上的一行，带来源 ID、行号、字节列、绝对偏移和半开区间。
pub const LineEvent = sink_mod.LineEvent;
/// 来源结束。未命中的来源也有 begin 和 end，计数可以为 0。
pub const EndEvent = sink_mod.EndEvent;
/// 运行时多态的旧回调。虚表必须活得比它久。不实现 `event`。
pub const AnySink = sink_mod.AnySink;
/// 为旧回调生成虚表。缺的方法保持继续搜索。不分配。
pub const anyVtable = sink_mod.anyVtable;
/// 无上下文的拉式迭代。`Line.bytes` 指向调用方的 haystack，直到那份字节失效。
pub const SliceIter = sink_mod.SliceIter;
/// 成功返回的结果。软错误、有匹配、无匹配都在这里，致命错误走函数的错误。
pub const Result = sink_mod.Result;
/// `complete`、`stopped`、`binary_quit`、`binary_matched`。
pub const Outcome = sink_mod.Outcome;
/// 预算耗尽时看这个字段：`none`、`max_results`、`max_bytes`、`deadline`、`decompressed_bytes`、`cancelled`。
pub const LimitHit = sink_mod.LimitHit;
/// 来源软错误，只有 `read_failed`。没有内部路径。没有匹配时这个字段是 null。
pub const SoftError = sink_mod.SoftError;
/// 服务回调的控制：继续、暂停、停止。暂停没有 end，也没有 summary。
pub const Flow = sink_mod.Flow;
/// 扫完后的汇总。没扫完、暂停、或实时流还开着时不发。
pub const Summary = sink_mod.Summary;
/// 按调用方间隔发出的进度，不是最终汇总。
pub const Progress = sink_mod.Progress;
/// 实时流空闲。不是错误，也不是结束。
pub const Heartbeat = sink_mod.Heartbeat;
/// 暂停后续搜的计数。`resumeSourceSlice` 会把它带回去。
pub const ResumeState = sink_mod.ResumeState;

/// 二进制处理。默认 `quit`，也就是二进制默认跳过。
pub const BinaryPolicy = searcher.BinaryPolicy;
/// `auto` 只在流开头嗅探 BOM。`none` 不转码。其它编码尚未提供。
pub const Encoding = searcher.Encoding;
/// 搜索配置。服务入口会给留空的预算填默认值，旧入口留空表示不另加上限。
pub const SearchConfig = searcher.SearchConfig;
/// 旧回调入口，搜索一块内存。不填服务默认预算。`name` 只传给 `begin`。
pub const searchSlice = searcher.searchSlice;
/// 旧回调入口，从 reader 搜索。短读视为结束。服务入口是 `searchSource`。
pub const searchReader = searcher.searchReader;
/// 服务入口：从 reader 搜索。来源 ID 由调用方分配。上游读失败是 `soft_error`，不是致命错误。
pub const searchSource = searcher.searchSource;
/// 服务入口：搜索一块内存。行字节只在 `event` 返回前有效。没有 BOM 时不分配。
pub const searchSourceSlice = searcher.searchSourceSlice;
/// 从上次暂停继续搜同一块内存。不再发 begin。
pub const resumeSourceSlice = searcher.resumeSourceSlice;
/// 拉式入口。复制出来的事件活到 `deinit`，并且只保留一部分字段。
pub const openSourcePull = searcher.openSourcePull;

test "默认搜索配置" {
    const cfg: SearchConfig = .{};
    try std.testing.expectEqual(SearchConfig.default_buffer_size, cfg.buffer_size);
    try std.testing.expectEqual(SearchConfig.default_max_line_len, cfg.max_line_len);
    try std.testing.expectEqual(BinaryPolicy.quit, cfg.binary);
    try std.testing.expectEqual(Encoding.auto, cfg.encoding);
    try std.testing.expect(!cfg.null_data);
    try std.testing.expectEqual(MatchMode.earliest, cfg.match_mode);
    try std.testing.expect(cfg.max_count == null);
    try std.testing.expect(cfg.max_source_bytes == null);
    try std.testing.expect(cfg.max_request_bytes == null);
    try std.testing.expect(cfg.time_budget_ns == null);
    try std.testing.expect(cfg.cancel == null);
    try std.testing.expect(!cfg.exists);
    try std.testing.expect(cfg.max_concurrency == null);
}

fn checkSearchFn(comptime F: type) !void {
    const info = @typeInfo(F);
    try std.testing.expect(info == .@"fn");
    inline for (info.@"fn".param_types) |maybe| {
        const T = maybe orelse continue;
        try std.testing.expect(T != std.Io.File);
        try std.testing.expect(T != std.Io.Dir);
        try std.testing.expect(T != *std.Io.File);
        try std.testing.expect(T != *std.Io.Dir);
    }
}

test "公共搜索入口没有路径参数" {
    try std.testing.expect(!@hasDecl(@This(), "searchFile"));
    try std.testing.expect(!@hasDecl(@This(), "parallel"));
    try std.testing.expect(!@hasDecl(@This(), "walker"));
    try checkSearchFn(@TypeOf(searchSlice));
    try checkSearchFn(@TypeOf(searchReader));
    try checkSearchFn(@TypeOf(searchSource));
    try checkSearchFn(@TypeOf(searchSourceSlice));
    try checkSearchFn(@TypeOf(resumeSourceSlice));
    try checkSearchFn(@TypeOf(openSourcePull));

    const Collect = struct {
        left: bool = false,
        right: bool = false,
        matches: u32 = 0,
        pub fn event(self: *@This(), ev: Event) bool {
            switch (ev) {
                .begin => |b| {
                    if (std.mem.eql(u8, b.source_id, "left")) self.left = true;
                    if (std.mem.eql(u8, b.source_id, "right")) self.right = true;
                },
                .match => self.matches += 1,
                else => {},
            }
            return true;
        }
    };
    var found = Collect{};
    var left = try finder.Finder.init("LEFT", .{});
    var right = try finder.Finder.init("RIGHT", .{});
    const left_result = try searchSourceSlice(Collect, &found, "left", "LEFT\n", &left, .{});
    const right_result = try searchSourceSlice(Collect, &found, "right", "RIGHT\n", &right, .{});
    try std.testing.expectEqual(sink_mod.Outcome.complete, left_result.outcome);
    try std.testing.expectEqual(sink_mod.Outcome.complete, right_result.outcome);
    try std.testing.expect(found.left);
    try std.testing.expect(found.right);
    try std.testing.expectEqual(@as(u32, 2), found.matches);
}

/// 单字节查找。不分配。宽度只接受 16 或 32。
pub const memchr = @import("finder/memchr.zig");
/// `Finder` 的定义模块。单条字面量，不分配，模式不能含有换行。
pub const finder = @import("finder/finder.zig");
/// 单条字面量查找器。模式字节由调用方持有。空模式是零宽匹配。
pub const Finder = finder.Finder;
/// `Multi` 的定义模块。多条字面量是 OR，智能大小写按模式分别判断。
pub const multi = @import("finder/multi.zig");
/// 多条字面量。调用方持有模式字节，`deinit` 只释放内部表。
pub const Multi = multi.Multi;
/// `Regex` 的定义模块。线性时间 Thompson NFA 与必需字面量 SIMD 预过滤。
pub const regex = @import("regex.zig");
/// 线性时间正则表达式匹配器，支持编译大小硬顶与有界跨行窗口。
pub const Regex = regex.Regex;
/// 构造 `Regex` 的选项：大小写、有界跨行、`.` 是否匹配换行与指令数硬顶。
pub const RegexOptions = regex.RegexOptions;

test {
    _ = @import("encoding.zig");
    _ = @import("matcher.zig");
    _ = @import("sink.zig");
    _ = @import("searcher.zig");
    _ = @import("regex.zig");
    _ = @import("ndjson_fixture.zig");
    _ = @import("finder/memchr.zig");
    _ = @import("finder/two_way.zig");
    _ = @import("finder/ascii.zig");
    _ = @import("finder/frequency.zig");
    _ = @import("finder/packed_pair.zig");
    _ = @import("finder/finder.zig");
    _ = @import("finder/byteset.zig");
    _ = @import("finder/aho.zig");
    _ = @import("finder/pairs.zig");
    _ = @import("finder/multi.zig");
    if (@import("build_options").teddy != .off) {
        _ = @import("finder/teddy.zig");
        switch (@import("build_options").teddy) {
            .neon => _ = @import("finder/teddy_neon.zig"),
            .ssse3 => _ = @import("finder/teddy_ssse3.zig"),
            .avx2 => _ = @import("finder/teddy_avx2.zig"),
            .off => {},
        }
    }
}

/// 最坏线性的字面量查找。不分配。大小写折叠只支持 ASCII。
pub const two_way = @import("finder/two_way.zig");

/// 内存树接口。搜索入口不接收它，也不打开它。
pub const source = @import("source.zig");
/// 字节 glob 辅助。搜索入口不按它选择来源。嵌套花括号尚未提供。
pub const walk_glob = @import("walk/glob.zig");
/// 解析调用方已有的忽略文本。不读环境，也不读父目录。搜索入口不应用它。
pub const walk_ignore = @import("walk/ignore.zig");
/// 指针的工作窃取队列。搜索入口不创建它，也不起线程。
pub const walk_deque = @import("walk/deque.zig");
/// 已打开目录或文件的设备号和 inode。搜索入口不调用它。
pub const walk_file_id = @import("walk/file_id.zig");
/// 固定类型名到文件名的辅助。搜索入口不按类型过滤。
pub const walk_types = @import("walk/types.zig");
/// 枚举已打开的目录。搜索入口不列举目录。
pub const walk_list = @import("walk/list_dir.zig");

test {
    _ = @import("source.zig");
    _ = @import("walk/glob.zig");
    _ = @import("walk/ignore.zig");
    _ = @import("walk/deque.zig");
    _ = @import("walk/file_id.zig");
    _ = @import("walk/types.zig");
    _ = @import("walk/list_dir.zig");
    _ = @import("walk/walker.zig");
    _ = @import("parallel.zig");
}
