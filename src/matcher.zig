//! 匹配器约定。字面量内核和将来的正则都实现 `find`。
//! Searcher 不依赖具体内核，只要求这个形状。

const std = @import("std");

/// 匹配语义。
/// 单个字面量下两种模式结果相同：最左边的那一次就是最早的那一次。
/// 多模式时才分开。`leftmost_first` 和 `rg -F` 的交替顺序一致，用于列号和高亮。
pub const MatchMode = enum {
    /// 结束位置最早的那一次。同样的结束位置，取得起点更靠左的；再相同则取得更早加入的模式。
    earliest,
    /// 起点最靠左的那一次。同一起点上，更早加入的模式胜出，不是更长的那个。
    leftmost_first,
};

/// 一次匹配。偏移相对本次传给 `find` 的 haystack，不是文件绝对偏移。
pub const Match = struct {
    start: usize,
    end: usize,
};

/// 正则预留的“必需字面量”。Searcher 在匹配器提供该方法时先用它做预过滤，
/// 再用真正的匹配器验证。字面量匹配器被问到时返回模式本身，偏移为 0。
/// 本次不实现正则。
pub const RequiredLiteral = struct {
    bytes: []const u8,
    /// 该字面量在完整匹配中的起始偏移。
    offset_in_match: usize,
};

/// 大小写。本次只折叠 ASCII。
/// `smart` 按每一条模式单独判断：全是小写才忽略大小写，出现 `A-Z` 就区分大小写。
/// 这和 rg 不同。rg 的 `-S` 是整组判断：整组里出现大写就全部区分大小写。
pub const CaseMode = enum {
    sensitive,
    insensitive,
    smart,
};

/// 模式条数硬顶。调用方可以把上限调低，不能超过这个值。
pub const pattern_count_hard_cap: usize = 1024;
/// 全部模式字节总长硬顶。按每条模式的长度相加。
pub const pattern_bytes_hard_cap: usize = 256 * 1024;

pub const LimitError = error{
    PatternCountExceeded,
    PatternBytesExceeded,
};

/// 构造查找器的选项。频率表的值越小，该字节越适合做预过滤锚点。
pub const FindOptions = struct {
    case: CaseMode = .sensitive,
    /// 开启 Unicode 简单大小写折叠（Simple Case Folding）。默认 false（仅折叠 ASCII）。
    unicode_case: bool = false,
    /// null 用内置表。
    frequency: ?[256]u8 = null,
    /// 长于 32 字节的模式，在两个稀有字节的平均间距小于 8、并且确认失败时，
    /// 剩下的查找改走 Two-Way。设为 1 或更大则一直留在 packed pair。
    /// 不超过 32 字节的模式不使用这个阈值。
    prefilter_fp_threshold: f32 = 0.80,
    /// 模式条数上限。null 用硬顶。比硬顶大时仍按硬顶拒绝。
    max_pattern_count: ?usize = null,
    /// 模式字节总长上限。null 用硬顶。比硬顶大时仍按硬顶拒绝。
    max_pattern_bytes: ?usize = null,
};

pub fn patternCountLimit(options: FindOptions) usize {
    return @min(options.max_pattern_count orelse pattern_count_hard_cap, pattern_count_hard_cap);
}

pub fn patternBytesLimit(options: FindOptions) usize {
    return @min(options.max_pattern_bytes orelse pattern_bytes_hard_cap, pattern_bytes_hard_cap);
}

/// 在分配自动机、Teddy 表或邻接对表之前调用。超限时搜索还没有开始。
pub fn checkPatternLimits(patterns: []const []const u8, options: FindOptions) LimitError!void {
    if (patterns.len > patternCountLimit(options)) return error.PatternCountExceeded;
    const byte_limit = patternBytesLimit(options);
    var total: usize = 0;
    for (patterns) |pat| {
        total = std.math.add(usize, total, pat.len) catch return error.PatternBytesExceeded;
        if (total > byte_limit) return error.PatternBytesExceeded;
    }
}

/// Matcher 需要的方法形状。写在这里供调用方对照，不产生运行时对象。
///
/// ```
/// pub fn find(self: *Self, haystack: []const u8, start: usize, mode: MatchMode) ?Match
/// ```
///
/// 可选：
///
/// ```
/// pub fn requiredLiteral(self: *const Self) ?RequiredLiteral
/// ```
pub const matcher_shape_docs = {};
