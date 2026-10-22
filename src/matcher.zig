//! 匹配器约定。字面量内核和将来的正则都实现 `find`。
//! Searcher 不依赖具体内核，只要求这个形状。

/// 匹配语义。
/// 单个字面量下两种模式结果相同：最左边的那一次就是最早的那一次。
/// 多模式时才分开。leftmost_first 留给 `-o` 和高亮。
pub const MatchMode = enum {
    /// 找到即停。
    earliest,
    /// 最左优先。重叠时取得更靠左、同样起点时取得更长的匹配。
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

/// 大小写。本次只有 ASCII。smart：模式里出现 `A-Z` 就区分大小写。
pub const CaseMode = enum {
    sensitive,
    insensitive,
    smart,
};

/// 构造查找器的选项。频率表的值越小，该字节越适合做预过滤锚点。
pub const FindOptions = struct {
    case: CaseMode = .sensitive,
    /// null 用内置表。
    frequency: ?[256]u8 = null,
    /// 长于 32 字节的模式，在两个稀有字节的平均间距小于 8、并且确认失败时，
    /// 剩下的查找改走 Two-Way。设为 1 或更大则一直留在 packed pair。
    /// 不超过 32 字节的模式不使用这个阈值。
    prefilter_fp_threshold: f32 = 0.80,
};

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
