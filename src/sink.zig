//! 推式输出。行切片指向 Searcher 的内部缓冲，只在回调返回前有效。

/// 匹配或上下文在行内的字节区间，相对 `Line.bytes`。
pub const Span = struct {
    start: usize,
    end: usize,
};

/// 交给 Sink 的一行。
pub const Line = struct {
    /// 不含结尾的 `\n`。只在本次回调期间有效。
    bytes: []const u8,
    /// 该行第一个字节在输入中的绝对偏移。
    offset: u64,
    /// 从 1 开始。未打开行号时为 null。
    number: ?u64,
    /// 相对 `bytes`。上下文行和反选行没有匹配。
    match: ?Span,
};

// AnySink 与拉式迭代器随搜索器一起落地。这里先把行数据定下来。
