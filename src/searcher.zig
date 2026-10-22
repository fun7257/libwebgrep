//! 单个输入上的行语义。具体搜索函数随后接上。

const matcher = @import("matcher.zig");

/// 二进制（NUL）策略。
pub const BinaryPolicy = enum {
    /// 遇到 NUL 就停止这个输入。遍历发现的文件用这个。
    quit,
    /// 有匹配时报告“二进制文件有匹配”并停止。显式给出的文件用这个。
    report,
    /// 不检测。
    none,
};

/// 一次搜索的配置。缓冲和单行长度都有上限，超限返回错误，不无限增长。
pub const SearchConfig = struct {
    /// 起始块大小。P0 结束前会按 64 KiB、128 KiB、256 KiB、1 MiB 的基准确认。
    pub const default_buffer_size: usize = 256 * 1024;
    /// 单行字节上限。缓冲倍增到这里仍放不下一整行时返回 `error.LineTooLong`。
    pub const default_max_line_len: usize = 2 * 1024 * 1024;

    line_numbers: bool = false,
    invert: bool = false,
    before: u32 = 0,
    after: u32 = 0,
    /// 这个输入上最多报告多少条匹配行。null 表示不限。
    max_count: ?u64 = null,
    binary: BinaryPolicy = .report,
    buffer_size: usize = default_buffer_size,
    max_line_len: usize = default_max_line_len,
    match_mode: matcher.MatchMode = .earliest,
};

/// 一个输入的结束原因。
pub const Outcome = enum {
    complete,
    /// Sink 返回 false，或达到 max_count。
    stopped,
    binary_quit,
    binary_matched,
};
