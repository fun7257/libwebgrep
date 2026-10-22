//! zrg：可嵌入的字面量行搜索库。
//!
//! 会分配或做 I/O 的公共函数显式接收分配器和 `std.Io`。
//! 纯切片上的查找不需要这两者。库代码没有全局可变状态。

const std = @import("std");

pub const matcher = @import("matcher.zig");
pub const sink_mod = @import("sink.zig");
pub const searcher = @import("searcher.zig");

pub const MatchMode = matcher.MatchMode;
pub const Match = matcher.Match;
pub const RequiredLiteral = matcher.RequiredLiteral;
pub const CaseMode = matcher.CaseMode;
pub const FindOptions = matcher.FindOptions;

pub const Span = sink_mod.Span;
pub const Line = sink_mod.Line;

pub const BinaryPolicy = searcher.BinaryPolicy;
pub const SearchConfig = searcher.SearchConfig;
pub const Outcome = searcher.Outcome;

test "默认搜索配置" {
    const cfg: SearchConfig = .{};
    try std.testing.expectEqual(SearchConfig.default_buffer_size, cfg.buffer_size);
    try std.testing.expectEqual(SearchConfig.default_max_line_len, cfg.max_line_len);
    try std.testing.expectEqual(BinaryPolicy.report, cfg.binary);
    try std.testing.expectEqual(MatchMode.earliest, cfg.match_mode);
    try std.testing.expect(cfg.max_count == null);
}

pub const memchr = @import("finder/memchr.zig");

test {
    _ = @import("matcher.zig");
    _ = @import("sink.zig");
    _ = @import("searcher.zig");
    _ = @import("finder/memchr.zig");
    _ = @import("finder/two_way.zig");
    _ = @import("finder/ascii.zig");
    _ = @import("finder/frequency.zig");
    _ = @import("finder/packed_pair.zig");
}

pub const two_way = @import("finder/two_way.zig");
