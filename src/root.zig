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
pub const AnySink = sink_mod.AnySink;
pub const anyVtable = sink_mod.anyVtable;
pub const SliceIter = sink_mod.SliceIter;
pub const Result = sink_mod.Result;
pub const Outcome = sink_mod.Outcome;

pub const BinaryPolicy = searcher.BinaryPolicy;
pub const SearchConfig = searcher.SearchConfig;
pub const searchSlice = searcher.searchSlice;
pub const searchReader = searcher.searchReader;
pub const searchFile = searcher.searchFile;

pub const text_printer = @import("printer/text.zig");
pub const count_printer = @import("printer/count.zig");
pub const TextPrinter = text_printer.Text;
pub const CountPrinter = count_printer.Count;

test "默认搜索配置" {
    const cfg: SearchConfig = .{};
    try std.testing.expectEqual(SearchConfig.default_buffer_size, cfg.buffer_size);
    try std.testing.expectEqual(SearchConfig.default_max_line_len, cfg.max_line_len);
    try std.testing.expectEqual(BinaryPolicy.report, cfg.binary);
    try std.testing.expectEqual(MatchMode.earliest, cfg.match_mode);
    try std.testing.expect(cfg.max_count == null);
}

pub const memchr = @import("finder/memchr.zig");
pub const finder = @import("finder/finder.zig");
pub const Finder = finder.Finder;
pub const multi = @import("finder/multi.zig");
pub const Multi = multi.Multi;

test {
    _ = @import("matcher.zig");
    _ = @import("sink.zig");
    _ = @import("searcher.zig");
    _ = @import("printer/text.zig");
    _ = @import("printer/count.zig");
    _ = @import("finder/memchr.zig");
    _ = @import("finder/two_way.zig");
    _ = @import("finder/ascii.zig");
    _ = @import("finder/frequency.zig");
    _ = @import("finder/packed_pair.zig");
    _ = @import("finder/finder.zig");
    _ = @import("finder/byteset.zig");
    _ = @import("finder/aho.zig");
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

pub const two_way = @import("finder/two_way.zig");

pub const source = @import("source.zig");
pub const walk_glob = @import("walk/glob.zig");
pub const walk_ignore = @import("walk/ignore.zig");
pub const walk_deque = @import("walk/deque.zig");
pub const walk_file_id = @import("walk/file_id.zig");
pub const walk_types = @import("walk/types.zig");
pub const walk_list = @import("walk/list_dir.zig");
pub const walker = @import("walk/walker.zig");
pub const parallel = @import("parallel.zig");
pub const json_printer = @import("printer/json.zig");
pub const files_printer = @import("printer/files.zig");

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
    _ = @import("printer/json.zig");
    _ = @import("printer/files.zig");
}
