//! 基准直接引用库内文件。公共模块 `src/root.zig` 不导出这里。
//! `searchFile` 和 `parallel.run` 因此到不了公共入口。

const searcher = @import("searcher.zig");
const finder_mod = @import("finder/finder.zig");

pub const searchFile = searcher.searchFile;
pub const searchSlice = searcher.searchSlice;
pub const Line = searcher.Line;
pub const parallel = @import("parallel.zig");
pub const memchr = @import("finder/memchr.zig");
pub const Finder = finder_mod.Finder;
pub const multi = @import("finder/multi.zig");
pub const Multi = multi.Multi;
