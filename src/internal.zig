//! Benchmarks import this internal module directly. The public module `src/root.zig` does not export it,
//! keeping `searchFile` and `parallel.run` out of the public API surface.

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
pub const Regex = @import("regex.zig").Regex;
