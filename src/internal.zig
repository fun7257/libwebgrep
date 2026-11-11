//! Benchmarks import this internal module directly. The public module `src/root.zig` does not export it,
//! keeping `searchFile` and `parallel.run` out of the public API surface.

const searcher = @import("searcher.zig");
const finder_mod = @import("finder/finder.zig");

pub const searchFile = searcher.searchFile;
pub const searchSlice = searcher.searchSlice;
pub const searchReader = searcher.searchReader;
pub const searchSource = searcher.searchSource;
pub const searchSourceSlice = searcher.searchSourceSlice;
pub const resumeSource = searcher.resumeSource;
pub const resumeSourceSlice = searcher.resumeSourceSlice;
pub const SearchConfig = searcher.SearchConfig;
pub const Scratch = searcher.Scratch;
pub const Result = searcher.Result;
pub const BinaryPolicy = searcher.BinaryPolicy;
pub const Line = searcher.Line;
pub const platform = @import("io/platform.zig");
pub const CaseMode = @import("matcher.zig").CaseMode;
pub const sink = @import("sink.zig");
pub const ndjson = @import("ndjson_fixture.zig");
pub const encoding = @import("codec/encoding.zig");
pub const decompress = @import("codec/decompress.zig");
pub const parallel = @import("parallel.zig");
pub const memchr = @import("finder/memchr.zig");
pub const unicode_fold = @import("finder/unicode_fold.zig");
pub const Finder = finder_mod.Finder;
pub const FindOptions = @import("matcher.zig").FindOptions;
pub const multi = @import("finder/multi.zig");
pub const Multi = multi.Multi;
pub const Regex = @import("regex.zig").Regex;
pub const RegexSet = @import("regex.zig").RegexSet;
pub const Captures = @import("regex.zig").Captures;
pub const openSourcePull = searcher.openSourcePull;
pub const openReaderPull = searcher.openReaderPull;
pub const archive = @import("codec/archive.zig");
pub const tree = @import("search/tree.zig");
pub const searchArchiveSlice = tree.searchArchiveSlice;

