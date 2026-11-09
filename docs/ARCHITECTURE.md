# libwebgrep 5-Layer Architecture & Co-Development Guide

[English](ARCHITECTURE.md) | [简体中文](ARCHITECTURE.zh-CN.md)

`libwebgrep` is structured as a strict **5-Layer Acyclic Architecture** engineered for both human readability and AI-assisted co-development:

1. **Accuracy First**: Every SIMD kernel, Thompson NFA transition, streaming transcode/decompression boundary, and line-context window is backed by deterministic unit tests and differential fuzzing (`src/fuzz.zig`).
2. **Extreme Performance Second**: Zero-cost `comptime` monomorphization across layers, 4-vector unrolled SIMD loops (`@Vector`, `@splat`), branchless ASCII/Unicode case folding, and `@branchHint(.cold)` on fallback paths.
3. **Elegant Code Taste & Co-Development Third**: Implementation files are scoped to a single clear responsibility (typically **150–800 lines**), with standardized English module headers (`//! [Module]`, `//! [Layer]`, `//! [Role]`, `//! [Invariants]`).

---

## 1. Five-Layer Architecture Overview

Dependencies flow strictly downward from Layer 5 to Layer 1. Lower layers never import higher layers.

```mermaid
flowchart TD
    subgraph L5["Layer 5: Facade, Multi-Source Pipeline & Fuzz Verification"]
        ROOT["src/root.zig<br/>Public API Facade"]
        PAR["src/parallel.zig<br/>Work-Stealing Multi-Source Pipeline"]
        WALK["src/walk/*<br/>glob / ignore / types / deque / walker"]
        FUZZ["src/fuzz.zig<br/>Differential & Smith Fuzz Suite"]
    end

    subgraph L4["Layer 4: Streaming Line Search Engine (src/search/)"]
        SRCH["src/searcher.zig<br/>Public Search Orchestrator"]
        PIPE["src/search/pipeline.zig<br/>Slice & Streaming Drivers"]
        LM["src/search/line_matcher.zig<br/>Line Scan, Word/Line & Filters"]
        RING["src/search/context_ring.zig<br/>Bounded Before-Context Ring"]
        LONG["src/search/long_line.zig<br/>Constant-Memory Long Line Window"]
        FMT["src/search/format.zig<br/>UTF-16 Columns, Spans & Replacement"]
        PULL["src/search/pull.zig<br/>EventBridge & Pull Cursor"]
        STATE["src/search/state.zig & config.zig<br/>Budgets, Deadlines & State"]
    end

    subgraph L3["Layer 3: Streaming Codec & Source Abstraction (src/codec/)"]
        ENC["src/codec/encoding.zig<br/>BOM Sniff & UTF-8/16/GBK/Latin-1 Decoder"]
        DEC["src/codec/decompress.zig<br/>Bomb-Safe Gzip / Zstd / XZ"]
        OMAP["src/codec/offset_map.zig<br/>Collinear-Compacted OffsetMap"]
        SRC["src/source.zig & src/sink.zig<br/>Source & SinkTraits Contracts"]
    end

    subgraph L2["Layer 2: SIMD Pattern & Regex Matchers (src/finder/ & src/regex/)"]
        MTRAIT["src/matcher.zig<br/>MatcherTraits & validateMatcher"]
        FIND["src/finder/finder.zig<br/>Single-Literal Finder (PackedPair + TwoWay)"]
        MULTI["src/finder/multi.zig<br/>4-Tier Multi-Literal (Bytes/Pairs/Teddy/AC)"]
        RE["src/regex/*<br/>inst / compiler / prefilter / vm"]
    end

    subgraph L1["Layer 1: Zero-Allocation Primitives & Static Tables"]
        SIMD["src/finder/memchr.zig, ascii.zig, byteset.zig,<br/>frequency.zig, two_way.zig, unicode_fold.zig"]
        TBL["src/tables/gbk_table.zig &<br/>src/tables/unicode_case_table.zig"]
    end

    L5 --> L4
    L4 --> L3
    L4 --> L2
    L3 --> L1
    L2 --> L1
```

---

## 2. Module Inventory by Layer

### Layer 1: Zero-Allocation Primitives & Static Tables
- `src/tables/unicode_case_table.zig` & `src/tables/unicode_prop_table.zig`: Pure static lookup tables for Unicode Simple Case Folding (`FoldGroup`), Unicode General Category & Script properties (`\p{...}` / `\P{...}`), and UAX #29 Unicode word character ranges.
- `src/tables/gbk_table.zig`: Compact 24 KiB two-stage page index for GBK / GB2312 to Unicode codepoint decoding.
- `src/finder/memchr.zig`: 4-vector unrolled SIMD byte search (`find`, `rfind`, `findEither`, `findAny`, `countByte`).
- `src/finder/ascii.zig`, `src/finder/byteset.zig`, `src/finder/frequency.zig`, `src/finder/two_way.zig`: Branchless ASCII case folding, 16-bucket SIMD byte sets, empirical byte frequency ranks, and $O(n)$ Two-Way substring search.

### Layer 2: Pattern Matchers (`src/matcher.zig`, `src/finder/`, `src/regex/`)
- `src/matcher.zig`: Defines `Match` (with `pattern_id`), `MatchMode`, `FindOptions`, `MatcherTraits(M)`, `validateMatcher(M)`, and runtime type-erased `AnyMatcher`.
- `src/finder/finder.zig`, `src/finder/packed_pair.zig`, `src/finder/unicode_fold.zig`: Lock-free `*const Finder` single-pattern literal matcher with SIMD packed-pair filtering, adaptive `TwoWay` fallback, and SIMD-prefiltered Unicode case folding.
- `src/finder/multi.zig`, `src/finder/pairs.zig`, `src/finder/teddy*.zig`, `src/finder/aho.zig`: Lock-free `*const Multi` 4-tier multi-pattern OR engine (`ByteSet` -> `RarePair` -> `Teddy` -> `AhoCorasick`) reporting exact `pattern_id`.
- `src/regex.zig` & `src/regex/` (`inst.zig`, `compiler.zig`, `prefilter.zig`, `dfa.zig`, `vm.zig`, `set.zig`, `tests.zig`): Modular Hybrid Lazy DFA + lockstep Thompson NFA / PikeVM regular expression engine (`*const Regex`, `RegexScratch`), simultaneous multi-pattern `RegexSet`, and structured `CompileDiagnostic`.

### Layer 3: Streaming Codec & Source Contracts (`src/codec/`, `src/source.zig`, `src/sink.zig`)
- `src/codec/offset_map.zig`: Strongly-typed `SearchByteOffset` and `RawByteOffset` with collinear-slope-compacted sparse anchor mapping (`OffsetMap`).
- `src/codec/decompress.zig`: In-process streaming Gzip, Zstd, and XZ decompression with dual Zip-Bomb budgets (`max_decompressed_bytes` and `max_compression_ratio`).
- `src/codec/encoding.zig`: BOM sniffing and comptime-specialized transcoding (`UTF-8`, `UTF-16LE`, `UTF-16BE`, `GBK`, `Latin-1`).
- `src/codec/archive.zig`: Zero-disk-landing in-memory archive unpacker (`ArchiveTree`) for `.tar`, `.tar.gz`/`.tgz`, `.tar.zst`, `.tar.xz`, and `.zip` with Zip-Slip path traversal defense.
- `src/source.zig` & `src/sink.zig`: Defines virtual `Source` / `Memory` cursors and `Event`, `LineEvent`, `Result`, `Flow`, `AnyEventSink`, and `SinkTraits(S)`.

### Layer 4: Streaming Line Search Engine (`src/searcher.zig` & `src/search/`)
- `src/search/config.zig`: `SearchConfig`, `Scratch` reusable buffer pool, and multi-tenant hard caps.
- `src/search/state.zig`: Per-search mutable `State`, monotonic clock deadlines, byte budgets, and comptime matcher capability dispatch.
- `src/search/context_ring.zig`: Seek-free `BeforeRing` circular buffer and `previewLine` centering.
- `src/search/format.zig`: UTF-16 column calculation, non-overlapping match span collection (`pattern_id`), `$0`–`$9` regex capture expansion, and `sinkLine` formatting.
- `src/search/line_matcher.zig`: Core `matchBuffer`, `findLine`, `matchInvert`, `whole_word` / `whole_line` verification, and `contains` / `excludes` secondary filtering.
- `src/search/long_line.zig`: Constant-memory sliding window (`beginLong`, `pumpLong`, `finishLong`) for lines exceeding `max_line_len`.
- `src/search/pull.zig`: `EventBridge(S)` adapter, slice `SourcePull` (`openSourcePull`), and true streaming `ReaderPull` (`openReaderPull`).
- `src/search/pipeline.zig`: High-level `materialize`, `searchPrepared`, and `drive` streaming state machine.
- `src/search/tree.zig`: Virtual tree and archive search orchestrators (`TreeConfig`, `searchTree`, `searchArchiveSlice`, `searchArchive`).

### Layer 5: Multi-Source Pipeline, Public Facade, C ABI & Differential Fuzzing
- `src/walk/` (`glob.zig`, `ignore.zig`, `types.zig`, `file_id.zig`, `list_dir.zig`, `linux_getdents.zig`, `deque.zig`, `walker.zig`) & `src/parallel.zig`: Controlled work-stealing multi-source traversal and parallel search.
- `src/root.zig` & `src/c_api.zig` (`include/webgrep.h`): Public Zig API facade and zero-libc C ABI.
- `src/fuzz.zig` & `src/adversarial_probe_m5.zig`: Differential, property-based, and red-team adversarial verification suites (`zig build fuzz`).

---

## 3. Extensibility Guide

### 3.1 Adding a New Pattern Matcher (`MatcherTraits`)
Any pointer `*M` or `*const M` (or `AnyMatcher`) passed to `searchSlice`, `searchSourceSlice`, `searchSource`, `openSourcePull`, `openReaderPull`, or `searchTree` is validated at compile time by `validateMatcher(@TypeOf(matcher))` in `src/matcher.zig`.
- **Required**: `pub fn find(self: *const M, haystack: []const u8, start: usize, mode: MatchMode) ?Match`
- **Optional Zero-Cost Hooks** (automatically detected via `MatcherTraits(M)`):
  - `findWatched(self: *const M, haystack: []const u8, start: usize, mode: MatchMode, nul: *?usize) ?Match` — Fuses single-pass NUL binary detection.
  - `findAllowed(self: *const M, haystack: []const u8, start: usize, mode: MatchMode, comptime allow: fn ([]const u8, usize, usize) bool) ?Match` — Enables fast in-kernel `whole_word` boundary filtering.
  - `acceptsSpan(self: *const M, span: []const u8) bool` — Custom `whole_line` check.
  - `isMultiline(self: *const M) bool` and `multilineWindow(self: *const M) usize` — Enables cross-line matching windows.

### 3.2 Adding a New Character Encoding (`src/codec/encoding.zig`)
1. Add the enum tag to `Encoding` and `Sniff` in `src/codec/encoding.zig`.
2. Add the WHATWG/MIME aliases in `parseCharsetLabel`.
3. Add the decoding branch in `decodeStepMode` (which automatically specializes both the whole-slice `convertIntoWithMap` fast path and the streaming `Decoder.emitPending` state machine at `comptime`).

---

## 4. Zig `0.17.1` Idioms & Verification Commands

- **SIMD & Branch Hints**: Use `@Vector(width, u8)` with `@splat(...)` and annotate error/fallback branches with `@branchHint(.cold)` so hot loops remain compact in instruction cache.
- **Unmanaged Containers**: Prefer `std.ArrayList(T) = .empty` with explicit allocator passing.
- **Verification**:
  ```sh
  zig build test --summary all
  zig build fuzz --summary all
  zig build bench -Doptimize=ReleaseFast -Dteddy=avx2
  ```
