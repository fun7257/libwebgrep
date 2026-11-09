# libwebgrep Feature Matrix & Security Boundaries

[English](FEATURES.md) | [简体中文](FEATURES.zh-CN.md)

`libwebgrep` is a high-performance, embeddable text and regular expression search engine written in pure Zig `0.17.1` with zero external dependencies and no `libc` requirement.

---

## 1. Feature Summary by Domain

| Domain | Capabilities Implemented |
| :--- | :--- |
| **Input & Streaming Sources** | Abstract `source_id` + `std.Io.Reader` / `[]const u8` entry points (`searchSource`, `searchSourceSlice`, `resumeSourceSlice`, `openSourcePull`); non-seekable streaming; newline-delimited pattern list parser (`Multi.initFromText`); in-process Gzip / Zstd / XZ streaming decompression (`src/codec/decompress.zig`) with dual Zip-Bomb caps |
| **SIMD Search & Regex Kernels** | Single-literal `Finder` (`PackedPair` + `TwoWay` fallback); 4-tier `Multi` OR engine (`ByteSet`, `RarePair`, `Teddy`, `AhoCorasick` with 64B nibble skip); modular linear-time Thompson NFA `Regex` (`src/regex/*`) with compile size hard cap, prefix/interior/tail/alternation SIMD prefilters, and bounded multiline windows; SIMD-prefiltered ASCII & Unicode Simple Case Folding (`src/finder/unicode_fold.zig` + `src/tables/unicode_case_table.zig`) |
| **Line Semantics & Filtering** | Half-boundary whole-word matching (`whole_word`, ASCII + Unicode word codepoints); whole-line matching (`whole_line`); invert match (`invert`); chained `contains` / `contains_regexes` (AND) and `excludes` / `excludes_regexes` (NOT) filters; ordered-stream early stop (`stop_on_nonmatch`); `max_count`, `exists`, and `files_without_match`; read-only replacement preview (`replacement` with `$0`–`$9` capture expansion) |
| **Line Framing & Encodings** | LF / CRLF line framing; NUL-delimited records (`null_data`); UTF-8 / UTF-16LE / UTF-16BE BOM sniffing; WHATWG / HTTP `charset` hint transcoding for GBK / GB2312 / Latin-1 (`src/codec/encoding.zig` + `src/tables/gbk_table.zig`); constant-memory sliding window for ultra-long lines (`src/search/long_line.zig`) |
| **Binary Detection** | Single-pass NUL byte detection fused into SIMD search loops (`quit`, `report`, `none`), reporting exact `binary_offset` and `binary_status` |
| **Bounded Context & Highlighting** | Seek-free circular ring buffer (`src/search/context_ring.zig`) for `before` context; `after` context counter; automatic contiguous window merging with structured `context_break` events; full-stream highlighting mode (`passthru`) |
| **Positions, UTF-16 & Offsets** | 1-based line numbers, byte columns, and UTF-16 columns (`u16_column`); half-open byte and UTF-16 spans (`u16_start`, `u16_end`); searchable stream `absolute_offset` and pre-transcode/pre-decompression `raw_offset` (`src/codec/offset_map.zig`) |
| **Events, Flow Control & Pagination** | Synchronous `begin`, `match`, `context`, `context_break`, `progress`, `heartbeat`, `end`, and `summary` events; `Flow.pause` backpressure and stateless cursor pagination (`resume_at` / `resumeSourceSlice`); live-stream idle heartbeats |
| **Multi-Tenant Budgets & Isolation** | Per-source & per-request byte caps, monotonic wall-clock `time_budget_ns`, atomic cancellation token (`cancel`), `max_results`, `max_output_bytes`, bounded context/decode/event memory buffers, and three-state error separation (`SoftError.read_failed` vs. no match vs. fatal error) without leaking server paths |
| **Multi-Source Pipeline & Filtering** | Byte globbing with nested brace expansion `{a,{b,c}}`, rule caps, and case-insensitive `iglob`; layered `.gitignore`/`.ignore`/`.rgignore` evaluation (with or without `.git`), in-memory rule injection (`ignore_texts`), and `dot`/`vcs`/`exclude` switches; injectable file-type tables (`expandTypesToGlobs`); fixed server max depth, entry budgets, controlled `max_concurrency` worker pool, and streaming per-source event delivery |
| **Extensibility & Verification** | Compile-time `MatcherTraits` (`validateMatcher`) and `SinkTraits` contracts; 205+ unit tests and cross-layer differential + `std.testing.Smith` fuzz suites (`src/fuzz.zig`, `zig build fuzz`) |

---

## 2. Hard Security & Architectural Boundaries

1. **Zero External Processes**: Never calls `execve`, `posix.spawn`, or external decompression binaries.
2. **Zero Backtracking Regex**: Never uses backtracking regex engines or PCRE bindings; every regex executes in strict $O(n)$ time.
3. **Zero Path Traversal & Symlink Following**: Public search entry points never accept filesystem paths; directory traversal never follows symlinks, never reads parent directories above the search root, and never reads global host configuration.
4. **Zero Host CPU Probing**: Concurrency is strictly governed by caller-supplied `max_concurrency` rather than probing host CPU cores.
5. **Zero Unbounded Buffering**: Events are streamed as each line and source completes; `libwebgrep` never buffers full result sets in memory for post-hoc sorting, and leaves terminal colorization and NDJSON wire serialization to the caller.
