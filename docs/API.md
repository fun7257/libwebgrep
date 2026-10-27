# libwebgrep API Reference

[English](API.md) | [简体中文](API.zh-CN.md)

This document is the complete reference for all public declarations exported by `src/root.zig`. Importing the module as `@import("libwebgrep")` gives access to every type, function, and submodule documented below.

`libwebgrep` searches byte streams and in-memory slices provided by the caller. Entry points that allocate or perform I/O accept an explicit `std.mem.Allocator` and `std.Io`. Pure in-memory slice search requires neither. The library holds no mutable global state.

---

## Scope

`libwebgrep` is an embeddable, multi-tenant text and regular expression search engine library. The caller supplies bytes (via `*std.Io.Reader` or `[]const u8`) and an opaque `source_id`, and `libwebgrep` delivers structured events via callbacks or pull iteration.

- The public search API does not accept filesystem paths.
- The library does not spawn external processes.
- The library does not format terminal colors or serialize NDJSON; it returns exact half-open byte and UTF-16 code-unit spans so the caller can render or serialize them as needed.

See [Non-Goals](#non-goals) for capabilities intentionally excluded from the core engine.

---

## Entry Points

| Function | Input Type | Default Multi-Tenant Budgets | Delivery Model | Allocation Behavior |
| :--- | :--- | :--- | :--- | :--- |
| **`searchSourceSlice`** | `[]const u8` | Yes (auto-populated when `null`) | Push (`Event` callback) | Zero allocation when no transcoding/decompression is needed |
| **`searchSource`** | `*std.Io.Reader` | Yes (auto-populated when `null`) | Push (`Event` callback) | Rolling buffer + optional context/decode buffers (reusable via `scratch`) |
| **`resumeSourceSlice`** | `[]const u8` + `Result` | Yes (auto-populated when `null`) | Push (`Event` callback) | Same as `searchSourceSlice`, resumes from `previous.resume_at` |
| **`openSourcePull`** | `[]const u8` | Yes (auto-populated when `null`) | Pull (`SourcePull.next()`) | Copies event payloads into caller's `allocator` until `deinit()` |
| **`searchSlice`** | `[]const u8` | No (`null` means unbounded) | Legacy (`Line` callbacks) | Zero allocation when no transcoding/decompression is needed |
| **`searchReader`** | `*std.Io.Reader` | No (`null` means unbounded) | Legacy (`Line` callbacks) | Rolling buffer + optional context/decode buffers |

Matchers passed to any search function can be `*Finder` (single literal), `*Multi` (multi-literal OR), or `*Regex` (linear-time regular expression). Each search call invokes `matcher.resetStats()` at the start of a stream.

A service sink `S` implements:

```zig
pub fn event(self: *S, ev: libwebgrep.Event) libwebgrep.Flow // or bool
```

- Returning `true` or `Flow.cont` continues scanning.
- Returning `false` or `Flow.stop` stops scanning the current source and still emits `end`.
- Returning `Flow.pause` pauses immediately without emitting `end` or `summary` and sets `Result.paused = true`; pass that `Result` to `resumeSourceSlice` to continue from the exact byte offset without re-emitting `begin`.

Events are delivered synchronously one by one without batching multiple lines in memory. Borrowed slices are valid only until the callback returns.

### searchSourceSlice

```zig
pub fn searchSourceSlice(
    comptime S: type,
    sink: *S,
    source_id: []const u8,
    haystack: []const u8,
    matcher: anytype,
    config: SearchConfig,
) SliceError!Result
```

Searches an in-memory slice for a single source. Performs zero heap allocations when no BOM transcoding, decompression, or replacement preview buffer is needed. If transcoding or decompression is required on a slice, `SearchConfig.decode_allocator` must be provided (otherwise `error.OutOfMemory` is returned), and any temporary buffer is freed before `searchSourceSlice` returns.

`source_id` and `haystack` are borrowed from the caller and must remain valid for the duration of the call. Fatal configuration or allocation errors are returned as `SliceError` (`ContextLinesExceeded`, `OutOfMemory`, `DecodeLimit`, `BufferLimit`, `BudgetExceeded`). When scanning finishes without pause and without an open live stream, a final `summary` event is emitted.

### searchSource

```zig
pub fn searchSource(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    reader: *std.Io.Reader,
    source_id: []const u8,
    matcher: anytype,
    config: SearchConfig,
) ReadError!Result
```

Searches a `*std.Io.Reader` stream. `allocator` is used for the rolling read buffer, transcoding/decompression buffers, and the bounded before-context ring buffer, all of which are freed before returning unless `SearchConfig.scratch` is provided for buffer reuse across calls.

When `live` is false, a short read indicates EOF. On early termination (`exists`, `max_count`, `stop_on_nonmatch`, `cancel`, or `BinaryPolicy.quit`), `close_input` is invoked if configured so the caller can close the upstream stream.

Upstream read failures are reported as a per-source soft error (`Result.soft_error = .read_failed`) rather than aborting the request: `searchSource` still emits `end` and returns a valid `Result` containing no internal server paths.

### resumeSourceSlice

```zig
pub fn resumeSourceSlice(
    comptime S: type,
    sink: *S,
    source_id: []const u8,
    haystack: []const u8,
    matcher: anytype,
    config: SearchConfig,
    previous: Result,
) SliceError!Result
```

Resumes searching the same `haystack` slice from a paused `Result` (`previous.paused == true`). Restores `resume_from` from `previous.resume_at` along with all running counters in `previous.resume_state`, and does not re-emit `begin`.

### openSourcePull

```zig
pub fn openSourcePull(
    allocator: std.mem.Allocator,
    matcher: anytype,
    source_id: []const u8,
    haystack: []const u8,
    config: SearchConfig,
) searcher.SourcePull
```

Pull-based iterator over service events (`searcher.SourcePull`). The first call to `next()` executes `searchSourceSlice` and copies event payloads into `allocator` so that `source_id`, `bytes`, and `spans` remain valid until `SourcePull.deinit()`. Do not free individual events returned by `next()`; calling `pull.deinit()` frees all copied payloads at once.

### searchSlice

```zig
pub fn searchSlice(
    comptime S: type,
    sink: *S,
    haystack: []const u8,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) SliceError!Result
```

Legacy callback entry point over an in-memory slice. Does not populate default service budgets (`null` means unbounded) and does not force line numbers. `S` may define any subset of:
- `pub fn begin(self: *S, name: []const u8) bool`
- `pub fn matched(self: *S, line: Line) bool`
- `pub fn context(self: *S, line: Line) bool`
- `pub fn contextBreak(self: *S) bool`
- `pub fn binary(self: *S, offset: u64) bool`
- `pub fn finish(self: *S, result: Result) bool`
- `pub fn progress(self: *S, bytes_searched: u64, matches: u64, matched_lines: u64) bool`
- `pub fn heartbeat(self: *S, bytes_searched: u64, matches: u64, matched_lines: u64) bool`

### searchReader

```zig
pub fn searchReader(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    reader: *std.Io.Reader,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) ReadError!Result
```

Legacy callback entry point over a `*std.Io.Reader` stream without default service budgets. Prefer `searchSource` for service workloads.

### Flow

```zig
pub const Flow = enum { cont, pause, stop };
```

Flow control returned by service `event` callbacks:
- `cont`: Continue scanning.
- `pause`: Pause immediately, record `Result.resume_state` and `Result.resume_at`, and suppress `end` and `summary` so the caller can resume later via `resumeSourceSlice`.
- `stop`: Stop scanning this source and emit `end`.

### AnySink

Runtime-polymorphic wrapper for legacy sinks (`ctx: *anyopaque` and `vtable: *const AnySink.VTable`). Forwards `begin`, `matched`, `context`, `contextBreak`, `binary`, and `finish` to the vtable. Can be passed directly to `searchSlice` or `searchReader`.

### anyVtable

```zig
pub fn anyVtable(comptime S: type) AnySink.VTable
```

Constructs a `VTable` for legacy sink type `S` at comptime without heap allocation. Missing methods default to continuing the search.

### SliceIter

```zig
pub fn SliceIter(comptime M: type) type
```

Zero-allocation, context-free pull iterator over matched lines in a single slice:
```zig
var iter = libwebgrep.SliceIter(*libwebgrep.Finder){
    .matcher = &finder,
    .haystack = haystack,
    .mode = .earliest,
    .line_numbers = true,
};
while (iter.next()) |line| {
    // line.bytes points directly into haystack
}
```

---

## Sources

`source_id` is an opaque identifier assigned by the caller. `libwebgrep` never interprets it as a filesystem path and never frees it.

Borrowed slices are valid only until the callback returns. This applies to `bytes`, `text`, `raw`, `replaced`, `matches`, and `source_id`. If you need to retain line data after `event` returns, copy it inside the callback (or use `openSourcePull`).

Sources with zero matches still emit begin and end (`matched_lines = 0`, `matches = 0`, no `match` events), followed by `summary` when the request completes.

### source

Re-exports `src/source.zig`, an abstract virtual/in-memory tree interface (`Kind`, `Entry`, `VTable`, `Source`, `Node`, `Memory`) for testing and non-filesystem tree inputs. Public search entry points do not open or traverse `Source` automatically.

---

## Matching

`libwebgrep` provides three interchangeable matcher types (`Finder`, `Multi`, and `Regex`), all sharing the same matcher protocol.

Literal patterns (`Finder` and `Multi`) cannot contain `\n` (returning `error.PatternHasNewline` before scanning). An empty literal pattern `""` produces a zero-width match `[0, 0)` once per line.

Pattern count is capped at a server hard limit of `1024` (`pattern_count_hard_cap`), and total pattern bytes are capped at `256 KiB` (`pattern_bytes_hard_cap`). Exceeding either returns `error.PatternCountExceeded` or `error.PatternBytesExceeded` before allocating any tables.

Case matching defaults to `sensitive`. It uses ASCII case folding by default (`A-Z` and `a-z`); setting `FindOptions.unicode_case = true` enables Unicode Simple Case Folding in `Multi`.

Smart case is evaluated per pattern (`CaseMode.smart`): a pattern is matched case-insensitively only if that specific pattern contains no uppercase letters, and case-sensitively if it contains any uppercase letter.

### Finder

Single-literal SIMD finder (`src/finder/finder.zig`).

```zig
pub fn init(pattern: []const u8, options: FindOptions) !Finder
pub fn find(self: *Finder, haystack: []const u8, start: usize, mode: MatchMode) ?Match
pub fn findWatched(self: *Finder, haystack: []const u8, start: usize, mode: MatchMode, nul_at: *?usize) ?Match
pub fn acceptsSpan(self: *const Finder, span: []const u8) bool
pub fn requiredLiteral(self: *const Finder) ?RequiredLiteral
pub fn resetStats(self: *Finder) void
```

Zero heap allocation. `pattern` is borrowed from the caller and must outlive `Finder`. Combines frequency-ranked `PackedPair` 4-window SIMD filtering with worst-case linear-time `TwoWay` fallback and fused single-pass NUL detection (`findWatched`).

### finder

Re-exports `src/finder/finder.zig`, the definition module for `Finder`.

### Multi

Multi-literal OR SIMD search engine (`src/finder/multi.zig`).

```zig
pub fn init(allocator: std.mem.Allocator, patterns: []const []const u8, options: FindOptions) !Multi
pub fn initFromText(allocator: std.mem.Allocator, text: []const u8, options: FindOptions) !Multi
pub fn deinit(self: *Multi) void
pub fn find(self: *Multi, haystack: []const u8, start: usize, mode: MatchMode) ?Match
pub fn acceptsSpan(self: *const Multi, span: []const u8) bool
pub fn isEmpty(self: *const Multi) bool
pub fn engineName(self: *const Multi) []const u8
pub fn resetStats(self: *Multi) void
```

Automatically dispatches across four SIMD-accelerated engines based on pattern characteristics:
1. `ByteSet`: 4-way unrolled SIMD broadcast for single-byte patterns (`<= 16` folded bytes).
2. `RarePair`: Rare adjacent byte-pair SIMD hash prefilter (`<= 2` direct vector compare or `<= 8` hash buckets).
3. `Teddy`: 8-bucket Slim Teddy nibble-mask SIMD lookup (`vtbl` / `pshufb` / `vpshufb`) with 2-phase fingerprint verification (`<= 32` patterns).
4. `AhoCorasick`: Byte-equivalence-compressed dense DFA with 64-byte high-nibble bucket bitmap SIMD skip loop at `state == 0`.

`Multi.initFromText` splits newline-delimited pattern text (supporting both LF and CRLF, treating empty lines as empty pattern `""`) and validates count and byte limits before allocating tables. Once constructed, `Multi` is immutable and thread-safe to share across concurrent searches.

### multi

Re-exports `src/finder/multi.zig`, the definition module for `Multi`.

### Regex

Linear-time regular expression matcher (`src/regex.zig`).

```zig
pub fn init(allocator: std.mem.Allocator, pattern: []const u8, options: RegexOptions) !Regex
pub fn deinit(self: *Regex) void
pub fn find(self: *Regex, haystack: []const u8, start: usize, mode: MatchMode) ?Match
pub fn findWatched(self: *Regex, haystack: []const u8, start: usize, mode: MatchMode, nul_at: *?usize) ?Match
pub fn acceptsSpan(self: *Regex, span: []const u8) bool
pub fn requiredLiteral(self: *const Regex) ?RequiredLiteral
pub fn resetStats(self: *Regex) void
```

Supported regular expression syntax:
- Literals and escapes: `\d`, `\D`, `\w`, `\W`, `\s`, `\S`, `\n`, `\r`, `\t`, and escaped metacharacters `\.`, `\*`, `\+`, `\?`, `\(`, `\)`, `\[`, `\]`, `\{`, `\}`, `\|`, `\^`, `\$`, `\\`.
- Wildcard and anchors: `.` (any byte except `\n`, or including `\n` when `dot_all = true` and `multiline = true`), `^` (start of line/input), `$` (end of line/input).
- Character classes: `[a-z0-9_]`, negated `[^a-z]` or `[!a-z]`, and shorthand classes inside brackets.
- Quantifiers: `*`, `+`, `?`, `{m}`, `{m,}`, `{m,n}` (greedy).
- Alternation and grouping: `a|b`, `(expr)`, `(?:expr)`.

Executes lockstep Thompson NFA / PikeVM simulation where each NFA instruction is activated at most once per input byte, guaranteeing worst-case $O(n)$ time complexity and immunity to catastrophic backtracking (ReDoS). Enforces a server compile size hard cap (`inst_count_hard_cap = 4096`) and bounded multiline window cap (`multiline_window_hard_cap = 8 MiB`), returning `error.RegexTooLarge` before scanning if exceeded. Automatically extracts a `RequiredLiteral` from the AST and attaches a SIMD `Finder` prefilter.

### RegexOptions

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `case` | `CaseMode` | `.sensitive` | Case folding mode (ASCII case folding by default) |
| `multiline` | `bool` | `false` | Allows matches to span across `\n` within `max_multiline_window`, and makes `^`/`$` match line boundaries |
| `dot_all` | `bool` | `false` | When `true` alongside `multiline`, allows `.` to match `\n` |
| `max_inst` | `?usize` | `null` | Compiled NFA instruction cap (`null` uses hard cap `4096`) |
| `max_multiline_window` | `usize` | `64 * 1024` | Maximum byte span for a multiline match (`64 KiB` default, `8 MiB` hard cap) |

### regex

Re-exports `src/regex.zig`, the definition module for `Regex` and `RegexOptions`.

### MatchMode

- `.earliest`: Selects the match that finishes at the smallest `end` offset (breaking ties by smaller `start`, then earlier pattern index). Default mode.
- `.leftmost_first`: Selects the match with the smallest `start` offset (breaking ties by earlier pattern index). Matches `rg -F` submatch ordering.

### Match

Half-open byte range `{ start: usize, end: usize }` relative to the `haystack` slice passed to `find`.

### CaseMode

`sensitive`, `insensitive`, or `smart`. Uses ASCII case folding by default. Smart case is evaluated per pattern.

### FindOptions

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `case` | `CaseMode` | `.sensitive` | Case sensitivity mode (`sensitive`, `insensitive`, `smart`) |
| `unicode_case` | `bool` | `false` | Enables Unicode Simple Case Folding expansion in `Multi` |
| `frequency` | `?*const [256]u8` | `null` | Optional custom byte frequency rank table for anchor selection |
| `prefilter_fp_threshold` | `f32` | `0.80` | Threshold (`< 1.0` enables adaptive fallback to `TwoWay` on patterns `> 32` bytes) |
| `max_pattern_count` | `?usize` | `null` | Optional pattern count cap (clamped to hard cap `1024`) |
| `max_pattern_bytes` | `?usize` | `null` | Optional total pattern bytes cap (clamped to hard cap `256 KiB`) |

### matcher

Re-exports `src/matcher.zig`, defining `MatchMode`, `Match`, `RequiredLiteral`, `CaseMode`, `FindOptions`, `pattern_count_hard_cap` (`1024`), `pattern_bytes_hard_cap` (`256 KiB`), and `checkPatternLimits`.

### RequiredLiteral

`struct { bytes: []const u8, offset_in_match: usize }`. Used by `Searcher` to run SIMD literal prefiltering before invoking a general matcher.

### memchr

Re-exports `src/finder/memchr.zig`. Vectorized single-byte primitives (`find`, `findEither`, `findLast`, `count`, `findAny`) operating on 16-byte or 32-byte vectors with zero allocation.

### two_way

Re-exports `src/finder/two_way.zig`. Crochemore-Perrin worst-case linear-time substring search (`TwoWay.init(pattern, fold)` and `find(haystack, start)`) with zero allocation and ASCII case folding by default (`Fold.sensitive` or `Fold.ascii`).

---

## Lines and Encoding

Lines are delimited by `\n` (LF) by default, stripping the trailing `\n` and an immediately preceding `\r`. When `null_data` is `true`, records are delimited by NUL (`0x00`) without stripping `\r` and without treating NUL as binary.

Line numbers (`line_number`), byte columns (`column`), and UTF-16 code-unit columns (`u16_column`) are 1-based. `absolute_offset` is the 0-based byte offset in the decoded/searchable stream; `raw_offset` is the corresponding 0-based byte offset in the original compressed or un-transcoded input stream.

### Encoding

```zig
pub const Encoding = enum { auto, none, utf8, utf16le, utf16be, gbk, latin1 };
```

- `auto` (default): Sniffs UTF-8, UTF-16LE, and UTF-16BE BOMs at the start of the stream. If no BOM is present and `SearchConfig.charset` is provided (supporting WHATWG labels and HTTP `Content-Type` headers such as `"gbk"`, `"gb2312"`, `"utf-8"`, `"utf-16le"`, `"iso-8859-1"`, `"text/plain; charset=gbk"`), transcodes into UTF-8 automatically.
- `utf8`, `utf16le`, `utf16be`, `gbk`, `latin1`: Explicit input encoding.
- `none`: Disables BOM sniffing and transcoding.

### Compression

```zig
pub const Compression = enum { none, auto, gzip, zstd, xz };
```

In-process streaming decompression mode:
- `none` (default): No decompression.
- `auto`: Detects Gzip (`1F 8B`), Zstd (`28 B5 2F FD`), and XZ (`FD 37 7A 58 5A 00`) magic headers automatically.
- `gzip`, `zstd`, `xz`: Explicit format decompression.

Enforces both `max_decompressed_bytes` and `max_compression_ratio` (default `100:1`, hard cap `1000:1`) on every decompressed chunk to block Zip Bombs (`LimitHit.decompressed_bytes`). Corrupted compressed streams are handled gracefully as `SoftError.read_failed`.

### decompress

Re-exports `src/decompress.zig`, providing `Compression`, `OffsetMap`, `DecompressResult`, and `decompressSlice` for in-process bomb-safe streaming decompression and raw offset mapping.

---

## Binary Detection

Binary detection uses NUL byte heuristics fused into the SIMD search loop. Binary inputs are skipped by default (`BinaryPolicy.quit`).

- `quit` (default): Stops reading as soon as a NUL byte is encountered (`binary_status = .suppressed`, `outcome = .binary_quit`).
- `report`: Continues scanning until a match is confirmed without emitting line contents (`binary_status = .detected`, `outcome = .binary_matched`).
- `none`: Treats NUL as ordinary text bytes (`binary_status = .none`).

### BinaryPolicy

`quit`, `report`, or `none` (configured on `SearchConfig.binary`).

### BinaryStatus

`none`, `detected`, or `suppressed` (reported on `LineEvent`, `Line`, and `EndEvent`).

---

## Context

`context` sets symmetric before/after context line counts (default `0`), overridable individually via `before` and `after`. Before-context uses a bounded circular ring buffer without seeking; adjacent or overlapping context windows merge automatically and emit `context_break` when non-contiguous.

Context lines are capped at `SearchConfig.context_lines_hard_cap` (`10`), and the before-context buffer is capped by `max_before_bytes` (default `20 MiB`, hard cap `80 MiB`).

Setting `passthru = true` enables full-stream highlighting mode: all non-matching lines are emitted as `context` events and matching lines as `match` events, subject to `max_output_bytes`.

---

## Events

Service entry points deliver `Event` values synchronously:

### Event

```zig
pub const Event = union(enum) {
    begin: BeginEvent,
    match: LineEvent,
    context: LineEvent,
    context_break: ContextBreakEvent,
    progress: Progress,
    heartbeat: Heartbeat,
    end: EndEvent,
    summary: Summary,
};
```

### LineEvent

| Field | Type | Description |
| :--- | :--- | :--- |
| `source_id` | `[]const u8` | Caller-assigned opaque source identifier |
| `line_number` | `u64` | 1-based line number (or record number when `null_data = true`) |
| `column` | `?u64` | 1-based byte column of the first match (`null` when no match) |
| `u16_column` | `?u64` | 1-based UTF-16 code-unit column of the first match (`null` when no match) |
| `absolute_offset` | `u64` | 0-based byte offset of the line start in the searchable UTF-8 stream |
| `raw_offset` | `u64` | 0-based byte offset of the line start in the pre-transcode / pre-decompression raw stream |
| `bytes` | `[]const u8` | Searchable line bytes (borrowed, valid only until callback returns) |
| `text` | `[]const u8` | Valid UTF-8 text (invalid sequences replaced with `U+FFFD`) |
| `raw` | `[]const u8` | Raw line bytes |
| `replaced` | `?[]const u8` | Read-only preview line with matched spans replaced when `SearchConfig.replacement != null` |
| `matches` | `[]const Span` | Sorted, non-overlapping half-open match spans relative to `bytes` |
| `truncated` | `bool` | `true` if the line exceeded `max_line_len` and was windowed |
| `line_len` | `u64` | Original full line length in bytes prior to windowing |
| `window_start` | `u64` | Starting byte offset of `bytes` within the original line |
| `binary_status` | `BinaryStatus` | Binary status for this line (`none`, `detected`, `suppressed`) |

### Line

Legacy callback line struct (`searchSlice` / `searchReader`), carrying `bytes`, `text`, `raw`, `replaced`, `offset`, `raw_offset`, `number` (`?u64`), `match` (`?Match`), `matches` (`[]const Span`), `column`, `u16_column`, `binary_status`, `truncated`, `line_len`, and `window_start`.

### Span

| Field | Type | Description |
| :--- | :--- | :--- |
| `start` | `usize` | Inclusive 0-based start byte offset relative to `bytes` |
| `end` | `usize` | Exclusive 0-based end byte offset relative to `bytes` |
| `u16_start` | `usize` | Inclusive 0-based UTF-16 code-unit start offset on `text` |
| `u16_end` | `usize` | Exclusive 0-based UTF-16 code-unit end offset on `text` |
| `replacement` | `?[]const u8` | Replacement template slice when `SearchConfig.replacement != null` |

### EndEvent

| Field | Type | Description |
| :--- | :--- | :--- |
| `source_id` | `[]const u8` | Caller-assigned source identifier |
| `binary_status` | `BinaryStatus` | `none`, `detected`, or `suppressed` |
| `binary_offset` | `?u64` | Offset of the first NUL byte if seen |
| `matched_lines` | `u64` | Total matching lines emitted for this source |
| `matches` | `u64` | Total match spans found in this source |
| `bytes_read` | `u64` | Total searchable bytes processed |
| `outcome` | `Outcome` | `complete`, `stopped`, `binary_quit`, or `binary_matched` |
| `limit_hit` | `LimitHit` | Budget limit reached (`none` if completed normally) |
| `partial` | `bool` | `true` if a budget or cancellation stopped the scan before EOF |
| `resume_at` | `?u64` | Next searchable byte offset when stopped by `max_results` |
| `soft_error` | `?SoftError` | `read_failed` if an upstream I/O error occurred, otherwise `null` |

### Progress

`struct { source_id: []const u8, bytes_searched: u64, matches: u64, matched_lines: u64 }`. Emitted every `progress_interval` bytes scanned.

### Heartbeat

`struct { source_id: []const u8, bytes_searched: u64, matches: u64, matched_lines: u64 }`. Emitted on a live stream (`live = true`) when an idle read occurs after `idle_timeout_ns`.

### Summary

`struct { source_id: []const u8, elapsed: u64, searches: u64, searches_with_match: u64, bytes_searched: u64, bytes_printed: u64, matched_lines: u64, matches: u64, bytes_read_raw: u64, sources_failed: u64 }`. Emitted once when a request finishes completely without pause.

### Result

| Field | Type | Description |
| :--- | :--- | :--- |
| `outcome` | `Outcome` | `complete`, `stopped`, `binary_quit`, or `binary_matched` |
| `matched_lines` | `u64` | Number of matching lines |
| `matches` | `u64` | Total number of match spans |
| `binary_offset` / `nul_offset` | `?u64` | First NUL byte offset, if any |
| `bytes_read` | `u64` | Total bytes read |
| `bytes_searched` | `u64` | Total searchable bytes scanned |
| `output_bytes` | `u64` | Total line bytes delivered to the sink |
| `limit_hit` | `LimitHit` | Budget limit reached (`none`, `max_results`, `max_bytes`, `deadline`, `decompressed_bytes`, `cancelled`) |
| `partial` | `bool` | `true` if scanning stopped before EOF due to a budget or cancellation |
| `resume_at` | `?u64` | Byte offset to resume from when `limit_hit == .max_results` or `paused == true` |
| `soft_error` | `?SoftError` | `.read_failed` on upstream read failure, `null` otherwise |
| `paused` | `bool` | `true` when the callback returned `Flow.pause` |
| `scanned_all` | `bool` | `true` if the entire input was scanned to EOF |
| `elapsed_ns` | `u64` | Elapsed nanoseconds |
| `resume_state` | `ResumeState` | Saved counters consumed by `resumeSourceSlice` |

### Outcome

`complete`, `stopped`, `binary_quit`, or `binary_matched`.

### LimitHit

`none`, `max_results`, `max_bytes`, `deadline`, `decompressed_bytes`, or `cancelled`.

### SoftError

Per-source non-fatal error (`read_failed`), sanitized of any internal server paths.

### ResumeState

Internal state snapshot stored on `Result.resume_state` and consumed by `resumeSourceSlice` (`matched_lines`, `matches`, `bytes_read`, `bytes_searched`, `output_bytes`, `results_out`, `limit_count`, `line_number`, `started_ns`, `deadline_armed`, `skip_begin`).

---

## Budgets and Errors

All multi-tenant budgets are configured via `SearchConfig` and enforced deterministically without reading environment variables or global files.

### SearchConfig

| Field | Type | Struct Default | Service Default / Hard Cap | Description |
| :--- | :--- | :--- | :--- | :--- |
| `line_numbers` | `bool` | `false` | Forced `true` on service entry | Enables 1-based line numbers |
| `invert` | `bool` | `false` | `false` | Emits lines that do not match |
| `whole_word` | `bool` | `false` | `false` | Half-boundary ASCII word check (`[0-9A-Za-z_]`) |
| `whole_line` | `bool` | `false` | `false` | Requires entire line content to match |
| `contains` | `[]const []const u8` | `&.{}` | `&.{}` | Every listed literal must appear on the line (AND) |
| `excludes` | `[]const []const u8` | `&.{}` | `&.{}` | None of the listed literals may appear on the line (NOT) |
| `filter_case_insensitive` | `bool` | `false` | `false` | Enables ASCII case-insensitive matching for `contains` and `excludes` |
| `filter_smart_case` | `bool` | `false` | `false` | Enables per-filter smart-case matching for `contains` and `excludes` |
| `contains_regexes` | `[]const Regex` | `&.{}` | `&.{}` | Compiled regexes that must all match within the line (AND) |
| `excludes_regexes` | `[]const Regex` | `&.{}` | `&.{}` | Compiled regexes that must not match within the line (NOT) |
| `context` | `u32` | `0` | Hard cap `10` | Symmetric before/after context lines |
| `before` / `after` | `?u32` | `null` | Hard cap `10` | Asymmetric before/after context lines |
| `max_context_lines` | `?u32` | `null` | Hard cap `10` | Lowers maximum allowed context lines |
| `passthru` | `bool` | `false` | `false` | Emits all lines (`match` and `context`), bounded by `max_output_bytes` |
| `replacement` | `?[]const u8` | `null` | `null` | Read-only replacement preview template |
| `max_count` | `?u64` | `null` | Unbounded | Per-source matched line limit (`Outcome.stopped`) |
| `max_results` | `?u64` | `null` | Unbounded | Request-level matched line limit (populates `resume_at`) |
| `resume_from` | `u64` | `0` | `0` | Searchable byte offset to start/resume scanning from |
| `exists` | `bool` | `false` | `false` | Stops and closes upstream after emitting the first match |
| `files_without_match` | `bool` | `false` | `false` | Stops on first match without emitting lines |
| `stop_on_nonmatch` | `bool` | `false` | `false` | Stops and closes upstream on first non-matching line after a match |
| `binary` | `BinaryPolicy` | `.quit` | `.quit` | Binary handling (`quit`, `report`, `none`) |
| `null_data` | `bool` | `false` | `false` | Uses NUL (`0x00`) as record delimiter instead of LF |
| `encoding` | `Encoding` | `.auto` | `.auto` | BOM sniffing or explicit encoding (`utf8`, `utf16le/be`, `gbk`, `latin1`) |
| `charset` | `?[]const u8` | `null` | `null` | WHATWG or HTTP `Content-Type` charset hint |
| `compression` | `Compression` | `.none` | `.none` | In-process streaming decompression (`none`, `auto`, `gzip`, `zstd`, `xz`) |
| `max_compression_ratio` | `?u64` | `null` | Default `100`, Hard cap `1000` | Maximum decompression expansion ratio (`decompressed / raw`) |
| `decompressed_bytes` | `u64` | `0` | `0` | Prior decompressed bytes charged to this request |
| `max_decompressed_bytes` | `?u64` | `null` | Default `64 MiB` when compressed | Maximum decompressed bytes (`LimitHit.decompressed_bytes`) |
| `decode_allocator` | `?Allocator` | `null` | `null` | Allocator for slice transcoding/decompression/replacement preview |
| `buffer_size` | `usize` | `1 MiB` | `1 MiB` | Rolling stream read buffer size |
| `max_line_len` | `usize` | `2 MiB` | Hard cap `8 MiB` | Sliding window cap for ultra-long lines |
| `match_mode` | `MatchMode` | `.earliest` | `.earliest` | `.earliest` or `.leftmost_first` |
| `scratch` | `?*[]u8` | `null` | `null` | Reusable buffer pointer across streaming calls |
| `max_source_bytes` | `?u64` | `null` | Default `16 MiB`, Hard cap `64 MiB` | Max bytes scanned per source (`LimitHit.max_bytes`) |
| `max_request_bytes` | `?u64` | `null` | Default `16 MiB`, Hard cap `64 MiB` | Max bytes scanned per request (`LimitHit.max_bytes`) |
| `max_output_bytes` | `?u64` | `null` | Default `1 MiB`, Hard cap `8 MiB` | Max cumulative bytes emitted in line events |
| `time_budget_ns` | `?u64` | `null` | Default `30s`, Hard cap `120s` | Wall-clock deadline in nanoseconds (`LimitHit.deadline`) |
| `cancel` | `?*const Atomic(bool)` | `null` | `null` | Atomic cancellation token (`LimitHit.cancelled`) |
| `stop` | `?*const Atomic(bool)` | `null` | `null` | Cooperative stop flag between chunks |
| `max_before_bytes` | `?usize` | `null` | Default `20 MiB`, Hard cap `80 MiB` | Cap on before-context ring buffer |
| `max_decode_bytes` | `?usize` | `null` | Default `4 MiB`, Hard cap `8 MiB` | Cap on transcoding buffer |
| `max_queued_event_bytes` | `?usize` | `null` | Default `2 MiB`, Hard cap `8 MiB` | Cap on a single pending event payload |
| `max_concurrency` | `?u32` | `null` | Clamped to `32` | Caller-injected worker thread limit |
| `progress_interval` | `?u64` | `null` | `null` | Byte interval between `progress` events |
| `live` | `bool` | `false` | `false` | Treats 0-byte reads as idle stream rather than EOF |
| `idle_timeout_ns` | `?u64` | `null` | `null` | Idle duration before emitting `heartbeat` on a live stream |
| `live_closed` | `?*const Atomic(bool)` | `null` | `null` | Signals that a live stream has closed |
| `close_input` / `close_ctx` | `?fn` / `?*anyopaque` | `null` | `null` | Callback to close upstream on early termination |
| `clock` / `clock_ctx` | `?fn` / `?*anyopaque` | `null` | `null` | Custom monotonic clock hook for deterministic testing |
| `log` / `log_ctx` | `?fn` / `?*anyopaque` | `null` | `null` | Diagnostic log callback (never written to terminal) |

---

## Defaults

Service entry points (`searchSourceSlice`, `searchSource`, `resumeSourceSlice`, `openSourcePull`) populate safe multi-tenant defaults whenever budget fields are `null`:
- `line_numbers`: `true`
- `binary`: `BinaryPolicy.quit` (Binary inputs are skipped by default)
- `max_source_bytes` / `max_request_bytes`: `16 MiB` (hard cap `64 MiB`)
- `time_budget_ns`: `30s` (hard cap `120s`)
- `max_output_bytes`: `1 MiB` (hard cap `8 MiB`)
- `max_decode_bytes`: `4 MiB` (hard cap `8 MiB`)
- `max_before_bytes`: `20 MiB` (hard cap `80 MiB`)

---

## Non-Goals

To keep the core engine safe for multi-tenant server embedding:
- Single-source public search entry points only operate on caller-opened streams or slices; they do not open filesystem paths directly.
- Symlink following, parent-directory ignore traversal above the root, and global host ignore configuration are permanently disabled.
- Terminal color rendering and NDJSON transport serialization are left to the caller.

### sink_mod

Re-exports `src/sink.zig`, containing all event, line, and result definitions.

### searcher

Re-exports `src/searcher.zig`, containing `SearchConfig`, `SliceError`, `ReadError`, `PullEvent`, `SourcePull`, and the search entry points.

### walk_glob

Re-exports `src/walk/glob.zig`. Byte-oriented glob matcher supporting `*`, `?`, `**`, character classes `[a-z]` with `!`/`^` negation, nested brace expansion `{a,{b,c}}` (`expandBraces`, `compileGlobs`), `case_insensitive` matching (`classifyWithCase`, `matchTextCase`), later-rule precedence (`matchGlobs`), and server hard caps (`rule_count_hard_cap = 1024`, `rule_len_hard_cap = 4096`, `brace_depth_hard_cap = 8`).

### walk_ignore

Re-exports `src/walk/ignore.zig`. Parses and evaluates in-memory `.gitignore`, `.ignore`, and `.rgignore` rule sets (`parseLine`, `parseInto`, `parseTextsInto`, `parseLayerInto`, `build`, `isIgnored`) with fine-grained switches (`LayerSwitch`: `dot`, `vcs`, `exclude`, `case_insensitive`) without reading host environment variables or parent directories above the search root.

### walk_deque

Re-exports `src/walk/deque.zig`. Generic Chase-Lev work-stealing deque `Deque(T)` for pointer elements.

### walk_file_id

Re-exports `src/walk/file_id.zig`. Extracts device (`dev`) and inode (`ino`) identifiers from opened `std.Io.Dir` and `std.Io.File` handles to enforce `one_file_system`.

### walk_types

Re-exports `src/walk/types.zig`. Maps file type names (e.g. `zig`, `rust`, `py`, `ts`) to glob patterns, supporting caller-injected custom type tables (`findInTable`, `expandTypesToGlobs`, `matchesWithTable`).

### walk_list

Re-exports `src/walk/list_dir.zig`. Batched directory entry iterator (`Lister`) over an opened `std.Io.Dir`.

---

## Example

The code block below demonstrates:
1. Single-literal smart-case search with UTF-16 span inspection (`searchSourceSlice`).
2. Multi-literal OR search from newline-delimited pattern text (`Multi.initFromText`) and cursor pagination (`Flow.pause` + `resumeSourceSlice`).
3. Linear-time `Regex` search with read-only replacement preview (`SearchConfig.replacement`).
4. Streaming `*std.Io.Reader` search (`searchSource`) and pull-based iteration (`openSourcePull`).
5. Glob nested brace expansion (`walk_glob.compileGlobs`) and in-memory ignore rule matching (`walk_ignore`).

`build.zig` extracts this exact block and compiles and runs it during `zig build test`.

```zig
const std = @import("std");
const libwebgrep = @import("libwebgrep");

const Recorder = struct {
    saw_begin: bool = false,
    saw_end: bool = false,
    saw_summary: bool = false,
    matched_lines: usize = 0,
    first_u16_end: usize = 0,
    last_replaced: [64]u8 = undefined,
    last_replaced_len: usize = 0,
    pause_after_first: bool = false,

    pub fn event(self: *Recorder, ev: libwebgrep.Event) libwebgrep.Flow {
        switch (ev) {
            .begin => |b| {
                if (std.mem.eql(u8, b.source_id, "doc-1")) self.saw_begin = true;
            },
            .match => |m| {
                self.matched_lines += 1;
                if (m.matches.len > 0) {
                    self.first_u16_end = m.matches[0].u16_end;
                }
                if (m.replaced) |rep| {
                    const n = @min(rep.len, self.last_replaced.len);
                    @memcpy(self.last_replaced[0..n], rep[0..n]);
                    self.last_replaced_len = n;
                }
                if (self.pause_after_first and self.matched_lines == 1) {
                    return .pause;
                }
            },
            .end => |e| {
                if (e.soft_error == null) self.saw_end = true;
            },
            .summary => |s| {
                if (s.searches == 1 and s.searches_with_match == 1) self.saw_summary = true;
            },
            else => {},
        }
        return .cont;
    }
};

test "API documentation example" {
    const allocator = std.testing.allocator;

    // 1. Single-literal smart-case search on a slice
    var finder = try libwebgrep.Finder.init("needle", .{ .case = .smart });
    var recorder = Recorder{};
    const input = "first line\nhello NEEDLE world\nlast line\n";
    const result = try libwebgrep.searchSourceSlice(
        Recorder,
        &recorder,
        "doc-1",
        input,
        &finder,
        .{},
    );
    try std.testing.expectEqual(libwebgrep.Outcome.complete, result.outcome);
    try std.testing.expectEqual(libwebgrep.LimitHit.none, result.limit_hit);
    try std.testing.expect(!result.partial);
    try std.testing.expect(result.soft_error == null);
    try std.testing.expect(recorder.saw_begin);
    try std.testing.expect(recorder.saw_end);
    try std.testing.expect(recorder.saw_summary);
    try std.testing.expectEqual(@as(usize, 1), recorder.matched_lines);
    try std.testing.expectEqual(@as(usize, 12), recorder.first_u16_end);

    // 2. Multi-literal OR search + pause & resume pagination
    var many = try libwebgrep.Multi.initFromText(allocator, "WARN\nERROR\n", .{});
    defer many.deinit();
    var paged_sink = Recorder{ .pause_after_first = true };
    const log_slice = "WARN: disk 80%\nINFO: ok\nERROR: timeout\n";
    const first_page = try libwebgrep.searchSourceSlice(
        Recorder,
        &paged_sink,
        "log-1",
        log_slice,
        &many,
        .{},
    );
    try std.testing.expect(first_page.paused);
    try std.testing.expectEqual(@as(usize, 1), paged_sink.matched_lines);

    paged_sink.pause_after_first = false;
    const second_page = try libwebgrep.resumeSourceSlice(
        Recorder,
        &paged_sink,
        "log-1",
        log_slice,
        &many,
        .{},
        first_page,
    );
    try std.testing.expect(!second_page.paused);
    try std.testing.expectEqual(@as(u64, 2), second_page.matched_lines);

    // 3. Linear-time Regex search + read-only replacement preview
    var re = try libwebgrep.Regex.init(allocator, "ERR_[0-9]+", .{});
    defer re.deinit();
    var regex_sink = Recorder{};
    _ = try libwebgrep.searchSourceSlice(
        Recorder,
        &regex_sink,
        "regex-1",
        "code=ERR_404 found\n",
        &re,
        .{
            .replacement = "REDACTED",
            .decode_allocator = allocator,
        },
    );
    try std.testing.expectEqualStrings(
        "code=REDACTED found",
        regex_sink.last_replaced[0..regex_sink.last_replaced_len],
    );

    // 4. Streaming Reader search + Pull iterator
    var reader = std.Io.Reader.fixed("stream NEEDLE line\n");
    var stream_sink = Recorder{};
    const stream_res = try libwebgrep.searchSource(
        Recorder,
        allocator,
        &stream_sink,
        &reader,
        "stream-1",
        &finder,
        .{},
    );
    try std.testing.expectEqual(@as(u64, 1), stream_res.matched_lines);

    var pull = libwebgrep.openSourcePull(allocator, &finder, "pull-1", "pull NEEDLE\n", .{});
    defer pull.deinit();
    var pull_matches: usize = 0;
    while (try pull.next()) |ev| {
        if (ev.kind == .match) pull_matches += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), pull_matches);

    // 5. Glob nested brace expansion & in-memory ignore rules
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const globs = try libwebgrep.walk_glob.compileGlobs(
        arena,
        &.{ "*.{zig,{c,h}}", "!generated.c" },
        .{ .case_insensitive = true },
    );
    try std.testing.expect(libwebgrep.walk_glob.matchGlobs(globs, "src/MAIN.ZIG", "MAIN.ZIG", false));
    try std.testing.expect(!libwebgrep.walk_glob.matchGlobs(globs, "src/generated.c", "generated.c", false));
}
```
