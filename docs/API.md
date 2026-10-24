# libwebgrep API Reference

This document specifies all public declarations exported by `src/root.zig`. Importing the module as `@import("libwebgrep")` gives access to every symbol documented below.

`libwebgrep` searches byte streams and memory slices provided by the caller. Entry points that allocate or perform I/O accept an explicit `std.mem.Allocator` and `std.Io`. The library contains no mutable global state.

## Scope

`libwebgrep` is an embeddable, multi-tenant search engine library. The caller supplies bytes (via `std.Io.Reader` or `[]const u8`) and an opaque `source_id`, and `libwebgrep` delivers structured events via callbacks or pull iteration.

- The public search API does not accept filesystem paths.
- The library does not spawn external processes.
- The library does not format terminal colors or serialize NDJSON; it returns exact half-open byte and UTF-16 code-unit spans so the caller can render or serialize them as needed.

See [Non-Goals](#non-goals) for boundaries intentionally excluded from the core engine.

## Entry Points

The primary service entry points are `searchSourceSlice`, `searchSource`, `resumeSourceSlice`, and `openSourcePull`. They always enable 1-based line numbers and populate default multi-tenant budgets (scan bytes, wall-clock time budget, output bytes, decode buffer, and context buffer) whenever those fields are left `null`. Passing a value exceeding a server hard cap returns `error.BudgetExceeded` before scanning begins.

Legacy callback entry points (`searchSlice` and `searchReader`) do not apply default service budgets (`null` means unbounded for that limit) and use method callbacks (`begin`, `matched`, `context`, `finish`) instead of the unified `event` callback. New integrations should prefer the service entry points.

Matchers passed to any search function can be `*Finder`, `*Multi`, or `*Regex`. Each search call invokes `matcher.resetStats()` at the start of a stream.

A service sink `S` implements:

```text
pub fn event(self: *S, ev: Event) bool
```

or returns `Flow` (`Flow.cont`, `Flow.pause`, `Flow.stop`). Returning `true` or `Flow.cont` continues scanning. Returning `false` or `Flow.stop` stops scanning the current source and still emits `end`. Returning `Flow.pause` pauses immediately without emitting `end` or `summary` and sets `Result.paused = true`; pass that `Result` to `resumeSourceSlice` to continue from the exact byte offset without re-emitting `begin`.

Events are delivered synchronously one by one without batching multiple lines in memory. Borrowed slices are valid only until the callback returns.

### searchSourceSlice

```text
searchSourceSlice(S, sink, source_id, haystack, matcher, config) SliceError!Result
```

Searches an in-memory slice for a single source. Performs zero heap allocations when no BOM transcoding or decompression is required. If transcoding or decompression is required on a slice, `SearchConfig.decode_allocator` must be provided (otherwise `error.OutOfMemory` is returned), and any temporary buffer is freed before `searchSourceSlice` returns.

`source_id` and `haystack` are borrowed from the caller and must remain valid for the duration of the call.

Fatal configuration or allocation errors are returned as `SliceError` (`ContextLinesExceeded`, `OutOfMemory`, `DecodeLimit`, `BufferLimit`, `BudgetExceeded`). When scanning finishes without pause and without an open live stream, a final `summary` event is emitted.

### searchSource

```text
searchSource(S, allocator, sink, reader, source_id, matcher, config) ReadError!Result
```

Searches a `*std.Io.Reader` stream. `allocator` is used for the rolling read buffer, transcoding/decompression buffers, and the bounded before-context ring buffer, all of which are freed before returning unless `SearchConfig.scratch` is provided for buffer reuse across calls.

When `live` is false, a short read indicates EOF. On early termination (`exists`, `max_count`, `stop_on_nonmatch`, `cancel`, or `BinaryPolicy.quit`), `close_input` is invoked if configured so the caller can close the upstream stream.

Upstream read failures are reported as a per-source soft error (`Result.soft_error = .read_failed`) rather than aborting the request: `searchSource` still emits `end` and returns a valid `Result` containing no internal server paths.

### resumeSourceSlice

```text
resumeSourceSlice(S, sink, source_id, haystack, matcher, config, previous) SliceError!Result
```

Resumes searching the same `haystack` slice from a paused `Result` (`previous.paused == true`). Restores `resume_from` from `previous.resume_at` along with all running counters in `previous.resume_state`, and does not re-emit `begin`.

### openSourcePull

```text
openSourcePull(allocator, matcher, source_id, haystack, config) SourcePull
```

Pull-based iterator over service events (`searcher.SourcePull`). The first call to `next()` executes `searchSourceSlice` and copies event payloads into `allocator` so that `source_id`, `bytes`, and `spans` remain valid until `SourcePull.deinit()`.

### searchSlice

```text
searchSlice(S, sink, haystack, name, matcher, config) SliceError!Result
```

Legacy callback entry point over an in-memory slice. Does not populate default service budgets and does not force line numbers. `S` may define any subset of `pub fn begin`, `pub fn matched`, `pub fn context`, `pub fn contextBreak`, `pub fn binary`, `pub fn finish`, `pub fn progress`, and `pub fn heartbeat`.

### searchReader

```text
searchReader(S, allocator, sink, reader, name, matcher, config) ReadError!Result
```

Legacy callback entry point over a `*std.Io.Reader` stream without default service budgets. Prefer `searchSource` for service workloads.

### Flow

Flow control returned by service `event` callbacks: `cont` (continue), `pause` (pause and record `ResumeState`), or `stop` (stop scanning this source and emit `end`).

### AnySink

Runtime-polymorphic wrapper for legacy sinks (`ctx: *anyopaque` and `vtable: *const AnySink.VTable`). Forwards `begin`, `matched`, `context`, `contextBreak`, `binary`, and `finish` to the vtable.

### anyVtable

```text
anyVtable(S) AnySink.VTable
```

Constructs a `VTable` for legacy sink type `S` at comptime without heap allocation. Missing methods default to continuing the search.

### SliceIter

```text
SliceIter(M)
```

Zero-allocation, context-free pull iterator over matched lines in a single slice. `Line.bytes` points directly into `haystack`.

## Sources

`source_id` is an opaque identifier assigned by the caller. `libwebgrep` never interprets it as a filesystem path and never frees it.

Borrowed slices are valid only until the callback returns. This applies to `bytes`, `text`, `raw`, `replaced`, `matches`, and `source_id`. If you need to retain line data after `event` returns, copy it inside the callback (or use `openSourcePull`).

Sources with zero matches still emit begin and end (`matched_lines = 0`, `matches = 0`, no `match` events), followed by `summary` when the request completes.

### source

Re-exports `src/source.zig`, an abstract virtual/in-memory tree interface (`Kind`, `Entry`, `VTable`, `Source`, `Node`, `Memory`) for testing and non-filesystem tree inputs. Public search entry points do not open or traverse `Source` automatically.

## Matching

`libwebgrep` supports single-literal (`Finder`), multi-literal OR (`Multi`), and linear-time regular expression (`Regex`) matchers. Literal patterns cannot contain `\n` (returning `error.PatternHasNewline` before scanning). An empty literal pattern `""` produces a zero-width match `[0, 0)` once per line.

Pattern count is capped at a server hard limit of `1024` (`pattern_count_hard_cap`), and total pattern bytes are capped at `256 KiB` (`pattern_bytes_hard_cap`). Exceeding either returns `error.PatternCountExceeded` or `error.PatternBytesExceeded` before allocating any tables.

Case matching defaults to `sensitive`. It uses ASCII case folding by default (`A-Z` and `a-z`); setting `FindOptions.unicode_case = true` enables Unicode Simple Case Folding in `Multi`.

Smart case is evaluated per pattern (`CaseMode.smart`): a pattern is matched case-insensitively only if that specific pattern contains no uppercase letters, and case-sensitively if it contains any uppercase letter.

- **Whole-word matching (`whole_word`)**: Checks only whether the bytes immediately adjacent to the match span are ASCII word characters (`[0-9A-Za-z_]`), enabling non-word tokens such as `-2` to match inside `(-2)`.
- **Whole-line matching (`whole_line`)**: Requires the entire line (after stripping `\n` and an immediately preceding `\r`) to match. Takes precedence over `whole_word`.
- **Invert & chained filters (`invert`, `contains`, `excludes`)**: `invert` emits non-matching lines; `contains` requires every listed literal to appear on the line (AND); `excludes` rejects the line if any listed literal appears (NOT).
- **Early termination (`files_without_match`, `exists`, `stop_on_nonmatch`, `max_count`)**:
  - `files_without_match`: stops on the first match without emitting `match` events and invokes `close_input`.
  - `exists`: emits the first matching line, invokes `close_input`, and stops immediately.
  - `stop_on_nonmatch`: for ordered streams (e.g. timestamp-sorted logs), stops and invokes `close_input` as soon as the first non-matching line is encountered after at least one match.
  - `max_count`: stops after `N` matched lines in the current source (`Outcome.stopped`).
- **Read-only replacement preview (`replacement`)**: When set to a non-null template slice, populates `Span.replacement` and builds a read-only preview slice in `Line.replaced` / `LineEvent.replaced` without mutating input buffers.

Match spans within a line are non-overlapping, sorted by start offset, and half-open `[start, end)` relative to `bytes`.

### Finder

Single-literal SIMD finder (`src/finder/finder.zig`).

```text
Finder.init(pattern, options) !Finder
```

Zero heap allocation. Combines frequency-ranked `PackedPair` 4-window SIMD filtering with worst-case linear-time `TwoWay` fallback and fused single-pass NUL detection (`findWatched`).

### finder

Re-exports `src/finder/finder.zig`, the definition module for `Finder`.

### Multi

Multi-literal OR SIMD search engine (`src/finder/multi.zig`).

```text
Multi.init(allocator, patterns, options) !Multi
Multi.initFromText(allocator, text, options) !Multi
Multi.deinit(self)
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

```text
Regex.init(allocator, pattern, options) !Regex
Regex.deinit(self)
```

Executes lockstep Thompson NFA / PikeVM simulation where each NFA instruction is activated at most once per input byte, guaranteeing worst-case $O(n)$ time complexity and immunity to catastrophic backtracking (ReDoS). Enforces a server compile size hard cap (`inst_count_hard_cap = 4096`) and bounded multiline window cap (`multiline_window_hard_cap = 8 MiB`), returning `error.RegexTooLarge` before scanning if exceeded. Automatically extracts a `RequiredLiteral` from the AST and attaches a SIMD `Finder` prefilter.

### RegexOptions

Configuration for `Regex.init`:
- `case`: `CaseMode` (defaults to `sensitive`, ASCII case folding by default).
- `multiline`: defaults to `false`. When `true`, allows matching across `\n` within `max_multiline_window` and makes `^`/`$` match line boundaries.
- `dot_all`: defaults to `false`. When `true` with `multiline`, `.` matches `\n`.
- `max_inst`: optional instruction cap (clamped to `4096`).
- `max_multiline_window`: bounded multiline window cap in bytes (default `64 KiB`, hard cap `8 MiB`).

### regex

Re-exports `src/regex.zig`, the definition module for `Regex` and `RegexOptions`.

### MatchMode

`earliest` (match ending earliest wins) or `leftmost_first` (leftmost start offset wins, ties broken by earlier pattern index). Defaults to `earliest`.

### Match

Half-open byte range `{ start: usize, end: usize }` relative to the `haystack` slice passed to `find`.

### CaseMode

`sensitive`, `insensitive`, or `smart`. Uses ASCII case folding by default. Smart case is evaluated per pattern.

### FindOptions

Options for `Finder.init` and `Multi.init`:
- `case`: defaults to `sensitive`.
- `unicode_case`: defaults to `false` (ASCII case folding by default). When `true`, expands Unicode Simple Case Folding equivalents in `Multi`.
- `frequency`: optional custom `*[256]u8` byte frequency rank table.
- `prefilter_fp_threshold`: defaults to `0.80` for adaptive `TwoWay` fallback on patterns longer than 32 bytes.
- `max_pattern_count`, `max_pattern_bytes`: optional lower bounds below server hard caps.

### matcher

Re-exports `src/matcher.zig`, defining `MatchMode`, `Match`, `RequiredLiteral`, `CaseMode`, `FindOptions`, `pattern_count_hard_cap` (`1024`), `pattern_bytes_hard_cap` (`256 KiB`), and `checkPatternLimits`.

### RequiredLiteral

Contains `bytes: []const u8` and `offset_in_match: usize`. Used by `Searcher` to run SIMD literal prefiltering before invoking a general matcher.

### memchr

Re-exports `src/finder/memchr.zig`. Vectorized single-byte primitives (`find`, `findEither`, `findLast`, `count`, `findAny`) operating on 16-byte or 32-byte vectors with zero allocation.

### two_way

Re-exports `src/finder/two_way.zig`. Crochemore-Perrin worst-case linear-time substring search with zero allocation and ASCII case folding by default (`Fold.sensitive` or `Fold.ascii`).

## Lines and Encoding

Lines are delimited by `\n` (LF) by default, stripping the trailing `\n` and an immediately preceding `\r`. When `null_data` is `true`, records are delimited by NUL (`0x00`) without stripping `\r` and without treating NUL as binary.

Line numbers (`line_number`), byte columns (`column`), and UTF-16 code-unit columns (`u16_column`) are 1-based. `absolute_offset` is the 0-based byte offset in the decoded/searchable stream; `raw_offset` is the corresponding 0-based byte offset in the original compressed or un-transcoded input stream.

### Encoding

`auto` (default) sniffs UTF-8, UTF-16LE, and UTF-16BE BOMs at the start of the stream, or transcodes using `SearchConfig.charset` (supporting WHATWG labels and HTTP `Content-Type` headers such as `gbk`, `gb2312`, `utf-8`, `utf-16le`, `iso-8859-1`). Can also be set explicitly to `utf8`, `utf16le`, `utf16be`, `gbk`, `latin1`, or `none`.

### Compression

In-process streaming decompression mode: `none` (default), `auto` (magic-byte detection for Gzip, Zstd, and XZ), `gzip`, `zstd`, or `xz`. Enforces both `max_decompressed_bytes` and `max_compression_ratio` (default `100:1`, hard cap `1000:1`) on every decompressed chunk to block Zip Bombs (`LimitHit.decompressed_bytes`). Corrupted compressed streams are handled gracefully as `SoftError.read_failed`.

### decompress

Re-exports `src/decompress.zig`, providing `Compression`, `OffsetMap`, and bomb-safe streaming decompression utilities.

## Binary Detection

Binary detection uses NUL byte heuristics fused into the SIMD search loop. Binary inputs are skipped by default (`BinaryPolicy.quit`).

- `quit` (default): stops reading as soon as a NUL byte is encountered (`binary_status = .suppressed`, `outcome = .binary_quit`).
- `report`: continues scanning until a match is confirmed without emitting line contents (`binary_status = .detected`, `outcome = .binary_matched`).
- `none`: treats NUL as ordinary text bytes (`binary_status = .none`).

### BinaryPolicy

`quit`, `report`, or `none` (configured on `SearchConfig.binary`).

### BinaryStatus

`none`, `detected`, or `suppressed` (reported on `LineEvent`, `Line`, and `EndEvent`).

## Context

`context` sets symmetric before/after context line counts (default `0`), overridable individually via `before` and `after`. Before-context uses a bounded circular ring buffer without seeking; adjacent or overlapping context windows merge automatically and emit `context_break` when non-contiguous.

Context lines are capped at `SearchConfig.context_lines_hard_cap` (`10`), and the before-context buffer is capped by `max_before_bytes` (default `20 MiB`, hard cap `80 MiB`).

Setting `passthru = true` enables full-stream highlighting mode: all non-matching lines are emitted as `context` events and matching lines as `match` events, subject to `max_output_bytes`.

## Events

Service entry points deliver `Event` values synchronously:
- `begin`: `{ source_id }`
- `match`: `LineEvent`
- `context`: `LineEvent`
- `context_break`: `{ source_id }`
- `progress`: `Progress`
- `heartbeat`: `Heartbeat`
- `end`: `EndEvent`
- `summary`: `Summary`

### Event

Tagged union of all service events listed above.

### LineEvent

A matched or context line on service entry points, carrying `source_id`, `line_number`, `column`, `u16_column`, `absolute_offset`, `raw_offset`, `bytes`, `text`, `raw`, `replaced`, `matches` (`[]const Span`), `truncated`, `line_len`, `window_start`, and `binary_status`.

### Line

A matched or context line on legacy callbacks (`searchSlice` / `searchReader`).

### Span

Half-open byte range `[start, end)` within a line, plus precomputed UTF-16 code-unit endpoints `[u16_start, u16_end)` and optional `replacement` preview slice.

### EndEvent

Per-source completion event carrying `source_id`, `binary_status`, `binary_offset`, `matched_lines`, `matches`, `bytes_read`, `outcome`, `limit_hit`, `partial`, `resume_at`, and `soft_error`.

### Progress

Periodic progress snapshot carrying `source_id`, `bytes_searched`, `matches`, and `matched_lines`.

### Heartbeat

Live-stream idle notification carrying the same fields as `Progress`.

### Summary

Request-level completion summary carrying `source_id`, `elapsed`, `searches`, `searches_with_match`, `bytes_searched`, `bytes_printed`, `matched_lines`, `matches`, `bytes_read_raw`, and `sources_failed`.

### Result

Return value of all search functions: `outcome`, `matched_lines`, `matches`, `binary_offset`, `nul_offset`, `bytes_read`, `bytes_searched`, `output_bytes`, `limit_hit`, `partial`, `resume_at`, `soft_error`, `paused`, `scanned_all`, `elapsed_ns`, and `resume_state`.

### Outcome

`complete`, `stopped`, `binary_quit`, or `binary_matched`.

### LimitHit

`none`, `max_results`, `max_bytes`, `deadline`, `decompressed_bytes`, or `cancelled`.

### SoftError

Per-source non-fatal error (`read_failed`), sanitized of any internal server paths.

### ResumeState

Internal state snapshot stored on `Result.resume_state` and consumed by `resumeSourceSlice`.

## Budgets and Errors

All multi-tenant budgets are configured via `SearchConfig` and enforced deterministically without reading environment variables or global files:

- **Scan bytes**: `max_source_bytes` and `max_request_bytes` (default `16 MiB`, hard cap `64 MiB` on service entry points).
- **Wall-clock time budget**: `time_budget_ns` (default `30s`, hard cap `120s`), checked in both the read loop and line-matching loop.
- **Cancellation token**: `cancel: ?*const std.atomic.Value(bool)`, triggers `LimitHit.cancelled` and invokes `close_input`.
- **Result count**: `max_results`, halts with `LimitHit.max_results` and populates `resume_at` for cursor pagination.
- **Output bytes**: `max_output_bytes` (default `1 MiB`, hard cap `8 MiB`).
- **Memory caps**: `max_line_len` (default `2 MiB`, hard cap `8 MiB`), `max_before_bytes` (default `20 MiB`, hard cap `80 MiB`), `max_decode_bytes` (default `4 MiB`, hard cap `8 MiB`), `max_queued_event_bytes` (default `2 MiB`, hard cap `8 MiB`).
- **Decompression bomb protection**: `max_decompressed_bytes` and `max_compression_ratio` (default `100:1`, hard cap `1000:1`).

### SearchConfig

Unified configuration struct for all search entry points, containing the budget constants and behavior toggles described in the sections above.

## Defaults

Service entry points (`searchSourceSlice`, `searchSource`, `resumeSourceSlice`, `openSourcePull`) populate safe multi-tenant defaults whenever budget fields are `null`:
- `line_numbers`: `true`
- `binary`: `BinaryPolicy.quit` (Binary inputs are skipped by default)
- `max_source_bytes` / `max_request_bytes`: `16 MiB` (hard cap `64 MiB`)
- `time_budget_ns`: `30s` (hard cap `120s`)
- `max_output_bytes`: `1 MiB` (hard cap `8 MiB`)
- `max_decode_bytes`: `4 MiB` (hard cap `8 MiB`)
- `max_before_bytes`: `20 MiB` (hard cap `80 MiB`)

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

## Example

The code block below is extracted by `build.zig` and compiled and executed as `test "API documentation example"` during `zig build test`.

```zig
const std = @import("std");
const libwebgrep = @import("libwebgrep");

const Recorder = struct {
    saw_begin: bool = false,
    saw_end: bool = false,
    saw_summary: bool = false,
    matched_lines: usize = 0,
    first_u16_end: usize = 0,

    pub fn event(self: *Recorder, ev: libwebgrep.Event) libwebgrep.Flow {
        switch (ev) {
            .begin => |b| {
                if (std.mem.eql(u8, b.source_id, "doc-1")) self.saw_begin = true;
            },
            .match => |m| {
                if (std.mem.eql(u8, m.source_id, "doc-1") and
                    m.line_number == 2 and
                    std.mem.eql(u8, m.bytes, "hello NEEDLE world") and
                    m.matches.len == 1)
                {
                    self.matched_lines += 1;
                    self.first_u16_end = m.matches[0].u16_end;
                }
            },
            .end => |e| {
                if (e.matched_lines == 1 and e.soft_error == null) self.saw_end = true;
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
}
```
