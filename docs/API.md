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
| **`searchSourceRange`** | `RandomAccess` + `ByteRange` | Yes (auto-populated when `null`) | Push (`Event` callback) | Positional reads restricted to `[start, end)` without reading outside the range |
| **`searchSourceReverseSlice`** | `[]const u8` | Yes (auto-populated when `null`) | Push (`Event` callback) | Reverse tail scan emitting matches newest-first |
| **`searchSourceReverseAt`** | `RandomAccess` | Yes (auto-populated when `null`) | Push (`Event` callback) | `O(tail)` reverse positional reads emitting matches newest-first |
| **`resumeSourceSlice`** | `[]const u8` + `Result` | Yes (auto-populated when `null`) | Push (`Event` callback) | Same as `searchSourceSlice`, resumes from `previous.resume_at` |
| **`openSourcePull`** | `[]const u8` | Yes (auto-populated when `null`) | Pull (`SourcePull.next()`) | Copies event payloads into caller's `allocator` until `deinit()` |
| **`searchSlice`** | `[]const u8` | No (`null` means unbounded) | Legacy (`Line` callbacks) | Zero allocation when no transcoding/decompression is needed |
| **`searchReader`** | `*std.Io.Reader` | No (`null` means unbounded) | Legacy (`Line` callbacks) | Rolling buffer + optional context/decode buffers |
| **`searchRange`** | `RandomAccess` + `ByteRange` | No (`null` means unbounded) | Legacy (`Line` callbacks) | Positional reads restricted to `[start, end)` |
| **`searchReverseSlice`** | `[]const u8` | No (`null` means unbounded) | Legacy (`Line` callbacks) | Reverse tail scan emitting matches newest-first |
| **`searchReverseAt`** | `RandomAccess` | No (`null` means unbounded) | Legacy (`Line` callbacks) | `O(tail)` reverse positional reads emitting matches newest-first |

Matchers passed to any search function can be `*Finder` (single literal), `*Multi` (multi-literal OR), `*Regex` (linear-time regular expression), `*RegexSet` (multi-regex set), or `AnyMatcher`. Each search call invokes `matcher.resetStats()` at the start of a stream.

A service sink `S` implements:

```zig
pub fn event(self: *S, ev: libwebgrep.Event) libwebgrep.Flow // or bool, or libwebgrep.FlowAction
```

- Returning `true`, `Flow.cont`, or `FlowAction.cont` continues scanning.
- Returning `Flow.skipTo(target_offset)` (`FlowAction{ .skip_to = target_offset }`) jumps directly to `target_offset` in the searchable stream (using `read_at`/`seek_input` when available, or draining unseekable streams without scanning skipped bytes).
- Returning `false`, `Flow.stop`, or `FlowAction.stop` stops scanning the current source and still emits `end`.
- Returning `Flow.pause` or `FlowAction.pause` pauses immediately without emitting `end` or `summary` and sets `Result.paused = true`; pass that `Result` to `resumeSourceSlice` or `resumeSource` to continue from the exact byte offset without re-emitting `begin`.

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

Resumes searching the same `haystack` slice from a paused `Result` (`previous.paused == true`). Restores `resume_from` from `previous.resume_at` along with all running counters in `previous.resume_state`, and does not re-emit `begin`. When `haystack` uses an uncompressed character encoding (`utf16le`, `utf16be`, `gbk`, `latin1`), only the unsearched raw tail starting at `previous.resume_state.raw_resume_at` is transcoded.

### resumeSource

```zig
pub fn resumeSource(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    reader: *std.Io.Reader,
    source_id: []const u8,
    matcher: anytype,
    config: SearchConfig,
    previous: Result,
) ReadError!Result
```

Resumes searching a `*std.Io.Reader` from a paused `Result` (`previous.paused == true`) without re-emitting `begin`.

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

### searchRange

```zig
pub fn searchRange(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    source: RandomAccess,
    range: ByteRange,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) ReadError!Result
```

Legacy callback entry point that searches `range` (`[start, end)`) over a handle-free `RandomAccess` source using positional `read_at` calls without reading bytes outside `[start, end)` (except local line alignment when `range_align_lines = true`).

### searchSourceRange

```zig
pub fn searchSourceRange(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    source: RandomAccess,
    range: ByteRange,
    source_id: []const u8,
    matcher: anytype,
    config: SearchConfig,
) ReadError!Result
```

Service entry point that searches `range` (`[start, end)`) over a handle-free `RandomAccess` source with default multi-tenant budgets. When `range` completes normally without hitting a budget, `Result.limit_hit` is `.none` and `Result.partial` is `false`.

### searchReverseSlice

```zig
pub fn searchReverseSlice(
    comptime S: type,
    sink: *S,
    haystack: []const u8,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) SliceError!Result
```

Legacy callback entry point that scans `haystack` (or `config.byte_range`) backward from the tail in bounded chunks, emitting matching lines newest-first (highest byte offset first).

### searchSourceReverseSlice

```zig
pub fn searchSourceReverseSlice(
    comptime S: type,
    sink: *S,
    source_id: []const u8,
    haystack: []const u8,
    matcher: anytype,
    config: SearchConfig,
) SliceError!Result
```

Service entry point for reverse tail search over an in-memory slice. When stopped by `max_results` or `Flow.pause`, `Result.resume_at` holds the byte offset of the last emitted line so the next page can continue backward with `byte_range = .{ .start = 0, .end = prev.resume_at }`.

### searchReverseAt

```zig
pub fn searchReverseAt(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    source: RandomAccess,
    name: []const u8,
    matcher: anytype,
    config: SearchConfig,
) ReadError!Result
```

Legacy callback entry point that scans backward from the end of `source` (or `config.byte_range`) in `O(tail)` positional reads without scanning from byte 0.

### searchSourceReverseAt

```zig
pub fn searchSourceReverseAt(
    comptime S: type,
    allocator: std.mem.Allocator,
    sink: *S,
    source: RandomAccess,
    source_id: []const u8,
    matcher: anytype,
    config: SearchConfig,
) ReadError!Result
```

Service entry point for `O(tail)` reverse search over a `RandomAccess` source with default multi-tenant budgets.

### Flow

```zig
pub const Flow = enum {
    cont,
    pause,
    stop,
    pub fn skipTo(target_offset: u64) FlowAction
};
```

Flow control returned by service `event` callbacks:
- `cont`: Continue scanning.
- `pause`: Pause immediately, record `Result.resume_state` and `Result.resume_at`, and suppress `end` and `summary` so the caller can resume later via `resumeSourceSlice` or `resumeSource`.
- `stop`: Stop scanning this source and emit `end`.
- `Flow.skipTo(target_offset)`: Returns `FlowAction{ .skip_to = target_offset }` to jump to `target_offset` within the current source.

### FlowAction

```zig
pub const FlowAction = union(enum) {
    cont,
    pause,
    stop,
    skip_to: u64,
};
```

Extended flow control action union returned by `event` (or legacy `matched` / `begin`) callbacks. Forward searches ignore `skip_to` targets at or behind the current cursor and advance directly via slice indexing, buffered jumps, `read_at`/`seek_input`, or unseekable stream draining; reverse searches jump backward to `target < current_line_offset`. When jumping across uncounted bytes without an explicit line number, `line_number_known` automatically transitions to `false` under `LineNumberMode.auto`.

### AnySink

Runtime-polymorphic wrapper for legacy sinks (`ctx: *anyopaque` and `vtable: *const AnySink.VTable`). Forwards `begin`, `matched`, `context`, `contextBreak`, `binary`, and `finish` to the vtable. Can be passed directly to `searchSlice` or `searchReader`.

### anyVtable

```zig
pub fn anyVtable(comptime S: type) AnySink.VTable
```

Constructs a `VTable` for legacy sink type `S` at comptime without heap allocation. Missing methods default to continuing the search.

### AnyEventSink

Runtime-polymorphic wrapper for service event sinks (`ctx: *anyopaque` and `action_fn: *const fn (ctx: *anyopaque, ev: Event) FlowAction`), allowing heterogeneous `Event` sinks (`searchSourceSlice`, `searchSource`, `searchTree`, `searchArchiveSlice`) to share a single monomorphized pipeline instance (`AnyEventSink.init(S, &sink)` or `AnyEventSink.from(&sink)`).

### PullEvent

Owned event structure yielded by `SourcePull.next()` and `ReaderPull.next()`. Holds `kind` (`begin`, `match`, `context`, `context_break`, `progress`, `heartbeat`, `end`, `summary`), `source_id`, `line_number`, `column`, `u16_column`, `absolute_offset`, `raw_offset`, `bytes`, `replaced`, `spans` (carrying `pattern_id`), and completion metadata. All slices remain valid until `deinit()` on the pull iterator.

### SourcePull

```zig
pub fn SourcePull(comptime M: type) type
```

Pull-based iterator over service events for an in-memory slice, created via `openSourcePull`.

### ReaderPull

```zig
pub fn ReaderPull(comptime M: type) type
```

True streaming pull-based state machine over a `*std.Io.Reader`, created via `openReaderPull`. Reads chunks on demand as `next()` is called, supporting in-process streaming decompression (`gzip`, `zstd`, `xz`, `auto`), BOM/charset transcoding, and bounded context without buffering the entire stream in memory.

### openReaderPull

```zig
pub fn openReaderPull(
    allocator: std.mem.Allocator,
    matcher: anytype,
    source_id: []const u8,
    reader: *std.Io.Reader,
    config: SearchConfig,
) ReadError!ReaderPull(@TypeOf(matcher))
```

Opens a streaming pull iterator (`ReaderPull`) over `reader`. Each call to `pull.next()` advances the streaming state machine until the next `PullEvent` is produced or EOF is reached (`null`). Call `pull.deinit()` to release all streaming and event buffers.

### Scratch

```zig
pub const Scratch = struct {
    allocator: std.mem.Allocator,
    // ...
    pub fn init(allocator: std.mem.Allocator) Scratch
    pub fn deinit(self: *Scratch) void
    pub fn reset(self: *Scratch) void
};
```

Reusable per-worker scratch buffer pool (`SearchConfig.scratch_pool`). Retains allocated capacities for rolling stream buffers, UTF-8 transcoding buffers, replacement preview buffers, match span arrays, and before-context ring buffers across searches so steady-state multi-source or multi-request workers perform zero heap allocations.

### SliceIter

```zig
pub fn SliceIter(comptime M: type) type
```

Zero-allocation, context-free pull iterator over matched lines in a single slice:
```zig
var iter = libwebgrep.SliceIter(*const libwebgrep.Finder){
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

Borrowed slices are valid only until the callback returns. This applies to `bytes`, `text`, `raw`, `replaced`, `matches`, and `source_id`. If you need to retain line data after `event` returns, copy it inside the callback (or use `openSourcePull` / `openReaderPull`).

Sources with zero matches still emit begin and end (`matched_lines = 0`, `matches = 0`, no `match` events), followed by `summary` when the request completes.

### source

Re-exports `src/source.zig`, an abstract virtual/in-memory tree interface (`Kind`, `Entry`, `VTable`, `Source`, `Node`, `Memory`) for virtual trees and unpacked archives. `Node` carries optional `mtime: ?i64 = null` Unix modification timestamps, and `Memory` maintains per-handle read/list cursors, supports slot reuse on `close`, and rejects `..` path traversal.

### probe

Re-exports `src/probe.zig`, providing handle-free `RandomAccess` and O(line) byte-offset line extraction (`ProbeOptions`, `LineProbe`, `probeLineSlice`, `probeLineAtBuf`, `probeLineAt`).

### RandomAccess

```zig
pub const RandomAccess = struct {
    ctx: ?*anyopaque = null,
    read_at: *const fn (?*anyopaque, u64, []u8) anyerror!usize,
    size: ?u64 = null,
    pub fn readAt(self: RandomAccess, offset: u64, dest: []u8) anyerror!usize
    pub fn readAtFull(self: RandomAccess, offset: u64, dest: []u8) anyerror!usize
    pub fn fromSlice(slice: *const []const u8) RandomAccess
};
```

Handle-free, path-free positional byte reader abstraction used by `probeLineAt*`, `searchRange`, `searchSourceRange`, `searchReverseAt`, `searchSourceReverseAt`, `ZstdSeekTable`, and `GzipIndex`.

### ProbeOptions

Configuration for byte-offset line probing (`delimiter: u8 = '\n'`, `strip_crlf: bool = true`, `max_line_bytes: usize = 2 MiB`, `window_chunk_bytes: usize = 4096`).

### LineProbe

Extracted line or bounded window enclosing a probed `offset` (`start_offset`, `end_offset`, `raw_end_offset`, `bytes`, `truncated_left`, `truncated_right`, `owned`, `deinit`). Guarantees the partition invariant `start_offset <= offset < raw_end_offset`.

### probeLineSlice

```zig
pub fn probeLineSlice(haystack: []const u8, offset: u64, options: ProbeOptions) ?LineProbe
```

Zero-allocation byte-offset line probe over an in-memory `haystack` slice (`null` if empty or `offset >= haystack.len`).

### probeLineAtBuf

```zig
pub fn probeLineAtBuf(source: RandomAccess, offset: u64, buf: []u8, options: ProbeOptions) !?LineProbe
```

Zero-heap-allocation byte-offset line probe over `RandomAccess`, writing extracted bytes into caller-supplied `buf`.

### probeLineAt

```zig
pub fn probeLineAt(allocator: std.mem.Allocator, source: RandomAccess, offset: u64, options: ProbeOptions) !?LineProbe
```

Allocator-backed byte-offset line probe over `RandomAccess`. Call `lp.deinit(allocator)` to release `owned`.

### seekable

Re-exports `src/codec/seekable.zig`, providing seekable compressed random access over Zstandard Seekable Format streams (`ZstdSeekTable`, `SeekableZstdReader`, `compressSeekableZstdAlloc`) and multi-member / multi-block Gzip streams (`GzipIndex`, `IndexedGzipReader`, `compressMultiMemberGzipAlloc`).

### ZstdSeekTable

Parses (`parseFromSlice`, tail-only `parseFromRandomAccess`), builds (`buildFromSlice`), serializes (`serializeAlloc`), binary-searches (`locateOffset` in `O(log F)`), and reads (`readAt`) Zstandard Seekable Format (`0x184D2A5E` / `0x8F92EAB1`) streams with XXH64 checksum verification and decompression-ratio guards.

### SeekableZstdReader

```zig
pub const SeekableZstdReader = struct {
    pub fn init(allocator: std.mem.Allocator, source: RandomAccess, table: *const ZstdSeekTable) SeekableZstdReader
    pub fn readAt(self: *const SeekableZstdReader, uncomp_offset: u64, dest: []u8) anyerror!usize
    pub fn randomAccess(self: *const SeekableZstdReader) RandomAccess
};
```

Adapter wrapping a parsed `ZstdSeekTable` and a compressed `RandomAccess` source into an uncompressed `RandomAccess` view for `probeLineAt`, `searchSourceRange`, and `searchSourceReverseAt`.

### GzipIndex

Pure-Zig RFC 1951/1952 multi-member Gzip & Deflate block checkpoint index (`buildFromSlice`, streaming `buildFromReader`, CRC32-protected `serializeAlloc` / `deserialize`, `O(log C)` `locateOffset`, and checkpoint-resuming `readAt`).

### IndexedGzipReader

```zig
pub const IndexedGzipReader = struct {
    pub fn init(allocator: std.mem.Allocator, source: RandomAccess, index: *const GzipIndex) IndexedGzipReader
    pub fn readAt(self: *const IndexedGzipReader, uncomp_offset: u64, dest: []u8) anyerror!usize
    pub fn randomAccess(self: *const IndexedGzipReader) RandomAccess
};
```

Adapter wrapping a `GzipIndex` and a compressed `RandomAccess` source into an uncompressed `RandomAccess` view for `probeLineAt`, `searchSourceRange`, and `searchSourceReverseAt`.

### archive

Re-exports `src/codec/archive.zig`, providing zero-disk-landing in-memory archive unpacking (`ArchiveFormat`, `ArchiveEntryMeta`, `ArchiveOptions`, `ArchiveError`, `ArchiveTree`) for `.tar` (USTAR, GNU `@LongLink`, PAX `path=`/`size=`), `.tar.gz`/`.tgz`, `.tar.zst`, `.tar.xz`, and `.zip` (Store & Deflate).

### ArchiveFormat

```zig
pub const ArchiveFormat = enum { auto, tar, tar_gz, tar_zst, tar_xz, zip };
```

Archive container format selector (`auto` sniffs magic bytes for `.zip`, `.tar.gz`, `.tar.zst`, `.tar.xz`, and `.tar`).

### ArchiveEntryMeta

```zig
pub const ArchiveEntryMeta = struct {
    path: []const u8,
    kind: source.Kind,
    size: u64,
    compressed_size: u64,
    mtime: ?i64 = null,
};
```

Sanitized archive entry metadata passed to `ArchiveOptions.entry_filter` strictly before decompression, payload allocation, or entry/byte quota accounting.

### ArchiveOptions

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `format` | `ArchiveFormat` | `.auto` | Container format or automatic magic-byte detection |
| `max_entries` | `usize` | `10_000` | Maximum files/directories allowed (`error.ArchiveLimit`) |
| `max_entry_bytes` | `u64` | `64 MiB` | Maximum uncompressed bytes for a single entry (`error.ArchiveLimit`) |
| `max_total_bytes` | `u64` | `256 MiB` | Maximum total uncompressed bytes across the archive (`error.ArchiveLimit`) |
| `max_compression_ratio` | `u64` | `100` | Maximum decompression expansion ratio (`error.ArchiveLimit`) |
| `entry_filter` / `entry_filter_ctx` | `?fn` / `?*anyopaque` | `null` | Optional pre-decompression callback `(ctx, ArchiveEntryMeta) -> bool`; returning `false` skips the entry before decompression and quota checks |

### ArchiveError

`error{ UnsupportedFormat, CorruptArchive, ArchiveLimit, PathTraversal, OutOfMemory }`. Any entry containing `..` components, backslashes `\`, Windows drive prefixes (`C:`), or NUL bytes is rejected with `error.PathTraversal` (Zip-Slip defense). Symlink, hardlink, FIFO, and device entries are safely skipped.

### ArchiveTree

```zig
pub const ArchiveTree = struct {
    pub fn initFromSlice(allocator: std.mem.Allocator, bytes: []const u8, options: ArchiveOptions) ArchiveError!ArchiveTree
    pub fn initFromReader(allocator: std.mem.Allocator, reader: *std.Io.Reader, options: ArchiveOptions) ArchiveError!ArchiveTree
    pub fn deinit(self: *ArchiveTree) void
    pub fn source(self: *ArchiveTree) source.Source
};
```

Unpacks an archive from a slice or stream into an arena-backed `source.Memory` virtual tree without touching the host disk. Call `tree.source()` to obtain a `source.Source` handle for `searchTree`.

### tree

Re-exports `src/search/tree.zig`, providing `TreeConfig`, `searchTree`, `searchArchiveSlice`, and `searchArchive`.

### TreeConfig

Configures virtual tree and archive search (`search: SearchConfig`, `archive: ArchiveOptions`, `globs`, `iglobs`, `iglob`, `types`, `types_not`, `custom_types`, `ignore_texts`, `respect_gitignore`, `respect_ignore`, `respect_rgignore`, `hidden`, `skip_git`, `max_depth`, `max_entries`, `max_filesize`, `max_concurrency`, `max_glob_rules`, `max_glob_rule_len`, `max_glob_brace_depth`, and `files`).

### searchTree

```zig
pub fn searchTree(
    comptime S: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: *S,
    src: source.Source,
    root_path: []const u8,
    matcher_ptr: anytype,
    config: TreeConfig,
) !Summary
```

Searches a virtual `source.Source` tree starting at `root_path`, hierarchical `.gitignore`/`.ignore`/`.rgignore` files inside the virtual tree, glob/type filters, and aggregate request budgets (`max_results`, `max_request_bytes`, `max_decompressed_bytes`, `time_budget_ns`). Does not accept `std.Io.File` or `std.Io.Dir`.

### searchArchiveSlice

```zig
pub fn searchArchiveSlice(
    comptime S: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: *S,
    archive_bytes: []const u8,
    matcher_ptr: anytype,
    config: TreeConfig,
) !Summary
```

Unpacks `archive_bytes` into an in-memory `ArchiveTree` and searches all matching entries via `searchTree` with zero disk landing.

### searchArchive

```zig
pub fn searchArchive(
    comptime S: type,
    allocator: std.mem.Allocator,
    io: std.Io,
    sink: *S,
    reader: *std.Io.Reader,
    matcher_ptr: anytype,
    config: TreeConfig,
) !Summary
```

Unpacks an archive stream from `reader` into an in-memory `ArchiveTree` and searches all matching entries via `searchTree`.

---

## Matching

`libwebgrep` provides four interchangeable matcher types (`Finder`, `Multi`, `Regex`, and `RegexSet`) plus the type-erased `AnyMatcher`, all sharing the same lock-free `*const` matcher protocol.

Literal patterns (`Finder` and `Multi`) cannot contain `\n` by default (returning `error.PatternHasNewline` before scanning) unless `FindOptions.multiline = true`. An empty literal pattern `""` produces a zero-width match `[0, 0)` once per line.

Pattern count defaults to `1024` (`default_max_pattern_count`), and total pattern bytes default to `256 KiB` (`default_max_pattern_bytes`). Both limits can be configured or raised freely via `FindOptions.max_pattern_count` and `FindOptions.max_pattern_bytes`. Exceeding the configured limit returns `error.PatternCountExceeded` or `error.PatternBytesExceeded` before allocating any tables.

Case matching defaults to `sensitive`. Setting `FindOptions.unicode_case = true` enables BMP Unicode Simple Case Folding in both `Finder` and `Multi`.

Smart case is evaluated per pattern (`CaseMode.smart`): a pattern is matched case-insensitively only if that specific pattern contains no uppercase letters, and case-sensitively if it contains any uppercase letter.

### Finder

Single-literal SIMD finder (`src/finder/finder.zig`).

```zig
pub fn init(pattern: []const u8, options: FindOptions) !Finder
pub fn find(self: *const Finder, haystack: []const u8, start: usize, mode: MatchMode) ?Match
pub fn findWatched(self: *const Finder, haystack: []const u8, start: usize, nul: *?usize) ?Match
pub fn requiredLiteral(self: *const Finder) ?RequiredLiteral
pub fn resetStats(self: *const Finder) void
```

Zero heap allocation and 100% immutable (`*const Finder`). `pattern` is borrowed from the caller and must outlive `Finder`. Combines frequency-ranked `PackedPair` 4-window SIMD filtering with worst-case linear-time `TwoWay` fallback, fused single-pass NUL detection (`findWatched`), and zero-allocation BMP Unicode Simple Case Folding when `options.unicode_case` is `true`.

### finder

Re-exports `src/finder/finder.zig`, the definition module for `Finder`.

### Multi

Multi-literal OR SIMD search engine (`src/finder/multi.zig`).

```zig
pub fn init(allocator: std.mem.Allocator, patterns: []const []const u8, options: FindOptions) !Multi
pub fn initFromText(allocator: std.mem.Allocator, text: []const u8, options: FindOptions) !Multi
pub fn deinit(self: *Multi) void
pub fn find(self: *const Multi, haystack: []const u8, start: usize, mode: MatchMode) ?Match
pub fn findWatched(self: *const Multi, haystack: []const u8, start: usize, nul: *?usize) ?Match
pub fn acceptsSpan(self: *const Multi, span: []const u8, mode: MatchMode) bool
pub fn isEmpty(self: *const Multi) bool
pub fn engineName(self: *const Multi) []const u8
pub fn resetStats(self: *const Multi) void
```

Automatically dispatches across four SIMD-accelerated engines based on pattern characteristics:
1. `ByteSet`: 4-way unrolled SIMD broadcast for single-byte patterns (`<= 16` folded bytes).
2. `RarePair`: Rare adjacent byte-pair SIMD hash prefilter (`<= 2` direct vector compare or `<= 8` hash buckets).
3. `Teddy`: 8-bucket Slim Teddy nibble-mask SIMD lookup (`vtbl` / `pshufb` / `vpshufb`) with 2-phase fingerprint verification (`<= 32` patterns).
4. `AhoCorasick`: Byte-equivalence-compressed dense DFA with 64-byte high-nibble bucket bitmap SIMD skip loop at `state == 0`.

Every `Match` returned by `Multi.find` carries the exact 0-based `pattern_id: ?u32` of the winning pattern (breaking ties by smaller `pattern_id`). Once constructed, `Multi` is completely immutable (`*const Multi`) and lock-free to share across concurrent threads.

### multi

Re-exports `src/finder/multi.zig`, the definition module for `Multi`.

### Regex

Linear-time Hybrid Lazy DFA + Thompson NFA / PikeVM regular expression matcher (`src/regex.zig`).

```zig
pub fn init(allocator: std.mem.Allocator, pattern: []const u8, options: RegexOptions) !Regex
pub fn initDiagnostic(allocator: std.mem.Allocator, pattern: []const u8, options: RegexOptions, diag: ?*CompileDiagnostic) !Regex
pub fn deinit(self: *Regex) void
pub fn find(self: *const Regex, haystack: []const u8, start: usize, mode: MatchMode) ?Match
pub fn findWithScratch(self: *const Regex, haystack: []const u8, start: usize, mode: MatchMode, scratch: *RegexScratch) ?Match
pub fn findWatched(self: *const Regex, haystack: []const u8, start: usize, nul: *?usize) ?Match
pub fn findCaptures(self: *const Regex, haystack: []const u8, start: usize, mode: MatchMode) ?Captures
pub fn extractCaptures(self: *const Regex, haystack: []const u8, match_span: Match) Captures
pub fn acceptsSpan(self: *const Regex, span: []const u8, mode: MatchMode) bool
pub fn requiredLiteral(self: *const Regex) ?RequiredLiteral
pub fn resetStats(self: *const Regex) void
```

Supported regular expression syntax:
- Literals and escapes: `\d`, `\D`, `\w`, `\W`, `\s`, `\S`, `\b`, `\B` (UAX #29 Unicode word boundaries when `unicode_case = true`), `\A`, `\z`, `\n`, `\r`, `\t`, `\xHH`, `\u{HHHH}`, and escaped metacharacters.
- Unicode General Category & Script properties: `\p{L}`, `\p{Lu}`, `\p{Ll}`, `\p{N}`, `\p{Nd}`, `\p{P}`, `\p{S}`, `\p{Sc}`, `\p{Z}`, `\p{ASCII}`, `\p{Han}`, `\p{Hiragana}`, `\p{Katakana}`, `\p{Greek}`, `\p{Cyrillic}`, `\p{Latin}`, and negated `\P{...}` (`src/tables/unicode_prop_table.zig`).
- Wildcard and anchors: `.` (any valid UTF-8 codepoint except `\n`, or including `\n` when `dot_all = true` and `multiline = true`), `^` (start of line/input), `$` (end of line/input).
- Character classes: `[a-z0-9_]`, multi-byte UTF-8 classes `[你好α-ω]`, negated `[^a-z]` or `[!a-z]`, and shorthand/property classes inside brackets.
- Quantifiers: `*`, `+`, `?`, `{m}`, `{m,}`, `{m,n}` (greedy and lazy `*?`, `+?`, `??`, `{m,n}?`, operating on complete UTF-8 codepoints).
- Alternation, grouping, and inline flags: `a|b`, `(expr)` (numbered capture groups `$1`..`$9`), `(?:expr)`, `(?i)`, `(?m)`, `(?s)`, `(?-i)`, `(?i:expr)`.

Executes a bounded Hybrid Lazy DFA for eligible patterns with lockstep Thompson NFA / PikeVM fallback, guaranteeing worst-case $O(n)$ time complexity, immunity to catastrophic backtracking (ReDoS), and lock-free `*const Regex` concurrency.

### RegexScratch

```zig
pub const RegexScratch = struct {
    pub fn init(allocator: std.mem.Allocator) RegexScratch
    pub fn deinit(self: *RegexScratch) void
};
```

Optional per-thread reusable scratch space for `Regex.findWithScratch`, caching the bounded `HeapDfa` transition table (up to 256 states) and NFA thread queues across invocations with zero steady-state allocations.

### RegexSet

Multi-pattern simultaneous regular expression engine (`src/regex/set.zig`).

```zig
pub fn init(allocator: std.mem.Allocator, patterns: []const []const u8, options: RegexOptions) !RegexSet
pub fn initDiagnostic(allocator: std.mem.Allocator, patterns: []const []const u8, options: RegexOptions, diag: ?*CompileDiagnostic) !RegexSet
pub fn deinit(self: *RegexSet) void
pub fn isMatch(self: *const RegexSet, haystack: []const u8) bool
pub fn find(self: *const RegexSet, haystack: []const u8, start: usize, mode: MatchMode) ?Match
pub fn matches(self: *const RegexSet, haystack: []const u8, out_ids: []u32) usize
```

Compiles up to `1,024` regular expressions into a combined Thompson NFA with `match_id` accepting states and an automatic `Multi` SIMD prefix prefilter when all patterns have extractable literal prefixes. Evaluates all patterns in a single pass, reporting the winning `Match.pattern_id` in `find()` or writing all matching 0-based pattern IDs in ascending order into `out_ids` via `matches()`.

### DiagnosticCode

Structured error classification enum for `CompileDiagnostic` (`none`, `unexpected_end_of_pattern`, `invalid_escape`, `invalid_hex_escape`, `invalid_unicode_escape`, `unknown_unicode_property`, `unclosed_group`, `unmatched_close_paren`, `unclosed_char_class`, `invalid_char_range`, `dangling_quantifier`, `invalid_repeat_quantifier`, `repeat_quantifier_too_large`, `unrecognized_inline_flag`, `invalid_utf8`, `pattern_has_newline`, `recursion_depth_exceeded`, `instruction_limit_exceeded`, `multiline_window_exceeded`, `pattern_count_exceeded`, `pattern_bytes_exceeded`, `out_of_memory`).

### CompileDiagnostic

```zig
pub const CompileDiagnostic = struct {
    code: DiagnosticCode = .none,
    offset: usize = 0,
    line: usize = 1,
    column: usize = 1,
    message: []const u8 = "",
    pattern_index: ?usize = null,
};
```

Populated by `Regex.initDiagnostic` and `RegexSet.initDiagnostic` when compilation fails, providing exact 0-based byte `offset`, 1-based `line` and `column`, static human-readable `message`, and `pattern_index` (for `RegexSet`).

### RegexOptions

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `case` | `CaseMode` | `.sensitive` | Case folding mode |
| `unicode_case` | `bool` | `true` | Enables BMP Unicode Simple Case Folding and UAX #29 word boundaries |
| `multiline` | `bool` | `false` | Allows matches to span across `\n` within `max_multiline_window`, and makes `^`/`$` match line boundaries |
| `dot_all` | `bool` | `false` | When `true` alongside `multiline`, allows `.` to match `\n` |
| `max_inst` | `?usize` | `null` | Compiled NFA instruction cap (`null` uses default `8192`, unconstrained override up to `u32` max) |
| `max_insts` | `?usize` | `null` | Alias for `max_inst` |
| `max_repeat` | `usize` | `1000` | Maximum bounded repetition count `{m,n}` (default `1000`, caller-configurable) |
| `max_recursion_depth` | `usize` | `64` | Maximum AST nesting/recursion depth (default `64`, caller-configurable) |
| `max_multiline_window` | `usize` | `64 * 1024` | Maximum byte span for a multiline match (`64 KiB` default, unconstrained override) |
| `max_pattern_count` | `?usize` | `null` | Optional pattern count cap for `RegexSet` (`null` uses default `1024`, caller-configurable) |
| `max_pattern_bytes` | `?usize` | `null` | Optional total pattern bytes cap for `RegexSet` (`null` uses default `256 KiB`, caller-configurable) |
| `max_unicode_variants` | `usize` | `64` | Maximum Unicode variants per pattern expanded for SIMD prefilters |
| `aot_dfa_max_insts` | `usize` | `256` | Maximum NFA instructions eligible for AOT dense DFA compilation |
| `max_dfa_states` | `u16` | `256` | Maximum lazy DFA states cached before falling back to PikeVM |

### Captures

```zig
pub const Captures = struct {
    match: Match,
    groups: [9]?Match = @splat(null),
    pub fn fullMatch(self: Captures) Match
    pub fn group(self: Captures, index: usize) ?Match
    pub fn slice(self: Captures, haystack: []const u8, index: usize) ?[]const u8
};
```

Holds the full match (`match`) and numbered submatch capture groups `$1`..`$9` (`groups[0..8]`) extracted by `Regex.findCaptures` or `Regex.extractCaptures`, and automatically used by `SearchConfig.replacement` when expanding `$0`, `$&`, `$1`..`$9`, `${1}`..`${9}`, and `$$`.

### regex

Re-exports `src/regex.zig`, the definition module for `Regex`, `RegexScratch`, `RegexSet`, `RegexOptions`, `Captures`, `DiagnosticCode`, and `CompileDiagnostic`.

### AnyMatcher

```zig
pub const AnyMatcher = struct {
    ctx: *const anyopaque,
    vtable: *const VTable,
    pub fn init(comptime M: type, matcher_ptr: anytype) AnyMatcher
    pub fn from(matcher_ptr: anytype) AnyMatcher
};
```

Runtime-polymorphic, immutable (`*const anyopaque`) matcher wrapper for `Finder`, `Multi`, `Regex`, `RegexSet`, or custom matchers. Reduces compile-time monomorphization bloat by allowing all search entry points to compile once against `AnyMatcher`.

### MatchMode

- `.earliest`: Selects the match that finishes at the smallest `end` offset (breaking ties by smaller `start`, then smaller `pattern_id`). Default mode.
- `.leftmost_first`: Selects the match with the smallest `start` offset (breaking ties by smaller `pattern_id`). Matches `rg -F` submatch ordering.

### Match

Half-open byte range `{ start: usize, end: usize, pattern_id: ?u32 = null }` relative to the `haystack` slice passed to `find`. `pattern_id` identifies the 0-based index of the matching pattern in `Multi` and `RegexSet` (`null` for single-pattern `Finder` and `Regex`).

### CaseMode

`sensitive`, `insensitive`, or `smart`. Uses ASCII case folding by default. Smart case is evaluated per pattern.

### FindOptions

| Field | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `case` | `CaseMode` | `.sensitive` | Case sensitivity mode (`sensitive`, `insensitive`, `smart`) |
| `unicode_case` | `bool` | `false` | Enables Unicode Simple Case Folding expansion in `Finder` and `Multi` |
| `multiline` | `bool` | `false` | Allows literal patterns to contain `\n` and match across lines within `max_multiline_window` |
| `max_multiline_window` | `usize` | `64 * 1024` | Maximum byte span for a cross-line match (`64 KiB` default, caller configurable) |
| `frequency` | `?[256]u8` | `null` | Optional custom byte frequency rank table for anchor selection |
| `prefilter_fp_threshold` | `f32` | `0.80` | Threshold (`< 1.0` enables adaptive fallback to `TwoWay` on patterns `> 32` bytes) |
| `max_pattern_count` | `?usize` | `null` | Optional pattern count cap (defaults to `1024`, caller configurable) |
| `max_pattern_bytes` | `?usize` | `null` | Optional total pattern bytes cap (defaults to `256 KiB`, caller configurable) |
| `max_unicode_variants` | `usize` | `64` | Maximum Unicode variants per pattern expanded during case folding |

### matcher

Re-exports `src/matcher.zig`, defining `MatchMode`, `Match`, `RequiredLiteral`, `CaseMode`, `FindOptions`, `AnyMatcher`, `default_max_pattern_count` (`1024`), `default_max_pattern_bytes` (`256 KiB`), and `checkPatternLimits`.

### RequiredLiteral

`struct { bytes: []const u8, offset_in_match: usize }`. Used by `Searcher` to run SIMD literal prefiltering before invoking a general matcher.

### memchr

Re-exports `src/finder/memchr.zig`. Vectorized single-byte primitives (`find`, `findEither`, `findLast`, `count`, `findAny`) operating on 16-byte or 32-byte vectors with zero allocation.

### two_way

Re-exports `src/finder/two_way.zig`. Crochemore-Perrin worst-case linear-time substring search (`TwoWay.init(pattern, fold)` and `find(haystack, start)`) with zero allocation and ASCII case folding by default (`Fold.sensitive` or `Fold.ascii`).

### bloom

Re-exports `src/finder/bloom.zig`, providing Kirsch-Mitzenmacher N-gram / Trigram Bloom indexing and zero-false-negative matcher pre-screening (`BloomConfig`, `NgramBloom`).

### BloomConfig

Configuration for `NgramBloom` (`bit_count: u32 = 16384`, `num_hashes: u8 = 3`, `ngram_len: u8 = 3`, `ascii_lower: bool = true`).

### NgramBloom

Space-efficient N-gram / Trigram Bloom filter supporting `init`, zero-allocation `initBorrowed`, `addSlice`, chunk-bridging `Writer` (`writer().addChunk`), CRC32-protected `serializeAlloc` / `deserialize`, `merge`, `estimatedFillRatio`, and zero-false-negative pre-screeners (`mayContainLiteral`, `mayContainRequired`, `mayContainFinder`, `mayContainMulti`, `mayContainRegex`, `mayContainRegexSet`, `mayContainMatcher`) across `sensitive`, `insensitive`, `smart`, and Unicode Simple Case Folding (`k`/`K`, `s`/`ſ`, `ß`/`ẞ`).

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

Enforces both `max_decompressed_bytes` and `max_compression_ratio` (default `100:1`, caller-configurable) on every decompressed chunk to block Zip Bombs (`LimitHit.decompressed_bytes`). Corrupted compressed streams are handled gracefully as `SoftError.read_failed`.

### decompress

Re-exports `src/codec/decompress.zig`, providing `Compression`, `OffsetMap`, `DecompressResult`, and `decompressSlice` for in-process bomb-safe streaming decompression and raw offset mapping.

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

Context lines default to `10` when unconfigured, overridable via `SearchConfig.max_context_lines`. The before-context buffer is optionally capped by `max_before_bytes`.

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
| `line_number` | `u64` | 1-based line number (or record number when `null_data = true`; `0` when `line_number_known == false`) |
| `line_number_known` | `bool` | `true` when `line_number` is exact; `false` when starting mid-file or in reverse tail search without scanning from offset 0 or supplying `initial_line_number` |
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

When cross-line matching is active (`multiline = true`), a `LineEvent` (or legacy `Line`) that spans multiple physical lines contains the contiguous multi-line block in `bytes` (preserving internal `\n` delimiters and stripping only the final line's trailing delimiter), reports the 1-based `line_number` of the first spanned line, and merges any subsequent match starting on the final spanned line that extends onto further lines into the same event within a bounded sliding window (`max_multiline_window`).

### Line

Legacy callback line struct (`searchSlice` / `searchReader`), carrying `bytes`, `text`, `raw`, `replaced`, `offset`, `raw_offset`, `number` (`?u64`), `match` (`?Match`), `matches` (`[]const Span`), `column`, `u16_column`, `binary_status`, `truncated`, `line_len`, and `window_start`.

### Span

| Field | Type | Description |
| :--- | :--- | :--- |
| `start` | `usize` | Inclusive 0-based start byte offset relative to `bytes` |
| `end` | `usize` | Exclusive 0-based end byte offset relative to `bytes` |
| `u16_start` | `usize` | Inclusive 0-based UTF-16 code-unit start offset on `text` |
| `u16_end` | `usize` | Exclusive 0-based UTF-16 code-unit end offset on `text` |
| `pattern_id` | `?u32` | 0-based pattern index that produced this match (`Multi` / `RegexSet`, `null` for single pattern) |
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

| Field | Type | Struct Default | Service Default / Behavior | Description |
| :--- | :--- | :--- | :--- | :--- |
| `line_numbers` | `bool` | `false` | `line_number_mode != .unknown` on service entry | Enables 1-based line numbers |
| `initial_line_number` | `?u64` | `null` | `null` | Explicit starting 1-based line number for `byte_range` or last line number in reverse tail search |
| `line_number_mode` | `LineNumberMode` | `.auto` | `.auto` | Line numbering policy (`.auto`, `.from_one`, `.unknown`) |
| `byte_range` | `?ByteRange` | `null` | `null` | Half-open byte range `[start, end)` to search without scanning outside the range |
| `range_align_lines` | `bool` | `false` | `false` | Aligns `byte_range.start > 0` forward to the next line start and extends `byte_range.end` through the end of a cut line |
| `seek_input` / `seek_ctx` | `?fn` / `?*anyopaque` | `null` | `null` | Optional seek callback `(ctx, offset)` for `byte_range`, `resume_from`, and `Flow.skipTo` |
| `read_at` / `read_at_ctx` | `?fn` / `?*anyopaque` | `null` | `null` | Optional positional read callback `(ctx, offset, dest) -> usize` for zero-seek range and jump I/O |
| `stream_offset` | `?u64` | `null` | `null` | Declares that `*std.Io.Reader` is already positioned at this absolute byte offset |
| `line_filter` / `line_filter_ctx` | `?fn` / `?*anyopaque` | `null` | `null` | Synchronous pre-count / pre-quota predicate `(ctx, LineFilterCandidate) -> bool` evaluated strictly before `max_count`, `max_results`, `matched_lines`, `matches`, and context |
| `invert` | `bool` | `false` | `false` | Emits lines that do not match |
| `whole_word` | `bool` | `false` | `false` | Half-boundary word check (ASCII + Unicode word characters) |
| `whole_line` | `bool` | `false` | `false` | Requires entire line content to match |
| `multiline` | `bool` | `false` | `false` | Enables cross-line (`-U`) search semantics across line boundaries |
| `max_multiline_window` | `?usize` | `null` | Matcher's window (`64 KiB` default) | Optional override for the maximum cross-line lookahead window in bytes |
| `contains` | `[]const []const u8` | `&.{}` | `&.{}` | Every listed literal must appear on the line (AND) |
| `excludes` | `[]const []const u8` | `&.{}` | `&.{}` | None of the listed literals may appear on the line (NOT) |
| `filter_case_insensitive` | `bool` | `false` | `false` | Enables ASCII case-insensitive matching for `contains` and `excludes` |
| `filter_smart_case` | `bool` | `false` | `false` | Enables per-filter smart-case matching for `contains` and `excludes` |
| `contains_regexes` | `[]const Regex` | `&.{}` | `&.{}` | Compiled regexes that must all match within the line (AND) |
| `excludes_regexes` | `[]const Regex` | `&.{}` | `&.{}` | Compiled regexes that must not match within the line (NOT) |
| `context` | `u32` | `0` | Default limit `10` (`max_context_lines`) | Symmetric before/after context lines |
| `before` / `after` | `?u32` | `null` | Default limit `10` (`max_context_lines`) | Asymmetric before/after context lines |
| `max_context_lines` | `?u32` | `null` | Default `10` (caller-configurable) | Maximum allowed context lines |
| `passthru` | `bool` | `false` | `false` | Emits all lines (`match` and `context`), bounded by `max_output_bytes` |
| `replacement` | `?[]const u8` | `null` | `null` | Read-only replacement preview template (`$0`, `$&`, `$1`..`$9`, `$$`) |
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
| `max_compression_ratio` | `?u64` | `null` | Default `100` (caller-configurable) | Maximum decompression expansion ratio (`decompressed / raw`) |
| `decompressed_bytes` | `u64` | `0` | `0` | Prior decompressed bytes charged to this request |
| `max_decompressed_bytes` | `?u64` | `null` | Default `64 MiB` when compressed | Maximum decompressed bytes (`LimitHit.decompressed_bytes`) |
| `allocator` | `?Allocator` | `null` | `null` | Unified allocator for slice transcoding, decompression, and replacement preview |
| `decode_allocator` | `?Allocator` | `null` | `null` | Legacy alias for `allocator` (deprecated in favor of `allocator` / `scratch_pool`) |
| `buffer_size` | `usize` | `1 MiB` | `1 MiB` | Rolling stream read buffer size |
| `max_line_len` | `usize` | `2 MiB` | Default `2 MiB` (caller-configurable) | Sliding window cap for ultra-long lines |
| `match_mode` | `MatchMode` | `.earliest` | `.earliest` | `.earliest` or `.leftmost_first` |
| `scratch` | `?*[]u8` | `null` | `null` | Reusable raw byte buffer pointer across streaming calls |
| `scratch_pool` | `?*Scratch` | `null` | `null` | Reusable `Scratch` pool eliminating steady-state heap allocations |
| `max_source_bytes` | `?u64` | `null` | Default `16 MiB` (caller-configurable) | Max bytes scanned per source (`LimitHit.max_bytes`) |
| `max_request_bytes` | `?u64` | `null` | Default `16 MiB` (caller-configurable) | Max bytes scanned per request (`LimitHit.max_bytes`) |
| `max_output_bytes` | `?u64` | `null` | Default `1 MiB` (caller-configurable) | Max cumulative bytes emitted in line events |
| `time_budget_ns` | `?u64` | `null` | Default `30s` (caller-configurable) | Wall-clock deadline in nanoseconds (`LimitHit.deadline`) |
| `cancel` | `?*const Atomic(bool)` | `null` | `null` | Atomic cancellation token (`LimitHit.cancelled`) |
| `stop` | `?*const Atomic(bool)` | `null` | `null` | Cooperative stop flag between chunks |
| `max_before_bytes` | `?usize` | `null` | Default `20 MiB` (caller-configurable) | Cap on before-context ring buffer |
| `max_decode_bytes` | `?usize` | `null` | Default `4 MiB` (caller-configurable) | Cap on transcoding buffer |
| `max_queued_event_bytes` | `?usize` | `null` | Default `2 MiB` (caller-configurable) | Cap on a single pending event payload |
| `max_concurrency` | `?u32` | `null` | Caller-configurable | Caller-injected worker thread limit |
| `progress_interval` | `?u64` | `null` | `null` | Byte interval between `progress` events |
| `live` | `bool` | `false` | `false` | Treats 0-byte reads as idle stream rather than EOF |
| `idle_timeout_ns` | `?u64` | `null` | `null` | Idle duration before emitting `heartbeat` on a live stream |
| `live_closed` | `?*const Atomic(bool)` | `null` | `null` | Signals that a live stream has closed |
| `close_input` / `close_ctx` | `?fn` / `?*anyopaque` | `null` | `null` | Callback to close upstream on early termination |
| `clock` / `clock_ctx` | `?fn` / `?*anyopaque` | `null` | `null` | Custom monotonic clock hook for deterministic testing |
| `log` / `log_ctx` | `?fn` / `?*anyopaque` | `null` | `null` | Diagnostic log callback (never written to terminal) |

### ByteRange

```zig
pub const ByteRange = struct {
    start: u64 = 0,
    end: ?u64 = null,
};
```

Half-open byte range `[start, end)` within a source (`end == null` searches through EOF). Used by `SearchConfig.byte_range`, `searchRange`, and `searchSourceRange`.

### LineNumberMode

```zig
pub const LineNumberMode = enum { auto, from_one, unknown };
```

Controls line number tracking:
- `.auto`: Computes exact 1-based line numbers when starting at byte 0 or when `initial_line_number` / `continuation` is supplied; marks line numbers unknown (`Line.number = null`, `LineEvent.line_number_known = false`) when starting mid-file or in reverse tail search without scanning from byte 0.
- `.from_one`: Counts lines starting at `1` from the start of the searched range (unless overridden by `initial_line_number`).
- `.unknown`: Never computes line numbers (`Line.number = null`, `LineEvent.line_number = 0`, `LineEvent.line_number_known = false`).

### LineFilterCandidate

```zig
pub const LineFilterCandidate = struct {
    bytes: []const u8,
    raw_bytes: []const u8,
    absolute_offset: u64,
    first_match: Span,
    is_inverted: bool = false,
};
```

Candidate line passed to `SearchConfig.line_filter` after primary pattern and `whole_word`/`whole_line`/`contains`/`excludes` checks pass, and strictly before `max_count`, `max_results`, `matched_lines`, `matches`, or context buffers are affected. Returning `false` rejects the line with zero quota impact.

---

## Defaults

Service entry points (`searchSourceSlice`, `searchSource`, `resumeSourceSlice`, `openSourcePull`, `openReaderPull`) populate safe multi-tenant defaults whenever budget fields are `null`:
- `line_numbers`: `true`
- `binary`: `BinaryPolicy.quit` (Binary inputs are skipped by default)
- `max_source_bytes` / `max_request_bytes`: `16 MiB` (caller-configurable)
- `time_budget_ns`: `30s` (caller-configurable)
- `max_output_bytes`: `1 MiB` (caller-configurable)
- `max_decode_bytes`: `4 MiB` (caller-configurable)
- `max_before_bytes`: `20 MiB` (caller-configurable)

---

## Non-Goals

To keep the core engine safe for multi-tenant server embedding:
- Single-source public search entry points only operate on caller-opened streams or slices; they do not open filesystem paths directly.
- Symlink following, parent-directory ignore traversal above the root, and global host ignore configuration are permanently disabled.
- Terminal color rendering and NDJSON transport serialization are left to the caller.

### sink_mod

Re-exports `src/sink.zig`, containing all event, line, `AnySink`, `AnyEventSink`, and result definitions.

### searcher

Re-exports `src/searcher.zig`, containing `SearchConfig`, `Scratch`, `SliceError`, `ReadError`, `PullEvent`, `SourcePull`, `ReaderPull`, `openReaderPull`, and the search entry points.

### walk_glob

Re-exports `src/walk/glob.zig`. Byte-oriented glob matcher supporting `*`, `?`, `**`, character classes `[a-z]` with `!`/`^` negation, nested brace expansion `{a,{b,c}}` (`expandBraces`, `compileGlobs`), `case_insensitive` matching (`classifyWithCase`, `matchTextCase`), later-rule precedence (`matchGlobs`), and caller-configurable limits (`max_rules` default 1024, `max_rule_len` default 4096, `max_brace_depth` default 8).

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

### scheduler

Re-exports `src/scheduler.zig`, providing a generic path-free, handle-free Chase-Lev work-stealing task scheduler (`SchedulerConfig`, `Scheduler`, `max_threads_hard_cap`, `resolveWorkerCount`).

### SchedulerConfig

```zig
pub const SchedulerConfig = struct {
    max_threads: ?u32 = null,
    stop: ?*const std.atomic.Value(bool) = null,
    cancel: ?*const std.atomic.Value(bool) = null,
};
```

Configuration for `Scheduler(Task, Context).run`. `max_threads == null` or `<= 1` runs inline on the calling thread with zero mutex or `Io.Group` overhead; `max_threads > 1` runs up to `64` Chase-Lev workers.

### Scheduler

```zig
pub fn Scheduler(comptime Task: type, comptime Context: type) type
```

Generic Chase-Lev work-stealing scheduler executing `initial_tasks` and recursively spawned `handle.spawn(subtask)` items across worker deques (`LIFO` local pop for cache locality, `FIFO` peer steal, `handle.stop()`, `handle.isStopped()`, `handle.isCancelled()`).

---

## C ABI (`include/webgrep.h`)

`zig build` installs static (`libwebgrep.a`) and shared (`libwebgrep.so` / `.dylib`) libraries along with `include/webgrep.h`, exposing 20 C ABI functions (`callconv(.c)`):
- `webgrep_version`, `webgrep_find_options_default`, `webgrep_regex_options_default`, `webgrep_config_default`, `webgrep_tree_config_default`, `webgrep_probe_options_default`
- `webgrep_matcher_compile_literal`, `webgrep_matcher_compile_multi`, `webgrep_matcher_compile_regex`, `webgrep_matcher_compile_regex_set`, `webgrep_matcher_free`
- `webgrep_scratch_new`, `webgrep_scratch_free`
- `webgrep_find`, `webgrep_regex_set_matches`, `webgrep_probe_line_slice`
- `webgrep_search_slice`, `webgrep_search_reader`, `webgrep_search_reverse_slice`, `webgrep_search_archive_slice`

---

## Example

The code block below demonstrates:
1. Single-literal smart-case search with UTF-16 span inspection (`searchSourceSlice`).
2. Multi-literal OR search from newline-delimited pattern text (`Multi.initFromText`), `pattern_id` attribution, and cursor pagination (`Flow.pause` + `resumeSourceSlice`).
3. Linear-time `Regex` search with Unicode properties (`\p{Han}`), `RegexSet` simultaneous matching, and read-only replacement preview (`SearchConfig.replacement`).
4. Streaming `*std.Io.Reader` search (`searchSource`), slice pull iteration (`openSourcePull`), and true streaming pull iteration (`openReaderPull`).
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
    last_pattern_id: u32 = 0,
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
                    self.last_pattern_id = m.matches[0].pattern_id orelse 0;
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

    // 1. Single-literal smart-case search on a slice (*const Finder)
    const finder = try libwebgrep.Finder.init("needle", .{ .case = .smart });
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

    // 2. Multi-literal OR search + pattern_id + pause & resume pagination
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
    try std.testing.expectEqual(@as(u32, 0), paged_sink.last_pattern_id);

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
    try std.testing.expectEqual(@as(u32, 1), paged_sink.last_pattern_id);

    // 3. Linear-time Regex search + RegexSet + read-only replacement preview
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
            .allocator = allocator,
        },
    );
    try std.testing.expectEqualStrings(
        "code=REDACTED found",
        regex_sink.last_replaced[0..regex_sink.last_replaced_len],
    );

    var re_set = try libwebgrep.regex.RegexSet.init(allocator, &.{ "ALPHA", "ERR_[0-9]+" }, .{});
    defer re_set.deinit();
    var set_ids: [4]u32 = undefined;
    try std.testing.expectEqual(@as(usize, 1), re_set.matches("code=ERR_404", &set_ids));
    try std.testing.expectEqual(@as(u32, 1), set_ids[0]);

    // Cross-line (multiline) literal & regex search
    const ml_finder = try libwebgrep.Finder.init("alpha\nbeta", .{ .multiline = true });
    var ml_sink = Recorder{};
    const ml_res = try libwebgrep.searchSourceSlice(
        Recorder,
        &ml_sink,
        "ml-1",
        "header\nalpha\nbeta\nfooter\n",
        &ml_finder,
        .{ .multiline = true },
    );
    try std.testing.expectEqual(@as(u64, 1), ml_res.matched_lines);

    // 4. Streaming Reader search + Slice & Streaming Pull iterators
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

    var pull_reader_in = std.Io.Reader.fixed("chunk NEEDLE 1\nchunk NEEDLE 2\n");
    var rpull = try libwebgrep.searcher.openReaderPull(allocator, &finder, "rpull-1", &pull_reader_in, .{});
    defer rpull.deinit();
    var rpull_matches: usize = 0;
    while (try rpull.next()) |ev| {
        if (ev.kind == .match) rpull_matches += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), rpull_matches);

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

    // 6. Byte-offset line probe, RandomAccess range search, reverse tail search, and NgramBloom pre-screening
    const probed = libwebgrep.probeLineSlice(input, 17, .{}).?;
    try std.testing.expectEqualStrings("hello NEEDLE world", probed.bytes);

    var bloom_filter = try libwebgrep.NgramBloom.init(allocator, .{});
    defer bloom_filter.deinit();
    bloom_filter.addSlice(input);
    try std.testing.expect(bloom_filter.mayContainMatcher(&finder));

    const input_slice: []const u8 = input;
    const ra = libwebgrep.RandomAccess.fromSlice(&input_slice);
    var range_sink = Recorder{};
    const range_res = try libwebgrep.searchSourceRange(
        Recorder,
        allocator,
        &range_sink,
        ra,
        .{ .start = 11, .end = 30 },
        "range-1",
        &finder,
        .{ .initial_line_number = 2 },
    );
    try std.testing.expectEqual(@as(u64, 1), range_res.matched_lines);

    var rev_sink = Recorder{};
    const rev_res = try libwebgrep.searchSourceReverseSlice(
        Recorder,
        &rev_sink,
        "rev-1",
        log_slice,
        &many,
        .{ .max_count = 1 },
    );
    try std.testing.expectEqual(@as(u64, 1), rev_res.matched_lines);
    try std.testing.expectEqual(@as(u32, 1), rev_sink.last_pattern_id);
}
```

