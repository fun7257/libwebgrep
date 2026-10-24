# libwebgrep Architecture Milestones

All planned capability milestones for `libwebgrep` have been completed, verified by unit and fuzz tests, and benchmarked in `ReleaseFast` mode.

```mermaid
flowchart TD
    M0["Milestone 1: Core SIMD Kernels & Streaming Searcher<br/>memchr / PackedPair / TwoWay / ByteSet / RarePair / Teddy / AhoCorasick<br/>Constant-memory sliding window, bounded context, multi-tenant budgets"] --> M1["Milestone 2: High-Value Query Semantics<br/>Pattern list parser (Multi.initFromText), ordered-stream early stop,<br/>full-stream highlighting (passthru), read-only replacement preview"]
    M1 --> M2["Milestone 3: Linear-Time Regex + SIMD Prefilter<br/>Lockstep Thompson NFA / PikeVM, compile size hard cap,<br/>RequiredLiteral SIMD prefilter (42.9 GB/s), bounded multiline window"]
    M2 --> M3["Milestone 4: Bomb-Safe Streaming Decompression & Encodings<br/>In-process Gzip / Zstd / XZ with dual Zip-Bomb caps,<br/>Unicode Simple Case Folding, GBK / Latin-1 transcoding, raw_offset mapping"]
    M3 --> M4["Milestone 5: Controlled Multi-Source Pipeline<br/>Nested brace globbing with caps, in-memory & layered Ignore rules,<br/>injectable file-type tables, controlled worker concurrency & streaming events"]
```

| Milestone | Focus Area | Key Modules | Status | Verification & Performance Highlights |
| :--- | :--- | :--- | :---: | :--- |
| **Milestone 1** | **Core SIMD Kernels & Multi-Tenant Searcher** | `src/finder/*`, `src/searcher.zig`, `src/sink.zig` | **Completed** | 24–62 GB/s SIMD kernel throughput; zero-allocation slice search; fused single-pass NUL detection |
| **Milestone 2** | **High-Value Query Semantics** | `src/finder/multi.zig`, `src/searcher.zig`, `src/sink.zig` | **Completed** | `Multi.initFromText` pre-allocation limit check; `stop_on_nonmatch`; `passthru`; read-only `replacement` preview |
| **Milestone 3** | **Linear-Time Regex + SIMD Prefilter** | `src/regex.zig`, `src/searcher.zig` | **Completed** | Worst-case $O(n)$ Thompson NFA; 4096-instruction hard cap; 42.87 GB/s `RequiredLiteral` SIMD prefilter; bounded multiline |
| **Milestone 4** | **Streaming Decompression & Extended Encodings** | `src/decompress.zig`, `src/encoding.zig`, `src/finder/unicode_fold.zig` | **Completed** | In-process Gzip/Zstd/XZ Zip-Bomb protection (`max_decompressed_bytes` + `max_compression_ratio`); Unicode case folding; GBK/Latin-1 & `raw_offset` |
| **Milestone 5** | **Controlled Multi-Source Pipeline** | `src/walk/*`, `src/parallel.zig` | **Completed** | Nested `{a,{b,c}}` glob expansion with caps; pure-text & `.gitignore`/`.ignore`/`.rgignore` switches; `expandTypesToGlobs`; strict `max_concurrency` |
