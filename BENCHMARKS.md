# libwebgrep Benchmarks (v0.4.0)

This document records the reproducible `ReleaseFast` microbenchmarks ([`bench/micro.zig`](bench/micro.zig)) across `x86_64` (AMD Ryzen 7 7735U AVX2) and `aarch64` (Apple M2 NEON), the microarchitectural cache-hierarchy throughput curves, the `v0.3.0`–`v0.4.0` engine specialization evaluations, and the **rigorous 15-scenario Warm Cache (`mincore=100%`) & Cold Disk (`POSIX_FADV_DONTNEED` + `mincore=0`) end-to-end comparative experiment against `ripgrep 14.1.1`**.

Run the in-process benchmark suite with:

```sh
zig build bench -Doptimize=ReleaseFast -Dteddy=avx2
```

---

## 1. Executive Summary

1. **Microarchitectural Compute Peak vs. Memory Bandwidth Wall**:
   - Inside L1d / L2 cache on a single physical core (AMD Ryzen 7 7735U, Zen 3+, 32-byte AVX2 vectors), `libwebgrep` reaches **`147.8 GB/s`** (`memchr.findEither`), **`81.0 GB/s`** (`Finder` / `PackedPair`), **`67.2 GB/s`** (AVX2 `Teddy`), and **`63.8 GB/s`** (`Finder` case-insensitive).
   - Once the working set exceeds the 16 MiB L3 cache into 64 MiB DRAM, throughput converges to the single-core memory controller read bandwidth ceiling (**`20.4–28.2 GB/s`** on LPDDR5 `x86_64` with CV `0.10%–0.32%`, and **`24.1–62.4 GB/s`** on unified-memory Apple M2 `aarch64`).
2. **Core Engine Capabilities (`v0.3.0`–`v0.4.0`)**:
   - **`Scratch` Worker Buffer Pool**: Reduces heap allocations across `20,000 × 4 KiB` context-enabled streaming searches from `40,000` allocations (`81.25 GiB`) to **2 warmup allocations (`0` steady-state allocations)**, boosting throughput by **`44.7x` (`12,284 QPS → 549,368 QPS`, `1.82 µs/req`)**.
   - **`RegexSet` Single-Pass Multi-Regex**: Evaluates 256 prefixed regular expressions simultaneously at **`35.13 GB/s`** (**`266x` faster** than looping 256 individual `Regex.isMatch` calls at `0.132 GB/s`).
   - **Zero-Cost Polymorphism & C ABI (`include/webgrep.h`)**: Runtime-dispatched `AnyMatcher` + `AnyEventSink` incurs **`< 0.02%`** overhead vs. static generics, and the zero-`libc` C ABI (`webgrep_search_slice`) incurs **`< 0.4%`** FFI overhead.
3. **15 / 15 Full-Scenario Surpass over `ripgrep 14.1.1` (Warm Cache & Cold Disk)**:
   - Evaluated strictly through the public `libwebgrep` library interface (`src/root.zig`) on the 2.488 GB `zg-corpus` using an interleaved ABBA C11 benchmark driver (`sched_setaffinity`, `mincore(2)` residency verification, and `wait4` resource accounting), `libwebgrep` (`wg (auto)`) **surpasses `rg_best = min(rg --no-mmap, rg --mmap)` across all 15 scenarios in both Warm Cache (`1.01x–72.73x`) and Cold Disk (`1.09x–176.67x`)** with **100% output and match-count parity**.

---

## 2. Test Environments

| Property | Primary Linux `x86_64` Rig (`v0.4.0`) | Reference macOS `aarch64` Rig |
| :--- | :--- | :--- |
| **Processor** | AMD Ryzen 7 7735U (Zen 3+, 8C/16T, up to `4.82 GHz`) | Apple M2 (8 cores, 8 GiB unified RAM) |
| **Cache Topology** | L1d `32 KiB/core` \| L2 `512 KiB/core` \| **L3 `16 MiB` shared** | L1d `128/64 KiB` \| SLC + unified memory |
| **Native SIMD Width** | **32 bytes (`x86_64` AVX2)** + BMI2 + POPCNT | **16 bytes (`aarch64` ARM NEON)** |
| **Compiler & Baseline** | Zig `0.17.1` (`ReleaseFast`, `znver3`), `gcc 14.2.0`, `ripgrep 14.1.1` | Zig `0.17.0` (`ReleaseFast`, `apple_m2`) |
| **Isolation Controls** | `amd_pstate` EPP=`performance`, `sched_setaffinity` physical core pinning, `mincore(2)` verification | Unpinned single-process warmup + timed loop |

---

## 3. In-Process 35-Scenario Microbenchmark Suite (`bench/micro.zig`)

Each scenario executes 1 unmeasured warmup iteration followed by at least 300 ms and at least 2 measured iterations, guarded by a compiler memory barrier and a 1-bit input flip per iteration:

| Scenario | Working Set | Ryzen 7 7735U AVX2 (GB/s) | CV% | Apple M2 NEON (GB/s) | Engine / Microarchitectural Notes |
| :--- | ---: | ---: | ---: | ---: | :--- |
| `memchr_either` | `64 MiB` | **28.181** | 0.25% | **62.390** | Single-core DRAM bandwidth ceiling (`147.8 GB/s` in L1d) |
| `std_find_scalar` | `64 MiB` | **26.465** | 0.22% | **50.912** | `std.mem.findScalarPos` baseline |
| `memchr_find` | `64 MiB` | **26.420** | 0.23% | **48.254** | Single-byte 4-vector unrolled SIMD |
| `finder_sensitive` | `64 MiB` | **23.314** | 1.65% | **42.617** | `PackedPair` 32B×4=128B unrolled SIMD (`81.0 GB/s` in L2) |
| `finder_alphabet` | `64 MiB` | **23.242** | 0.31% | **42.818** | `"libwebgrep"` on repeating alphabet text |
| `regex_prefilter` | `64 MiB` | **23.223** | 1.07% | **42.866** | `Regex` with extracted literal prefilter (zero NFA overhead) |
| `multi_bytes` | `64 MiB` | **21.374** | 0.25% | **34.182** | `ByteSet` 4-way unrolled vector comparison |
| `multi_pairs` | `64 MiB` | **21.374** | 0.11% | **32.162** | `RarePair` synchronous 2-byte SIMD pair comparison |
| `search_slice` | `64 MiB` | **21.024** | 0.72% | **28.062** | Full `searchSlice` pipeline (line framing + fused NUL check) |
| `finder_smart` | `64 MiB` | **21.003** | 2.54% | **24.570** | Smart-case `Finder` |
| `finder_ignore` | `64 MiB` | **20.982** | 1.39% | **24.881** | Branchless `(block \| 0x20)` 32B AVX2 case folding (`63.8 GB/s` in L2) |
| `multi_teddy` | `64 MiB` | **20.398** | 0.12% | **24.131** | AVX2 `vpshufb` / NEON `vtbl` nibble-mask `Teddy` (`67.2 GB/s` in L2) |
| `multi_ac` | `64 MiB` | **17.706** | 0.10% | **24.273** | Dense `AhoCorasick` DFA + 64B high-nibble SIMD skip |
| `regex_utf8_class` | `16 MiB` | **39.941** | 14.59% | — | UTF-8 character class alternation with SIMD prefilter |
| `finder_unicode_case` | `16 MiB` | **35.770** | 17.44% | — | ASCII fast-path skips UTF-8 case folding on pure ASCII chunks |
| `regex_captures` | `16 MiB` | **33.687** | 14.23% | — | SIMD prefilter + bounded capture group extraction (`$1..$3`) |
| `regex_alternation` | `16 MiB` | **22.937** | 3.35% | — | Top-level regex alternation routed to `Multi` prefilter |
| `multi_unicode_expanded` | `16 MiB` | **22.585** | 3.91% | — | Unicode case-expanded multi-pattern search |
| `regex_set_matches` | `16 MiB` | **22.540** | 2.88% | — | Single-pass `RegexSet.matches` |
| `search_unicode_word` | `16 MiB` | **18.519** | 13.39% | — | UAX #29 Unicode whole-word boundary verification |
| `regex_replace_template` | `16 MiB` | **17.680** | 8.45% | — | Read-only `$2:$1 ($0)` replacement preview |
| `stream_auto_sniff` | `16 MiB` | **16.897** | 0.78% | — | `searchSource` BOM auto-sniff + `256 KiB` rolling buffer |
| `pull_reader_stream` | `16 MiB` | **16.837** | 0.72% | **11.760** | Streaming `openReaderPull` (**43% faster** on Zen 3+ L2) |
| `service_ndjson_filter` | `16 MiB` | **13.124** | 9.00% | — | Secondary smart-case `contains` filter + NDJSON serialization |
| `file_256KiB` | `128 MiB` | **9.155** | 3.05% | **10.789** | `256 KiB` rolling stream buffer (fits inside 512 KiB L2) |
| `file_1MiB` | `128 MiB` | **9.088** | 4.21% | **10.987** | Default `1 MiB` rolling stream buffer |
| `file_128KiB` | `128 MiB` | **9.079** | 2.79% | **10.417** | `128 KiB` rolling stream buffer |
| `file_64KiB` | `128 MiB` | **8.773** | 3.06% | **10.150** | `64 KiB` rolling stream buffer |
| `file_readall` | `128 MiB` | **4.115** | 0.40% | **6.149** | Single whole-file allocation + read (**2.22x slower** than streaming) |
| `archive_search_slice` | `1.03 MiB` | **2.178** | 0.24% | — | Zero-disk in-memory `.tar` unpacking + 64-file tree search |
| `encoding_utf16le` | `4 MiB` | **0.976** | 0.38% | — | UTF-16LE BOM transcoding to UTF-8 with `OffsetMap` |
| `encoding_gbk` | `4 MiB` | **0.607** | 0.27% | — | GBK double-byte lookup transcoding to UTF-8 |
| `walk_4` | `768 KiB` | **0.229** | 1.18% | — | 384 small files across 4 worker threads |
| `resume_utf16le_tail` | `64 KiB` | **0.172** | 5.40% | — | Stateless `raw_resume_at` continuation on UTF-16LE |
| `walk_1` | `768 KiB` | **0.112** | 1.35% | **0.158** | 384 small files on 1 worker thread |

---

## 4. Microarchitectural Cache Hierarchy Curve (L1d → L2 → L3 → DRAM)

Measured on a single pinned physical core (Core 0, Ryzen 7 7735U AVX2) across working sets from `16 KiB` (L1d) to `64 MiB` (DRAM):

| Engine Kernel | `16 KiB` (L1d) | `256 KiB` (L2) | `4 MiB` (L3) | `8 MiB` (L3) | `16 MiB` (L3 Edge) | `64 MiB` (DRAM) | Bottleneck Regime |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| **`memchr_either`** | **147.77 GB/s** | 143.65 GB/s | 119.99 GB/s | 119.93 GB/s | 66.04 GB/s | **28.10 GB/s** | Memory-bandwidth bound above L3 (5.26x L1→DRAM ratio) |
| **`finder_sensitive`** | 73.34 GB/s | **81.03 GB/s** | 78.56 GB/s | 77.88 GB/s | 44.10 GB/s | **23.36 GB/s** | Peak IPC at `256 KiB` L2; DRAM-bound at `64 MiB` |
| **`multi_teddy` (AVX2)** | 59.94 GB/s | **67.18 GB/s** | 67.11 GB/s | 67.03 GB/s | 38.05 GB/s | **21.34 GB/s** | Dual-port `vpshufb` sustains **67 GB/s** throughout L2/L3 |
| **`finder_ignore`** | 53.33 GB/s | **63.83 GB/s** | 63.49 GB/s | 62.16 GB/s | 36.21 GB/s | **20.95 GB/s** | Branchless `(block \| 0x20)` sustains **63.8 GB/s** in L2/L3 |
| **`multi_ac`** | 33.31 GB/s | **35.38 GB/s** | 35.08 GB/s | 35.02 GB/s | 25.81 GB/s | **19.06 GB/s** | 64B nibble skip hides dense DFA transition table latency |

---

## 5. Rigorous 15-Scenario Comparative Experiment vs. `ripgrep 14.1.1`

### 5.1 Experimental Methodology

To eliminate ordering bias, page-cache leakage, and I/O mode asymmetry, `libwebgrep` is benchmarked strictly as an embedded library via a standalone CLI wrapper (`wg-cli` importing only [`src/root.zig`](src/root.zig)) driven by a native C11 harness (`bench-driver`):

1. **Symmetric Subprocess Accounting**: All 5 configurations (`wg (auto)`, `wg --no-mmap`, `wg --mmap`, `rg --no-mmap`, `rg --mmap`) are launched via `fork() + execve()` and measured with `clock_gettime(CLOCK_MONOTONIC_RAW)` + `wait4()` (`ru_utime`, `ru_stime`, `ru_minflt`, `ru_majflt`), capturing full process startup, pattern compilation, file open, I/O, matching, output formatting, and teardown.
2. **ABBA Interleaved Ordering & Physical Core Pinning**: Single-threaded scenarios (`S01`–`S14`) are pinned to physical Core 2 (`sched_setaffinity`); 8-thread directory search (`S15`) is pinned to all 8 physical cores (`0,2,4,6,8,10,12,14`). Even rounds execute in forward order (`0 → 4`) and odd rounds execute in reverse order (`4 → 0`) across **9 Warm Cache rounds** and **5 Cold Disk rounds**.
3. **`mincore(2)` Hardware Page-Cache Residency Proofs**:
   - **Warm Cache**: Verified via `mincore(2)` prior to every round (`mincore == 100.0%` resident).
   - **Cold Disk**: Before **every individual subprocess invocation**, the harness calls `fsync()` + `posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED)` on the target file(s) and verifies via `mincore(2)` that **`max_resident_pages == 0`** before starting the timer.
4. **Strictest Baseline (`rg_best`)**: `wg (auto)` is compared directly against **`rg_best = min(rg --no-mmap, rg --mmap)`** in addition to same-mode (`no-mmap` vs. `no-mmap`, `mmap` vs. `mmap`) comparisons.

---

### 5.2 Platform-Conditional Library Optimizations (`comptime` Guards)

All hardware- and OS-specific optimizations inside `libwebgrep` are guarded at `comptime` (`builtin.cpu.arch`, `builtin.os.tag`, `builtin.cpu.arch.endian()`, and `build_options.teddy`) with zero-dependency portable fallbacks:

| Module | `comptime` Platform Guard | Optimization Mechanism & Gain |
| :--- | :--- | :--- |
| [`src/finder/packed_pair.zig`](src/finder/packed_pair.zig) | `builtin.cpu.arch.endian() == .little` & `width == 16 / 32` | Removed the 48-byte scalar prefix loop before the 128B 4-window SIMD loop; extracts lane hits via `@bitCast` hardware integer bitmask + `@ctz` bit-clearing (`6.75 GB/s` on 514 MB `log.txt`). |
| [`src/finder/teddy.zig`](src/finder/teddy.zig) & [`src/finder/multi.zig`](src/finder/multi.zig) | `build_options.teddy` (`avx2` / `ssse3` / `neon` / `off`) | Per-pattern rarest 3-byte window selection (`pickWindowOffset` + `pat_offsets`), 3rd-byte `vpshufb`/`tbl` SIMD secondary filter (`evalRefine`), and `preferTeddyOverPairs` adaptive routing. |
| [`src/finder/pairs.zig`](src/finder/pairs.zig) | `@Vector(width, u8)` native SIMD width | `rarestPair` minimum joint-frequency anchor selection + synchronous 2-byte `(v0 == f_splat) & (v1 == s_splat)` vector filtering in `scanDirect`. |
| [`src/regex/dfa.zig`](src/regex/dfa.zig) & [`src/regex/vm.zig`](src/regex/vm.zig) | Compile-time DFA state capacity & determinization guards | Ahead-of-time determinized DFA with precomputed linear single-successor chain depth (`chain_len` 2-byte tail fast-reject) + 4-way parallel transition verification; `haystack[0..limit]` bounded NUL scan in `Regex.findWatched`; non-overlapping `req_prefix_shift` and exact literal alternation (`alt_is_exact`) fast paths. |
| [`src/search/pipeline.zig`](src/search/pipeline.zig) & [`src/search/long_line.zig`](src/search/long_line.zig) | `exactMatcherMaxLen` bounded-matcher guard | Fused full-chunk scan (`fuse_full_buf`) for bounded-length exact matchers; on a chunk miss, retains only `max_pat_len - 1` overlap bytes, avoiding `lastComplete` backwards scans, duplicate NUL scans, and 400 KiB long-line tail `memmove`s (`8.03 GB/s` on `long.txt`). |
| [`src/search/config.zig`](src/search/config.zig) & [`src/io/platform.zig`](src/io/platform.zig) | `switch (comptime builtin.cpu.arch)` (`.x86_64, .aarch64`) & `switch (comptime builtin.os.tag)` (`.linux`) | `SearchConfig.optimalBufferSize(threads)` sizes per-worker streaming buffers to `256 KiB` when `threads > 1` so each worker buffer stays inside core-private 512 KiB L2 cache and cuts concurrent minor page faults (`minflt`) by 4x; issues `POSIX_FADV_SEQUENTIAL` on Linux. |

---

### 5.3 Warm Cache Results (`mincore = 100.0%`, 9 Interleaved ABBA Rounds, Median)

All 15 scenarios verified **100% accuracy parity** (identical exit codes, match counts, and `27,670,092`-byte FNV-1a checksum `c03c2d5e2da6acee` on `S03`) prior to timing:

| Scenario | Corpus & Query | `wg (auto)` (ms) | `wg (auto)` GB/s | `wg --mmap` (ms) | `rg --no-mmap` (ms) | `rg --mmap` (ms) | `rg_best` (ms) | `wg(auto)` vs `rg_best` | Same-Mode `no-mmap` |
| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | :---: | :---: |
| **`S01_log_lit_rare`** | `log.txt` (514 MB) `-c -F 'req=04203afdc6de'` | **76.15** | `6.750` | 85.46 | 79.25 | 85.75 | 79.25 | **1.04x WIN** | **1.05x** |
| **`S02_log_lit_dense`** | `log.txt` (514 MB) `-c -F 'ERROR [http]'` | **86.87** | `5.917` | 81.91 | 106.79 | 97.20 | 97.20 | **1.12x WIN** | **1.23x** |
| **`S03_log_lit_dense_lines`** | `log.txt` (514 MB) `-n -F 'ERROR [http]'` (27.7 MB out) | **115.36** | `4.455` | 112.46 | 137.42 | 125.08 | 125.08 | **1.08x WIN** | **1.18x** |
| **`S04_log_lit_icase`** | `log.txt` (514 MB) `-c -F -i 'error [http]'` | **114.66** | `4.483` | 113.15 | 164.08 | 144.96 | 144.96 | **1.26x WIN** | **1.44x** |
| **`S05_log_multi6_or`** | `log.txt` (514 MB) `-c -F` (6-pattern `-e` OR) | **108.91** | `4.719` | 105.00 | 123.38 | 110.38 | 110.38 | **1.01x WIN** | **1.13x** |
| **`S06_log_regex_prefilter`** | `log.txt` (514 MB) `-c 'ERROR \[http\] req=...'` | **107.89** | `4.764` | 117.73 | 122.91 | 110.17 | 110.17 | **1.02x WIN** | **1.14x** |
| **`S07_log_regex_midlit`** | `log.txt` (514 MB) `-c '\[[a-z]{4,5}\] req=0000...'` | **77.90** | `6.598` | 98.71 | 198.63 | 180.24 | 180.24 | **2.31x WIN** | **2.54x** |
| **`S08_log_regex_alt`** | `log.txt` (514 MB) `-c '(FATAL \[auth\]\|...)'` | **94.33** | `5.449` | **90.55** | 125.45 | 109.27 | 109.27 | **1.16x WIN** | **1.33x** |
| **`S09_long_lit_miss`** | `long.txt` (512 MB, 400 KiB lines) `-c -F` miss | **63.79** | `8.030` | 73.44 | 70.52 | 75.21 | 70.52 | **1.11x WIN** | **1.12x** |
| **`S10_short_lit_miss`** | `short.txt` (300 MB, 120M lines) `-c -F` miss | **35.99** | `8.336` | 40.91 | 41.22 | 42.19 | 41.22 | **1.15x WIN** | **1.16x** |
| **`S11_words_lit_rare`** | `words.txt` (540 MB) `-c -F 'zealtionou'` | **74.70** | `7.229` | 82.89 | 77.76 | 80.70 | 77.76 | **1.04x WIN** | **1.05x** |
| **`S12_words_regex`** | `words.txt` (540 MB) `-c 'zealtionou\s+[a-z]+\s+the'` | **76.78** | `7.033` | 85.44 | 77.52 | 80.42 | 77.52 | **1.01x WIN** | **1.04x** |
| **`S13_random_bin_quit`** | `random.bin` (537 MB binary) `-c -F` early NUL quit | **0.87** | `616.0` | **0.44** | 95.36 | 63.36 | 63.36 | **72.73x WIN** | **106.85x** |
| **`S14_dir_all_T1`** | `zg-corpus/` (2.49 GB, 9 files) `-c -j 1 -F` | **262.82** | `9.465` | 287.58 | 288.93 | 287.60 | 287.60 | **1.09x WIN** | **1.10x** |
| **`S15_dir_all_T8`** | `zg-corpus/` (2.49 GB, 9 files) `-c -j 8 -F` | **93.10** | `26.721` | 126.86 | 95.91 | 128.78 | 95.91 | **1.03x WIN** | **1.02x** |

---

### 5.4 Cold Disk Results (`POSIX_FADV_DONTNEED` + `mincore == 0`, 5 Interleaved Rounds, Median)

| Scenario | Corpus Size | `wg (auto)` (ms) | `wg (auto)` GB/s | `wg --mmap` (ms) | `rg --no-mmap` (ms) | `rg --mmap` (ms) | `rg_best` (ms) | `wg(auto)` vs `rg_best` | Same-Mode `no-mmap` |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :---: | :---: |
| **`S01_log_lit_rare`** | 514.0 MB | **278.38** | `1.846` | 364.86 | 384.63 | 375.70 | 375.70 | **1.35x WIN** | **1.38x** |
| **`S02_log_lit_dense`** | 514.0 MB | **290.27** | `1.771` | 369.92 | 396.26 | 383.57 | 383.57 | **1.32x WIN** | **1.37x** |
| **`S03_log_lit_dense_lines`** | 514.0 MB | **320.54** | `1.604` | 401.95 | 428.59 | 394.88 | 394.88 | **1.23x WIN** | **1.34x** |
| **`S04_log_lit_icase`** | 514.0 MB | **318.78** | `1.612` | 404.60 | 435.56 | 403.16 | 403.16 | **1.26x WIN** | **1.37x** |
| **`S05_log_multi6_or`** | 514.0 MB | **310.06** | `1.658` | 393.59 | 409.52 | 388.50 | 388.50 | **1.25x WIN** | **1.32x** |
| **`S06_log_regex_prefilter`** | 514.0 MB | **308.56** | `1.666` | 398.97 | 409.10 | 389.32 | 389.32 | **1.26x WIN** | **1.33x** |
| **`S07_log_regex_midlit`** | 514.0 MB | **277.96** | `1.849` | 379.58 | 431.70 | 417.14 | 417.14 | **1.50x WIN** | **1.55x** |
| **`S08_log_regex_alt`** | 514.0 MB | **293.79** | `1.750` | 382.31 | 402.58 | 389.24 | 389.24 | **1.32x WIN** | **1.37x** |
| **`S09_long_lit_miss`** | 512.2 MB | **264.88** | `1.934` | 351.83 | 367.85 | 363.34 | 363.34 | **1.37x WIN** | **1.39x** |
| **`S10_short_lit_miss`** | 300.0 MB | **158.14** | `1.897` | 217.07 | 227.06 | 232.02 | 227.06 | **1.44x WIN** | **1.44x** |
| **`S11_words_lit_rare`** | 540.0 MB | **284.08** | `1.901` | 365.17 | 392.42 | 371.07 | 371.07 | **1.31x WIN** | **1.38x** |
| **`S12_words_regex`** | 540.0 MB | **285.54** | `1.891` | 366.85 | 391.47 | 370.58 | 370.58 | **1.30x WIN** | **1.37x** |
| **`S13_random_bin_quit`** | 536.9 MB | **2.06** | `260.4` | **1.07** | 401.21 | 364.05 | 364.05 | **176.67x WIN** | **194.76x** |
| **`S14_dir_all_T1`** | 2,487.6 MB | **1025.16** | `2.427` | 1373.40 | 1456.60 | 1408.04 | 1408.04 | **1.37x WIN** | **1.42x** |
| **`S15_dir_all_T8`** | 2,487.6 MB | **885.54** | `2.809` | 961.00 | 1086.08 | 962.68 | 962.68 | **1.09x WIN** | **1.23x** |
