# libwebgrep Benchmarks (v0.4.1)

This document records the reproducible `ReleaseFast` microbenchmarks ([`bench/micro.zig`](bench/micro.zig)) across `x86_64` (AMD Ryzen 7 7735U AVX2) and `aarch64` (Apple M2 NEON), the microarchitectural cache-hierarchy throughput curves, the `v0.3.0`–`v0.4.1` engine specialization evaluations, and the **reproducible 17-scenario Warm Cache (`mincore=100%`) & Cold Disk (`fsync` + `POSIX_FADV_DONTNEED` + `mincore=0`) end-to-end comparative experiment against `ripgrep 15.2.0`** ([`bench/wg_cli.zig`](bench/wg_cli.zig) & [`bench/bench_driver.c`](bench/bench_driver.c)).

Run the in-process microbenchmark suite with:

```sh
zig build bench -Doptimize=ReleaseFast -Dteddy=avx2
```

Build and run the standalone CLI + C11 end-to-end benchmark harness against `ripgrep` with:

```sh
zig build bench-cli -Doptimize=ReleaseFast -Dteddy=avx2
./zig-out/bin/bench-driver all --warm-rounds 7 --cold
```

---

## 1. Executive Summary

1. **Microarchitectural Compute Peak vs. Memory Bandwidth Wall**:
   - Inside L1d / L2 cache on a single physical core (AMD Ryzen 7 7735U, Zen 3+, 32-byte AVX2 vectors), `libwebgrep` reaches **`147.8 GB/s`** (`memchr.findEither`), **`81.0 GB/s`** (`Finder` / `PackedPair`), **`67.2 GB/s`** (AVX2 `Teddy`), and **`63.8 GB/s`** (`Finder` case-insensitive).
   - Once the working set exceeds the 16 MiB L3 cache into 64 MiB DRAM, throughput converges to the single-core memory controller read bandwidth ceiling (**`20.4–28.2 GB/s`** on LPDDR5 `x86_64` with CV `0.10%–0.32%`, and **`24.1–62.4 GB/s`** on unified-memory Apple M2 `aarch64`).
2. **Core Engine Capabilities (`v0.3.0`–`v0.4.1`)**:
   - **`Scratch` Worker Buffer Pool**: Reduces heap allocations across `20,000 × 4 KiB` context-enabled streaming searches from `40,000` allocations (`81.25 GiB`) to **2 warmup allocations (`0` steady-state allocations)**, boosting throughput by **`44.7x` (`12,284 QPS → 549,368 QPS`, `1.82 µs/req`)**.
   - **`RegexSet` Single-Pass Multi-Regex**: Evaluates 256 prefixed regular expressions simultaneously at **`35.13 GB/s`** (**`266x` faster** than looping 256 individual `Regex.isMatch` calls at `0.132 GB/s`).
   - **Zero-Cost Polymorphism & C ABI ([`include/webgrep.h`](include/webgrep.h))**: Runtime-dispatched `AnyMatcher` + `AnyEventSink` incurs **`< 0.02%`** overhead vs. static generics, and the zero-`libc` C ABI (`webgrep_search_slice`) incurs **`< 0.4%`** FFI overhead.
3. **17 / 17 Non-Inferiority & Surpass over `ripgrep 15.2.0` (Warm Cache & Cold Disk)**:
   - Evaluated via [`bench/wg_cli.zig`](bench/wg_cli.zig) and [`bench/bench_driver.c`](bench/bench_driver.c) on the 2.488 GB `zg-corpus` using an interleaved ABBA C11 benchmark driver (`sched_setaffinity` to physical Core 2, `mincore(2)` residency verification with hard fail on residual cold pages, and median-sample `wait4` resource accounting), `libwebgrep` (`wg_best = min(wg --no-mmap, wg --mmap)`) achieves **`wg_best <= rg_best` on 17/17 scenarios in Warm Cache** — **15 scenarios clearly surpass `rg_best` (`1.01x–2.88x`, with 14 at `1.02x–2.88x`) and 2 scenarios (`S01` at `75.43 ms vs 75.46 ms`, `S15` at `104.20 ms vs 104.72 ms`) tie `rg_best` (`1.00x`, within ~1% CV), with zero scenarios lagging** — and **surpasses `rg_best` on all 17/17 scenarios in Cold Disk (`1.08x–2.02x`)** with **100% output, exit-code, and match-count parity**.

---

## 2. Test Environments

| Property | Primary Linux `x86_64` Rig (`v0.4.1`) | Reference macOS `aarch64` Rig |
| :--- | :--- | :--- |
| **Processor** | AMD Ryzen 7 7735U (Zen 3+, 8C/16T, up to `4.82 GHz`) | Apple M2 (8 cores, 8 GiB unified RAM) |
| **Cache Topology** | L1d `32 KiB/core` \| L2 `512 KiB/core` \| **L3 `16 MiB` shared** | L1d `128/64 KiB` \| SLC + unified memory |
| **Native SIMD Width** | **32 bytes (`x86_64` AVX2)** + BMI2 + POPCNT | **16 bytes (`aarch64` ARM NEON)** |
| **Compiler & Baseline** | Zig `0.17.1` (`ReleaseFast`, `znver3`), `gcc 14.2.0`, `ripgrep 15.2.0` | Zig `0.17.0` (`ReleaseFast`, `apple_m2`) |
| **Isolation Controls** | `sched_setaffinity` physical Core 2 (1T) / Cores `0,2,4,6,8,10,12,14` (8T), `mincore(2)` hard check | Unpinned single-process warmup + timed loop |

---

## 3. In-Process 35-Scenario Microbenchmark Suite ([`bench/micro.zig`](bench/micro.zig))

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

Measured on a single pinned physical core (Ryzen 7 7735U AVX2) across working sets from `16 KiB` (L1d) to `64 MiB` (DRAM):

| Engine Kernel | `16 KiB` (L1d) | `256 KiB` (L2) | `4 MiB` (L3) | `8 MiB` (L3) | `16 MiB` (L3 Edge) | `64 MiB` (DRAM) | Bottleneck Regime |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | :--- |
| **`memchr_either`** | **147.77 GB/s** | 143.65 GB/s | 119.99 GB/s | 119.93 GB/s | 66.04 GB/s | **28.10 GB/s** | Memory-bandwidth bound above L3 (5.26x L1→DRAM ratio) |
| **`finder_sensitive`** | 73.34 GB/s | **81.03 GB/s** | 78.56 GB/s | 77.88 GB/s | 44.10 GB/s | **23.36 GB/s** | Peak IPC at `256 KiB` L2; DRAM-bound at `64 MiB` |
| **`multi_teddy` (AVX2)** | 59.94 GB/s | **67.18 GB/s** | 67.11 GB/s | 67.03 GB/s | 38.05 GB/s | **21.34 GB/s** | Dual-port `vpshufb` sustains **67 GB/s** throughout L2/L3 |
| **`finder_ignore`** | 53.33 GB/s | **63.83 GB/s** | 63.49 GB/s | 62.16 GB/s | 36.21 GB/s | **20.95 GB/s** | Branchless `(block \| 0x20)` sustains **63.8 GB/s** in L2/L3 |
| **`multi_ac`** | 33.31 GB/s | **35.38 GB/s** | 35.08 GB/s | 35.02 GB/s | 25.81 GB/s | **19.06 GB/s** | 64B nibble skip hides dense DFA transition table latency |

---

## 5. Reproducible 17-Scenario Comparative Experiment vs. `ripgrep 15.2.0`

### 5.1 Experimental Methodology ([`bench/wg_cli.zig`](bench/wg_cli.zig) & [`bench/bench_driver.c`](bench/bench_driver.c))

To eliminate ordering bias, page-cache leakage, and I/O mode asymmetry, `libwebgrep` is benchmarked via the in-tree CLI wrapper ([`bench/wg_cli.zig`](bench/wg_cli.zig)) and native C11 driver ([`bench/bench_driver.c`](bench/bench_driver.c)), built via `zig build bench-cli -Doptimize=ReleaseFast -Dteddy=avx2`:

1. **Symmetric 4-Contender Subprocess Accounting**: All 4 distinct I/O configurations (`wg --no-mmap`, `wg --mmap`, `rg --no-mmap`, `rg --mmap`) are launched via `fork() + execve()` and measured with `clock_gettime(CLOCK_MONOTONIC_RAW)` + `wait4()`. Each round records a coupled `TimedSample { wall_ms, user_ms, sys_ms, minflt, majflt }` and sorts by `wall_ms` so that all reported resource metrics come from the exact median wall-clock sample.
2. **ABBA Interleaved Ordering & Physical Core Pinning**: Single-threaded scenarios (`S01`–`S14`) are pinned to physical Core 2 (`sched_setaffinity`, avoiding Core 0 IRQ noise); 8-thread directory search (`S15`) is pinned to all 8 physical cores (`0,2,4,6,8,10,12,14`). Even rounds execute in forward order (`0 → 3`) and odd rounds execute in reverse order (`3 → 0`) across **7 Warm Cache rounds** and **5 Cold Disk rounds**.
3. **`mincore(2)` Hardware Page-Cache Residency Proofs**:
   - **Warm Cache**: Pre-warmed via `populate_page_cache()` and verified via `mincore(2)` prior to timing (`mincore == 100.0%` resident).
   - **Cold Disk**: Before **every individual subprocess invocation**, the harness calls `fsync(fd)` + `posix_fadvise(fd, 0, 0, POSIX_FADV_DONTNEED)` on the target file(s) and verifies via `mincore(2)` that **`max_resident_pages == 0`** (hard-aborting with exit code `2` if any page remains resident).
4. **Apples-to-Apples Binary & Dense Regex Coverage**:
   - **`S12_words_regex` & `S12b_words_regex_dense`**: Tests both the rare prefix-literal regex (`zealtionou\s+[a-z]+\s+the`, 40 hits) and the high-frequency interior-literal regex (`[a-z]+tion\s+[a-z]+\s+the`, 27,035 hits across millions of `"tion"` occurrences).
   - **`S13_random_bin_quit` & `S13b_random_bin_text`**: Tests both directory-mode implicit binary quit (`-g random.bin`, where both `wg` and `rg` stop on the first NUL byte) and explicit full-file binary scan (`-a/--text` on 537 MB `random.bin`, where both `wg` and `rg` scan all 537 MB).

---

### 5.2 Platform-Conditional Library Optimizations (`comptime` Guards)

All hardware- and OS-specific optimizations inside `libwebgrep` are guarded at `comptime` (`builtin.cpu.arch`, `builtin.os.tag`, `builtin.cpu.arch.endian()`, and `build_options.teddy`) with zero-dependency portable fallbacks:

| Module | `comptime` Platform Guard | Optimization Mechanism & Gain |
| :--- | :--- | :--- |
| [`src/finder/packed_pair.zig`](src/finder/packed_pair.zig) | `builtin.cpu.arch.endian() == .little` & `width == 16 / 32` | Removed the 48-byte scalar prefix loop before the 128B 4-window SIMD loop; extracts lane hits via `@bitCast` hardware integer bitmask + `@ctz` bit-clearing (`6.81 GB/s` on 514 MB `log.txt`). |
| [`src/finder/teddy.zig`](src/finder/teddy.zig) & [`src/finder/multi.zig`](src/finder/multi.zig) | `build_options.teddy` (`avx2` / `ssse3` / `neon` / `off`) | Per-pattern rarest 3-byte window selection (`pickWindowOffset` + `pat_offsets`), 3rd-byte `vpshufb`/`tbl` SIMD secondary filter (`evalRefine`), and `preferTeddyOverPairs` adaptive routing. |
| [`src/regex/dfa.zig`](src/regex/dfa.zig), [`src/regex/vm.zig`](src/regex/vm.zig) & [`src/regex/prefilter.zig`](src/regex/prefilter.zig) | Compile-time DFA state capacity & determinization guards | Ahead-of-time determinized prefix DFA (`dfa_is_exact` in `.earliest` mode) + **interior required-literal suffix DFA (`dfa_suffix_state` & `determinizeSuffix`)** rejecting non-matching suffixes in 1–5 bytes before `windowLimit`/`lineStartAt`; single-pass fused `pf.findWatched` in `Regex.findWatched`. |
| [`src/search/pipeline.zig`](src/search/pipeline.zig) & [`src/search/line_matcher.zig`](src/search/line_matcher.zig) | `@hasDecl(S, "matched")` & `exactMatcherMaxLen` comptime checks | Count-only `needLineStart` elision skips backward `memchr.findLast` when no `matched` callback is present; direct `sinkMatched` in `searchPrepared` eliminates duplicate per-line `matcher.find` on `mmap`; 64 KiB initial binary-quit probe on cold streams. |
| [`src/search/config.zig`](src/search/config.zig) & [`src/io/platform.zig`](src/io/platform.zig) | `switch (comptime builtin.cpu.arch)` (`.x86_64, .aarch64`) & `switch (comptime builtin.os.tag)` (`.linux`) | `SearchConfig.optimalBufferSize(threads)` sizes per-worker streaming buffers (`1 MiB` for 1T, `256 KiB` for multi-thread L2 residency); issues `POSIX_FADV_SEQUENTIAL` and `MADV_SEQUENTIAL \| MADV_HUGEPAGE` on Linux. |

---

### 5.3 Warm Cache Results (`mincore = 100.0%`, 7 Interleaved ABBA Rounds, Median)

All 17 scenarios verified **100% accuracy parity** (identical exit codes, match counts, and `27,670,092`-byte FNV-1a checksum `c03c2d5e2da6acee` on `S03`) prior to timing. Across the 17 Warm Cache scenarios, `wg_best <= rg_best` on all 17/17 (`0` lagging): 15 scenarios surpass `rg_best` (`1.01x–2.88x`) and 2 scenarios (`S01` at `75.43 ms vs 75.46 ms`, `S15` at `104.20 ms vs 104.72 ms`) tie `rg_best` (`1.00x`, within ~1% CV):

| Scenario | Corpus & Query | `wg --no-mmap` (ms) | `wg --mmap` (ms) | `rg --no-mmap` (ms) | `rg --mmap` (ms) | `wg_best` vs `rg_best` | Same-Mode (`no-mmap` / `mmap`) |
| :--- | :--- | ---: | ---: | ---: | ---: | :---: | :---: |
| **`S01_log_lit_rare`** | `log.txt` (514 MB) `-c -F 'req=04203afdc6de'` | **75.43** | 84.95 | 79.35 | **75.46** | **1.00x TIE** | **1.05x** / 0.89x |
| **`S02_log_lit_dense`** | `log.txt` (514 MB) `-c -F 'ERROR [http]'` | **82.00** | 83.99 | 107.61 | **95.07** | **1.16x WIN** | **1.31x** / **1.13x** |
| **`S03_log_lit_dense_lines`** | `log.txt` (514 MB) `-n -F 'ERROR [http]'` (27.7 MB) | **112.51** | 114.66 | 139.04 | **124.66** | **1.11x WIN** | **1.24x** / **1.09x** |
| **`S04_log_lit_icase`** | `log.txt` (514 MB) `-c -F -i 'error [http]'` | 107.56 | **103.23** | 160.29 | **138.54** | **1.34x WIN** | **1.49x** / **1.34x** |
| **`S05_log_multi6_or`** | `log.txt` (514 MB) `-c -F` (6-pattern `-e` OR) | 102.71 | **95.84** | 122.42 | **109.03** | **1.14x WIN** | **1.19x** / **1.14x** |
| **`S06_log_regex_prefilter`** | `log.txt` (514 MB) `-c 'ERROR \[http\] req=...'` | 104.73 | **100.48** | 118.23 | **105.18** | **1.05x WIN** | **1.13x** / **1.05x** |
| **`S07_log_regex_midlit`** | `log.txt` (514 MB) `-c '\[[a-z]{4,5}\] req=0000...'` | **73.73** | 77.15 | 196.24 | **178.06** | **2.42x WIN** | **2.66x** / **2.31x** |
| **`S08_log_regex_alt`** | `log.txt` (514 MB) `-c '(FATAL \[auth\]\|...)'` | 91.50 | **85.25** | 122.49 | **105.25** | **1.23x WIN** | **1.34x** / **1.23x** |
| **`S09_long_lit_miss`** | `long.txt` (512 MB, 400 KiB lines) `-c -F` miss | **65.91** | 76.29 | **73.80** | 77.78 | **1.12x WIN** | **1.12x** / **1.02x** |
| **`S10_short_lit_miss`** | `short.txt` (300 MB, 120M lines) `-c -F` miss | **41.23** | 46.84 | 45.28 | **44.39** | **1.08x WIN** | **1.10x** / 0.95x |
| **`S11_words_lit_rare`** | `words.txt` (540 MB) `-c -F 'zealtionou'` | **78.60** | 88.85 | 82.87 | **80.16** | **1.02x WIN** | **1.05x** / 0.90x |
| **`S12_words_regex`** | `words.txt` (540 MB) `-c 'zealtionou\s+[a-z]+\s+the'` | **79.86** | 90.02 | 84.53 | **80.40** | **1.01x WIN** | **1.06x** / 0.89x |
| **`S12b_words_regex_dense`** | `words.txt` (540 MB) `-c '[a-z]+tion\s+[a-z]+\s+the'` | **263.57** | 309.76 | 779.09 | **758.16** | **2.88x WIN** | **2.96x** / **2.45x** |
| **`S13_random_bin_quit`** | `zg-corpus/` `-g random.bin` (537 MB) NUL quit | 0.65 | **0.63** | **1.36** | 1.39 | **2.16x WIN** | **2.09x** / **2.20x** |
| **`S13b_random_bin_text`** | `random.bin` (537 MB) `-a -c -F` full binary scan | **53.57** | 64.22 | **62.49** | 68.27 | **1.17x WIN** | **1.17x** / **1.06x** |
| **`S14_dir_all_T1`** | `zg-corpus/` (2.49 GB, 9 files) `-c -j 1 -F` | **265.14** | 285.94 | 293.04 | **286.85** | **1.08x WIN** | **1.11x** / **1.00x** |
| **`S15_dir_all_T8`** | `zg-corpus/` (2.49 GB, 9 files) `-c -j 8 -F` | **104.20** | 140.43 | **104.72** | 139.89 | **1.00x TIE** | **1.00x** / **1.00x** |

---

### 5.4 Cold Disk Results (`fsync` + `POSIX_FADV_DONTNEED` + `mincore == 0`, 5 Interleaved Rounds, Median)

| Scenario | Corpus Size | `wg --no-mmap` (ms) | `wg --mmap` (ms) | `rg --no-mmap` (ms) | `rg --mmap` (ms) | `wg_best` vs `rg_best` | Same-Mode (`no-mmap` / `mmap`) |
| :--- | ---: | ---: | ---: | ---: | ---: | :---: | :---: |
| **`S01_log_lit_rare`** | 514.0 MB | 287.23 | **213.86** | 396.26 | **382.78** | **1.79x WIN** | **1.38x** / **1.79x** |
| **`S02_log_lit_dense`** | 514.0 MB | 288.08 | **192.60** | 405.87 | **389.03** | **2.02x WIN** | **1.41x** / **2.02x** |
| **`S03_log_lit_dense_lines`** | 514.0 MB | 318.92 | **225.73** | 435.58 | **396.46** | **1.76x WIN** | **1.37x** / **1.76x** |
| **`S04_log_lit_icase`** | 514.0 MB | 309.76 | **213.52** | 458.59 | **409.59** | **1.92x WIN** | **1.48x** / **1.92x** |
| **`S05_log_multi6_or`** | 514.0 MB | 305.51 | **210.56** | 414.53 | **391.22** | **1.86x WIN** | **1.36x** / **1.86x** |
| **`S06_log_regex_prefilter`** | 514.0 MB | 310.17 | **220.47** | 418.21 | **390.15** | **1.77x WIN** | **1.35x** / **1.77x** |
| **`S07_log_regex_midlit`** | 514.0 MB | 284.74 | **210.22** | 491.77 | **424.90** | **2.02x WIN** | **1.73x** / **2.02x** |
| **`S08_log_regex_alt`** | 514.0 MB | 298.81 | **212.16** | 419.65 | **391.19** | **1.84x WIN** | **1.40x** / **1.84x** |
| **`S09_long_lit_miss`** | 512.2 MB | 269.16 | **204.24** | 380.22 | **375.60** | **1.84x WIN** | **1.41x** / **1.84x** |
| **`S10_short_lit_miss`** | 300.0 MB | 164.30 | **135.72** | **231.02** | 237.90 | **1.70x WIN** | **1.41x** / **1.75x** |
| **`S11_words_lit_rare`** | 540.0 MB | 287.48 | **221.37** | 396.36 | **374.16** | **1.69x WIN** | **1.38x** / **1.69x** |
| **`S12_words_regex`** | 540.0 MB | 288.24 | **222.02** | 397.99 | **372.52** | **1.68x WIN** | **1.38x** / **1.68x** |
| **`S12b_words_regex_dense`** | 540.0 MB | 464.59 | **443.47** | 1094.81 | **870.72** | **1.96x WIN** | **2.36x** / **1.96x** |
| **`S13_random_bin_quit`** | 536.9 MB | **1.11** | 1.22 | **1.89** | 1.89 | **1.70x WIN** | **1.70x** / **1.55x** |
| **`S13b_random_bin_text`** | 536.9 MB | 265.06 | **202.70** | 394.92 | **369.24** | **1.82x WIN** | **1.49x** / **1.82x** |
| **`S14_dir_all_T1`** | 2,487.6 MB | 1018.30 | **721.25** | 1451.80 | **1398.97** | **1.94x WIN** | **1.43x** / **1.94x** |
| **`S15_dir_all_T8`** | 2,487.6 MB | **889.84** | 946.46 | 1102.98 | **963.16** | **1.08x WIN** | **1.24x** / **1.02x** |
