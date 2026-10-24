# libwebgrep Benchmarks

This document records the in-process `ReleaseFast` microbenchmarks implemented in [`bench/micro.zig`](bench/micro.zig).

Run the benchmark suite with:

```sh
zig build bench -Doptimize=ReleaseFast
```

## Methodology

- Each benchmark scenario prints:
  ```text
  scenario <name> bytes <n> gbs <throughput> iters <count> sink <checksum>
  ```
- Throughput is reported in **GB/s** (`bytes_processed / elapsed_seconds / 1e9`).
- Every scenario executes **1 unmeasured warmup iteration**, followed by at least **300 ms** and at least **2 measured iterations**.
- Before each iteration, a compiler memory barrier (`asm volatile ("" ::: .{ .memory = true })`) and a 1-bit flip on `buf[0]` prevent the compiler from hoisting or eliminating pure slice scans.
- `sink` accumulates the return value of every iteration and is verified against the exact expected match offset or line count; any mismatch fails the benchmark immediately.

## Test Environment

| Property | Value |
| :--- | :--- |
| **Date** | 2026-10-24 |
| **Hardware** | Apple M2 (8 cores, 8 GiB RAM) |
| **OS / Arch** | macOS (`aarch64-macos`) |
| **Compiler** | Zig `0.17.0` (`-Doptimize=ReleaseFast`) |
| **Native SIMD Width** | 16 bytes (ARM NEON) |
| **Teddy Engine** | `neon` (default on `aarch64`) |

---

## Latest Benchmark Output

```text
libwebgrep bench width 16 walk_default_threads 1
scenario memchr_find bytes 67108864 gbs 48.254 iters 216 sink 0
scenario memchr_either bytes 67108864 gbs 62.390 iters 279 sink 0
scenario std_find_scalar bytes 67108864 gbs 50.912 iters 228 sink 0
scenario finder_sensitive bytes 67108864 gbs 42.617 iters 191 sink 12817791687
scenario finder_ignore bytes 67108864 gbs 24.881 iters 112 sink 7516191984
scenario finder_smart bytes 67108864 gbs 24.570 iters 110 sink 7381974270
scenario search_slice bytes 67108864 gbs 28.062 iters 126 sink 126
engine multi_bytes bytes
scenario multi_bytes bytes 67108864 gbs 34.182 iters 153 sink 0
engine multi_pairs pairs
scenario multi_pairs bytes 67108864 gbs 32.162 iters 144 sink 144
engine multi_teddy teddy
scenario multi_teddy bytes 67108864 gbs 24.131 iters 108 sink 0
engine multi_ac ac
scenario multi_ac bytes 67108864 gbs 24.273 iters 109 sink 0
scenario finder_alphabet bytes 67108864 gbs 42.818 iters 192 sink 12884899776
scenario regex_prefilter bytes 67108864 gbs 42.866 iters 192 sink 12884899776
scenario file_64KiB bytes 134217735 gbs 10.150 iters 23 sink 23
scenario file_128KiB bytes 134217735 gbs 10.417 iters 24 sink 24
scenario file_256KiB bytes 134217735 gbs 10.789 iters 25 sink 25
scenario file_1MiB bytes 134217735 gbs 10.987 iters 25 sink 25
scenario file_readall bytes 134217735 gbs 6.149 iters 14 sink 14
scenario walk_1 bytes 786432 gbs 0.158 iters 61 sink 549
```

---

## 1. In-Memory 64 MiB Kernel & Engine Throughput

The 64 MiB buffer (`67,108,864` bytes) is populated with 64-byte lines of `'a'` terminated by `\n`, with `"NEEDLE\n"` placed at the final 7 bytes (`offset = 67,108,857`). For `finder_alphabet` and `regex_prefilter`, the buffer is populated with repeating `"abcdefghijklmnopqrstuvwxyz\n"` lines and `"libwebgrep\n"` at the end.

| Scenario | Engine / Algorithm | Result per Run | Throughput (GB/s) |
| :--- | :--- | :--- | ---: |
| `memchr_find` | Single-byte SIMD (`memchr.find`) | Miss (`0`) | **48.25 GB/s** |
| `memchr_either` | 2-byte 4-vector unrolled SIMD (`memchr.findEither`) | Miss (`0`) | **62.39 GB/s** |
| `std_find_scalar` | `std.mem.findScalar` baseline | Miss (`0`) | **50.91 GB/s** |
| `finder_sensitive` | `Finder` (`PackedPair` 4-window SIMD, `"NEEDLE"`) | Match at tail | **42.62 GB/s** |
| `finder_ignore` | `Finder` (`PackedPair` branchless `(block \| 0x20)`, `"needle"`) | Match at tail | **24.88 GB/s** |
| `finder_smart` | `Finder` (smart-case `"needle"`) | Match at tail | **24.57 GB/s** |
| `finder_alphabet` | `Finder` (`"libwebgrep"` on repeating alphabet text) | Match at tail | **42.82 GB/s** |
| `regex_prefilter` | `Regex` (`"libweb.*[0-9]*grep"`, Thompson NFA + SIMD prefilter) | Match at tail | **42.87 GB/s** |
| `search_slice` | Full `searchSlice` pipeline (line framing + NUL watch) | 1 matched line | **28.06 GB/s** |
| `multi_bytes` | `Multi` → `ByteSet` (4-way unrolled SIMD single-byte set) | 0 lines | **34.18 GB/s** |
| `multi_pairs` | `Multi` → `RarePair` (2-stage direct SIMD pair compare) | 1 matched line | **32.16 GB/s** |
| `multi_teddy` | `Multi` → `Teddy` (17 2-byte patterns, NEON `vtbl` nibble mask) | 0 lines | **24.13 GB/s** |
| `multi_ac` | `Multi` → `AhoCorasick` (33 patterns, dense DFA + 64B nibble skip) | 0 lines | **24.27 GB/s** |

### Why Throughput Reaches 24–62 GB/s

1. **Zero-Branch 4-Vector Unrolling**: `memchr.findEither`, `PackedPair`, `ByteSet`, `RarePair`, and `AhoCorasick`'s `state == 0` skip loop process 64 bytes per iteration (`4 x 16B` vectors) and merge comparison masks with `@reduce(.Or)` before branching once.
2. **Branchless Bitwise Case Folding**: ASCII case-insensitive SIMD comparison folds uppercase letters via `(block | @splat(0x20)) == lower_splat` instead of two equality comparisons plus an OR per byte.
3. **2-Stage Candidate Verification**: `Teddy` and `RarePair` check primary anchor masks across 64 bytes first, and only compute secondary shifted masks when a primary hit occurs.
4. **Regex on Top of SIMD**: `Regex` extracts required prefix/suffix literals from the AST (`RequiredLiteral`) and scans the haystack at **42.87 GB/s** using `Finder`, invoking the linear-time Thompson NFA only on candidate line windows.

---

## 2. Streaming File I/O (`128 MiB` File Sweep)

`bench/tmp/sweep.txt` (`134,217,735` bytes = `128 MiB` body + `"NEEDLE\n"`) is searched end-to-end via `searchFile` across varying rolling buffer sizes:

| Rolling Buffer Size | Throughput (GB/s) | Latency per `128 MiB` File |
| :--- | ---: | ---: |
| `64 KiB` | **10.15 GB/s** | `13.2 ms` |
| `128 KiB` | **10.42 GB/s** | `12.9 ms` |
| `256 KiB` | **10.79 GB/s** | `12.4 ms` |
| `1 MiB` (default) | **10.99 GB/s** | `12.2 ms` |
| `file_readall` (`128 MiB` single allocation) | **6.15 GB/s** | `21.8 ms` |

Streaming in a reusable `1 MiB` L2/SLC-resident buffer is **1.79x faster** than allocating and reading the entire `128 MiB` file at once.
