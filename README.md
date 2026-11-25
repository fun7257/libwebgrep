# libwebgrep

[English](README.md) | [简体中文](README.zh-CN.md)

**`libwebgrep` (`v0.10.3`)** is an ultra-fast, embeddable SIMD text and regular expression search engine library written in pure **Zig `0.17.1`**, purpose-built for multi-tenant web services, log analytics, and code search backends.

It ships with **zero external dependencies**, **does not link `libc`**, guarantees **worst-case $O(n)$ linear time** across all literal, multi-pattern, and regex queries, and enforces strict **multi-tenant resource budgets** (scan bytes, wall-clock deadlines, memory caps, and Zip-Bomb decompression guards).

---

## Key Highlights (`v0.10.3`)

- **93 / 93 (100% WIN) vs. `ripgrep 16.0.0`, Runtime CPUID Dispatch & Cross-Arch Portability**:
  - **End-to-End `ripgrep 16.0.0` Benchmark Sweep**: Wins **93 / 93** scenarios (**0 TIE / 0 LAG / 0 MISMATCH**, grand geomean **`1.82x`**, min **`1.06x`**) across Core (`S01`–`S19`, 22/22, geomean **`1.31x`**), Adversarial Stress (`X01`–`X13`, 15/15, geomean **`1.89x`**), P0–P1 (`Y01`–`Y16`, 41/41, geomean **`2.21x`**), and Extended (`R01`–`P03`, 15/15, geomean **`1.74x`**) suites, reaching **`25.31 GB/s`** on 8-thread 2.49 GB directory scans (`S15 --mmap`, `97.97 ms`).
  - **Baseline `x86_64` + Runtime CPUID Dispatch (`-Dteddy=runtime`)**: Safe on baseline SSE2 `x86_64` CPUs with zero illegal instructions, while automatically dispatching to AVX2/SSSE3 at runtime via `CPUID + OSXSAVE + XGETBV`, plus full **ARM NEON** (`aarch64`), **Big-Endian** (`s390x`), and **WASM / WASI** (`wasm32-wasi`) support.
  - **Single-Byte & Single-Literal (`memchr` / `Finder`)**: `@ctz`/`@clz`-accelerated 4-vector unrolled SIMD loops (`findSepOrNul` simultaneous `\n`/`\0` probe), frequency-ranked `PackedPair` SIMD filtering with inline case-folding + `watch_nul` confirmation, single-pass `scanFinderFast`, and worst-case $O(n)$ `TwoWay` fallback.
  - **4-Tier Multi-Pattern OR Matrix (`Multi`)**: Automatically dispatches across `ByteSet`, `RarePair`, 8-bucket Slim `Teddy` (`vtbl`/`pshufb`/`vpshufb`) with fused `findVerified` and bucket-aware ghost-byte avoidance, and a hybrid dense-prefix + sparse-NFA `AhoCorasick` automaton with frequency-ordered BFS, depth-2 L2 budget, and adaptive **4-stream ILP** scanning (`20.56 GB/s` in microbenchmarks), reporting exact `pattern_id` on every match.
  - **Two-Tier Unanchored Set DFA + Linear-Time Regex (`Regex` & `RegexSet`)**: Lockstep Thompson NFA / PikeVM paired with `UnanchoredDfa`, `BoundedDfa`, and **`SetUnanchoredDfa` / `LazySetDfa`** wired into both `Regex` and `RegexSet`, multiline `PrefixAnyTail` fast paths, up to 32 captures (`$1`..`$32`) with named groups (`(?P<name>...)` / `(?<name>...)` and `CompiledReplacement` `${name}` expansion), `\xHH`/`\x{...}`/`\uHHHH`/`\u{...}`, `\Q...\E`, `\a`/`\f`/`\v`/`\Z`, 14 POSIX classes, `(?x)`/`(?U)`/`(?u)` flags, `\p{...}` Unicode properties, **UTS #18 Unicode 16.0 word boundaries** (`whole_word_unicode` / `webgrep_whole_word_mode_t`), and structured `CompileDiagnostic`.
- **Zero-Copy Windowed `mmap`, Bomb-Safe Streaming Decompression & SIMD Encodings**:
  - **Zero-Copy 8 MiB Windowed `mmap` (`src/io/window_map.zig`)**: Integrated directly into `src/parallel.zig` and single-file `--mmap` search on Linux to keep PTE pages L2/L3-hot at `munmap` time, paired with 64B-aligned `preadv` streaming buffers to eliminate 4K-aliasing cliffs.
  - **In-Process Streaming Decompression & Zero-Disk Archives**: Streams **Gzip, Zlib, Deflate, Zstd, XZ, LZ4, Bzip2, and Brotli** in-process without spawning external binaries, enforcing `max_decompressed_bytes` and `max_compression_ratio` (default `100:1`) on every chunk to stop Zip Bombs; supports constant-memory `searchTarStream`, zero-disk in-memory `ArchiveTree` (`.tar.*`, `.zip` / ZIP64, nested archives) with parallel `Scheduler` support and Zip-Slip protection.
  - **SIMD Multi-Encoding Transcoding**: Sniffs UTF-8 / UTF-16 / UTF-32 BOMs and transcodes **SIMD GBK (direct UTF-8 LUT / Variant H), GB18030, SIMD UTF-16LE, UTF-16BE, Latin-1, Windows-1252, Windows-1251, Shift-JIS, EUC-JP, Big5, and EUC-KR** (plus heuristic detection and HTTP `charset` hints), while maintaining run-level `OffsetMap` translations (`raw_offset`) and UTF-16 code-unit spans.
- **Hardened for Multi-Tenant Server Embedding, 172 File Types, 60-Function C ABI & Fuzz/OOM Audit**:
  - Public service entry points (`searchSource`, `searchSourceSlice`, `resumeSourceSlice`, `openSourcePull`, `openReaderPull`) operate strictly on caller-supplied `std.Io.Reader` streams or memory slices with caller-assigned `source_id`—eliminating path traversal (`CWE-22`) by design.
  - Reusable `Scratch` buffer pool (`SearchConfig.scratch_pool`), configurable CRLF handling (`SearchConfig.strip_cr`), runtime type-erased `AnyMatcher` / `AnyEventSink`, **172 built-in file types** (`src/walk/types.zig`), and a **60-function** zero-`libc` C ABI (`include/webgrep.h`, `WEBGREP_API`), including custom allocator hooks (`webgrep_set_allocator`) and distinct `WEBGREP_ERR_PATH_TRAVERSAL` / `WEBGREP_ERR_UNSUPPORTED_FORMAT` status codes.
  - Verified by Zig unit/E2E/adversarial/doc tests, **`27 / 27` C ABI test sections** (including exhaustive OOM-rollback leak audits), **5 differential fuzz suites**, a `std.testing.checkAllAllocationFailures` OOM injection audit (`src/fuzz.zig`), and optional standalone CLI parity binary `wg-cli` (`-Dcli=true` / `zig build bench-cli`).

---

## Performance Overview (`v0.10.0`)

1. **End-to-End `v0.10.0` vs. `ripgrep 16.0.0` (93-Case Full Matrix, AMD Ryzen 7 7735U AVX2, `ReleaseFast -Dteddy=avx2`)**:

| Benchmark Suite | Cases | WIN / TIE / LAG | Geomean Speedup (`wg` vs `rg 16.0.0`) | Min Ratio | Highlights |
| :--- | ---: | :---: | ---: | ---: | :--- |
| **Core Suite (`S01`–`S19`, 2.48 GB)** | 22 | **22 / 0 / 0** | **`1.28x`** → **`1.31x`**\* | **1.06x** | `S15 --mmap`: **`97.97 ms` (`25.31 GB/s`, `1.33x` mmap WIN)**; `S14 --mmap`: **`253.71 ms` (`1.12x`)** |
| **Adversarial Stress (`X01`–`X13`)** | 15 | **15 / 0 / 0** | **`1.87x`** → **`1.89x`**\* | **1.12x** | `X01u_nolit_unicode`: **`10.11x`** (`15.12x` mmap); `X04_large_dfa`: **`4.11x`**; `X05–X07`: **`2.19x–2.59x`** |
| **P0–P1 Targeted (`Y01`–`Y16`)** | 41 | **41 / 0 / 0** | **`2.21x`** | **1.09x** | `Y03u`: **`55.56x`**; `Y06c`: **`10.94x`**; `Y02`: **`9.43x`**; `Y16c_smart_case`: **`1.77x`** |
| **Extended Coverage (`R01`–`P03`)** | 15 | **15 / 0 / 0** | **`1.74x`** | **1.11x** | `P01–P03`: **`3.15x–3.35x`**; `U01–U07`: **`1.11x–2.38x`** (`U03`: **`2.04x`**) |
| **GRAND TOTAL** | **93** | **93 / 0 / 0** | **`1.82x`** | **1.06x** | **100.0% WIN**, 0 MISMATCH, 0 TIMEOUT |

<sub>\*Final `v0.10.0` polish re-verification after sinking zero-copy 8 MiB windowed `mmap` (`src/io/window_map.zig`) into `src/parallel.zig` and wiring `SetUnanchoredDfa`/`LazySetDfa` into single `Regex`.</sub>

2. **In-Process SIMD Kernel Throughput** (`zig build bench -Doptimize=ReleaseFast`):
   - `v0.10.0` AVX2 highlights: `regex_*` mean **`29.403 GB/s`**, `multi_*` mean **`18.774 GB/s`** (`multi_ac` **`20.560 GB/s`**, `multi_teddy` **`17.866 GB/s`**), `walk_4` **`1.136 GB/s`**.
   - Single-core L1d/L2 peak reaches **`147.8 GB/s`** (`memchr_either`), **`81.0 GB/s`** (`finder_sensitive`), **`67.2 GB/s`** (`multi_teddy`), and up to **`62.4 GB/s`** on Apple M2 NEON (64 MiB DRAM).

See [BENCHMARKS.md](BENCHMARKS.md) for the complete 93-case breakdown, methodology, microbenchmark tables, and cold-disk reference numbers.

---

## Getting Started

### Requirements

- **Zig `0.17.1`**

### Adding `libwebgrep` to Your `build.zig`

```zig
const libwebgrep_dep = b.dependency("libwebgrep", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("libwebgrep", libwebgrep_dep.module("libwebgrep"));
```

### Quick Example: Service Entry Point (`searchSourceSlice`)

```zig
const std = @import("std");
const libwebgrep = @import("libwebgrep");

const Collector = struct {
    matches: usize = 0,

    pub fn event(self: *Collector, ev: libwebgrep.Event) libwebgrep.Flow {
        switch (ev) {
            .match => |line| {
                self.matches += line.matches.len;
                // Borrowed slices (`line.bytes`, `line.matches`) are valid during this callback.
            },
            else => {},
        }
        return .cont;
    }
};

pub fn runExample() !void {
    const finder = try libwebgrep.Finder.init("needle", .{ .case = .smart });
    var sink = Collector{};
    const result = try libwebgrep.searchSourceSlice(
        Collector,
        &sink,
        "log-chunk-01",
        "info: ok\nwarn: NEEDLE detected\n",
        &finder,
        .{
            .replacement = "[REDACTED]",
        },
    );
    std.debug.assert(result.outcome == .complete);
    std.debug.assert(sink.matches == 1);
}
```

### Multi-Literal OR, Linear-Time Regex & `RegexSet`

```zig
// 1. Multi-literal OR search (with optional Unicode Simple Case Folding & pattern_id)
var many = try libwebgrep.Multi.init(allocator, &.{ "ERR_TIMEOUT", "ERR_RESET" }, .{
    .case = .smart,
    .unicode_case = true,
});
defer many.deinit();

// 2. Linear-time Hybrid Lazy DFA + SetUnanchoredDfa + Thompson NFA Regex
var re = try libwebgrep.Regex.init(allocator, "\\p{Han}+_ERR_[0-9]{2,4}", .{
    .case = .sensitive,
    .multiline = false,
});
defer re.deinit();

// 3. Multi-pattern simultaneous RegexSet (unified prefilter + SetUnanchoredDfa/LazySetDfa)
var set = try libwebgrep.regex.RegexSet.init(allocator, &.{ "WARN_[0-9]+", "FATAL_[A-Z]+" }, .{});
defer set.deinit();
```

---

## Building, Testing, Fuzzing & Cross-Compiling

```sh
# Run all unit, E2E, adversarial, differential fuzz, OOM audit, 60-fn C ABI (27 sections), and API doc tests
zig build test --summary all

# Build static & shared libraries (libwebgrep.a / libwebgrep.so / .dylib) and install include/webgrep.h
zig build

# Also build and install the standalone ripgrep-compatible CLI binary (`zig-out/bin/wg-cli`)
zig build -Dcli=true -Doptimize=ReleaseFast

# Run tests with Teddy SIMD disabled (baseline self-hosted x86_64 verification)
zig build test -Dteddy=off --summary all

# Run the dedicated 5-suite cross-layer differential fuzz & OOM injection audit
zig build fuzz --summary all

# Run the in-process ReleaseFast microbenchmark suite
zig build bench -Doptimize=ReleaseFast -Dteddy=avx2

# Filter specific benchmark scenarios
zig build bench -Doptimize=ReleaseFast -Dteddy=avx2 -Dbench-filter=regex_

# Cross-compile verification (Tier 2 targets, no execution required)
zig build check -Dtarget=x86_64-linux-musl -Dteddy=runtime
zig build check -Dtarget=x86_64-linux-musl -Dteddy=off
zig build check -Dtarget=aarch64-linux-musl
zig build check -Dtarget=s390x-linux-musl
zig build check -Dtarget=riscv64-linux-musl
zig build -Dtarget=wasm32-wasi
```

### Platform Support Policy

| Tier | Platforms | Guarantee |
| :--- | :--- | :--- |
| **Tier 1** | `x86_64-linux`, `aarch64-linux`, `aarch64-macos`, `x86_64-windows` | Native CI execution of all Zig unit tests, 27-section C11 ABI suite, doc examples, and `ReleaseFast` builds (`avx2`/`neon`/`runtime`/`off`). |
| **Tier 2** | `x86_64-linux-musl`, `aarch64-linux-musl`, `x86_64-macos`, `wasm32-wasi`, `s390x-linux-musl`, `riscv64-linux-musl` | CI cross-compilation gate guarding static musl containers, Intel Mac, 32-bit WASI, Big-Endian byte order, and pure 64-bit scalar builds. |
| **Tier 3** | `*BSD` (`FreeBSD` / `OpenBSD` / `NetBSD`) | Best-effort POSIX compatibility; community-tested without blocking CI. |

### Build Options

| Option | Values | Default | Description |
| :--- | :--- | :--- | :--- |
| `-Dteddy` | `runtime`, `off`, `neon`, `ssse3`, `avx2` | Auto-detected per target (`avx2`/`ssse3`/`off` on `x86_64`, `neon`/`off` on `aarch64`, `off` on other targets) | Selects static SIMD backend or CPUID runtime dispatch (`runtime`) |
| `-Dmmap-windows` | `bool` | `false` | Maps large files in 8 MiB rolling windows instead of `readPositional` (`src/io/window_map.zig`) |
| `-Dcli` | `bool` | `false` | Installs the standalone `wg-cli` executable (supports `-V`, stdin/`-`, multi-path, `-b`, `--passthru`, `-u`/`-uu`/`-uuu`, `--hidden`, `--max-depth`, `--max-filesize`, `-0`, `--null-data`, `--crlf`, `-z` `.br`/`.zlib`) |
| `-Dlink-libc` | `bool` | `false` | Links `libc` into C ABI library artifacts |
| `-Dsanitize-c` | `bool` | `false` | Enables C sanitizer support (automatically links `libc` into C ABI artifacts) |
| `-Dsanitize-thread` | `bool` | `false` | Enables ThreadSanitizer (`TSan`) |
| `-Dbench-filter` | `string` | `null` | Runs only microbenchmark scenarios whose names contain the substring |
| `-Dfuzz-filter` | `string` | `null` | Runs only fuzz test targets whose names contain the substring |

---

## Documentation (Bilingual: English & 简体中文)

- [**5-Layer Architecture & Extensibility Guide (`docs/ARCHITECTURE.md`)**](docs/ARCHITECTURE.md) ([简体中文 (`docs/ARCHITECTURE.zh-CN.md`)](docs/ARCHITECTURE.zh-CN.md)) — 5-layer acyclic module layout, `MatcherTraits`/`SinkTraits` extension contracts, and `v0.10.0` kernel internals.
- [**API Reference (`docs/API.md`)**](docs/API.md) ([简体中文 (`docs/API.zh-CN.md`)](docs/API.zh-CN.md)) — Complete specification of all exported types, functions, events, C ABI, and multi-tenant budgets.
- [**Feature Matrix (`docs/FEATURES.md`)**](docs/FEATURES.md) ([简体中文 (`docs/FEATURES.zh-CN.md`)](docs/FEATURES.zh-CN.md)) — Overview of implemented `v0.10.0` capabilities and security boundaries.
- [**Architecture Milestones (`docs/ROADMAP.md`)**](docs/ROADMAP.md) ([简体中文 (`docs/ROADMAP.zh-CN.md`)](docs/ROADMAP.zh-CN.md)) — Completed milestones through `v0.10.0` and upcoming `v1.0.0` API freeze.
- [**Algorithmic Deep Dive (`DESIGN.md`)**](DESIGN.md) — Detailed walkthrough of SIMD kernels, Thompson NFA regex engine, streaming decompression, and work-stealing scheduler.
- [**Benchmarks (`BENCHMARKS.md`)**](BENCHMARKS.md) — Complete 93-case `v0.10.0` vs. `ripgrep 16.0.0` report, microbenchmarks, and methodology.

---

## License

Released under the [MIT License](LICENSE). See [NOTICE](NOTICE) for algorithmic attributions and academic references.
