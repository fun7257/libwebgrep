# libwebgrep

[English](README.md) | [简体中文](README.zh-CN.md)

**`libwebgrep`** is an ultra-fast, embeddable SIMD text and regular expression search engine library written in pure **Zig 0.17.0**, purpose-built for multi-tenant web services, log analytics, and code search backends.

It ships with **zero external dependencies**, **does not link `libc`**, guarantees **worst-case $O(n)$ linear time** across all literal, multi-pattern, and regex queries, and enforces strict **multi-tenant resource budgets** (scan bytes, wall-clock deadlines, memory caps, and Zip-Bomb decompression guards).

---

## Key Highlights

- **Blazing SIMD Throughput (24–62 GB/s) & Lock-Free `*const` Matchers**:
  - **Single-Byte Primitives (`memchr`)**: 4-vector unrolled SIMD loops reaching **48.3–62.4 GB/s**.
  - **Single-Literal (`Finder`)**: Frequency-ranked `PackedPair` 4-window SIMD filtering with branchless `(block | 0x20)` ASCII case folding (**42.6 GB/s** sensitive, **24.9 GB/s** case-insensitive) and automatic worst-case $O(n)$ `TwoWay` fallback.
  - **4-Tier Multi-Pattern OR Matrix (`Multi`)**: Automatically dispatches across `ByteSet` (**34.2 GB/s**), `RarePair` (**32.2 GB/s**), 8-bucket Slim `Teddy` (`vtbl`/`pshufb`/`vpshufb`, **24.1 GB/s**), and byte-equivalence-compressed `AhoCorasick` DFA with a 64-byte high-nibble SIMD skip loop (**24.3 GB/s**), reporting exact `pattern_id` on every match.
  - **Hybrid Lazy DFA + Linear-Time Regex (`Regex` & `RegexSet`)**: Lockstep Thompson NFA / PikeVM paired with a bounded Hybrid Lazy DFA (`RegexScratch`), multi-pattern simultaneous `RegexSet`, `\p{...}` Unicode General Category & Script properties, UAX #29 Unicode word boundaries (`\b`/`\B`), structured `CompileDiagnostic`, and automatic SIMD literal/alternation prefiltering (**42.9 GB/s**).
- **In-Process Bomb-Safe Streaming Decompression, Transcoding & Zero-Disk Archives**:
  - Streams **Gzip**, **Zstd**, and **XZ** in-process without spawning external binaries, enforcing both `max_decompressed_bytes` and `max_compression_ratio` (default `100:1`) on every chunk to stop Zip Bombs immediately.
  - Unpacks `.tar`, `.tar.gz`/`.tgz`, `.tar.zst`, `.tar.xz`, and `.zip` archives directly into an in-memory `ArchiveTree` (`searchArchiveSlice`, `searchArchive`, `searchTree`) with Zip-Slip path traversal protection and zero disk landing.
  - Sniffs UTF-8 / UTF-16LE / UTF-16BE BOMs and transcodes **GBK / GB2312 / Latin-1** via WHATWG or HTTP `Content-Type` `charset` hints, while maintaining an `OffsetMap` to report exact original stream offsets (`raw_offset`) alongside UTF-8 byte and UTF-16 code-unit spans.
- **Hardened for Multi-Tenant Server Embedding & Polyglot FFI**:
  - Public search entry points (`searchSource`, `searchSourceSlice`, `resumeSourceSlice`, `openSourcePull`, streaming `openReaderPull`) operate strictly on caller-supplied `std.Io.Reader` streams or memory slices with caller-assigned `source_id`—eliminating path traversal (`CWE-22`) by design.
  - Reusable `Scratch` buffer pool (`SearchConfig.scratch_pool`), runtime type-erased `AnyMatcher` / `AnyEventSink`, and a zero-`libc` C ABI (`include/webgrep.h`, `-Dc-lib=true`).
  - Controlled multi-source pipeline (`walk_glob`, `walk_ignore`, `walk_types`, `searchTree`) supporting nested brace expansion `{a,{b,c}}`, in-memory ignore rules, and work-stealing concurrency strictly bounded by `max_concurrency`.

---

## Performance Overview

1. **In-Memory SIMD Kernel Throughput** (`zig build bench -Doptimize=ReleaseFast`, 64 MiB DRAM / L1d–L2 cache):

| Benchmark Scenario | Engine / Path | Ryzen 7 7735U AVX2 (L1d/L2 → 64 MiB DRAM) | Apple M2 NEON (64 MiB) |
| :--- | :--- | ---: | ---: |
| `memchr_either` | 2-byte 4-vector unrolled SIMD | **147.77 GB/s** (L1d) / **28.18 GB/s** (DRAM) | **62.39 GB/s** |
| `finder_sensitive` | `Finder` (`PackedPair` 4-window SIMD, `"NEEDLE"`) | **81.03 GB/s** (L2) / **23.31 GB/s** (DRAM) | **42.62 GB/s** |
| `multi_teddy` | `Multi` → `Teddy` (3-byte rarest-window `vpshufb`/`vtbl`) | **67.18 GB/s** (L2) / **20.40 GB/s** (DRAM) | **24.13 GB/s** |
| `finder_ignore` | `Finder` (case-insensitive branchless `(block \| 0x20)`) | **63.83 GB/s** (L2) / **20.98 GB/s** (DRAM) | **24.88 GB/s** |
| `regex_prefilter` | `Regex` (Determinized Lazy DFA / NFA + SIMD prefilter) | **78.56 GB/s** (L3) / **23.22 GB/s** (DRAM) | **42.87 GB/s** |
| `multi_pairs` | `Multi` → `RarePair` (synchronous 2-byte SIMD compare) | **21.37 GB/s** (DRAM) | **32.16 GB/s** |
| `search_slice` | Full `searchSlice` pipeline (line framing + fused NUL watch) | **21.02 GB/s** (DRAM) | **28.06 GB/s** |
| `pull_reader_stream` | Streaming `openReaderPull` (`256 KiB` rolling buffer) | **16.84 GB/s** | **11.76 GB/s** |

2. **End-to-End 2.49 GB `zg-corpus` vs. `ripgrep 14.1.1`** (15 scenarios, interleaved ABBA ordering, `mincore(2)` residency verified):
   - **Warm Cache (`mincore = 100%`)**: Surpasses `rg_best = min(rg --no-mmap, rg --mmap)` in **15 / 15 scenarios** (**`1.01x–72.73x` faster**; e.g., interior-literal regex **`2.31x`**, case-insensitive literal **`1.26x`**, alternation regex **`1.16x`**, dense literal **`1.12x`**, 8-thread 2.49 GB directory scan **`26.72 GB/s`**).
   - **Cold Disk (`POSIX_FADV_DONTNEED` + `mincore = 0`)**: Surpasses `rg_best` in **15 / 15 scenarios** (**`1.09x–176.67x` faster**; **`1.23x–1.50x`** across all single-file text and regex queries).

See [BENCHMARKS.md](BENCHMARKS.md) for full methodology and detailed 15-scenario breakdowns.

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

// 2. Linear-time Hybrid Lazy DFA + Thompson NFA Regex with Unicode properties
var re = try libwebgrep.Regex.init(allocator, "\\p{Han}+_ERR_[0-9]{2,4}", .{
    .case = .sensitive,
    .multiline = false,
});
defer re.deinit();

// 3. Multi-pattern simultaneous RegexSet
var set = try libwebgrep.regex.RegexSet.init(allocator, &.{ "WARN_[0-9]+", "FATAL_[A-Z]+" }, .{});
defer set.deinit();
```

---

## Building, Testing, Fuzzing & Cross-Compiling

```sh
# Run all unit, E2E, adversarial, fuzz, and compile-checked API documentation tests
zig build test --summary all

# Build static and shared C ABI libraries (libwebgrep.a / libwebgrep.so) and run C ABI tests
zig build test -Dc-lib=true --summary all

# Run the dedicated cross-layer differential & Smith fuzz suite
zig build fuzz --summary all

# Run the 35-scenario in-process ReleaseFast microbenchmark suite
zig build bench -Doptimize=ReleaseFast -Dteddy=avx2

# Filter specific benchmark scenarios
zig build bench -Doptimize=ReleaseFast -Dteddy=avx2 -Dbench-filter=regex_

# Cross-compile verification (no execution required)
zig build check -Dtarget=x86_64-linux-musl -Doptimize=ReleaseFast
zig build check -Dtarget=x86_64-linux-musl -Dteddy=avx2
zig build check -Dtarget=aarch64-linux-musl
```

### Build Options

| Option | Values | Default | Description |
| :--- | :--- | :--- | :--- |
| `-Dteddy` | `off`, `neon`, `ssse3`, `avx2` | `neon` on `aarch64`, `avx2`/`ssse3` on `x86_64` | Selects the SIMD ISA backend for the Slim Teddy multi-pattern engine |
| `-Dc-lib` | `bool` | `false` | Builds static and shared C ABI libraries (`include/webgrep.h`) |
| `-Dlinux-getdents` | `bool` | `false` | Uses raw `getdents64` syscall for directory enumeration on Linux |
| `-Dmmap-windows` | `bool` | `false` | Maps large files in 8 MiB rolling windows instead of `readPositional` |
| `-Dsanitize-thread` | `bool` | `false` | Enables ThreadSanitizer (`TSan`) |
| `-Dbench-filter` | `string` | `null` | Runs only microbenchmark scenarios whose names contain the substring |

---

## Documentation (Bilingual: English & 简体中文)

- [**5-Layer Architecture & Extensibility Guide (`docs/ARCHITECTURE.md`)**](docs/ARCHITECTURE.md) ([简体中文 (`docs/ARCHITECTURE.zh-CN.md`)](docs/ARCHITECTURE.zh-CN.md)) — 5-layer acyclic module layout, `MatcherTraits`/`SinkTraits` extension contracts, and human + AI co-development protocol.
- [**API Reference (`docs/API.md`)**](docs/API.md) ([简体中文 (`docs/API.zh-CN.md`)](docs/API.zh-CN.md)) — Complete specification of all exported types, functions, events, and multi-tenant budgets.
- [**Feature Matrix (`docs/FEATURES.md`)**](docs/FEATURES.md) ([简体中文 (`docs/FEATURES.zh-CN.md`)](docs/FEATURES.zh-CN.md)) — Overview of implemented capabilities and security boundaries.
- [**Architecture Milestones (`docs/ROADMAP.md`)**](docs/ROADMAP.md) ([简体中文 (`docs/ROADMAP.zh-CN.md`)](docs/ROADMAP.zh-CN.md)) — Completed engineering and architecture milestones.
- [**Algorithmic Deep Dive (`DESIGN.md`)**](DESIGN.md) — Detailed walkthrough of SIMD kernels, Thompson NFA regex engine, streaming decompression, and work-stealing scheduler.
- [**Benchmarks (`BENCHMARKS.md`)**](BENCHMARKS.md) — Reproducible microbenchmark suite and throughput analysis.

---

## License

Released under the [MIT License](LICENSE). See [NOTICE](NOTICE) for algorithmic attributions and academic references.
