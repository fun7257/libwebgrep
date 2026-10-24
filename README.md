# libwebgrep

[English](README.md) | [简体中文](README.zh-CN.md)

**`libwebgrep`** is an ultra-fast, embeddable SIMD text and regular expression search engine library written in pure **Zig 0.17.0**, purpose-built for multi-tenant web services, log analytics, and code search backends.

It ships with **zero external dependencies**, **does not link `libc`**, guarantees **worst-case $O(n)$ linear time** across all literal, multi-pattern, and regex queries, and enforces strict **multi-tenant resource budgets** (scan bytes, wall-clock deadlines, memory caps, and Zip-Bomb decompression guards).

---

## Key Highlights

- **Blazing SIMD Throughput (24–62 GB/s)**:
  - **Single-Byte Primitives (`memchr`)**: 4-vector unrolled SIMD loops reaching **48.3–62.4 GB/s**.
  - **Single-Literal (`Finder`)**: Frequency-ranked `PackedPair` 4-window SIMD filtering with branchless `(block | 0x20)` ASCII case folding (**42.6 GB/s** sensitive, **24.9 GB/s** case-insensitive) and automatic worst-case $O(n)$ `TwoWay` fallback.
  - **4-Tier Multi-Pattern OR Matrix (`Multi`)**: Automatically dispatches across `ByteSet` (**34.2 GB/s**), `RarePair` (**32.2 GB/s**), 8-bucket Slim `Teddy` (`vtbl`/`pshufb`/`vpshufb`, **24.1 GB/s**), and byte-equivalence-compressed `AhoCorasick` DFA with a 64-byte high-nibble SIMD skip loop (**24.3 GB/s**).
  - **Linear-Time Regex (`Regex`)**: Lockstep Thompson NFA / PikeVM engine immune to catastrophic backtracking (ReDoS), paired with automatic AST `RequiredLiteral` extraction and SIMD prefiltering (**42.9 GB/s**).
- **In-Process Bomb-Safe Streaming Decompression & Transcoding**:
  - Streams **Gzip**, **Zstd**, and **XZ** in-process without spawning external binaries, enforcing both `max_decompressed_bytes` and `max_compression_ratio` (default `100:1`) on every chunk to stop Zip Bombs immediately.
  - Sniffs UTF-8 / UTF-16LE / UTF-16BE BOMs and transcodes **GBK / GB2312 / Latin-1** via WHATWG or HTTP `Content-Type` `charset` hints, while maintaining an `OffsetMap` to report exact original stream offsets (`raw_offset`) alongside UTF-8 byte and UTF-16 code-unit spans.
- **Hardened for Multi-Tenant Server Embedding**:
  - Public search entry points (`searchSource`, `searchSourceSlice`, `resumeSourceSlice`, `openSourcePull`) operate strictly on caller-supplied `std.Io.Reader` streams or memory slices with caller-assigned `source_id`—eliminating path traversal (`CWE-22`) by design.
  - Built-in budgets for scan bytes, output bytes, wall-clock nanosecond deadlines (`time_budget_ns`), atomic cancellation (`cancel`), and stateless cursor pagination (`Flow.pause` / `resume_at`).
  - Controlled multi-source pipeline (`walk_glob`, `walk_ignore`, `walk_types`) supporting nested brace expansion `{a,{b,c}}`, in-memory ignore rules, and work-stealing concurrency strictly bounded by `max_concurrency`.

---

## Performance Overview

Measured in-process with `zig build bench -Doptimize=ReleaseFast` on Apple M2 (`aarch64`, 16-byte NEON vectors, 64 MiB buffer):

| Benchmark Scenario | Engine / Path | Throughput |
| :--- | :--- | ---: |
| `memchr_either` | 2-byte 4-vector unrolled SIMD | **62.39 GB/s** |
| `memchr_find` | Single-byte SIMD scan | **48.25 GB/s** |
| `regex_prefilter` | `Regex` (`"libweb.*[0-9]*grep"`, Thompson NFA + SIMD prefilter) | **42.87 GB/s** |
| `finder_alphabet` | `Finder` (`"libwebgrep"` on repeating alphabet text) | **42.82 GB/s** |
| `finder_sensitive` | `Finder` (`PackedPair` 4-window SIMD, `"NEEDLE"`) | **42.62 GB/s** |
| `multi_bytes` | `Multi` → `ByteSet` (4-way unrolled SIMD single-byte set) | **34.18 GB/s** |
| `multi_pairs` | `Multi` → `RarePair` (2-stage direct SIMD pair compare) | **32.16 GB/s** |
| `search_slice` | Full `searchSlice` pipeline (line framing + fused NUL watch) | **28.06 GB/s** |
| `finder_ignore` | `Finder` (case-insensitive branchless `(block \| 0x20)`) | **24.88 GB/s** |
| `multi_ac` | `Multi` → `AhoCorasick` (dense DFA + 64B high-nibble SIMD skip) | **24.27 GB/s** |
| `multi_teddy` | `Multi` → `Teddy` (NEON `vtbl` nibble mask + 2-phase verify) | **24.13 GB/s** |
| `file_1MiB` | Streaming 128 MiB file via `1 MiB` rolling buffer | **10.99 GB/s** |

See [BENCHMARKS.md](BENCHMARKS.md) for full methodology and detailed breakdowns.

---

## Getting Started

### Requirements

- **Zig `0.17.0`**

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
    var finder = try libwebgrep.Finder.init("needle", .{ .case = .smart });
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

### Multi-Literal OR & Linear-Time Regex

```zig
// 1. Multi-literal OR search (with optional Unicode Simple Case Folding)
var many = try libwebgrep.Multi.init(allocator, &.{ "ERR_TIMEOUT", "ERR_RESET" }, .{
    .case = .smart,
    .unicode_case = true,
});
defer many.deinit();

// 2. Linear-time Thompson NFA Regex with automatic SIMD literal prefiltering
var re = try libwebgrep.Regex.init(allocator, "ERR_[0-9]{2,4}_TIMEOUT", .{
    .case = .sensitive,
    .multiline = false,
});
defer re.deinit();
```

---

## Building, Testing & Cross-Compiling

```sh
# Run all 182 unit tests and compile-checked API documentation examples
zig build test --summary all

# Run the in-process ReleaseFast microbenchmark suite
zig build bench -Doptimize=ReleaseFast

# Cross-compile verification (no execution required)
zig build check -Dtarget=x86_64-linux-musl -Doptimize=ReleaseFast
zig build check -Dtarget=x86_64-linux-musl -Dteddy=avx2
zig build check -Dtarget=aarch64-linux-musl
```

### Build Options

| Option | Values | Default | Description |
| :--- | :--- | :--- | :--- |
| `-Dteddy` | `off`, `neon`, `ssse3`, `avx2` | `neon` on `aarch64`, `off` otherwise | Selects the SIMD ISA backend for the Slim Teddy multi-pattern engine |
| `-Dlinux-getdents` | `bool` | `false` | Uses raw `getdents64` syscall for directory enumeration on Linux |
| `-Dmmap-windows` | `bool` | `false` | Maps large files in 8 MiB rolling windows instead of `readPositional` |
| `-Dsanitize-thread` | `bool` | `false` | Enables ThreadSanitizer (`TSan`) |

---

## Documentation

- [**API Reference (`docs/API.md`)**](docs/API.md) — Complete specification of all exported types, functions, events, and multi-tenant budgets.
- [**Architecture & Design (`DESIGN.md`)**](DESIGN.md) — Deep dive into the SIMD kernels, Thompson NFA regex engine, streaming decompression, and work-stealing scheduler.
- [**Benchmarks (`BENCHMARKS.md`)**](BENCHMARKS.md) — Reproducible microbenchmark suite and throughput analysis.
- [**Feature Matrix (`docs/FEATURES.md`)**](docs/FEATURES.md) — Overview of implemented capabilities and security boundaries.

---

## License

Released under the [MIT License](LICENSE). See [NOTICE](NOTICE) for algorithmic attributions and academic references.
