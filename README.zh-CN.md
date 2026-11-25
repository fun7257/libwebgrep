# libwebgrep

[English](README.md) | [简体中文](README.zh-CN.md)

**`libwebgrep`（`v0.10.3`）** 是一个使用纯 **Zig `0.17.1`** 编写的超高速、可嵌入 SIMD 文本与正则表达式搜索引擎库，专为多租户 Web 服务、日志检索分析与代码搜索后端设计。

本库**零第三方依赖**、**不链接 `libc`**，在单字面量、多模式 OR 与正则表达式查询上均保证**最坏 $O(n)$ 线性时间复杂度**，并内置严密的**多租户资源配额保护**（扫描字节上限、单调时钟超时预算、内存缓冲硬顶与压缩炸弹流式拦截）。

---

## 核心特性（`v0.10.3`）

- **93 / 93（100% WIN）全面超越 `ripgrep 16.0.0`、运行时 CPUID 分发与跨架构可移植性**：
  - **端到端对标 `ripgrep 16.0.0` 全胜战绩**：在 93 项全量评测中达成 **93 / 93 全胜（0 TIE / 0 LAG / 0 MISMATCH**，总几何均值 **`1.82x`**，最低 **`1.06x`**），覆盖核心常规（`S01`–`S19`，22/22，几何均值 **`1.31x`**）、极限对抗（`X01`–`X13`，15/15，几何均值 **`1.89x`**）、P0–P1 专项（`Y01`–`Y16`，41/41，几何均值 **`2.21x`**）与扩展全版图（`R01`–`P03`，15/15，几何均值 **`1.74x`**），8 线程 2.49 GB 全目录扫描（`S15 --mmap`）低至 **`97.97 ms`（`25.31 GB/s`）**。
  - **`x86_64` 基线兼容 + `-Dteddy=runtime` 运行时分发**：在基线 SSE2 `x86_64` CPU 上绝不发射非法指令，运行期通过 `CPUID + OSXSAVE + XGETBV` 自动切换 AVX2/SSSE3，同时原生支持 **ARM NEON**（`aarch64`）、**大端序（`s390x`）** 与 **WASM / WASI（`wasm32-wasi`）**。
  - **单字节与单字面量引擎（`memchr` / `Finder`）**：全系采用 `@ctz`/`@clz` 4 向量展开无分支 SIMD 循环（含单向量同步探测 `\n`/`\0` 的 `findSepOrNul`）、内联大小写折叠与 `watch_nul` 确认的 `PackedPair` 预过滤、单遍融合 `scanFinderFast`，并在高频锚点场景下平滑回退至最坏 $O(n)$ `TwoWay`。
  - **四级多模式 OR 引擎矩阵（`Multi`）**：按模式特征自动调度 `ByteSet`、`RarePair`、支持零中断融合验证 `findVerified` 与桶感知 Ghost-Byte 避让的 8 桶 Slim `Teddy`（`vtbl`/`pshufb`/`vpshufb`），以及带按频排序 BFS、Depth-2 L2 预算与自适应 **4 路 ILP** 扫描的混合稠密+稀疏 `AhoCorasick` 自动机（微基准 **`20.56 GB/s`**），每次命中均精确报告 `pattern_id`。
  - **双层无锚定集合 DFA + 线性时间正则引擎（`Regex` & `RegexSet`）**：无回溯 Thompson NFA / PikeVM 结合 `UnanchoredDfa`、`BoundedDfa` 及同时接入 `Regex` 与 `RegexSet` 的 **`SetUnanchoredDfa` / `LazySetDfa`**；内置跨行 `PrefixAnyTail` 快速路径、32 个捕获组（`$1`..`$32`）与命名捕获组（支持 `CompiledReplacement` `${name}` 模板替换）、14 个 POSIX 字符类、`(?x)`/`(?U)`/`(?u)` 标志、`\p{...}` Unicode 属性、**UTS #18 Unicode 16.0 单词边界**（`whole_word_unicode` / `webgrep_whole_word_mode_t`）及结构化诊断 `CompileDiagnostic`。
- **零拷贝 8 MiB 滑窗 `mmap`、进程内防爆解压与 SIMD 多编码转码**：
  - **零拷贝 8 MiB 滑窗 `mmap`（`src/io/window_map.zig`）**：已下沉集成至 `src/parallel.zig` 与单文件 `--mmap` 路径，在 Linux 下使 PTE 页表在 `munmap` 时保持 L2/L3 缓存热态，并配合 64B 对齐 `preadv` 彻底消除 4K-aliasing 性能悬崖。
  - **进程内流式解压与零落盘内存归档**：进程内流式解压 **Gzip、Zlib、Deflate、Zstd、XZ、LZ4、Bzip2 与 Brotli**（绝不派生外部子进程），实时强制校验 `max_decompressed_bytes` 与 `max_compression_ratio`（默认 `100:1`）以拦截压缩炸弹；支持恒定内存 `searchTarStream` 与零落盘 `ArchiveTree`（`.tar.*`、`.zip` / ZIP64、嵌套归档），内置并行 `Scheduler` 调度与 Zip-Slip 路径穿越防御。
  - **SIMD 多字符集转码**：支持 UTF-8 / UTF-16 / UTF-32 BOM 嗅探，以及 **SIMD GBK（直查 UTF-8 LUT / Variant H）、GB18030、SIMD UTF-16LE、UTF-16BE、Latin-1、Windows-1252、Windows-1251、Shift-JIS、EUC-JP、Big5 与 EUC-KR** 高速转码（支持启发式编码检测与 HTTP `charset` 提示），并通过区间级 `OffsetMap` 同步保留原始流偏移 `raw_offset` 与 UTF-16 码元区间。
- **多租户服务端嵌入加固、172 种内置文件类型、60 函数 C ABI 与模糊/OOM 审计**：
  - 公共服务入口（`searchSource`、`searchSourceSlice`、`resumeSourceSlice`、`openSourcePull`、`openReaderPull`）仅接收调用方打开的 `std.Io.Reader` 或内存切片以及调用方分配的 `source_id`，从根源上消除路径穿越（`CWE-22`）。
  - 提供工作线程零分配内存复用池 `Scratch`（`SearchConfig.scratch_pool`）、可配置 CRLF 剥离（`SearchConfig.strip_cr`）、运行时类型擦除 `AnyMatcher` / `AnyEventSink`、**172 种内置文件类型**（`src/walk/types.zig`）与 **60 个零 `libc` C ABI 导出函数**（`include/webgrep.h`、`WEBGREP_API`），新增自定义分配器钩子 `webgrep_set_allocator` 及独立状态码 `WEBGREP_ERR_PATH_TRAVERSAL` / `WEBGREP_ERR_UNSUPPORTED_FORMAT`。
  - 通过全部 Zig 单元/端到端/对抗/文档编译测试、**`27 / 27` 组 C ABI 测试**（含穷举 OOM 回滚零泄漏审计）、**5 组跨层差分模糊测试**、`std.testing.checkAllAllocationFailures` 全路径 OOM 注入审计（`src/fuzz.zig`），以及可选独立 CLI 工具 `wg-cli`（`-Dcli=true` / `zig build bench-cli`）。

---

## 性能基准概览（`v0.10.0`）

1. **`v0.10.0` 对标 `ripgrep 16.0.0` 端到端 93 场景全量战报（AMD Ryzen 7 7735U AVX2，`ReleaseFast -Dteddy=avx2`）**：

| 评测套件 | 场景数 | WIN / TIE / LAG | 几何均值提速（`wg` vs `rg 16.0.0`） | 最低比值 | 关键亮点 |
| :--- | ---: | :---: | ---: | ---: | :--- |
| **核心常规 (`S01`–`S19`, 2.48 GB)** | 22 | **22 / 0 / 0** | **`1.28x`** → **`1.31x`**\* | **1.06x** | `S15 --mmap`：**`97.97 ms`（`25.31 GB/s`，`1.33x` mmap WIN）**；`S14 --mmap`：**`253.71 ms`（`1.12x`）** |
| **极限对抗 (`X01`–`X13`)** | 15 | **15 / 0 / 0** | **`1.87x`** → **`1.89x`**\* | **1.12x** | `X01u_nolit_unicode`：**`10.11x`**（mmap **`15.12x`**）；`X04_large_dfa`：**`4.11x`**；`X05–X07`：**`2.19x–2.59x`** |
| **P0–P1 专项 (`Y01`–`Y16`)** | 41 | **41 / 0 / 0** | **`2.21x`** | **1.09x** | `Y03u`：**`55.56x`**；`Y06c`：**`10.94x`**；`Y02`：**`9.43x`**；`Y16c_smart_case`：**`1.77x`** |
| **扩展全版图 (`R01`–`P03`)** | 15 | **15 / 0 / 0** | **`1.74x`** | **1.11x** | `P01–P03`：**`3.15x–3.35x`**；`U01–U07`：**`1.11x–2.38x`**（`U03` 达 **`2.04x`**） |
| **GRAND TOTAL** | **93** | **93 / 0 / 0** | **`1.82x`** | **1.06x** | **100.0% WIN**，0 MISMATCH，0 TIMEOUT |

<sub>\*`v0.10.0` 终版复测数据：已包含将零拷贝 8 MiB 滑窗 `mmap`（`src/io/window_map.zig`）下沉至 `src/parallel.zig` 及将 `SetUnanchoredDfa`/`LazySetDfa` 接入单正则 `Regex` 后的实测收益。</sub>

2. **进程内 SIMD 内核吞吐**（`zig build bench -Doptimize=ReleaseFast`）：
   - `v0.10.0` AVX2 亮点：`regex_*` 均值 **`29.403 GB/s`**，`multi_*` 均值 **`18.774 GB/s`**（`multi_ac` **`20.560 GB/s`**、`multi_teddy` **`17.866 GB/s`**），`walk_4` **`1.136 GB/s`**。
   - 单核 L1d/L2 峰值达 **`147.8 GB/s`**（`memchr_either`）、**`81.0 GB/s`**（`finder_sensitive`）、**`67.2 GB/s`**（`multi_teddy`），Apple M2 NEON（64 MiB DRAM）峰值达 **`62.4 GB/s`**。

完整的 93 场景明细、评测方法学、微基准与冷盘参考数据请参阅 [BENCHMARKS.md](BENCHMARKS.md)。

---

## 快速上手

### 环境要求

- **Zig `0.17.1`**

### 在 `build.zig` 中引入

```zig
const libwebgrep_dep = b.dependency("libwebgrep", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("libwebgrep", libwebgrep_dep.module("libwebgrep"));
```

### 服务入口示例（`searchSourceSlice`）

```zig
const std = @import("std");
const libwebgrep = @import("libwebgrep");

const Collector = struct {
    matches: usize = 0,

    pub fn event(self: *Collector, ev: libwebgrep.Event) libwebgrep.Flow {
        switch (ev) {
            .match => |line| {
                self.matches += line.matches.len;
                // line.bytes 与 line.matches 切片在本次回调返回前有效
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

### 多模式 OR、线性时间正则与 `RegexSet`

```zig
// 1. 多字面量 OR 检索（支持 Unicode Simple Case Folding 与 pattern_id）
var many = try libwebgrep.Multi.init(allocator, &.{ "ERR_TIMEOUT", "ERR_RESET" }, .{
    .case = .smart,
    .unicode_case = true,
});
defer many.deinit();

// 2. 线性时间 Hybrid Lazy DFA + SetUnanchoredDfa + Thompson NFA 正则
var re = try libwebgrep.Regex.init(allocator, "\\p{Han}+_ERR_[0-9]{2,4}", .{
    .case = .sensitive,
    .multiline = false,
});
defer re.deinit();

// 3. 多正则单遍同时匹配 RegexSet（统一预过滤 + SetUnanchoredDfa/LazySetDfa）
var set = try libwebgrep.regex.RegexSet.init(allocator, &.{ "WARN_[0-9]+", "FATAL_[A-Z]+" }, .{});
defer set.deinit();
```

---

## 构建、测试、模糊测试与交叉编译

```sh
# 运行全部单元、端到端、对抗、差分模糊、OOM 审计、60 函数 C ABI（27 组）与文档编译测试
zig build test --summary all

# 构建静态库/动态库（libwebgrep.a / libwebgrep.so / .dylib）并安装 include/webgrep.h
zig build

# 同时构建并安装独立 ripgrep 兼容命令行工具（zig-out/bin/wg-cli）
zig build -Dcli=true -Doptimize=ReleaseFast

# 关闭 Teddy SIMD 运行基线自举 x86_64 兼容性测试
zig build test -Dteddy=off --summary all

# 运行 5 组跨层差分模糊测试与 OOM 注入审计套件
zig build fuzz --summary all

# 运行 ReleaseFast 进程内微基准测试
zig build bench -Doptimize=ReleaseFast -Dteddy=avx2

# 按名称子串过滤运行特定微基准场景
zig build bench -Doptimize=ReleaseFast -Dteddy=avx2 -Dbench-filter=regex_

# 跨平台编译校验（Tier 2 目标，无需本机执行）
zig build check -Dtarget=x86_64-linux-musl -Dteddy=runtime
zig build check -Dtarget=x86_64-linux-musl -Dteddy=off
zig build check -Dtarget=aarch64-linux-musl
zig build check -Dtarget=s390x-linux-musl
zig build check -Dtarget=riscv64-linux-musl
zig build -Dtarget=wasm32-wasi
```

### 平台支持策略

| 支持层级 | 目标平台 | 保障承诺 |
| :--- | :--- | :--- |
| **Tier 1（完整支持）** | `x86_64-linux`、`aarch64-linux`、`aarch64-macos`、`x86_64-windows` | 原生真机 CI 全量运行 Zig 单元测试、27 节 C11 ABI 套件、文档示例与 `ReleaseFast` 构建（覆盖 `avx2`/`neon`/`runtime`/`off`）。 |
| **Tier 2（编译保障）** | `x86_64-linux-musl`、`aarch64-linux-musl`、`x86_64-macos`、`wasm32-wasi`、`s390x-linux-musl`、`riscv64-linux-musl` | CI 交叉编译门禁，守住静态 musl 容器、Intel Mac、32 位 WASI、大端字节序与纯 64 位标量零回归。 |
| **Tier 3（尽力兼容）** | `*BSD`（`FreeBSD` / `OpenBSD` / `NetBSD`） | POSIX 路径尽力兼容，由社区反馈维护，不作为 CI 阻塞项。 |

### 构建选项

| 选项 | 可选值 | 默认值 | 说明 |
| :--- | :--- | :--- | :--- |
| `-Dteddy` | `runtime`、`off`、`neon`、`ssse3`、`avx2` | 按目标架构自动检测（`x86_64` 为 `avx2`/`ssse3`/`off`，`aarch64` 为 `neon`/`off`，其余为 `off`） | 选择静态 SIMD 后端或 CPUID 运行时分发（`runtime`） |
| `-Dmmap-windows` | `bool` | `false` | 以 8 MiB 滚动窗口映射大文件替代 `readPositional`（`src/io/window_map.zig`） |
| `-Dcli` | `bool` | `false` | 安装独立 `wg-cli` 可执行文件（支持 `-V`、stdin/`-`、多路径、`-b`、`--passthru`、`-u`/`-uu`/`-uuu`、`--hidden`、`--max-depth`、`--max-filesize`、`-0`、`--null-data`、`--crlf`、`-z` `.br`/`.zlib`） |
| `-Dlink-libc` | `bool` | `false` | 为 C ABI 库产物链接 `libc` |
| `-Dsanitize-c` | `bool` | `false` | 启用 C Sanitizer 检测（自动为 C ABI 产物链接 `libc`） |
| `-Dsanitize-thread` | `bool` | `false` | 启用 ThreadSanitizer（`TSan`） |
| `-Dbench-filter` | `string` | `null` | 仅运行名称包含指定子串的微基准场景 |
| `-Dfuzz-filter` | `string` | `null` | 仅运行名称包含指定子串的模糊测试目标 |

---

## 文档导航（中英双语）

- [**五层架构设计与协同开发指南 (`docs/ARCHITECTURE.zh-CN.md`)**](docs/ARCHITECTURE.zh-CN.md) ([English (`docs/ARCHITECTURE.md`)](docs/ARCHITECTURE.md)) — 五层无环架构布局、`MatcherTraits`/`SinkTraits` 零成本扩展契约与内核机制。
- [**API 参考手册 (`docs/API.zh-CN.md`)**](docs/API.zh-CN.md) ([English (`docs/API.md`)](docs/API.md)) — 公共导出符号、事件结构、60 函数 C ABI 与多租户预算完整说明。
- [**功能矩阵与安全边界 (`docs/FEATURES.zh-CN.md`)**](docs/FEATURES.zh-CN.md) ([English (`docs/FEATURES.md`)](docs/FEATURES.md)) — `v0.10.0` 核心能力全景与安全红线说明。
- [**架构演进里程碑 (`docs/ROADMAP.zh-CN.md`)**](docs/ROADMAP.zh-CN.md) ([English (`docs/ROADMAP.md`)](docs/ROADMAP.md)) — `v0.10.0` 已完成里程碑与 `v1.0.0` API 冻结规划。
- [**算法与内核深入解析 (`DESIGN.md`)**](DESIGN.md) — SIMD 查找内核、Thompson NFA 正则引擎、流式防爆解压与工作窃取调度详解。
- [**性能基准报告 (`BENCHMARKS.md`)**](BENCHMARKS.md) — 93 场景 `v0.10.0` 对标 `ripgrep 16.0.0` 完整报告、微基准与评测方法。

---

## 开源许可

本项目采用 [MIT 许可证](LICENSE) 开源。算法参考文献与致谢见 [NOTICE](NOTICE)。
