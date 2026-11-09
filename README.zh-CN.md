# libwebgrep

[English](README.md) | [简体中文](README.zh-CN.md)

**`libwebgrep`** 是一个使用纯 **Zig 0.17.0** 编写的超高速、可嵌入 SIMD 文本与正则表达式搜索引擎库，专为多租户 Web 服务、日志检索分析与代码搜索后端设计。

本库**零第三方依赖**、**不链接 `libc`**，在单字面量、多模式 OR 与正则表达式查询上均保证**最坏 $O(n)$ 线性时间复杂度**，并内置严密的**多租户资源配额保护**（扫描字节上限、单调时钟超时预算、内存缓冲硬顶与压缩炸弹流式拦截）。

---

## 核心特性

- **极致 SIMD 扫描吞吐（24～62 GB/s）与无锁 `*const` 匹配器**：
  - **单字节向量原语（`memchr`）**：4 向量展开无分支 SIMD 循环，吞吐达 **48.3～62.4 GB/s**。
  - **单字面量引擎（`Finder`）**：基于字符频率表的 `PackedPair` 4 窗口合并 SIMD 预过滤，配合无分支位或 `(block | 0x20)` ASCII 忽略大小写（区分大小写 **42.6 GB/s**、忽略大小写 **24.9 GB/s**），并在高频锚点场景下自动平滑切换至最坏 $O(n)$ 的 `TwoWay` 算法。
  - **四级多模式 OR 引擎矩阵（`Multi`）**：按模式特征自动调度 `ByteSet`（**34.2 GB/s**）、`RarePair` 稀有邻接字节对过滤（**32.2 GB/s**）、8 桶 Slim `Teddy` 半字节 SIMD 查表（`vtbl`/`pshufb`/`vpshufb`，**24.1 GB/s**）以及带 64 字节高半字节位图跳步的字节等价类压缩 `AhoCorasick` 稠密自动机（**24.3 GB/s**），并精确返回命中模式的 `pattern_id`。
  - **混合惰性 DFA + 线性时间正则引擎（`Regex` & `RegexSet`）**：无回溯 Thompson NFA / PikeVM 结合有界混合惰性 DFA（`RegexScratch`）、多正则单遍同时匹配 `RegexSet`、`\p{...}` Unicode 属性、UAX #29 Unicode 单词边界（`\b`/`\B`）、结构化编译诊断 `CompileDiagnostic` 与自动 SIMD 预过滤（**42.9 GB/s**）。
- **进程内防爆流式解压、多编码转码与零落盘内存归档检索**：
  - 进程内流式解压 **Gzip**、**Zstd** 与 **XZ**（绝不派生外部子进程），实时校验 `max_decompressed_bytes` 与 `max_compression_ratio`（默认 `100:1`）双重防爆上限以拦截压缩炸弹。
  - 支持对 `.tar`、`.tar.gz`/`.tgz`、`.tar.zst`、`.tar.xz` 与 `.zip` 归档进行零落盘内存解包与虚拟树检索（`ArchiveTree`、`searchArchiveSlice`、`searchArchive`、`searchTree`），内置严密的 Zip-Slip 路径穿越防御。
  - 支持 UTF-8 / UTF-16LE / UTF-16BE BOM 自动嗅探，支持通过 WHATWG 标签或 HTTP `Content-Type` `charset` 提示流式转码 **GBK / GB2312 / Latin-1**，并通过 `OffsetMap` 同步给出原始流字节偏移 `raw_offset` 与 UTF-16 码元区间。
- **面向多租户服务端嵌入与多语言 FFI 的安全架构**：
  - 公共服务入口（`searchSource`、`searchSourceSlice`、`resumeSourceSlice`、`openSourcePull`、增量流式拉模式 `openReaderPull`）仅接收调用方打开的 `std.Io.Reader` 或内存切片以及调用方分配的 `source_id`，从根源上消除路径穿越（`CWE-22`）。
  - 提供工作线程零分配内存复用池 `Scratch`（`SearchConfig.scratch_pool`）、运行时类型擦除 `AnyMatcher` / `AnyEventSink` 以及零 `libc` C ABI（`include/webgrep.h`，`-Dc-lib=true`）。
  - 提供受控的多来源过滤与并发组件（`walk_glob`、`walk_ignore`、`walk_types`、`searchTree`），支持 `{a,{b,c}}` 嵌套花括号展开、纯文本忽略规则注入与完全受 `max_concurrency` 控制的工作窃取调度。

---

## 性能基准概览

以下数据由 `zig build bench -Doptimize=ReleaseFast` 在 Apple M2（`aarch64`，16 字节 NEON 向量，64 MiB 内存缓冲）上进程内实测：

| 基准场景 | 引擎 / 路径 | 吞吐 (GB/s) |
| :--- | :--- | ---: |
| `memchr_either` | 双字节 4 向量展开 SIMD 扫描 | **62.39 GB/s** |
| `memchr_find` | 单字节向量扫描 | **48.25 GB/s** |
| `regex_prefilter` | `Regex`（`"libweb.*[0-9]*grep"`，Lazy DFA / NFA + SIMD 预过滤） | **42.87 GB/s** |
| `finder_alphabet` | `Finder`（重复字母表文本查找 `"libwebgrep"`） | **42.82 GB/s** |
| `finder_sensitive` | `Finder`（`PackedPair` 4 窗口 SIMD，`"NEEDLE"`） | **42.62 GB/s** |
| `multi_bytes` | `Multi` → `ByteSet`（4 路展开单字节集合 SIMD） | **34.18 GB/s** |
| `multi_pairs` | `Multi` → `RarePair`（两阶段直接向量字节对比较） | **32.16 GB/s** |
| `search_slice` | `searchSlice` 完整切片搜索管线（含分行与融合 NUL 检测） | **28.06 GB/s** |
| `finder_ignore` | `Finder`（无分支 `(block \| 0x20)` 忽略大小写） | **24.88 GB/s** |
| `multi_ac` | `Multi` → `AhoCorasick`（稠密 DFA + 64B 高半字节 SIMD 跳步） | **24.27 GB/s** |
| `multi_teddy` | `Multi` → `Teddy`（NEON `vtbl` 半字节查表 + 两阶段验证） | **24.13 GB/s** |
| `pull_reader_stream` | `openReaderPull` 增量流式拉模式迭代（`256 KiB` 滚动缓冲） | **11.76 GB/s** |
| `file_1MiB` | `1 MiB` 滚动缓冲流式扫描 `128 MiB` 文件 | **10.99 GB/s** |

完整的基准方法与详细分析请参阅 [BENCHMARKS.md](BENCHMARKS.md)。

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

---

## 构建、测试、模糊测试与交叉编译

```sh
# 运行全部单元测试、端到端测试、对抗测试、模糊测试与 API 文档编译校验测试
zig build test --summary all

# 构建静态与动态 C ABI 库 (libwebgrep.a / libwebgrep.so) 并运行 C ABI 测试
zig build test -Dc-lib=true --summary all

# 运行跨层差分与 Zig 0.17.1 Smith 模糊测试套件
zig build fuzz --summary all

# 运行 35 场景 ReleaseFast 进程内微基准测试
zig build bench -Doptimize=ReleaseFast -Dteddy=avx2

# 按名称子串过滤运行特定微基准场景
zig build bench -Doptimize=ReleaseFast -Dteddy=avx2 -Dbench-filter=regex_

# 跨平台编译校验
zig build check -Dtarget=x86_64-linux-musl -Doptimize=ReleaseFast
zig build check -Dtarget=x86_64-linux-musl -Dteddy=avx2
zig build check -Dtarget=aarch64-linux-musl
```

---

## 文档导航（中英双语）

- [**五层架构设计与协同开发指南 (`docs/ARCHITECTURE.zh-CN.md`)**](docs/ARCHITECTURE.zh-CN.md) ([English (`docs/ARCHITECTURE.md`)](docs/ARCHITECTURE.md)) — 五层无环架构布局、`MatcherTraits`/`SinkTraits` 零成本扩展契约与人机协同开发规范。
- [**API 参考手册 (`docs/API.zh-CN.md`)**](docs/API.zh-CN.md) ([English (`docs/API.md`)](docs/API.md)) — 公共导出符号、事件结构与多租户预算完整说明。
- [**功能矩阵与安全边界 (`docs/FEATURES.zh-CN.md`)**](docs/FEATURES.zh-CN.md) ([English (`docs/FEATURES.md`)](docs/FEATURES.md)) — 核心能力全景与安全红线说明。
- [**架构演进里程碑 (`docs/ROADMAP.zh-CN.md`)**](docs/ROADMAP.zh-CN.md) ([English (`docs/ROADMAP.md`)](docs/ROADMAP.md)) — 已完成的全部功能与架构演进里程碑。
- [**算法与内核深入解析 (`DESIGN.md`)**](DESIGN.md) — SIMD 查找内核、Thompson NFA 正则引擎、流式防爆解压与工作窃取调度详解。
- [**性能基准报告 (`BENCHMARKS.md`)**](BENCHMARKS.md) — 微基准测试方法与吞吐数据解析。

---

## 开源许可

本项目采用 [MIT 许可证](LICENSE) 开源。算法参考文献与致谢见 [NOTICE](NOTICE)。
