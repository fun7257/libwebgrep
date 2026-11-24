# libwebgrep 功能矩阵与安全架构边界（`v0.10.0`）

[English](FEATURES.md) | [简体中文](FEATURES.zh-CN.md)

`libwebgrep`（`v0.10.0`）是使用纯 **Zig `0.17.1`** 编写的高性能、可嵌入文本与正则表达式搜索引擎，**零第三方依赖**且**不依赖 `libc`**。

---

## 1. 核心领域功能矩阵

| 领域 | 已实现能力与对应模块（`v0.10.0`） |
| :--- | :--- |
| **输入流、滑窗 I/O 与数据源抽象** | 基于 `source_id` + `std.Io.Reader` / `[]const u8` 的服务级入口（`searchSource`、`searchSourceSlice`、`resumeSourceSlice`、`openSourcePull`、流式 `openReaderPull`）；集成至 `src/parallel.zig` 的零拷贝 8 MiB 滑窗 `mmap`（`src/io/window_map.zig`）；64B 对齐 `preadv` 流式缓冲；有界内存单源并发引擎（`src/search/parallel_source.zig`）；支持 `-B`/`-A`/`-C`、解压与编码对齐的倒序尾部检索（`src/search/reverse.zig`） |
| **零落盘归档与防爆流式解压** | 纯 Zig 进程内流式解压 **Gzip、Zlib、Deflate、Zstd、XZ、LZ4、Bzip2 与 Brotli**（`src/codec/decompress.zig`、`lz4.zig`、`bzip2.zig`、`brotli.zig`），强制执行双重防爆上限（`max_decompressed_bytes` + `max_compression_ratio`）；可寻址 Zstd/Gzip 随机索引（`src/codec/seekable.zig`）；恒定内存 `searchTarStream`；零落盘内存归档 `ArchiveTree`（`.tar.*`、`.zip`/ZIP64、嵌套归档）与 `searchTree`/`searchArchiveSlice`/`searchArchive` |
| **SIMD 检索与多模式内核** | 无锁 `*const` 匹配器（`Finder`、`Multi`、`Regex`、`RegexSet`、`AnyMatcher`）与 `pattern_id` 模式归因；`@ctz`/`@clz` `memchr` 与单向量 `findSepOrNul`；支持内联大小写折叠与 `watch_nul` 确认的 `PackedPair`、`MaskedPair` 与 `TwoWay` 回退；四级 `Multi` 多模式 OR 引擎（`ByteSet`、`RarePair`、支持桶感知 Ghost-Byte 避让与融合 `findVerified` 的 `Teddy`，以及混合稠密+稀疏 **4 路 ILP** `AhoCorasick`） |
| **线性时间正则与 `RegexSet`** | 锁步 Thompson NFA / PikeVM 结合 `UnanchoredDfa`（精确 ASCII/词边界追踪）、`BoundedDfa` 及同时接入 `Regex` 与 `RegexSet` 的 **`SetUnanchoredDfa` / `LazySetDfa`**；`RegexSet` 统一多模式 SIMD 预过滤；跨行 **`PrefixAnyTail`** 快速路径；32 个捕获组（`$1`..`$32`）与命名捕获组（`(?P<name>...)`/`(?<name>...)`）；14 个 POSIX 字符类；`(?x)`/`(?U)`/`(?u)` 标志；Unicode `\d`/`\w`/`\s`（`unicode_classes`）、`\p{...}` 属性、UTS #18 Unicode 16.0 `\b`/`\B` 与结构化诊断 `CompileDiagnostic` |
| **行级语义与二次过滤** | 半边界整词匹配，支持可选 **UTS #18 Unicode 16.0**（`whole_word_unicode = true` / `WEBGREP_WHOLE_WORD_UNICODE`）与 **ASCII**（`whole_word_unicode = false` / `WEBGREP_WHOLE_WORD_ASCII`）双模式（`webgrep_whole_word_mode_t`）；`whole_line`；批量 `invert`；`contains`/`contains_regexes`（AND）与 `excludes`/`excludes_regexes`（NOT）链式过滤；`stop_on_nonmatch`；`max_count`、`exists`、`files_without_match`；指针编译式 `CompiledReplacement` 只读替换预览（`$0`–`$32` 与 `${name}`） |
| **行定界与 SIMD 多字符集转码** | LF / CRLF 行定界；NUL 分隔记录（`null_data`）；UTF-8 / UTF-16 / UTF-32 BOM 嗅探与启发式编码检测；基于 WHATWG / HTTP `charset` 提示的 **SIMD GBK（直查 UTF-8 LUT / Variant H）、GB18030、SIMD UTF-16LE、UTF-16BE、Latin-1、Windows-1252、Windows-1251、Shift-JIS、EUC-JP、Big5 与 EUC-KR** 高速转码（`src/codec/encoding.zig`、`src/tables/gbk_table.zig`、`legacy_encodings.zig`）；超长行常数内存滑窗（`src/search/long_line.zig`） |
| **二进制 NUL 检测** | 将 NUL 字节检测单遍融合进 SIMD 搜索主循环（`scanFinderFast` + `lineEndOrNul`、`findWatched`、`findVerifiedWatchingNul`），支持 `quit`、`report`、`none` 三种策略并精确报告 `binary_offset` 与 `binary_status` |
| **有界上下文与全流高亮** | 惰性零拷贝 `BeforeRing` 前文环形缓冲区（`src/search/context_ring.zig`）；后文计数器；相邻上下文窗口自动合并与结构化 `context_break` 分隔事件；全流直通高亮模式（`passthru`） |
| **偏移量、UTF-16 与源码映射** | 1 起始行号（`LineNumberMode`）、字节列号与 UTF-16 码元列号（`u16_column`）；半开字节区间、`matched_raw_spans`、UTF-16 区间（`u16_start`、`u16_end`、`pattern_id`）；可搜索流 `absolute_offset` 与区间级 `OffsetMap` 原始流偏移 `raw_offset`（`src/codec/offset_map.zig`） |
| **事件流控与无状态续查** | 同步发送 `begin`、`match`、`context`、`context_break`、`progress`、`heartbeat`、`end` 与 `summary` 事件；支持 `Flow.pause` / `Flow.skipTo` 背压流控与无状态 `ResumeState` 游标分页续查（`resume_at` / `resumeSourceSlice`）；工作线程零分配内存复用池 `Scratch`（`SearchConfig.scratch_pool`）；实时流空闲心跳 |
| **多租户配额与隔离** | 调用方可配置的单源与单请求扫描字节上限、单调时钟纳秒超时预算（`time_budget_ns`）、原子取消令牌 `CancelToken`（`cancel`）、`max_results`、`max_output_bytes`、上下文/解码/事件内存硬顶，以及不泄露服务端路径的三态错误分离（`SoftError.read_failed` vs. 无匹配 vs. 致命错误） |
| **受控多源管线与 172 种文件类型** | 支持 `{a,{b,c}}` 嵌套花括号展开、规则上限与 `iglob` 的字节级通配符；分层 `.gitignore`/`.ignore`/`.rgignore` 评估（`ScopedIgnore`、虚拟 `source.Source` / `ArchiveTree`、内存规则注入 `ignore_texts`）；**172 种内置文件类型**（`src/walk/types.zig`、`expandTypesToGlobs`）；可选符号链接跟随（带 `file_id.zig` 循环检测保护）；`--sort` 与 `--files`；受 `max_concurrency` 约束的工作窃取并发池 |
| **多态契约、59 函数 C ABI 与模糊/OOM 验证** | `MatcherTraits`（`validateMatcher`）与 `SinkTraits` 编译期扩展契约；`AnyMatcher` 与 `AnyEventSink` 运行时类型擦除；**59 函数**零 `libc` C ABI（`include/webgrep.h`、`src/c_api.zig`、`src/c_api_ext.zig`）；**`1,027` 项测试**（`zig build test` AVX2 LLVM）、**`1,013` 项测试**（`-Dteddy=off`）、**`25/25` 组 C ABI 测试**、**5 组跨层差分模糊测试**与 **`std.testing.checkAllAllocationFailures` 全路径 OOM 注入审计**（`src/fuzz.zig`） |

---

## 2. 安全与架构红线

1. **绝不派生外部子进程**：绝不调用 `execve`、`posix.spawn` 或外部解压可执行程序。
2. **绝不使用回溯正则引擎**：绝不引入回溯式正则或 PCRE 绑定，所有正则通过 `UnanchoredDfa` / `SetUnanchoredDfa` / `LazySetDfa` / `BoundedDfa` + Thompson NFA / PikeVM 严格在 $O(n)$ 线性时间内执行。
3. **路径穿越与符号链接安全**：公共服务检索入口（`searchSource`、`searchSourceSlice`、`resumeSourceSlice`、`openSourcePull`、`openReaderPull`）绝不接受文件系统路径；`ArchiveTree` 与 `source.Memory` 严密拦截 `..` / Zip-Slip 路径穿越并跳过符号链接；目录遍历默认禁止跟随符号链接（显式开启 `--follow` 时强制启用 `file_id.zig` inode/device 循环检测保护），且绝不读取宿主机全局配置。
4. **绝不探测宿主机核心数**：并发度完全由调用方传入的 `max_concurrency` 决定。
5. **绝不无界缓冲完整结果集**：事件按行与数据源完成即时流式回调，绝不在内存中无界积压完整结果集；终端着色与 NDJSON 网络序列化交由上层服务处理。
