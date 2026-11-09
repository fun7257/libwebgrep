# libwebgrep 功能矩阵与安全架构边界

[English](FEATURES.md) | [简体中文](FEATURES.zh-CN.md)

`libwebgrep` 是使用纯 Zig `0.17.1` 编写的高性能、可嵌入文本与正则表达式搜索引擎，**零第三方依赖**且**不依赖 `libc`**。

---

## 1. 核心领域功能矩阵

| 领域 | 已实现能力与对应模块 |
| :--- | :--- |
| **输入流与数据源抽象** | 基于 `source_id` + `std.Io.Reader` / `[]const u8` 的服务级入口（`searchSource`、`searchSourceSlice`、`resumeSourceSlice`、`openSourcePull`、增量流式拉模式 `openReaderPull`）；零落盘内存归档解包（`ArchiveTree`，支持 `.tar`、`.tar.gz`/`.tgz`、`.tar.zst`、`.tar.xz`、`.zip`）；虚拟树与归档直接检索（`searchTree`、`searchArchiveSlice`、`searchArchive`）；进程内 Gzip / Zstd / XZ 流式解压与双重防爆保护 |
| **SIMD 检索与正则内核** | 无锁 `*const` 只读匹配器（`Finder`、`Multi`、`Regex`、`RegexSet`、`AnyMatcher`）与 `pattern_id` 模式归因；单字面量 `Finder`（`PackedPair` + `TwoWay` 自适应回退）；四级 `Multi` 多模式 OR 引擎；有界混合惰性 DFA（Hybrid Lazy DFA）+ 锁步 Thompson NFA `Regex`（`src/regex/*`），支持 `RegexScratch`、多正则单遍同时匹配 `RegexSet`、`\p{...}` Unicode 属性（`src/tables/unicode_prop_table.zig`）、UAX #29 Unicode 单词边界（`\b`/`\B`）与结构化编译诊断 `CompileDiagnostic` |
| **行级语义与二次过滤** | 半边界整词匹配（`whole_word`，支持 ASCII 与 Unicode 单词字符）；整行匹配（`whole_line`）；反转匹配（`invert`）；支持字面量与正则的 `contains` / `contains_regexes`（AND）和 `excludes` / `excludes_regexes`（NOT）链式过滤；有序流提前终止（`stop_on_nonmatch`）；`max_count`、`exists` 与 `files_without_match`；只读替换预览（`replacement`，支持 `$0`～`$9` 捕获组展开） |
| **行定界与多字符集转码** | LF / CRLF 行定界；NUL 分隔记录（`null_data`）；UTF-8 / UTF-16LE / UTF-16BE BOM 自动嗅探；基于 WHATWG / HTTP `charset` 提示的 GBK / GB2312 / Latin-1 高速流式转码（`src/codec/encoding.zig` + `src/tables/gbk_table.zig`）；超长行常数内存滑窗（`src/search/long_line.zig`） |
| **二进制 NUL 检测** | 将 NUL 字节检测单遍融合进 SIMD 搜索主循环（`quit`、`report`、`none` 三种策略），精确报告 `binary_offset` 与 `binary_status` |
| **有界上下文与全流高亮** | 免回溯 `BeforeRing` 前文环形缓冲区（`src/search/context_ring.zig`）；后文计数器；相邻上下文窗口自动合并与结构化 `context_break` 分隔事件；全流直通高亮模式（`passthru`） |
| **偏移量、UTF-16 与源码映射** | 1 起始行号、字节列号与 UTF-16 码元列号（`u16_column`）；半开字节区间、UTF-16 区间（`u16_start`、`u16_end`）与 `pattern_id`；可搜索流偏移 `absolute_offset` 与转码/解压前原始流偏移 `raw_offset`（`src/codec/offset_map.zig`） |
| **事件流控与无状态续查** | 同步发送 `begin`、`match`、`context`、`context_break`、`progress`、`heartbeat`、`end` 与 `summary` 事件；支持 `Flow.pause` 背压暂停与无状态游标分页续查（`resume_at` / `resumeSourceSlice`）；工作线程零分配内存复用池 `Scratch`（`SearchConfig.scratch_pool`）；实时流空闲心跳 |
| **多租户配额与隔离** | 单源与单请求扫描字节上限、单调时钟纳秒超时预算（`time_budget_ns`）、原子取消令牌（`cancel`）、`max_results`、`max_output_bytes`、上下文/解码/事件内存硬顶，以及不泄露服务端路径的三态错误分离（`SoftError.read_failed` vs. 无匹配 vs. 致命错误） |
| **受控多源管线与过滤** | 支持 `{a,{b,c}}` 嵌套花括号展开、规则上限与忽略大小写 `iglob` 的字节级通配符；支持物理目录与虚拟 `source.Source` / `ArchiveTree` 的分层 `.gitignore`/`.ignore`/`.rgignore` 评估与内存规则注入（`ignore_texts`）；可注入文件类型表（`expandTypesToGlobs`）；受 `max_concurrency` 严格约束的工作窃取并发池 |
| **多态契约、C ABI 与模糊验证** | `MatcherTraits`（`validateMatcher`）与 `SinkTraits` 编译期扩展契约；`AnyMatcher` 与 `AnyEventSink` 运行时类型擦除；零 `libc` C ABI（`include/webgrep.h`、`src/c_api.zig`、`-Dc-lib=true`）；400+ 项单元、端到端、红队对抗与 `std.testing.Smith` 差分模糊测试套件（`src/fuzz.zig`、`zig build fuzz`） |

---

## 2. 安全与架构红线

1. **绝不派生外部子进程**：绝不调用 `execve`、`posix.spawn` 或外部解压可执行程序。
2. **绝不使用回溯正则引擎**：绝不引入回溯式正则或 PCRE 绑定，所有正则通过有界混合惰性 DFA + Thompson NFA / PikeVM 严格在 $O(n)$ 线性时间内执行。
3. **绝不发生路径穿越或跟随符号链接**：公共检索入口不接受文件系统路径；`ArchiveTree` 与 `source.Memory` 严密拦截 `..` / Zip-Slip 路径穿越并跳过符号链接；目录遍历绝不跟随符号链接、绝不向上越界读取父目录、绝不读取宿主机全局配置。
4. **绝不探测宿主机核心数**：并发度完全由调用方传入的 `max_concurrency` 决定。
5. **绝不无界缓冲完整结果集**：事件按行与数据源完成即时流式回调，绝不在内存中积压完整结果集做后置排序；终端着色与 NDJSON 网络序列化交由上层服务处理。

