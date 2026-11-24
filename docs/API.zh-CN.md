# libwebgrep API 调用参考手册

[English](API.md) | [简体中文](API.zh-CN.md)

本文档是 **libwebgrep v0.10.1**（Zig `0.17.1`、零 libc 依赖、59 个导出 C ABI 函数）的完整参考手册，覆盖 `src/root.zig` 与 `include/webgrep.h` 导出的全部公共类型、函数与子模块。在代码中通过 `@import("libwebgrep")` 导入模块后，即可使用以下所有接口。

`libwebgrep` 在调用方提供的字节流（`*std.Io.Reader`）或内存切片（`[]const u8`）上执行搜索。涉及内存分配或流式 I/O 的入口显式接收 `std.mem.Allocator` 与 `std.Io`；纯内存切片搜索无需分配器。库内部不包含任何全局可变状态。

---

## 一、设计范围与职责边界

`libwebgrep` 是面向多租户服务端嵌入的高性能文本与正则表达式检索引擎：
- **不接收文件系统路径**：公共搜索入口只接收调用方已打开的 `*std.Io.Reader` 或内存切片 `[]const u8`，以及调用方分配的 `source_id: []const u8`，从根源上杜绝路径穿越漏洞（CWE-22）。
- **不派生外部子进程**：所有 Gzip / Zstd / XZ 流式解压与字符集转码均在进程内完成。
- **不耦合终端染色或传输编码**：核心库只返回精确的半开字节区间（`[start, end)`）与 UTF-16 码元区间（`[u16_start, u16_end)`），由调用方决定如何高亮渲染或序列化为 JSON / NDJSON。

---

## 二、核心搜索入口对比

| 入口函数 | 输入数据类型 | 默认注入多租户预算 | 结果交付方式 | 内存分配特性 |
| :--- | :--- | :--- | :--- | :--- |
| **`searchSourceSlice`** | `[]const u8` | **是**（留空字段自动填默认预算） | 推式回调（`Event`） | 无需转码/解压/替换预览时 **零堆内存分配** |
| **`searchSource`** | `*std.Io.Reader` | **是**（留空字段自动填默认预算） | 推式回调（`Event`） | 分配滚动读缓冲与上下文环形缓冲（可通过 `scratch` 跨调用复用） |
| **`searchSourceRange`** | `RandomAccess` + `ByteRange` | **是**（留空字段自动填默认预算） | 推式回调（`Event`） | 定点读取 `[start, end)`，绝不扫描区间外字节 |
| **`searchSourceReverseSlice`** | `[]const u8` | **是**（留空字段自动填默认预算） | 推式回调（`Event`） | 从尾部反向扫描，按最新行优先顺序输出 |
| **`searchSourceReverseAt`** | `RandomAccess` | **是**（留空字段自动填默认预算） | 推式回调（`Event`） | `O(tail)` 反向定点读取，无需从头扫描 |
| **`resumeSourceSlice`** | `[]const u8` + `Result` | **是**（留空字段自动填默认预算） | 推式回调（`Event`） | 从上次 `Flow.pause` 的字节偏移无缝续查，不重复发 `begin` |
| **`openSourcePull`** | `[]const u8` | **是**（留空字段自动填默认预算） | 拉式迭代（`SourcePull.next()`） | 将事件切片深拷贝至 `allocator`，生命周期持续到 `pull.deinit()` |
| **`searchSlice`** | `[]const u8` | 否（留空表示不另设上限） | 旧版方法回调（`Line`） | 无需转码/解压时零堆内存分配 |
| **`searchReader`** | `*std.Io.Reader` | 否（留空表示不另设上限） | 旧版方法回调（`Line`） | 分配滚动读缓冲 |
| **`searchRange`** | `RandomAccess` + `ByteRange` | 否（留空表示不另设上限） | 旧版方法回调（`Line`） | 定点读取 `[start, end)` |
| **`searchReverseSlice`** | `[]const u8` | 否（留空表示不另设上限） | 旧版方法回调（`Line`） | 切片尾部反向扫描（最新行优先） |
| **`searchReverseAt`** | `RandomAccess` | 否（留空表示不另设上限） | 旧版方法回调（`Line`） | `O(tail)` 反向定点读取 |

所有搜索入口的 `matcher` 参数均可传入：
- `*libwebgrep.Finder`（单字面量 SIMD 查找器）
- `*libwebgrep.Multi`（多字面量 OR 自动分级引擎）
- `*libwebgrep.Regex`（线性时间 Thompson NFA 正则引擎）
- `*libwebgrep.RegexSet`（多正则单遍同时匹配引擎）
- `libwebgrep.AnyMatcher`（零分配运行时多态擦除包装器）

### 服务入口回调签名（`S.event`）

传给 `searchSourceSlice`、`searchSource`、`searchSourceRange`、`searchSourceReverseSlice`、`searchSourceReverseAt`、`resumeSourceSlice` 的接收器类型 `S` 只需实现：

```zig
pub fn event(self: *S, ev: libwebgrep.Event) libwebgrep.Flow // 或返回 bool / libwebgrep.FlowAction
```

- 返回 `true`、`Flow.cont` 或 `FlowAction.cont`：继续扫描后续内容。
- 返回 `Flow.skipTo(target_offset)`（即 `FlowAction{ .skip_to = target_offset }`）：在可搜索字节流中直接跳转至 `target_offset`（可用 `read_at`/`seek_input` 时零读取跳过中间段，流式输入则跳过扫描开销）。
- 返回 `false`、`Flow.stop` 或 `FlowAction.stop`：立即停止当前来源，之后仍会收到 `end` 事件。
- 返回 `Flow.pause` 或 `FlowAction.pause`：立即暂停当前来源（不发送 `end` 与 `summary`），返回的 `Result.paused` 为 `true`；将该 `Result` 传给 `resumeSourceSlice` 或 `resumeSource` 即可从暂停处继续扫描。

> **生命周期注意**：回调期间收到的 `LineEvent` 上的切片（`bytes`、`text`、`raw`、`replaced`、`matches`）仅在本次 `event` 回调返回前有效。若需在回调返回后保留，请在回调内拷贝，或使用 `openSourcePull`。

---

## 三、匹配器（Matchers）

### 1. `Finder`（单字面量 SIMD 查找器）

```zig
pub fn init(pattern: []const u8, options: FindOptions) !Finder
pub fn find(self: *const Finder, haystack: []const u8, start: usize, mode: MatchMode) ?Match
pub fn findWatched(self: *const Finder, haystack: []const u8, start: usize, nul: *?usize) ?Match
pub fn requiredLiteral(self: *const Finder) ?RequiredLiteral
pub fn resetStats(self: *const Finder) void
```

- **零堆内存分配**：`pattern` 切片由调用方持有，没有 `deinit`。
- 默认情况下模式中不能包含 `\n`（否则返回 `error.PatternHasNewline`），设置 `FindOptions.multiline = true` 时允许包含 `\n` 并跨行匹配；空模式 `""` 产生零宽匹配 `[0, 0)`。
- 内部采用基于字符频率表的 `PackedPair` 4 窗口合并 SIMD 过滤（42.6 GB/s），并在长模式假阳性超阈值时自动切换为最坏 $O(n)$ 的 Crochemore-Perrin `TwoWay` 算法。

### 2. `Multi`（多字面量 OR 引擎矩阵）

```zig
pub fn init(allocator: std.mem.Allocator, patterns: []const []const u8, options: FindOptions) !Multi
pub fn initFromText(allocator: std.mem.Allocator, text: []const u8, options: FindOptions) !Multi
pub fn deinit(self: *Multi) void
pub fn find(self: *const Multi, haystack: []const u8, start: usize, mode: MatchMode) ?Match
```

- **构造前保护与灵活配置**：模式条数默认上限 `1024`（`default_max_pattern_count`），总字节默认上限 `256 KiB`（`default_max_pattern_bytes`），调用方可通过 `FindOptions` 自由上调或下调；超限在分配表之前返回 `error.PatternCountExceeded` 或 `error.PatternBytesExceeded`。
- **按单条模式智能大小写（`CaseMode.smart`）**：每条模式独立判断（全小写才忽略大小写，含大写则区分大小写）。设置 `FindOptions.unicode_case = true` 时启用 Unicode 简单大小写折叠（Simple Case Folding）。
- **四级自动加速**：按模式特征自动选择 `ByteSet` → `RarePair` → `Teddy` → `AhoCorasick`（稠密+稀疏混合 DFA 与 64B 高半字节 SIMD 跳步）。构造完成后只读（`*const Multi`），可无锁在多线程间共享。

### 3. `Regex` 与 `RegexSet`（线性时间正则表达式引擎）

```zig
pub fn init(allocator: std.mem.Allocator, pattern: []const u8, options: RegexOptions) !Regex
pub fn deinit(self: *Regex) void
pub fn find(self: *const Regex, haystack: []const u8, start: usize, mode: MatchMode) ?Match
```

- **语法支持**：字符类 `[a-z0-9_]` / `[^...]`、14 个 POSIX 字符类（`[:alnum:]`..`[:xdigit:]` 及否定形式 `[:^...:]`）、预定义类 `\d` `\D` `\w` `\W` `\s` `\S`（支持 `RegexOptions.unicode_classes` 或内联 `(?u)`/`(?-u)` 启用 Unicode 语义）、单词边界 `\b` `\B`（默认采用 UTS #18 Unicode 16.0 词字符集 `Alphabetic | M | Nd | Pc | Join_Control`，可通过 `unicode_word_boundary = false` 或 `(?-u)` 切换为 ASCII `[0-9A-Za-z_]`）、转义序列 `\xHH` `\x{...}` `\uHHHH` `\u{...}` `\a` `\f` `\v` `\Q...\E`、通配符 `.`、行/流锚点 `^` `$` `\A` `\z` `\Z`、贪婪与非贪婪量词 `*` `+` `?` `{m}` `{m,}` `{m,n}`、交替 `a|b`、分组 `(?:...)` / 32 个捕获组 `(...)` / 命名捕获组 `(?P<name>...)` / `(?<name>...)` 及内联标志 `(?i)` `(?m)` `(?s)` `(?U)` `(?u)` `(?x)`。
- **绝对防 ReDoS 与多层 DFA 加速**：在 AOT `UnanchoredDfa` / 混合惰性 DFA + 锁步 Thompson NFA / PikeVM 基础上，针对复杂无字面量单正则自动启用与 `RegexSet` 共享的双层无锚点多表 DFA（`SetUnanchoredDfa` Tier A + `LazySetDfa` Tier B），并为多行/单行 `<prefix_lit>.{min,max}<tail_lit>` / `<prefix_lit>.*<tail_lit>` 提供专用 `PrefixAnyTail` 快速路径与线性捕获计划（`extractCaptures`）。最坏时间复杂度严格为 $O(n)$；默认编译指令数上限 `8192`（可通过 `max_inst` 按需上调或下调），超限返回 `error.RegexTooLarge`。
- **统一 SIMD 预过滤（`Regex` 与 `RegexSet`）**：单正则自动提取必需前缀/尾随字面量及多分支前缀做 SIMD 预过滤；`RegexSet` 采用统一的多模式 SIMD 预过滤（前缀/内部/精确字面量 + 次字节掩码校验）、逐模式栈缓冲 NFA 验证以及 `SetUnanchoredDfa` / `LazySetDfa` 双层集合 DFA，单遍完成最多 `1,024` 条正则并发匹配。
- **有界窗口跨行（`RegexOptions.multiline`）**：跨行跨度严格限制在 `max_multiline_window`（默认 `64 KiB`，支持调用方按需配置）内，窗口耗尽仍未闭合匹配时立即判定失配。

---

## 四、`SearchConfig` 完整配置表

| 字段名 | 类型 | 结构体默认值 | 服务入口默认值 / 配置行为 | 功能说明 |
| :--- | :--- | :--- | :--- | :--- |
| `line_numbers` | `bool` | `false` | 服务入口按 `line_number_mode != .unknown` 开启 | 是否计算从 1 开始的行号 |
| `initial_line_number` | `?u64` | `null` | `null` | 为 `byte_range` 中段搜索显式注入起始行号，或为反向尾部搜索注入末尾行号 |
| `line_number_mode` | `LineNumberMode` | `.auto` | `.auto` | 行号计算策略（`.auto`、`.from_one`、`.unknown`） |
| `byte_range` | `?ByteRange` | `null` | `null` | 搜索半开字节区间 `[start, end)`，绝不读取或扫描区间外字节 |
| `range_align_lines` | `bool` | `false` | `false` | 将非行首 `byte_range.start` 对齐至下一行起点，并将切断行的 `byte_range.end` 延伸至该行末尾 |
| `seek_input` / `seek_ctx` | `?fn` / `?*anyopaque` | `null` | `null` | 可选流定位回调 `(ctx, offset)`，用于 `byte_range`、`resume_from` 与 `Flow.skipTo` |
| `read_at` / `read_at_ctx` | `?fn` / `?*anyopaque` | `null` | `null` | 可选定点读取回调 `(ctx, offset, dest) -> usize`，实现零 seek 区间与跳转 I/O |
| `stream_offset` | `?u64` | `null` | `null` | 声明传入的 `*std.Io.Reader` 已由调用方预先定位至该绝对字节偏移 |
| `line_filter` / `line_filter_ctx` | `?fn` / `?*anyopaque` | `null` | `null` | 计入配额前的同步行过滤回调 `(ctx, LineFilterCandidate) -> bool`；在 `max_count`、`max_results`、`matched_lines`、`matches` 与上下文输出前裁决 |
| `invert` | `bool` | `false` | `false` | 按行反选（交出不匹配的行） |
| `whole_word` | `bool` | `false` | `false` | 半边界整词匹配：校验匹配外侧紧邻字符是否非词字符（`whole_word_unicode = true` 时按 UTS #18 Unicode 16.0 词字符集判断，`false` 时按 ASCII `[0-9A-Za-z_]` 判断）；启用 `whole_line` 时忽略 |
| `whole_word_unicode` | `bool` | `true` | `true` | 为 `true`（默认）时，`whole_word` 使用 UTS #18 Unicode 16.0 词字符分类（`Alphabetic \| M \| Nd \| Pc \| Join_Control`）；为 `false` 时仅使用 ASCII `[0-9A-Za-z_]`（与 `rg -w --no-unicode` 一致） |
| `whole_line` | `bool` | `false` | `false` | 整行匹配（优先于 `whole_word`） |
| `multiline` | `bool` | `false` | `false` | 开启跨行（`-U`）搜索语义，允许匹配跨越换行符 |
| `max_multiline_window` | `?usize` | `null` | 默认继承匹配器窗口（`64 KiB`） | 可选覆盖流式与切片跨行搜索的最大前瞻滑窗字节数 |
| `contains` | `[]const []const u8` | `&.{}` | `&.{}` | 链式包含过滤（AND：行内必须同时包含全部所列字节串） |
| `excludes` | `[]const []const u8` | `&.{}` | `&.{}` | 链式排除过滤（NOT：行内不得包含任一所列字节串） |
| `filter_case_insensitive` | `bool` | `false` | `false` | `contains` 与 `excludes` 启用 ASCII 忽略大小写匹配 |
| `filter_smart_case` | `bool` | `false` | `false` | `contains` 与 `excludes` 按每条过滤词独立评估智能大小写 |
| `contains_regexes` | `[]const Regex` | `&.{}` | `&.{}` | 行内必须全部命中的已编译正则列表（AND） |
| `excludes_regexes` | `[]const Regex` | `&.{}` | `&.{}` | 行内不得命中的已编译正则列表（NOT） |
| `context` | `u32` | `0` | 默认上限 `10` 行（可通过 `max_context_lines` 配置） | 对称的前后上下文行数 |
| `before` / `after` | `?u32` | `null` | 默认上限 `10` 行（可通过 `max_context_lines` 配置） | 单独指定前置 / 后置上下文行数 |
| `max_context_lines` | `?u32` | `null` | 默认 `10` 行（可按需上调或下调） | 最大允许的上下文行数上限 |
| `passthru` | `bool` | `false` | `false` | 全文高亮模式：未命中行作为 `context` 交出，受 `max_output_bytes` 约束 |
| `replacement` | `?[]const u8` | `null` | `null` | 只读替换预览模板（填充 `Span.replacement` 与 `LineEvent.replaced`，不改原输入） |
| `max_count` | `?u64` | `null` | 不限 | 单来源最大匹配行数（达到后 `outcome = .stopped`） |
| `max_results` | `?u64` | `null` | 不限 | 请求级最大匹配行数（达到后 `limit_hit = .max_results` 并填 `resume_at`） |
| `resume_from` | `u64` | `0` | `0` | 从可搜索流的指定字节偏移处开始扫描 |
| `exists` | `bool` | `false` | `false` | 存在性查询：首条命中交出后立即停止并调用 `close_input` |
| `files_without_match` | `bool` | `false` | `false` | 无匹配来源筛选：首条命中即停且不交出行事件 |
| `stop_on_nonmatch` | `bool` | `false` | `false` | 有序流提前停止：出现匹配后遇到第一条不匹配行立即停止并关闭上游 |
| `binary` | `BinaryPolicy` | `.quit` | `.quit` | 二进制处理策略：`.quit`（默认跳过）、`.report`（探测但不交出行）、`.none`（按文本） |
| `null_data` | `bool` | `false` | `false` | 用 NUL (`0x00`) 代替 `\n` 分隔记录 |
| `encoding` | `Encoding` | `.auto` | `.auto` | 编码处理：`.auto`（嗅探 BOM 或用 `charset`）、`.detect`（启发式自动识别）、`.utf8`、`.utf16le/be`、`.utf32le/be`、`.gbk`、`.gb18030`、`.shift_jis`、`.euc_jp`、`.big5`、`.euc_kr`、`.latin1`、`.windows1252`、`.windows1251`、`.none`（GBK 与 UTF-16LE 启用 SIMD 批量转码与零拷贝 `Decoder` 缓冲） |
| `charset` | `?[]const u8` | `null` | `null` | WHATWG 标签或 HTTP `Content-Type` 字符集提示（如 `"gb18030"`、`"shift_jis"`、`"windows-1252"`） |
| `compression` | `Compression` | `.none` | `.none` | 进程内流式解压（等价 `-z`）：`.none`、`.auto`（魔数识别 Gzip/Zstd/XZ/Bzip2/LZ4）、`.gzip`、`.zlib`、`.deflate`、`.zstd`、`.xz`、`.lz4`、`.bzip2`、`.brotli` |
| `max_compression_ratio` | `?u64` | `null` | 默认 `100`（调用方可配置） | 最大允许解压膨胀比（拦截压缩炸弹） |
| `max_decompressed_bytes` | `?u64` | `null` | 开启解压时默认 `64 MiB` | 最大解压产出字节上限（超限记为 `LimitHit.decompressed_bytes`） |
| `allocator` | `?Allocator` | `null` | `null` | 切片解压、转码、替换预览与超 32 匹配区间的统一分配器（优先于 `decode_allocator` / `scratch_pool`） |
| `decode_allocator` | `?Allocator` | `null` | `null` | 切片入口在需要转码/解压/生成替换预览时使用的分配器（兼容字段，推荐使用 `allocator` 或 `scratch_pool`） |
| `buffer_size` | `usize` | `1 MiB` | `1 MiB` | 流式读取滚动缓冲区大小 |
| `max_line_len` | `usize` | `2 MiB` | 默认 `2 MiB`（调用方可配置） | 单行最大长度上限（超长行进入恒定内存滑窗预览） |
| `match_mode` | `MatchMode` | `.earliest` | `.earliest` | `.earliest`（最早结束优先）或 `.leftmost_first`（最左起点优先） |
| `scratch` | `?*[]u8` | `null` | `null` | 供 `searchSource` / `searchReader` 跨调用复用的缓冲区指针 |
| `scratch_pool` | `?*Scratch` | `null` | `null` | 跨调用复用的工作线程 `Scratch` 缓冲池，消除稳态堆分配 |
| `max_source_bytes` | `?u64` | `null` | 默认 `16 MiB`（调用方可配置） | 单个来源最大扫描字节预算 |
| `max_request_bytes` | `?u64` | `null` | 默认 `16 MiB`（调用方可配置） | 单次请求最大扫描字节预算 |
| `max_output_bytes` | `?u64` | `null` | 默认 `1 MiB`（调用方可配置） | 行事件累计输出字节上限 |
| `time_budget_ns` | `?u64` | `null` | 默认 `30s`（调用方可配置） | 纳秒级单调时钟超时预算（`LimitHit.deadline`） |
| `cancel` | `?*const Atomic(bool)` | `null` | `null` | 原子取消令牌（置真后立即停止并触发 `LimitHit.cancelled`） |

---

## 五、事件与返回结果结构

### 1. `LineEvent`（行事件）
- `source_id: []const u8`：调用方传入的来源 ID。
- `line_number: u64`：1 起始行号（`null_data` 模式下为记录号；`line_number_known == false` 时为 `0`）。
- `line_number_known: bool`：行号是否已知；未从偏移 0 扫描且未指定 `initial_line_number` 的中段区间搜索或反向尾部搜索下为 `false`。
- `column: ?u64` / `u16_column: ?u64`：1 起始的字节列号与 UTF-16 码元列号。
- `absolute_offset: u64`：行起点在可搜索 UTF-8 流中的 0 起始字节偏移。
- `raw_offset: u64`：行起点在转码或解压前原始字节流中的 0 起始偏移（由 `OffsetMap` 映射）。
- `bytes: []const u8` / `text: []const u8` / `raw: []const u8`：行字节切片与有损 UTF-8 文本切片。
- `replaced: ?[]const u8`：配置了 `SearchConfig.replacement` 时的只读整行替换预览切片。
- `matches: []const Span`：不重叠、按起点升序排列的半开区间数组（含 `start`、`end`、`u16_start`、`u16_end`、`replacement`）。
- `truncated: bool` / `line_len: u64` / `window_start: u64`：超长行窗口截断标记、原始行长与窗口起点偏移。
- **跨行匹配行为（`multiline = true`）**：当匹配跨越多个物理行时，`LineEvent`（及旧版 `Line`）的 `bytes` 包含从首行起点到末行终点的连续跨行切片（保留内部 `\n`、仅剥离末行末尾的换行分隔符），`line_number` 为所跨首行的 1 起始行号，且在同一末行上继续向后续行延伸的桥接匹配会在有界滑窗（`max_multiline_window`）内自动合并至同一事件中。

### 2. `Result`（搜索返回值）与三态错误分离
- **无匹配**：函数正常返回 `Result`，`soft_error == null` 且 `matched_lines == 0`，`begin` 和 `end` 事件照常发出。
- **单来源软错误**：上游读取失败或压缩流损坏时，函数仍正常返回 `Result`，`soft_error == .read_failed`（不含任何服务器内部路径）。
- **致命错误**：上下文超限（`error.ContextLinesExceeded`）、缓冲/转码配额超限（`error.BufferLimit` / `error.DecodeLimit`）或内存不足（`error.OutOfMemory`）通过 Zig 错误联合直接返回。

---

## 六、来源过滤辅助模块（`walk_*`）

- **`walk_glob`（`src/walk/glob.zig`）**：支持 `*`、`?`、`**`、字符类 `[a-z]`、`!` 否定、嵌套花括号 `{a,{b,c}}` 展开（`expandBraces`、`compileGlobs`）、忽略大小写匹配（`classifyWithCase`、`matchTextCase`）与后写规则优先裁决（`matchGlobs`），条数上限（默认 `1024`）、长度上限（默认 `4096`）与花括号深度上限（默认 `8`）均可按需配置。
- **`walk_ignore`（`src/walk/ignore.zig`）**：解析内存中的 `.gitignore` / `.ignore` / `.rgignore` 规则文本（`parseInto`、`parseTextsInto`、`parseLayerInto`），支持 `dot` / `vcs` / `exclude` / `case_insensitive` 细分开关；自动将复合扩展名规则（如 `*.gen.c`、`*.local.log`）路由至后缀匹配以保证根层/子目录层的精确匹配，同时保持点文件扩展名与子目录 `*` + `!反选` 规则一致性。
- **`walk_types`（`src/walk/types.zig`）**：内置 **172 种文件类型**（严格字典序排列、支持二分查找，与 `ripgrep 16.0.0` 对齐，覆盖 `ada` 至 `zstd` 及 `zig`、`rust`、`py`、`ts`、`cpp`、`dockerfile`、`lock`、`markdown`、`toml` 等），并支持调用方自定义类型表注入及展开为 Glob（`find`、`findInTable`、`expandTypesToGlobs`、`matches`、`matchesWithTable`）。

---

## 七、`src/root.zig` 导出符号完整索引

### matcher
重导出 `src/matcher.zig`，定义字面量与正则共用的匹配模式、区间结构、大小写策略、类型擦除包装器 `AnyMatcher` 与模式配额上限校验函数 `checkPatternLimits`。

### sink_mod
重导出 `src/sink.zig`，包含所有服务事件（`Event`）、行结果（`LineEvent` / `Line`）、流控（`Flow`）、`AnySink`、`AnyEventSink` 与完成状态（`Result`）定义。

### searcher
重导出 `src/searcher.zig`，包含 `SearchConfig`、`Scratch`、`SliceError`、`ReadError`、`PullEvent`、`SourcePull`、`ReaderPull`、`openReaderPull` 及全部搜索入口实现。

### MatchMode
匹配选择模式枚举：`.earliest`（选择最早结束的匹配，默认）或 `.leftmost_first`（选择最左起点的匹配，与 `rg -F` 一致）。

### Match
半开字节区间 `struct { start: usize, end: usize, pattern_id: ?u32 = null }`，相对于传入 `find` 的 `haystack` 切片，并携带命中模式的 0 起始索引 `pattern_id`（单模式为 `null`）。

### RequiredLiteral
`struct { bytes: []const u8, offset_in_match: usize }`，从匹配器提取的必需字面量锚点，供 `Searcher` 执行 SIMD 预过滤。

### CaseMode
大小写匹配模式枚举：`sensitive`（默认）、`insensitive` 或 `smart`（按每条模式独立判断智能大小写）。

### FindOptions
构造 `Finder` 或 `Multi` 的配置项（`case`、`unicode_case`、`multiline`、`max_multiline_window`、`frequency: ?[256]u8 = null`、`prefilter_fp_threshold`、`max_pattern_count`、`max_pattern_bytes`、`max_unicode_variants`）。

### AnyMatcher
面向 `*const Finder`、`*const Multi`、`*const Regex`、`*const RegexSet` 及自定义匹配器的零分配运行时多态擦除包装器（`AnyMatcher.init(M, &m)` 或 `AnyMatcher.from(&m)`），支持无锁多线程共享与减少编译期单态化膨胀。

### Span
行内匹配的半开字节区间（`start`、`end`）、预计算的 UTF-16 码元端点（`u16_start`、`u16_end`）、0 起始命中模式 ID（`pattern_id: ?u32 = null`）与可选只读替换切片（`replacement`）。

### Line
旧版回调入口（`searchSlice` / `searchReader`）交付的匹配行或上下文行结构，切片仅在回调返回前有效。

### BinaryStatus
二进制检测状态枚举：`none`、`detected` 或 `suppressed`。

### Event
服务入口同步交付的事件联合体：`begin`、`match`、`context`、`context_break`、`progress`、`heartbeat`、`end`、`summary`。

### LineEvent
服务入口交付的单行事件结构，包含 `source_id`、1 起始行号、字节列号与 UTF-16 列号、`absolute_offset`、`raw_offset`、行内容切片及 `matches` 区间数组。

### EndEvent
单来源完成事件。即使来源零命中也必会依次发出 `begin` 与 `end`。

### AnySink
旧版接收器的运行时多态擦除包装器（`ctx` + `vtable`），其 `vtable` 生命周期须长于 `AnySink`。

### anyVtable
在编译期为任意旧版接收器类型 `S` 生成 `AnySink.VTable`，零堆内存分配。

### AnyEventSink
服务级 `Event` 接收器的运行时多态擦除包装器（`AnyEventSink.init(S, &sink)` 或 `AnyEventSink.from(&sink)`），允许异构接收器复用同一套单态化搜索管线。

### SliceIter
面向单个内存切片的无上下文、零分配拉式匹配行迭代器（`SliceIter(M)`）。

### Result
单来源搜索完成后的返回值结构，区分正常匹配、零命中、单来源软错误（`soft_error`）与预算停止原因（`limit_hit`）。

### Outcome
搜索终止结果枚举：`complete`、`stopped`、`binary_quit` 或 `binary_matched`。

### LimitHit
搜索触发的多租户配额限制枚举：`none`、`max_results`、`max_bytes`、`deadline`、`decompressed_bytes` 或 `cancelled`。

### SoftError
单来源非致命软错误枚举（`read_failed`），已剥离任何服务器内部文件路径。

### Flow
服务事件回调返回的流控指令：`cont`（继续）、`pause`（暂停并保存游标）或 `stop`（停止当前来源），并提供 `Flow.skipTo(offset)` 生成流内字节跳转动作。

### FlowAction
扩展流控动作联合体（`cont`、`pause`、`stop`、`skip_to: u64`），支持在正向或反向搜索回调中直接按字节偏移跳步跳过无关区域。

### Summary
单次请求完整结束（未暂停且非打开的实时流）时发出的最终统计汇总事件。

### Progress
按 `SearchConfig.progress_interval` 字节间隔周期性发出的扫描进度快照。

### Heartbeat
在实时流（`live = true`）空闲读取达到 `idle_timeout_ns` 时发出的心跳事件。

### ResumeState
保存在 `Result.resume_state` 中的内部计数器与原始流断点（`raw_resume_at`）快照，供 `resumeSourceSlice` 与 `resumeSource` 在 `Flow.pause` 后无缝恢复。

### BinaryPolicy
二进制输入处理策略枚举：`quit`（默认遇到 NUL 立即跳过）、`report`（探测但不输出行内容）或 `none`（按普通文本处理）。

### ByteRange
数据源内的半开字节区间 `struct { start: u64 = 0, end: ?u64 = null }`（`end == null` 表示扫描至 EOF），供 `SearchConfig.byte_range`、`searchRange` 与 `searchSourceRange` 使用。

### LineNumberMode
行号计算策略枚举：`.auto`（从偏移 0 开始或提供 `initial_line_number` 时计算精确行号，否则标记 `line_number_known = false`）、`.from_one`（从所搜区间起点按 1 计数）与 `.unknown`（禁用行号统计）。

### LineFilterCandidate
传给 `SearchConfig.line_filter` 的候选命中行结构（含 `bytes`、`raw_bytes`、`absolute_offset`、`first_match`、`is_inverted`），在消耗 `max_count`、`max_results` 或递增命中计数前执行零配额损耗过滤。

### Encoding
输入字符集编码枚举（共 17 种）：`auto`（默认嗅探 UTF-8/UTF-16/UTF-32 BOM 或采用 `charset` 提示）、`detect`（启发式自动识别）、`none`、`utf8`、`utf16le`、`utf16be`、`utf32le`、`utf32be`、`gbk`、`gb18030`、`shift_jis`、`euc_jp`、`big5`、`euc_kr`、`latin1`、`windows1252`、`windows1251`。其中 GBK（直接 UTF-8 LUT + `@ctz` SIMD ASCII 前缀扫描）与 UTF-16LE 路径启用 SIMD 批量转码，配合零拷贝 `Decoder` 缓冲与游程级 `OffsetMap` 偏移映射。

### Compression
进程内流式解压格式枚举（共 10 种，等价 `-z` 且无需全量缓存在内存中）：`none`（默认）、`auto`（自动识别 Gzip/Zstd/XZ/Bzip2/LZ4 魔数，非压缩流保持零缓冲流式扫描）、`gzip`、`zstd`、`xz`、`zlib`、`deflate`、`lz4`、`bzip2`、`brotli`。

### decompress
重导出 `src/codec/decompress.zig`，提供防压缩炸弹（实时校验 `max_decompressed_bytes` 与 `max_compression_ratio`）的进程内流式解压（`-z`）与游程级原始字节偏移映射表 `OffsetMap`。

### SearchConfig
搜索行为与多租户预算配置结构（含统一 `allocator` 与零分配复用池 `scratch_pool`）；服务入口在预算字段为 `null` 时自动填充安全默认值，并支持调用方按需覆盖配置。

### Scratch
跨请求/跨来源复用的工作线程内存缓冲池（`SearchConfig.scratch_pool`），复用流式读缓冲、转码缓冲、替换预览缓冲与前文环形缓冲，实现稳态零堆分配。

### PullEvent
拉式迭代器（`SourcePull` 与 `ReaderPull`）产出的单条事件结构，其内部切片在调用迭代器 `deinit()` 前始终有效。

### SourcePull
面向内存切片的拉式服务事件迭代器类型（`SourcePull(M)`）。

### ReaderPull
面向 `*std.Io.Reader` 的增量流式拉模式状态机（`ReaderPull(M)`），按需分块读取、流式解压与转码，不将整个流预加载至内存。

### searchSlice
旧版内存切片回调搜索入口（不自动填充服务默认预算）。

### searchReader
旧版 `*std.Io.Reader` 流式回调搜索入口（服务负载请优先使用 `searchSource`）。

### searchRange
旧版定点区间回调搜索入口：在无句柄 `RandomAccess` 数据源上仅读取并搜索 `ByteRange`（`[start, end)`）。

### searchSource
服务级流式搜索入口：在 `*std.Io.Reader` 上搜索调用方指定的 `source_id`，自动应用多租户默认预算。

### searchSourceRange
服务级定点区间搜索入口：在无句柄 `RandomAccess` 数据源上搜索 `ByteRange` 并自动应用多租户默认预算（正常扫完区间时 `limit_hit == .none` 且 `partial == false`）。

### resumeSource
从前一次 `Flow.pause` 返回的 `Result` 断点处继续搜索 `*std.Io.Reader` 流，不重复发出 `begin` 事件。

### searchSourceSlice
服务级内存切片搜索入口：无需转码、解压或替换预览时执行零堆分配搜索。

### resumeSourceSlice
从前一次 `Flow.pause` 返回的 `Result` 断点处继续搜索同一切片（转码场景仅对 `raw_resume_at` 之后的未扫描尾部转码），不重复发出 `begin` 事件。

### searchReverseSlice
旧版内存切片反向尾部搜索入口：从切片（或 `byte_range`）末尾向前分块扫描，按最新行优先顺序交付命中。

### searchSourceReverseSlice
服务级内存切片反向尾部搜索入口：支持 `max_results` / `Flow.pause` 反向游标分页（`Result.resume_at` 保存上一条已发命中行的起始偏移）。

### searchReverseAt
旧版 `RandomAccess` 反向尾部搜索入口：以 `O(tail)` 定点读取从数据源尾部向前检索，无需扫描前段数据。

### searchSourceReverseAt
服务级 `RandomAccess` 反向尾部搜索入口：以 `O(tail)` 定点读取配合多租户默认预算执行最新日志优先检索。

### ParallelOptions
单来源多核并行搜索的调优参数：`workers`（含调用线程在内的扫描线程数，`null` 时依次取 `max_concurrency`、CPU 逻辑核数，上限 64）、`chunk_size`（默认 `256 KiB`，按记录边界对齐）、`max_inflight`（领先于有序发射器的分块数，默认 `2 * workers`）、`max_buffered_bytes`（在途分块已记录行事件的总字节上限，默认 `4 MiB`）、`min_parallel_bytes`（小于该值走顺序路径，默认 `2 * chunk_size`）。工作内存上限为 `max_buffered_bytes` 加每个扫描线程一个 `chunk_size + 256 KiB` 读缓冲（仅 `RandomAccess` 来源；切片直接借用、零拷贝），8 核 Apple M2 上以 8 个扫描线程检索 512 MiB 文件型来源时实测进程峰值 RSS 约 6–11 MiB。Sink 回调只在调用线程上按字节顺序执行、绝不并发，行号、偏移、`max_count` / `max_results` / `exists` / `max_output_bytes`、二进制处理与 `Flow`（`stop` / `pause` / `skip_to`）语义与顺序入口完全一致；上下文行、`passthru`、`invert`、跨行匹配器、含 `\A` / `\z` / `\Z` 的正则、转码或解压、`line_filter`、`live`、`resume_from` / `continuation`、`progress_interval` 与 `BinaryPolicy.report` 会在任何回调之前自动回退到顺序引擎。并行入口的 `allocator` 必须线程安全。

### searchSliceParallel
旧版内存切片多核并行入口：`searchSlice` 的多核等价实现，`Line` 回调在调用线程上按字节顺序交付。

### searchSourceSliceParallel
服务级内存切片多核并行入口：`searchSourceSlice` 的多核等价实现，适用于单个大型内存来源并自动应用多租户默认预算。

### searchParallelAt
旧版 `RandomAccess` 多核并行入口：对 `config.byte_range`（或整个来源）分块并行检索，每个扫描线程独立执行定点读取；`source.size` 未知时回退到 `searchRange`。

### searchSourceParallelAt
服务级 `RandomAccess` 多核并行入口：`searchSourceRange` 的多核等价实现，覆盖 `config.byte_range`（或整个来源）并自动应用多租户默认预算。

### countSliceParallel
内存切片多核并行计数：不交付行事件，仅统计匹配行（等价于使用无 `matched` 回调的 Sink 调用 `searchSlice`），扫描线程不做任何记录，接近线性扩展。

### countParallelAt
`RandomAccess` 来源多核并行计数：不交付行事件，仅统计匹配行。

### openSourcePull
基于拉式迭代器的切片服务事件搜索入口（返回 `searcher.SourcePull`）。

### openReaderPull
基于增量流式拉模式状态机的 `*std.Io.Reader` 服务事件搜索入口（返回 `ReadError!ReaderPull(@TypeOf(matcher))`）。

### probe
重导出 `src/probe.zig`，提供无文件句柄的 `RandomAccess` 抽象与按字节偏移提取完整行/有界窗口的原语（`ProbeOptions`、`LineProbe`、`probeLineSlice`、`probeLineAtBuf`、`probeLineAt`）。

### RandomAccess
无路径、无文件句柄的定点随机读取接口（`ctx`、`read_at`、`size`、`readAt`、`readAtFull`、`fromSlice`）。

### ProbeOptions
字节偏移行探测配置（`delimiter`、`strip_crlf`、`max_line_bytes`、`window_chunk_bytes`）。

### LineProbe
围绕目标字节偏移提取出的所在行或有界窗口结果（`start_offset`、`end_offset`、`raw_end_offset`、`bytes`、`truncated_left`、`truncated_right`、`owned`、`deinit`），严格满足区间划分不变量 `start_offset <= offset < raw_end_offset`。

### probeLineSlice
在内存切片 `haystack` 上按字节偏移执行零分配行探测。

### probeLineAtBuf
在 `RandomAccess` 数据源上将探测到的行内容直接写入调用方缓冲区 `buf`，零堆内存分配。

### probeLineAt
在 `RandomAccess` 数据源上使用显式 `Allocator` 探测并分配返回所在行切片（调用 `deinit(allocator)` 释放）。

### seekable
重导出 `src/codec/seekable.zig`，提供可寻址压缩流的随机读取支持（`ZstdSeekTable`、`SeekableZstdReader`、`GzipIndex`、`IndexedGzipReader`）。

### ZstdSeekTable
官方 Zstandard Seekable Format（尾部可跳过帧 `0x184D2A5E` / `0x8F92EAB1`）索引解析器与 `O(log F)` 帧级随机解压读取器（含纯 Zig XXH64 校验与防压缩炸弹膨胀比保护）。

### SeekableZstdReader
将 `ZstdSeekTable` 与底层压缩 `RandomAccess` 封装为透明未压缩 `RandomAccess` 视图的适配器（通过 `.randomAccess()` 直接对接 `probeLineAt`、`searchSourceRange` 与 `searchSourceReverseAt`）。

### GzipIndex
纯 Zig RFC 1951/1952 多成员 Gzip / Deflate 块级检查点索引器与 `O(log C)` 随机恢复解压读取器（支持流式建索引、CRC32 序列化持久化及跨块滑窗恢复）。

### IndexedGzipReader
将 `GzipIndex` 与底层压缩 `RandomAccess` 封装为透明未压缩 `RandomAccess` 视图的适配器（通过 `.randomAccess()` 直接对接 `probeLineAt`、`searchSourceRange` 与 `searchSourceReverseAt`）。

### memchr
重导出 `src/finder/memchr.zig`，提供 16/32 字节宽度的向量化单字节查找（`find`、`findEither`、`findAny`、`findLast`、`count`）。

### finder
重导出 `src/finder/finder.zig`，即单字面量 SIMD 查找器 `Finder` 的定义模块。

### Finder
单字面量 SIMD 查找器（`*const Finder` 无锁只读，采用 `PackedPair` 4 窗口 SIMD + `TwoWay` 线性回退，支持 `unicode_case` 零分配 BMP Unicode 大小写折叠），零堆内存分配。

### multi
重导出 `src/finder/multi.zig`，即多字面量 OR 引擎 `Multi` 的定义模块。

### Multi
多字面量 OR 自动分级检索引擎（`*const Multi` 无锁只读，`ByteSet` / `RarePair` / `Teddy` / `AhoCorasick`，精确返回获胜模式的 `pattern_id`）。

### regex
重导出 `src/regex.zig`，即线性时间正则引擎 `Regex`、`RegexScratch`、`RegexSet`、`RegexOptions`、`Captures`、`DiagnosticCode` 与 `CompileDiagnostic` 的定义模块。

### Regex
基于 AOT `UnanchoredDfa` + 有界混合惰性 DFA（Hybrid Lazy DFA）+ 锁步 Thompson NFA / PikeVM 与 SIMD 预过滤的线性时间正则表达式引擎（`*const Regex` 无锁只读）：对复杂无字面量单正则同样启用 `SetUnanchoredDfa` / `LazySetDfa` 双层多表 DFA，为多行/单行 `<prefix_lit>.{min,max}<tail_lit>` / `<prefix_lit>.*<tail_lit>` 提供专用 `PrefixAnyTail` 快速路径，并支持 `\p{...}` Unicode 属性、14 个 POSIX 字符类 `[:...:]`、UTS #18 Unicode 16.0 单词边界 `\b`/`\B`（`Alphabetic | M | Nd | Pc | Join_Control`，可切换 ASCII）、`\Q...\E` 字面引用、`(?x)`/`(?U)`/`(?u)` 标志、命名捕获组 `(?P<name>...)`/`(?<name>...)` 与 `$1`..`$32` 捕获组。

### RegexScratch
供 `Regex.findWithScratch` 与 `Regex.findCapturesWithScratch` 复用的线程本地 DFA 状态缓存与 NFA 队列缓冲池，实现稳态零分配正则匹配。

### RegexSet
多正则单遍同时匹配引擎（默认上限 `1,024` 条正则、可通过 `max_pattern_count` / `max_pattern_bytes` 配置）：编译为合并 Thompson NFA，配备统一 `RegexSet` SIMD 预过滤（`Multi` 前缀/内部/精确字面量 + 次字节掩码校验）、逐模式栈缓冲 NFA 验证以及 `SetUnanchoredDfa` Tier A / `LazySetDfa` Tier B 双层无锚点集合 DFA，支持 `isMatch`、`find`、`findWatched`、`findEnd`、`findEndWatched` 与单遍获取全部命中模式 ID 的 `matches`。

### DiagnosticCode
正则编译诊断错误码枚举（精确标识 `empty_pattern`、未闭合括号、无效/重复捕获组名 `invalid_group_name`/`duplicate_group_name`、无效 POSIX 字符类 `invalid_posix_class`、未闭合字符类、未知 Unicode 属性、非法量词、递归深度超限、指令数超限等）。

### CompileDiagnostic
由 `Regex.initDiagnostic` 与 `RegexSet.initDiagnostic` 填充的结构化编译错误诊断信息（含 `err`、`code`、字节偏移 `offset`/`byte_offset`、1 起始 `line`/`column`、错误描述 `message` 与模式索引 `pattern_index`）。

### RegexOptions
构造 `Regex` 与 `RegexSet` 的配置项：大小写模式（`case` / `unicode_case`）、Unicode 字符类与词边界开关（`unicode_classes: bool = false`、`unicode_word_boundary: bool = true` 控制 UTS #18 Unicode 16.0 vs ASCII `\b`/`\B`）、有界跨行匹配（`multiline` / `max_multiline_window` 默认 `64 KiB`）、`dot_all`、编译限制（`max_inst` / `max_insts: ?usize = null` 默认 `8192`、`max_repeat: usize = 1000`、`max_recursion_depth: usize = 64`）、多模式与预过滤限制（`max_pattern_count: ?usize = null` 默认 `1024`、`max_pattern_bytes: ?usize = null` 默认 `256 KiB`、`max_unicode_variants: usize = 64`）及 DFA 规模限制（`aot_dfa_max_insts: usize = 256`、`max_dfa_states: u16 = 256`）。

### Captures
正则子匹配捕获组结构，保存完整匹配（`match`）与最多 32 个编号/命名捕获组 `$1`..`$32`（`groups[0..31]`、`byName(re, name)`），供 `Regex.findCaptures`、`Regex.findCapturesWithScratch`、`Regex.extractCaptures` 及 `SearchConfig.replacement` 替换模板（`$0`/`$&`/`$1`..`$32`/`${1}`..`${32}`/`${name}`/`$$`）使用。

### two_way
重导出 `src/finder/two_way.zig`，提供最坏时间复杂度严格 $O(n)$、零堆分配的 Crochemore-Perrin Two-Way 子串查找器。

### bloom
重导出 `src/finder/bloom.zig`，提供基于 Kirsch-Mitzenmacher 双重哈希的 N-gram / 三元组布隆过滤器与零漏报匹配器预筛器（`BloomConfig`、`NgramBloom`）。

### BloomConfig
`NgramBloom` 配置结构（`bit_count: u32 = 16384`、`num_hashes: u8 = 3`、`ngram_len: u8 = 3`、`ascii_lower: bool = true`）。

### NgramBloom
紧凑型 N-gram 布隆过滤器，支持 `init`、零堆分配 `initBorrowed`、`addSlice`、跨块边界重叠续写的 `writer().addChunk`、带 CRC32 校验的 `serializeAlloc` / `deserialize`、`merge` 及面向 `Finder`、`Multi`、`Regex`、`RegexSet` 的零漏报预筛（完整覆盖 `k`/`K`、`s`/`ſ`、`ß`/`ẞ` 等 Unicode 大小写折叠伙伴）。

### source
重导出 `src/source.zig`，提供面向归档或内存虚拟目录树的抽象接口（`Source`、`Node` 含可选 `mtime: ?i64` 时间戳、`Memory`，支持分块读取/枚举游标、句柄关闭复用及 `..` 路径穿越拦截）。

### archive
重导出 `src/codec/archive.zig`，提供零落盘内存归档解包引擎（支持 `.tar`、`.tar.gz`/`.tgz`、`.tar.zst`、`.tar.xz`、`.tar.bz2`、`.tar.lz4` 与 `.zip`）。

### ArchiveFormat
归档容器格式枚举：`auto`（自动魔数嗅探）、`tar`、`tar_gz`、`tar_zst`、`tar_xz`、`tar_bz2`、`tar_lz4`、`zip`。

### ArchiveEntryMeta
归档条目元数据结构（`path`、`kind`、`size`、`compressed_size`、`mtime`），在执行解压与配额计费前传给 `ArchiveOptions.entry_filter`。

### ArchiveOptions
归档解包安全配额与预过滤选项（`format`、`max_entries`、`max_entry_bytes`、`max_total_bytes`、`max_compression_ratio`、`max_archive_depth` 嵌套归档最大深度及解压前元数据过滤回调 `entry_filter` / `entry_filter_ctx`）。

### ArchiveError
归档解包错误集（`UnsupportedFormat`、`CorruptArchive`、`ArchiveLimit`、`PathTraversal`、`OutOfMemory`），内置严密的 Zip-Slip 路径穿越防御。

### ArchiveTree
零落盘内存归档树结构（`initFromSlice`、`initFromReader`、`deinit`、`source`），解包后直接生成虚拟 `source.Source` 供 `searchTree` 检索。

### tree
重导出 `src/search/tree.zig`，提供面向虚拟目录树与内存归档的检索编排入口（`TreeConfig`、`searchTree`、`searchArchiveSlice`、`searchArchive`）。

### TreeConfig
虚拟树与归档检索配置（聚合 `SearchConfig`、`ArchiveOptions`、Glob/文件类型过滤及配额 `max_glob_rules`/`max_glob_rule_len`/`max_glob_brace_depth`、内存与分层 `.gitignore`/`.ignore`/`.rgignore` 开关及目录深度/文件数配额）。

### searchTree
在虚拟 `source.Source` 目录树上执行分层 `.gitignore` 过滤、Glob/类型筛选与多租户预算受控检索（绝不接收物理文件句柄 `std.Io.File` 或 `std.Io.Dir`）。当 `max_concurrency > 1` 时自动通过 `Scheduler` 多线程并发扫描，对原子重放保证单文件行事件不交叉，并在单线程目标上自动降级串行执行。

### searchArchiveSlice
直接对内存中的归档字节切片（`.tar` / `.tar.gz` / `.tar.zst` / `.tar.xz` / `.zip`）执行零落盘解包与多文件检索。

### searchArchive
直接对 `*std.Io.Reader` 归档字节流执行零落盘解包与多文件检索。

### searchTarStream
以恒定 O(buffer_size) 内存单遍流式扫描 `*std.Io.Reader` 中的 `.tar` / `.tar.gz` / `.tar.zst` / `.tar.xz` 归档，不在内存中缓存整份归档或条目负载；强制执行路径穿越防护、符号链接跳过、`entry_filter` 预过滤、解压炸弹/条目上限及全局请求预算（`.zip` 返回 `error.UnsupportedFormat`）。

### scheduler
重导出 `src/scheduler.zig`，提供不依赖任何文件路径或目录句柄的通用无锁 Chase-Lev 工作窃取任务调度器模块。

### SchedulerConfig
通用工作窃取调度器配置（`max_threads`、`stop`、`cancel`；单工作线程自动走零锁内联快速路径）。

### Scheduler
参数化通用工作窃取调度器 `Scheduler(comptime Task: type, comptime Context: type)`，支持递归子任务 `handle.spawn(subtask)`、本地 `LIFO` 弹出与跨线程 `FIFO` 窃取、`handle.stop()` 及异常/取消自动排空清理。

### walk_glob
重导出 `src/walk/glob.zig`，提供支持嵌套花括号展开、可配置条数/长度/花括号深度上限与忽略大小写的字节级 Glob 匹配器。

### walk_ignore
重导出 `src/walk/ignore.zig`，提供内存态 `.gitignore` / `.ignore` / `.rgignore` 规则解析与层级化匹配器，支持复合扩展名（如 `*.gen.c`、`*.local.log`）后缀路由、点文件扩展名与子目录通配符反选一致性。

### walk_deque
重导出 `src/walk/deque.zig`，提供面向指针元素的无锁 Chase-Lev 工作窃取双端队列 `Deque(T)`。

### walk_file_id
重导出 `src/walk/file_id.zig`，从已打开的 `std.Io.Dir` 与 `std.Io.File` 句柄提取设备号与 inode 标识（`Id`）。

### walk_types
重导出 `src/walk/types.zig`，提供内置 **172 种文件类型**（严格字典序二分查找，与 `ripgrep 16.0.0` 对齐）与可注入自定义文件类型映射表及 Glob 展开工具。

### walk_list
重导出 `src/walk/list_dir.zig`，提供在已打开 `std.Io.Dir` 上批量读取目录项的迭代器 `Lister`。

---

## 八、C ABI 跨语言绑定接口（`include/webgrep.h`）

`zig build` 默认产出零 libc 依赖的静态库（`libwebgrep.a`）、动态库（`libwebgrep.so` / `.dylib`）与标准 C99/C11 头文件 `include/webgrep.h`（`WEBGREP_VERSION_MAJOR = 0`、`WEBGREP_VERSION_MINOR = 10`、`WEBGREP_VERSION_PATCH = 1`、`WEBGREP_VERSION_STRING = "0.10.1"`，`webgrep_version()` 返回 `"0.10.1"`，带 `WEBGREP_API` DLL 导入/导出宏），导出全部 **59 个 C ABI 函数**：
- **默认配置与版本（7）**：`webgrep_version`、`webgrep_find_options_default`、`webgrep_regex_options_default`、`webgrep_config_default`、`webgrep_tree_config_default`、`webgrep_probe_options_default`、`webgrep_bloom_config_default`
- **匹配器、缓存与取消令牌（11）**：`webgrep_matcher_compile_literal`、`webgrep_matcher_compile_multi`、`webgrep_matcher_compile_regex`、`webgrep_matcher_compile_regex_set`、`webgrep_matcher_free`、`webgrep_scratch_new`、`webgrep_scratch_free`、`webgrep_cancel_new`、`webgrep_cancel_trigger`、`webgrep_cancel_reset`、`webgrep_cancel_free`
- **查找、捕获组与拉式迭代（8）**：`webgrep_find`、`webgrep_regex_set_matches`、`webgrep_find_captures`、`webgrep_matcher_group_index`、`webgrep_pull_open_slice`、`webgrep_pull_open_reader`、`webgrep_pull_next`、`webgrep_pull_free`
- **流式、随机访问与归档检索（9）**：`webgrep_search_slice`、`webgrep_search_reader`、`webgrep_search_range`、`webgrep_search_reverse_slice`、`webgrep_search_reverse_at`、`webgrep_probe_line_slice`、`webgrep_probe_line_at`、`webgrep_search_archive_slice`、`webgrep_search_archive_reader`
- **Bloom 预筛与随机解压索引（17）**：`webgrep_bloom_new`、`webgrep_bloom_free`、`webgrep_bloom_add`、`webgrep_bloom_merge`、`webgrep_bloom_may_contain`、`webgrep_bloom_serialize`、`webgrep_bloom_deserialize`、`webgrep_zstd_seek_table_parse`、`webgrep_zstd_seek_table_free`、`webgrep_zstd_seek_table_uncompressed_size`、`webgrep_zstd_seek_table_read_at`、`webgrep_gzip_index_build`、`webgrep_gzip_index_free`、`webgrep_gzip_index_uncompressed_size`、`webgrep_gzip_index_serialize`、`webgrep_gzip_index_deserialize`、`webgrep_gzip_index_read_at`
- **流控回调与无状态续查分页（7）**：`webgrep_resume_state_new`、`webgrep_resume_state_free`、`webgrep_resume_state_reset`、`webgrep_resume_state_offset`、`webgrep_resume_state_is_paused`、`webgrep_search_slice_flow`、`webgrep_search_reader_flow`

关键 C ABI 枚举与配置说明（`include/webgrep.h`）：
- `webgrep_whole_word_mode_t`（用于 `webgrep_config_t.whole_word`）：`WEBGREP_WHOLE_WORD_OFF = 0`（关闭）、`WEBGREP_WHOLE_WORD_UNICODE = 1`（UTS #18 Unicode 16.0 词边界，非零且非 ASCII 值默认按 Unicode 语义保持向后兼容）、`WEBGREP_WHOLE_WORD_ASCII = 2`（仅 ASCII `[0-9A-Za-z_]`，对应 `rg -w --no-unicode`）。
- `webgrep_flow_action_t`（配合 `webgrep_flow_t` 与 `webgrep_flow_line_cb`）：`WEBGREP_FLOW_CONT = 0`、`WEBGREP_FLOW_STOP = 1`、`WEBGREP_FLOW_PAUSE = 2`、`WEBGREP_FLOW_SKIP_TO = 3`。
- 其他完整枚举：`webgrep_status_t`、`webgrep_case_mode_t`、`webgrep_match_mode_t`、`webgrep_binary_policy_t`、`webgrep_encoding_t`（17 种编码）、`webgrep_compression_t`（10 种压缩格式）、`webgrep_archive_format_t`（8 种归档格式）、`webgrep_limit_hit_t`、`webgrep_line_number_mode_t` 与 `webgrep_entry_kind_t`。

---

## 九、全场景实战代码示例

以下代码块完整演示了 6 个高频实战场景，并由 `build.zig` 自动抽取编译执行：
1. **单字面量智能大小写搜索与 UTF-16 码元区间读取**（`searchSourceSlice` + `*const Finder`）
2. **多模式文本解析（`Multi.initFromText`）、`pattern_id` 归因与无状态分页暂停/续查**（`Flow.pause` + `resumeSourceSlice`）
3. **线性时间正则匹配（`Regex`）、多正则集合（`RegexSet`）与只读替换预览**（`SearchConfig.replacement`）
4. **流式 `*std.Io.Reader` 搜索（`searchSource`）、切片拉式迭代（`openSourcePull`）与增量流式拉模式迭代（`openReaderPull`）**
5. **Glob 嵌套花括号展开与忽略大小写过滤**（`walk_glob.compileGlobs` + `matchGlobs`）
6. **字节偏移行探测（`probeLineSlice`）、`RandomAccess` 区间搜索（`searchSourceRange`）、反向尾部搜索（`searchSourceReverseSlice`）与 `NgramBloom` 零漏报预筛**

```zig
const std = @import("std");
const libwebgrep = @import("libwebgrep");

const Recorder = struct {
    saw_begin: bool = false,
    saw_end: bool = false,
    saw_summary: bool = false,
    matched_lines: usize = 0,
    first_u16_end: usize = 0,
    last_pattern_id: u32 = 0,
    last_replaced: [64]u8 = undefined,
    last_replaced_len: usize = 0,
    pause_after_first: bool = false,

    pub fn event(self: *Recorder, ev: libwebgrep.Event) libwebgrep.Flow {
        switch (ev) {
            .begin => |b| {
                if (std.mem.eql(u8, b.source_id, "doc-1")) self.saw_begin = true;
            },
            .match => |m| {
                self.matched_lines += 1;
                if (m.matches.len > 0) {
                    self.first_u16_end = m.matches[0].u16_end;
                    self.last_pattern_id = m.matches[0].pattern_id orelse 0;
                }
                if (m.replaced) |rep| {
                    const n = @min(rep.len, self.last_replaced.len);
                    @memcpy(self.last_replaced[0..n], rep[0..n]);
                    self.last_replaced_len = n;
                }
                if (self.pause_after_first and self.matched_lines == 1) {
                    return .pause;
                }
            },
            .end => |e| {
                if (e.soft_error == null) self.saw_end = true;
            },
            .summary => |s| {
                if (s.searches == 1 and s.searches_with_match == 1) self.saw_summary = true;
            },
            else => {},
        }
        return .cont;
    }
};

test "API documentation example" {
    const allocator = std.testing.allocator;

    // 1. 单字面量智能大小写切片搜索 (*const Finder) + UTF-16 区间读取
    const finder = try libwebgrep.Finder.init("needle", .{ .case = .smart });
    var recorder = Recorder{};
    const input = "first line\nhello NEEDLE world\nlast line\n";
    const result = try libwebgrep.searchSourceSlice(
        Recorder,
        &recorder,
        "doc-1",
        input,
        &finder,
        .{},
    );
    try std.testing.expectEqual(libwebgrep.Outcome.complete, result.outcome);
    try std.testing.expectEqual(libwebgrep.LimitHit.none, result.limit_hit);
    try std.testing.expect(!result.partial);
    try std.testing.expect(result.soft_error == null);
    try std.testing.expect(recorder.saw_begin);
    try std.testing.expect(recorder.saw_end);
    try std.testing.expect(recorder.saw_summary);
    try std.testing.expectEqual(@as(usize, 1), recorder.matched_lines);
    try std.testing.expectEqual(@as(usize, 12), recorder.first_u16_end);

    // 2. 多字面量 OR 文本解析 + pattern_id + 暂停与无状态游标续查
    var many = try libwebgrep.Multi.initFromText(allocator, "WARN\nERROR\n", .{});
    defer many.deinit();
    var paged_sink = Recorder{ .pause_after_first = true };
    const log_slice = "WARN: disk 80%\nINFO: ok\nERROR: timeout\n";
    const first_page = try libwebgrep.searchSourceSlice(
        Recorder,
        &paged_sink,
        "log-1",
        log_slice,
        &many,
        .{},
    );
    try std.testing.expect(first_page.paused);
    try std.testing.expectEqual(@as(usize, 1), paged_sink.matched_lines);
    try std.testing.expectEqual(@as(u32, 0), paged_sink.last_pattern_id);

    paged_sink.pause_after_first = false;
    const second_page = try libwebgrep.resumeSourceSlice(
        Recorder,
        &paged_sink,
        "log-1",
        log_slice,
        &many,
        .{},
        first_page,
    );
    try std.testing.expect(!second_page.paused);
    try std.testing.expectEqual(@as(u64, 2), second_page.matched_lines);
    try std.testing.expectEqual(@as(u32, 1), paged_sink.last_pattern_id);

    // 3. 线性时间正则搜索 + RegexSet + 只读替换预览
    var re = try libwebgrep.Regex.init(allocator, "ERR_[0-9]+", .{});
    defer re.deinit();
    var regex_sink = Recorder{};
    _ = try libwebgrep.searchSourceSlice(
        Recorder,
        &regex_sink,
        "regex-1",
        "code=ERR_404 found\n",
        &re,
        .{
            .replacement = "REDACTED",
            .allocator = allocator,
        },
    );
    try std.testing.expectEqualStrings(
        "code=REDACTED found",
        regex_sink.last_replaced[0..regex_sink.last_replaced_len],
    );

    var re_set = try libwebgrep.regex.RegexSet.init(allocator, &.{ "ALPHA", "ERR_[0-9]+" }, .{});
    defer re_set.deinit();
    var set_ids: [4]u32 = undefined;
    try std.testing.expectEqual(@as(usize, 1), re_set.matches("code=ERR_404", &set_ids));
    try std.testing.expectEqual(@as(u32, 1), set_ids[0]);

    // 跨行 (multiline) 字面量与流式搜索
    const ml_finder = try libwebgrep.Finder.init("alpha\nbeta", .{ .multiline = true });
    var ml_sink = Recorder{};
    const ml_res = try libwebgrep.searchSourceSlice(
        Recorder,
        &ml_sink,
        "ml-1",
        "header\nalpha\nbeta\nfooter\n",
        &ml_finder,
        .{ .multiline = true },
    );
    try std.testing.expectEqual(@as(u64, 1), ml_res.matched_lines);

    // 4. 流式 Reader 搜索 + 切片拉式迭代 (SourcePull) + 增量流式拉模式迭代 (ReaderPull)
    var reader = std.Io.Reader.fixed("stream NEEDLE line\n");
    var stream_sink = Recorder{};
    const stream_res = try libwebgrep.searchSource(
        Recorder,
        allocator,
        &stream_sink,
        &reader,
        "stream-1",
        &finder,
        .{},
    );
    try std.testing.expectEqual(@as(u64, 1), stream_res.matched_lines);

    var pull = libwebgrep.openSourcePull(allocator, &finder, "pull-1", "pull NEEDLE\n", .{});
    defer pull.deinit();
    var pull_matches: usize = 0;
    while (try pull.next()) |ev| {
        if (ev.kind == .match) pull_matches += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), pull_matches);

    var pull_reader_in = std.Io.Reader.fixed("chunk NEEDLE 1\nchunk NEEDLE 2\n");
    var rpull = try libwebgrep.searcher.openReaderPull(allocator, &finder, "rpull-1", &pull_reader_in, .{});
    defer rpull.deinit();
    var rpull_matches: usize = 0;
    while (try rpull.next()) |ev| {
        if (ev.kind == .match) rpull_matches += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), rpull_matches);

    // 5. Glob 嵌套花括号展开与忽略大小写匹配
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const globs = try libwebgrep.walk_glob.compileGlobs(
        arena,
        &.{ "*.{zig,{c,h}}", "!generated.c" },
        .{ .case_insensitive = true },
    );
    try std.testing.expect(libwebgrep.walk_glob.matchGlobs(globs, "src/MAIN.ZIG", "MAIN.ZIG", false));
    try std.testing.expect(!libwebgrep.walk_glob.matchGlobs(globs, "src/generated.c", "generated.c", false));

    // 6. 字节偏移行探测、RandomAccess 区间检索、反向尾部检索与 NgramBloom 预筛
    const probed = libwebgrep.probeLineSlice(input, 17, .{}).?;
    try std.testing.expectEqualStrings("hello NEEDLE world", probed.bytes);

    var bloom_filter = try libwebgrep.NgramBloom.init(allocator, .{});
    defer bloom_filter.deinit();
    bloom_filter.addSlice(input);
    try std.testing.expect(bloom_filter.mayContainMatcher(&finder));

    const input_slice: []const u8 = input;
    const ra = libwebgrep.RandomAccess.fromSlice(&input_slice);
    var range_sink = Recorder{};
    const range_res = try libwebgrep.searchSourceRange(
        Recorder,
        allocator,
        &range_sink,
        ra,
        .{ .start = 11, .end = 30 },
        "range-1",
        &finder,
        .{ .initial_line_number = 2 },
    );
    try std.testing.expectEqual(@as(u64, 1), range_res.matched_lines);

    var rev_sink = Recorder{};
    const rev_res = try libwebgrep.searchSourceReverseSlice(
        Recorder,
        &rev_sink,
        "rev-1",
        log_slice,
        &many,
        .{ .max_count = 1 },
    );
    try std.testing.expectEqual(@as(u64, 1), rev_res.matched_lines);
    try std.testing.expectEqual(@as(u32, 1), rev_sink.last_pattern_id);
}
```
