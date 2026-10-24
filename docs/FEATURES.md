# libwebgrep 功能全景与边界规范

`libwebgrep` 是使用纯 Zig 0.17 编写的高性能、可嵌入服务端文本搜索引擎库，专为公开 Web 服务、日志检索与代码搜索设计。本库面向一切可流式读取的文本来源，提供确定性的线性时间复杂度与多租户资源配额保护，不包含任何终端 CLI 负担。

---

## 一、功能状态总览

| 领域 | 已完成 (DONE) | 部分完成 (PARTIAL) | 待实现 (TODO) | 明确禁止/不做 |
| :--- | :---: | :---: | :---: | :---: |
| **输入与来源** | 5 (`A01`–`A05`) | 0 | 0 | 2 (`A06`, `A07`) |
| **匹配语义与内核** | 17 (`B01`–`B17`) | 0 | 0 | 1 (`B18`) |
| **行处理与编码** | 8 (`C01`–`C08`) | 0 | 0 | 0 |
| **二进制检测** | 3 (`D01`–`D03`) | 0 | 0 | 0 |
| **上下文管理** | 6 (`E01`–`E06`) | 0 | 0 | 0 |
| **位置与事件结果** | 12 (`F01`–`F12`) | 0 | 0 | 0 |
| **输出模式与统计** | 9 (`G01`–`G09`) | 0 | 0 | 0 |
| **事件流控与回调** | 5 (`H01`–`H05`) | 0 | 0 | 0 |
| **多租户预算与安全** | 12 (`I01`–`I12`) | 0 | 0 | 0 |
| **多来源管线与过滤** | 15 (`J01`–`J15`) | 0 | 0 | 1 (`J16`) |
| **呈现边界与 CLI 剥离** | 4 (`L01`–`L04`) | 0 | 0 | 6 (`K01`–`K06`) |

---

## 二、已具备的核心能力（MVP 全量闭环 + 高性能多模式内核）

### 1. 纯流式来源与零路径输入（`src/root.zig`, `src/searcher.zig`）
- **抽象来源模型（`A01`, `A02`）**：服务入口（`searchSource`、`searchSourceSlice`、`resumeSourceSlice`、`openSourcePull`）仅接收 `std.Io.Reader` 或内存切片以及调用方分配的 `source_id`，不接受任何文件系统路径，从根源上消除路径穿越（CWE-22）。
- **不可回退流式处理（`C07`）**：完全不依赖 `seek` 或 `mmap`，自动处理跨块边界的未完成行与跨块匹配。

### 2. 高性能 SIMD 查找内核（`src/finder/`）
- **单字节扫描（`memchr.zig`）**：16/32 字节向量化 `find`、`findEither`、`findAny`、`findLast` 及 `u8` 水平向量累加 `count`（50～63 GB/s）。
- **单字面量查找（`B01`, `B03`, `B04`）**：
  - `packed_pair.zig`：基于字符频率表挑选最稀有两个锚点字节，4 窗口合并单次归约；ASCII 忽略大小写采用无分支位或 `(block | 0x20) == lower`（敏感 42 GB/s、忽略大小写 25 GB/s）。
  - `two_way.zig`：当高频字节导致预过滤假阳性超阈值时，自动切换至最坏 $O(n)$ 线性时间的 Two-Way 算法。
- **多模式 OR 引擎矩阵（`B02`, `B06`, `B15`, `I07`）**：
  - 构造前严格校验模式条数上限（硬顶 1024）与字节总长上限（硬顶 256 KiB）。
  - 智能大小写（`smart`）按**每条模式独立判断**（全小写才折叠，含大写则敏感）。
  - 按模式特征自动调度四级引擎，且全部支持单遍融合 NUL 检测（`findWatchingNul`）：
    1. `byteset.zig`：全单字节模式（`<= 16` 种折叠后字节），4 路 SIMD 广播比较（~34 GB/s）。
    2. `pairs.zig`：稀有邻接字节对预过滤，`<= 2` 对时走两阶段直接向量比较，`<= 8` 桶时走移位哈希（~31 GB/s）。
    3. `teddy.zig`：`<= 32` 条模式时采用单组 8 桶 Slim Teddy 半字节 SIMD 查表（`vtbl`/`pshufb`/`vpshufb`）+ 两阶段指纹过滤（~24 GB/s）。
    4. `aho.zig`：字节等价类压缩的 Aho-Corasick 稠密 DFA + 初始状态（`state == 0`）高半字节分桶位图 64B SIMD 跳步（~24 GB/s）。
- **线性时间正则引擎与有界跨行（`B16`, `B17`）**：
  - `regex.zig`：无回溯 Thompson NFA / PikeVM，每个输入字节上每条 NFA 指令最多激活一次，最坏时间复杂度严格为 $O(n)$；内置编译指令数服务端硬顶（4096），超限在扫描前返回 `RegexTooLarge`。
  - 自动提取必需字面量（`RequiredLiteral`）并挂载 SIMD `Finder` 前置/尾随双预过滤；跨行匹配（`multiline`）严格限制在有界窗口（`max_multiline_window`）内，窗口耗尽立即判定失配并停止无效上游读取。

### 3. 行级匹配语义（`src/searcher.zig`）
- **半边界整词匹配（`B07`）**：仅校验匹配外侧紧邻字节是否为单词字符（`[0-9A-Za-z_]`），支持如 `-2` 在 `(-2)` 中命中。
- **整行匹配与 CRLF 剥离（`B08`, `C01`, `C02`）**：默认 LF 分行，自动剥离行尾紧邻的 `\r`；整行开启时优先于整词。
- **反选与链式过滤（`B09`, `B12`）**：支持按行反选（`invert`），以及对同一行施加多条 `contains`（AND）与 `excludes`（NOT）链式过滤。
- **提前终止模式（`B10`, `B11`, `B13`, `G04`, `G05`）**：支持单来源匹配行数上限（`max_count`）、存在性查询（`exists`，首条命中即停并关闭上游）、无匹配来源筛选（`files_without_match`）、有序输入首条不匹配即停（`stop_on_nonmatch`）。
- **模式文本与只读替换预览（`A03`, `B14`）**：支持 `Multi.initFromText` 按行解析多模式文本（空行匹配所有行，构造前校验条数与字节上限）；支持 `SearchConfig.replacement` 只读替换预览（产出 `Span.replacement` 与 `Line.replaced` / `LineEvent.replaced`，不修改原输入）。

### 4. 超长行窗口、二进制与有界上下文（`src/searcher.zig`, `src/encoding.zig`）
- **恒定内存超长行滑窗（`C08`, `D03`）**：超出 `max_line_len` 的超长行继续流式扫描，仅保留匹配附近的预览窗口交出，标记 `truncated = true` 并给出精确的原始行长与窗口偏移。
- **单遍融合二进制检测（`D01`, `D02`, `F08`）**：以 NUL 字节启发式检测二进制，将 NUL 扫描并入 SIMD 查找快循环；支持 `quit`（默认跳过）、`report`（搜索但不交出行内容）、`text`（按文本处理）三种策略，并产出 `binary_offset` 与 `binary_status`。
- **有界流式上下文与全文高亮（`E01`–`E06`）**：前置上下文采用固定上限的环形缓冲（不依赖 `seek`），后置上下文采用计数器，相邻片段自动合并，非连续处发出结构化 `context_break` 事件；支持 `passthru` 全文高亮模式，输出全部行并受 `max_output_bytes` 约束。
- **BOM 嗅探、扩展编码、流式防爆解压与原始偏移（`A04`, `A05`, `B05`, `C03`–`C06`, `F01`–`F06`, `F12`）**：
  - 支持 NUL 记录模式；`auto` 模式下嗅探 UTF-8 / UTF-16LE / UTF-16BE BOM，并支持通过 `charset`（WHATWG 标签或 HTTP `Content-Type`）转码 GBK / GB2312 / Latin-1；
  - 支持进程内 Gzip / Zstd / XZ 流式解压，配备 `max_decompressed_bytes` 与 `max_compression_ratio` 双重防爆拦截（拦截 Zip Bomb），损坏流归入 `SoftError.read_failed`；
  - 支持 `unicode_case` Unicode 简单大小写折叠（按单条模式智能大小写展开进 SIMD 多模式引擎）；
  - 扫描时一次算出 `u16_start`、`u16_end`、`u16_column`，并通过 `OffsetMap` 在转码/解压后精确给出原始字节流偏移 `raw_offset`。

### 5. 事件流控、游标续查与多租户安全配额（`src/sink.zig`, `src/searcher.zig`）
- **结构化事件流（`G01`–`G09`, `H01`–`H05`）**：逐条回调 `begin`、`match`、`context`、`context_break`、`progress`、`heartbeat`、`end`、`summary`；支持 `Flow.pause` 背压暂停与 `resumeSourceSlice` 游标续查；支持实时流（`live`）空闲心跳。
- **多租户硬顶预算（`F10`, `F11`, `I01`–`I12`, `J10`）**：
  - 扫描字节上限（`max_source_bytes` / `max_request_bytes`）
  - 纳秒级单调时钟时间预算（`time_budget_ns`，读取与匹配双循环检查）
  - 原子取消令牌（`cancel`，断开即停并关闭上游）
  - 请求级最大结果数（`max_results`，附带 `resume_at` 续查偏移）
  - 输出字节上限（`max_output_bytes`）与三大内存缓冲硬顶（`max_before_bytes`、`max_decode_bytes`、`max_queued_event_bytes`）
- **三态错误分离（`I09`, `I10`）**：严格区分「无匹配」、「单来源软错误（`SoftError.read_failed`）」与「致命错误」；返回给调用方的错误绝不包含服务器内部路径，内部细节仅走服务端 `log` 钩子。

### 6. 受控多来源过滤与并发管线（`src/walk/`, `src/parallel.zig`）
- **完备 Glob 与嵌套花括号（`J01`, `J02`）**：支持嵌套花括号 `{a,{b,c}}` 展开、后写规则优先与 `!` 否定过滤、ASCII 忽略大小写匹配（`iglob` / `case_insensitive`），内置规则条数（1024）、单条长度（4096）与嵌套深度（8）服务端硬顶。
- **细粒度 Ignore 规则与纯文本注入（`J03`–`J08`）**：支持无 `.git` 目录时读取 `.gitignore`、`.ignore`、`.rgignore` 并按层级与后写优先覆盖；支持内存纯文本规则注入（`ignore_texts`，不收路径）及 `dot`/`vcs`/`exclude`/`case_insensitive` 独立细分开关；严格不读父目录与全局配置。
- **注入式类型过滤、遍历预算与受控并发（`J09`, `J11`–`J15`, `L04`）**：
  - 支持调用方注入自定义文件类型表并展开为 Glob（`expandTypesToGlobs` / `matchesWithTable`）；
  - 内置服务端最大遍历深度硬顶（`max_depth_hard_cap = 64`）与最大遍历条数预算（`max_entries`）；仅列出来源模式（`files_only`）同样计入遍历与结果预算；
  - 彻底移除宿主 CPU 核数探测，工作线程数完全由调用方 `max_concurrency` / `threads` 决定并受硬顶约束；多来源边搜边流式交出 `begin`/`match`/`end` 事件，绝不为排序缓存全量事件。

---

## 三、阶段演进闭环状态（N0～N11 全部完成）

| 阶段 | 覆盖节点 | 核心能力 | 当前状态 |
| :--- | :--- | :--- | :---: |
| **基线与多模式内核** | N0～N7, N11, P2 | 纯流式零路径入口、SIMD 单/多模式查找内核、有界上下文与多租户硬顶预算 | **DONE** |
| **阶段一** | N9-Lite (`A03`, `B13`, `E06`, `B14`) | 模式列表文本解析、有序流提前停止、全文高亮（`passthru`）、只读替换预览 | **DONE** |
| **阶段二** | N10 (`B16`, `B17`) | 线性时间 Thompson NFA 正则引擎、`RequiredLiteral` SIMD 预过滤、有界跨行匹配 | **DONE** |
| **阶段三** | N9-Stream (`A04`, `A05`, `B05`, `C06`, `F12`) | 进程内 Gzip/Zstd/XZ 流式防爆解压、Unicode 简单大小写折叠、GBK/Latin-1 与 `raw_offset` | **DONE** |
| **阶段四** | N8 (`J01`–`J15`, `L04`) | Glob 嵌套花括号与上限、纯文本 Ignore 与细分开关、受控并发与流式多来源收口 | **DONE** |

---

## 四、安全红线与不做边界（架构铁律）

### 1. 安全红线（`[禁止]`，绝不引入）
- **`A06` / `A07` / `K02` 禁止外部进程**：库内绝不调用 `execve`、`posix.spawn`、`ChildProcess` 或任何外部命令/外部解压程序。
- **`B18` 禁止回溯正则与 PCRE2**：绝不引入指数级回溯的正则实现或 PCRE2 绑定，彻底杜绝正则拒绝服务（ReDoS）。
- **`J16` / `A01` 禁止路径穿越与符号链接跟随**：公共搜索入口绝不接受客户端路径；目录遍历绝不跟随符号链接（`follow_symlinks` 永久移除），绝不读取搜索根之上的父目录规则或全局配置（`J06`, `J07`）。

### 2. 职责边界（`[不做]`，保持 Core 纯粹）
- **`K01` / `L01` 不做终端染色与 HTML 拼接**：Core 只返回精确的半开字节区间与 UTF-16 区间，高亮渲染由调用方完成。
- **`K03`–`K06` 不做终端排版与 CLI 参数**：不包含 `--pretty`、`--vimgrep`、命令行帮助、shell 补全、分页器或向 `stderr` 打印文本。
- **`H05` / `L04` 不在 Core 内耦合序列化与全量排序缓冲**：事件结构可直接无损映射为 NDJSON，但编码由传输层完成；Core 绝不为了排序而在内存中积压全部搜索结果。
