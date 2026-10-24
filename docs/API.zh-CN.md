# libwebgrep API 调用参考手册

[English](API.md) | [简体中文](API.zh-CN.md)

本文档完整说明 `src/root.zig` 导出的全部公共类型、函数与子模块。在代码中通过 `@import("libwebgrep")` 导入模块后，即可使用以下所有接口。

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
| **`resumeSourceSlice`** | `[]const u8` + `Result` | **是**（留空字段自动填默认预算） | 推式回调（`Event`） | 从上次 `Flow.pause` 的字节偏移无缝续查，不重复发 `begin` |
| **`openSourcePull`** | `[]const u8` | **是**（留空字段自动填默认预算） | 拉式迭代（`SourcePull.next()`） | 将事件切片深拷贝至 `allocator`，生命周期持续到 `pull.deinit()` |
| **`searchSlice`** | `[]const u8` | 否（留空表示不另设上限） | 旧版方法回调（`Line`） | 无需转码/解压时零堆内存分配 |
| **`searchReader`** | `*std.Io.Reader` | 否（留空表示不另设上限） | 旧版方法回调（`Line`） | 分配滚动读缓冲 |

所有搜索入口的 `matcher` 参数均可传入：
- `*libwebgrep.Finder`（单字面量 SIMD 查找器）
- `*libwebgrep.Multi`（多字面量 OR 自动分级引擎）
- `*libwebgrep.Regex`（线性时间 Thompson NFA 正则引擎）

### 服务入口回调签名（`S.event`）

传给 `searchSourceSlice`、`searchSource`、`resumeSourceSlice` 的接收器类型 `S` 只需实现：

```zig
pub fn event(self: *S, ev: libwebgrep.Event) libwebgrep.Flow // 或返回 bool
```

- 返回 `true` 或 `Flow.cont`：继续扫描后续内容。
- 返回 `false` 或 `Flow.stop`：立即停止当前来源，之后仍会收到 `end` 事件。
- 返回 `Flow.pause`：立即暂停当前来源（不发送 `end` 与 `summary`），返回的 `Result.paused` 为 `true`；将该 `Result` 传给 `resumeSourceSlice` 即可从暂停处继续扫描。

> **生命周期注意**：回调期间收到的 `LineEvent` 上的切片（`bytes`、`text`、`raw`、`replaced`、`matches`）仅在本次 `event` 回调返回前有效。若需在回调返回后保留，请在回调内拷贝，或使用 `openSourcePull`。

---

## 三、匹配器（Matchers）

### 1. `Finder`（单字面量 SIMD 查找器）

```zig
pub fn init(pattern: []const u8, options: FindOptions) !Finder
pub fn find(self: *Finder, haystack: []const u8, start: usize, mode: MatchMode) ?Match
pub fn findWatched(self: *Finder, haystack: []const u8, start: usize, mode: MatchMode, nul_at: *?usize) ?Match
pub fn acceptsSpan(self: *const Finder, span: []const u8) bool
pub fn requiredLiteral(self: *const Finder) ?RequiredLiteral
pub fn resetStats(self: *Finder) void
```

- **零堆内存分配**：`pattern` 切片由调用方持有，没有 `deinit`。
- 模式中不能包含 `\n`（否则返回 `error.PatternHasNewline`）；空模式 `""` 产生零宽匹配 `[0, 0)`。
- 内部采用基于字符频率表的 `PackedPair` 4 窗口合并 SIMD 过滤（42.6 GB/s），并在长模式假阳性超阈值时自动切换为最坏 $O(n)$ 的 Crochemore-Perrin `TwoWay` 算法。

### 2. `Multi`（多字面量 OR 引擎矩阵）

```zig
pub fn init(allocator: std.mem.Allocator, patterns: []const []const u8, options: FindOptions) !Multi
pub fn initFromText(allocator: std.mem.Allocator, text: []const u8, options: FindOptions) !Multi
pub fn deinit(self: *Multi) void
pub fn find(self: *Multi, haystack: []const u8, start: usize, mode: MatchMode) ?Match
```

- **构造前硬顶保护**：模式条数硬顶 `1024`（`pattern_count_hard_cap`），总字节硬顶 `256 KiB`（`pattern_bytes_hard_cap`），超限在分配表之前返回 `error.PatternCountExceeded` 或 `error.PatternBytesExceeded`。
- **按单条模式智能大小写（`CaseMode.smart`）**：每条模式独立判断（全小写才忽略大小写，含大写则区分大小写）。设置 `FindOptions.unicode_case = true` 时启用 Unicode 简单大小写折叠（Simple Case Folding）。
- **四级自动加速**：按模式特征自动选择 `ByteSet`（34.2 GB/s）→ `RarePair`（32.2 GB/s）→ `Teddy`（24.1 GB/s）→ `AhoCorasick`（稠密 DFA + 64B 高半字节 SIMD 跳步，24.3 GB/s）。构造完成后只读，可安全在多线程间共享。

### 3. `Regex`（线性时间正则表达式引擎）

```zig
pub fn init(allocator: std.mem.Allocator, pattern: []const u8, options: RegexOptions) !Regex
pub fn deinit(self: *Regex) void
pub fn find(self: *Regex, haystack: []const u8, start: usize, mode: MatchMode) ?Match
```

- **语法支持**：字符类 `[a-z0-9_]` / `[^...]`、预定义类 `\d` `\D` `\w` `\W` `\s` `\S`、通配符 `.`、行/流锚点 `^` `$`、量词 `*` `+` `?` `{m}` `{m,}` `{m,n}`、交替 `a|b` 与分组 `(...)` / `(?:...)`。
- **绝对防 ReDoS**：采用锁步 Thompson NFA / PikeVM 执行，每个输入字节上每条指令最多激活 1 次，最坏时间复杂度严格为 $O(n)$；内置编译指令数硬顶 `4096`，超限返回 `error.RegexTooLarge`。
- **SIMD 字面量双预过滤**：自动从 AST 提取必需的前缀与尾随字面量（`RequiredLiteral`）并挂载 `Finder` 做 42.9 GB/s SIMD 预过滤。
- **有界窗口跨行（`RegexOptions.multiline`）**：跨行跨度严格限制在 `max_multiline_window`（默认 `64 KiB`，硬顶 `8 MiB`）内，窗口耗尽仍未闭合匹配时立即判定失配。

---

## 四、`SearchConfig` 完整配置表

| 字段名 | 类型 | 结构体默认值 | 服务入口默认值 / 服务端硬顶 | 功能说明 |
| :--- | :--- | :--- | :--- | :--- |
| `line_numbers` | `bool` | `false` | 服务入口强制 `true` | 是否计算从 1 开始的行号 |
| `invert` | `bool` | `false` | `false` | 按行反选（交出不匹配的行） |
| `whole_word` | `bool` | `false` | `false` | 半边界整词匹配（校验匹配外侧紧邻字节是否为 `[0-9A-Za-z_]`） |
| `whole_line` | `bool` | `false` | `false` | 整行匹配（优先于 `whole_word`） |
| `contains` | `[]const []const u8` | `&.{}` | `&.{}` | 链式包含过滤（AND：行内必须同时包含全部所列字节串） |
| `excludes` | `[]const []const u8` | `&.{}` | `&.{}` | 链式排除过滤（NOT：行内不得包含任一所列字节串） |
| `context` | `u32` | `0` | 硬顶 `10` 行 | 对称的前后上下文行数 |
| `before` / `after` | `?u32` | `null` | 硬顶 `10` 行 | 单独指定前置 / 后置上下文行数 |
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
| `encoding` | `Encoding` | `.auto` | `.auto` | 编码处理：`.auto`（嗅探 BOM 或用 `charset`）、`.utf8`、`.utf16le/be`、`.gbk`、`.latin1`、`.none` |
| `charset` | `?[]const u8` | `null` | `null` | WHATWG 标签或 HTTP `Content-Type` 字符集提示（如 `"gbk"`） |
| `compression` | `Compression` | `.none` | `.none` | 进程内流式解压：`.none`、`.auto`（魔数识别）、`.gzip`、`.zstd`、`.xz` |
| `max_compression_ratio` | `?u64` | `null` | 默认 `100`，硬顶 `1000` | 最大允许解压膨胀比（拦截压缩炸弹） |
| `max_decompressed_bytes` | `?u64` | `null` | 开启解压时默认 `64 MiB` | 最大解压产出字节上限（超限记为 `LimitHit.decompressed_bytes`） |
| `decode_allocator` | `?Allocator` | `null` | `null` | 切片入口在需要转码/解压/生成替换预览时使用的分配器 |
| `buffer_size` | `usize` | `1 MiB` | `1 MiB` | 流式读取滚动缓冲区大小 |
| `max_line_len` | `usize` | `2 MiB` | 硬顶 `8 MiB` | 单行最大长度上限（超长行进入恒定内存滑窗预览） |
| `match_mode` | `MatchMode` | `.earliest` | `.earliest` | `.earliest`（最早结束优先）或 `.leftmost_first`（最左起点优先） |
| `scratch` | `?*[]u8` | `null` | `null` | 供 `searchSource` / `searchReader` 跨调用复用的缓冲区指针 |
| `max_source_bytes` | `?u64` | `null` | 默认 `16 MiB`，硬顶 `64 MiB` | 单个来源最大扫描字节预算 |
| `max_request_bytes` | `?u64` | `null` | 默认 `16 MiB`，硬顶 `64 MiB` | 单次请求最大扫描字节预算 |
| `max_output_bytes` | `?u64` | `null` | 默认 `1 MiB`，硬顶 `8 MiB` | 行事件累计输出字节上限 |
| `time_budget_ns` | `?u64` | `null` | 默认 `30s`，硬顶 `120s` | 纳秒级单调时钟超时预算（`LimitHit.deadline`） |
| `cancel` | `?*const Atomic(bool)` | `null` | `null` | 原子取消令牌（置真后立即停止并触发 `LimitHit.cancelled`） |

---

## 五、事件与返回结果结构

### 1. `LineEvent`（行事件）
- `source_id: []const u8`：调用方传入的来源 ID。
- `line_number: u64`：1 起始行号（`null_data` 模式下为记录号）。
- `column: ?u64` / `u16_column: ?u64`：1 起始的字节列号与 UTF-16 码元列号。
- `absolute_offset: u64`：行起点在可搜索 UTF-8 流中的 0 起始字节偏移。
- `raw_offset: u64`：行起点在转码或解压前原始字节流中的 0 起始偏移（由 `OffsetMap` 映射）。
- `bytes: []const u8` / `text: []const u8` / `raw: []const u8`：行字节切片与有损 UTF-8 文本切片。
- `replaced: ?[]const u8`：配置了 `SearchConfig.replacement` 时的只读整行替换预览切片。
- `matches: []const Span`：不重叠、按起点升序排列的半开区间数组（含 `start`、`end`、`u16_start`、`u16_end`、`replacement`）。
- `truncated: bool` / `line_len: u64` / `window_start: u64`：超长行窗口截断标记、原始行长与窗口起点偏移。

### 2. `Result`（搜索返回值）与三态错误分离
- **无匹配**：函数正常返回 `Result`，`soft_error == null` 且 `matched_lines == 0`，`begin` 和 `end` 事件照常发出。
- **单来源软错误**：上游读取失败或压缩流损坏时，函数仍正常返回 `Result`，`soft_error == .read_failed`（不含任何服务器内部路径）。
- **致命错误**：配置超硬顶（`error.BudgetExceeded`）、上下文超限（`error.ContextLinesExceeded`）或内存不足（`error.OutOfMemory`）通过 Zig 错误联合直接返回。

---

## 六、来源过滤辅助模块（`walk_*`）

- **`walk_glob`（`src/walk/glob.zig`）**：支持 `*`、`?`、`**`、字符类 `[a-z]`、`!` 否定、嵌套花括号 `{a,{b,c}}` 展开（`expandBraces`、`compileGlobs`）、忽略大小写匹配（`classifyWithCase`、`matchTextCase`）与后写规则优先裁决（`matchGlobs`），内置条数硬顶（`1024`）、长度硬顶（`4096`）与花括号深度硬顶（`8`）。
- **`walk_ignore`（`src/walk/ignore.zig`）**：解析内存中的 `.gitignore` / `.ignore` / `.rgignore` 规则文本（`parseInto`、`parseTextsInto`、`parseLayerInto`），支持 `dot` / `vcs` / `exclude` / `case_insensitive` 细分开关。
- **`walk_types`（`src/walk/types.zig`）**：支持内置类型表（`zig`、`rust`、`py`、`ts` 等）与调用方自定义类型表注入及展开为 Glob（`expandTypesToGlobs`、`matchesWithTable`）。

---

## 七、全场景实战代码示例

以下代码块完整演示了 5 个高频实战场景，并且其英文对应版本由 `build.zig` 自动抽取作为 `api-doc-example` 单元测试编译执行：
1. **单字面量智能大小写搜索与 UTF-16 码元区间读取**（`searchSourceSlice`）
2. **多模式文本解析（`Multi.initFromText`）与无状态分页暂停/续查**（`Flow.pause` + `resumeSourceSlice`）
3. **线性时间正则匹配（`Regex`）与只读替换预览**（`SearchConfig.replacement`）
4. **流式 `*std.Io.Reader` 搜索（`searchSource`）与拉式事件迭代器（`openSourcePull`）**
5. **Glob 嵌套花括号展开与忽略大小写过滤**（`walk_glob.compileGlobs` + `matchGlobs`）

```zig
const std = @import("std");
const libwebgrep = @import("libwebgrep");

const Recorder = struct {
    saw_begin: bool = false,
    saw_end: bool = false,
    saw_summary: bool = false,
    matched_lines: usize = 0,
    first_u16_end: usize = 0,
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

    // 1. 单字面量智能大小写切片搜索 + UTF-16 区间读取
    var finder = try libwebgrep.Finder.init("needle", .{ .case = .smart });
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

    // 2. 多字面量 OR 文本解析 + 暂停与无状态游标续查
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

    // 3. 线性时间正则搜索 + 只读替换预览
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
            .decode_allocator = allocator,
        },
    );
    try std.testing.expectEqualStrings(
        "code=REDACTED found",
        regex_sink.last_replaced[0..regex_sink.last_replaced_len],
    );

    // 4. 流式 Reader 搜索 + 拉式事件迭代器（SourcePull）
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
}
```
