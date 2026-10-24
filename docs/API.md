# libwebgrep 调用说明

读者只看这份文档就能调用库。它描述 `src/root.zig` 当前导出的全部公共声明。模块根是 `src/root.zig`。示例里把这个模块导入为 `libwebgrep`。

库搜索调用方给出的流。会分配的入口接收调用方的分配器。没有全局可变状态。

## 范围

库搜索调用方给出的流。调用方提供字节和来源 ID，库通过回调或拉式迭代交出事件。不接收文件系统路径，不执行外部命令，不输出终端文本或 NDJSON。颜色、分页和编码成 NDJSON 都由调用方自己做。库只给出匹配区间。

下面「尚未提供」一节里的能力现在不能调用。

## 入口

服务入口是 `searchSourceSlice`、`searchSource`、`resumeSourceSlice`、`openSourcePull`。它们强制打开行号，并在调用方留空时填上扫描字节、时间和输出字节等默认预算。留空不能关掉这些预算。大于硬顶时返回 `BudgetExceeded`，搜索还没有开始扫输入。

旧回调入口是 `searchSlice` 和 `searchReader`。它们不填那些默认预算，留空表示该项不另加上限。回调形状是 `begin`、`matched`、`context`、`finish`，不是服务入口的 `event`。新代码用服务入口。

匹配器传 `*Finder`、`*Multi` 或 `*Regex`。搜索函数在开始时调用它的 `resetStats`。

服务入口的接收者 `S` 实现：

```text
pub fn event(self: *S, ev: Event) bool
```

返回 `Flow` 也可以。`true` 或 `Flow.cont` 继续。`false` 或 `Flow.stop` 停止，之后仍会收到 `end`。`Flow.pause` 暂停：没有 `end`，没有 `summary`，`Result.paused` 为真。用 `resumeSourceSlice` 从同一次暂停继续，不再发 `begin`。

每个事件产生就调用一次，不把多行攒起来。`summary` 的返回值被忽略。行上的 `bytes`、`text`、`raw`、`matches` 只在这次回调返回前有效。

### searchSourceSlice

```text
searchSourceSlice(S, sink, source_id, haystack, matcher, config) SliceError!Result
```

在内存切片上搜索一个来源。不接收分配器参数。没有 BOM 时不分配。出现 BOM 且需要转码时必须设置 `SearchConfig.decode_allocator`，否则返回 `OutOfMemory`。库在返回前释放这次自己分配的转码缓冲。

`source_id` 和 `haystack` 由调用方持有，库不释放。`source_id` 会原样出现在事件里，必须活过整个调用。

成功返回 `Result`。读失败不是这个入口的情况，它没有上游。软错误字段留空。致命错误是 `SliceError`：`ContextLinesExceeded`、`OutOfMemory`、`DecodeLimit`、`BufferLimit`、`BudgetExceeded`。

扫完、没有暂停、并且不是仍开着的实时流时，最后再回调一次 `summary`。

### searchSource

```text
searchSource(S, allocator, sink, reader, source_id, matcher, config) ReadError!Result
```

从 `*std.Io.Reader` 搜索。`allocator` 由调用方提供。库用它分配读缓冲、解码缓冲和前置上下文，返回前释放。`SearchConfig.scratch` 不是 null 时改为复用这块缓冲：不够就 `realloc`，把新切片写回指针，由调用方最终释放。

没有把输入标成实时流时，短读就是结束，不是错误。库不关闭 `reader`。提前停止时如果设置了 `close_input`，库调用它，由调用方关上游。正常读到结束不调用 `close_input`。

上游读失败时函数仍然成功返回，`Result.soft_error` 为 `read_failed`，并照常发 `end`。错误值里没有内部路径。分配失败和解码超限仍作为错误返回。`ReadError` 的类型里还包含 `ReadFailed` 以及文件读取错误，当前读取循环把上游失败收成软错误。

其余和 `searchSourceSlice` 相同：服务默认预算、行号、`event`、`summary` 的条件。

### resumeSourceSlice

```text
resumeSourceSlice(S, sink, source_id, haystack, matcher, config, previous) SliceError!Result
```

从上次暂停继续搜同一段内存。`previous` 必须是同一次搜索返回的、`paused` 为真的 `Result`。它把 `resume_from` 设成 `previous.resume_at`（null 时从 0），并恢复计数。不再发 `begin`。分配和错误与 `searchSourceSlice` 相同。调用方继续持有 `source_id`、`haystack` 和匹配器。

### openSourcePull

```text
openSourcePull(allocator, matcher, source_id, haystack, config) SourcePull
```

拉式接口，类型是 `searcher.SourcePull`。构造不返回错误。第一次 `next` 才运行 `searchSourceSlice`，把事件复制进 `allocator`。`next` 返回 `!?PullEvent`，没有更多事件时是 null。`PullEvent` 定义在 `searcher` 模块里。

复制出来的 `source_id`、`bytes`、`spans` 活到 `SourcePull.deinit`。`deinit` 会释放已经由 `next` 交出去的事件。不要再对那些事件单独 `deinit`。

拉式副本只保留一部分字段：

- `begin`、`context_break`：来源 ID。
- `match`、`context`：来源 ID、行号、字节列、绝对偏移、行字节、`spans`。这里的 `matches` 是这一行的区间个数，不是来源累计匹配次数。不复制 `text`、`raw`、截断字段、`u16_column`、二进制状态。区间结构体本身带有 UTF-16 半开端点。
- `progress`、`heartbeat`：来源 ID、已扫描字节、累计匹配次数、累计匹配行数。
- `end`：来源 ID、匹配行数、累计匹配次数。不复制 `limit_hit`、`partial`、`soft_error`、`outcome`、`binary_offset`。
- `summary`：来源 ID 和汇总计数，包括 `elapsed`、`sources_failed`。

要看预算、软错误、截断或有损文本，用回调入口。

### searchSlice

```text
searchSlice(S, sink, haystack, name, matcher, config) SliceError!Result
```

旧回调入口。不填服务默认预算，不把 `name` 当成来源 ID。`name` 只传给旧的 `begin`。不强制行号。没有 `event` 回调时什么行都不交。服务入口是 `searchSourceSlice`。

`S` 可以提供这些方法，缺的就跳过。返回 false 表示停止：

- `begin(self, name: []const u8) bool`
- `matched(self, line: Line) bool`
- `context(self, line: Line) bool`
- `contextBreak(self) bool`
- `binary(self, offset: u64) bool`
- `finish(self, result: Result) bool`
- `progress(self, bytes_searched: u64, matches: u64, matched_lines: u64) bool`
- `heartbeat` 与 `progress` 同一组参数

`Line` 上的切片只在这次方法返回前有效。错误集与 `searchSourceSlice` 相同。

### searchReader

```text
searchReader(S, allocator, sink, reader, name, matcher, config) ReadError!Result
```

旧回调入口，从 `*std.Io.Reader` 读。分配和释放与 `searchSource` 相同，但不填服务默认预算，`name` 只传给旧的 `begin`。短读视为结束。服务入口是 `searchSource`。

### Flow

回调对服务入口的控制。`cont` 继续，`pause` 暂停并留下续查状态，`stop` 停止并仍然结束这个来源。旧入口只看 bool，没有暂停。

### AnySink

运行时多态的旧回调。字段是 `ctx: *anyopaque` 和 `vtable: *const AnySink.VTable`。虚表必须活得比 `AnySink` 久。方法 `begin`、`matched`、`context`、`contextBreak`、`binary`、`finish` 转发到虚表。可以直接把它传给 `searchSlice` 或 `searchReader`。它不实现服务入口的 `event`。

`begin` 的字节参数是旧入口传来的名字，由调用方持有。

### anyVtable

```text
anyVtable(S) AnySink.VTable
```

为类型 `S` 生成虚表。某个方法不存在时，对应槽位保持继续搜索。方法必须是 `pub`，返回 `bool`。返回值是结构体，调用方要把它存在活得够久的地方，再把指针放进 `AnySink`。不分配。

### SliceIter

```text
SliceIter(M)
```

单输入、无上下文的拉式迭代器。`M` 是匹配器指针，例如 `*Finder`。自己填字段：`matcher`、`haystack`、可选 `mode`（默认 `earliest`）、可选 `line_numbers`（默认 false）。`next` 返回 `?Line`。没有来源事件，没有上下文，不看 `SearchConfig`。

`Line.bytes` 指向 `haystack`，一直有效到 `haystack` 失效。下一次 `next` 不使上一次失效。不分配。

## 来源

来源 ID 由调用方分配。库不解释它，不把它看成文件系统里的名字，也不释放它。每个事件都带这一个 ID。

切片只在回调返回前有效。这包括 `bytes`、`text`、`raw`、`matches`，以及事件里的 `source_id`（它指向调用方原来的那份字节）。回调返回后还要使用行内容，就在回调里复制。`openSourcePull` 是例外：它复制出来的切片活到 `SourcePull.deinit`。

未命中的来源也有 begin 和 end。`matched_lines` 为 0，`matches` 为 0，没有 `match` 事件。扫完时还有 `summary`。

多个来源由调用方自己打开流，逐个调用搜索入口。库不接收一组路径。

### source

导出 `src/source.zig`。这是一份内存树接口，供测试和非文件输入使用。搜索入口不接收 `Source`，也不会去打开它。

- `Kind`：`file`、`directory`、`other`。
- `Entry`：`name` 和 `kind`。`name` 指向节点里的字节。
- `VTable`：`open`、`read`、`list`、`close` 四个函数指针。
- `Source`：`ctx` 加虚表。`open` 的名称是树内的名字，返回句柄。`read` 把字节写入调用方的缓冲。`list` 把目录项写入调用方的数组，返回写入的个数。`close` 放开句柄。这些方法都接收 `std.Io`。
- `Node`：`name`、`kind`、`bytes`、`children`。子节点是调用方持有的指针。
- `Memory`：最多 8 个同时打开的句柄，0 不是有效句柄。`source` 方法交出 `Source`。打不开、读到目录、列出文件时返回错误。句柄用完返回 `SystemResources`。

调用方持有节点和字节。`Memory` 不复制它们。

## 匹配

匹配是字面量。多条模式是 OR：任一条命中即可。模式字节里不能有换行，否则 `Finder.init` 或 `Multi.init` 返回 `PatternHasNewline`，扫描还没有开始。空模式是零宽匹配；一行里空模式只留下一个零宽区间。

条数硬顶 1024，全部模式的字节总长硬顶 256 KiB。`FindOptions.max_pattern_count` 和 `max_pattern_bytes` 只能把上限调低。超过硬顶的请求仍按硬顶拒绝。超限时返回 `PatternCountExceeded` 或 `PatternBytesExceeded`，表还没有分配。

大小写默认敏感。`insensitive` 忽略大小写。默认情况下大小写折叠只支持 ASCII，也就是 `A-Z` 与 `a-z`；当 `FindOptions.unicode_case` 设为真时，在 `Multi` 中启用 Unicode 简单大小写折叠（Simple Case Folding）。

智能大小写按模式分别判断。这一条全是小写才忽略大小写，出现大写就对这一条区分大小写。这和 rg 整组判断不同。rg 是整组里出现大写就全部区分大小写。

整词看匹配外侧那个字节是不是 ASCII 单词字符（字母、数字、下划线）。这是半边界：`-2` 能命中 `(-2)`，不能命中 `x-2` 或 `-2y`。和整行同时打开时不检查词边界。

整行在去掉 LF、以及 LF 模式下行尾紧挨着的一个 CR 之后，行内容必须和某一条模式相同。比较使用那一条模式自己的大小写规则。

反选交出不含匹配的行，那些行以 `match` 事件出现。它和「无匹配来源」不是一回事。

`contains` 里的每一条都必须出现在行里，`excludes` 里的每一条都不能出现。比较是原始字节，不折叠大小写。空切片表示不额外要求。这两项和反选可以同时用，语义仍然分开。

`files_without_match` 要的是没有命中的来源。找到第一条匹配就停止这个来源，不把行交出去，并调用 `close_input`。这时 `matched_lines` 会变成 1，但没有 `match` 事件。完全没有命中时 `matched_lines` 保持 0，并且有 begin 和 end。

`exists` 是存在性查询。找到第一条匹配就返回，那一行会作为 `match` 事件交出，并关闭上游。

`stop_on_nonmatch` 用于有序输入（如按时间戳递增的日志流）。在已经出现至少一条匹配行之后，一旦遇到第一条不匹配的行就立即停止读取，并调用 `close_input` 关闭上游。

`replacement` 提供只读替换预览。设置非 null 的模板切片后，库不修改输入缓冲或 `bytes`、`raw`，而是在每个命中的 `Span.replacement` 上填入该切片，并在 `Line.replaced` 与 `LineEvent.replaced` 上给出替换后的整行预览切片（只在本次回调返回前有效）。

`max_count` 是这个来源最多报告多少条匹配行。null 表示不限。达到后不再读后面的块，`outcome` 为 `stopped`，不写 `limit_hit`，也不带 `resume_at`。已经在缓冲里的后置上下文仍会交。后置窗口里被抬成匹配的行不占用这个额度，但仍作为 `match` 事件交出。

`MatchMode.earliest` 取结束位置最早的一次；结束位置相同则起点更靠左，再相同则更早加入的模式。`leftmost_first` 取起点最靠左的一次；同一起点上更早加入的模式胜出，不是更长的那条。单条字面量下两种结果相同。默认 `earliest`。

一行里的区间互不重叠，按起点排序，半开，相对这一行交出的 `bytes`。只显示命中片段时，调用方用这些区间去切 `bytes`。库没有单独的片段输出。

### Finder

单条字面量。

```text
Finder.init(pattern, options) !Finder
```

不分配。`pattern` 由调用方持有，必须活过查找器。没有 `deinit`。错误是 `PatternHasNewline` 或模式条数、总长度超限。

`find(self, haystack, start, mode)` 返回 `?Match`。偏移相对这次传入的 `haystack`。`findWatched` 另外记下扫描范围内第一个 NUL。`acceptsSpan` 判断一段是否整段等于模式。`findAllowed` 在调用方的 `allow` 拒绝当前区间时，从起点的下一字节继续。`requiredLiteral` 在模式非空时返回模式本身，偏移 0。忽略大小写时这些字节仍是原模式。`resetStats` 清掉内部计数。搜索入口每次开始会自己调用它。

### finder

导出 `src/finder/finder.zig`，也就是 `Finder` 的定义模块。调用用根上的 `Finder` 即可。

### Multi

多条字面量，OR。

```text
Multi.init(allocator, patterns, options) !Multi
Multi.initFromText(allocator, text, options) !Multi
Multi.deinit(self)
```

`allocator` 只用于内部表。`Multi.init` 的模式字节和指针数组都由调用方持有，`deinit` 不释放它们。`Multi.initFromText` 按 LF（兼容 CRLF）切分调用方给出的模式列表文本（不接受文件名），其中的空行作为空模式 `""`（匹配所有行），在分配自动机前先校验条数与字节总长上限；`text` 字节由调用方持有，切分出的模式切片数组由 `deinit` 释放。只有创建者调用 `deinit`。复制结构体只复制指针，建好之后表只读，可以共享给别的调用者去 `find`。

错误是 `PatternHasNewline`、`PatternCountExceeded`、`PatternBytesExceeded`、`OutOfMemory`。

`find`、`acceptsSpan`、`findAllowed`、`resetStats` 与单条查找器同一用途。整行比较按每一条自己的大小写规则。`isEmpty` 表示只有空模式。`engineName` 返回一个短名字，给对照测试用。文档不描述如何挑选内部实现。

### multi

导出 `src/finder/multi.zig`，也就是 `Multi` 的定义模块。

### Regex

线性时间正则表达式匹配器（Thompson NFA + SIMD 必需字面量预过滤 + 有界跨行窗口）。

```text
Regex.init(allocator, pattern, options) !Regex
Regex.deinit(self)
```

采用无回溯的 Thompson NFA 执行，最坏步数随输入长度线性增长。构造时校验编译指令数上限（硬顶 4096）与跨行窗口上限（硬顶 8 MiB），超限在扫描开始前返回 `RegexTooLarge`。自动从语法树提取必需字面量（`requiredLiteral`）并挂载 `Finder` 做 SIMD 预过滤。提供 `find`、`findWatched`、`findAllowed`、`acceptsSpan`、`resetStats`。

### RegexOptions

构造 `Regex` 的选项。

- `case`：默认 `sensitive`。大小写折叠只支持 ASCII。
- `multiline`：默认 false。为真时允许匹配跨越 LF，且 `^` 与 `$` 匹配行首与行尾。
- `dot_all`：默认 false。为真且 `multiline` 打开时 `.` 可匹配 LF。
- `max_inst`：编译指令数上限，null 使用硬顶 4096。
- `max_multiline_window`：有界跨行窗口字节上限，默认 64 KiB，硬顶 8 MiB。跨行跨度耗尽该窗口仍未闭合匹配时立即判定失配。

### regex

导出 `src/regex.zig`，也就是 `Regex` 与 `RegexOptions` 的定义模块。

### MatchMode

`earliest` 或 `leftmost_first`。含义见上面的匹配一节。

### Match

一次 `find` 的结果。`start` 和 `end` 半开，相对这次传给 `find` 的 haystack，不是来源里的绝对偏移。

### CaseMode

`sensitive`、`insensitive`、`smart`。默认敏感。大小写折叠只支持 ASCII。`smart` 就是智能大小写按模式分别判断。

### FindOptions

构造 `Finder` 或 `Multi` 的选项。不分配。

- `case`：默认 `sensitive`。
- `unicode_case`：默认 false（仅折叠 ASCII）。为真时在 `Multi` 中按 Unicode 简单大小写折叠展开等价变体。
- `frequency`：256 字节的频率表。null 用内置表。数值越小，这个字节越适合做锚点。
- `prefilter_fp_threshold`：默认 0.80。只影响长于 32 字节的单条模式。设为 1 或更大则不因为预过滤放弃而换查找方法。
- `max_pattern_count`、`max_pattern_bytes`：null 表示用硬顶。比硬顶大时仍按硬顶拒绝。

### matcher

导出 `src/matcher.zig`。根上的 `MatchMode`、`Match`、`RequiredLiteral`、`CaseMode`、`FindOptions` 都来自这里。另外还有：

- `pattern_count_hard_cap`：1024。
- `pattern_bytes_hard_cap`：256 KiB。
- `LimitError`：`PatternCountExceeded`、`PatternBytesExceeded`。
- `patternCountLimit`、`patternBytesLimit`：把调用方的上限收进硬顶。
- `checkPatternLimits(patterns, options)`：在分配查找表之前调用。搜索入口的 `init` 已经调用它。
- `matcher_shape_docs`：空声明，用来记下 `find` 的形状，没有运行时的值。可选方法是 `requiredLiteral`。

### RequiredLiteral

`bytes` 加上 `offset_in_match`。`Regex` 从语法树提取出必需字面量时返回该片段及其起始偏移；字面量查找器被问到时，非空模式返回自身，偏移为 0。

### memchr

导出 `src/finder/memchr.zig`。单字节查找，不分配。`native_width` 是 16 或 32。显式传入的 `width` 也只能是这两个数。

- `find(width, haystack, start, needle)`：`haystack[start..]` 里的第一个下标。
- `findEither(width, haystack, start, a, b)`：第一个等于 `a` 或 `b` 的下标。
- `findLast(width, haystack, start, end, needle)`：`[start, end)` 里的最后一个下标。
- `count(width, haystack, start, end, needle)`：`[start, end)` 里的个数。
- `findAny(width, haystack, start, a, b, c)`：`a`、`b`、`c` 中最先出现的字节。返回 `AnyHit`，字段是 `index` 和 `byte`。三者可以相同。

搜索入口会用它找行界和 NUL。调用方也可以直接用。

### two_way

导出 `src/finder/two_way.zig`。最坏线性于输入长度的字面量查找。不分配。模式字节由调用方持有。

`Fold` 取 `sensitive` 或 `ascii`。大小写折叠只支持 ASCII。`TwoWay.init(pattern, fold)` 做预处理。`find(haystack, start)` 返回下一次匹配的起点，不是半开区间。终点是起点加上模式长度。空模式在 `start <= haystack.len` 时匹配于 `start`。

## 行与编码

默认行终止符是 LF。交给调用方的行内容去掉结尾的 LF。LF 模式下再去掉紧挨着的一个 CR。NUL 记录模式不剥 CR。

行号从 1 开始。服务入口始终计行号。NUL 记录模式计的是记录号。字节列从 1 开始，按 `bytes` 计，取区间起点最小的那一次；没有匹配时是 null。`u16_column` 是同一位置的 UTF-16 列，从 1 开始，和字节列是两个数。多字节字符上两者可以不同。

`absolute_offset` 是这一行起点在可搜索字节流里的绝对偏移，任何行都有。转码之后从转码结果计。`raw_offset` 是这一行起点在转码或解压前的原始字节流上的偏移（未发生转码或解压时等于 `absolute_offset`）。半开区间相对 `bytes`，按起点排序。UTF-16 半开端点在扫描时算好，记在 `Span.u16_start` 和 `Span.u16_end`，坐标在有损文本上。

`bytes` 是搜索用的行字节。`text` 在合法 UTF-8 时与 `bytes` 相同。非法序列换成 U+FFFD。栈上 1024 字节放不下、又没有分配器时，`text` 退回 `bytes`。`raw` 当前与 `bytes` 相同。库不把这些字节做成 base64。

### Encoding

`auto` 在流开头嗅探 BOM（认 UTF-8、UTF-16LE、UTF-16BE）；无 BOM 时若提供了 `SearchConfig.charset`（支持 WHATWG 标签或 HTTP `Content-Type` 头部，如 `gbk`、`gb2312`、`utf-8`、`utf-16le`、`iso-8859-1`），则按该提示转码为 UTF-8。也可显式指定 `utf8`、`utf16le`、`utf16be`、`gbk`、`latin1`。`none` 不嗅探、不转码。

### Compression

进程内流式解压模式：`none`（默认，不解压）、`auto`（按流开头魔数识别 Gzip、Zstd、XZ）、`gzip`、`zstd`、`xz`。解压过程实时累加 `decompressed_bytes` 并检查 `max_decompressed_bytes` 与 `max_compression_ratio`（默认 100，硬顶 1000），超出任一上限立即停止并记为 `LimitHit.decompressed_bytes`；损坏的压缩流不崩溃，记为 `SoftError.read_failed`。

### decompress

导出 `src/decompress.zig`，提供 `Compression`、`OffsetMap`、`decompressSlice` 等进程内流式解压与偏移映射工具。

`null_data` 为真时用 NUL 分隔记录。记录里的 LF 不断行，NUL 也不当成二进制。

超长行继续流式查找。交出去的是匹配附近的窗口：`truncated` 为真，`line_len` 是去掉分隔符之后的原始内容长度，`window_start` 是 `bytes` 在这行内容里的起点。窗口尽量包住匹配。匹配本身长过上限时，窗口从匹配起点开始。字节偏移仍然精确：绝对偏移加上窗口内的区间。

`max_line_len` 默认 2 MiB，硬顶 8 MiB。读缓冲不超过单行上限加一个分隔字节，不会为了装下整行继续涨。

## 二进制

用 NUL 字节判断二进制。`null_data` 打开时 NUL 是记录分隔符，不参与这个判断。

二进制默认跳过，也就是 `BinaryPolicy.quit`。

三种模式：

- `quit`：跳过。看到 NUL 后停止读取，后面的内容不再交给调用方。NUL 落在第一块缓冲里时，这一块也不搜索。`binary_status` 为 `suppressed`，`outcome` 为 `binary_quit`。
- `report`：继续搜索，直到知道有没有匹配，但是不返回行内容。`binary_status` 为 `detected`。有匹配时 `outcome` 为 `binary_matched`。
- `none`：按文本处理。NUL 只是字节，行里可以含有它。`binary_status` 保持 `none`。仍然受单行长度上限保护。

`binary_offset` 是这次输入里第一次看到 NUL 的绝对偏移。没有 NUL 就是 null。`Result.nul_offset` 与它相同。

### BinaryPolicy

`quit`、`report`、`none`。默认 `quit`。字段在 `SearchConfig.binary`。

### BinaryStatus

`none`、`detected`、`suppressed`。含义见上面三种模式。`EndEvent.binary_status` 和 `LineEvent.binary_status` 都用这个枚举。没看到 NUL，或者调用方要求按文本处理时，是 `none`。

## 上下文

`context` 是两侧共用的行数，默认 0。`before` 或 `after` 不是 null 时，对应的一侧改用那个值。前置用环形缓冲，不回退读取。相邻的片段合并，不重复发送。中间断开时发 `context_break`，只带来源 ID。库不输出分隔文本。

普通上下文行没有匹配区间。反选时，被当作上下文交出的模式行可以带区间。

行数硬顶是 `SearchConfig.context_lines_hard_cap`，值为 10。`max_context_lines` 可以把这个上限再调低，不能调高。`context`、`before`、`after` 里任一值超过生效的上限，返回 `ContextLinesExceeded`。

前置缓冲的字节量是前置行数乘以 `max_line_len`。它不能超过 `max_before_bytes`，否则返回 `BufferLimit`。服务入口在留空时把 `max_before_bytes` 至少设成 20 MiB，并且不超过硬顶 80 MiB。切片入口的前置直接指向调用方的 haystack。reader 入口用分配器拷贝，返回前释放。

`passthru` 打开全文高亮模式：不匹配的行全部作为 `context` 事件交出，匹配的行作为带区间的 `match` 事件交出，中间不发 `context_break`。所有交出的行字节同样计入 `max_output_bytes`，达到上限时停止并把未扫完的来源标成 `partial = true`。

## 事件

服务入口的 `Event` 是一个联合。每产生一个就回调一次。标签：

- `begin`：只有 `source_id`。
- `match`：`LineEvent`。
- `context`：`LineEvent`。
- `context_break`：只有 `source_id`。上下文不连续。
- `progress`：按 `progress_interval` 产生。null 或 0 表示不发。流没有结束时这不是最终汇总。
- `heartbeat`：实时流空闲。不是错误，也不是结束。
- `end`：这个来源结束。未命中的来源也有 begin 和 end。
- `summary`：扫完、没有暂停、实时流已经关闭时才发。没扫完不把 `summary` 当成最终结果。

暂停时没有 `end`，也没有 `summary`。

### Event

见上一节的标签。`source_id` 都指向调用方传入的那份字节，只在回调返回前跟事件一起使用。

### LineEvent

服务入口上的一行。`bytes`、`text`、`raw`、`matches` 只在本次回调返回前有效。

- `source_id`
- `line_number`：从 1 开始。NUL 记录模式是记录号。
- `column`：从 1 开始的字节列。没有匹配时为 null。
- `u16_column`：从 1 开始的 UTF-16 列。没有匹配时为 null。
- `absolute_offset`：行起点的绝对偏移。
- `raw_offset`：行起点在转码或解压前原始字节流上的偏移。
- `bytes`、`text`、`raw`：见「行与编码」。
- `replaced`：设置了 `SearchConfig.replacement` 且本行有匹配区间时为替换后的预览切片，否则为 null。只在本次回调返回前有效。
- `matches`：半开区间，相对 `bytes`，按起点排序。
- `truncated`、`line_len`、`window_start`：超长行窗口。
- `binary_status`

### Line

旧回调入口上的一行。`bytes`、`text`、`raw`、`replaced`、`matches` 只在本次回调返回前有效。

- `bytes`、`text`、`raw`、`replaced`：与 `LineEvent` 同一含义。
- `offset`：行起点的绝对偏移。
- `raw_offset`：行起点在转码或解压前原始字节流上的偏移。
- `number`：从 1 开始。旧入口没打开行号时为 null。
- `match`：发现这一行的那一次匹配。普通上下文和反选命中行可以是 null。
- `matches`：全部区间，按起点排序。
- `column`、`u16_column`：与 `LineEvent` 同一含义。
- `binary_status`、`truncated`、`line_len`、`window_start`

### Span

半开区间。`start`、`end` 在事件里相对行的 `bytes`，在 `Match` 里相对 `find` 的 haystack。`u16_start`、`u16_end` 是同一段在有损文本上的 UTF-16 码元，半开，扫描时算好。`replacement` 在设置了 `SearchConfig.replacement` 时指向替换模板切片，否则为 null。

### EndEvent

一个来源结束。没有命中时也会产生，计数字段为 0，不会省掉。

- `source_id`
- `binary_status`、`binary_offset`
- `matched_lines`：匹配行数。
- `matches`：匹配次数。一行里可以有多次，所以它和 `matched_lines` 不是同一个数。
- `bytes_read`
- `outcome`
- `limit_hit`、`partial`
- `resume_at`：下次可以从这个可搜索字节偏移继续。只在 `max_results` 停下时有值。
- `soft_error`

### Progress

`source_id`、`bytes_searched`、`matches`、`matched_lines`。`matches` 是到目前为止的匹配次数。

### Heartbeat

字段与 `Progress` 相同。表示实时流空闲超时，不是错误，也不是结束。

### Summary

一次请求扫完后的汇总。字段：

- `source_id`
- `elapsed`：纳秒。
- `searches`：一次服务调用是 1。
- `searches_with_match`：`matched_lines > 0` 时为 1，否则 0。
- `bytes_searched`
- `bytes_printed`：已经交给调用方的行字节。
- `matched_lines`、`matches`
- `bytes_read_raw`
- `sources_failed`：这个来源有软错误时为 1，否则 0。

### Result

函数的成功返回值。致命错误走 `try` 的错误，不会装进这个结构。软错误、有匹配、无匹配都是成功返回，靠字段区分。

- `outcome`
- `matched_lines`、`matches`
- `binary_offset`、`nul_offset`：同一个 NUL 偏移。
- `bytes_read`、`bytes_searched`、`output_bytes`
- `limit_hit`、`partial`
- `resume_at`
- `soft_error`
- `paused`：为真时还没有 `end`，也没有 `summary`。
- `scanned_all`：输入已经扫完。没扫完时不要把 `summary` 当成最终结果。
- `elapsed_ns`
- `resume_state`：暂停后续搜用的计数。没暂停时也是结束时的快照。

### Outcome

- `complete`：扫完，没有被回调或 `max_count` 停下。
- `stopped`：回调要求停止，或达到 `max_count`，或暂停。
- `binary_quit`：按跳过处理时看到了 NUL。
- `binary_matched`：按 `report` 处理时看到了 NUL，并且有匹配。

### LimitHit

这次为什么在扫完之前停下。正常扫完是 `none`。

- `none`
- `max_results`：请求级结果条数。`resume_at` 有值。
- `max_bytes`：来源扫描上限和请求扫描上限里先到的那个。
- `deadline`：时间预算。
- `decompressed_bytes`：调用方传入的解压字节达到上限。库自己不解压，也不自己累加这个数。
- `cancelled`：取消令牌。

`max_count` 不写入这个枚举。输出字节达到上限时也不一定改写它，见预算一节。

### SoftError

单个来源上的软错误。只有 `read_failed`。没有路径，也没有系统调用细节。搜索函数仍然成功返回。

没有匹配时 `soft_error` 为 null，并且 `matched_lines` 为 0。有匹配时 `matched_lines` 大于 0。`files_without_match` 打开且中途命中时，没有 `match` 事件，但 `matched_lines` 为 1，`soft_error` 仍是 null。

### ResumeState

暂停后续搜需要的计数。`resumeSourceSlice` 从 `Result.resume_state` 读它。调用方通常不自己填。

字段：`matched_lines`、`matches`、`bytes_read`、`bytes_searched`、`output_bytes`、`results_out`、`limit_count`、`line_number`、`started_ns`、`deadline_armed`、`skip_begin`。

## 预算与错误

预算由调用方传入。库不读环境变量，不读配置文件，不自己选配额。

预算耗尽时看 `limit_hit`。输入没扫完时 `partial` 为真。`partial` 的条件是：`limit_hit` 不是 `none`，或者输出字节已经挡住后续的行，并且 `scanned_all` 为假。暂停那一次 `partial` 为假。

- 扫描字节：`max_source_bytes` 与 `max_request_bytes` 同时生效，取更小的那个，停下时 `limit_hit` 为 `max_bytes`。直接传入的切片也受这个上限约束。
- 时间：`time_budget_ns` 纳秒，从搜索开始算。停下时 `limit_hit` 为 `deadline`。`clock` 不是 null 时用它代替单调时钟，签名是 `fn (?*anyopaque) i128`，配合 `clock_ctx`。
- 取消：`cancel` 指向 `std.atomic.Value(bool)`。置位后停止，关闭上游，`limit_hit` 为 `cancelled`。
- 结果数：`max_results` 是请求级匹配行数。达到后 `limit_hit` 为 `max_results`，`resume_at` 是可搜索字节流上的续查偏移。这和 `max_count` 不同。`max_count` 只停这个来源，不带续查位置。
- 输出字节：`max_output_bytes` 累计行事件的字节。达到后不再交出行。输入没扫完时 `partial` 为真。它不一定改写 `limit_hit`。
- 内存：单行长度、前置上下文、解码输入、单条排队事件都有上限。服务回调是同步的，不攒多条事件队列。超限返回 `BufferLimit` 或 `DecodeLimit`，这是致命错误。
- 解压字节：`decompressed_bytes` 与 `max_decompressed_bytes`。解压尚未提供。调用方把已经计入的值传进来，达到上限时 `limit_hit` 为 `decompressed_bytes`。

`stop` 不是取消。它指向另一个原子布尔。置位后下一块开始前停止，不关闭上游，也不写成 `cancelled`。

怎样区分软错误和没有匹配：调用成功，并且 `soft_error` 为 null、`matched_lines` 为 0，这是没有匹配，begin 和 end 都在。调用成功，并且 `soft_error` 为 `read_failed`，这是来源软错误。函数返回错误，则这次没有 `Result`，那是致命错误。

致命错误：

- `BudgetExceeded`：某项配置大于硬顶。
- `ContextLinesExceeded`：上下文行数超过生效上限。
- `BufferLimit`：前置上下文放不进 `max_before_bytes`，或单条行事件超过 `max_queued_event_bytes`。
- `DecodeLimit`：转码输入超过 `max_decode_bytes`。
- `OutOfMemory`：分配失败。切片上需要转码却没有 `decode_allocator`，或一行的区间超过栈上的 32 个又没有分配器，也是这个错误。
- `PatternCountExceeded`、`PatternBytesExceeded`、`PatternHasNewline`：构造匹配器失败，扫描还没有开始。

返回给调用方的错误不含内部路径。需要细节时设置 `log`：`fn (?*anyopaque, []const u8) void`，配合 `log_ctx`。这条消息可以含有调用方自己放进去的名字。库不把这些消息交给终端。

实时流把 `live` 设为真。空读是空闲，不是错误，也不是结束。`idle_timeout_ns` 留空时按 0 处理，第一次空读就会发 `heartbeat`。`live_closed` 置位后，下一次空读才是结束。流还开着时不发 `summary`。

`max_concurrency` 由调用方写入。单输入搜索不创建线程，也不改写这个数。库不按 CPU 核数自己起线程。

### SearchConfig

全部搜索入口的配置。下面的默认值是结构体字面量的默认值。服务入口还会在留空时填预算，见「默认值」。

常量：

- `default_buffer_size`：1 MiB。
- `default_max_line_len`：2 MiB。
- `context_lines_hard_cap`：10。
- `max_line_len_hard_cap`：8 MiB。
- `default_max_source_bytes`、`default_max_request_bytes`：各 16 MiB。
- `max_source_bytes_hard_cap`、`max_request_bytes_hard_cap`：各 64 MiB。
- `default_time_budget_ns`：30 秒。`max_time_budget_ns`：120 秒。
- `default_max_output_bytes`：1 MiB。`max_output_bytes_hard_cap`：8 MiB。
- `default_max_decode_bytes`：4 MiB。`max_decode_bytes_hard_cap`：8 MiB。
- `default_max_queued_event_bytes`：2 MiB。硬顶等于单行硬顶。
- `default_max_before_bytes`：20 MiB。硬顶 80 MiB。

字段：

- `line_numbers`：结构体默认 false。服务入口会改成 true。
- `invert`、`whole_word`、`whole_line`：默认 false。
- `context`、`before`、`after`、`max_context_lines`：见上下文。
- `max_count`、`exists`、`files_without_match`：见匹配。
- `contains`、`excludes`：调用方持有的模式切片。
- `close_input`、`close_ctx`：提前停止时关闭上游。
- `binary`：默认 `quit`。
- `null_data`：默认 false。
- `encoding`：默认 `auto`。
- `charset`：可选的 HTTP `Content-Type` 或 WHATWG 字符集提示。
- `compression`：默认 `none`。进程内流式解压模式。
- `max_compression_ratio`：最大解压膨胀比，默认 null（解压开启时按 100 检查，硬顶 1000）。
- `decode_allocator`：切片转码/解压和放不下的有损文本使用。
- `buffer_size`：起始块大小，默认 1 MiB。0 会按默认 1 MiB 处理。
- `max_line_len`：默认 2 MiB。
- `match_mode`：默认 `earliest`。
- `scratch`：reader 入口的可复用缓冲。
- `stop`：提前停下，但不是取消。
- `max_source_bytes`、`max_request_bytes`：null 在旧入口表示不另加上限。
- `max_results`、`resume_from`：请求级条数和续查偏移。`resume_from` 默认 0。
- `max_output_bytes`、`time_budget_ns`。
- `clock`、`clock_ctx`。
- `cancel`。
- `decompressed_bytes`：默认 0。`max_decompressed_bytes`：null 表示不检查。
- `max_before_bytes`、`max_decode_bytes`、`max_queued_event_bytes`。
- `max_concurrency`。
- `progress_interval`：null 或 0 不发进度。
- `live`、`idle_timeout_ns`、`live_closed`。
- `continuation`：由 `resumeSourceSlice` 填入。
- `stop_on_nonmatch`：默认 false。有序输入在出现匹配后遇到第一条不匹配行立即停止并关闭上游。
- `passthru`：默认 false。全文高亮模式，输出全部行并受 `max_output_bytes` 约束。
- `replacement`：默认 null。非 null 时提供只读替换预览。
- `log`、`log_ctx`。

## 默认值

服务入口（`searchSourceSlice`、`searchSource`、`resumeSourceSlice`、`openSourcePull`）在调用方留空时填上：

- 行号：打开。
- 每个来源的扫描字节：16 MiB，硬顶 64 MiB。
- 每次请求的扫描字节：16 MiB，硬顶 64 MiB。
- 时间：30 秒，硬顶 120 秒。
- 输出字节：1 MiB，硬顶 8 MiB。
- 解码缓冲：4 MiB，硬顶 8 MiB。
- 单条事件字节：至少是单行上限，硬顶 8 MiB。
- 前置上下文缓冲：至少 20 MiB，硬顶 80 MiB。

这些项可以在硬顶以内覆盖。把数写成大于硬顶会得到 `BudgetExceeded`。服务入口不能靠留空把它们关掉。旧入口 `searchSlice` 和 `searchReader` 留空表示不另加对应上限。

可以覆盖的还有：二进制策略（二进制默认跳过）、上下文行数、单行长度、大小写、整词、整行、反选、包含与排除、`max_count`、`max_results`、编码、NUL 记录、进度间隔、实时流、存在性查询、无匹配来源。上下文硬顶 10 行，单行硬顶 8 MiB。

不能打开的项：跟随符号链接，读取全局或父目录忽略。搜索配置里没有这两个开关。搜索入口不打开目录，也不读忽略文件。

搜索入口不映射外部文件，配置里也没有这个开关。搜索入口不遍历目录，因此没有跨文件系统的开关。调用方交给库的是已经打开的流。

## 尚未提供

下面这些现在不能当作已经可以调用的搜索能力：

- 把目录列举、glob、忽略规则、类型过滤直接作为单输入搜索入口的参数自动打开文件（单输入搜索入口只搜调用方已打开的流或切片，目录路径的自动打开尚未提供在公共搜索入口上）。

`walk_glob`、`walk_ignore`、`walk_types`、`walk_list`、`walk_deque`、`walk_file_id` 已经导出，供调用方在构造或过滤来源集合时直接使用，单输入搜索入口不隐式调用它们来列举目录。

### sink_mod

导出 `src/sink.zig`。事件、行、`Result`、`Flow` 的定义在这里，根上有同名再导出。旧回调的可选方法形状也写在这个文件顶部的说明里。

### searcher

导出 `src/searcher.zig`。服务入口和 `SearchConfig` 定义在这里，根上有再导出。`SliceError`、`ReadError`、`PullEvent`、`SourcePull` 也在这个模块里。

这个模块里还有没有从根再导出的读取已经打开文件的函数。它不是服务入口。服务入口是根上的 `searchSource` 和 `searchSourceSlice`。

### walk_glob

导出 `src/walk/glob.zig`。字节 glob。`*` 和 `?` 不跨 `/`。`**` 只有占满一整段时才跨目录。字符类支持区间，以及 `!` 或 `^` 取反。按字节比较，支持 ASCII 忽略大小写（`case_insensitive`）与嵌套花括号 `{a,{b,c}}` 展开，内置规则条数硬顶（`rule_count_hard_cap = 1024`）、单条长度硬顶（`rule_len_hard_cap = 4096`）与花括号嵌套深度硬顶（`brace_depth_hard_cap = 8`）。

- `Class`：`exact`、`ext`、`prefix`、`suffix`、`general`。
- `Glob`：`text`、`key`、`class`，以及 `anchored`、`dir_only`、`negated`、`case_insensitive`。`text` 和 `key` 由调用方持有。
- `classify(text)`、`classifyWithCase(text, case_insensitive)` 按元字符分类。`key` 指向 `text` 里的字面量部分。
- `expandBraces(allocator, pattern, out, max_rules)`、`compileGlobs(arena, patterns, options)`：展开嵌套花括号并校验规则条数与长度上限。
- `matches(glob, rel, base, is_dir)`、`matchGlobs(globs, rel, base, is_dir)`：`rel` 是相对这一层的名字，`base` 是最后一段，多条规则按后写优先裁决。
- `matchText(pattern, text)`、`matchTextCase(pattern, text, case_insensitive)` 做一般匹配。
- `basename` 取最后一个 `/` 之后的字节。输入是调用方已有的切片。

搜索入口不按 glob 选择来源。

### walk_ignore

导出 `src/walk/ignore.zig`。解析调用方已经放在内存里的规则文本。不读环境变量，也不沿父目录寻找规则文件。搜索入口不应用这些规则。

- `Affix`：`text` 和 `index`。
- `Set`：一层规则。`parent` 把更深层链到外层。建好之后只读，可以共享。
- `ParseOptions`、`LayerFiles`、`LayerSwitch`：支持控制 `dot`（`.ignore` 与 `.rgignore`）、`vcs`（`.gitignore`）、`exclude`（仓库内 info 忽略）、`case_insensitive` 与条数上限。
- `parseLine`、`parseLineWithOptions` 解析一行。空行和 `#` 注释返回 null。`!` 表示否定，尾部 `/` 表示只对目录。文本由分配器复制。
- `parseInto`、`parseIntoWithOptions`、`parseTextsInto`、`parseLayerInto` 把单段或多段纯文本规则追加进 `std.ArrayList(glob.Glob)`。
- `build` 用 arena 做索引。glob 的文本必须活得和集合一样久。
- `isIgnored(set, rel, is_dir, scratch)`。`scratch` 要能放下前缀加相对名称。放不下时这一层自己的规则不参与判断。父层已经忽略时，里面的名字也算忽略，后写的否定不能把它救回来。同一层里后写的规则胜出。

### walk_deque

导出 `src/walk/deque.zig`。`Deque(T)` 是工作窃取双端队列，元素是指针，空位是 null。

`init(allocator, cap)` 分配，容量会抬到不小于 8 的 2 的幂。`deinit` 释放槽位，不释放元素指向的对象。`push` 和 `pop` 只给所有者调用，所有者这一侧是后进先出。`steal` 任意线程可以调用，那一侧是先进先出。只有所有者会扩容。搜索入口不创建这个队列，也不起线程。

### walk_file_id

导出 `src/walk/file_id.zig`。打开的目录或文件的设备号和 inode，用来识别是不是同一个对象。

- `Id`：`dev`、`ino`，以及 `eql`。
- `Error`：`Unexpected` 或文件 `stat` 的错误。
- `fromDir(dir)`、`fromFile(io, file)`。参数是已经打开的 `std.Io.Dir` 或 `std.Io.File`。搜索入口不调用它们。

### walk_types

导出 `src/walk/types.zig`。按类型名做文件名过滤并支持调用方注入自定义类型表。`Type` 有 `name` 和 `patterns`。`builtin` 是内置表。`find(name)`、`findInTable(table, name)` 按名字查找。`expandTypesToGlobs(arena, table, include, exclude)` 把包含与排除的类型名展开为 `glob.Glob` 切片。`matches(selected, base)`、`matchesWithTable(table, selected, excluded, base)`：`selected` 为空表示不过滤正向类型，命中 `excluded` 则直接拒绝。搜索入口不按类型过滤。

### walk_list

导出 `src/walk/list_dir.zig`。枚举一个已经打开的 `std.Io.Dir`。`buffer_len` 是 32 KiB。`Lister.init(dir, scratch)` 要求 `scratch` 至少达到 `std.Io.Dir.Reader` 的最小缓冲，并且按 `usize` 对齐。`fill(io, out)` 把目录项写入调用方的数组，返回写入的个数。结束之后返回 0。`State` 是内部游标。搜索入口不列举目录。

## 示例

下面这一段就是测试 `API 文档示例能跑通`。构建从这里抽出这一份代码，编译并运行。仓库里没有第二份副本。

它从构造一条字面量开始，搜索调用方给出的切片，读完 begin、match、end 和 summary。行字节在回调里比较，因为切片只在回调返回前有效。`soft_error` 为 null 表示这不是软错误。`limit_hit` 为 `none` 且 `partial` 为假，表示预算没有中途停下。

```zig
const std = @import("std");
const libwebgrep = @import("libwebgrep");

test "API 文档示例能跑通" {
    const Collect = struct {
        begin_ok: bool = false,
        line_ok: bool = false,
        end_ok: bool = false,
        summary_ok: bool = false,
        matches: u32 = 0,

        pub fn event(self: *@This(), ev: libwebgrep.Event) bool {
            switch (ev) {
                .begin => |begin| {
                    self.begin_ok = std.mem.eql(u8, begin.source_id, "doc");
                },
                .match => |line| {
                    // 行字节只在这次回调返回前有效，所以在这里比较。
                    self.matches += 1;
                    self.line_ok = std.mem.eql(u8, line.bytes, "hay needle") and
                        line.line_number == 1 and
                        line.absolute_offset == 0 and
                        line.column == 5 and
                        line.matches.len == 1 and
                        line.matches[0].start == 4 and
                        line.matches[0].end == 10;
                },
                .end => |end| {
                    self.end_ok = end.soft_error == null and
                        end.matched_lines == 1 and
                        end.matches == 1 and
                        end.limit_hit == .none and
                        !end.partial;
                },
                .summary => |summary| {
                    self.summary_ok = summary.matches == 1 and summary.sources_failed == 0;
                },
                else => {},
            }
            return true;
        }
    };

    var found = Collect{};
    var finder = try libwebgrep.Finder.init("needle", .{});
    const result = try libwebgrep.searchSourceSlice(
        Collect,
        &found,
        "doc",
        "hay needle\n",
        &finder,
        .{},
    );
    try std.testing.expectEqual(libwebgrep.Outcome.complete, result.outcome);
    try std.testing.expect(result.soft_error == null);
    try std.testing.expect(found.begin_ok);
    try std.testing.expect(found.line_ok);
    try std.testing.expectEqual(@as(u32, 1), found.matches);
    try std.testing.expect(found.end_ok);
    try std.testing.expect(found.summary_ok);
}
```
