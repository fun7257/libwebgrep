# 设计

P0 实现内核和单个输入上的 Searcher。下面每节对应已经落地的模块。和任务说明不一致的地方写在最后，并附上本机数据。

宿主是 Apple M2（8 核，8 GiB）。性能数字都来自这台机器上的 ReleaseFast，不能当成 x86_64 的结果。

## 分层

四层里目前可以用的是前两层。

- 内核：`src/finder/`。在一段内存里找一个字面量。不分配，不碰 I/O。
- Searcher：`src/searcher.zig`、`src/sink.zig`、`src/matcher.zig`。切片、`*std.Io.Reader`、已打开的文件。负责行边界、行号、上下文、反选和 NUL。
- 编排层（P1）：目录遍历、忽略规则、`std.Io.Group` 调度。
- C ABI（P3）：`src/c_api.zig` 和 `include/zrg.h` 还没有。

公共入口是 `src/root.zig`。库代码没有全局可变状态。

## 查找内核

`Finder.init` 拒绝带换行的模式。空模式匹配每个位置。单字节走 memchr。长度不超过 32 的模式由 packed pair 自己完成查找。更长的模式仍先走 packed pair，两个稀有字节挤在一起并且确认总是失败时，这次查找剩下的部分改走 Two-Way。

### memchr

`find` 调用 `std.mem.findScalarPos`。手写 `@Vector` 版和 std 的差距在 5% 以内，按约定改用 std。对比是同一块 64 MiB 缓冲、查找不存在的 `0xff`、ReleaseFast：

| 实现 | GB/s |
| --- | ---: |
| 手写 `find`（改用 std 之前） | 55.769 |
| `std.mem.findScalar` | 54.631 |
| 比值 | 1.021 |

改完之后又测了一次。`find` 只是转调，53.423 GB/s；同一次运行里 std 是 55.595 GB/s。两次都在 5% 以内，保持调用 std。

`findEither`、`findLast`、`count`、`findAny` 仍用手写向量。std 的 `findScalarLast` 是标量循环，计数没有对应的向量实现。`findAny` 在最多三个字节里找最先出现的那个，没命中时只做比较和 `@reduce(.Or)`，命中处理标成 `never_inline`。当前微基准里 `findEither` 是 56.456 GB/s，相对同一次 std 单字节查找是 1.083。

宽度是 comptime 参数，支持 16 和 32。这台 M2 的 `native_width` 是 16。NEON 没有 movemask：16 字节比较结果看成 8 个 16 位通道，右移 4 位再窄化，匹配字节对应 4 个 1，下标用 `ctz / 4`。短于一个向量的尾巴用标量循环。

换行计数走 `count`。单字节正向查找走 std。流式文本搜索里的 NUL 不单独再扫一遍，见 Searcher。

### packed pair

用频率秩选出最稀有的两个字节。秩越小越稀有。默认表在 `src/finder/frequency.zig`，是按英文和源码手写的，调用方可以用 `FindOptions.frequency` 换掉。

热路径是 Muła 的通用 SIMD：每个向量同时比较两个偏移上的字节，掩码取与，只有两个字节一起命中才离开循环。大小写是否折叠、要不要记账，都在循环外拆成 comptime 版本，循环里没有这条分支。一次推进 4 个向量。确认和 `firstTrue` 用 `@call(.never_inline)` 放到循环外面，否则 LLVM 会把它们编进未命中路径。忽略大小写时每个锚点的两种 ASCII 形式取或。确认用 `std.mem.eql`，第一个不相等的字节就返回。

长度不超过 32 时，packed pair 自己把输入扫完。最坏是 32 倍的线性时间，不再切到 Two-Way。字母表填充上的 `zrgneedle` 因此和稀有字面量同一条向量路径，内核大约 39 GB/s。

输入比一个向量短，或者向量循环收尾时，用标量比较。不监视 NUL 的查找还会先标量看 48 字节。密集文件从第二块起走这条路径，下一次命中通常就在这一小段里，不必为了一次确认进入向量循环。监视 NUL 的快路径不跑这 48 字节。

### Two-Way

按 Crochemore–Perrin 的临界分解实现：预处理 O(m)，搜索最坏 O(n)，不按模式长度分配。周期模式记住已经对上的前缀。非周期路径用 `findEither` 跳到临界字节。这是照论文写的，没有复制 memchr crate 的代码。

长于 32 字节时才可能回退。条件和 memchr 的 PrefilterState 一致：至少 50 个候选，且平均每次跳过少于 8 字节，就把 `use_two_way` 粘住，从失败候选的下一个字节继续。`prefilter_fp_threshold` 小于 1 时启用这组判断，大于等于 1 时一直留在 packed pair。默认 0.80 是启用。不超过 32 字节的模式忽略这个阈值。只统计确认失败的候选，所以这个 `f32` 实际是开关，不是 80% 的比率。`resetStats` 在每个新输入开始时清零。

单个字面量下 `earliest` 和 `leftmost_first` 是同一处匹配。多模式的区分留到 P2。

## Matcher

`find(haystack, start, mode) ?Match`。可选的 `requiredLiteral` 返回模式本身和偏移 0。Searcher 在匹配器提供这个方法时先用它预过滤，再用 `find` 验证。正则没有实现。

`CaseMode` 有 `sensitive`、`insensitive`、`smart`。smart 在模式含有 `A-Z` 时区分大小写。大小写只折叠 ASCII。

## Searcher

先在整块上找匹配，命中后再向两侧找 `\n`。没命中的区域不逐行扫描。

- 反选输出相邻匹配之间的非匹配行，不逐行跑匹配器。
- 行号只在上报时用向量 `count` 数从上一个位置到这里的换行。
- `-A/-B/-C` 用滚动状态保留前 N 行。after 计数跨块延续。绝对偏移不连续时调用 `contextBreak`。
- `max_count` 只统计主循环找到的命中。after 窗口里后来抬成匹配的行仍然调用 `matched`，所以 `-c` 会把它们算进去。这和 ripgrep 15 一致。
- Sink 返回 false，或达到 max_count 且 after 窗口用完，就停止。

没有上下文、没有反选、还没见过 NUL 时，流式读取把 NUL 检查并进这次查找已经加载的向量。下标更小的那个锚点覆盖了向量区间，不再为 NUL 多加载一次。匹配起点之后的尾部和锚点覆盖不到的前缀用标量补上。这一块里 4096 字节以内就有匹配时，后面的块改回先扫 NUL，避免密集文件每一块搜两遍。`quit` 或 Sink 的 `binary` 返回 false 时，丢掉含有 NUL 的这一次读入，不再搜索它。`report` 继续读，直到知道有没有匹配。有上下文、反选，以及 `searchSlice`，仍是先把要搜的范围扫一遍 NUL。

缓冲从 `buffer_size` 倍增，上限是 `max_line_len + 1`（多出来的一个字节留给换行符）。行内容长度等于 `max_line_len` 可以读完，超过才返回 `error.LineTooLong`。

1 GiB 热文件、库内 `searchFile`、Nop sink、三次取中位数：1 MiB 109.7 ms，256 KiB 111.9 ms，8 MiB 124.1 ms。128 MiB 文件上 1 MiB 缓冲是 10.178 GB/s，256 KiB 是 10.010 GB/s。默认取 1 MiB。

文件读取是 `readPositional` 滚动缓冲。整文件映射在新鲜进程的 1 GiB 热缓存上是 192.4 ms、驻留约 1 GiB，同一轮 rg 是 125.4 ms、4.9 MiB。进程内小文件的映射吞吐没有预言这个结果，所以映射没有留下。流输入同样走这块缓冲。

## Sink 和打印器

`searchSlice`、`searchReader`、`searchFile` 的第一个类型参数是 Sink 的结构体，第二个参数是它的指针。方法：

- `begin(path) bool`
- `matched(line) bool`
- `context(line) bool`
- `contextBreak() bool`
- `binary(offset) bool`
- `finish(result) bool`

`Line.bytes` 指向内部缓冲或调用方切片，回调返回后不能再留着。同时给出绝对偏移、可选行号和行内匹配区间。

`AnySink` 是同一组方法的虚表。`SliceIter` 是单输入、无上下文的拉式适配。

`TextPrinter` 对齐 `rg --no-config --color=never` 的行格式。匹配用 `:`，上下文用 `-`，列号是 1 起的字节偏移。二进制说明和 ripgrep 15 的句子相同。`CountPrinter` 不实现 `binary`，因此 `-c` 会数 NUL 后面的匹配，也不打印二进制句子。

文件之间的 `--` 由示例 CLI 在每个文件结束后写出，不放进 Searcher。只有打开了上下文才缓冲一个文件的输出。

## 示例 CLI

`examples/cli.zig` 的 `execute` 接收分配器、`std.Io`、参数和两个 writer。单线程。目录打印“目录遍历还没做”并记成错误。

`--column` 同时打开行号。`-q` 优先于 `-c`，`-c` 优先于文本。显式文件的默认二进制策略是 `report`；`--binary` 被接受并忽略，`-a` 改成 `none`。

## 测试

`zig build test` 跑库测试和示例 CLI 测试。源码里有 55 个 `test` 声明：库 50 个，示例 CLI 5 个。示例 CLI 用临时文件对照 `rg --no-config --color=never -F -j 1`，覆盖 `-n`、`-C`、`-v`、`-c`、`-i`、`-S`、`--column`、`-m`、`-q`、`-a` 和二进制说明。

内核模糊测试用 `zig build test --fuzz=100K -Doptimize=ReleaseFast -Dfuzz-filter=...` 把三个入口拆开。这次三个过滤器和三个交叉编译目标一起跑完，墙钟 48 秒，退出码都是 0。对照的是标量或 `std.mem` 的朴素查找。memchr 的次数含缓存里上一次的 100048 次。

| 测试 | 运行次数 | 独立输入 | 覆盖 |
| --- | ---: | ---: | --- |
| memchr | 100048 → 200063 | 10 | 74/8438（0.88%） |
| packed pair | 100419 | 382 | 233/9073（2.57%） |
| Two-Way | 100429 | 394 | 207/8578（2.41%） |

`zig build check` 在 `x86_64-linux-musl`、`x86_64-windows`、`aarch64-linux-musl` 上编译库、示例和测试，三个目标都通过。没有在那些目标上运行。

## 和任务说明的偏差

1. 单字节 `find` 调用 `std.mem.findScalarPos`。手写版和 std 的差距在 5% 以内。`findEither`、`findAny`、反向查找和计数仍是手写 SIMD。
2. 默认缓冲是 1 MiB。1 GiB 热文件上它比 256 KiB 和 8 MiB 都快，128 MiB 的缓冲扫描里它也是最快的一档。
3. 文件 I/O 是流式 `readPositional`。整文件映射在 1 GiB 端到端上更慢，并且把驻留撑到文件大小，测量写在 `BENCHMARKS.md`。
4. 不超过 32 字节的模式不回退到 Two-Way。长模式的回退是 50 个候选且平均跳过少于 8 字节，`prefilter_fp_threshold` 只决定这组判断开不开。字母表填充上的 `zrgneedle` 走向量快路径，1 GiB 热缓存 zrg 116.1 ms，rg 127.9 ms。
5. 计数打印器在 P0，因为验收要求 `-c` 和 `rg` 逐字节一致。JSON Lines 和文件名列表仍是 P1。
6. 列号默认关闭。`--column` 隐含行号，和 rg 一样。
7. 文件之间的 `--` 在 CLI 里发，不在 Searcher 里发。
8. 默认块是 1 MiB，rg 是 64 KiB。`quit` 按这个块对齐停。NUL 落在块中间时，zrg 会在搜索这一次读入之前停掉，rg 可能已经打出前面的行。样例文件都很小，不受影响。跨块行为有小缓冲单测。
9. 示例 CLI 是单线程的。和 rg 比输出时，rg 侧加了 `-j 1`，否则多文件顺序不稳定。
10. 切片上的 `quit`：NUL 落在第一块里就整段不搜；落在后面则先搜完它之前的整块，再停。流式读取是丢掉含 NUL 的那一次读入。
11. 普通搜索不扫描没命中的区域。一条超长且完全不匹配的行，在非反选模式下不会触发 `LineTooLong`。反选和命中行会检查。
12. 本机没有 x86 吞吐数据。`zig build check` 已确认 `x86_64-linux-musl`、`x86_64-windows`、`aarch64-linux-musl` 能编过，没有在那些目标上跑测试。
13. `-i` 在这份 ASCII 文件上比 rg 快，是因为 zrg 只做 ASCII 折叠，rg 的 `-i` 做更多。Unicode 大小写还没有做。

还没做、也没有改约定的部分：getdents64 大缓冲、Chase-Lev 队列、gitignore、glob 分类、`Io.Group` 固定 worker、mmap 与 `MADV_DONTNEED`、Teddy、Aho-Corasick、C ABI、UTF-16、压缩包、Unicode 折叠表。
