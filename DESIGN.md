# 设计

P0 实现内核和单个输入上的 Searcher。P1 加上目录遍历、忽略规则、并行调度、JSON Lines 和文件名列表。下面每节对应已经落地的模块。和任务说明不一致的地方写在最后，并附上本机数据。

宿主是 Apple M2（8 核，8 GiB）。性能数字都来自这台机器上的 ReleaseFast，不能当成 x86_64 的结果。

## 分层

四层里目前可以用的是前三层。

- 内核：`src/finder/`。在一段内存里找一个字面量。不分配，不碰 I/O。
- Searcher：`src/searcher.zig`、`src/sink.zig`、`src/matcher.zig`。切片、`*std.Io.Reader`、已打开的文件。负责行边界、行号、上下文、反选和 NUL。
- 编排层：`src/walk/`、`src/parallel.zig`。目录遍历、忽略规则、`std.Io.Group` 调度。
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

默认文件读取是 `readPositional` 滚动缓冲。整文件映射在新鲜进程的 1 GiB 热缓存上是 192.4 ms、驻留约 1 GiB，同一轮 rg 是 125.4 ms、4.9 MiB。进程内小文件的映射吞吐没有预言这个结果，所以默认路径仍是流式读取。比缓冲更大的文件可以改用 8 MiB 窗口映射，那是构建选项 `-Dmmap-windows`，默认关闭，见「构建特性」。流输入同样走这块缓冲。

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

## 构建特性

系统和 CPU 专属的优化不进默认路径。用构建选项打开，对应源文件只在选项为真时被分析。默认的 `zig build test` 不编译这两份文件。

P1 没有 CPU 分派，也没有 `-Dcpu`。向量宽度仍是 P0 的 `suggestVectorLength`。这台 M2 是 16。AVX-512、Teddy、Aho-Corasick 留到后面的阶段。

| 选项 | 默认 | 源文件 | 做什么 |
| --- | --- | --- | --- |
| `-Dmmap-windows` | 关 | `src/io/mmap_window.zig` | 比搜索缓冲大的文件按 8 MiB、页对齐的窗口映射，再拷进已有的搜索缓冲。小于等于缓冲、或者映射失败，退回 `readPositional`。打开文件时只有 `OutOfMemory` 会传出去。 |
| `-Dlinux-getdents` | 关 | `src/walk/linux_getdents.zig` | Linux 上用裸 `getdents64` 枚举目录。目标不是 Linux 时，`test`、`check`、`install` 失败，报错是「-Dlinux-getdents 只适用于 os 为 linux 的目标」。 |

窗口丢掉时通知内核可以回收这些页。Linux 调用 `std.os.linux.madvise`，这是系统调用，不链接 libc，所以 musl 目标不用 `-lc`。macOS 用系统 libc 里的 `madvise`。Windows 和 WASI 跳过。

这两项都还没有一组端到端数字说明它们比默认路径快，所以默认关闭。默认目录枚举是 `std.Io.Dir.Reader` 加调用方的 32 KiB 缓冲。Linux 上标准库自己会走 `getdents64`，裸系统调用留着是为了以后能单独测。

文件身份不是性能开关，也不做成构建选项。`src/walk/file_id.zig` 按操作系统在编译期选择：Linux 用 `statx` 的 `EMPTY_PATH`，设备号是 `(major << 32) | minor`；其他 POSIX 用 `fstat`；Windows 的 `File.Stat` 没有设备号，设备号记 0，只用 inode。跟随符号链接时用这一对数字识别环。

## 目录遍历

`src/walk/walker.zig` 从搜索根往下走。路径按字节拼接，不假定 UTF-8。

- 默认跳过以 `.` 开头的名字。名为 `.git` 的条目始终跳过，包括一个叫 `.git` 的普通文件，也包括 `--hidden`。这比 rg 严：`rg --hidden --files` 会列出 `.git/config`，zrg 不会。`.gitignore` 在 `--hidden` 下会列出来。
- 默认不跟随符号链接。`--follow` 才跟随，目录用设备号加 inode 防环。
- `--max-depth`：起始目录的深度是 1。0 什么也不列。当前深度的文件仍然列出，子目录在深度达到上限时不再进入。
- `--max-filesize` 只作用于遍历发现的文件。大小等于上限的留下，大于上限的跳过。后缀只认可选的 `K`/`M`/`G`，按 1024，大小写都可以。`1KB` 和 `1KiB` 是用法错误。命令行上直接给出的文件不套这个上限。
- 打不开的目录记一笔并继续。读不了的忽略文件跳过，不中断遍历。`LineTooLong` 记入错误并继续。有错误时示例 CLI 退出码是 2。

显示路径：根 `foo` 加相对路径 `a/b` 得到 `foo/a/b`。根是 `.` 时保留 `./` 前缀，用来对齐 rg。其它根不额外加 `./`。末尾的 `/` 和 `\\` 会去掉，只保留单独的根分隔符。

## 忽略规则

`src/walk/ignore.zig` 解析 gitignore 的一个子集：注释、行首转义、`!`、尾部 `/`、锚定的 `/`、不跨 `/` 的 `*` 和 `?`、`**/`、字符类。同一份文件里后写的胜出。更深的目录覆盖父目录。同一目录先读 `.gitignore`，再读 `.ignore`，所以 `.ignore` 胜出。`.git/info/exclude` 挂在最外层，路径相对仓库根。不读全局 `core.excludesFile`。

父目录被排除之后，里面的文件不能被重新包含。`dir/` 会挡住 `!dir/keep.txt`。`*.log` 后面的 `!keep.log` 可以带回 `keep.log` 和 `sub/keep.log`，因为父目录本身没有被排除。这和 `git check-ignore` 一致，也和 `rg --files` 一致。

一次搜索用一个 arena 持有这些集合。发布时用 `std.Io.Mutex`（`lockUncancelable`）。发布之后工人只读。任务自己持有路径字节和 `Dir`，弹出它的工人负责释放。子目录的规则在子任务入队之前发布。

搜索根上面还有仓库时，exclude 规则要先接上仓库相对前缀。接不上调用方的临时缓冲就按忽略处理。

## Glob 和类型

`src/walk/glob.zig` 把模式分成五类。精确名和扩展名走哈希，前缀和后缀各放一列，其余线性扫描。带 `/` 的模式算锚定，放进通用匹配，避免后面一条只针对目录的规则盖掉前面的文件规则。哈希里保存每一条命中的下标，不只留最后一条。`*` 和 `?` 不跨 `/`。`**` 只在作为完整路径分量时跨目录。

用户的 `-g` 不经过 gitignore 的行解析。`!` 开头是否定。含 `/` 时对搜索根的相对路径匹配，不加 `./`。不含 `/` 时匹配最后一段文件名。只要出现过正模式，匹配不上的文件就被排除。最后一条命中的 glob 说了算。目录匹配不上文件白名单时仍然往下走。只有最后一条命中的 glob 是否定，才不进入这个目录。

`src/walk/types.zig` 是 `rg --type-list` 的常用子集：zig、c、cpp、rust、py、python、md、markdown、json、toml、yaml、sh、js、ts、typescript、go、java、html、css、txt、asm、cmake、make。未知的 `-t` 是用法错误。没有选择时不过滤。

## 调度

`src/walk/deque.zig` 是 Chase-Lev 工作窃取双端队列。owner 从 bottom 压入和弹出，后进先出。stealer 从 top 取，先进先出。每个工人一条队列。主线程在工人启动前把根放进 0 号队列。空闲人数达到工人数，再偷一整轮都失败，然后退出。退出之后把剩下的任务弹完并销毁。

Zig 0.14 起没有独立的 `@fence`。push 先用 unordered 写槽，再用 release 写 bottom。pop 用 seq_cst 写 bottom，再 seq_cst 读 top。steal 用 seq_cst 读 top，再 seq_cst 读 bottom。旧缓冲通过 `prev` 留到 `deinit`。这是按论文另写的，没有复制示例代码。

`src/parallel.zig` 用 `std.Io.Group.concurrent` 起 N 个长期工人。N 为 1 时不建 Group，调用线程跑同一套循环。`-j 0` 和默认值都是 `std.Thread.getCpuCount()`。工人的返回类型要能转成 `std.Io.Cancelable!void`。每个工人有自己的 Finder、scratch 和按文件分配的输出缓冲。Finder 的模式切片指向调用方，复制是安全的。

遍历到的文件，二进制策略不是 `.none` 时改成 `.quit`。命令行上直接给出的文件仍是 `.report`，除非 `-a`。输出先攒一个文件，再拿一把 `std.Io.Mutex` 一次写出。提前停止用 `std.atomic.Value(bool)`，每个文件和每一块都看。`std.Io` 取消返回 `error.Canceled`。

显式文件保持参数顺序。目录里的结果顺序不稳定，和 rg 对结果时先排序。参数里既有文件又有目录时，一个根走完再走下一个。

并行用的分配器必须能跨线程。示例 CLI 用进程分配器。库测试里两个工人用 `std.heap.smp_allocator`。

## 打印

`src/printer/json.zig` 写 JSON Lines，字段对齐 `rg --json`：begin、match、context、end、summary。没有命中的文件不写事件，调用方仍把它算进 `summary.searches`。一行里的多个命中由打印器再用 Finder 扫这一行。`lines.text` 总是补一个换行；文件末尾本来没有换行时，这里和 rg 不完全一样，所以不逐字节比较。比较的是路径、匹配文本和子匹配区间。耗时字段不必相同。`end` 里的 `bytes_printed` 目前写 0。

示例 CLI 在所有根结束之后写一条 summary。`parallel.Run.write_summary` 默认是 false，单次目录调用自己不写。

`src/printer/files.zig` 给出 `-l`：命中一次就写路径并停止。`--files` 不搜索。没有路径时用 `.`。空结果退出码 1。

`-c` 每个文件一行 `路径:计数`，不另写总计。零次省略，除非打开 `include_zero`。

## 来源接口

`src/source.zig` 是归档和其它非文件系统输入的虚表，并带一个内存目录测试。文件系统的快路径不用它，直接用 `std.Io.Dir`。

## 示例 CLI

`examples/cli.zig` 的 `execute` 接收分配器、`std.Io`、参数和两个 writer。文件按参数顺序搜索。目录交给 `parallel.run`，一次一个根。

模式的优先级是：`--files`，然后 `-q`，然后 `--json`，然后 `-l`，然后 `-c`，最后是文本。`--column` 和 `--json` 都会打开行号。`--binary`、`--no-config`、`--color` 被接受并忽略。`--no-config` 不会关掉 gitignore，和 rg 一样。

## 测试

`zig build test` 跑库测试和示例 CLI 测试。源码里有 80 个 `test` 声明。默认构建不编译 `src/io/mmap_window.zig`，所以跑 79 个：库 72 个，示例 CLI 7 个。`-Dmmap-windows` 多跑窗口映射那 1 个，本机通过。

示例 CLI 用临时文件对照 `rg --no-config --color=never -F -j 1`，覆盖 `-n`、`-C`、`-v`、`-c`、`-i`、`-S`、`--column`、`-m`、`-q`、`-a` 和二进制说明。目录用例在排序后对照 `--files`、字面量搜索、`-g`、`--max-depth`、`--max-filesize`、`-t`、`--no-ignore`、`-l`、`-c`。`--hidden` 期望列出 `.gitignore`，并且不列出 `.git/config`。另一则用例用 `git check-ignore` 核对父目录排除。

`zig build test -Dsanitize-thread=true` 在这台 M2 上退出码 0，墙钟约 29 秒。队列和两个工人的测试都在里面。

内核模糊测试是 P0 跑的，这一阶段没有改查找内核，没有重跑。当时三个过滤器和三个交叉编译目标一起跑完，墙钟 48 秒，退出码都是 0。对照的是标量或 `std.mem` 的朴素查找。

| 测试 | 运行次数 | 独立输入 | 覆盖 |
| --- | ---: | ---: | --- |
| memchr | 100048 → 200063 | 10 | 74/8438（0.88%） |
| packed pair | 100419 | 382 | 233/9073（2.57%） |
| Two-Way | 100429 | 394 | 207/8578（2.41%） |

`zig build check` 在 `x86_64-linux-musl`、`x86_64-windows`、`aarch64-linux-musl` 上编译库、示例和测试，三个目标都通过。`-Dlinux-getdents` 在 `x86_64-linux-musl` 上能编过。在本机 macOS 上，这个选项让 `test` 失败，报错就是上面那句。`-Dmmap-windows` 在本机测试通过，并在这三个交叉目标上编过。Linux 的 `madvise` 走系统调用，musl 不需要再链接 libc。没有在那些目标上运行。

## 和任务说明的偏差

1. 单字节 `find` 调用 `std.mem.findScalarPos`。手写版和 std 的差距在 5% 以内。`findEither`、`findAny`、反向查找和计数仍是手写 SIMD。
2. 默认缓冲是 1 MiB。1 GiB 热文件上它比 256 KiB 和 8 MiB 都快，128 MiB 的缓冲扫描里它也是最快的一档。
3. 默认文件 I/O 是流式 `readPositional`。整文件映射在 1 GiB 端到端上更慢，并且把驻留撑到文件大小，测量写在 `BENCHMARKS.md`。8 MiB 窗口映射是 `-Dmmap-windows`，默认关闭。
4. 不超过 32 字节的模式不回退到 Two-Way。长模式的回退是 50 个候选且平均跳过少于 8 字节，`prefilter_fp_threshold` 只决定这组判断开不开。字母表填充上的 `zrgneedle` 走向量快路径，1 GiB 热缓存 zrg 116.1 ms，rg 127.9 ms。
5. JSON Lines 对齐 `rg --json` 的事件种类和子匹配区间。`lines.text` 总会补换行，所以不逐字节比较。`-l` 和 `--files` 已经接上。
6. 列号默认关闭。`--column` 隐含行号，和 rg 一样。
7. 文件之间的 `--` 在 CLI 里发，不在 Searcher 里发。
8. 默认块是 1 MiB，rg 是 64 KiB。`quit` 按这个块对齐停。NUL 落在块中间时，zrg 会在搜索这一次读入之前停掉，rg 可能已经打出前面的行。样例文件都很小，不受影响。跨块行为有小缓冲单测。
9. 显式文件保持参数顺序，rg 对照仍加 `-j 1`。目录搜索可以并行，结果先排序再比较。
10. 切片上的 `quit`：NUL 落在第一块里就整段不搜；落在后面则先搜完它之前的整块，再停。流式读取是丢掉含 NUL 的那一次读入。
11. 普通搜索不扫描没命中的区域。一条超长且完全不匹配的行，在非反选模式下不会触发 `LineTooLong`。反选和命中行会检查。
12. 本机没有 x86 吞吐数据。`zig build check` 已确认 `x86_64-linux-musl`、`x86_64-windows`、`aarch64-linux-musl` 能编过，没有在那些目标上跑测试。
13. `-i` 在这份 ASCII 文件上比 rg 快，是因为 zrg 只做 ASCII 折叠，rg 的 `-i` 做更多。Unicode 大小写还没有做。
14. `--hidden` 仍然跳过名为 `.git` 的条目。这是有意的，比 rg 严。测试把这个差固定下来。
15. P1 没有按 CPU 特性分派。没有 `-Dcpu`。
16. `-Dlinux-getdents` 和 `-Dmmap-windows` 默认关闭。前者在非 Linux 目标上直接让构建失败。窗口映射在 Linux 上用 `madvise` 系统调用，避免 musl 目标去链接 libc。
17. `--max-filesize` 的后缀按 1024，只认一个 `K`、`M` 或 `G`。
18. Chase-Lev 用 seq_cst 负载和存储代替独立栅栏，因为 Zig 0.14 起没有 `@fence`。
19. JSON 的 summary 由示例 CLI 在全部根结束之后写一条。单次 `parallel.run` 默认不写。`end.stats.bytes_printed` 写 0。
20. Windows 上的文件身份没有设备号，环检测只看 inode。同一卷上的不同文件 inode 不同；跨卷时设备号都是 0。
21. 不读全局 `core.excludesFile`。

还没做：Teddy、Aho-Corasick、C ABI、UTF-16、真正的压缩包读取、Unicode 折叠表。`src/source.zig` 只定了接口和一个内存目录。
