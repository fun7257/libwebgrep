# 基准

只记录 ReleaseFast 下 `bench/micro.zig` 的进程内计时。命令是 `zig build bench -Doptimize=ReleaseFast`。不启动命令行，也不和 ripgrep 比。

每一行是 `scenario 名字 bytes 字节数 gbs 吞吐 iters 次数 sink 累计结果`。吞吐是 `字节 / 秒 / 1e9`。先空跑一次，不计入。之后至少再跑 300 ms，并且至少两次。每次调用前有内存屏障。会改写缓冲的查找还会翻转第一个字节，避免被当成死代码删掉。`sink` 是各次返回值的和。返回值和下面写的预期不一致时，这次基准失败，不会把空结果记成吞吐。

单模式 `Finder` 在计时外建好，循环里只清统计再查找。多模式在计时外建好。模式表是 `src/finder/multi.zig` 里的 `scenario_bytes`、`scenario_pairs`、`scenario_teddy`、`scenario_ac`，和库测试共用。目录场景每次都走完整的 `parallel.run`，包含建工人和拆工人。

没有 x86_64 的计时。

## 环境

| 项 | 值 |
| --- | --- |
| 日期 | 2026-10-23 |
| 机器 | Apple M2，8 核，8 GiB |
| 系统 | Darwin arm64 |
| Zig | 0.17.0 |
| 优化 | ReleaseFast |
| 向量宽度 | 16 |
| Teddy | 默认 neon。这次 `multi_teddy` 落到 `teddy` |
| 目录默认线程 | `resolveThreads(0)` = 4，本机性能核数 |

## 测试怎么锁住这些场景

`zig build test` 不跑计时。它锁契约：

- `基准场景的模式落到各自的引擎`：四组模式分别落到字节集、邻接对、Teddy（关掉 Teddy 时这组改走自动机）、自动机。样例文本上，字节集、Teddy、自动机没有命中，邻接对命中末尾的 `NEEDLE`。再种进一个模式字节，确认没命中不是空转。
- `基准场景的切片命中和基准同一配置`：同一形状的文本，用默认 `searchSlice` 配置。`NEEDLE` 区分大小写、`needle` 忽略大小写、`needle` 的 smart case 都是 1 行。四组多模式的行数是 0、1、0、0。

文本形状是 `fillScenarioText`：全是 `a`，每 64 字节一个换行，末尾盖上 `NEEDLE\n`。大基准用 64 MiB。文件基准是同一形状的 128 MiB 正文再加末尾那 7 个字节。

## 2026-10-23 这一次

```
libwebgrep bench width 16 walk_default_threads 4
scenario memchr_find bytes 67108864 gbs 48.260 iters 216 sink 0
scenario memchr_either bytes 67108864 gbs 26.494 iters 119 sink 0
scenario std_find_scalar bytes 67108864 gbs 50.595 iters 227 sink 0
scenario finder_sensitive bytes 67108864 gbs 35.747 iters 160 sink 10737417120
scenario finder_ignore bytes 67108864 gbs 13.510 iters 61 sink 4093640277
scenario finder_smart bytes 67108864 gbs 13.514 iters 61 sink 4093640277
scenario search_slice bytes 67108864 gbs 21.007 iters 94 sink 94
engine multi_bytes bytes
scenario multi_bytes bytes 67108864 gbs 22.906 iters 103 sink 0
engine multi_pairs pairs
scenario multi_pairs bytes 67108864 gbs 19.423 iters 87 sink 87
engine multi_teddy teddy
scenario multi_teddy bytes 67108864 gbs 2.789 iters 13 sink 0
engine multi_ac ac
scenario multi_ac bytes 67108864 gbs 1.044 iters 5 sink 0
scenario finder_alphabet bytes 67108864 gbs 35.896 iters 161 sink 10804525333
scenario file_64KiB bytes 134217735 gbs 9.584 iters 22 sink 22
scenario file_128KiB bytes 134217735 gbs 9.781 iters 22 sink 22
scenario file_256KiB bytes 134217735 gbs 10.063 iters 23 sink 23
scenario file_1MiB bytes 134217735 gbs 10.242 iters 23 sink 23
scenario file_readall bytes 134217735 gbs 5.041 iters 12 sink 12
scenario walk_1 bytes 786432 gbs 0.157 iters 60 sink 540
scenario walk_default bytes 786432 gbs 0.371 iters 142 sink 1278
```

`find / std` = 48.260 / 50.595 = 0.954。`memchr.find` 就是 `std.mem.findScalarPos`。`memchr_either` 同时找 `0xff` 和 `0xfe`，两个都不在文本里，工作量和单字节查找不同。

### 64 MiB 文本

缓冲 67108864 字节。单字节查找的是不存在的字节，每次返回 0。`Finder` 每次返回 `NEEDLE` 的起点，也就是 `67108864 - 7`。`search_slice` 和多模式每次返回命中行数。

| 场景 | 每次结果 | GB/s |
| --- | --- | ---: |
| `memchr_find` | 未命中 | 48.260 |
| `memchr_either` | 两个字节都未命中 | 26.494 |
| `std_find_scalar` | 未命中 | 50.595 |
| `finder_sensitive`，`NEEDLE` | 命中末尾 | 35.747 |
| `finder_ignore`，`needle`，忽略大小写 | 命中末尾 | 13.510 |
| `finder_smart`，`needle`，smart case | 命中末尾 | 13.514 |
| `search_slice`，`NEEDLE`，默认配置 | 1 行 | 21.007 |
| `multi_bytes`，`Q` 和 `Z`，字节集 | 0 行 | 22.906 |
| `multi_pairs`，`NEEDLE` 和 `ZXZQ`，邻接对 | 1 行 | 19.423 |
| `multi_teddy`，17 条双字节，Teddy | 0 行 | 2.789 |
| `multi_ac`，33 条双字节，自动机 | 0 行 | 1.044 |
| `finder_alphabet`，`libwebgrep` | 命中末尾 | 35.896 |

`needle` 全是小写，smart case 会折叠，所以和忽略大小写同一条路径，两次分别是 13.510 和 13.514。

`search_slice` 用默认配置。默认 `binary` 是 `report`，切片路径会先把整段扫一遍 NUL。这是嵌入时调用的入口，吞吐低于单独的 `Finder.find`。

四组多模式的模式不同，数字是这一类查询在这份文本上的代价。字节集是两个缺失单字节。邻接对带一个末尾命中。Teddy 和自动机是整段未命中。17 条超过邻接对的 16 条上限，33 条超过 Teddy 的 32 条上限。能收成邻接对的查询不会走到后面两档。

字母表场景把同一块缓冲改成重复的 `abcdefghijklmnopqrstuvwxyz`。`libwebgrep` 只出现在末尾。35.896 和区分大小写的 `NEEDLE` 同一档，预过滤没有掉进标量确认。

### 128 MiB 文件

`bench/tmp/sweep.txt`，正文 128 MiB，再加末尾 `NEEDLE\n`，共 134217735 字节。同一次进程里写完再反复读，是热缓存。`searchFile` 加空 sink，模式 `NEEDLE`。每次 1 行，并且 `bytes_read` 必须等于文件长度。缓冲按调用传入。`file_readall` 的缓冲等于文件长度，一次读完再搜。

由 GB/s 折回的单次时间是 `134217735 / gbs / 1e9`。

| 缓冲 | GB/s | 单次 |
| --- | ---: | ---: |
| 64 KiB | 9.584 | 14.0 ms |
| 128 KiB | 9.781 | 13.7 ms |
| 256 KiB | 10.063 | 13.3 ms |
| 1 MiB | 10.242 | 13.1 ms |
| 一次读完再搜 | 5.041 | 26.6 ms |

四档里 1 MiB 最快。一次读完再搜大约用掉两倍时间。默认缓冲保持 1 MiB。

### 目录

`bench/tmp/walk`。`flat/` 里 128 个文件，另外 8 个目录各 32 个，一共 384 个文件。每个文件 2048 字节，合计 786432 字节。每个目录的 `f000.txt` 末尾有一个 `NEEDLE`，一共 9 个命中。`read_ignore` 关闭，输出是计数，写进丢弃 writer。

`walk_1` 指定 1 个线程。`walk_default` 传入 0，由调度层选成这次的 4。每次迭代都是一次完整的 `parallel.run`。单次时间是 `786432 / gbs / 1e9`。

| 场景 | GB/s | 单次 | 命中文件 |
| --- | ---: | ---: | ---: |
| `walk_1` | 0.157 | 5.0 ms | 9 |
| `walk_default` | 0.371 | 2.1 ms | 9 |

这 768 KiB 里大部分时间花在打开文件和建立工人，不花在匹配。这个 GB/s 不和上面的内存扫描放在一起比。4 个线程这次大约是单线程的 2.4 倍。
