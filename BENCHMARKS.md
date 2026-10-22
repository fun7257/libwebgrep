# 基准

只记录 ReleaseFast。Debug 在 x86_64 上会走 Zig 自研后端，这里的宿主虽然是 aarch64，基准仍然只用 ReleaseFast。

## 环境

| 项 | 值 |
| --- | --- |
| 机器 | Apple M2，8 核，8 GiB |
| 系统 | Darwin arm64 |
| Zig | 0.17.0 |
| ripgrep | 15.2.0（本机是 NEON 构建） |
| hyperfine | 2.0.0，`--shell=bash --warmup 2 --runs 5` |
| 向量宽度 | 16 |

吞吐的 GB/s 是 `字节 / 秒 / 1e9`。没有 x86_64 的计时。1 GiB 那几组是 P0 最终二进制同一次 `bench/e2e.sh`。这台机器当时已经跑过好几轮，绝对时间比冷机时高，rg 和 zrg 是同一轮比的。源码树是 P1 另一次运行，写在那张表后面。

## 内核微基准

64 MiB 文本，每 64 字节一个换行，末尾放一个 `NEEDLE`。单字节查找的是不存在的 `0xff`，避免命中后提前返回。每次调用前有编译器内存屏障，并翻转 `buf[0]`，避免被当成死代码删掉。

决定 `find` 走 std 的那次对比：手写 55.769 GB/s，`std.mem.findScalar` 54.631 GB/s，比值 1.021。后来同一次运行里转调 std 的 `find` 是 53.423 GB/s，std 是 55.595 GB/s，比值 0.961。两次都在 5% 以内，所以单字节 `find` 保持调用 std。

当前代码同一次运行：

| 项 | GB/s |
| --- | ---: |
| `memchr.find`（std） | 52.110 |
| 手写 `findEither` | 56.456 |
| `std.mem.findScalar` | 52.114 |
| find / std | 1.000 |
| findEither / std | 1.083 |
| Finder，`NEEDLE`，区分大小写 | 38.874 |
| Finder，`needle`，ASCII 忽略大小写 | 13.864 |
| Finder，`needle`，smart case | 13.996 |
| `searchSlice`，同一块缓冲，含 NUL 预扫 | 21.844 |
| Finder，字母表填充上的 `zrgneedle` | 39.477 |

128 MiB 文件、热缓存、`searchFile`、每种缓冲三次取中位数：

| 缓冲 | GB/s |
| --- | ---: |
| 64 KiB | 9.521 |
| 128 KiB | 9.737 |
| 256 KiB | 10.010 |
| 1 MiB | 10.178 |
| 一次读完整文件再搜 | 4.965 |

## 端到端

`hyperfine` 对比 `rg --no-config --color=never -F` 和 `zig-out/bin/zrg -F`。输出丢到 `/dev/null`。必须加 `--shell=bash`，否则 hyperfine 2.0 会把重定向当成文件名。

验收文件 `corpus/large/1g.txt` 是 1073741824 字节。填充行是 `the quick brown fox jumps over a dog 0123456789`，文件末尾一行 `ZXZQNEEDLE`。填充里没有 `Z`、`X`、`Q`。`corpus/large/adv.txt` 同样是 1 GiB，每行是 `abcdefghijklmnopqrstuvwxyz`，末尾一行 `zrgneedle`。

| 组 | rg | zrg | zrg 相对 rg | 内存 rg / zrg |
| --- | ---: | ---: | ---: | ---: |
| 1. 1 GiB 热缓存，`ZXZQNEEDLE` | 131.7 ms ± 3.4 | 116.9 ms ± 3.2 | −11.2% | 4.9 / 2.8 MiB |
| 1b. 1 GiB 字母表填充，`zrgneedle` | 127.9 ms ± 4.7 | 116.1 ms ± 3.5 | −9.2% | 4.9 / 2.8 MiB |
| 5. 密集匹配，40 万行 `match` | 17.7 ms ± 0.4 | 13.8 ms ± 0.5 | −22.1% | 4.9 / 2.8 MiB |
| 6. `-i zxzqneedle`，同一 1 GiB 文件 | 208.9 ms ± 1.5 | 169.2 ms ± 3.4 | −19.0% | 5.1 / 2.8 MiB |
| 6b. `-S zxzqneedle` | 211.8 ms ± 2.3 | 168.1 ms ± 4.5 | −20.6% | 5.1 / 2.8 MiB |

按 1e9 字节/秒，第 1 组 rg 约 8.15 GB/s，zrg 约 9.19 GB/s。zrg 这组最慢的一次是 121.1 ms，仍快于 rg 最快的 129.1 ms。

第 6 组 zrg 更快，是因为只做 ASCII 折叠。rg 的 `-i` 在这个全 ASCII 文件上仍比它自己的区分大小写慢。

同一最终二进制上另测的两项，不在 `e2e.sh` 里：

| 组 | rg | zrg | zrg 相对 rg |
| --- | ---: | ---: | ---: |
| 单字节 `Z`，1 GiB | 104.9 ms ± 1.3 | 94.5 ms ± 0.5 | −9.9% |
| `-c e`，1 GiB，几乎每行都命中 | 469.0 ms ± 48.8 | 397.4 ms ± 3.6 | −15.3% |

`-c e` 的 rg 有一次明显偏慢的首跑，中位数仍高于 zrg。

源码树是另一次运行，没有重测上面的 1 GiB 文件。树是 `/Users/fun/zig-source/zig-aarch64-macos-0.17.0/lib`，19501 个文件，约 228 MiB。模式是 `OutOfMemory`。跑之前先对照过：`zrg --files` 和 `rg --files` 排序后都是 19501 行，完全一致；`-F -j 1 OutOfMemory` 排序后都是 629 行，完全一致。hyperfine 仍是 `--shell=bash --warmup 2 --runs 5`。缓存已经被这次对照走热。

| 组 | rg | zrg | zrg 相对 rg | 内存 rg / zrg |
| --- | ---: | ---: | ---: | ---: |
| 2. 源码树，`-j 1` | 397.5 ms ± 2.0 | 374.6 ms ± 0.8 | −5.8% | 5.3 / 3.1 MiB |
| 3. 源码树，默认线程 | 168.4 ms ± 2.9 | 179.2 ms ± 4.3 | +6.4% | 11.2 / 8.2 MiB |

这台机器是 8 核，默认线程就是 8。第 3 组 zrg 比 rg 慢 6.4%，179.2 / 168.4 = 1.064，落在 rg 的 110% 以内。zrg 这次最慢的一次是 185.1 ms。

## 多模式

另一次运行，没有重测上面的 1 GiB 文件，也没有重测源码树。文件是 `corpus/large/multi.txt`，33554432 字节。填充行和 1 GiB 那组相同，每 64 行在前面加上轮换的 `alpha`、`beta`、`gamma`、`delta`。模式文件先写这四个词，其余是 `zq` 加四位编号再加 `miss`，长度至少 2，都不含换行。`rg -F -c -f` 和 zrg 的命中行数都是 10902，10、100、1000 三个集合一样。hyperfine 仍是 `--shell=bash --warmup 2 --runs 5`。命令是 `rg -f` 对 `zrg -f`，两边都带原来的 `-F`。

下面三行用的二进制是当时的 `zig-out/bin/zrg`，Teddy 关闭，三条都走 Aho-Corasick。相对差是 hyperfine 打印的。

| 组 | rg | zrg | zrg 相对 rg | 内存 rg / zrg |
| --- | ---: | ---: | ---: | ---: |
| 7. 10 个模式 | 10.4 ms ± 0.2 | 93.9 ms ± 0.3 | +804.4% | 5.0 / 3.1 MiB |
| 8. 100 个模式 | 13.0 ms ± 0.2 | 94.4 ms ± 0.4 | +626.5% | 5.9 / 3.7 MiB |
| 9. 1000 个模式 | 12.7 ms ± 0.2 | 98.7 ms ± 0.3 | +678.6% | 6.7 / 9.5 MiB |

内存相对差分别是 −38.4%、−37.1%、+43.1%。10 个模式大约是 rg 的 9.0 倍，100 个大约 7.3 倍，1000 个大约 7.8 倍。

同一文件上又单独跑了一轮 10 个模式，用来比较自动机和 NEON。NEON 二进制是 `zig build -Doptimize=ReleaseFast -Dteddy=neon`。这一轮的 rg 和自动机也重新计了时。命中行数仍是 10902。

| 实现 | 时间 | 相对这一轮 rg | 内存 |
| --- | ---: | ---: | ---: |
| rg 15.2.0 | 10.6 ms ± 0.3 | — | 5.0 MiB |
| zrg，Aho-Corasick | 93.4 ms ± 0.1 | +783.7% | 3.1 MiB |
| zrg，`-Dteddy=neon` | 57.6 ms ± 0.3 | +445.0% | 3.0 MiB |

NEON 相对自动机是 57.6 / 93.4，大约快 38%。相对 rg 仍是大约 5.5 倍，内存 −40.5%。100 和 1000 个模式超过 32 条，Teddy 用不上，上面那两行就是它们的数字。因为 NEON 比自动机快，并且超出噪声，aarch64 的默认改成 `neon`。它没有超过 rg。x86 的 SSSE3 和 AVX2 没有计时，默认仍是 `off`。

跳过的组：

- 4：`sudo -n true` 失败，不能 drop caches，也没有跑 `purge`。多模式这次也没有清缓存。
- 窗口映射和裸 `getdents64` 仍是默认关闭的构建选项，没有放进这张表。
- 1 GiB 和源码树没有为多模式重跑。

## 试过并放弃的读法

整文件 `mmap` 在新鲜进程的 1 GiB 热缓存上是 zrg 192.4 ms、驻留 1026 MiB，同一轮 rg 是 125.4 ms、4.9 MiB。进程内的 128 MiB 微基准曾经觉得映射更快，端到端对不上。文件路径保持 `readPositional` 滚动缓冲。

把 NUL 和模式分成两遍扫，`searchSlice` 停在大约 22 GB/s，接近单字节 memchr 和配对扫描的调和平均。窗口再扫一遍也没有提高。切片路径仍是两遍。流式路径在没有上下文、没有反选时，把 NUL 检查并进已经加载的向量，文本文件只扫一遍。
