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

吞吐的 GB/s 是 `字节 / 秒 / 1e9`。没有 x86_64 的计时。下面的端到端是最终二进制同一次 `bench/e2e.sh`。这台机器当时已经跑过好几轮，绝对时间比冷机时高，rg 和 zrg 是同一轮比的。

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

跳过的组：

- 2、3：没有目录遍历和并行，P1 再测。
- 4：`sudo -n true` 失败，不能 drop caches，也没有跑 `purge`。
- 多模式：P2。

## 试过并放弃的读法

整文件 `mmap` 在新鲜进程的 1 GiB 热缓存上是 zrg 192.4 ms、驻留 1026 MiB，同一轮 rg 是 125.4 ms、4.9 MiB。进程内的 128 MiB 微基准曾经觉得映射更快，端到端对不上。文件路径保持 `readPositional` 滚动缓冲。

把 NUL 和模式分成两遍扫，`searchSlice` 停在大约 22 GB/s，接近单字节 memchr 和配对扫描的调和平均。窗口再扫一遍也没有提高。切片路径仍是两遍。流式路径在没有上下文、没有反选时，把 NUL 检查并进已经加载的向量，文本文件只扫一遍。
