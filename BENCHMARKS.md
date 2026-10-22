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

吞吐的 GB/s 是 `字节 / 秒 / 1e9`。没有 x86_64 的计时。

## 内核微基准

64 MiB 文本，每 64 字节一个换行，末尾放一个 `NEEDLE`。单字节查找的是不存在的 `0xff`，避免命中后提前返回。每次调用前有编译器内存屏障，并翻转 `buf[0]`，避免被当成死代码删掉。

改用 std 之前，用来决定 `find` 走哪条实现：

| 项 | GB/s |
| --- | ---: |
| 手写 memchr `find` | 55.769 |
| `std.mem.findScalar` | 54.631 |
| 手写 / std | 1.021 |

当前代码（`find` 已转调 std）同一次运行：

| 项 | GB/s |
| --- | ---: |
| `memchr.find`（std） | 53.423 |
| 手写 `findEither`（两个针都是 `0xff`） | 59.464 |
| `std.mem.findScalar` | 55.595 |
| find / std | 0.961 |
| findEither / std | 1.070 |
| Finder，`NEEDLE`，区分大小写 | 26.376 |
| Finder，`needle`，ASCII 忽略大小写 | 26.359 |
| Finder，`needle`，smart case | 26.413 |
| `searchSlice`，同一块缓冲 | 17.365 |

`find` 和 std 的第二次比值低于 1，是测量噪声。两次差距都在 5% 以内。

128 MiB 文件、`searchFile`、每种缓冲三次取中位数：

| 缓冲 | GB/s |
| --- | ---: |
| 64 KiB | 8.247 |
| 128 KiB | 8.496 |
| 256 KiB | 8.597 |
| 1 MiB | 8.727 |

## 端到端

`hyperfine` 对比 `rg --no-config --color=never -F` 和 `zig-out/bin/zrg -F`。输出丢到 `/dev/null`。必须加 `--shell=bash`，否则 hyperfine 2.0 会把重定向当成文件名。

验收文件 `corpus/large/1g.txt` 是 1073741824 字节。填充行是 `the quick brown fox jumps over a dog 0123456789`，文件末尾一行 `ZXZQNEEDLE`。填充里没有 `Z`、`X`、`Q`，packed pair 不会切到 Two-Way。

| 组 | rg | zrg | zrg 相对 rg |
| --- | ---: | ---: | ---: |
| 1. 单个 1 GiB 文件，热缓存，`ZXZQNEEDLE` | 120.8 ms ± 6.2 | 128.4 ms ± 4.1 | 时间 +6.3%，吞吐是 rg 的 94.1% |
| 5. 密集匹配，40 万行 `match` | 16.3 ms ± 0.3 | 12.5 ms ± 0.1 | −23.3% |
| 6. `-i zxzqneedle`，同一 1 GiB 文件 | 197.0 ms ± 0.3 | 127.8 ms ± 0.8 | −35.1% |
| 6b. `-S zxzqneedle` | 198.1 ms ± 1.6 | 128.6 ms ± 0.6 | −35.1% |

第 1 组的内存：rg 4.9 MiB，zrg 2.2 MiB。按 1e9 字节/秒，rg 约 8.89 GB/s，zrg 约 8.36 GB/s。

第 6 组 zrg 更快，是因为只做 ASCII 折叠。rg 的 `-i` 在这个全 ASCII 文件上仍比它自己的区分大小写慢（197 ms 对 121 ms）。

跳过的组：

- 2、3：没有目录遍历和并行，P1 再测。
- 4：`sudo -n true` 失败，不能 drop caches，也没有跑 `purge`。
- 多模式：P2。

## 没有当作验收的一次测量

同一台机器、同样的热缓存，填充是含全部字母的句子，模式是 `zrgneedle`。`z` 每行都出现，packed pair 立刻超过假阳性阈值，剩下约 1 GiB 走标量 Two-Way。

| 程序 | 时间 |
| --- | ---: |
| rg | 118.5 ms ± 0.5 |
| zrg | 558.6 ms ± 1.3 |

大约 4.7 倍。这是回退路径的特征，不是读路径的问题：换掉语料之后，同一个二进制是 128.4 ms。P0 不据此改 Two-Way。
