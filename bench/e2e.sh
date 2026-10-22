#!/usr/bin/env bash
# 端到端基准。调用方应已用 ReleaseFast 装好 zig-out/bin/zrg。
# 大文件留在 corpus/large/，该目录被 gitignore。
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

zrg=$root/zig-out/bin/zrg
if [[ ! -x $zrg ]]; then
  echo "找不到 $zrg。先运行 zig build -Doptimize=ReleaseFast" >&2
  exit 1
fi

mkdir -p corpus/large bench/tmp

file_size() {
  if stat -f%z "$1" >/dev/null 2>&1; then
    stat -f%z "$1"
  else
    stat -c%s "$1"
  fi
}

big=corpus/large/1g.txt
target=$((1 << 30))
if [[ ! -f $big ]] || [[ $(file_size "$big") -lt $target ]]; then
  echo "生成 $big"
  python3 - "$big" "$target" <<'PY'
import sys
path, target = sys.argv[1], int(sys.argv[2])
# 填充里不放 Z/X/Q，两个锚点字节不会命中，测的是向量快路径。
line = b"the quick brown fox jumps over a dog 0123456789\n"
needle = b"ZXZQNEEDLE\n"
with open(path, "wb") as f:
    left = target - len(needle)
    while left > 0:
        chunk = line * min(left // len(line), 8192)
        if not chunk:
            chunk = b"a" * left
        f.write(chunk)
        left -= len(chunk)
    f.write(needle)
PY
fi

# 每个字母都出现，旧预过滤会在假阳性后掉进标量 Two-Way。
adv=corpus/large/adv.txt
if [[ ! -f $adv ]] || [[ $(file_size "$adv") -lt $target ]]; then
  echo "生成 $adv"
  python3 - "$adv" "$target" <<'PY'
import sys
path, target = sys.argv[1], int(sys.argv[2])
line = b"abcdefghijklmnopqrstuvwxyz\n"
needle = b"zrgneedle\n"
with open(path, "wb") as f:
    left = target - len(needle)
    while left > 0:
        chunk = line * min(left // len(line), 8192)
        if not chunk:
            chunk = b"a" * left
        f.write(chunk)
        left -= len(chunk)
    f.write(needle)
PY
fi

dense=corpus/large/dense.txt
dense_lines=400000
if [[ ! -f $dense ]] || [[ $(wc -l <"$dense" | tr -d ' ') -ne $dense_lines ]]; then
  echo "生成 $dense"
  python3 - "$dense" "$dense_lines" <<'PY'
import sys
path, n = sys.argv[1], int(sys.argv[2])
line = b"alpha match omega\n"
with open(path, "wb") as f:
    block = line * 4096
    left = n
    while left > 0:
        take = min(left, 4096)
        f.write(block if take == 4096 else line * take)
        left -= take
PY
fi

echo "machine: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || true)"
echo "zig: $(zig version)"
echo "rg: $(rg --version | head -n 1)"
echo "zrg: $zrg"
echo "big_bytes: $(file_size "$big")"

run_pair() {
  local name=$1
  shift
  local rg_cmd=$1
  local zrg_cmd=$2
  echo
  echo "## $name"
  hyperfine --shell=bash --warmup 2 --runs 5 \
    --command-name rg --command-name zrg \
    "$rg_cmd" "$zrg_cmd"
}

common_rg=(rg --no-config --color=never -F)
common_zrg=("$zrg" -F)

run_pair "1 单个大文件，热缓存" \
  "${common_rg[*]} ZXZQNEEDLE $big >/dev/null" \
  "${common_zrg[*]} ZXZQNEEDLE $big >/dev/null"

echo
echo "## 2 真实源码树，单线程"
echo "跳过：目录遍历在 P1。"
echo
echo "## 3 真实源码树，多线程"
echo "跳过：目录遍历和并行调度在 P1。"
echo
echo "## 4 冷缓存"
if sudo -n true >/dev/null 2>&1; then
  echo "有 sudo，但本阶段不主动清缓存，避免影响正在跑的机器。"
else
  echo "跳过：没有免密 sudo，不能 drop caches / purge。"
fi

run_pair "1b 字母表填充，热缓存" \
  "${common_rg[*]} zrgneedle $adv >/dev/null" \
  "${common_zrg[*]} zrgneedle $adv >/dev/null"

run_pair "5 密集匹配" \
  "${common_rg[*]} match $dense >/dev/null" \
  "${common_zrg[*]} match $dense >/dev/null"

run_pair "6 忽略大小写" \
  "${common_rg[*]} -i zxzqneedle $big >/dev/null" \
  "${common_zrg[*]} -i zxzqneedle $big >/dev/null"

echo
echo "## 6b smart case，小写模式"
run_pair "smart case" \
  "${common_rg[*]} -S zxzqneedle $big >/dev/null" \
  "${common_zrg[*]} -S zxzqneedle $big >/dev/null"
