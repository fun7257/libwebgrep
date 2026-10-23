# libwebgrep

可嵌入的字面量行搜索库。用 Zig 0.17.0 和标准库写成，没有第三方依赖，也不链接 C 库。

当前做到 P2：在一段内存、一个 `std.Io.Reader` 或一个已打开的文件里做字面量搜索，也能够遍历目录、应用 gitignore 和 glob、用多个工人并行，并写出 JSON Lines 或文件名列表。多个模式走 `Multi`：全部是单字节时用字节集。能收成不超过 16 种邻接对时用邻接对哈希。放不下时，aarch64 上不超过 32 个非空模式默认用 NEON Teddy，其它架构要显式打开。其余走 Aho-Corasick。锚点字节不超过 16 种时，自动机先做向量预过滤。

## 依赖

- Zig 0.17.0

## 构建

```sh
zig build test
zig build -Doptimize=ReleaseFast
zig build bench -Doptimize=ReleaseFast
```

`bench` 只接受 ReleaseFast。它编译 `bench/micro.zig` 并直接调用库。场景和上次记录在 `BENCHMARKS.md`。

单独跑某一个模糊测试：

```sh
zig build test --fuzz=100K -Doptimize=ReleaseFast -Dfuzz-filter='packed pair 模糊'
```

交叉编译只检查能不能编过：

```sh
zig build check -Dtarget=x86_64-linux-musl
zig build check -Dtarget=x86_64-windows
zig build check -Dtarget=aarch64-linux-musl
```

系统和 CPU 专属的优化用构建选项区分。窗口映射和裸 `getdents64` 默认关闭。没有运行时 CPU 分派。

```sh
zig build test -Dmmap-windows
zig build check -Dtarget=x86_64-linux-musl -Dlinux-getdents
zig build test -Dteddy=off
zig build check -Dtarget=x86_64-linux-musl -Dteddy=ssse3
zig build check -Dtarget=x86_64-linux-musl -Dteddy=avx2
```

`-Dlinux-getdents` 只适用于 Linux 目标。`-Dteddy` 的取值是 `off`、`neon`、`ssse3`、`avx2`。aarch64 默认 `neon`，其它架构默认 `off`。`neon` 只适用于 aarch64，`ssse3` 和 `avx2` 只适用于 x86_64。架构不符时，`test`、`check` 和 `install` 会失败。`-Dmmap-windows` 让大于搜索缓冲的文件按 8 MiB 窗口映射。细节在 `DESIGN.md` 的「构建特性」。SSSE3 和 AVX2 改用 LLVM 后端，不链接 libc。这两档只交叉编译过，没有计时。

在自己的 `build.zig` 里引用：

```zig
const libwebgrep_dep = b.dependency("libwebgrep", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("libwebgrep", libwebgrep_dep.module("libwebgrep"));
```

## 搜索一行内存

Sink 是 comptime 泛型。方法返回 `false` 就停止。行切片指向调用方的 haystack，只在这次回调里使用。可选方法必须声明成 `pub`，`@hasDecl` 才看得见。

```zig
const std = @import("std");
const libwebgrep = @import("libwebgrep");

const Collect = struct {
    lines: usize = 0,

    pub fn matched(self: *Collect, line: libwebgrep.Line) bool {
        _ = line;
        self.lines += 1;
        return true;
    }
};

pub fn countMatches(haystack: []const u8, pattern: []const u8) !usize {
    var finder = try libwebgrep.Finder.init(pattern, .{ .case = .smart });
    var sink: Collect = .{};
    _ = try libwebgrep.searchSlice(Collect, &sink, haystack, "", &finder, .{
        .line_numbers = true,
    });
    return sink.lines;
}
```

`searchSlice` 不分配内存。模式里有换行时 `Finder.init` 返回 `error.PatternHasNewline`。

多个模式用 `Multi`。调用方持有模式字节。构造可能分配自动机，`find` 不分配。只有创建者调用 `deinit`。

```zig
var many = try libwebgrep.Multi.init(allocator, &.{ "foo", "bar" }, .{ .case = .smart });
defer many.deinit();
if (many.find(haystack, 0, .leftmost_first)) |match| {
    _ = haystack[match.start..match.end];
}
```

`leftmost_first` 取起点最靠左的那次，同一起点上更早给出的模式胜出。`earliest` 取更早结束的那次。库的搜索配置默认是 `earliest`。全部是单字节时两种结果相同。智能大小写按每条模式判断：全是小写才忽略大小写。这和 rg 不同，rg 在整组里出现大写就全部区分大小写。

直接拿查找器扫字节，不处理行：

```zig
var finder = try libwebgrep.Finder.init("needle", .{});
if (finder.find(haystack, 0, .earliest)) |match| {
    _ = haystack[match.start..match.end];
}
```

没有上下文时也可以拉着迭代。`Line.bytes` 一直指向原来的切片：

```zig
var iter = libwebgrep.SliceIter(*libwebgrep.Finder){
    .matcher = &finder,
    .haystack = haystack,
    .line_numbers = true,
};
while (iter.next()) |line| {
    _ = line.bytes;
}
```

运行时才决定 Sink 类型时用虚表。缺的方法保持继续搜索：

```zig
const vtable = libwebgrep.anyVtable(Collect);
var any = libwebgrep.AnySink{ .ctx = @ptrCast(&sink), .vtable = &vtable };
_ = try libwebgrep.searchSlice(libwebgrep.AnySink, &any, haystack, "", &finder, .{});
```

## 搜索一个来源

公共入口是 `searchSource`（调用方打开的 reader）和 `searchSourceSlice`（内存切片）。来源标识由调用方分配，库不解释，事件里也不带服务器路径。要搜多个来源，调用方自己打开每一路流，分别传入来源标识。库不接收文件系统路径。

会分配或做 I/O 的函数显式接收分配器和 `std.Io`。热路径上的逐块查找不再分配，也不加锁。默认缓冲 1 MiB，单行上限 2 MiB，并且不超过硬顶。

```zig
const Collect = struct {
    pub fn event(self: *@This(), ev: libwebgrep.Event) bool {
        _ = self;
        _ = ev;
        return true;
    }
};
var found = Collect{};
var reader = std.Io.Reader.fixed("alpha\nbeta\n");
var one = try libwebgrep.Finder.init("alpha", .{});
_ = try libwebgrep.searchSource(Collect, allocator, &found, &reader, "src-1", &one, .{});
_ = try libwebgrep.searchSourceSlice(Collect, &found, "src-2", "beta\n", &one, .{});
```

二进制策略默认是 `.quit`：读到 NUL 就停。`.report` 继续确认有没有匹配，但是不返回行内容。`.none` 按文本处理。调用方可以在硬顶之内改上下文、单行、扫描字节和时间上限。跟随符号链接、读取全局忽略和父目录忽略都不能打开。

## 范围

做了：单模式和多模式字面量、ASCII 大小写和 smart case、行语义、文本、计数、JSON Lines、文件名列表、gitignore、glob、类型过滤、目录并行。多模式能收成邻接对时用哈希预过滤；放不下时，aarch64 默认还可以用 NEON Teddy。

没做：正则、多行匹配、C ABI、Unicode 大小写、压缩包读取、FDR、AVX-512、运行时 CPU 分派。窗口映射和裸 `getdents64` 有源文件，默认不编进去。x86 的 Teddy 要显式打开，还没有计时。见 `DESIGN.md`。
