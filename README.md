# zrg

可嵌入的字面量行搜索库。用 Zig 0.17.0 和标准库写成，没有第三方依赖，也不链接 C 库。

当前做到 P1：在一段内存、一个 `std.Io.Reader` 或一个已打开的文件里做单模式字面量搜索，也能够遍历目录、应用 gitignore 和 glob、用多个工人并行，并写出 JSON Lines 或文件名列表。多模式还没做。

示例程序 `zrg` 只用来对照 ripgrep 和跑基准，不追求兼容 `rg` 的全部参数。

## 依赖

- Zig 0.17.0
- 对照测试需要本机的 `rg`。基准还需要 `hyperfine`。

## 构建

```sh
zig build test
zig build -Doptimize=ReleaseFast
zig build bench -Doptimize=ReleaseFast
```

`bench` 只接受 ReleaseFast。它先跑内核微基准，再跑 `bench/e2e.sh`。

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

系统和 CPU 专属的优化用构建选项打开，默认都关闭。P1 没有 CPU 分派。

```sh
zig build test -Dmmap-windows
zig build check -Dtarget=x86_64-linux-musl -Dlinux-getdents
```

`-Dlinux-getdents` 只适用于 Linux 目标。在其它系统上，`test`、`check` 和 `install` 会失败。`-Dmmap-windows` 让大于搜索缓冲的文件按 8 MiB 窗口映射。细节在 `DESIGN.md` 的「构建特性」。

在自己的 `build.zig` 里引用：

```zig
const zrg_dep = b.dependency("zrg", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zrg", zrg_dep.module("zrg"));
```

## 搜索一行内存

Sink 是 comptime 泛型。方法返回 `false` 就停止。行切片指向调用方的 haystack，只在这次回调里使用。可选方法必须声明成 `pub`，`@hasDecl` 才看得见。

```zig
const std = @import("std");
const zrg = @import("zrg");

const Collect = struct {
    lines: usize = 0,

    pub fn matched(self: *Collect, line: zrg.Line) bool {
        _ = line;
        self.lines += 1;
        return true;
    }
};

pub fn countMatches(haystack: []const u8, pattern: []const u8) !usize {
    var finder = try zrg.Finder.init(pattern, .{ .case = .smart });
    var sink: Collect = .{};
    _ = try zrg.searchSlice(Collect, &sink, haystack, "", &finder, .{
        .line_numbers = true,
    });
    return sink.lines;
}
```

`searchSlice` 不分配内存。模式里有换行时 `Finder.init` 返回 `error.PatternHasNewline`。

直接拿查找器扫字节，不处理行：

```zig
var finder = try zrg.Finder.init("needle", .{});
if (finder.find(haystack, 0, .earliest)) |match| {
    _ = haystack[match.start..match.end];
}
```

没有上下文时也可以拉着迭代。`Line.bytes` 一直指向原来的切片：

```zig
var iter = zrg.SliceIter(*zrg.Finder){
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
const vtable = zrg.anyVtable(Collect);
var any = zrg.AnySink{ .ctx = @ptrCast(&sink), .vtable = &vtable };
_ = try zrg.searchSlice(zrg.AnySink, &any, haystack, "", &finder, .{});
```

## 搜索一个文件

会分配或做 I/O 的函数显式接收分配器和 `std.Io`。热路径上的逐块查找不再分配，也不加锁。

```zig
pub fn searchPath(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    pattern: []const u8,
    writer: *std.Io.Writer,
) !zrg.Result {
    var file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    var finder = try zrg.Finder.init(pattern, .{ .case = .insensitive });
    var printer = zrg.TextPrinter{ .writer = writer, .show_path = true };
    return zrg.searchFile(
        zrg.TextPrinter,
        allocator,
        io,
        &printer,
        file,
        path,
        &finder,
        .{ .line_numbers = true, .before = 1, .after = 1 },
    );
}
```

`searchReader` 的形状相同，只是把文件换成 `*std.Io.Reader`。默认缓冲 1 MiB，单行上限 2 MiB。超长行返回 `error.LineTooLong`，缓冲不会一直涨。

内置打印器：

- `TextPrinter`：`路径:行号:列号:文本`，上下文用 `-`，组之间用 `--`。
- `CountPrinter`：单输入写 `N`，多输入写 `路径:N`。
- `Json`：对齐 `rg --json` 的 JSON Lines。没有命中的文件不写事件。
- `Files`：命中一次就写路径，对应 `-l`。

二进制策略：

- `.quit`：读到 NUL 就停。遍历发现的文件用这个，除非 `-a`。
- `.report`：显式文件的默认。确认有匹配后只报告二进制说明。
- `.none`：不检测，对应示例 CLI 的 `-a`。

目录搜索在 `zrg.parallel.run`。每个工人有自己的查找器、搜索缓冲和 Chase-Lev 队列。忽略规则在发布之后只读。热路径上的逐块查找仍然不分配、不加锁；锁只包住一个文件的输出。

## 示例命令

```sh
zig build run -Doptimize=ReleaseFast -- -n -C 1 needle path/to/file
```

没有路径时读标准输入。`--files` 没有路径时列当前目录。退出码和 `rg` 一样：0 有匹配，1 没有，2 是用法或 I/O 错误。

目录参数会遍历。显式文件保持参数顺序。目录里的输出顺序不稳定。默认跳过隐藏文件，并且始终不进入名为 `.git` 的条目。`-g`、`-t`、`--max-depth`、`--max-filesize`、`-j`、`--hidden`、`--no-ignore`、`--follow`、`-l`、`--json` 见 `zrg --help`。

## 范围

做了：单模式字面量、ASCII 大小写和 smart case、行语义、文本、计数、JSON Lines、文件名列表、gitignore、glob、类型过滤、目录并行。

没做：正则、多行匹配、多模式、C ABI、Unicode 大小写、压缩包读取。窗口映射和裸 `getdents64` 有源文件，默认不编进去。见 `DESIGN.md`。
