# libwebgrep 功能检查清单

libwebgrep 原名 zrg（webgrep core），是用纯 Zig 0.17 编写的服务端搜索库，面向公开的 Web 服务，可以搜索一切能以流的方式读取的文本，不包含任何 CLI 功能。仓库里 SELF_CHECK.md 和 BENCHMARK_SPEC.md 中提到的 zrg 都指本库。

## 一、审查规则（给执行审查的 AI）
1. 只读审查：对照代码库逐项判断状态，不修改任何代码。
2. 每项的状态只能取以下之一：
   - DONE：已实现，并且有测试覆盖该行为
   - PARTIAL：只实现了一部分，或者已实现但没有测试
   - TODO：未实现
   - UNKNOWN：无法判断，必须写明原因
   - ABSENT-OK：标为[禁止]或[不做]的项，确认代码中不存在（这是期望状态）
   - VIOLATION：标为[禁止]的项，代码中却存在
   - EXTRA：标为[不做]的项，代码中存在（属于多余代码，不影响上线）
3. 判 DONE 必须同时给出实现位置（文件:行号）和测试名。只有实现、没有测试的，一律判 PARTIAL。
4. [禁止] 项要写明用了什么方法确认它不存在（例如搜索了哪些 API 调用），并给出搜索结果。
5. 标签含义：
   - 优先级：[MVP] 首个公开版本必须具备；[后续] 以后再做；[禁止] 公开服务中不得存在；[不做] CLI 专属功能，不需要
   - 阶段：P0 查找内核与单输入；P1 文件管线；P2 多模式；正则阶段
   - 归属：core 表示由库自己实现；能力 表示库只提供数据或钩子，呈现由 Web 层完成
   - 括号里的 rg 参数只是功能的参照来源，不要求参数名一致
6. 文中出现的数值（如上下文 ≤10 行、单行 ≤64 KiB）只是建议的数量级。审查只检查"有上限，且可以由服务层配置"，不检查具体数值。

## 二、输入与来源
- [x] A01 [MVP][P0][core] 输入抽象为"来源"（reader + 来源 ID）；公共 API 不接受用户提供的文件系统路径（rg PATH；CWE-22）
- [ ] A02 [MVP][P0][core] 支持不可回退的流式输入，不依赖 seek 或 mmap
- [ ] A03 [后续][P1][core] 模式列表输入：每行一个模式，空行匹配所有行；只接受文本，不读服务器上的文件（rg -f）
- [ ] A04 [后续][P1][core] gzip 在进程内流式解压，按 Content-Encoding 或文件魔数检测：
  - 解压后的字节计入扫描预算
  - 设有解压输出上限和压缩比上限（rg -z；CWE-409）
- [ ] A05 [后续][core] 其他压缩格式（bzip2、xz、zstd 等）也在进程内解压，同样受 A04 的限制
- [ ] A06 [禁止] 存在任何执行外部命令或创建子进程的代码路径（rg --pre / --pre-glob）
- [ ] A07 [禁止] 调用外部解压程序（rg -z 原本的实现方式）

## 三、匹配语义
- [ ] B01 [MVP][P0][core] 字面量匹配；在正则阶段之前，这是默认且唯一的匹配模式（rg -F）
- [ ] B02 [MVP][P0][core] 多模式 OR 匹配，并限制模式数量和总长度（rg 多次 -e）
- [ ] B03 [MVP][P0][core] 区分大小写，作为默认行为（rg -s）
- [ ] B04 [MVP][P0][core] ASCII 范围内忽略大小写；API 文档写明目前只支持 ASCII 折叠（rg -i）
- [ ] B05 [后续][core] 基于 Unicode 简单大小写折叠的忽略大小写（rg -i 的完整语义）
- [ ] B06 [MVP][P0][core] 智能大小写（rg -S）：
  - 模式全为小写时忽略大小写，否则区分大小写
  - 对每个模式分别判断，并在文档中说明这与 rg 的整体判断方式不同
- [ ] B07 [MVP][P0][core] 整词匹配（rg -w）：
  - 通过检查匹配前后的字符边界实现
  - 采用半边界语义，例如 `-2` 能在 `(-2)` 中命中
- [ ] B08 [MVP][P0][core] 整行匹配，与 B07 同时开启时以整行为准，判定时正确处理行尾的 \r（rg -x）
- [ ] B09 [MVP][P0][core] 按行反选，与"无匹配来源列表"（G05）是两个不同的功能（rg -v）
- [ ] B10 [MVP][P0][core] 每个来源的匹配行数上限，达到后立即停止读取并关闭上游（rg -m）
- [x] B11 [MVP][P0][core] 存在性查询：找到第一个匹配就返回，并取消上游读取（rg -q）
- [ ] B12 [MVP][P0 末或 P1][core] AND/NOT 链式过滤：同时满足所有"包含"和"不包含"条件的行才输出（参照 Loki 的 |= 与 !=；rg 没有此功能）
- [ ] B13 [后续][core] 有序数据优化：出现过匹配之后，遇到第一条不匹配的行就停止（rg --stop-on-nonmatch）
- [ ] B14 [后续][能力] 替换预览：只在结果中给出替换后的文本，不修改数据，匹配区间附带替换文本（rg -r）
- [ ] B15 [后续][P2][core] 高性能多模式实现：字节集、Teddy、Aho-Corasick
- [ ] B16 [正则阶段][core] 只使用线性时间的正则引擎；编译后的大小设服务端硬上限，不开放给用户调整（rg --regex-size-limit / --dfa-size-limit）
- [ ] B17 [正则阶段][core] 跨行匹配只在有界窗口内进行，不允许一直读到流结束（rg -U / --multiline-dotall）
- [ ] B18 [禁止] 回溯式正则引擎或 PCRE2（rg -P、--engine pcre2/auto）

## 四、行与编码
- [ ] C01 [MVP][P0][core] 默认以 LF 作为行终止符
- [ ] C02 [MVP][P0][core] 自动识别 CRLF：判定整行匹配时，以及返回行内容时，都去掉行尾的 \r（rg --crlf）
- [ ] C03 [MVP][P0][core] 支持以 NUL 作为行终止符，这种模式下同时按文本处理（rg --null-data）
- [ ] C04 [MVP][P0][core] 在流的开头嗅探 BOM（rg -E auto）：
  - 识别 UTF-8、UTF-16LE、UTF-16BE
  - UTF-16 先转成 UTF-8 再搜索
  - 非法字节序列替换为 U+FFFD
- [ ] C05 [MVP][P0][core] 原始字节模式，不做任何转码（rg -E none）
- [ ] C06 [后续][core] 支持其他编码（如 GBK，按 WHATWG 编码标签识别），并可以把 HTTP 的 charset 作为编码提示
- [ ] C07 [MVP][P0][core] 跨块处理：块末尾未读完的行保留到下一块，跨越块边界的字面量不会漏匹配
- [ ] C08 [MVP][P0][core] 单行长度上限（rg -M / --max-columns-preview 的扩展）：
  - 超长行继续流式查找，只保留匹配附近的窗口用于展示
  - 标记该行已截断
  - 字节偏移仍然精确

## 五、二进制
- [ ] D01 [MVP][P0][core] 用 NUL 字节启发式检测二进制内容
- [ ] D02 [MVP][P0][core] 二进制有三种处理模式，检测到二进制时返回 binary_offset：
  - 跳过（默认）
  - 搜索但不返回内容（rg --binary）
  - 按文本处理（rg -a）
- [ ] D03 [MVP][P0][core] 按文本处理二进制时，仍然受单行长度上限（C08）保护

## 六、上下文
- [ ] E01 [MVP][P0][core] 后置上下文，用计数器实现（rg -A）
- [ ] E02 [MVP][P0][core] 前置上下文，用环形缓冲实现，适用于不可回退的流；缓冲容量 = 上下文行数上限 × 单行长度上限（rg -B）
- [ ] E03 [MVP][P0][core] 前后对称的上下文，可以分别被前置或后置参数覆盖（rg -C）
- [ ] E04 [MVP][P0][core] 相邻片段合并，不重复发送；不连续的地方用结构化的断点标记表示，不输出 `--` 字符串（rg --context-separator）
- [ ] E05 [MVP][P0][core] 上下文行数有服务端上限（建议 ≤10）
- [ ] E06 [后续][core] 全文高亮模式：输出所有行并标出匹配位置，受输出字节上限（I05）约束（rg --passthru）

## 七、位置与结果模型
- [ ] F01 [MVP][P0][core] 从 1 开始的行号；NUL 模式下按记录计数（rg -n）
- [ ] F02 [MVP][P0][core] 从 1 开始、按字节计的列号（rg --column）
- [ ] F03 [MVP][P0][core] 行起点的绝对字节偏移，任何情况下都输出（rg -b / JSON 的 absolute_offset）
- [ ] F04 [MVP][P0][core] 每个匹配的半开字节区间（相对于行起点），按起点排序（rg JSON 的 submatches）
- [ ] F05 [MVP][P0][core] UTF-16 偏移：每个匹配的 u16_start、u16_end，以及行的 u16_column，在扫描时一次算出（浏览器中的 JavaScript 按 UTF-16 码元计数）
- [ ] F06 [MVP][P0][core] 含非法 UTF-8 的行同时提供两种表示：
  - 有损文本（非法字节替换为 U+FFFD），以及基于它的 UTF-16 偏移
  - 原始字节（可以 base64 编码），以及字节偏移
- [ ] F07 [MVP][P0][core] 每个事件都带来源 ID，不带服务器路径
- [ ] F08 [MVP][P0][core] 二进制状态字段，取值为 none、detected、suppressed
- [ ] F09 [MVP][P0][core] 截断相关字段：truncated、原始行长、预览窗口的位置
- [x] F10 [MVP][P0][core] 停止原因字段 limit_hit，取值为 none、max_results、max_bytes、deadline、decompressed_bytes、cancelled
- [x] F11 [MVP][P0][core] partial 标记：计数类结果因预算耗尽而没有扫完时置位
- [ ] F12 [后续][core] 发生转码或解压时，额外提供该位置在原始数据中的偏移

## 八、输出模式与统计
- [ ] G01 [MVP][P0][core] 默认模式：逐条产出匹配行事件
- [ ] G02 [MVP][P0][core] 统计匹配的行数（rg -c）
- [x] G03 [MVP][P0][core] 统计匹配的次数（rg --count-matches）
- [ ] G04 [MVP][P0][core] 输出有匹配的来源列表，每个来源找到第一个匹配就停止读取（rg -l）
- [x] G05 [MVP][P0][core] 输出没有匹配的来源列表（rg --files-without-match）
- [x] G06 [MVP][P0][core] 计数结果包含零命中的来源，结束事件里始终带计数（rg --include-zero）
- [x] G07 [MVP][P0][core] 统计字段：elapsed、searches、searches_with_match、bytes_searched、bytes_printed、matched_lines、matches，另外增加 bytes_read_raw、sources_failed（rg --stats / JSON 的 stats）
- [x] G08 [MVP][P0][core] 实时流定期产出 progress 事件（包含已扫描字节数和匹配数）；流没有结束时不发最终汇总
- [ ] G09 [MVP][P0][能力] "只显示命中片段"所需的数据完全由匹配区间提供，不单独实现这种输出模式（rg -o）

## 九、事件 API 与流控
- [x] H01 [MVP][P0][core] 事件类型齐全：begin、match、context、progress、end，以及最终的 summary（字段命名可以参照 rg --json）
- [ ] H02 [MVP][P0][core] 每产出一个事件就立即回调（相当于行缓冲），事件的聚合和 flush 交给传输层（rg --line-buffered）
- [x] H03 [MVP][P0][core] 背压：回调可以要求暂停或停止，或者提供拉取式接口
- [x] H04 [MVP][P0][core] 实时流（类似 tail -f）支持空闲超时和心跳事件
- [x] H05 [MVP][P0][能力] 事件结构可以无损地序列化为 NDJSON，供 SSE 或 WebSocket 推送；序列化由 API 层完成，不在 core 中（rg --json）

## 十、资源与安全（rg 没有这些，但公开服务必须具备）
- [x] I01 [MVP][P0][core] 扫描字节上限，按来源和按请求分别设置（CWE-400；OWASP API4:2023）
- [x] I02 [MVP][P0][core] 时间预算（截止时间），读取循环和匹配循环中都会检查
- [x] I03 [MVP][P0][core] 取消令牌：客户端断开时取消搜索，并关闭上游读取
- [x] I04 [MVP][P0][core] 全局最大结果数，配合游标续查实现分页
- [x] I05 [MVP][P0][core] 输出字节上限，也覆盖全文高亮和片段输出
- [x] I06 [MVP][P0][core] 内存上限：前置上下文缓冲、解码缓冲、事件队列都有界（CWE-770）
- [ ] I07 [MVP][P0][core] 构建匹配器之前，先校验模式长度和模式数量的上限
- [x] I08 [MVP][P0][core] 配额与并发钩子：各项预算由服务层按租户或 IP 注入，core 不自行决定
- [x] I09 [MVP][P0][core] 类型化错误：致命错误、每个来源的软错误、"有匹配/无匹配"三者分开表达。不照搬 rg 把软错误也归入退出码 2 的做法
- [x] I10 [MVP][P0][core] 返回给调用方的错误不包含内部路径等细节，细节只通过服务端日志钩子输出（OWASP Error Handling）
- [x] I11 [MVP][core] core 不读取任何环境变量或配置文件（rg RIPGREP_CONFIG_PATH / --no-config）
- [x] I12 [MVP][core] 安全默认值，并且都可以由服务层覆盖：
  - 二进制内容默认跳过
  - 不跟随符号链接
  - 不读取全局和父目录的忽略规则
  - 不跨文件系统
  - 外部可能被修改的文件不使用 mmap
  - 上下文 ≤10 行，单行 ≤64 KiB
  - 每个请求的扫描字节数和耗时都有上限

## 十一、文件管线（P1，只用于多文件或目录类来源）
- [ ] J01 [后续][P1][core] glob 包含与排除（rg -g）：
  - 后出现的规则优先，支持嵌套花括号
  - glob 的数量和长度有上限
- [ ] J02 [后续][P1][core] glob 不区分大小写（rg --glob-case-insensitive / --iglob）
- [ ] J03 [后续][P1][core] 是否包含隐藏文件的开关，默认值按来源类型区分（rg --hidden）
- [ ] J04 [后续][P1][core] 忽略规则（rg --no-ignore / --no-require-git）：
  - 读取 .gitignore、.ignore、.rgignore
  - 有总开关
  - 没有 git 仓库时同样生效
- [ ] J05 [后续][P1][core] 接受用户以文本形式提供的忽略规则，不接受路径（替代 rg --ignore-file）
- [x] J06 [MVP][P1][core] 强制不读取全局 excludes 配置（rg --no-ignore-global）
- [x] J07 [MVP][P1][core] 强制不读取搜索根目录之上的忽略规则（rg --no-ignore-parent）
- [ ] J08 [后续][P1][core] 细分的忽略开关（rg --no-ignore-dot / --no-ignore-exclude / --no-ignore-vcs / --ignore-file-case-insensitive）
- [ ] J09 [后续][P1][core] 最大遍历深度，由服务端固定（rg -d）
- [x] J10 [MVP][core] 每个文件或来源的大小上限，与 I01 统一处理（rg --max-filesize）
- [ ] J11 [后续][P1][core] 不跨越文件系统边界，默认开启（rg --one-file-system）
- [ ] J12 [后续][P1][能力] 提供"文件类型 → glob"的展开接口，类型表由配置层提供（rg -t / -T / --type-add）
- [ ] J13 [后续][P1][core] 可以列出将被搜索的来源，这一操作计入遍历预算（rg --files）
- [ ] J14 [后续][P1][core] 线程数由服务层的并发钩子决定，core 不自行启动数量无上限的线程（rg -j）
- [ ] J15 [后续][P1][core] 对外部可能被修改的文件不使用 mmap，避免文件被截断时进程崩溃（rg --mmap）
- [ ] J16 [禁止] 跟随符号链接，或者遍历越出搜索根目录（rg -L；CWE-59）

## 十二、能力项（core 只提供数据，不负责呈现）
- [ ] L01 [MVP][能力] 高亮：core 只返回匹配区间，不输出 ANSI 颜色码或 HTML（rg --color）
- [ ] L02 [MVP][能力] 分组：用 begin 和 end 事件界定每个来源的结果（rg --heading）
- [ ] L03 [MVP][能力] 去除行首空白之类的显示处理，不改变 core 返回的行内容和偏移（rg --trim）
- [ ] L04 [后续][能力] 排序由 Web 层完成，core 不为了排序而缓存全部结果（rg --sort）

## 十三、不做（CLI 专属，确认不存在即可）
- [ ] K01 [不做] 终端颜色与配色（rg --color / --colors）
- [ ] K02 [禁止] 终端超链接，以及通过执行命令获取主机名（rg --hyperlink-format / --hostname-bin）
- [ ] K03 [不做] 文本字段分隔符、路径分隔符、以 NUL 结尾的路径（rg --field-context-separator / --field-match-separator / --path-separator / -0）
- [ ] K04 [不做] 面向终端的文本排版输出（rg --pretty / --vimgrep / --heading 的文本格式）
- [ ] K05 [不做] 帮助、版本、shell 补全和 man 页生成（rg -h / --help / -V / --generate / --type-list / --pcre2-version）
- [ ] K06 [不做] 分页器，以及把调试信息打印到终端（rg --debug / --trace 的终端输出；日志只通过服务端钩子输出）

## 十四、审查报告格式
~~~markdown
# libwebgrep 功能审查报告
- 提交：<git rev-parse HEAD 的输出>
- 审查时间：
- 汇总：DONE a / PARTIAL b / TODO c / UNKNOWN d / ABSENT-OK e / VIOLATION f / EXTRA g
- MVP 完成率：判为 DONE 的 MVP 项数 / MVP 项总数

## VIOLATION（最优先处理）
| ID | 证据 | 说明 |
|---|---|---|

## 未完成清单（排序：MVP·P0 → MVP·P1 → 后续 → 正则阶段）
| ID | 状态 | 缺什么（一句话） |
|---|---|---|

## 全量结果
| ID | 状态 | 实现位置 | 测试名 | 备注 |
|---|---|---|---|---|
~~~
