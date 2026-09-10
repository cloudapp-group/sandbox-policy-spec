# 规格：命令执行策略（Exec Policy）

[提案 0001 — 沙箱安全策略](./overview.md) 的组成部分。本文档中的关键词 **必须（MUST）**、**不得（MUST NOT）**、**应该（SHOULD）**、**可以（MAY）** 依据 RFC 2119 解释。

---

## 1. 范围

本规格定义 `SandboxPolicy` 对象的命令执行子策略：对**经沙箱控制接口发起**的命令执行（进程启动、代码运行、交互会话）的约束。

它**不**约束沙箱负载运行后自行启动的进程；那是那些在控制接口之下强制执行的模块的领地 —— 提权、持久化与系统调用归 [process.md](./process.md)，路径归 [filesystem.md](./filesystem.md)，目标归 [network.md](./network.md)，消耗归 [resource.md](./resource.md)。这一边界在此明确写出，因为它是命令执行策略最主要的诚实局限，而 §3.5 量化了它的代价：对 Agent 生成的代码，一份放行了解释器的白名单几乎约束不了任何东西。各模块分别应对哪类威胁，见 [overview.md](./overview.md) §2.3 的纵深防御矩阵。

有一项推论值得在此点名，因为读者最常在这里期待本模块做它做不到的事。「拦截高危系统命令」这个需求，本模块只能对*经 API 提交*的命令给出答案。一条针对 `insmod` 的拒绝条目，并不能阻止一个 Python 脚本去加载内核模块，而再精巧的模式语法也改变不了这一点 —— 真正做到这件事的是 [process.md](./process.md) §4.3，它拒绝 `init_module` 这个系统调用。在两者重叠的地方，两者都值得有：exec 规则在 API 处产生一条可读、可归因的拒绝，而 process 规则才是真正守得住的那一条。

## 2. 对象模型

```yaml
policy:
  exec:
    mode:             unrestricted | denylist | allowlist   # 默认: unrestricted
    allowedCommands:  [CommandRule]
    deniedCommands:   [CommandRule]
    allowedUsers:     [string]        # 默认: [] = 不限制
    maxTimeoutSec:    int             # 默认: 3600
    maxConcurrent:    int             # 默认: 0 = 不限
    audit:            none | metadata | full   # 默认: none
```

## 3. 命令规则语法

`CommandRule` 形如：

```yaml
- name: string          # 必填，在其列表内唯一，用于错误与审计
  command: string       # 必填，模式见本节
```

`command` 模式语法：

### 3.1 模式形状

1. `command` 的第一个以空白分隔的 token 是**命令 token**；其余为**参数模式**。
2. 每个参数模式是一个 glob：`*` 匹配任意字符序列（含单个参数内的空格），`?` 匹配单个字符。裸 `*` 匹配任意一个参数。字面字符匹配自身。
3. 参数个数参与匹配：仅当规范参数向量（§3.3）中的参数个数等于参数模式个数时模式才匹配。`curl *` 不匹配无参数的 `curl`。要匹配「任意参数（含无参数）」，需提供两条规则（`curl` 与 `curl *`）—— v1 保持按个数精确匹配，因为它可预期。
4. shell 元字符组合（§4.3）在 shell 解析后按子命令逐个求值；模式**绝不**跨 `|`、`&&`、`;` 等操作符匹配。

### 3.2 可执行文件身份

v1 匹配的是**实际将被执行**的可执行文件，而不是调用时的书写形式。要求 `curl` 与 `/usr/bin/curl` 各配一条会使每个模板的维护量翻倍，并招来那一条遗漏 —— 而遗漏就是绕过。因此实现对每个子命令**必须**构造一个**身份集合**：

- 字面书写的命令 token；
- 解析该 token 得到的绝对路径（不含 `/` 的 token 走 `PATH` 查找，相对 token 按 `cwd` 解析），并解开 `.`、`..` 与全部符号链接 —— 即**规范解析路径**；
- 规范解析路径的 basename；
- 解析过程中经过的每一个中间符号链接路径。

匹配随后在两个方向上均为 fail-closed：

| 模式 | 规则匹配子命令的条件：其命令 token 匹配…… |
| --- | --- |
| `denylist` | 身份集合的**任一**成员 |
| `allowlist` | **规范解析路径**或其 basename |

这一不对称正是两种模式都安全的原因，而每一项后果都是刻意的：

1. `curl` 匹配解析到 `/usr/bin/curl` 的调用，`/usr/bin/curl` 也匹配写作 `curl` 的调用。名称形式与路径形式不再是两个宇宙。
2. denylist 规则 `curl` 仍能捉到 `./mycurl`（当 `mycurl` 是指向 `/usr/bin/curl` 的符号链接时），因为解析路径就在身份集合里。
3. allowlist 规则 `curl` **不会**放行 `~/bin/curl` —— 当该名称解析到一个无关的二进制时：只有规范解析路径算数，所以把二进制改名为被允许的名字不构成绕过。
4. 若 token 无法解析到可执行文件，身份集合仅含字面 token。`allowlist` 模式下无任何匹配，请求被拒；`denylist` 模式下仍对字面 token 做匹配，而执行随后会以平台惯常的「未找到」行为自行失败。
5. 解析**必须**由平台在沙箱的文件系统视图中、于求值时完成。请求中提供的路径**不得**被当作解析结果信任。

### 3.3 不确定的输入被拒绝，而不是被解析

一个早期版本规定了一个 shell 解析器：它拆解算符、从 `env`/`sudo`/`xargs` 中提取被包装的命令、递归解析 `sh -c` 主体、解析别名与 shell 函数、把 `--name=value` 规范化为两个参数，并把递归限制在深度 8。

这些全部被移除，且不是因为解析做错了。而是解析器对这份工作是错误的形状。每个解析器都有一份它处理得了的语料与一道它处理不了的边缘，而在一道安全边界上，那道边缘正是绕过所在 —— 一个漏掉 `env FOO=1 curl` 的匹配器不是一个抓得住它的匹配器的弱化版，它是一个洞。那套机制也曾是本提案中正确实现代价最大的面（§11），对一个其触及范围已被 §3.5 限定的门而言，这是笔糟糕的交易。

替代方案是失败即关闭的，且用一条规则就装得下：

1. **一条其被执行程序无法被静态确定的命令行必须被拒绝** —— 不分析，不以尽力而为的方式放行。这在 `allowlist` 与 `denylist` 下同等成立。
2. 下列构造使一条命令行变得不确定：

   | 构造 | 例子 |
   | --- | --- |
   | Shell 算符 | `\|`、`\|\|`、`&&`、`;`、`&` |
   | 命令替换 | `$(...)`、反引号 |
   | 重定向、here-document、here-string | `>`、`<`、`<<EOF`、`<<<` |
   | 不配对的引号或本规格未定义的语法 | `c"url x` |
   | 一个包装器或一个解释器（§3.4） | `sudo curl x`、`sh -c '...'` |

3. 拒绝是 `POLICY_EXEC_UNPARSEABLE`，携带一个指名所发现构造的 `reason`，使调用方得知该移除什么，而不是「有某个东西」错了。
4. 因此匹配只作用于**一个**参数向量 —— 请求自己的那个，在平台的引号移除与分词之后。没有子命令集合、没有传递闭包、没有递归、也没有深度上限，因为已经没有东西可供递归进去了。
5. 参数模式按字面匹配那个向量，不做规范化。`--url=x` 与 `--url x` 是**不同的**调用，一条要抓住两者的规则把两者都列出。这是一处刻意舍弃的便利：规范化曾是一个带着与大解析器同样边缘问题的小解析器。

这比它所取代的更严。一条过去会被拆解然后放行的命令行，现在被直接拒绝。那是刻意的方向 —— `exec` 是一道门，而一道无法辨认正在通过它的是什么的门，应当关闭而不是去猜。

### 3.4 包装器与解释器

有两族程序按其本性就是不确定的，因为它们的全部目的就是去运行别的东西。两者都在此点名，好让 §3.3 规则 2 有一个确定的指称对象：

| 族 | v1 集合 |
| --- | --- |
| **包装器** | `env`、`sudo`、`doas`、`nice`、`ionice`、`nohup`、`setsid`、`stdbuf`、`time`、`timeout`、`chroot`、`unshare`、`flock`、`xargs`、`watch`、`script`、`strace`、`ltrace` |
| **解释器** | `sh`、`bash`、`dash`、`zsh`、`ksh`、`ash`、`python`、`python3`、`node`、`perl`、`ruby`、`awk` |

1. 在 `allowlist` 下，一个其解析后可执行文件（§3.2）落在任一集合中的请求**必须**以 `POLICY_EXEC_UNPARSEABLE` 拒绝，并带 `reason: wrapper` 或 `reason: interpreter`。
2. 一个前导的环境赋值序列（`VAR=x cmd ...`）是一个隐式的 `env` 包装器，按同样的条件被拒。赋值不被剥离，被包装的命令也不被求值；请求就是不通过。
3. **在 `allowedCommands` 里指名一个包装器或解释器并不放行它。** 这样一条规则是死配置，平台**必须**在创建时把它报为一条 `policyWarnings` 条目 `{field, rule, reason: "rule_never_matches"}`。放行 `sudo` 会放行 `sudo sh`，放行 `python` 会放行 Python 能做的一切 —— 而那正是本节所关闭的绕过。
4. 在 `denylist` 下，同一请求以它自己解析后的身份对照黑名单求值，若无匹配则被放行。黑名单不作完整性声明（§4.1），所以它没有什么可失败关闭的；一个想让被包装调用能工作的部署用 `denylist` 或 `unrestricted`，并从 `process`、`filesystem`、`network` 取得围堵，那本来也是围堵所在（§3.5）。
5. 两个集合在 v1 中固定。它们的演进是 §10.5。

### 3.5 命令匹配的诚实局限

§3.4 关闭了*被声明的*解释器，而值得精确说明它买到的有多少，因为那道缺口是结构性的、而不是集合里的缺口：

1. 一个被白名单放行的程序可以自己启动一个解释器。`make`、`npm`、`cargo`、`pytest`，以及日常使用中的每一个构建工具，都会作为其工作的一部分去 shell out，而它们没有一个是 §3.4 意义上的包装器或解释器。匹配看到的是给它的那个调用；它看不到那个程序 fork 出什么。**因此一个 `allowlist` 限定的是什么可以被*提交*，而绝非什么可以被*运行*。**
2. 这正是 §3.4 拒绝而非仅仅告警的原因：在 API 处拒掉 `sh -c` 移除了最便宜的路径，而在这一层没有任何机制能移除其余路径。
3. `exec` 是一道控制接口门禁，不是一道围堵边界。对一个被放行程序所启动的任何东西的围堵，属于 `process`、`filesystem`、`network` 与 `resource` —— 见 [overview.md](./overview.md) §2.3。具体地说：一个读到本节的部署应当去配置 `process.syscall` 与 `filesystem.denyPaths`，因为那才是第一个进程存在之后仍然适用的规则。

## 4. 求值语义

### 4.1 模式

| 模式 | 对每次执行请求的判定 |
| --- | --- |
| `unrestricted` | 仅应用用户、超时与并发约束。 |
| `denylist` | 任一子命令（§4.3）命中 `deniedCommands` 规则 → 以 `POLICY_EXEC_DENIED` 拒绝并指名规则。否则允许。 |
| `allowlist` | **每个**子命令都命中某条 `allowedCommands` 规则 → 允许。任一子命令无匹配 → 以 `POLICY_EXEC_DENIED` 拒绝并指名第一个未匹配的子命令。 |

### 4.2 求值顺序

对每次执行请求，按序：

1. 解析请求用户（默认为沙箱默认用户）。若 `allowedUsers` 非空且用户不在其中 → `POLICY_EXEC_USER_DENIED`。
2. 确定命令行的被执行程序（§3.3）；若不确定则拒绝，否则在那单一参数向量上求值模式匹配。
3. 钳制请求超时：生效超时 = `min(请求值, maxTimeoutSec)`；发生钳制时响应**必须**包含 `effectiveTimeoutSec`。未显式指定超时的请求以 `maxTimeoutSec` 为上限而非默认值（既有默认超时语义不变）。
4. 并发：若当前运行中的执行数 ≥ `maxConcurrent`（当其 > 0 时）→ `POLICY_EXEC_CONCURRENCY_LIMIT`，携带 `retryAfterSec`。

第 1–2 步是策略检查；第 3–4 步是同样作用于 `unrestricted` 模式的约束。

### 4.3 复合命令行

1. 一条含 §3.3 表中任何构造的命令行**必须**以 `POLICY_EXEC_UNPARSEABLE` 拒绝，并在 `reason` 中指名该构造。它**不得**被拆解，也**不得**以尽力而为的方式执行。
2. 这在 `allowlist` 与 `denylist` 下同等适用，且在模式匹配之前适用 —— 没有子命令可供匹配。
3. `unrestricted` 模式根本不求值命令规则，所以一条复合命令行在那里如今天一样运行。§4.2 的超时与并发约束仍然适用。
4. 需明说的后果：`curl x | sh` 被拒而非被分析，而 `make build` 被拒**仅当** `make` 是一个包装器或解释器时 —— 它不是（§3.5.1）。前者在 API 处被关闭；后者在这里根本关不掉。

### 4.4 强制执行要求

1. 匹配**必须**作用于解析后的参数向量，绝不基于原始字符串包含关系。
2. 用户解析**必须**通过平台的用户数据库完成，不得与提示文本做字符串比较。
3. 既有进程 API 的每请求 `user` 参数是唯一的用户切换面；策略对其同等适用。
4. 可执行文件解析（§3.2）与不确定性检查（§3.3）**必须**都发生在强制执行路径内，以便决策是在随后被执行的同一身份上做出的。实现**不得**为匹配解析一次、再为执行重新解析一次。

## 5. 字段规格

| 字段 | 类型 | 约束 | 默认值 | 语义 |
| --- | --- | --- | --- | --- |
| `mode` | `enum?` | `unrestricted` \| `denylist` \| `allowlist` | `unrestricted` | §4.1。 |
| `allowedCommands` | `[CommandRule]?` | 仅在 `mode: allowlist` 下有意义；`mode: allowlist` 时**必须**非空。 | `[]` | 允许的命令模式。 |
| `deniedCommands` | `[CommandRule]?` | 仅在 `mode: denylist` 下有意义。 | `[]` | 拒绝的命令模式。 |
| `allowedUsers` | `[string]?` | 用户名。 | `[]` | 非空时，是允许执行的唯一用户集合。 |
| `maxTimeoutSec` | `int?` | > 0。 | `3600` | 每请求超时上限（§4.2 第 3 步）。 |
| `maxConcurrent` | `int?` | ≥ 0。`0` = 不限。 | `0` | 同时运行中执行数的上限。 |
| `audit` | `enum?` | `none` \| `metadata` \| `full` | `none` | 执行事件的审计级别（§7）。 |

在 `mode: denylist` 下设置 `allowedCommands`，或在 `mode: allowlist` 下设置 `deniedCommands`，**必须**以 `400 INVALID_POLICY` 拒绝（字段对该模式无意义）。

## 6. 默认值

```yaml
exec:
  mode: unrestricted
  allowedCommands: []
  deniedCommands: []
  allowedUsers: []
  maxTimeoutSec: 3600
  maxConcurrent: 0
  audit: none
```

`unrestricted` + `maxTimeoutSec` 上限是 v1 刻意的默认值：它不改变*什么可以运行*，但为被遗忘的超时兜底。需要更强保证的模板**应该**随附 `mode: allowlist` 默认值。

以上就是 `baseline` 分级（[overview.md](./overview.md) §7.1）。`tier: restricted` 在这里只改一个字段 —— `audit: metadata` —— 并刻意把 `mode` 留在 `unrestricted`。两条理由都已在别处写过，在此重复是因为它们缺席看起来会像疏漏：`allowlist` 要求 `allowedCommands` 非空（§5），所以一个选择 `allowlist` 的分级会让单独写 `tier: restricted` 直接校验失败；而按 §3.5，白名单本来也不是围堵一个已放行解释器的东西。想要命令白名单的部署自己声明它，因为只有那个部署知道自己的命令清单。分级在不猜的前提下能提供的是审计轨迹，所以它提供的就是审计轨迹。

### 6.1 影子评估支持

依 [overview.md](./overview.md) §7.2.5，本模块必须声明它在 `auditTier` 之下支持什么，而诚实的答案是**几乎什么都没有，而理由并不是机制上的局限**。

影子评估上报的是一个更严分级*本来会*拒绝什么。而 `tier: restricted` 在这里唯一改动的字段是 `audit`，而一个更详尽的审计级别不拒绝任何东西 —— 所以就当前这套分级而言，本模块的影子评估没有任何东西可发现。针对本模块的 `auditTier: restricted` 是一个格式良好的空操作，而本小节存在的目的是不让读者把这份沉默误读成一个未实现的功能。

有两条推论：

1. 只指向本模块字段的 `auditTier`，只要在 [overview.md](./overview.md) §7.2.2 之下是合法的，就**必须**仍被接受 —— 那条校验规则管的是分级，而不是每个模块有多少话可说。生效策略会记录它，而不产生任何影子事件。
2. 如果 [overview.md](./overview.md) §11.4 所设想的那个更严的第四档分级最终被定义出来，它*确实*会要求一份 `exec` 白名单，而那时本模块的影子评估既有意义又容易做：命令在控制接口处本来就已被解析成子命令（§4.3），所以对同一份分解再求值第二套规则集只多一遍开销。届时的支持方式会是：影子白名单本来会拒绝的命令**照常运行**，并产生一条 `shadow: true` 事件指名那个未匹配的子命令。那就是本模块会采用的机制；只是目前没有任何分级在要求它。

更大的那点就是 §3.5 已经说过的。即便一份 `exec` 白名单被完整影子，它上报的也只是经 API 提交的命令，而对 Agent 生成的代码来说那是一次解释器调用之后归于沉默。真正告诉运维 `restricted` 能不能采纳的那些影子发现，来自 `process`、`filesystem` 与 `network`。

## 7. 错误与可观测性

结构化错误载荷（所有执行错误都携带，便于 Agent 自我纠正）：

| 错误码 | 载荷 | 时机 |
| --- | --- | --- |
| `POLICY_EXEC_DENIED` | `{rule, subCommand, mode}` | 模式匹配拒绝了某子命令。 |
| `POLICY_EXEC_USER_DENIED` | `{user, allowedUsers}` | 用户不在 `allowedUsers`。 |
| `POLICY_EXEC_CONCURRENCY_LIMIT` | `{maxConcurrent, running, retryAfterSec}` | 达到并发上限。 |
| `POLICY_EXEC_UNPARSEABLE` | `{reason}` | 命令行不确定（§3.3、§4.3）。`reason` 取值之一：`shell_operator`、`command_substitution`、`redirection`、`unbalanced_quotes`、`unknown_syntax`、`wrapper`、`interpreter`。 |
| `POLICY_GRANT_INVALID`（400） | `{field, reason}` | 授权指向本模块的不可授权字段（§8.1）。 |
| `INVALID_POLICY`（400） | `{field, reason}` | 配置时校验。 |

非致命发现以 `policyWarnings` 数组随创建/更新响应返回；警告绝不改变请求的结果。已定义的警告：`rule_never_matches`（§3.5.2）。

审计事件（`audit: metadata`）：`{sandboxID, user, command, effectiveTimeoutSec, exitCode, outcome: allowed|denied, rule?}`。`full` 额外附带上限字节数的 stdout/stderr 摘要。审计事件**不得**输出到沙箱内部。

依 [overview.md](./overview.md) §8.1.4，一次**被拒绝**的执行在任何审计级别下都产生违规事件，包括 `audit: none`：`{sandboxID, user, command, rule, subCommand, mode, outcome: denied, effectivePolicyVersion, shadow: false}`。`audit: none` 压掉的是那些*被放行*执行的记录 —— 也就是普通活动。本模块正是这个区分代价最小的地方：这里的一次拒绝本来就是一个结构化的 `400` 返回给调用方，所以该事件重复的是调用方已经拿到的信息，它的价值在于读取审计流的运维，而不在于那个被拒的 Agent。

### 7.1 没有违规动作

依 [overview.md](./overview.md) §8.1.6，本模块声明自己的立场：**它没有 `onViolation` 字段。**

它的强制执行点是控制接口，所以违规是在进程*存在之前*被抓住的。没有东西可杀 —— §4.2 的全部要点就是那条命令从未运行 —— 而 `deny` 是唯一讲得通的结果。一个只有一种合法取值的字段比没有字段更糟，因为它暗示还存在第二种取值。

这同时也是"为什么 `kill` 并非普遍可用"（[overview.md](./overview.md) §8.1.3）最干净的一个例证：一个模块在违规时能采取的动作，被它在哪里强制执行所限定。`exec` 坐得足够早，因此拒绝是彻底的 —— 而这恰恰也是 §3.5 反复强调"它的拒绝覆盖面如此之小"的原因。

## 8. 合并语义

在 [overview.md](./overview.md) §5 的共享规则之上：

| 字段 | 合并细化 |
| --- | --- |
| `mode` | 最严格者胜：`allowlist` > `denylist` > `unrestricted`。 |
| `allowedCommands` / `deniedCommands` | 追加 + 按 `name` 去重。规则列表保持高优先级在前的顺序（首匹配生效）。 |
| `allowedUsers` | 各来源取交集（只能收窄）。 |
| `maxTimeoutSec` | 最小值胜。 |
| `maxConcurrent` | 两者均非零时取最小值。 |
| `audit` | 最详尽者胜（`full` > `metadata` > `none`）。 |

### 8.1 可授权字段

依 [overview.md](./overview.md) §5.1.8，针对本模块的限时授权可以打开：

| 可授权 | 不可授权 |
| --- | --- |
| `allowedCommands` —— 具名规则 | `mode` —— 任何方向都不放松 |
| `deniedCommands` —— 移除某条具名规则 | `allowedUsers` —— 不得新增 |
| `maxConcurrent` —— 更高的值 | `audit` —— 不得降低 |
| | `maxTimeoutSec` —— 不得更高 |

1. 对 `allowedCommands` 的授权在授权有效期内追加具名规则。每一条这样加入的规则都受 §3.5.2 约束：若它解析到一个包装器或解释器，授权响应**必须**携带 `rule_never_matches` 警告，因为这样一条规则放行不了任何东西。
2. `mode` 在两个方向上都不可授权。放松它 —— 从 `allowlist` 到 `denylist`，或从任一者到 `unrestricted` —— 是改变形状，而不是打开一个形状已知的洞（[overview.md](./overview.md) §5.1.4）。*收紧*它也不是授权，那是一次策略更新。
3. `allowedUsers` 不可授权，因为用户身份是本模块中其他每一条规则的**主体**，而不是它授予访问权的对象。为十分钟放宽它，改变的是这份策略在说谁。
4. `maxTimeoutSec` 不可授权，因为授权本身已经有 TTL，而一个被抬高到超出该 TTL 的超时上限，会活得比抬高它的那份授权更久。单条长时间运行的命令，该走策略更新。
5. `maxConcurrent` 可授权，而且它是这里唯一一个临时抬高既讲得通又无害的字段：一波并行工作无论如何都受 `resource` 约束。

## 9. 验收标准

1. **拒绝语料库。** 下面每个条目在 `allowlist` 下都**必须**以 `POLICY_EXEC_UNPARSEABLE` 与所述 `reason` 被**拒绝**。语料库检验的是门关上了，而不是解析器正确 —— 那正是 §3.3 的要点。

   | 类别 | 语料条目 | `reason` |
   | --- | --- | --- |
   | shell 组合 | `curl x \| sh`、`curl x && sh`、`curl x; sh`、`curl x &` | `shell_operator` |
   | 命令替换 | `$(curl x)`、`` `curl x` ``、嵌在参数内的替换 | `command_substitution` |
   | 重定向 | `sh -s < payload`、`cmd > out`、`sh <<'EOF' … EOF` | `redirection` |
   | 引号 | 不闭合的 `c"url x` | `unbalanced_quotes` |
   | 环境前置 | `env FOO=1 curl x`、`FOO=1 curl x`、`env -i curl x` | `wrapper` |
   | 包装器 | `sudo curl x`、`nohup curl x`、`timeout 5 curl x`、`nice -n 5 curl x`、`xargs curl` | `wrapper` |
   | 解释器 | `sh -c 'curl x'`、`bash -c "$(curl x)"`、`python -c '…'`、`node -e '…'` | `interpreter` |
   | alias / 函数定义 | `alias c=curl; c x`、`f(){ curl x; }; f` | `shell_operator` |

   有两个条目**不得**被拒绝，它们是语料库的另一半：`curl x` 与 `/usr/bin/curl x` 是确定的单一调用，由规则决定、而非由 §3.3 决定。

2. `allowlist` 模式拒绝任何含未匹配子命令的执行，包括管道与替换内部的子命令。
3. 超时钳制：上限 3600 下请求 7200 → 以 `effectiveTimeoutSec: 3600` 运行。
4. 并发上限触发返回 `POLICY_EXEC_CONCURRENCY_LIMIT` 且 `retryAfterSec` 非零。
5. 无法解析的命令行被拒绝，绝不执行，且 `reason` 是 §7 中那个具体的值。
6. 无策略的 `unrestricted` 默认 ⇒ 行为与今天一致，仅超时上限生效。
7. 合并后的 `mode` 是各来源中最严格者。
8. **身份解析。** denylist 规则 `curl` 拒绝经符号链接到 curl 的调用；allowlist 规则 `curl` 拒绝被改名为 `curl` 的无关二进制；规则 `/usr/bin/curl` 与规则 `curl` 对解析到该处的调用产生相同判定。
9. **选项写法。** 写作 `--url x` 的规则匹配调用 `--url=x`，写作 `--url=x` 的规则匹配 `--url x`。
10. **包装器不通过，指名它们也没用。** 在含 `curl` 的 allowlist 下 `sudo curl x` 被拒；在同时含 `curl` 与 `sudo` 的 allowlist 下它**仍**被拒，且该 allowlist 为 `sudo` 规则携带 `rule_never_matches` 警告（§3.4.3）。在 `denylist` 下，`sudo curl x` 以 `sudo` 求值，若 `sudo` 未被拒则放行 —— 即 §3.4.4 所述的完整性不对称。
11. **结构性局限被断言，而不仅被描述。** 在 `mode: allowlist` 与 `allowedCommands: [make]` 下，一个 `make build` 调用被放行，而它内部 fork 出的 `sh` 根本不被本模块求值。这被断言为一个测试，好让 §3.5.1 保持可见，而不是被作为一份漏洞报告重新发现。
12. `allowedUsers` 跨来源合并后为交集，请求无法添加模板未允许的用户。
13. **受限分级。** `tier: restricted` 且不带任何 exec 字段，解析为 `mode: unrestricted` 加 `audit: metadata`，且生效策略记录这些展开值。单独的 `tier: restricted` 校验通过 —— 它**不得**要求一份 `allowedCommands` 清单。
14. **授权。** 一次追加具名 `allowedCommands` 规则的授权，在授权到期前放行该命令、到期后不再放行；指名 `mode`、`allowedUsers` 或更高 `maxTimeoutSec` 的授权被 `400 POLICY_GRANT_INVALID` 拒绝。规则解析到包装器或解释器的授权携带 `rule_never_matches` 警告，因为这样一条规则放行不了任何东西（§3.4.3）。

## 10. 开放问题

1. **按规则约束环境变量。** `VAR=x cmd` 在 `allowlist` 下被直接拒绝（§3.4.2），所以那里没有东西能躲在赋值后面。待定的是 `CommandRule` 是否应为那些确实放行此类调用的模式*约束*环境 —— 例如对网络相关命令禁止覆盖 `HTTP_PROXY`。v1 不限制环境变量的取值。
2. **工作目录/按路径的规则。** 规则是否应支持按 `cwd` 限定（如「仅允许在 `/workspace` 下执行 `cargo build`」）？
3. **交互会话。** 交互会话是逐次击键求值，还是建立会话时一次求值、其余交给文件系统/资源模块？v1：会话建立时一次求值；重新求值为开放问题。
4. **默认拒绝列表。** `unrestricted` 默认是否也应像文件系统那样附带一个小的内置拒绝列表？人们常提的候选 —— `insmod`、`modprobe`、`mount`、篡改 host-key —— 大多在下一层能得到更好的答案：[process.md](./process.md) §4.3 在其基线里拒绝了 `init_module` 及其同类，无论命令怎么拼写、甚至无论它是否经过 API，那条都守得住。一份内置的 exec 拒绝列表能额外带来的，是在 API 边界上、对确实经由 API 抵达的那部分尝试给出一条*可读、可归因*的拒绝，这有真实的运维价值，也有真实的惊讶成本。这个权衡现在比过去更窄了，而回答它要求先决定：一条已被系统调用规则覆盖的 API 拒绝，值不值得那份惊讶。
5. **包装器与解释器集合的演进。** §3.4 的集合在 v1 是固定的，而它们现在决定的是*拒绝*而非提取，这抬高了赌注：一个缺失于解释器集合的程序会被当作一个普通命令放行。
6. **会话重新求值与授权。** 上面的问题 3 让交互会话只在建立时求值一次。因此一次在会话进行中到期的授权（§8.1），并不会重新关上该会话的命令面；而同一次授权若是针对 `network` 或 `process`，则会重新关上，因为那些模块是按每次操作强制的。要么会话获得重新求值能力，要么就把这处不对称记录为会话级 exec 策略的一项已知局限。

## 11. 非规范性说明

- **本模块是一个可选的合规性 profile，而不属于强制的 v1 核心。** §3 中的命令匹配规则 —— 可执行文件身份、参数规范化、包装器提取、内联脚本解析 —— 是本提案中实现代价最高的一个面，而按 §3.5，它们的安全价值被限定在经控制接口提交的命令上。对 Agent 生成的代码而言，那通常是一次解释器调用之后归于沉默。因此一个部署**可以**把本模块作为一个**控制面合规性 profile** 来实现、并把它的字段声明为 `unsupported`（[overview.md](./overview.md) §8.2），而不会因此在强制核心上不合规 —— 那个核心是：`process`（非 root、能力、系统调用面）、`filesystem`、`network`、`identity` 与 `resource`，也就是那些仍然约束着工作负载自行启动的代码的模块。

  这是一个关于实现优先级的陈述，而不是对下文各条规则的降级。一个*确实*实现本模块的部署**必须**按规格实现它，包括 §9 的拒绝语料库；一个不完整的命令匹配器就是 [overview.md](./overview.md) §8.2.1 规则 4 所禁止的那种近似 —— 因为一个漏掉了 `env FOO=1 curl` 的模式语言，并不是一个能抓住它的模式语言的更窄版本。可选的是要不要实现，而不是实现多少。
- **这是唯一一个完全与基质无关的模块。** 本文档中的每一条规则都在控制面求值、在任何东西被启动之前，所以其中没有任何一条依赖某个内核接口、某个容器运行时或某个 CNI（[overview.md](./overview.md) §12.2）。命令解析（§3）、用户解析、超时钳制与并发计数，全都是纯服务端逻辑。任一基质上的部署都把本模块的每个字段声明为 `enforced`，不存在需要协商的能力状态。
- 这个属性正是 §3.5 那份诚实的另一面。`exec` 之所以在任何地方都容易实现，恰恰因为它从不需要伸进一个正在运行的沙箱里 —— 而"从不伸进去"也正是它约束得如此之少的原因。那些难以可移植地实现的模块（`filesystem` 的路径规则、`network` 的域名条目），其困难与其承重是同一个理由：它们在 API 之下强制执行，而那正是基质能力真正起作用的地方。
- 有一项实现要求确实跨过了这条界线：§3.2 要求可执行文件解析发生在**沙箱的文件系统视图中**、且在求值时进行。在 VM 基质上那是一次客户机侧查找；在容器基质上那是在该容器 mount 命名空间中的一次查找。无论哪种，该解析**不得**针对宿主的视图进行、也不得信任请求中给出的结果，这一点 §4.4.4 已有规定 —— 在此重复，是因为这是本模块唯一触及基质的地方。
