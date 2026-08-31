# 规格：命令执行策略（Exec Policy）

[提案 0001 — 沙箱安全策略](./overview.md) 的组成部分。本文档中的关键词 **必须（MUST）**、**不得（MUST NOT）**、**应该（SHOULD）**、**可以（MAY）** 依据 RFC 2119 解释。

---

## 1. 范围

本规格定义 `SandboxPolicy` 对象的命令执行子策略：对**经沙箱控制接口发起**的命令执行（进程启动、代码运行、交互会话）的约束。

它**不**约束沙箱负载运行后自行启动的进程；那是文件系统与资源模块的领地。这一边界在此明确写出，因为它是命令执行策略最主要的诚实局限，而 §3.6 量化了它的代价：对 Agent 生成的代码，一份放行了解释器的白名单几乎约束不了任何东西。各模块分别应对哪类威胁，见 [overview.md](./overview.md) §2.3 的纵深防御矩阵。

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

### 3.3 参数规范化

匹配之前，每个子命令的参数向量**必须**被规范化为**规范参数向量**：

1. 形如 `--name=value` 的参数**必须**拆为两个参数 `--name` 与 `value`。规则模式同样规范化，因此作者可任选一种写法，两种调用形式都能匹配。
2. 捆绑的短选项（`-sSL`）**不得**被拆开。它们按字面匹配；需要捉住某个短选项的规则自行列出它关心的写法。
3. 去引号与分词遵循 shell 规则，发生在规范化之前。匹配作用于所得向量，绝不作用于原始字符串（§4.4.1）—— 因此 `c"ur"l` 的命令 token 就是 `curl`。
4. 前置环境赋值（`VAR=x cmd`）不是 `cmd` 的参数；它们由 §3.4 作为隐式包装器处理。

### 3.4 包装器与启动器

有若干标准命令存在的目的就是去运行*另一个*命令。只匹配包装器会让 `env curl x` 轻松走过针对 `curl` 的规则。因此：

1. 当子命令解析后的可执行文件是一个**包装器**时，被包装的命令**必须**被提取并作为另一个子命令递归求值。包装器与被包装命令均受 §4.1 约束。
2. v1 的包装器集合是固定的：`env`、`sudo`、`doas`、`nice`、`ionice`、`nohup`、`setsid`、`stdbuf`、`time`、`timeout`、`chroot`、`unshare`、`flock`、`xargs`、`watch`、`script`、`strace`、`ltrace`。
3. 前置的环境赋值序列（`VAR=x VAR2=y cmd ...`）**必须**被视为隐式 `env` 包装器：剥去赋值后将 `cmd ...` 作为子命令求值。
4. 若包装器所包装的命令无法静态确定 —— 它从 stdin 抵达、来自文件，或使用了本规格未定义的构造 —— 则请求在 `allowlist` 与 `denylist` **两种**模式下都**必须**以 `POLICY_EXEC_UNPARSEABLE` 拒绝。猜测就是绕过向量，理由同 §4.3.4。

### 3.5 解释器与内联脚本

1. 当子命令是带 `-c` 调用的 **shell**（`sh`、`bash`、`dash`、`zsh`、`ksh`、`ash`）时，脚本文本**必须**被解析，其子命令递归求值。
2. 当 shell 的脚本文本经 heredoc（`sh <<'EOF' … EOF`）或 here-string 抵达时，该文本同样**必须**被解析并递归求值。**未**被喂入解释器的 heredoc 正文是数据，**不得**被当作子命令。
3. 当 shell 从 stdin 或从不属于本请求的文件读取脚本（`sh -s`、`sh script.sh`、`curl x | sh`）时，内容无法静态得知。shell 调用本身作为子命令求值，而本规格对它随后会跑什么不做任何断言。
4. 命令行中出现的 alias 与 shell 函数定义**必须**在匹配前被解开，对同一行内先前定义名称的调用**必须**对着其定义求值。若定义无法静态解开，请求**必须**以 `POLICY_EXEC_UNPARSEABLE` 拒绝。
5. 递归求值 —— 包装器、`-c` 体、命令替换 —— **必须**限定在嵌套深度 8 以内。超过**必须**以 `POLICY_EXEC_UNPARSEABLE` 拒绝，携带 `{reason: "nesting_depth_exceeded"}`。
6. **非 shell** 解释器的内联代码（`python -c`、`node -e`、`perl -e`、`ruby -e`、`awk`）**不得**被分析。它对本规格是不透明的，而假装不是这样比坦白承认更糟。

### 3.6 命令匹配的诚实局限

§3.5.6 与 §1 叠加出一个**必须**明说而不能糊弄过去的局限：

1. 在 `allowlist` 中放行任何 shell 或通用解释器 —— 直接放行、经包装器放行，或作为一个会外包 shell 的构建工具放行 —— 就使该白名单对解释器能做的一切而言**等同于不限制**。匹配看到的是解释器的调用，而不是它要跑的程序。
2. 因此，当策略设为 `mode: allowlist` 且任何一条 `allowedCommands` 规则解析到已知的 shell 或通用解释器时，创建/更新响应**必须**包含 `policyWarnings` 条目 `{field, rule, reason: "interpreter_admitted"}`，记录该白名单并未约束那条规则可执行的范围。
3. `exec` 是控制接口门禁，不是围堵边界。对解释器启动的一切的围堵，是 `filesystem`、`network` 与 `resource` 的责任 —— 见 [overview.md](./overview.md) §2.3。

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
2. shell 解析命令行（§4.3），按模式逐子命令求值。
3. 钳制请求超时：生效超时 = `min(请求值, maxTimeoutSec)`；发生钳制时响应**必须**包含 `effectiveTimeoutSec`。未显式指定超时的请求以 `maxTimeoutSec` 为上限而非默认值（既有默认超时语义不变）。
4. 并发：若当前运行中的执行数 ≥ `maxConcurrent`（当其 > 0 时）→ `POLICY_EXEC_CONCURRENCY_LIMIT`，携带 `retryAfterSec`。

第 1–2 步是策略检查；第 3–4 步是同样作用于 `unrestricted` 模式的约束。

### 4.3 复合命令

1. 含 shell 操作符（`|`、`||`、`&&`、`;`、`&`、命令替换 `$(...)` 或反引号）的命令行**必须**先经 shell 解析拆分为子命令再匹配。
2. 每个子命令独立匹配；任一子命令被拒则整体请求被拒（§4.1）。
3. 命令替换**必须**在其出现位置被视为一个子命令。
4. 命令行无法被无歧义解析（引号不闭合、无法识别的语法）时，请求**必须**以 `POLICY_EXEC_UNPARSEABLE` 拒绝，而不得尽力执行。对歧义输入的尽力执行本身就是绕过向量。
5. 子命令集合是在操作符、命令替换、包装器提取（§3.4）与内联 shell 脚本（§3.5）上的**传递闭包**，并受 §3.5.5 深度上限约束。
6. 重定向与 heredoc 正文是数据而非子命令，除非 §3.5.2 将其喂入解释器。

### 4.4 强制执行要求

1. 匹配**必须**作用于解析后的参数向量，绝不基于原始字符串包含关系。
2. 用户解析**必须**通过平台的用户数据库完成，不得与提示文本做字符串比较。
3. 既有进程 API 的每请求 `user` 参数是唯一的用户切换面；策略对其同等适用。
4. 可执行文件解析（§3.2）、包装器提取（§3.4）与内联脚本解析（§3.5）**必须**全部在强制执行路径内完成，使判定所依据的身份与随后被执行的身份是同一个。实现**不得**为匹配解析一次、再为执行重新解析一次。

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

## 7. 错误与可观测性

结构化错误载荷（所有执行错误都携带，便于 Agent 自我纠正）：

| 错误码 | 载荷 | 时机 |
| --- | --- | --- |
| `POLICY_EXEC_DENIED` | `{rule, subCommand, mode}` | 模式匹配拒绝了某子命令。 |
| `POLICY_EXEC_USER_DENIED` | `{user, allowedUsers}` | 用户不在 `allowedUsers`。 |
| `POLICY_EXEC_CONCURRENCY_LIMIT` | `{maxConcurrent, running, retryAfterSec}` | 达到并发上限。 |
| `POLICY_EXEC_UNPARSEABLE` | `{reason}` | 命令行歧义（§4.3.4）。`reason` 取值之一：`unbalanced_quotes`、`unknown_syntax`、`indeterminate_wrapper`（§3.4.4）、`unresolvable_alias`（§3.5.4）、`nesting_depth_exceeded`（§3.5.5）。 |
| `INVALID_POLICY`（400） | `{field, reason}` | 配置时校验。 |

非致命发现以 `policyWarnings` 数组随创建/更新响应返回；警告绝不改变请求的结果。已定义的警告：`interpreter_admitted`（§3.6.2）。

审计事件（`audit: metadata`）：`{sandboxID, user, command, effectiveTimeoutSec, exitCode, outcome: allowed|denied, rule?}`。`full` 额外附带上限字节数的 stdout/stderr 摘要。`none` 不输出任何事件。审计事件**不得**输出到沙箱内部。

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

## 9. 验收标准

1. **绕过语料库。** 语料库**必须**至少涵盖下列类别。每个条目在 `denylist` 与 `allowlist` 两种模式下都**必须**解析出预期的子命令分解与预期的判定结果。

   | 类别 | 语料条目 |
   | --- | --- |
   | shell 组合 | `curl x \| sh`、`curl x && sh`、`curl x; sh`、`curl x &` |
   | 命令替换 | `$(curl x)`、`` `curl x` ``、嵌在参数内的替换 |
   | 引号 | `"curl" x`、`c"ur"l x`、`'curl' x`、引号不闭合 |
   | 可执行文件身份 | `curl` vs `/usr/bin/curl`；`./mycurl` 作为指向 `/usr/bin/curl` 的符号链接；一个无关二进制被改名为 `curl`；无法解析的 token |
   | 环境前置 | `env FOO=1 curl x`、`FOO=1 curl x`、`env -i curl x` |
   | 包装器 | `sudo curl x`、`nohup curl x`、`timeout 5 curl x`、`nice -n 5 curl x`、`xargs curl`、不带命令的 `xargs` |
   | 选项写法 | `--url=x` vs `--url x`；捆绑的 `-sSL` |
   | 内联脚本 | `sh -c 'curl x'`、`bash -c "$(curl x)"` |
   | heredoc | `sh <<'EOF' … curl x … EOF`（子命令）vs `cat <<'EOF' … curl x … EOF`（数据） |
   | alias / 函数 | `alias c=curl; c x`、`f(){ curl x; }; f` |
   | 无法确定 | `sh -s < payload`、目标从 stdin 抵达的包装器 |
   | 深度 | 超过 §3.5.5 上限的嵌套 |
   | 参数个数 | `curl` vs `curl *` |

2. `allowlist` 模式拒绝任何含未匹配子命令的执行，包括管道与替换内部的子命令。
3. 超时钳制：上限 3600 下请求 7200 → 以 `effectiveTimeoutSec: 3600` 运行。
4. 并发上限触发返回 `POLICY_EXEC_CONCURRENCY_LIMIT` 且 `retryAfterSec` 非零。
5. 无法解析的命令行被拒绝，绝不执行，且 `reason` 是 §7 中那个具体的值。
6. 无策略的 `unrestricted` 默认 ⇒ 行为与今天一致，仅超时上限生效。
7. 合并后的 `mode` 是各来源中最严格者。
8. **身份解析。** denylist 规则 `curl` 拒绝经符号链接到 curl 的调用；allowlist 规则 `curl` 拒绝被改名为 `curl` 的无关二进制；规则 `/usr/bin/curl` 与规则 `curl` 对解析到该处的调用产生相同判定。
9. **选项写法。** 写作 `--url x` 的规则匹配调用 `--url=x`，写作 `--url=x` 的规则匹配 `--url x`。
10. **包装器提取。** 在针对 `curl` 的 denylist 下，`env FOO=1 curl x` 被拒；在未列出 `sh` 的 allowlist 下，`sudo sh` 被拒；目标无法确定的包装器以 `indeterminate_wrapper` 被拒。
11. **解释器诚实性。** 规则放行了 shell 或通用解释器的 `allowlist` 在创建时产生 `interpreter_admitted` 警告，且请求仍然成功。
12. `allowedUsers` 跨来源合并后为交集，请求无法添加模板未允许的用户。

## 10. 开放问题

1. **按规则约束环境变量。** `VAR=x cmd` 现已被分解（§3.4.3），因此被包装的命令不能再躲在赋值后面。待定的是 `CommandRule` 是否应*约束*环境 —— 例如对网络相关命令禁止覆盖 `HTTP_PROXY`。v1 不限制环境变量的取值。
2. **工作目录/按路径的规则。** 规则是否应支持按 `cwd` 限定（如「仅允许在 `/workspace` 下执行 `cargo build`」）？
3. **交互会话。** 交互会话是逐次击键求值，还是建立会话时一次求值、其余交给文件系统/资源模块？v1：会话建立时一次求值；重新求值为开放问题。
4. **默认拒绝列表。** `unrestricted` 默认是否也应像文件系统那样附带一个小的内置拒绝列表（如篡改 host-key）？这是「策略 vs 惊讶」的权衡。
5. **包装器集合的演进。** §3.4.2 的包装器集合在 v1 是固定的。它与文件系统基线集合有同样的演进问题，且**应该**采用同一答案：用带版本的集合而非静默扩展（[filesystem.md](./filesystem.md) §6.2）。
