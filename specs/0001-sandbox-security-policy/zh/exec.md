# 规格：命令执行策略（Exec Policy）

[提案 0001 — 沙箱安全策略](./overview.md) 的组成部分。本文档中的关键词 **必须（MUST）**、**不得（MUST NOT）**、**应该（SHOULD）**、**可以（MAY）** 依据 RFC 2119 解释。

---

## 1. 范围

本规格定义 `SandboxPolicy` 对象的命令执行子策略：对**经沙箱控制接口发起**的命令执行（进程启动、代码运行、交互会话）的约束。

它**不**约束沙箱负载运行后自行启动的进程；那是文件系统与资源模块的领地（allowlist 执行策略正是让未经审查的代码根本跑不起来的工具）。这一边界在此明确写出，因为它是命令执行策略最主要的诚实局限。

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

1. 第一个以空白分隔的 token 是**命令 token**；其余为**参数模式**。
2. 不含 `/` 的命令 token 按**命令名**（basename）匹配；含 `/` 的命令 token 按解析后的绝对路径匹配。名称形式与路径形式互不匹配（`curl` 不匹配 `/usr/bin/curl`）。
3. 每个参数模式是一个 glob：`*` 匹配任意字符序列（含单个参数内的空格），`?` 匹配单个字符。裸 `*` 匹配任意一个参数。字面字符匹配自身。
4. 参数个数参与匹配：仅当参数个数等于参数模式个数时模式才匹配。`curl *` 不匹配无参数的 `curl`。要匹配"任意参数（含无参数）"，需提供两条规则（`curl` 与 `curl *`）—— v1 保持按个数精确匹配，因为它可预期。
5. shell 元字符组合（§4.3）在 shell 解析后按子命令逐个求值；模式**绝不**跨 `|`、`&&`、`;` 等操作符匹配。

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

### 4.4 强制执行要求

1. 匹配**必须**作用于解析后的参数向量，绝不基于原始字符串包含关系。
2. 用户解析**必须**通过平台的用户数据库完成，不得与提示文本做字符串比较。
3. 既有进程 API 的每请求 `user` 参数是唯一的用户切换面；策略对其同等适用。

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
| `POLICY_EXEC_UNPARSEABLE` | `{reason}` | 命令行歧义（§4.3.4）。 |
| `INVALID_POLICY`（400） | `{field, reason}` | 配置时校验。 |

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

1. 绕过语料库：`denylist` 模式的语料库**必须**至少涵盖 —— shell 组合（`curl x | sh`）、命令替换（`$(curl x)`）、引号变体、名称形式 vs 路径形式（`sh` vs `/bin/sh`）、参数个数不匹配 —— 且每个语料条目**必须**解析出预期的子命令分解与判定结果。
2. `allowlist` 模式拒绝任何含未匹配子命令的执行，包括管道与替换内部的子命令。
3. 超时钳制：上限 3600 下请求 7200 → 以 `effectiveTimeoutSec: 3600` 运行。
4. 并发上限触发返回 `POLICY_EXEC_CONCURRENCY_LIMIT` 且 `retryAfterSec` 非零。
5. 无法解析的命令行被拒绝，绝不执行。
6. 无策略的 `unrestricted` 默认 ⇒ 行为与今天一致，仅超时上限生效。
7. 合并后的 `mode` 是各来源中最严格者。

## 10. 开放问题

1. **按规则约束环境变量。** `CommandRule` 是否应增加每条规则的环境约束（如对网络相关命令禁止覆盖 `HTTP_PROXY`）？v1 不动环境变量。
2. **工作目录/按路径的规则。** 规则是否应支持按 `cwd` 限定（如"仅允许在 `/workspace` 下执行 `cargo build`"）？
3. **交互会话。** 交互会话是逐次击键求值，还是建立会话时一次求值、其余交给文件系统/资源模块？v1：会话建立时一次求值；重新求值为开放问题。
4. **默认拒绝列表。** `unrestricted` 默认是否也应像文件系统那样附带一个小的内置拒绝列表（如篡改 host-key）？这是"策略 vs 惊讶"的权衡。
