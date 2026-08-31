# 规格：文件系统策略（Filesystem Policy）

[提案 0001 — 沙箱安全策略](./overview.md) 的组成部分。本文档中的关键词 **必须（MUST）**、**不得（MUST NOT）**、**应该（SHOULD）**、**可以（MAY）** 依据 RFC 2119 解释。

---

## 1. 范围

本规格定义 `SandboxPolicy` 对象的文件系统子策略。沙箱文件系统边界是两层的，策略也是两层的：

1. **宿主边界** — 哪些宿主路径可以挂载进沙箱、默认可写性如何。这把既有的宿主挂载前缀白名单形式化为面向用户的策略。
2. **沙箱边界** — 沙箱**内部**哪些路径可读、可写、可执行，作用于沙箱运行的每一个进程。

不在范围内：内容审查、文件数量/大小配额（写入字节量由资源限额覆盖）、镜像层构建。

## 2. 对象模型

```yaml
policy:
  filesystem:
    mode:            baseline | unrestricted   # 默认: baseline
    denyPaths:       [string]                  # 完全禁止访问
    readOnlyPaths:   [string]                  # 允许读、禁止写
    writableRoots:   [string]                  # 反向表述：仅这些根下可写
    mounts:
      allowedHostPrefixes: [string]            # 可挂载的宿主路径
      defaultReadOnly:     bool                # 默认: false
```

## 3. 路径模式语法

所有路径字段使用同一套模式语法：

1. 模式**必须**是绝对路径。
2. `*` 匹配**单个路径段内**的任意字符序列（**不得**匹配 `/`）。
3. 每段只允许一个 `*`；v1 不定义 `?` 与 `**`。
4. 不含通配符的模式匹配该路径本身及其下所有内容（按路径段的前缀语义，而非原始字符串前缀）。
5. 匹配区分大小写，且作用于**规范化后**的路径（§4.1）。

示例：

| 模式 | 匹配 | 不匹配 |
| --- | --- | --- |
| `/etc` | `/etc`、`/etc/passwd`、`/etc/apt/...` | `/etcetera` |
| `/home/*/.ssh` | `/home/alice/.ssh`、`/home/bob/.ssh/keys` | `/home/.ssh`、`/home/a/b/.ssh` |
| `/root/.aws` | `/root/.aws`、`/root/.aws/credentials` | `/home/root/.aws` |

## 4. 求值语义

### 4.1 路径规范化

匹配前，被访问路径**必须**先规范化：词法上解析 `.` 与 `..`，再解析符号链接。若符号链接目标逃逸出沙箱根，则以解析后的宿主侧路径参与宿主边界匹配。实现**不得**依赖对规范化前字符串的策略匹配（即 `/home/x/../root/.ssh` 这类穿越**必须**按解析后的形式判定）。

### 4.2 判定顺序

对沙箱任意进程的任意文件系统访问，判定**必须**为：

1. 解析后的路径命中任一 `denyPaths` 模式（或内置基线集合，§6）→ **拒绝一切访问**（`EACCES`）。
2. 否则若 `writableRoots` 非空且解析后的路径不命中任何 `writableRoots` 模式 → **只读**（写操作以 `EACCES`/`EROFS` 失败）。
3. 否则若命中任一 `readOnlyPaths` 模式 → **只读**。
4. 否则 → 默认（可读写，受镜像层权限约束）。

`denyPaths` 永远优先于 `writableRoots` 与 `readOnlyPaths`。规则 2 与规则 3 是互斥的两种表述方式；约束见 §5。

### 4.3 强制执行要求

1. 策略**必须**在进程级对沙箱运行的**每一个进程**生效，而不仅是对经由特定入口派生的进程。进程 shell 出任意二进制**必须**继承同样的限制。
2. 强制执行**不得**依赖环境变量、`PATH` 操纵或纯用户态拦截。
3. `denyPaths` **必须**对沙箱内的属主用户身份也拒绝读取。
4. 效果自策略应用起对新建进程生效。策略更新能否重新作用于已运行进程是开放问题（§10）。

### 4.4 宿主边界语义

1. 宿主路径不在任何 `mounts.allowedHostPrefixes` 条目之下的挂载请求**必须**在创建时以 `400 POLICY_FS_MOUNT_FORBIDDEN` 拒绝。
2. `mounts.defaultReadOnly: true` 表示未显式请求读写的挂载按只读挂载。
3. 前缀校验**必须**在匹配前解析 `..`（路径穿越尝试被拒绝）。
4. 集群侧运维白名单仍是**兜底约束**：生效的 `allowedHostPrefixes` **必须**是策略声明前缀与运维配置前缀的交集。策略不能放宽运维所禁止的范围。

## 5. 字段规格与约束

| 字段 | 类型 | 约束 | 默认值 | 语义 |
| --- | --- | --- | --- | --- |
| `mode` | `enum?` | `baseline` \| `unrestricted` | `baseline` | `baseline` 附加内置敏感路径拒绝集（§6）。`unrestricted` 仅应用显式声明的规则。 |
| `denyPaths` | `[string]?` | 模式语法 §3。 | `[]`（+ 基线集合） | 一切访问均被拒绝。 |
| `readOnlyPaths` | `[string]?` | 模式语法 §3。`writableRoots` 非空时**必须**为空。 | `[]` | 允许读；写/创建/删除被拒绝。 |
| `writableRoots` | `[string]?` | 模式语法 §3。`readOnlyPaths` 非空时**必须**为空。 | `[]` | 非空时，仅这些根之下允许写。 |
| `mounts.allowedHostPrefixes` | `[string]?` | 宿主绝对路径，不允许通配。 | 运维配置 | 哪些宿主路径可挂载进该沙箱。 |
| `mounts.defaultReadOnly` | `bool?` | — | `false` | 未显式指定模式的挂载的默认可写性。 |

违反 `readOnlyPaths`/`writableRoots` 互斥约束**必须**以 `400 INVALID_POLICY` 失败，并同时指名两个字段。

## 6. 默认值

内置基线拒绝集（`mode: baseline` 时生效）：

```yaml
denyPaths:
  - /root/.ssh
  - /home/*/.ssh
  - /root/.aws
  - /home/*/.aws
  - /root/.gnupg
  - /home/*/.gnupg
  - /root/.config/gcloud
  - /home/*/.config/gcloud
  - /etc/shadow
  - /etc/gshadow
```

基线的存在是为了阻断沙箱内的凭据窃取：以沙箱用户身份运行的 Agent 生成代码**不得**能够读取正是该用户用于向外部服务认证的凭据。v1 刻意将其定为**固定集合** —— 不允许不经 `denyPaths` 的用户扩展 —— 以保持语义可预期。

`mode: unrestricted` **必须**在生效策略中被显式表示；它绝不由缺省产生。

## 7. 合并语义

在 [overview.md](./overview.md) §5 的共享规则之上：

| 字段 | 合并细化 |
| --- | --- |
| `mode` | 最严格者胜：任一来源为 `baseline`，结果即 `baseline`。 |
| `denyPaths` | 追加 + 去重（含生效中的基线集合）。 |
| `readOnlyPaths` / `writableRoots` | 追加 + 去重。互斥约束在**合并后**的结果上校验，而非逐来源校验。 |
| `mounts.allowedHostPrefixes` | 各来源取交集（挂载面只能收窄，不能放宽）。 |
| `mounts.defaultReadOnly` | `true` 胜（最严格）。 |

## 8. 错误

配置错误（创建/更新时）：`400 INVALID_POLICY`（模式格式错误、违反互斥约束）、`400 POLICY_FS_MOUNT_FORBIDDEN`（宿主路径超出白名单）。

强制执行错误是 OS 层的，不是 API 层的，因为策略作用于 API 表面之下：

| 访问 | 结果 |
| --- | --- |
| 读取 `denyPaths` 之下 | `EACCES` |
| 在 `readOnlyPaths` 之下 / `writableRoots` 之外写入 | `EACCES` 或 `EROFS` |
| 在只读之下创建/删除/重命名 | `EACCES` |
| 列出被拒目录 | `EACCES` |

拒绝**不得**以某种可区别于普通权限失败的方式向沙箱进程泄露规则身份（不得存在错误侧信道）；规则身份只出现在审计流（§9）中。

## 9. 可观测性

1. 文件系统拒绝**应该**以配置的审计级别输出审计事件 `{sandboxID, rule (模式), path, op (read|write|...), outcome: denied}`；`mode: unrestricted` 关闭基线集合事件，但不关闭显式 `denyPaths` 事件。
2. 审计载荷**不得**包含文件内容。

## 10. 开放问题

1. **热应用。** 更新后的文件系统策略能否作用于已运行进程，还是只能作用于新进程？内核规则集重应用语义因机制而异；规格需要一个稳定答案。
2. **基线集合演进。** 内置集合如何扩展（新的凭据位置）而不破坏合法读取其中某路径的模板？
3. **执行位。** 规格是否应区分执行权限与读权限？v1 将执行问题交给网络/命令执行策略；待确认。
4. **写 `/etc` 的镜像。** 一些包管理器会写 `/etc`。`baseline` 是否需要镜像级注解来豁免特定路径？

## 11. 非规范性说明

- 每个沙箱独占一个内核，因此 §4.3 的要求可由沙箱内、无特权、按沙箱粒度的机制满足（如带按进程规则集的 LSM，或等价的系统调用级强制）。本规格刻意只规定*属性*，不规定机制。
- 宿主边界规则将既有行为（前缀白名单 + 只读重挂载）形式化，行为不变。
