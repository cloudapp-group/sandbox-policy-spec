# 规格：文件系统策略（Filesystem Policy）

[提案 0001 — 沙箱安全策略](./overview.md) 的组成部分。本文档中的关键词 **必须（MUST）**、**不得（MUST NOT）**、**应该（SHOULD）**、**可以（MAY）** 依据 RFC 2119 解释。

---

## 1. 范围

本规格定义 `SandboxPolicy` 对象的文件系统子策略。沙箱文件系统边界是两层的，策略也是两层的：

1. **宿主边界** — 哪些宿主路径可以挂载进沙箱、默认可写性如何。这把既有的宿主挂载前缀白名单形式化为面向用户的策略。
2. **沙箱边界** — 沙箱**内部**哪些路径可读、可写、可执行，作用于沙箱运行的每一个进程。

不在范围内：内容审查、文件数量/大小配额（写入字节量由资源限额覆盖）、镜像层构建。同样不在范围内：识别异常文件访问 —— 那是审计流的关切，而不是一个策略字段（[overview.md](./overview.md) §2.3.1）。

有两个相邻的面归 [process.md](./process.md) 管，在此点名，因为需要其中一个的策略通常也需要另一个。进程能否*提权*是 `process.noNewPrivileges`，不是一条路径规则 —— 一个位于可读路径下的 `setuid` 二进制，提权照样发生。进程能否*持久化*只有一部分是 `process.allowDaemonize`：自启型持久化是写在文件里的（`crontab`、systemd unit、shell profile、XDG autostart），所以阻止它是在本文档中由 `denyPaths`/`readOnlyPaths` 做出的决定（[process.md](./process.md) §3.4）。

## 2. 对象模型

```yaml
policy:
  filesystem:
    mode:            baseline | unrestricted   # 默认: baseline
    baselineVersion: string                    # 如 "baseline/1"；默认：平台默认值
    baselineExceptions: [string]               # 从基线集合中排除的路径
    denyPaths:       [string]                  # 完全禁止访问
    readOnlyPaths:   [string]                  # 允许读、禁止写
    writableRoots:   [string]                  # 反向表述：仅这些根下可写
    implicitRuntimeWritable: bool              # 默认: true
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

1. 解析后的路径命中任一 `denyPaths` 模式，或命中生效基线集合（§6）的任一模式 → **拒绝一切访问**（`EACCES`）。
2. 否则若 `writableRoots` 非空且解析后的路径既不命中任何 `writableRoots` 模式、也不命中隐式运行时可写集合（§6.4）→ **只读**（写操作以 `EACCES`/`EROFS` 失败）。
3. 否则若命中任一 `readOnlyPaths` 模式 → **只读**。
4. 否则 → 默认（可读写，受镜像层权限约束）。

`denyPaths` 永远优先于 `writableRoots`、`readOnlyPaths` 与隐式运行时可写集合。规则 2 与规则 3 是互斥的两种表述方式；约束见 §5。

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
| `baselineVersion` | `string?` | 已发布的基线集合标识符。未知取值**必须**以 `400 INVALID_POLICY` 拒绝。 | 平台默认值 | 固定内置拒绝集的版本（§6.2）。 |
| `baselineExceptions` | `[string]?` | 每个条目**必须**与所固定基线集合中的某个模式完全一致。 | `[]` | 从基线集合中排除的路径（§6.3）。 |
| `denyPaths` | `[string]?` | 模式语法 §3。 | `[]`（+ 基线集合） | 一切访问均被拒绝。 |
| `readOnlyPaths` | `[string]?` | 模式语法 §3。`writableRoots` 非空时**必须**为空。 | `[]` | 允许读；写/创建/删除被拒绝。 |
| `writableRoots` | `[string]?` | 模式语法 §3。`readOnlyPaths` 非空时**必须**为空。 | `[]` | 非空时，仅这些根之下允许写（加 §6.4）。 |
| `implicitRuntimeWritable` | `bool?` | — | `true` | `writableRoots` 非空时运行时可写集合是否生效（§6.4）。 |
| `mounts.allowedHostPrefixes` | `[string]?` | 宿主绝对路径，不允许通配。 | 运维配置 | 哪些宿主路径可挂载进该沙箱。 |
| `mounts.defaultReadOnly` | `bool?` | — | `false` | 未显式指定模式的挂载的默认可写性。 |

违反 `readOnlyPaths`/`writableRoots` 互斥约束**必须**以 `400 INVALID_POLICY` 失败，并同时指名两个字段。

## 6. 默认值

### 6.1 基线拒绝集 `baseline/1`

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

基线的存在是为了阻断沙箱内的凭据窃取：以沙箱用户身份运行的 Agent 生成代码**不得**能够读取正是该用户用于向外部服务认证的凭据。

**生效基线集合**是所固定版本的集合减去 `baselineExceptions`（§6.3）。

`mode: unrestricted` **必须**在生效策略中被显式表示；它绝不由缺省产生。

### 6.2 基线版本化与演进

凭据的存放位置会不断被发明出来，所以集合必然要长。而扩充一个*固定的、无版本的*集合，会使每一次新增对那些合法读取该路径的模板构成 break change。因此版本化在 v1 就是规范性的，不拖到实现期：

1. 基线集合是**带版本且不可变**的。`baseline/1` 就是 §6.1 的集合；已发布的版本**不得**被原地修改。
2. 新版本**只得增加**路径。删去一个路径会削弱所有解析到该版本的策略，因此**必须**改走已公告的弃用周期。
3. `baselineVersion` 固定集合。生效策略**必须**始终显式记录**解析后**的版本 —— 包括策略并未固定版本的情形 —— 以使该版本出现在策略快照中（[overview.md](./overview.md) §4.1）。
4. 未固定版本的策略解析到平台的**默认基线版本**。将该默认值向前滚动是一次带弃用窗口的、经公告的平台变更；它**不得**静默发生，也**不得**影响已固定版本的策略。
5. 沙箱在其整个生命周期内保持其生效策略中记录的版本。新基线版本只能通过一次策略更新抵达运行中的沙箱，而那会产生一个新的 `effectivePolicyVersion`。

无法容忍任何未来新增的模板就固定一个版本；希望跟上新凭据位置的模板就不固定。无论哪种，选择都是显式且可审计的。

### 6.3 显式退出：`baselineExceptions`

`baselineExceptions` 是那个窄口径的退出手段，用于确实合法需要基线中某一条路径、而用 `mode: unrestricted` 抛弃整个基线又不成比例的场景。

1. 每个条目**必须**与所固定基线集合中的某个模式完全一致。什么都匹配不上的条目**必须**以 `400 INVALID_POLICY` 拒绝 —— 否则当基线演进时，一条例外会静默地变成死配置。
2. 例外**仅**作用于内置集合。它们**不得**抵消任何来源的显式 `denyPaths` 条目。
3. 合并为**交集**：仅当每个贡献来源都声明了某条例外，它才生效（只能收窄，[overview.md](./overview.md) §5）。
4. 每一条生效的例外**必须**被记录在生效策略中，并**必须**在沙箱创建时发出审计事件，使「这个沙箱可以读 `/home/*/.aws`」永不对运维方隐形。

### 6.4 隐式运行时可写集合

`writableRoots` 非空时，其外的一切就变成只读 —— 包括普通工具链默认自己能写的临时目录。一份没有考虑到这一点的 `writableRoots: [/workspace]` 策略会搞坏 `pip`、`npm`、编译器以及任何调用 `mkstemp` 的东西，而且它们坏掉的方式是令人困惑的构建失败，而不是可读的策略拒绝。

因此，当 `writableRoots` 非空时，以下路径**隐式可写**，除非 `implicitRuntimeWritable: false`：

```yaml
- /tmp
- /var/tmp
- /dev/shm
```

1. 隐式集合对 `writableRoots` 是可加的。它绝不覆盖 `denyPaths` 或基线集合 —— 后两者在 §4.2 第 1 步仍然胜出。
2. `implicitRuntimeWritable: false` 去掉隐式集合，用于确实只想要一个可写根的策略。这类策略**应该**在 `writableRoots` 中自行列出其镜像所需的临时目录。
3. 强制执行**不得**去读 `TMPDIR` 或任何其他环境变量来发现临时目录：§4.3.2 禁止这样做，而且环境变量是工作负载可控的。镜像把 `TMPDIR` 指向隐式集合之外的部署，**必须**把该路径显式加入 `writableRoots`；当平台能从模板配置中检测到这一不匹配时，它**应该**在创建时发出 `policyWarnings` 条目 `{reason: "tmpdir_outside_writable_roots"}`。

### 6.5 分级默认值

由 `policy.tier` 选择适用哪一套默认值（[overview.md](./overview.md) §7.1）：

| | `tier: baseline`（默认） | `tier: restricted` |
| --- | --- | --- |
| `mode` | `baseline` | `baseline` |
| `baselineVersion` | 平台默认值 | 平台默认值 |
| `mounts.defaultReadOnly` | `false` | `true` |

注意 `baseline` 与 `restricted` 共用 `mode: baseline`。这是刻意的，也是整份提案中仅有两处「某模块的 `baseline` 分级并非逐字节等于今天行为」的地方之一（[overview.md](./overview.md) §9）：敏感路径拒绝集在默认分级下就是开着的，因为一条正当工作负载从不读取的凭据路径，不是一个值得保留的兼容性面。不同意的部署可以固定 `baselineExceptions` 或设置 `mode: unrestricted`，两者都会被记录并审计（§6.3.4）。

`tier: restricted` 只改一个字段：挂载除非明确请求写，否则以只读到达。它**不**收窄沙箱内的路径规则，因为没有任何有用的猜测可做 —— 一个打开 `writableRoots` 的受限分级不得不发明出那个根，而为一个在 `/src` 里构建的镜像发明 `/workspace`，正是 §6.4 存在所要避免的那种令人困惑的构建失败。

### 6.6 影子评估支持

依 [overview.md](./overview.md) §7.2.5，本模块在 `auditTier` 之下对其完整的路径面支持影子评估：`mode`、解析出的基线集合、`denyPaths`、`readOnlyPaths`、`writableRoots` 与 `mounts.defaultReadOnly`。影子配置本来会拒绝的访问**照常成功**，并产生一条 `shadow: true` 审计事件，携带该路径、该操作，以及本来会拒绝它的那条影子规则。

路径面有一个其他模块没有的事件量问题，而它必须被处理，而不只是被提一句。一次遍历目录树的构建会成千上万次地触碰同一批目录，因此按访问逐条产生影子发现会把真正重要的那条发现埋掉。因此实现**应该**按 `{rule, operation}` 聚合影子发现，并在一个有界的条数内报告涉及的不同路径，而不是每次访问发一条事件（[overview.md](./overview.md) §7.2.7）。

有一处不对称值得说明，因为它限定了一份影子报告在这里能承诺什么。被拒绝的*读*通常是可恢复的 —— 工作负载拿到 `EACCES` 并可见地失败。被拒绝的*写*可能让工作负载处在一个它无法上报的状态里，而影子评估分不清这两者：它观察的是访问，而不是后果。因此一份干净的影子报告意味着"本来不会有任何东西被拒绝"，而不是"这份更严的策略可以安全采纳"。特别是对 `mounts.defaultReadOnly`，请把报告读作一份需要声明的写入位置清单，而不是一个判决。

## 7. 合并语义

在 [overview.md](./overview.md) §5 的共享规则之上：

| 字段 | 合并细化 |
| --- | --- |
| `mode` | 最严格者胜：任一来源为 `baseline`，结果即 `baseline`。 |
| `baselineVersion` | 所固定的最新版本胜。因为版本只会增加路径（§6.2.2），最新也就是最严格。 |
| `baselineExceptions` | 各来源取交集：仅当每个来源都声明了某条例外，它才生效。 |
| `denyPaths` | 追加 + 去重（含生效中的基线集合）。 |
| `readOnlyPaths` / `writableRoots` | 追加 + 去重。互斥约束在**合并后**的结果上校验，而非逐来源校验。 |
| `implicitRuntimeWritable` | `false` 胜（最严格）。 |
| `mounts.allowedHostPrefixes` | 各来源取交集（挂载面只能收窄，不能放宽）。 |
| `mounts.defaultReadOnly` | `true` 胜（最严格）。 |

### 7.1 可授权字段

依 [overview.md](./overview.md) §5.1.8，针对本模块的限时授权可以打开：

| 可授权 | 不可授权 |
| --- | --- |
| `baselineExceptions` —— 具名的基线路径 | `mode: unrestricted` |
| `writableRoots` —— 具名的根 | 移除任何 `denyPaths` 条目 |
| `readOnlyPaths` —— 移除某个具名条目 | `implicitRuntimeWritable` |
| | `mounts.allowedHostPrefixes` |

两处排除承载了主要分量。`denyPaths` 不可授权，因为在本模块里，显式拒绝是作者字面意思就是如此的那一条陈述；「临时打开某一条内置路径」已经由 `baselineExceptions` 覆盖，而且它带着 §6.3.4 的审计轨迹。`mounts.allowedHostPrefixes` 不可授权，因为宿主边界受运维配置兜底（§4.4.4），授权本来就放宽不了它 —— 把这一点说出来，比让人靠试出来更省事。

在 `writableRoots` 原本为空时对它授权，是一次**收窄**而不是放宽：它把本模块从「默认允许写」切换成「只有这里允许写」。授权**不得**产生这种效果（[overview.md](./overview.md) §5.1.4 —— 授权打开一个形状已知的洞，它不改变策略的形状）。这类请求**必须**以 `400 POLICY_GRANT_INVALID` 拒绝。

## 8. 错误

配置错误（创建/更新时）：`400 INVALID_POLICY`（模式格式错误、违反互斥约束、未知的 `baselineVersion`、`baselineExceptions` 条目不在所固定的基线集合中）、`400 POLICY_FS_MOUNT_FORBIDDEN`（宿主路径超出白名单）、`400 POLICY_GRANT_INVALID`（授权指向不可授权字段，或在 `writableRoots` 为空时对其授权，§7.1）。

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
3. 每一条生效的 `baselineExceptions` 条目**必须**在沙箱创建时发出审计事件 `{sandboxID, baselineVersion, exception, sources}`（§6.3.4）。削弱基线是一个事件，而不是一个静默的字段。

## 10. 开放问题

1. **热应用。** 更新后的文件系统策略能否作用于已运行进程，还是只能作用于新进程？内核规则集重应用语义因机制而异；规格需要一个稳定答案。
2. **默认版本的滚动。** §6.2.4 要求默认基线版本移动前先有一个经公告的弃用窗口。该窗口多长？通过什么渠道公告？
3. **执行位。** 规格是否应区分执行权限与读权限？v1 将执行问题交给网络/命令执行策略；待确认。
4. **镜像级声明。** `baselineExceptions` 是按策略的。如果未来某个基线版本拒绝了某个*镜像*合法需要的路径，按策略的例外够吗，还是需要镜像声明一次、使所有用该镜像的策略都继承它？
5. **任务结束时的临时数据清理。** 本文档没有任何地方说明一个任务写下的数据在任务结束后会怎样。隐式运行时可写集合（§6.4）与任何 `writableRoots` 都在沙箱的整个生命周期内持续存在，因此一个被跨任务复用的沙箱，会把上一个任务的临时文件、缓存与下载产物带进下一个任务。这该是一个策略字段（例如在任务边界处需要擦除的路径），一个本模块之外的生命周期操作，还是刻意留给调用方的活？在此之前更前置的问题是：平台是否真的存在一个区别于沙箱生命周期的「任务边界」概念 —— [overview.md](./overview.md) §11.8 跟踪那个问题，而本问题在它之前无法回答。
6. **快照与恢复。** §4.2 治理的是沙箱*内部*进程的访问。而快照是从沙箱*外部*读取文件系统，恢复则是从外部写入。两者都不经过那套判定顺序，所以今天一条 `denyPaths` 条目并不能阻止其内容随快照镜像流出。快照/恢复是否需要它自己的声明式权限 —— 而如果答案是 `denyPaths` 应当把路径从快照中排除，那就是对这个字段含义的一次实质改变，属于某个明确写出这一点的规格版本。
7. **执行位，再议。** 问题 3 把执行权限交给 `exec` 策略。既然 [process.md](./process.md) 现在规定了系统调用级的强制，替代方案就更清楚了：按路径拒绝执行是一条文件系统规则，而彻底拒绝 `execve` 是一条进程规则，两者都不是 `exec` 控制接口。确认「按路径禁止执行」在 v1 之外。

## 11. 非规范性说明

- 每个沙箱独占一个内核，因此 §4.3 的要求可由沙箱内、无特权、按沙箱粒度的机制满足（如带按进程规则集的 LSM，或等价的系统调用级强制）。本规格刻意只规定*属性*，不规定机制。[process.md](./process.md) §4.5 对系统调用面提出了同样的要求，且预期两者可由同一套机制满足。
- 宿主边界规则将既有行为（前缀白名单 + 只读重挂载）形式化，行为不变。
