# 规格：进程策略（Process Policy）

属于 [提案 0001 — 沙箱安全策略](./overview.md)。本文档中的关键词 **必须（MUST）**、**不得（MUST NOT）**、**应该（SHOULD）**、**可以（MAY）** 依据 RFC 2119 解释。

---

## 1. 范围

本规格定义 `SandboxPolicy` 对象的进程（`process`）子策略：适用于**已在沙箱内运行的进程**的约束，无论它是以何种方式启动的。它治理三件事：

- **提权** — 进程是否可以获得它启动时并不持有的权限。
- **持久化** — 进程是否可以活得比启动它的会话更久。
- **系统调用** — 沙箱到底可以使用哪些内核入口。

这个模块之所以存在，是因为提案其余部分已经明确指出了一处缺口。[exec.md](./exec.md) §1 与 §3.6 声明 `exec` 策略是一道控制接口门禁，**不是**围堵边界：一条命令一旦被放行，它启动的进程可以 `fork`/`exec` 任何东西而不再经过 `exec` 求值，而对 Agent 生成的代码来说，被放行的那条命令典型就是一个解释器。[overview.md](./overview.md) §2.3 给出了推论 —— 对自启进程的围堵，必须来自在控制接口之下强制执行的模块。

`process` 就是权限面与系统调用面上的那道围堵，正如 `filesystem` 之于路径、`network` 之于目标。分工是固定的，不是口味问题：

| 问题 | 模块 |
| --- | --- |
| 这条命令可以通过 API 被启动吗？ | `exec` |
| 这个运行中的进程可以提权、可以持久化、可以发起这个系统调用吗？ | `process`（本规格） |
| 它可以读写这个路径吗？ | `filesystem` |
| 它可以访问这个目标吗？ | `network` |
| 它可以消耗这么多吗？ | `resource` |

不在范围内：沙箱之间以及沙箱与宿主之间的进程隔离 —— 那是沙箱模型的属性，而不是一个策略字段（[overview.md](./overview.md) §12）—— 之所以没有对应字段，是因为没有任何东西需要用户来决定。同样不在范围内：识别异常、僵尸或恶意进程（[overview.md](./overview.md) §2.3.1），以及进程数与 CPU 消耗 —— 那些是 `resource` 的维度。

## 2. 对象模型

```yaml
policy:
  process:
    mode:                 baseline | unrestricted   # 默认：baseline
    noNewPrivileges:      bool                      # 默认：false
    allowDaemonize:       bool                      # 默认：true
    allowedCapabilities:  [string]                  # 默认：平台默认集合
    audit:                none | metadata           # 默认：none
    syscall:
      mode:                       baseline | denylist | allowlist   # 默认：baseline
      baselineVersion:            string            # 如 "syscall/1"；默认：平台默认值
      baselineExceptions:         [string]          # 从基线集合中排除的系统调用
      deniedSyscalls:             [string]
      allowedSyscalls:            [string]
      implicitEssentialSyscalls:  bool              # 默认：true
      onViolation:                deny | kill       # 默认：deny
```

## 3. 权限语义

### 3.1 `noNewPrivileges`

为 `true` 时，进程**不得**能获得它尚未持有的权限：

1. 可执行文件上的 `setuid` 与 `setgid` 位**不得**生效。对这类二进制文件执行 `execve` 要么失败，要么在不提权的情况下继续；二者取其一属于机制选择，但提权**不得**发生。
2. 文件能力（file capabilities）**不得**生效。
3. 该属性**必须**被每一个后代进程继承，且**不得**能被进程自己解除。一条进程自己就能解除的限制，不是限制。

在 `baseline` 分级下默认为 `false`，在 `restricted` 下为 `true`（[overview.md](./overview.md) §7.1）。这个默认值刻意是宽松的：`sudo` 是一个 setuid 二进制，[exec.md](./exec.md) §3.4.2 把它列在平台预期要解析的包装器之中，而使用它的镜像很常见。默认拒绝提权会让这些镜像在离肇因策略很远的地方崩掉。[filesystem.md](./filesystem.md) §6.1 的凭据路径先例在性质上不同 —— 读 `~/.aws/credentials` 在正当工作负载里很少见，而 `sudo` 不是。

### 3.2 `allowedCapabilities`

1. 非空时，`allowedCapabilities` 就是沙箱内任何进程可用能力的**完整**集合。集合之外的能力**不得**可被获取，包括沙箱内的特权用户也不行。
2. 条目是不带厂商前缀的能力名（`net_bind_service`、`sys_admin` 等）。未知名称**必须**以 `400 INVALID_POLICY` 拒绝。
3. 空列表表示"平台默认集合"，而不是"没有能力"。要表达"移除全部权限"，得写成一份显式的、无权限的策略 —— 也就是指名工作负载确实需要的那个小集合，而绝不是靠省略（原则 2）。

### 3.3 `allowDaemonize`

为 `false` 时，进程**不得**活得比启动它的会话更久：

1. 脱离控制会话（`setsid`）、通过双重 `fork` 变孤儿、以及重挂到 init 进程之下，**必须**被拒绝。
2. 一个会话或一次 `exec` 调用终止时，其整个进程组**必须**随之终止。
3. 拒绝的呈现方式见 §6。

### 3.4 诚实的局限：持久化比本模块更宽

`allowDaemonize: false` 阻止进程*脱离*会话。它并不阻止工作负载安排自己被重新启动，而本规格**不得**被理解成它做到了这一点。

1. 自启型持久化写在**文件**里：`crontab` 条目、systemd unit、shell profile 脚本、`~/.bashrc`、XDG autostart 条目。阻止它是 `filesystem` 的事（`denyPaths`、`readOnlyPaths`），而不是系统调用或会话的事，因为内核里没有哪个入口点的含义是"把我注册到以后运行"。
2. 一份设置了 `allowDaemonize: false` 却把那些路径留作可写的策略，只关上了一扇门。在意持久化的部署**应该**为其镜像支持的持久化位置配上 `filesystem` 拒绝。
3. 因此本模块约束的是*当前这个*进程的存活时长，而不是工作负载卷土重来的能力。把这一点说出来正是关键：另一种做法是交付一个以它无法兑现的保证来命名的字段。

## 4. 系统调用语义

### 4.1 模式

| 模式 | 对每个系统调用的裁决 |
| --- | --- |
| `baseline` | 在生效基线集合（§4.3）中则拒绝。否则允许。 |
| `denylist` | 在生效基线集合**或** `deniedSyscalls` 中则拒绝。否则允许。 |
| `allowlist` | 仅当在 `allowedSyscalls` 或隐式必需集合（§4.4）中，**且**不在生效基线集合中时允许。否则拒绝。 |

基线集合在三种模式下都适用，`allowlist` 也不例外。一份恰好列出了某个基线拒绝项的白名单并不会放行它；逃出基线只能通过 `baselineExceptions`（§4.3.3），在那里它是可见且被审计的，别无他途。

`process` 对象上的 `mode: unrestricted` 会整体停用 §3 与 §4，且**必须**在生效策略中被显式表示；它绝不因省略而产生。

### 4.2 系统调用名称

1. 条目是平台发布的、与架构无关的系统调用名（`init_module`、`bpf` 等）。数字型系统调用编号**不得**被接受：它们在不同架构上不同，而一份在 `arm64` 和 `x86_64` 上含义不同的策略，是一份没人能评审的策略。
2. 未知名称**必须**以 `400 INVALID_POLICY` 拒绝并指名该条目。静默忽略未知名称，会把黑名单里的一个拼写错误变成一个洞。
3. 当某个系统调用在某架构上有多个编号变体时，指名它**必须**覆盖全部变体。策略作者写下 `clone` 时**不得**被要求知道还存在 `clone3` 才能得到保护；分组由平台发布。

### 4.3 基线集合 `syscall/1`

只要 `mode` 不是 `unrestricted`，以下内置基线拒绝集合即生效：

```yaml
deniedSyscalls:
  - init_module
  - finit_module
  - delete_module
  - kexec_load
  - kexec_file_load
  - bpf
  - perf_event_open
  - pivot_root
  - setns
  - reboot
  - open_by_handle_at
  - iopl
  - ioperm
  - swapon
  - swapoff
  - add_key
  - keyctl
  - request_key
```

筛选规则与产出 [filesystem.md](./filesystem.md) §6.1 中 `baseline/1` 的那一条相同：拒绝那些既危险*又*不出现在正当应用负载中的东西。加载内核模块、替换正在运行的内核、加入别的进程的命名空间、直接编程 I/O 端口，都不是 Agent 的 Python 脚本在通往正确答案的路上会做的事。

三处刻意的**排除**，记录在此以免有人以为是漏了：

| 被排除 | 原因 |
| --- | --- |
| `ptrace` | 调试器要用它，而 [exec.md](./exec.md) §3.4.2 把 `strace` 与 `ltrace` 列在平台会解析的包装器之中。在基线里拒绝它，会与提案已经预期能工作的一个面自相矛盾。 |
| `unshare`、`chroot` | 创建*自己的*命名空间或根，是正当的负载内沙箱工具会做的事，而 `chroot` 与 `unshare` 同时也在 `exec` 的包装器集合里。注意它与被拒绝的 `setns` 的不对称：创建一个新命名空间是工作负载活动，而*加入一个已存在的*命名空间只对抵达自己边界之外的东西有用。 |
| `mount`、`umount2` | 构建与打包工具用得足够频繁，基线拒绝会产生令人困惑的失败。不需要它的部署**应该**通过 `deniedSyscalls` 自行加上。 |

版本化完全遵循 [filesystem.md](./filesystem.md) §6.2，理由也相同 —— 新的逃逸面会不断被发现，所以集合必须能够增长，而不打破那些已解析到旧版本的策略：

1. 基线集合是**带版本且不可变**的。`syscall/1` 就是上面那个集合；已发布的版本**不得**被原地修改。
2. 新版本**必须**只**追加**条目。移除一个条目会削弱所有解析到该版本的策略，因此**必须**走公告过的弃用周期。
3. `baselineVersion` 用于 pin 住集合。生效策略**必须**始终记录**解析出的**版本，包括策略并未 pin 版本的情形，使版本出现在策略快照中（[overview.md](./overview.md) §4.1）。
4. 未 pin 版本的策略解析到平台的**默认基线版本**。推进该默认值是一次带弃用窗口、需要公告的平台变更；它**不得**静默发生，也**不得**影响已 pin 版本的策略。
5. 沙箱在其整个生命周期内保持其生效策略中记录的版本。新版本只能通过一次策略更新抵达运行中的沙箱，而该更新会产生新的 `effectivePolicyVersion`。

`baselineExceptions` 是那个窄口退出，条件与 [filesystem.md](./filesystem.md) §6.3 相同：

1. 每个条目**必须**与被 pin 集合中的某个条目精确匹配。匹配不到任何条目的**必须**以 `400 INVALID_POLICY` 拒绝，使例外不会随集合演进而静默沦为死配置。
2. 例外**仅**作用于内置集合。它们**不得**取消任何来源的显式 `deniedSyscalls` 条目。
3. 它们按**交集**合并：一个例外只有在每个贡献来源都声明它时才生效（只能收窄，[overview.md](./overview.md) §5）。
4. 每一个生效的例外**必须**被记录在生效策略中，并**必须**在沙箱创建时产生一条审计事件。"这个沙箱可以调用 `bpf`"对运维永不隐形。

### 4.4 隐式必需集合

`allowlist` 模式有着与 `writableRoots` 完全相同的陷阱（[filesystem.md](./filesystem.md) §6.4）：一份按*工作负载做什么*来写的清单，会漏掉运行时在它之下所做的一切，而结果不是一条可读的策略拒绝，而是一个根本起不来的进程。

因此，当 `syscall.mode` 为 `allowlist` 时，一个带版本的**必需集合** —— 缺了它任何进程都无法被创建、运行或退出的那些系统调用（`execve`、`exit_group`、`mmap`、`brk`、`rt_sigreturn` 及其同类）—— 被隐式允许，除非 `implicitEssentialSyscalls: false`。

1. 必需集合对 `allowedSyscalls` 是增量的，并与基线集合一同版本化。它绝不覆盖基线拒绝集合 —— 按 §4.1，基线仍然胜出。
2. `implicitEssentialSyscalls: false` 是给那些基于完整枚举的镜像画像构建的策略用的。这类策略**必须**列出其运行时需要的每一个系统调用，并**应该**由观测画像生成，而不是手写。
3. 平台**必须**在生效策略中记录所施加的必需集合版本。

### 4.5 强制执行要求

1. 策略**必须**适用于沙箱运行的**每一个进程**，而不只是某个特定入口点的后代进程。一个 shell 出去执行任意二进制的进程**必须**继承同一套限制。
2. 强制执行**不得**依赖环境变量、`LD_PRELOAD`、`PATH` 操纵或任何纯用户态的拦截 —— 与 [filesystem.md](./filesystem.md) §4.3.2 相同的要求，理由也相同：这些全都在工作负载的掌控之中。
3. 限制**必须**在目标程序的第一条指令执行之前安装好，并**必须**对该进程及其后代不可逆。
4. `onViolation: deny` 以 `EPERM` 把拒绝呈现给调用进程。`onViolation: kill` 则终止该进程。`kill` 把一个被利用的进程变成一个死进程，而不是一个学到了哪些系统调用被过滤的进程；`deny` 让那些不合身但诚实的工作负载继续跑。二者都不是普适正确的，所以它是一个字段。
5. 拒绝**不得**以一种可与普通权限失败区分开的方式，向沙箱泄露命中规则的身份。规则身份属于审计流（§6），而不属于某条工作负载可以探测的旁路。

## 5. 字段规格

| 字段 | 类型 | 约束 | 默认 | 语义 |
| --- | --- | --- | --- | --- |
| `mode` | `enum?` | `baseline` \| `unrestricted` | `baseline` | §4.1。`unrestricted` 停用 §3 与 §4。 |
| `noNewPrivileges` | `bool?` | — | `false` | §3.1。 |
| `allowDaemonize` | `bool?` | — | `true` | §3.3。 |
| `allowedCapabilities` | `[string]?` | 已知能力名。 | `[]` = 平台默认集合 | §3.2。 |
| `audit` | `enum?` | `none` \| `metadata` | `none` | 进程策略事件的审计级别（§6）。 |
| `syscall.mode` | `enum?` | `baseline` \| `denylist` \| `allowlist` | `baseline` | §4.1。 |
| `syscall.baselineVersion` | `string?` | 已发布的集合标识。未知取值**必须**以 `400 INVALID_POLICY` 拒绝。 | 平台默认值 | §4.3。 |
| `syscall.baselineExceptions` | `[string]?` | 每个条目**必须**与被 pin 集合中的条目精确匹配。 | `[]` | §4.3。 |
| `syscall.deniedSyscalls` | `[string]?` | 仅在 `mode: denylist` 下有意义。 | `[]` | 额外被拒绝的系统调用。 |
| `syscall.allowedSyscalls` | `[string]?` | 仅在 `mode: allowlist` 下有意义；此时**必须**非空。 | `[]` | 被许可的集合，外加 §4.4。 |
| `syscall.implicitEssentialSyscalls` | `bool?` | — | `true` | §4.4。 |
| `syscall.onViolation` | `enum?` | `deny` \| `kill` | `deny` | §4.5.4。 |

在 `mode: denylist` 下设置 `allowedSyscalls`、或在 `mode: allowlist` 下设置 `deniedSyscalls`，**必须**以 `400 INVALID_POLICY` 拒绝：该字段在那个模式下没有意义，而接受它会让作者以为某份清单正在生效，而其实并没有。

### 5.1 分级默认值

采用哪一套默认值由 `policy.tier` 选择（[overview.md](./overview.md) §7.1）：

| 字段 | `tier: baseline`（默认） | `tier: restricted` |
| --- | --- | --- |
| `mode` | `baseline` | `baseline` |
| `syscall.mode` | `baseline` | `baseline` |
| `noNewPrivileges` | `false` | `true` |
| `allowDaemonize` | `true` | `false` |
| `audit` | `none` | `metadata` |

两个分级都让 `syscall/1` 拒绝集合生效。只有提权与持久化不同，因为这是两个无需知道工作负载就能做的决定：一个镜像要么需要 `sudo`，要么不需要，而无论哪种情况失败都是立即且可读的。系统调用面不是分级该决定的事，理由正相反 —— 进一步收窄它需要知道镜像用到哪些系统调用，而一个会去猜的分级会产生 §4.4 存在的目的所要防止的"进程起不来"式失败。`restricted` 是否应该引入第二个更大的基线集合，记录为 §10.2。

这里的 `tier: baseline` 并不是逐字节等于今天的行为 —— `syscall/1` 集合是新的，而本模块此前并不存在。它是兼容性规则两处刻意例外之一（[overview.md](./overview.md) §9），并且受到与另一处相同的约束：集合是带版本、可 pin 的，且可通过 `baselineExceptions` 逐条逃出（§4.3）。

## 6. 错误与可观测性

| 错误码 | 呈现面 | 载荷 | 何时 |
| --- | --- | --- | --- |
| `POLICY_PROCESS_SYSCALL_DENIED` | 对进程返回 `EPERM`；审计事件 | `{syscall, mode, source}` | 某个系统调用按 §4.1 被拒绝。 |
| `POLICY_PROCESS_PRIVILEGE_DENIED` | OS 级失败；审计事件 | `{operation, binary?}` | 按 §3.1 拒绝提权，或按 §3.2 拒绝某项能力。 |
| `POLICY_PROCESS_PERSISTENCE_DENIED` | OS 级失败；审计事件 | `{operation}` | 按 §3.3 拒绝脱离或重挂父进程。 |
| `INVALID_POLICY` | `400` | `{field, reason}` | 未知系统调用名或能力名、例外不在被 pin 集合中、`allowlist` 下 `allowedSyscalls` 为空、字段与模式不匹配。 |

与 `filesystem` 一样，强制执行错误是 OS 级而非 API 级的，因为策略作用于 API 层之下。

`audit: metadata` 下的审计事件：`{sandboxID, event: syscall_denied|privilege_denied|persistence_denied, syscall?, operation?, pid, comm, outcome: denied|killed, effectivePolicyVersion}`。每一个生效的 `baselineExceptions` 条目在创建时产生 `{sandboxID, baselineVersion, exception, sources}`（§4.3）。审计事件**不得**写入沙箱内部。

一个触发了系统调用拒绝的工作负载通常会反复触发它。实现**应该**聚合相同的 `{syscall, pid}` 拒绝，而不是每次调用发一条事件，使审计流在一份很紧的 `allowlist` 下仍然可读。

## 7. 合并语义

在 [overview.md](./overview.md) §5 的共享规则之上：

| 字段 | 合并细化 |
| --- | --- |
| `mode` | 最严格者胜出：任一来源为 `baseline`，结果即为 `baseline`。 |
| `noNewPrivileges` | `true` 胜出。 |
| `allowDaemonize` | `false` 胜出。 |
| `allowedCapabilities` | 各来源取**交集**（只能收窄）。请求不能添加模板未许可的能力。 |
| `syscall.mode` | 最严格者胜出：`allowlist` > `denylist` > `baseline`。 |
| `syscall.baselineVersion` | 被 pin 的最新版本胜出；由于版本只追加条目（§4.3.2），最新也即最严格。 |
| `syscall.baselineExceptions` | 交集：一个例外只有在每个来源都声明它时才生效。 |
| `syscall.deniedSyscalls` | 追加 + 去重。 |
| `syscall.allowedSyscalls` | 各来源取**交集**：高优先级来源只能缩小被许可集合。追加会让请求放宽管理员的白名单，而 §5 禁止这样做。 |
| `syscall.implicitEssentialSyscalls` | `false` 胜出（更严格）。 |
| `syscall.onViolation` | `kill` 胜出。 |
| `audit` | 更详细者胜出（`metadata` > `none`）。 |

## 8. 可授权字段

按 [overview.md](./overview.md) §5.1.8，本模块指名限时授权可以打开什么：

| 可授权 | 不可授权 |
| --- | --- |
| `syscall.baselineExceptions` — 指名条目，限定窗口内 | `mode: unrestricted` |
| `syscall.allowedSyscalls` — 向被许可集合指名追加 | `noNewPrivileges: false` |
| `allowedCapabilities` — 指名能力 | `syscall.implicitEssentialSyscalls` |
| `allowDaemonize: true` | |

`mode: unrestricted` 与 `noNewPrivileges: false` 被排除，是因为授权必须是"一个形状已知的洞"（[overview.md](./overview.md) §5.1.4）。翻转 `noNewPrivileges` 会一次性打开镜像中的每一个 setuid 二进制与每一项文件能力；批准它的运维无法知道自己批准了什么。一个确实需要十分钟特权的任务，去申请它需要的那项能力 —— 那是可评审的，且到期后自动收回。

这里的每一份授权都仍受上限约束（[overview.md](./overview.md) §5.1.3）：授权**不得**重开模板或策略档已关闭的能力或系统调用。

## 9. 验收标准

1. **普遍适用。** 通过 `exec` 启动的进程、它 `fork`/`exec` 出的进程、以及由 `exec` 白名单放行的解释器启动的进程，受到完全相同的 `process` 策略约束。具体地：在 `syscall/1` 生效时，无论 `init_module` 是从控制接口抵达，还是从一段被放行的 `python -c` 脚本内部抵达，都被拒绝。
2. **基线在白名单下存活。** 一份 `syscall.mode: allowlist` 且在 `allowedSyscalls` 中写了 `bpf` 的策略仍然拒绝 `bpf`，因为基线集合胜出（§4.1）。放行它需要一条 `baselineExceptions` 条目，而它会产生创建时审计事件。
3. **刻意的排除。** 只有基线生效时，`ptrace`、`unshare`、`chroot` 成功，而 `setns` 被拒绝。
4. **不可逆性。** 进程无法解除 `noNewPrivileges`、无法重获 `allowedCapabilities` 之外的能力、无法移除自己的系统调用过滤器。后代进程继承这三者。
5. **提权。** `noNewPrivileges: true` 时执行 setuid 二进制不产生提权；`noNewPrivileges: false`（baseline 分级默认值）时同一个二进制的行为与今天一致。
6. **持久化。** `allowDaemonize: false` 时，`setsid` 与双重 `fork` 变孤儿被拒绝，且终止一个会话会终止其整个进程组。默认 `true` 时，两者都与今天一样可用。
7. **用名字，不用编号。** 使用数字型系统调用编号的策略被拒绝；指名了一个有多个编号变体的系统调用的策略，在每一个受支持架构上覆盖其全部变体。
8. **未知条目。** 未知系统调用名、未知能力名、以及不在被 pin 集合中的 `baselineExceptions` 条目，各自都以 `400 INVALID_POLICY` 并带 `field` 指针被拒绝。
9. **必需集合。** `syscall.mode: allowlist` 且 `allowedSyscalls: [read, write]`，在 `implicitEssentialSyscalls: true` 下能成功启动进程，且生效策略记录了所施加的必需集合版本。在 `implicitEssentialSyscalls: false` 与同一份清单下，进程创建以一条带审计事件的策略拒绝失败 —— 而不是以一次无从解释的崩溃失败。
10. **违规动作。** `onViolation: deny` 返回 `EPERM` 并让进程继续运行；`onViolation: kill` 终止它。两者都产生携带 `effectivePolicyVersion` 的审计事件。
11. **版本 pin。** 已 pin 到 `syscall/1` 的沙箱在平台默认值推进到 `syscall/2` 时不受影响；未 pin 的沙箱无论如何都在其生效策略与快照中记录解析出的版本。
12. **合并。** `allowedCapabilities` 与 `allowedSyscalls` 在各来源间取交集 —— 请求无法放宽其中任何一个。`noNewPrivileges: true`、`allowDaemonize: false`、`onViolation: kill` 以及最严格的 `syscall.mode`，各自都从任一来源胜出。
13. **例外取交集。** 请求声明了但模板未声明的 `baselineExceptions` 条目不生效，且其不生效按 [overview.md](./overview.md) §5 被报告。
14. **授权。** 一份追加了某项具名能力的授权，在沙箱或任务不做任何动作的情况下到期，之后该能力再次不可用；试图授予 `mode: unrestricted` 或 `noNewPrivileges: false` 的授权被拒绝；试图重开模板已关闭能力的授权以 `POLICY_GRANT_EXCEEDS_CEILING` 被拒绝。
15. **无旁路。** 从沙箱内部看，被拒绝的系统调用与普通权限失败无法区分；命中的规则只出现在审计流中。

## 10. 开放问题

1. **进程数与 fork 炸弹。** 进程数上限属于消耗量，按本提案划的缝它应归 `resource` —— 但它在进程创建时强制执行，和本文档里的一切一样。归哪个模块？
2. **restricted 分级的系统调用集合。** `tier: restricted` 目前展开为与 `tier: baseline` 相同的基线集合（[overview.md](./overview.md) §7.1）。`restricted` 是否应该引入第二个更大的带版本集合（追加 `mount`、`umount2`、`unshare`），而不是只收紧权限与持久化？
3. **画像生成。** §4.4.2 建议由观测画像生成 `allowlist` 策略。平台是否应把这项观测作为受支持的功能提供（一种"记录系统调用、产出候选策略"的模式），还是手写白名单是唯一受支持的路径？
4. **能力默认集合。** §3.2.3 把"平台默认集合"留给了平台。该默认集合本身是否应成为一个带版本、已发布的集合，条件与系统调用基线相同，从而可 pin、可审计？
5. **持久化路径集合。** §3.4 把自启型持久化推给了 `filesystem`。文件系统基线是否应新增一个带版本的持久化路径集合（`crontab`、systemd unit、shell profile），让 `allowDaemonize: false` 有一个已文档化的搭档，而不只是一条建议？
6. **热施加。** 更新后的进程策略能否施加到已在运行的进程，还是只对新进程生效？系统调用过滤器通常在进程创建时安装，并按设计不可逆，这暗示"仅新进程" —— 而按 [overview.md](./overview.md) §11.2，那将意味着本模块无法针对已在运行的进程接受授权。本规格**不得**在没有明确答案的情况下发布。

## 11. 非规范性说明

- 本文档的每一条要求都可以用按进程、非特权、按沙箱的机制表达（在进程创建时安装的 seccomp 式过滤器、内核的 no-new-privileges 标记、bounding 能力集、按会话的进程组跟踪）。与本提案其他部分一样，规格固定的是*属性*，机制选型留待开放。
- 每沙箱一个内核的模型，是系统调用策略负担得起的原因：过滤器的作用域是单一租户的内核，因此收窄它不会波及邻居（[overview.md](./overview.md) §12）。
- 参考过的类比对象：Kubernetes Pod Security Standards 与 `seccompProfile`、Docker 默认 seccomp 画像与 `--security-opt no-new-privileges`、systemd unit sandboxing 指令。
