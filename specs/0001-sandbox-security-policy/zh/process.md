# 规格：进程策略（Process Policy）

属于 [提案 0001 — 沙箱安全策略](./overview.md)。本文档中的关键词 **必须（MUST）**、**不得（MUST NOT）**、**应该（SHOULD）**、**可以（MAY）** 依据 RFC 2119 解释。

---

## 1. 范围

本规格定义 `SandboxPolicy` 对象的进程（`process`）子策略：适用于**已在沙箱内运行的进程**的约束，无论它是以何种方式启动的。它治理三件事：

- **权限** — 进程起步时带有哪些权限，以及它是否可以获得任何它启动时并不持有的权限。
- **持久化** — 进程是否可以活得比启动它的会话更久。
- **系统调用** — 沙箱到底可以使用哪些内核入口。

这个模块之所以存在，是因为提案其余部分已经明确指出了一处缺口。[exec.md](./exec.md) §1 与 §3.6 声明 `exec` 策略是一道控制接口门禁，**不是**围堵边界：一条命令一旦被放行，它启动的进程可以 `fork`/`exec` 任何东西而不再经过 `exec` 求值，而对 Agent 生成的代码来说，被放行的那条命令典型就是一个解释器。[overview.md](./overview.md) §2.3 给出了推论 —— 对自启进程的围堵，必须来自在控制接口之下强制执行的模块。

`process` 就是权限面与系统调用面上的那道围堵，正如 `filesystem` 之于路径、`network` 之于目标。分工是固定的，不是口味问题：

| 问题 | 模块 |
| --- | --- |
| 这条命令可以通过 API 被启动吗？ | `exec` |
| 这个运行中的进程可以以这个用户运行、可以提权、可以持久化、可以发起这个系统调用吗？ | `process`（本规格） |
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
    runAsNonRoot:         bool                      # 默认：false
    allowDaemonize:       bool                      # 默认：true
    allowedCapabilities:  [string]                  # 默认：平台默认集合；["none"] = 空集
    onViolation:          deny | kill               # 默认：deny —— 适用于 §3 与 §4
    audit:                none | metadata           # 默认：none
    syscall:
      mode:                       baseline | denylist | allowlist   # 默认：baseline
      baselineVersion:            string            # 如 "syscall/1"；默认：平台默认值
      baselineExceptions:         [string]          # 从基线集合中排除的系统调用
      deniedSyscalls:             [string]
      allowedSyscalls:            [string]
      implicitEssentialSyscalls:  bool              # 默认：true
      onViolation:                deny | kill       # 默认：继承 process.onViolation
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
3. 空列表表示"平台默认集合"，而不是"没有能力"。省略绝不意味着限制（原则 2），所以需要一个窄集合的工作负载就指名那个集合。
4. **空集** —— 完全没有任何能力，也就是本字段最强的形态 —— 写作保留的单一条目 `["none"]`。它**不得**与任何能力名混用；`["none", "net_bind_service"]` **必须**以 `400 INVALID_POLICY` 拒绝，因为它读起来像"没有，除了……"，而那什么意思都不是。

   规则 4 之所以存在，是因为规则 1 与规则 3 合在一起，使本字段中最有价值的那个取值变得无法表达。`[]` 已经被"平台默认集合"占用，所以在 `["none"]` 之前，接近零能力的唯一办法是指名一个集合并期待它足够小 —— 那是对唯一一种评审者能一眼验证的姿态的近似。对于不需要任何能力的工作负载（即绝大多数 Agent 生成的代码而言），丢弃全部能力是可获得的最有效的单项加固措施，它不该需要一个变通写法。这里用一个拼写出来的保留词而不是复用 `[]`，是为了让省略与空列表继续表示同一件事，而这正是原则 2 的要求。

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

### 3.5 `runAsNonRoot`

§3.1 管的是一个进程**可以获得**的特权。它对一个进程**起步时就带有**的特权只字未提，而这处遗漏的受力方向是错的：`noNewPrivileges: true` 施加在一个已经以 uid 0 运行的进程上什么也保护不了，因为已经没有什么可供它去获得了。

取 `true` 时：

1. 沙箱内任何进程都**不可以**以 uid 0 运行。这适用于每一个进程，无论它以何种方式启动 —— 与 §4.5.1 同样的普遍适用性。
2. 若解析出的沙箱用户会是 uid 0 —— 因为镜像默认用户是 root 且未指定其他用户 —— 则创建请求**必须**以 `400 INVALID_POLICY` 拒绝，并指名解析出的那个用户。在创建时失败是刻意的：另一种结果是沙箱起来了，然后在它的第一个进程上失败，而那个位置离肇因策略很远。
3. 运行时试图变成 uid 0 —— `setuid(0)` 及其同类 —— **必须**被拒绝，且**必须**在进程持有本来允许该操作的那个能力时也被拒绝。一个进程能放弃的属性，就不是一个属性。
4. 检查的是数值 uid 0，而不是名字 `root`。一个能靠给账户改名来满足的策略不是策略。

`runAsNonRoot` 与 `noNewPrivileges` 相互独立且互补，两者都值得设置：

| | 起步时无特权 | 起步时即 root |
| --- | --- | --- |
| `noNewPrivileges: true` | 无法获得特权 —— 有效 | 已经什么都有了 —— **毫无作用** |
| `runAsNonRoot: true` | 本来就成立 —— 无变化 | 在创建时被拒（规则 2） |

默认值在 `baseline` 分级下是 `false`、在 `restricted` 下是 `true`（[overview.md](./overview.md) §7.1），与 `noNewPrivileges` 是同一种切分，理由也相同：一个镜像要么以 root 运行要么不是，这个答案无需知道工作负载就能得到，而按规则 2 失败是立即的、并且会指名自己的原因。有必要明说的是，这让 `tier: restricted` **直接拒绝以 root 为默认用户的镜像**。这不是一个需要被抹平的副作用 —— 它就是这个分级的含义；而一个在 `restricted` 下确实需要 root 默认镜像的运维会显式写 `runAsNonRoot: false`，那是在生效策略里可见的（§7.1 规则 3）。

注意与 [exec.md](./exec.md) §5 的分工。`exec.allowedUsers` 约束的是**经控制接口**提交的命令可以以哪个用户运行；`runAsNonRoot` 约束的是沙箱内每一个进程，无论其来源。`exec` 那个字段是 API 上的一道门禁，而这一个是沙箱的一项属性 —— 与 [overview.md](./overview.md) §2.3 为这两个模块中其他每一对字段划出的，是同一种不对称。

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
4. 违规动作由 `onViolation` 决定（§4.6）。它同样治理 §3 与 §4，而 `syscall.onViolation` 只为系统调用面覆盖它。
5. 拒绝**不得**以一种可与普通权限失败区分开的方式，向沙箱泄露命中规则的身份。规则身份属于审计流（§6），而不属于某条工作负载可以探测的旁路。

### 4.6 违规动作

依 [overview.md](./overview.md) §8.1，本模块把每一次违规 —— 提权（§3.1）、使用集合之外的能力（§3.2）、脱离或重挂父进程（§3.3）、抵达 uid 0（§3.5），以及每一次被拒绝的系统调用（§4.1）—— 都通过同一个字段来解析：

| 动作 | 结果 |
| --- | --- |
| `deny`（默认） | 操作失败：系统调用拒绝对调用进程返回 `EPERM`，其余情况返回相应的 OS 级失败。进程继续运行。 |
| `kill` | 改为终止**那个违规进程**。这里的强制执行点在内核边界上，精确地知道自己的调用者，所以终止是精准的 —— 不同于 `network`，同一个动作在那里会结束整个沙箱（[overview.md](./overview.md) §8.1.3）。 |

1. `syscall.onViolation` 被设置时，**仅为系统调用面**覆盖 `onViolation`。§3 的违规始终遵循模块级字段。之所以存在两级，是因为系统调用面是那个"一份过紧的 `allowlist` 会产出本属*策略*而非工作负载之过的违规"的地方，而一个部署完全可能合理地希望那些被拒绝，同时让一次提权尝试被杀掉。
2. `syscall.onViolation` 缺省时继承 `onViolation`。由于两者都默认为 `deny`，一份未配置的策略的行为与本字段存在之前完全一致。
3. `kill` 把一个被利用的进程变成一个死进程，而不是一个学到了哪些系统调用被过滤的进程；`deny` 让那些不合身但诚实的工作负载继续跑。二者都不是普适正确的，所以它是一个字段，而默认值取的是保守的那个。
4. 没有 `warn` 动作，理由见 [overview.md](./overview.md) §8.1.2：一个检测到提权之后又放行它的动作，不是策略。要观察一个更严的姿态*本来会*拒绝什么，用 `auditTier`（§6.1）。
5. 两种动作都会产生违规事件，且在任何审计级别下都产生（[overview.md](./overview.md) §8.1.4）。

## 5. 字段规格

| 字段 | 类型 | 约束 | 默认 | 语义 |
| --- | --- | --- | --- | --- |
| `mode` | `enum?` | `baseline` \| `unrestricted` | `baseline` | §4.1。`unrestricted` 停用 §3 与 §4。 |
| `noNewPrivileges` | `bool?` | — | `false` | §3.1。 |
| `runAsNonRoot` | `bool?` | — | `false` | §3.5。 |
| `allowDaemonize` | `bool?` | — | `true` | §3.3。 |
| `allowedCapabilities` | `[string]?` | 已知能力名，或保留的单一条目 `["none"]`，后者**不得**与名称混用。 | `[]` = 平台默认集合 | §3.2。 |
| `onViolation` | `enum?` | `deny` \| `kill` | `deny` | §4.6。适用于 §3 与 §4。 |
| `audit` | `enum?` | `none` \| `metadata` | `none` | **普通**进程事件的审计级别（§6）。它不压制违规事件（[overview.md](./overview.md) §8.1.4）。 |
| `syscall.mode` | `enum?` | `baseline` \| `denylist` \| `allowlist` | `baseline` | §4.1。 |
| `syscall.baselineVersion` | `string?` | 已发布的集合标识。未知取值**必须**以 `400 INVALID_POLICY` 拒绝。 | 平台默认值 | §4.3。 |
| `syscall.baselineExceptions` | `[string]?` | 每个条目**必须**与被 pin 集合中的条目精确匹配。 | `[]` | §4.3。 |
| `syscall.deniedSyscalls` | `[string]?` | 仅在 `mode: denylist` 下有意义。 | `[]` | 额外被拒绝的系统调用。 |
| `syscall.allowedSyscalls` | `[string]?` | 仅在 `mode: allowlist` 下有意义；此时**必须**非空。 | `[]` | 被许可的集合，外加 §4.4。 |
| `syscall.implicitEssentialSyscalls` | `bool?` | — | `true` | §4.4。 |
| `syscall.onViolation` | `enum?` | `deny` \| `kill` | 继承 `onViolation` | §4.6。仅为系统调用面覆盖 `onViolation`。 |

在 `mode: denylist` 下设置 `allowedSyscalls`、或在 `mode: allowlist` 下设置 `deniedSyscalls`，**必须**以 `400 INVALID_POLICY` 拒绝：该字段在那个模式下没有意义，而接受它会让作者以为某份清单正在生效，而其实并没有。

### 5.1 分级默认值

采用哪一套默认值由 `policy.tier` 选择（[overview.md](./overview.md) §7.1）：

| 字段 | `tier: baseline`（默认） | `tier: restricted` |
| --- | --- | --- |
| `mode` | `baseline` | `baseline` |
| `syscall.mode` | `baseline` | `baseline` |
| `noNewPrivileges` | `false` | `true` |
| `runAsNonRoot` | `false` | `true` |
| `allowDaemonize` | `true` | `false` |
| `onViolation` | `deny` | `deny` |
| `audit` | `none` | `metadata` |

两个分级都让 `syscall/1` 拒绝集合生效。只有特权与持久化不同，因为这是无需知道工作负载就能做的决定：一个镜像要么需要 `sudo` 要么不需要，要么以 root 运行要么不是，而无论哪种情况失败都是立即且可读的。系统调用面不是分级该决定的事，理由正相反 —— 进一步收窄它需要知道镜像用到哪些系统调用，而一个会去猜的分级会产生 §4.4 存在的目的所要防止的"进程起不来"式失败。`allowedCapabilities` 因同样的理由被留在原样：`["none"]` 对大多数 Agent 工作负载是对的取值，对任何要绑定特权端口的镜像是错的取值，而分级分不清自己手上是哪一种。`onViolation` 在两个分级下都留在 `deny`，那有它自己的理由，见 [overview.md](./overview.md) §8.1.7。`restricted` 是否应该引入第二个更大的基线集合，记录为 §10.2。

在这几项里，`runAsNonRoot: true` 是最有可能直接拒掉一个存量镜像的那一项（§3.5 规则 2）。这是有意的，而 [overview.md](./overview.md) §7.2 就是运维在真正投入之前弄清这件事的方式：`auditTier: restricted` 会上报哪些沙箱*本来会*被拒，而不拒任何一个。

这里的 `tier: baseline` 并不是逐字节等于今天的行为 —— `syscall/1` 集合是新的，而本模块此前并不存在。它是兼容性规则两处刻意例外之一（[overview.md](./overview.md) §9），并且受到与另一处相同的约束：集合是带版本、可 pin 的，且可通过 `baselineExceptions` 逐条逃出（§4.3）。

## 6. 错误与可观测性

| 错误码 | 呈现面 | 载荷 | 何时 |
| --- | --- | --- | --- |
| `POLICY_PROCESS_SYSCALL_DENIED` | 对进程返回 `EPERM`，或在 `kill` 下终止进程；审计事件 | `{syscall, mode, source, action}` | 某个系统调用按 §4.1 被拒绝。 |
| `POLICY_PROCESS_PRIVILEGE_DENIED` | OS 级失败，或在 `kill` 下终止进程；审计事件 | `{operation, binary?, action}` | 按 §3.1 拒绝提权、按 §3.2 拒绝某项能力，或按 §3.5.3 拒绝一次变成 uid 0 的尝试。 |
| `POLICY_PROCESS_PERSISTENCE_DENIED` | OS 级失败，或在 `kill` 下终止进程；审计事件 | `{operation, action}` | 按 §3.3 拒绝脱离或重挂父进程。 |
| `INVALID_POLICY` | `400` | `{field, reason}` | 未知系统调用名或能力名、`["none"]` 与能力名混用、`runAsNonRoot: true` 下解析出的沙箱用户为 uid 0（§3.5.2）、例外不在被 pin 集合中、`allowlist` 下 `allowedSyscalls` 为空、字段与模式不匹配。 |

与 `filesystem` 一样，强制执行错误是 OS 级而非 API 级的，因为策略作用于 API 层之下。每份载荷都携带 `action: denied|killed`，使审计的读者无需通过"该进程之后再无事件"来反推，就能判断 §4.6 的两种结果中发生了哪一种。

违规事件在**任何**审计级别下都会产生，包括 `audit: none`，依 [overview.md](./overview.md) §8.1.4：`{sandboxID, event: syscall_denied|privilege_denied|persistence_denied, syscall?, operation?, pid, comm, outcome: denied|killed, effectivePolicyVersion, shadow: false}`。而 `audit: metadata` 所增加的是对**普通**活动的记录 —— 进程启动、解析出的用户、在用的能力集 —— 那才是一个部署可能合理地不想要的部分。每一个生效的 `baselineExceptions` 条目在创建时产生 `{sandboxID, baselineVersion, exception, sources}`（§4.3），同样与审计级别无关，因为削弱基线不是普通活动。审计事件**不得**写入沙箱内部。

一个触发了系统调用拒绝的工作负载通常会反复触发它。实现**应该**聚合相同的 `{syscall, pid}` 拒绝，而不是每次调用发一条事件，使审计流在一份很紧的 `allowlist` 下仍然可读。

### 6.1 影子评估支持

依 [overview.md](./overview.md) §7.2.5，本模块声明它在 `auditTier` 之下支持什么。本模块正是影子评估存在的理由：`syscall/1` 与 `restricted` 的展开内容是最有可能弄坏一个镜像的变更，而其损坏形态最不可读。

| 字段 | 是否影子 | 方式 |
| --- | --- | --- |
| `syscall.*` | 是 | 更严的集合与被强制执行的集合并行求值；影子集合本来会拒绝的调用产生一条 `shadow: true` 事件并照常执行。 |
| `noNewPrivileges`、`allowDaemonize` | 是 | 操作按被强制执行的取值照常进行；一条影子事件记录下更严的取值本来会拒绝它。 |
| `allowedCapabilities` | 是 | 使用影子集合之外的某项能力时产生一条影子事件。 |
| `runAsNonRoot` | 是，**在创建时** | §3.5.2 让这一项成为创建时检查，因此影子发现在创建时产生："这个沙箱在 `restricted` 之下本来会被拒"。这是本模块中价值最高的一条影子发现，因为它正是把一次 fleet 范围的铺开变成一份待修镜像清单的那一条。 |

有两条约束来自机制本身而不是取舍偏好：

1. 系统调用的影子评估**不得**改变被强制执行的过滤器。既上报一次本来会发生的拒绝、又放行该调用，需要一个既记录又允许的过滤动作；机制上无法同时做到记录与允许的部署**不得**用"改成拒绝"来近似它。
2. 影子拒绝**不得**以任何形式被上报给进程，依 [overview.md](./overview.md) §7.2.4。进程什么都学不到；审计流什么都学到。

## 7. 合并语义

在 [overview.md](./overview.md) §5 的共享规则之上：

| 字段 | 合并细化 |
| --- | --- |
| `mode` | 最严格者胜出：任一来源为 `baseline`，结果即为 `baseline`。 |
| `noNewPrivileges` | `true` 胜出。 |
| `runAsNonRoot` | `true` 胜出。 |
| `allowDaemonize` | `false` 胜出。 |
| `allowedCapabilities` | 各来源取**交集**（只能收窄）。请求不能添加模板未许可的能力。`["none"]` 与任何集合取交集都是 `["none"]`，因为它就是空集（§3.2.4）。 |
| `syscall.mode` | 最严格者胜出：`allowlist` > `denylist` > `baseline`。 |
| `syscall.baselineVersion` | 被 pin 的最新版本胜出；由于版本只追加条目（§4.3.2），最新也即最严格。 |
| `syscall.baselineExceptions` | 交集：一个例外只有在每个来源都声明它时才生效。 |
| `syscall.deniedSyscalls` | 追加 + 去重。 |
| `syscall.allowedSyscalls` | 各来源取**交集**：高优先级来源只能缩小被许可集合。追加会让请求放宽管理员的白名单，而 §5 禁止这样做。 |
| `syscall.implicitEssentialSyscalls` | `false` 胜出（更严格）。 |
| `onViolation` | `kill` 胜出（[overview.md](./overview.md) §8.1.7）。 |
| `syscall.onViolation` | `kill` 胜出。与 `onViolation` 独立合并；只设置模块级字段的来源不约束系统调用级的那个，反之亦然。 |
| `audit` | 更详细者胜出（`metadata` > `none`）。 |

## 8. 可授权字段

按 [overview.md](./overview.md) §5.1.8，本模块指名限时授权可以打开什么：

| 可授权 | 不可授权 |
| --- | --- |
| `syscall.baselineExceptions` — 指名条目，限定窗口内 | `mode: unrestricted` |
| `syscall.allowedSyscalls` — 向被许可集合指名追加 | `noNewPrivileges: false` |
| `allowedCapabilities` — 指名能力 | `runAsNonRoot: false` |
| `allowDaemonize: true` | `syscall.implicitEssentialSyscalls` |

`mode: unrestricted` 与 `noNewPrivileges: false` 被排除，是因为授权必须是"一个形状已知的洞"（[overview.md](./overview.md) §5.1.4）。翻转 `noNewPrivileges` 会一次性打开镜像中的每一个 setuid 二进制与每一项文件能力；批准它的运维无法知道自己批准了什么。一个确实需要十分钟特权的任务，去申请它需要的那项能力 —— 那是可评审的，且到期后自动收回。

`runAsNonRoot: false` 被排除的理由比"形状"更强：它在原理上就无法被授权。按 §3.5.2 这个字段在创建时就已解析，而一个以非 root 用户启动的沙箱无法被交给十分钟的 uid 0 再被拿回来 —— 已经在跑的那些进程得改变身份，而它们以 root 创建的任何文件都会活得比这份授权更久。一份效果比自己的到期更长命的授权就不是限时的，而限时是 §5.1 的全部前提。需要 root 是沙箱的一项属性，所以它属于沙箱创建时所用的那份策略。

针对 `allowedCapabilities: ["none"]` 授权一项能力是允许的，而且这正是"这个任务需要做一次特权操作"的预期处理方式：沙箱以零能力运行，在一个限定窗口内收到它确实需要的那一项，然后回到零。这和其他一切一样受上限约束 —— 如果是模板设了 `["none"]`，那就是一条模板限制，任何授权都不得重新打开它。

这里的每一份授权都仍受上限约束（[overview.md](./overview.md) §5.1.3）：授权**不得**重开模板或策略档已关闭的能力或系统调用。

## 9. 验收标准

1. **普遍适用。** 通过 `exec` 启动的进程、它 `fork`/`exec` 出的进程、以及由 `exec` 白名单放行的解释器启动的进程，受到完全相同的 `process` 策略约束。具体地：在 `syscall/1` 生效时，无论 `init_module` 是从控制接口抵达，还是从一段被放行的 `python -c` 脚本内部抵达，都被拒绝。
2. **基线在白名单下存活。** 一份 `syscall.mode: allowlist` 且在 `allowedSyscalls` 中写了 `bpf` 的策略仍然拒绝 `bpf`，因为基线集合胜出（§4.1）。放行它需要一条 `baselineExceptions` 条目，而它会产生创建时审计事件。
3. **刻意的排除。** 只有基线生效时，`ptrace`、`unshare`、`chroot` 成功，而 `setns` 被拒绝。
4. **不可逆性。** 进程无法解除 `noNewPrivileges`、无法重获 `allowedCapabilities` 之外的能力、无法移除自己的系统调用过滤器。后代进程继承这三者。
5. **提权。** `noNewPrivileges: true` 时执行 setuid 二进制不产生提权；`noNewPrivileges: false`（baseline 分级默认值）时同一个二进制的行为与今天一致。
6. **起始身份。** `runAsNonRoot: true` 时，解析出的用户为 uid 0 的沙箱在创建时以 `400 INVALID_POLICY` 被拒并指名该用户；运行中的进程即便持有本来允许该操作的能力，也无法经 `setuid(0)` 抵达 uid 0。一个已从 `root` 改名但仍是 uid 0 的账户被拒；一个名叫 `root` 但 uid 非零的账户不被拒。在 baseline 分级默认值 `false` 下，root 默认镜像的启动与今天一致。
7. **单靠 `noNewPrivileges` 是不够的。** 一个以 uid 0 运行、配置了 `noNewPrivileges: true` 与 `runAsNonRoot: false` 的沙箱，仍然能做 uid 0 能做的一切。这一条被写成测试断言，是为了让 §3.5 里的那处局限保持可见，而不是日后以一份漏洞报告的形式被重新发现。
8. **零能力。** `allowedCapabilities: ["none"]` 产生一个沙箱，其中任何进程都没有任何可用能力，包括以 uid 0 运行的进程。`["none"]` 与任何能力名混用以 `400 INVALID_POLICY` 被拒。空列表 `[]` 解析为平台默认集合，**不是**空集。
9. **持久化。** `allowDaemonize: false` 时，`setsid` 与双重 `fork` 变孤儿被拒绝，且终止一个会话会终止其整个进程组。默认 `true` 时，两者都与今天一样可用。
10. **用名字，不用编号。** 使用数字型系统调用编号的策略被拒绝；指名了一个有多个编号变体的系统调用的策略，在每一个受支持架构上覆盖其全部变体。
11. **未知条目。** 未知系统调用名、未知能力名、以及不在被 pin 集合中的 `baselineExceptions` 条目，各自都以 `400 INVALID_POLICY` 并带 `field` 指针被拒绝。
12. **必需集合。** `syscall.mode: allowlist` 且 `allowedSyscalls: [read, write]`，在 `implicitEssentialSyscalls: true` 下能成功启动进程，且生效策略记录了所施加的必需集合版本。在 `implicitEssentialSyscalls: false` 与同一份清单下，进程创建以一条带审计事件的策略拒绝失败 —— 而不是以一次无从解释的崩溃失败。
13. **违规动作。** `onViolation: deny` 返回 `EPERM`（或相应的 OS 级失败）并让进程继续运行；`onViolation: kill` 终止它。该字段同样治理 §3 而不只是 §4：在 `noNewPrivileges: true` 配 `onViolation: kill` 下，执行一个 setuid 二进制会终止该进程，而不只是拒绝那次提权。`onViolation: kill` 之下的 `syscall.onViolation: deny` 会拒绝一次被过滤的系统调用，同时仍对提权尝试执行终止；而缺省的 `syscall.onViolation` 继承模块级取值。两种动作都产生携带 `effectivePolicyVersion` 与 `action`/`outcome` 的审计事件。
14. **`audit: none` 下违规仍被审计。** 在默认的 `audit: none` 下，一次被拒绝的 `init_module` 仍然产生一条携带 `shadow: false` 的违规事件；`audit: none` 压掉的只是普通活动的记录。一份策略**不得**能够配置出"拒绝不留任何痕迹"的沙箱。
15. **版本 pin。** 已 pin 到 `syscall/1` 的沙箱在平台默认值推进到 `syscall/2` 时不受影响；未 pin 的沙箱无论如何都在其生效策略与快照中记录解析出的版本。
16. **合并。** `allowedCapabilities` 与 `allowedSyscalls` 在各来源间取交集 —— 请求无法放宽其中任何一个，且任一来源给出 `["none"]` 时结果就是 `["none"]`。`noNewPrivileges: true`、`runAsNonRoot: true`、`allowDaemonize: false`、`onViolation: kill` 以及最严格的 `syscall.mode`，各自都从任一来源胜出。
17. **例外取交集。** 请求声明了但模板未声明的 `baselineExceptions` 条目不生效，且其不生效按 [overview.md](./overview.md) §5 被报告。
18. **授权。** 一份追加了某项具名能力的授权，在沙箱或任务不做任何动作的情况下到期，之后该能力再次不可用；针对 `["none"]` 的授权行为完全相同，并在到期时让沙箱回到零能力。试图授予 `mode: unrestricted`、`noNewPrivileges: false` 或 `runAsNonRoot: false` 的授权被拒绝；试图重开模板已关闭能力的授权以 `POLICY_GRANT_EXCEEDS_CEILING` 被拒绝。
19. **无旁路。** 从沙箱内部看，被拒绝的系统调用与普通权限失败无法区分；命中的规则只出现在审计流中。在 `onViolation: kill` 之下，被终止的进程什么也学不到，而留给兄弟进程的那点残余信号，是 [overview.md](./overview.md) §8.1.5 记录下的、被接受的取舍。
20. **影子评估。** 在 `tier: baseline` 配 `auditTier: restricted` 下，镜像以 root 运行的沙箱**被成功创建**，并产生一条指名 `runAsNonRoot` 的创建时影子发现；一次 `setsid` 调用成功，并产生一条指名 `allowDaemonize` 的影子发现。没有任何操作被拒绝、没有返回 `EPERM`，且沙箱内部无法区分这份带影子的配置与不带影子的配置。每条影子事件都携带 `shadow: true` 与解析出的 `auditTier`。等于或宽于 `tier` 的 `auditTier` 以 `400 INVALID_POLICY` 被拒。

## 10. 开放问题

1. **进程数与 fork 炸弹。** 进程数上限属于消耗量，按本提案划的缝它应归 `resource` —— 但它在进程创建时强制执行，和本文档里的一切一样。归哪个模块？
2. **restricted 分级的系统调用集合。** `tier: restricted` 目前展开为与 `tier: baseline` 相同的基线集合（[overview.md](./overview.md) §7.1）。`restricted` 是否应该引入第二个更大的带版本集合（追加 `mount`、`umount2`、`unshare`），而不是只收紧权限与持久化？
3. **画像生成。** §4.4.2 建议由观测画像生成 `allowlist` 策略。影子评估（§6.1）提供了答案的一半 —— 它观测一个更严的集合*本来会*拒绝什么 —— 但影子报告是一份发现清单，不是一份策略。平台是否应该补上这段距离、从一个观测窗口产出候选的 `allowedSyscalls`，还是"由影子发现指导的手写白名单"是唯一受支持的路径？
4. **能力默认集合。** §3.2.3 把"平台默认集合"留给了平台。该默认集合本身是否应成为一个带版本、已发布的集合，条件与系统调用基线相同，从而可 pin、可审计？这个问题随 §3.2.4 变得更尖锐了：既然 `["none"]` 已经精确指名了取值范围的一端，"平台默认成什么样"就成了本字段中唯一一个评审者看不见的取值。
5. **持久化路径集合。** §3.4 把自启型持久化推给了 `filesystem`。文件系统基线是否应新增一个带版本的持久化路径集合（`crontab`、systemd unit、shell profile），让 `allowDaemonize: false` 有一个已文档化的搭档，而不只是一条建议？
6. **热施加。** 更新后的进程策略能否施加到已在运行的进程，还是只对新进程生效？系统调用过滤器通常在进程创建时安装，并按设计不可逆，这暗示"仅新进程" —— 而按 [overview.md](./overview.md) §11.2，那将意味着本模块无法针对已在运行的进程接受授权。本规格**不得**在没有明确答案的情况下发布。
7. **非 root 与可写面。** `runAsNonRoot: true`（§3.5）改变了工作负载所创建的一切归属于哪个 uid，而它与 `filesystem.writableRoots` 的交互尚未规定：一个属主为 uid 0 的可写根对一个非 root 进程并不可写，因此这两个字段可以各自合法而合在一起不可用。平台是否应在创建时校验这一对、还是调整已声明可写根的属主、还是把它留给镜像？无论答案是哪个，"沙箱起来了却没有任何地方可写"是那个要避免的失败形态。

## 11. 非规范性说明

- 本文档的每一条要求都可以用按进程、非特权、按沙箱的机制表达（在进程创建时安装的 seccomp 式过滤器、内核的 no-new-privileges 标记、bounding 能力集、按会话的进程组跟踪）。与本提案其他部分一样，规格固定的是*属性*，机制选型留待开放。影子评估（§6.1）也不例外：常用的过滤机制都提供一个"记录并允许"的动作，而那正是那里的规则 1 所要求的。
- 每沙箱一个内核的模型，是系统调用策略负担得起的原因：过滤器的作用域是单一租户的内核，因此收窄它不会波及邻居（[overview.md](./overview.md) §12）。
- 参考过的类比对象：Kubernetes Pod Security Standards（`runAsNonRoot`、`allowPrivilegeEscalation`、`capabilities.drop`）与 `seccompProfile`、Docker 默认 seccomp 画像与 `--security-opt no-new-privileges`、systemd unit sandboxing 指令。
- **关于用 `["none"]` 而不是 `[]`：** Kubernetes 把同一个想法拼作 `capabilities.drop: ["ALL"]`，那在它那里可行，因为它有一个独立的 `add` 列表，也没有一个"平台默认"取值来抢位置。本字段只有一个列表，而 `[]` 已经被默认集合占用，所以保留词是唯一一种不会让省略与空列表表示不同含义的拼法。选 `none` 而不是 `all`，是因为本列表指名的是被**允许**的东西；`drop: ALL` 与 `allowed: none` 是从相反两端描述同一种姿态。
