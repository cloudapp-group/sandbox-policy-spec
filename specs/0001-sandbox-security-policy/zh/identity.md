# 规格：身份与秘密策略（Identity and Secrets Policy）

[提案 0001 — 沙箱安全策略](./overview.md) 的组成部分。本文档中的关键词 **必须（MUST）**、**不得（MUST NOT）**、**应该（SHOULD）**、**可以（MAY）** 依据 RFC 2119 解释。

---

## 1. 范围

本规格定义 `SandboxPolicy` 对象的身份（`identity`）子策略：**沙箱可以使用哪些凭据，以及它们以何种形式抵达沙箱**。它治理三件事：

- **工作负载身份** —— 对平台、以及对它所调用的服务而言，这个沙箱*是*什么。
- **秘密暴露** —— 一个凭据的值是否会进入沙箱，若进入，以何种形式。
- **凭据作用域与生命周期** —— 一个凭据对哪些目的地、方法与路径有效，有效多久，以及如何被吊销。

本模块之所以存在，是因为提案的其余部分明说了、且无法关闭的一处缺口。[filesystem.md](./filesystem.md) §2.3 的纵深防御矩阵承认路径规则保护不了「已在进程内存里、或经环境变量传入的秘密」—— 而环境变量与文件恰恰就是今天凭据所在的地方。一个跑着 Agent 生成代码、环境里带着 `AWS_SECRET_ACCESS_KEY` 的沙箱，其文件系统策略在拒绝 `~/.aws/credentials`，而同一个秘密就在一个 `os.environ` 之外。那条拒绝并没有错；它只是在回答一个攻击者并没有问的问题。

与其他模块的分工是固定的：

| 问题 | 模块 |
| --- | --- |
| 这条命令可以通过 API 被启动吗？ | `exec` |
| 这个运行中的进程可以以这个用户运行、可以提权、可以持久化、可以发起这个系统调用吗？ | `process` |
| 它可以读写这个路径吗？ | `filesystem` |
| 它可以访问这个目标吗？ | `network` |
| **它可以以这个身份认证吗，以及它读不读得到那个凭据？** | `identity`（本规格） |
| 它可以消耗这么多吗？ | `resource` |

注意与 `network` 之间的那条缝。`network` 决定一个数据包是否可以抵达 `api.example.com`；`identity` 决定沙箱是否持有一个用于它的凭据，以及那个凭据的字节对工作负载是否可见。两者都需要：能抵达一个服务却没有凭据毫无用处，持有一个用于不可达服务的凭据也毫无用处。两者互不蕴含。

不在范围内：平台对自己 API 调用方的认证，那是控制面的事，且受 [overview.md](./overview.md) §5.2 约束；秘密的*存储*，那是该部署所运行的任何 vault 的属性；以及事后检测凭据滥用，那是 [overview.md](./overview.md) §2.3.1。

## 2. 对象模型

```yaml
policy:
  identity:
    mode:             managed | unrestricted     # 默认：managed
    workloadIdentity:
      enabled:        bool                       # managed 之下默认：true
      audience:       [string]                   # enabled 时必填
      ttlSec:         int                        # 默认：900
    defaultExposure:  proxy | file | env | none  # 默认：proxy
    secrets:          [SecretBinding]
    onViolation:      deny | kill                # 默认：deny
    audit:            none | metadata            # 默认：none
```

### 2.1 `SecretBinding`

一条绑定指名一个凭据，并在同一处说明它是干什么用的、以及工作负载可以看到它的多少。

```yaml
- name:        string        # 必填，在其列表内唯一；用于错误与审计
  secretRef:   string        # 必填；由平台解析的不透明引用
  exposure:    proxy | file | env | none   # 默认：identity.defaultExposure
  destinations: [string]     # exposure: proxy 时必填 —— 用 network Peer 语法
  methods:     [string]      # 可选；HTTP 方法的子集
  pathPrefixes: [string]     # 可选；请求路径前缀
  ttlSec:      int           # 默认：900
  path:        string        # exposure: file 时必填 —— 沙箱内绝对路径
  envVar:      string        # exposure: env 时必填 —— 变量名
```

1. `secretRef` 对本规格是不透明的。它指名一个平台可以解析的凭据；平台如何存储它不在范围内（§1）。
2. `name` 在 `secrets` 内**必须**唯一。错误与审计事件以 `name` 标识一条绑定，绝不以 `secretRef` 标识 —— 使这两个面都不会携带一个暗示该秘密所在位置的值。
3. 一条绑定**不得**在被接受时携带其 `exposure` 并不使用的字段 —— `exposure: env` 之下的 `path`、`exposure: file` 之下的 `envVar`、`exposure: none` 之下的 `destinations`。接受它们会让作者以为某项约束正在生效，而该模式其实忽略它。以 `400 INVALID_POLICY` 拒绝并指名该字段与该模式。

## 3. 暴露模式

`exposure` 是本模块存在的那个字段。它回答一个问题：**沙箱内的代码读不读得到这个凭据的字节？**

| 模式 | 工作负载看到 | 凭据可用 |
| --- | --- | --- |
| `proxy` | 什么都看不到 | 可用，限于所声明的目的地与作用域（§4） |
| `file` | 那个值，位于 `path` | 可用，且工作负载能把它发到任何地方 |
| `env` | 那个值，位于 `envVar` | 可用，且工作负载能把它发到任何地方 |
| `none` | 什么都看不到 | 不可用 —— 该绑定已声明但未激活 |

1. 在 `proxy` 之下，凭据值**不得**出现在沙箱中的任何地方：不在它的文件系统里、不在它的环境里、不在它的进程参数里，也无法通过任何工作负载可触达的平台 API 取回。平台在沙箱之外的一个强制点上，把凭据附加到匹配的出站请求上。
2. 在 `file` 与 `env` 之下，那个值就在沙箱内部，而本模块的保证到此为止。一个工作负载读得到的凭据，就是一个工作负载能发到 `network` 所允许的任何地方、能打进 stdout、能写进一个日后被快照运出去的文件（[overview.md](./overview.md) §8.3.2）的凭据。这两种模式之所以存在，是因为真实的工作负载使用那些会去读 `~/.aws/credentials` 或 `AWS_ACCESS_KEY_ID` 的 SDK，而一份只提供 `proxy` 的规格会被绕开而不是被采纳。它们不等价于 `proxy`，而 §6 让平台把这一点说出来。
3. `none` 的存在，是为了让一条绑定可以在被打开之前先被声明、被评审、被纳入版本控制，也为了让吊销一条绑定成为一次单字段修改 —— 那让声明保持可见，而不是删掉它曾存在过的证据。
4. **暴露在合并时只能收窄**（§10）：排序是 `none` > `proxy` > `file` > `env`。一个选了 `proxy` 的低优先级来源，**不得**被更高优先级的来源放宽为 `file` 或 `env`。

### 3.1 `proxy` 对部署提出的要求，直说

`proxy` 是本模块推荐的模式，也是有真实前置条件的那个模式。它需要出站路径上的一个强制点，能够终结连接、把请求与绑定的作用域相匹配、并附加凭据。那与 `network.rules` 做 L7 求值所需的、以及 `resource` 计量 LLM Token 所需的（[resource.md](./resource.md) §14）是同一个组件 —— 一套机制，三个模块。

一个没有这类组件的部署**必须**把 `exposure: proxy` 声明为 `unsupported`（[overview.md](./overview.md) §8.2），而不是回落到 `file`。把那个隐藏凭据的模式静默降级成一个把凭据交出去的模式，正是 §8.2.1 规则 4 所禁止的那种失败：一个写了 `proxy` 却得到 `env` 的作者，其策略的核心承诺被无声地反转了。

## 4. 目的地绑定与作用域

一个 `proxy` 之下的凭据只在绑定所说的地方可用。没有这一条，`proxy` 只是把秘密换了个位置 —— 工作负载读不到它，却仍然能把它花到任何地方。

1. `destinations` 在 `exposure: proxy` 之下**必填**且**必须**非空。它使用 [network.md](./network.md) §2.3 的 `Peer` 语法：地址、CIDR、DNS 名称与前导 `*.` 通配。`proxy` 之下为空或缺省的 `destinations` **必须**以 `400 INVALID_POLICY` 拒绝；一个可被附加到任意目的地的凭据，是一个套着作用域字段名的无作用域凭据。
2. 平台**必须**仅把凭据附加到那些目的地匹配、方法在 `methods`（若已设）之内、且请求路径以 `pathPrefixes`（若已设）之一开头的请求上。一个不匹配的请求**必须**在**不带**凭据的情况下被转发，而不是被拒绝 —— 工作负载有权发起未认证请求，而拒绝它们会让本模块变成第二份网络策略。
3. 目的地匹配**必须**在**解析后的连接目标**上进行，而不是在一个由工作负载控制的请求头上进行。一个连到别的地址、却带着指名某个被允许目的地的 `Host` 头的连接，**不得**得到该凭据。这与 [exec.md](./exec.md) §3.2 对可执行文件解析所提的是同一条要求，理由也相同。
4. `destinations` 不放宽 `network`。一个在此被许可、却被 `network` 拒绝的目的地仍然不可达；两个模块取交集。反过来也成立、且值得写明：`network.internal.mode: allow` 使云元数据端点可达，而从它取得的凭据是本模块从未签发、也无法吊销的（[network.md](./network.md) §2.2.3）。因此一份把该设置与一个 `proxy` 绑定配对的策略携带 `metadata_endpoint_reachable` 警告，因为 §3.1 的保证只对本模块所控制的凭据成立。一条其目的地在生效网络策略之下全部不可达的绑定，**必须**作为 `policyWarnings` 条目 `{field: "policy.identity.secrets", name, reason: "destinations_unreachable"}` 上报 —— 一个以为某个凭据正在被使用、而其实没有任何东西能抵达其目的地的作者，应该在创建时就知道这件事。
5. 当一个凭据是短期的、且由平台签发时（§5），该被签发凭据自身的 audience **必须**在签发系统支持的范围内被约束到该绑定的目的地上。在令牌上强制的作用域强于在代理上强制的作用域，因为它在代理出错时依然成立。

## 5. 工作负载身份与生命周期

1. 当 `workloadIdentity.enabled` 为 true 时，平台**必须**能够把该沙箱作为一个独立、可验证的身份呈现给外部服务，且该身份**必须**被限定到 `audience`。一个没有 audience 的身份，是一个多了几个步骤的 bearer token。
2. `enabled` 为 true 时 `audience` **必填**。以 `400 INVALID_POLICY` 拒绝一个空 audience 是刻意的：缺失 audience 的失败模式，是一个凭据被某个没人打算授权的服务接受。
3. 该身份**必须**绑定到沙箱实例，而不是绑定到模板、策略档或调用方。同一个模板出来的两个沙箱是两个身份，使吊销其中之一不会吊销另一个，也使审计轨迹能把一个请求归因到某个沙箱。
4. `ttlSec` 约束平台所签发或附加的任何凭据的生命周期，默认 900 秒。部署配置的最大值按与授权 TTL 上限相同的条件适用（[overview.md](./overview.md) §5.1.2），超过它的取值**必须**被拒绝。
5. **续期不得需要工作负载的配合。** 平台在沙箱有权持有该凭据期间按自己的节奏续期。一个由沙箱自己刷新凭据的设计，等于给了沙箱一个长期的刷新能力，而那正是 `ttlSec` 本要消除的东西。
6. **吊销必须在沙箱的生命周期内生效，而不是在下次重启时。** 移除一条绑定、或经控制面吊销，**必须**让该凭据不再被附加到后续请求上，并**必须**在签发系统允许的范围内使已在沙箱内的值失效。在签发系统不允许的地方，生效策略**必须**上报那处残余暴露，而不是声称一次它无法交付的吊销。
7. 在 `exposure: file` 或 `env` 之下，规则 5 与 6 **按构造只是尽力而为**，而平台**必须**把这一点说出来：一个已被读入工作负载内存的值无法被召回。这是那两种模式的具体代价，而它属于能力报告（§6），不属于一条脚注。

## 6. 字段规格

| 字段 | 类型 | 约束 | 默认值 | 语义 |
| --- | --- | --- | --- | --- |
| `mode` | `enum?` | `managed` \| `unrestricted` | `managed` | `managed` 施加本模块。`unrestricted` 完全停用它，且**必须**显式书写（原则 3）。 |
| `workloadIdentity.enabled` | `bool?` | — | `managed` 之下为 `true` | §5.1。 |
| `workloadIdentity.audience` | `[string]?` | `enabled` 为 true 时**必须**非空。 | `[]` | §5.2。 |
| `workloadIdentity.ttlSec` | `int?` | > 0，≤ 部署最大值。 | `900` | §5.4。 |
| `defaultExposure` | `enum?` | `proxy` \| `file` \| `env` \| `none` | `proxy` | 省略了 `exposure` 的绑定所用的默认值。 |
| `secrets` | `[SecretBinding]?` | 按 §2.1。`name` 唯一。 | `[]` | 已声明的各凭据。 |
| `onViolation` | `enum?` | `deny` \| `kill` | `deny` | §7。 |
| `audit` | `enum?` | `none` \| `metadata` | `none` | **普通**凭据使用的审计级别（§9）。它不压制违规事件（[overview.md](./overview.md) §8.1.4）。 |

在 `mode: managed` 配 `defaultExposure: proxy` 之下，一个没有任何 `secrets` 条目的沙箱完全不持有任何凭据。那正是 `restricted` 分级预期的姿态（[overview.md](./overview.md) §7）：在某条绑定说了别的之前，一个沙箱不以任何身份认证、也不携带任何东西。

### 6.1 分级默认值

采用哪一套默认值由 `policy.tier` 选择（[overview.md](./overview.md) §7.1）：

| 字段 | `compatibility` | `baseline` | `restricted` |
| --- | --- | --- | --- |
| `mode` | `unrestricted` | `managed` | `managed` |
| `defaultExposure` | — | `file` | `proxy` |
| `workloadIdentity.enabled` | `false` | `true` | `true` |
| `audit` | `none` | `none` | `metadata` |

`compatibility` 解析为 `unrestricted`，是因为今天的调用方在完全没有策略对象的情况下，以环境变量与文件传递凭据；对它们施加本模块会一次性弄坏其中每一个（[overview.md](./overview.md) §9）。这是本提案中第三处、也是最后一处刻意让某个分级成为空操作的地方，而与另外两处不同，它在 `baseline` 上并不是空操作。

`baseline` 设 `defaultExposure: file` 而不是 `proxy`，理由值得写出来：`proxy` 需要一个出站强制点（§3.1），而不是每个部署都有；一个解析到某个 `unsupported` 字段的分级，会让 `tier: baseline` 在那些部署上于 `enforcement: strict` 之下直接失败。`file` 至少让暴露成为显式且可审计的。`restricted` 选择 `proxy`，而一个无法强制它的部署会在创建时发现 —— 那正是对的时刻。

### 6.2 影子评估支持

依 [overview.md](./overview.md) §7.2.5，本模块在 `auditTier` 之下对 `mode`、`defaultExposure` 与每条绑定的 `exposure` 支持影子评估。一个影子分级本来会隐藏的凭据，在被强制执行的分级之下仍然被暴露，而一条 `shadow: true` 事件指名该绑定以及那个更严分级本来会要求的暴露模式。

这条发现可直接据以行动、也值得投入：`auditTier: restricted` 之下的一份影子报告，就是一份需要迁到 `proxy` 的绑定清单 —— 而那就是采纳本模块的迁移计划。影子评估无法告诉运维的是，某个工作负载的 SDK *能不能*透过代理工作 —— 那是工作负载的属性、不是策略的属性，而再多的观察也揭示不了它。

影子评估**不得**自己暴露一个凭据。对一条当前处于 `env` 模式的绑定求值「`proxy` 本来会怎样」，意思是上报那处差异，而不是为了测试它去多签发一个凭据。

## 7. 违规动作

依 [overview.md](./overview.md) §8.1，`onViolation` 决定当本模块拒绝某件事时会发生什么：

| 动作 | 结果 |
| --- | --- |
| `deny`（默认） | 请求在不带凭据的情况下被转发（§4.2），或该操作以本模块的错误失败（§8）。进程继续运行。 |
| `kill` | 那个违规**进程**被终止。 |

1. 没有 `warn`，理由见 [overview.md](./overview.md) §8.1.2。一个检测到「试图读取一个 `proxy` 模式凭据」之后又放行它的动作毫无意义，因为放行它*就是*那次暴露。
2. `kill` 特别适合一种情形：工作负载试图读取一个 `proxy` 模式本应隐藏的凭据。在 `proxy` 之下，工作负载没有任何正当理由去看，所以这次尝试本身就是信号 —— 与 [filesystem.md](./filesystem.md) §4.5.1 对凭据路径所用的是同一个推理。
3. 两种动作都会产生违规事件，且在任何审计级别下都产生（§9）。

## 8. 错误

| 错误码 | HTTP | 载荷 | 何时 |
| --- | --- | --- | --- |
| `INVALID_POLICY` | 400 | `{field, reason}` | `enabled: true` 下 `audience` 为空；`proxy` 下 `destinations` 为空；该模式不使用的字段（§2.1.3）；`ttlSec` 超过部署最大值。 |
| `POLICY_IDENTITY_SECRET_UNRESOLVABLE` | 400 | `{name}` | `secretRef` 指名了一个平台无法解析、或该主体无权使用的凭据（[overview.md](./overview.md) §5.2）。绝不回显 `secretRef`。 |
| `POLICY_IDENTITY_EXPOSURE_DENIED` | OS 级失败或 `403`；审计事件 | `{name, exposure, action}` | 工作负载试图读取一个其暴露模式将其隐藏的凭据（§3.1）。 |
| `POLICY_IDENTITY_DESTINATION_DENIED` | 仅审计事件 | `{name, destination}` | 因目的地不匹配而未附加凭据（§4.2）。该请求本身照常进行，因此这不是一个返回给调用方的错误。 |
| `POLICY_UNSUPPORTED` | 400 | `{field, state, capabilityVersion}` | 在 `enforcement: strict` 之下，策略使用了本部署声明为 `unsupported` 的暴露模式 —— 最常见的是 `proxy`（§3.1）。 |
| `POLICY_GRANT_INVALID` | 400 | `{field, reason}` | 授权指向一个不可授权字段（§10.1）。 |

本模块中任何错误载荷、警告或审计事件都**绝不得**包含一个凭据值、一个 `secretRef`，或两者的任何子串。绑定以 `name` 标识。把这一点作为要求写出来而不是假定它成立，是因为错误载荷是任何系统中被复制最多的文本，而一条没有被写下来的脱敏规则，就是一条没有被实现的脱敏规则。

## 9. 可观测性

1. 每一次违规都**必须**作为违规事件输出 `{sandboxID, name, event, exposure, outcome: denied|killed, effectivePolicyVersion, shadow: false}`，且在**任何**审计级别下都输出，包括 `audit: none`（[overview.md](./overview.md) §8.1.4）。
2. `audit: metadata` 增加的是对**普通**凭据使用的记录：哪条绑定在何时被附加到了哪个目的地、以哪个身份。不包括凭据本身。
3. 平台所签发或附加的每一个凭据都**必须**可归因到一个沙箱、一个绑定 `name` 与一个 `effectivePolicyVersion`。「14:03 时是哪个沙箱用了这个凭据？」**必须**能从审计流回答，因为那是一次事故的第一个问题。
4. 一条解析为 `exposure: file` 或 `env` 的绑定**必须**在沙箱创建时产生一条记录该残余暴露的审计事件（§5.7）。把一个可读的凭据交给部分可信的代码是一个事件，不是一个沉默的字段 —— 与 [filesystem.md](./filesystem.md) §9.4 给 `baselineExceptions` 的处理相同。

## 10. 合并语义

在 [overview.md](./overview.md) §5 的共享规则之上：

| 字段 | 合并细化 |
| --- | --- |
| `mode` | 最严格者胜出：任一来源为 `managed`，结果即为 `managed`。 |
| `defaultExposure` | 最严格者胜出：`none` > `proxy` > `file` > `env`（§3.4）。 |
| `secrets` | 按 `name` 追加并去重。来自更高优先级来源的同名绑定**不得**放宽低优先级那条：`exposure` 取最严格值、`destinations` 取**交集**、`ttlSec` 取最小值。 |
| `workloadIdentity.enabled` | `true` 胜出 —— 拥有一个受限身份，比完全没有身份是更窄的姿态，因为实践中后者的替代物是一个共享静态凭据。 |
| `workloadIdentity.audience` | 各来源取**交集**。请求不能扩大模板所设的 audience。 |
| `workloadIdentity.ttlSec` | 最小值胜出。 |
| `onViolation` | `kill` 胜出（[overview.md](./overview.md) §8.1.7）。 |
| `audit` | 更详细者胜出（`metadata` > `none`）。 |

`destinations` 取交集这一条值得一个注解，因为它是本模块合并中唯一可能产出令人意外结果的地方：一条限定到 `*.example.com` 的模板绑定，与一条同名、限定到 `api.other.com` 的请求绑定，交集为**空**，于是该绑定不附加到任何目的地。那是正确的只能收窄结果，而它**必须**作为 `destinations_unreachable` 警告（§4.4）上报，而不是留给工作负载以一次认证失败的形式去发现。

### 10.1 可授权字段

依 [overview.md](./overview.md) §5.1.8，针对本模块的限时授权可以打开：

| 可授权 | 不可授权 |
| --- | --- |
| `secrets` —— 一条具名绑定，限定窗口内 | `mode: unrestricted` |
| `destinations` —— 向一条既有绑定具名追加 | `exposure` —— 任何方向的放松 |
| `workloadIdentity.audience` —— 具名追加 | `workloadIdentity.ttlSec` —— 不得抬高 |

`exposure` 不可授权，而这是本表中最重要的一处排除。把一条绑定临时从 `proxy` 移到 `env`，会把凭据写进沙箱，而工作负载可能在第一秒就读到它、并永久留存。授权会到期；那次暴露不会。一份效果比自己的 TTL 更长命的授权就不是限时的，而限时是 §5.1 的全部前提 —— 与 `process.runAsNonRoot: false` 不可授权（[process.md](./process.md) §8）是同一个理由。

`ttlSec` 不可授权则出于相邻的理由：一个被抬高到超出授权自身 TTL 的凭据生命周期，会活得比抬高它的那份授权更久。

授权一条**新绑定**是允许的，而且这正是「这个任务需要多调一个 API」的预期形态：那条绑定带着 `exposure: proxy`、一个受限目的地、以及它自己的到期时间而来，事后消失。它与其他一切一样受上限约束 —— 授权**不得**重新打开一条模板或策略档已关闭的绑定。

## 11. 验收标准

1. **proxy 模式隐藏那个值。** 在 `exposure: proxy` 之下，凭据不出现在沙箱的文件系统、环境、进程参数与任何工作负载可触达的 API 中，而一个发往已声明目的地的请求抵达该目的地时是已认证的。
2. **目的地限定。** 一条限定到 `api.example.com` 的 `proxy` 绑定会附加到发往该主机的请求上，而对发往任何其他主机的请求**被扣下**。被扣下的那个请求以未认证形式转发、而不是被拒绝，并且只向审计流产生 `POLICY_IDENTITY_DESTINATION_DENIED`。
3. **伪造请求头不会导致附加。** 一个连到 `destinations` 之外地址、却带着指名某个被允许目的地的 `Host` 头的连接，不会得到该凭据（§4.3）。
4. **方法与路径限定。** 在 `methods: [GET]` 与 `pathPrefixes: [/v1/read]` 之下，一个发往该前缀的 `POST` 与一个发往其他前缀的 `GET`，两者都在不带凭据的情况下进行。
5. **不可达目的地会告警。** 一条其目的地全部被生效网络策略拒绝的绑定被接受，而创建响应携带指名该绑定的 `destinations_unreachable`。
6. **audience 是强制的。** `workloadIdentity.enabled: true` 配空 `audience` 以 `400 INVALID_POLICY` 被拒。
7. **身份按实例。** 同一模板出来的两个沙箱呈现不同的身份，而吊销其中之一不影响另一个继续工作。
8. **续期无需配合。** 一个在超过 `ttlSec` 的时间跨度内持续发起已认证请求的沙箱，在自己不执行任何刷新的情况下持续成功（§5.5）。
9. **吊销是实时的。** 移除一条绑定会让后续请求不再被认证，且无需重启沙箱（§5.6）。
10. **残余暴露是诚实的。** 在 `exposure: env` 之下，吊销不会撤回工作负载已读到的值，生效策略上报那处残余暴露，且创建时已产生 §9.4 的事件。
11. **载荷不泄露。** 本模块产出的任何错误、警告或审计事件都不包含凭据值或 `secretRef`，包括在「秘密无法解析」与「暴露被拒」这两种情形下（§8）。
12. **合并只能收窄。** 一条 `exposure: proxy` 的模板绑定，不能被一条同名请求绑定改成 `env`；`destinations` 取交集；`ttlSec` 取最小值；`audience` 取交集。任何试图放宽其中之一的请求按 [overview.md](./overview.md) §5 处理 —— 被拒绝或被上报，绝不静默生效。
13. **授权。** 一份追加了 `proxy` 绑定的授权在沙箱不做任何动作的情况下到期，之后请求不再被认证。试图改变 `exposure`、抬高 `ttlSec` 或设 `mode: unrestricted` 的授权被拒绝。
14. **不支持的 proxy 以 fail-closed 处理。** 在一个把 `exposure: proxy` 声明为 `unsupported` 的部署上，请求它的策略在 `enforcement: strict` 之下以 `400 POLICY_UNSUPPORTED` 被拒，而在 `bestEffort` 之下被接受、该绑定被上报为失效 —— 两种情况下它都不会被静默降级为 `file` 或 `env`。
15. **分级默认值。** `tier: restricted` 且不带任何身份字段，解析为 `mode: managed`、`defaultExposure: proxy`、`workloadIdentity.enabled: true`，且没有任何秘密 —— 一个不以任何身份认证、也不携带任何东西的沙箱。`tier: compatibility` 解析为 `mode: unrestricted`，且不改变今天行为的任何部分。
16. **影子评估。** 在 `tier: baseline` 配 `auditTier: restricted` 下，一条处于 `file` 模式的绑定继续工作，并产生一条指名该绑定与 `proxy` 的 `shadow: true` 发现。不为该影子评估签发任何凭据，且沙箱内部可观察到的一切没有差别。
17. **生命周期。** 一个从快照恢复的沙箱不继承秘密绑定（[overview.md](./overview.md) §8.3）；已认证请求会失败，直到那些绑定被重新建立。

## 12. 开放问题

1. **凭据类型的分类。** 本规格把每个凭据都当作一个被附加到出站请求上的不透明值。真实的凭据各不相同：bearer token 被附加到一个请求头上，AWS 签名是在请求之上计算出来的，客户端证书用在握手中，而数据库口令走的是一个本模块无法解析的协议。`SecretBinding` 是否需要一个带按类型附加语义的 `type`，还是说 `proxy` 模式诚实地只限于 HTTP 形状的凭据 —— 若是后者，那条限制**必须**写进 §3 而不是暗示出来？
2. **非 HTTP 目的地。** §4 是以目的地、方法与请求路径来写的，而那预设了 HTTP。一个用于 Postgres 连接的 `proxy` 模式凭据没有方法也没有路径，而代理将不得不去说那个线协议。`proxy` 在 v1 是否限定于 HTTP/HTTPS，而非 HTTP 凭据必然是 `file` 或 `env`？
3. **谁可以引用一个 `secretRef`。** [overview.md](./overview.md) §5.2 说了调用方不能超出其被委派的权限，但本模块没有说引用一个秘密是否需要一个区别于「创建沙箱」的独立权限。它应该需要：否则任何可以创建沙箱的调用方，都可以绑定平台能解析的任何秘密。这个问题阻塞本模块。
4. **`exposure: file` 之下与 `filesystem` 的交互。** 一个被写到 `path` 的凭据受 `filesystem` 规则约束，而一条覆盖该路径的 `denyPaths` 条目会让该凭据不可读 —— 一份内部自相矛盾、但各自合法的策略。平台是否应在创建时拒绝这一对，还是所产生的失败已经足够可读？
5. **按请求的审批。** `resource` 有一套用于超预算的 hold-and-approve 流程（[resource.md](./resource.md) §7）。一次异常作用域的凭据使用 —— 一个首次出现的目的地、一个异常的时段 —— 是否应能触发同一道人工闸门，还是那属于检测（[overview.md](./overview.md) §2.3.1）而不属于策略？
6. **出站代理的可信度。** `proxy` 模式把凭据移进出站路径，而那让该组件成为一个持有每个沙箱凭据的高价值目标。本规格要求那个强制点存在，却对它自身的隔离、密钥处理与爆炸半径只字未提。那大概可以算不在范围内，但一个读了本模块、然后建起一个持有每个租户秘密的单一代理的部署，确实是照着它的字面做的。

## 13. 非规范性说明

- **基质映射**（[overview.md](./overview.md) §12.2）。本模块中位于沙箱之外的那些部分 —— 身份签发、凭据附加、目的地匹配 —— 是控制面与出站路径的事，因此与基质无关：同一个代理对一个 MicroVM 与一个容器同样有效。而位于沙箱之内的那些部分 —— 写一个文件、设一个环境变量 —— 在两边同样可用。本模块没有 VM/容器的分岔，这在本提案中不寻常，而它源自本模块的强制点在沙箱之外、而不在内核里。
- 本模块*确实*依赖的东西，是一个出站强制点的存在，而那与 `network` 七层规则、`resource.limits.tokens`、`resource.rate.network` 所依赖的是同一个。一个四者都没有的部署有一个自洽但更弱的姿态；一个为其中之一有、而为其余没有的部署，大概是配置错了而不是刻意受限。
- **关于偏好 `proxy` 但不强制它。** 本模块的一个早期草案把 `proxy` 作为唯一模式。它因 §3.2 给出的理由被否决：SDK 生态从文件与环境变量读取凭据，而一门无法表达部署实际所做之事的策略语言会被绕开而不是被采纳。折中之处在于 `file` 与 `env` 仍然可用、仍然在创建时被审计，并且被如实描述为它们本来的样子 —— §5.7 与 §9.4 中关于残余暴露的措辞是刻意直白的。
- 参考过的类比对象：Cloudflare 把 Worker 置于沙箱之外、并从那里注入凭据的模型；E2B 的 audience 绑定工作负载身份；Daytona 的代理侧秘密占位符；OpenSandbox 带修订检查更新的 credential vault。这四者各自独立地收敛到「把秘密留在外面、在出去的路上附加它」，而那是 `proxy` 应当作为默认值而不是一个选项的最强论据。
