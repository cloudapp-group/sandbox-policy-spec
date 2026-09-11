# 规范：网络策略

[Proposal 0001 — Sandbox Security Policy](./overview.md) 的一部分。关键词 **MUST**、**MUST NOT**、**SHOULD**、**MAY** 按 RFC 2119 解释。

---

## 1. 范围

本规范定义 `SandboxPolicy` 对象的网络子策略。它由三部分组成，而它们是平级的：

- **出站（egress）** —— 沙箱可以访问什么。
- **入站（ingress）** —— 什么可以访问沙箱。
- **内网可达性（internal reachability）** —— 沙箱是否可以访问它所处的私有网络（§2.2）。

出站与入站用**同一种规则形状**表达（§2.1），每条规则携带一个显式的**优先级**，且每条规则在**四层或七层**二选一地陈述它的匹配。四层形式沿用云安全组模型（方向、协议、端口范围、授权对象、优先级、动作）。七层形式的目标沿用 URL 模型（scheme、host、port、path），其匹配器沿用 Gateway API `HTTPRoute` 模型（`path`、`headers`、`queryParams`，外加 `cookies`）。

求值是**有状态的**：规则描述的是连接，一个已被放行连接的回程方向无需自己的规则（§4.7）。这与云安全组提供的契约相同，也正是它把一份可评审的规则集与一份塞满了针对临时端口段的反向条目的规则集区分开来。

本模块的早期版本是不对称的 —— 出站有 `allowOut`、`denyOut`、`portRules` 与七层 `rules`，而入站只有一个布尔和一个 host 改写字符串。那份不对称曾被记为本模块最大的开放问题，现在已经关闭。旧字段仍永久受支持，并被归一化进下面的结构（§8）。

> **未解决的依赖 —— 发布阻断项。** 规定既有 DNS 学习行为与当前入站令牌语义的那些文档（[Egress Network Policy](../../../guide/network-policy.md)、[Security Proxy](../../../guide/security-proxy.md)、[Restrict Public Access](../../../guide/restrict-public-access.md)）**不属于本仓库**，上面的路径解析到仓库之外。因此只拿到本仓库的读者无法实现域名学习或入站令牌校验：本文档点了它们的名，却没有定义它们，这与「以引用方式纳入」不是一回事。解决办法 —— 一个仓库内的带版本捆绑包，或以版本与 SHA-256 记录的不可变 URL，无论哪种都进入合规性套件 —— 记为 [overview.md](./overview.md) §11.15。

## 2. 对象模型

```yaml
policy:
  network:
    internal:
      mode:          deny | allow | identity   # 默认：deny —— 见 §2.2
      allowedPeers:  [PeerRef]                 # 仅 identity 模式
    egress:
      defaultAction: allow | deny              # 由分级选择；见 §6
      rules:         [NetworkRule]
    ingress:
      defaultAction: allow | deny              # 由分级选择；见 §6
      rules:         [NetworkRule]
    onViolation:     deny | kill               # 默认：deny —— 见 §4.8
    audit:           none | metadata           # 默认：none
```

`egress` 与 `ingress` 是同一种形状，因为它们在两个方向上回答同一个问题。两者谁都不是对方的从属，而向其一新增的字段**必须**同时向另一个新增，或在本文档中说明其缺席的理由。

### 2.1 `NetworkRule`

```yaml
- name:     string          # 必填，列表内唯一
  priority: int             # 必填，1–65535；数值越小越先求值
  action:   allow | deny
  l4:                       # 与 l7 互斥
    protocol: tcp | udp | icmp | all      # 默认：all
    ports:    [string]                    # "443" 或 "8000-8100"；默认：全部端口
    peer:     Peer                        # 必填 —— 见 §2.3
  l7:                       # 与 l4 互斥
    scheme:      http | https             # 必填
    hosts:       [string]                 # 必填；DNS 名、前导 "*." 通配
    port:        int                      # 默认：http 为 80，https 为 443
    method:      string                   # GET | POST | ... ；默认：任意
    path:        HTTPMatch                # 可选
    headers:     [NamedHTTPMatch]         # 可选
    queryParams: [NamedHTTPMatch]         # 可选
    cookies:     [NamedHTTPMatch]         # 可选
```

1. `name` **必须**在其所在列表内唯一。错误与审计事件用 `{direction, name}` 标识一条规则。
2. **`l4` 与 `l7` 互斥。** 一条同时携带两者的规则**必须**以 `400 INVALID_POLICY` 拒绝。一条两者都不带的规则同样**必须**被拒绝：一条匹配一切的规则就是 `defaultAction`，把它写成规则只会把它藏起来。
3. **一条 `l7` 规则隐含地放行它所需要的连接。** 匹配 `path` 或某个 header 需要一个已建立、已终结的连接，所以一条 `l7` allow 规则放行到其 `hosts` 的、在其 `port` 上的连接建立，随后只放行匹配其匹配器的那些请求。没有这一条，一条 `l7` 规则描述的就是一个永远无法抵达的请求。
4. 到某条 `l7` 规则的 `hosts:port` 但**不**匹配其匹配器的请求，落到其余规则、再落到 `defaultAction`；它们不会因这次擦肩而过被隐式拒绝。一条规则陈述的是它放行什么，而不是它因遗漏而禁止什么。
5. `icmp` **不得**与 `ports` 组合；这样的规则以 `400 INVALID_POLICY` 拒绝。
6. 端口是 `1`–`65535` 内的单值或闭区间。畸形条目与反向区间**必须**以 `400 INVALID_POLICY` 拒绝。

### 2.2 `internal` —— 私有网络的可达性

沙箱所处的私有网段是地址空间里唯一一处「全部拒绝」与「全部允许」对不同部署都是合法默认、而真正有意思的答案两者皆非的地方。`internal` 陈述三者中哪一个适用：

| `mode` | 含义 |
| --- | --- |
| `deny`（默认） | 到 §4.2 私有网段的流量在任一方向上都不通。这是今天的行为。 |
| `allow` | 私有网段可达，受 §4.1 的普通规则约束。 |
| `identity` | 仅对 `allowedPeers` 中所列的对象可达，由平台从沙箱身份而非从地址解析。 |

1. `internal` 管辖 **`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 与 `169.254.0.0/16`**（§4.2）。它在每条规则之前求值，所以在 `deny` 下，没有任何优先级或来源的 `allow` 规则能触及那些网段。
2. `identity` 模式是不写 CIDR 就表达「这些沙箱可以互相通信」的方式。`allowedPeers` 条目由平台解析；调用方**不得**指名一个它无权访问的对象（[overview.md](./overview.md) §5.2）。
3. **`mode: allow` 包含云元数据端点，其代价在此写明而不留给人去发现。** `169.254.169.254` 及其等价端点提供实例凭据。一个能访问它们的沙箱可以直接取得实例角色的凭据，这会完全绕过 [identity.md](./identity.md) —— `exposure: proxy` 把一个密钥挡在沙箱之外，而这个设置递上了另一个。因此：
   - 一份既有 `internal.mode: allow` **又**有任何 `identity.secrets` 绑定解析为 `exposure: proxy` 的策略，**必须**产生一条 `policyWarnings` 条目 `{field: "policy.network.internal.mode", reason: "metadata_endpoint_reachable"}`。两者还不至于矛盾到要拒绝，但一个部署**不得**在无人告知的情况下配出这一对。
   - 当需求是沙箱间通信时，部署**应该**优先用带显式对象的 `identity` 模式而非 `allow`，因为那个需求从不需要元数据端点。
4. `127.0.0.0/8` **不在本模块范围内**。沙箱内的 loopback 是该沙箱自己进程之间的通信，在容器基质上则是一个 Pod 各容器之间的通信 —— 那在沙箱单位**内部**（[overview.md](./overview.md) §12.1），不跨越它。一份声称管辖它的网络策略，描述的是那里并不存在的边界。
5. 合并取最严模式：`deny` > `identity` > `allow`。`allowedPeers` 跨来源取交集。

### 2.3 `Peer` —— 一条四层规则的授权对象

```yaml
peer:
  cidrs:        [string]      # IPv4 地址或 CIDR
  domains:      [string]      # DNS 名或前导 "*." 通配 —— 仅出站
  sandboxGroup: string        # 平台解析的沙箱身份
```

1. 三者中**必须**至少有一个存在。空的 `peer` 以 `400 INVALID_POLICY` 拒绝。
2. `domains` 仅在**出站**有意义。入站规则上的域名**必须**以 `400 INVALID_POLICY` 拒绝：一个入站连接的来源是地址，把它与名字匹配需要一次由发送方控制的反向查询。
3. 域名条目通过 DNS 学习实现（§4.3），而这是本模块在不同部署之间最大的能力差异（§11）。
4. `sandboxGroup` 需要 `internal.mode: identity` 才有任何效果；在 `deny` 下指名一个**必须**产生一条 `policyWarnings` 条目 `{reason: "peer_unreachable_under_internal_deny"}`，而不是静默的空操作。
5. 这是其他模块提到网络目标时所指的那套语法 —— [identity.md](./identity.md) §4.1 就是其中之一。

### 2.4 `HTTPMatch` 与 `NamedHTTPMatch`

匹配器形状沿用 Gateway API `HTTPRoute`，使一位懂其中一个的运维也懂另一个：

```yaml
HTTPMatch:                    # 用于 path
  type:  Exact | PathPrefix | RegularExpression    # 默认：PathPrefix
  value: string

NamedHTTPMatch:               # 用于 headers、queryParams、cookies
  type:  Exact | RegularExpression                 # 默认：Exact
  name:  string
  value: string
```

1. Header 名不区分大小写；header 值、查询参数名与值、cookie 名与值区分大小写。
2. 一个列表里的多个条目按 **AND** 组合。一条列了两个 header 的规则匹配一个同时携带两者的请求。
3. `cookies` 是 `Cookie` header 上的便捷形式，本文档明说这一点而不暗示它是一个独立维度：一个 `cookies` 条目在从该 header 解析出的具名 cookie 匹配时匹配。`HTTPRoute` 没有 cookie 匹配器；这是新增，不是借用。
4. `RegularExpression` 支持对实现而言是**可选**的。不实现它的部署**必须**把它声明为 `unsupported`（[overview.md](./overview.md) §8.2），而不是静默地把一个模式当作字面量处理 —— 那会把一条窄规则变成匹配不到任何东西的规则，或把一个 deny 变成一个洞。
5. 类型为 `PathPrefix` 的 `path` 按整个路径段匹配，而非按字符串前缀：`/v1` 匹配 `/v1` 与 `/v1/x`，不匹配 `/v11`。

## 3. 字段规格

| 字段 | 类型 | 约束 | 默认 | 语义 |
| --- | --- | --- | --- | --- |
| `internal.mode` | `enum?` | `deny` \| `allow` \| `identity` | `deny` | §2.2。 |
| `internal.allowedPeers` | `[PeerRef]?` | 仅在 `identity` 下有意义。 | `[]` | §2.2.2。 |
| `egress.defaultAction` | `enum?` | `allow` \| `deny` | 由分级选择（§6） | 无规则匹配的连接的裁决。 |
| `egress.rules` | `[NetworkRule]?` | 按 §2.1。`name` 唯一；合并后 `priority` 在方向内唯一（§5）。 | `[]` | 出站规则。 |
| `ingress.defaultAction` | `enum?` | `allow` \| `deny` | 由分级选择（§6） | 无规则匹配的入站连接的裁决。 |
| `ingress.rules` | `[NetworkRule]?` | 按 §2.1；`peer.domains` **不得**使用（§2.3.2）。 | `[]` | 入站规则。 |
| `onViolation` | `enum?` | `deny` \| `kill` | `deny` | §4.8。注意 `kill` 结束的是**沙箱**，不是进程。 |
| `audit` | `enum?` | `none` \| `metadata` | `none` | **普通**连接活动的审计级别（§7）。它不抑制违规事件（[overview.md](./overview.md) §8.1.4）。 |

## 4. 求值语义

### 4.1 决策顺序

对每个连接，以及对一个被 `l7` 规则放行的连接上的每个请求：

| 步骤 | 检查 | 结果 |
| --- | --- | --- |
| 1 | `internal`（§2.2）—— 对象是否落在此模式所禁止的私有网段？ | 拒绝；任何规则、优先级、来源都不能越过 |
| 2 | **绑定拒绝**（§4.6）—— 由 `template` 或 `profile` 贡献的 `deny` 规则 | 拒绝；任何来源、任何优先级的 `allow` 规则都不能越过 |
| 3 | 匹配方向的其余规则，按 `priority` 顺序（§4.5） | 首个匹配胜出：`allow` 放行、`deny` 拒绝 |
| 4 | 无规则匹配 | 该方向的 `defaultAction` |

第 1、2 步位于优先级之前，理由相同：它们是策略中不允许被高优先级来源放宽的部分（[overview.md](./overview.md) §5），而优先级数值由写规则的人写。

### 4.2 私有网段

`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` 与 `169.254.0.0/16` 由 `internal`（§2.2）管辖，且仅由它管辖。在 `internal.mode: deny` 下 —— 每个分级的默认 —— 它们不论任何规则都不可达。

这取代了一条用户策略永远无法解除的无条件拒绝。这个改动是刻意的：先前那条规则使沙箱间通信无法表达，并把用户推向手写从不奏效的私有 CIDR，那正是前一版本 §10.7 所描述的失败。**没有**被放宽的是：访问这些网段现在是某个人必须显式做出的决定，写在一个出现在生效策略、快照与审计轨迹里的字段中。

### 4.3 域名语义

`peer.domains`（§2.3）中的域名条目与一条 `l7` 规则中的 `hosts`，通过带 TTL 上界的临时条目的 DNS A 记录学习实现。两条要求使它可强制而非仅是建议：

1. 平台**必须**是沙箱通往名字解析的唯一路径。一个能直接查询外部解析器 —— 走 UDP/TCP 53、DoT 或 DoH —— 的工作负载，可以解析一个策略从未学到的名字然后连到结果地址，这使域名规则沦为建议。无法确保这一点的部署**必须**把域名条目声明为 `unsupported`（[overview.md](./overview.md) §8.2），而不是部分强制它们。
2. 在准入时把一个名字解析一次并钉住地址，**不是**域名规则的实现。它是一条戴着域名名字的地址规则，[overview.md](./overview.md) §8.2.1 规则 4 禁止把它当作强制来上报。

### 4.4 条目上限

每个沙箱最终的唯一条目数**不得**超过：8192 条 allow、8192 条 deny、1024 条域名、每方向 256 条规则。四层规则在按其协议与端口区间展开后计入 allow 或 deny 映射，因为它们是在那里被实现的。违反者以 `400 POLICY_NETWORK_LIMIT` 使创建请求失败，携带 `{map, got, max}`。

### 4.5 优先级

1. `priority` 是 `1`–`65535` 内的整数。**越小越先求值**，沿用安全组惯例。
2. 在一个方向内，求值是按优先级顺序的**首个匹配胜出**。一旦某条规则匹配，不再查阅后续规则。
3. 合并后，一个方向内的两条规则**不得**共用一个优先级。冲突**必须**以 `400 POLICY_NETWORK_PRIORITY_CONFLICT` 拒绝，携带两条规则名及其来源。这是刻意的，也是本模块唯一一处选择报错而非约定的地方：一个隐式的平局决胜是一份规则集所能拥有的最难调试的行为，而每一种替代方案 —— 按来源顺序、按名字顺序、最严者优先 —— 都产生一份其求值顺序在运维所读文档中不可见的策略。
4. 优先级为规则排序；它不授予权限。§4.1 的第 1、2 步在任何优先级比较之前求值，所以一条请求级规则不能用一个小数值去越过管理员的 deny。
5. 旧字段归一化进保留的优先级带（§8），使一份旧配置与一份显式规则集能共存而不冲突。

### 4.6 拒绝来源与绑定拒绝

1. 每条合并后的规则**必须**保留其**来源**：`template`、`profile` 或 `request`。
2. 一条来源为 `template` 或 `profile` 的 `deny` 规则是一条**绑定拒绝**。绑定拒绝在 §4.1 第 2 步求值，且**不得**被任何来源、任何优先级的任何 `allow` 规则越过。
3. 在单一来源内，普通优先级顺序适用：来自**同一**来源的、数值更小的 `allow` 规则胜过一条 `deny` 规则。
4. 一条被绑定拒绝完全遮蔽的请求级 `allow` 规则**不得**使创建请求失败。它**必须**被报为一条 `policyWarnings` 条目 `{field, rule, shadowedBy, source}` 并作为审计事件发出，使调用方得知它所要求的洞没有被打开。
5. 来源**必须**在 API 暴露的生效策略中保留，使运维能看到每条规则由哪个来源贡献。

### 4.7 连接状态

§4 中的每条规则描述的是**连接**，不是单个数据包：

| | 要求 |
| --- | --- |
| 回程流量 | 属于一个已被放行连接的流量**必须**在该连接存续期间被允许，无需自己的匹配规则。 |
| 回程方向不是入站 | 一个沙箱发起的连接的入向半程**不是**入站，**不得**对照 `ingress` 规则或 `ingress.defaultAction` 求值。设 `ingress.defaultAction: deny` 从不破坏一个出站请求的响应。 |
| 无连接协议 | 对 UDP 与 ICMP，「连接」指平台以一个有文档记录的空闲超时跟踪的流。回程方向的保证对这样一个流的适用，与它对 TCP 的适用完全相同。 |
| 四层端口范围 | 一条四层规则限定它所管辖方向的**目的地**。临时端口上的回程流量由连接状态放行，不由第二条规则放行。 |
| 七层请求 | 有状态性适用于连接。一个已放行连接上的各个请求按 §4.1 求值，所以一个连接可以被建立而其上的一个后续请求仍被拒。 |

这被写下来而不是留给数据路径，因为它是使一份规则集可评审的那个性质。在无状态模型下，每条 allow 规则都需要一条覆盖临时端口段的伴随反向条目 —— 那既是每个作者都会忘的东西，又在写出后成为一个远比它本欲服务的规则更宽的洞。

### 4.8 违规动作

按 [overview.md](./overview.md) §8.1，`onViolation` 决定 §4.1 拒绝一个连接或一个请求时发生什么：

| 动作 | 结果 |
| --- | --- |
| `deny`（默认） | 连接如今天一样失败：被拒 TCP 收到一个 `ECONNREFUSED` 类的 TCP reset，其余丢弃。一个被拒的七层请求收到 `403`。 |
| `kill` | **沙箱**被终止。 |

1. **这里的 `kill` 结束的是沙箱，不是那个违规进程。** 四层强制作用于数据包，而在一个连接被拒时，打开该 socket 的进程在那一层不可靠地可知。尽力而为的归属比不归属更糟，因为它会终止那个猜测所落到的进程。
2. **一个设 `kill` 的部署是在选择「一次被拒连接结束沙箱」。** 对一个绝不该访问未具名目的地的工作负载这是合法姿态，对任何会探测的东西这是破坏性的。它**不得**在假定它像 `filesystem` 或 `process` 那种进程级 `kill` 的前提下被选择。
3. **当强制点是一个共享网关而非沙箱自己的数据路径时，`kill` 是异步的。** 网关拒绝连接，沙箱由一次后续的控制面动作终止，所以存在一个连接已被拒而沙箱仍在运行的窗口。处于这种形态的部署**必须**把 `onViolation: kill` 声明为 `partial` 并记录那个窗口的上界；它**不得**把一次延迟终止上报为一次即时终止。
4. 没有 `warn`，理由见 [overview.md](./overview.md) §8.1.2。`auditTier`（§6.1）是部署在保持当前规则被强制的同时得知一个更严姿态会拒绝哪些目的地的方式。
5. 任一动作都发出一个违规事件，在每个审计级别（§7）。

### 4.9 强制执行作用域

本提案中每一个模块的强制执行都落在沙箱单位上，本模块也不例外 —— 但这只是因为沙箱单位是为了让这句话成立而选定的：

1. 本策略在沙箱所处的**网络命名空间**上被强制执行。在 VM 基质上，那个命名空间恰好属于唯一一个沙箱。在容器基质上，沙箱单位是一个 Pod（[overview.md](./overview.md) §12.1），而一个 Pod 恰好拥有一个网络命名空间。因此在两种基质上，作用域与沙箱都是重合的。
2. 这份重合正是 §12.1 把单位定为 Pod 而不是容器的原因。以容器为单位会把本策略置于比沙箱更宽的作用域上，而在那里没有任何正确的行为可选：数据路径或出网路径上的强制点是按源地址归属连接的，而同处一地的容器共用同一个源地址，于是平台无法判定该施加谁的策略。
3. 部署**不得**把两个沙箱放进同一个网络命名空间。当某个实现仍然这样做时，该创建请求**必须**以 `400 POLICY_NETWORK_SCOPE_CONFLICT` 拒绝，携带冲突的字段以及那个建立了当前配置的沙箱，而不是继续下去。
4. 平台**不得**通过取最严值、取并集或取最近一次来消解这种情形。这三者中的每一个都会静默地让一个沙箱的策略去治理另一个沙箱的流量，而那既是本对象并未描述的一种边界，也是它所能产生的最难调试的失败。
5. 规则 3 是针对*解析后*配置的创建时检查，而不是文本比较。

这套安排没有解决的是同处问题的*另一半*。一个 Pod 内的容器处在同一个沙箱之内，所以它们按构造共享本策略；但它们同时也共享一份 `policy.process` 和一份 `policy.filesystem`，而这份策略要展开到那些可能合理地需要不同姿态的容器上。那份张力是挪了位置而非消失了，它被记为 [overview.md](./overview.md) §11.14。

## 5. 合并语义

在 [overview.md](./overview.md) §5 的共享规则之上：

| 字段 | 合并细化 |
| --- | --- |
| `internal.mode` | 最严者胜出：`deny` > `identity` > `allow`。请求**不得**在低优先级来源设了 `deny` 或 `identity` 处设 `allow`；这样的请求以 `400 POLICY_NETWORK_CONFLICT` 拒绝。 |
| `internal.allowedPeers` | 跨来源**取交集**。请求不能添加模板未许可的对象。 |
| `egress.defaultAction`、`ingress.defaultAction` | `deny` 胜出。请求**不得**在低优先级来源设了 `deny` 处设 `allow`（以 `400 POLICY_NETWORK_CONFLICT` 拒绝）。 |
| `egress.rules`、`ingress.rules` | 跨来源追加。每条规则保留其来源（§4.6）。合并后优先级**不得**冲突（§4.5.3）。来自 `template` 或 `profile` 的 `deny` 规则成为绑定拒绝。 |
| `onViolation` | `kill` 胜出（[overview.md](./overview.md) §8.1.7）。鉴于 §4.8，一个设 `kill` 的模板使从它创建的沙箱的每次被拒连接都致命，而请求无法软化它。 |
| `audit` | 更详细者胜出（`metadata` > `none`）。 |

规则从不按 `name` 合并。两个来源贡献同名规则会产生两条规则，以来源区分，且它们的优先级仍必须不同。

### 5.1 可授权字段

按 [overview.md](./overview.md) §5.1.8，针对本模块的限时授权可以打开：

| 可授权 | 不可授权 |
| --- | --- |
| `egress.rules` —— 具名 `allow` 规则 | `egress.defaultAction` / `ingress.defaultAction` |
| `ingress.rules` —— 具名 `allow` 规则 | `internal.mode` —— 任何放宽 |
| `internal.allowedPeers` —— `identity` 下的具名对象 | 移除任何 `deny` 规则 |

`defaultAction` 被排除，因为它不是一个形状已知的洞（[overview.md](./overview.md) §5.1.4）：翻转它会一次打开每一个目的地。一个需要多一个端点十分钟的任务，去要那个端点。`internal.mode` 被排除，理由相同，外加第二条 —— 按 §2.2.3 放宽它会暴露元数据端点，而在一次十分钟授权期间取得的凭据不随它过期。

## 6. 默认值

一个完全不带 `policy` 对象的请求解析为 `tier: compatibility`（[overview.md](./overview.md) §7），而它就是今天的行为：

```yaml
network:                 # tier: compatibility —— 仅旧路径
  internal:
    mode: deny
  egress:
    defaultAction: allow
    rules: []
  ingress:
    defaultAction: allow
    rules: []
  onViolation: deny
  audit: none
```

一个省略 `tier` 的 `policy` 对象解析为 `restricted`。逐分级：

| | `compatibility` | `baseline` | `restricted`（默认） |
| --- | --- | --- | --- |
| `internal.mode` | `deny` | `deny` | `deny` |
| `egress.defaultAction` | `allow` | `allow` | `deny` |
| `ingress.defaultAction` | `allow` | `deny` | `deny` |
| `audit` | `none` | `none` | `metadata` |

`internal.mode` 在**每个**分级下都是 `deny`，包括 `unrestricted`。分级是默认值选择器，而没有一个默认值应当让私有网络可达 —— 那是关于一个部署拓扑的决定，而分级无从知道。因此访问私有网络永远是一个显式动作，在生效策略中可见。

**`compatibility` 是唯一把 `ingress.defaultAction` 留在 `allow` 的分级**，也是唯一对这样做有兼容性理由的：一个默认可达的沙箱是可用性默认而非安全默认（[overview.md](./overview.md) §7.1）。`baseline` 处在两者之间 —— 出站开、入站关 —— 面向那个必须拉取依赖却绝不该被拨入的常见情形。

`onViolation` 在每个分级下都留在 `deny`，按 [overview.md](./overview.md) §8.1.7 —— 在这里尤其如此，因为一个把全拒出站与 `kill` 配对的分级会在沙箱访问它第一个未具名目的地时就终止它。

### 6.1 影子评估支持

按 [overview.md](./overview.md) §7.2.5，本模块对其完整面 —— 两个方向、`defaultAction`、每条规则以及 `internal.mode` —— 支持 `auditTier` 下的影子评估。一个影子集合本会拒绝的连接或请求仍照常进行，并发出一个 `shadow: true` 审计事件，指名目的地、端口与协议或请求行，以及本会拒绝它的那条影子规则。

这是本提案中最便宜可付诸行动的影子，因为那份发现*就是*修法：`auditTier: restricted` 下的一份影子报告就是一份全拒姿态所需规则的清单。运维可以把那份清单变成策略，然后翻转分级。

两个模块特定的点：

1. 有状态性（§4.7）适用于影子评估。一条影子发现在建立时按连接发出一次 —— 或对一条七层规则按请求发出一次 —— 不是按数据包。
2. `internal.mode` 在每个分级下都是 `deny`（§6），所以一个更严分级的影子不产生 `internal` 发现。想知道收紧 `internal` 要付出什么代价的部署，在一个非生产策略档里把它设成一个更严的值；没有一个分级去影子它。

## 7. 错误

| 代码 | HTTP | 载荷 | 何时 |
| --- | --- | --- | --- |
| `INVALID_POLICY` | 400 | `{field, reason}` | `l4` 与 `l7` 同时出现或同时缺失（§2.1.2）；空 `peer`；入站 `peer` 中的域名（§2.3.2）；`icmp` 带 `ports`；畸形 CIDR、端口或匹配器。 |
| `POLICY_NETWORK_LIMIT` | 400 | `{map, got, max}` | 某个条目或规则数超过 §4.4 的上限。 |
| `POLICY_NETWORK_PRIORITY_CONFLICT` | 400 | `{direction, priority, rules, sources}` | 合并后一个方向内两条规则共用一个优先级（§4.5.3）。 |
| `POLICY_NETWORK_CONFLICT` | 400 | `{field, legacyField?}` | 一个旧字段与对应的结构化字段同时出现（§8）；或一个高优先级来源放宽 `defaultAction` 或 `internal.mode`（§5）。 |
| `POLICY_NETWORK_SCOPE_CONFLICT` | 400 | `{fields, establishedBy}` | 一个沙箱将被放进另一个沙箱已占据的网络命名空间（§4.9.3）。 |
| `POLICY_UNSUPPORTED` | 400 | `{field, state, capabilityVersion}` | 在 `enforcement: strict` 下，策略指名了本部署声明为 `unsupported` 的字段。域名条目（§4.3）与 `RegularExpression` 匹配器（§2.4.4）是最可能处于该状态的字段。 |

运行期拒绝**不是** API 错误。四层拒绝以连接失败呈现给沙箱；七层拒绝以 `403` 呈现。在 `onViolation: kill`（§4.8）下沙箱被终止，终态记录目的地与匹配规则为原因。

每次拒绝**必须**在**每个**审计级别（包括 `audit: none`）发出一个违规事件（[overview.md](./overview.md) §8.1.4）：`{sandboxID, direction, destination, port, protocol, requestLine?, rule?, provenance?, outcome: denied|killed, effectivePolicyVersion, shadow: false}`。`audit: metadata` 所加的是**普通**流量的记录 —— 部署可以合理拒绝的部分。每连接一个事件，或每个被拒七层请求一个。

非致命发现在创建/更新响应的 `policyWarnings` 数组中返回。已定义的告警：被绑定拒绝遮蔽的规则（§4.6.4）、`internal.mode: deny` 下不可达的 `sandboxGroup` 对象（§2.3.4），以及 `metadata_endpoint_reachable`（§2.2.3）。

## 8. 兼容性与旧字段映射

旧字段面是永久的。每个旧字段在 API 边界被归一化进 §2 的结构；下游只有一种表示。

| 旧字段（请求） | 归一化为 |
| --- | --- |
| `allow_internet_access: false` | `egress.defaultAction: deny` |
| `allow_internet_access: true` | `egress.defaultAction: allow` |
| `network.allow_out: [t]` | 每条一条出站四层规则：`{action: allow, priority: 40000+n, l4: {protocol: all, peer: {cidrs\|domains: [t]}}}` |
| `network.deny_out: [t]` | 每条一条出站四层规则：`{action: deny, priority: 30000+n, l4: {protocol: all, peer: {cidrs: [t]}}}` |
| `network.allow_public_traffic` | `ingress.defaultAction`（`true` → `allow`，`false` → `deny`） |
| `network.rules` | 出站七层规则，按列表顺序，在 `priority: 20000+n` |
| `network.mask_request_host` | 一条 `priority: 60000` 的入站七层规则，携带一个 Host 改写过滤器 |

1. **保留的优先级带。** 旧字段归一化使用 `20000`–`49999`。一条显式写就的规则**可以**用 `1`–`65535` 内的任何优先级，但一个把显式规则与旧字段混用的部署**应该**待在保留带之外，以免 §4.5.3 冲突在升级时冒出来。
2. Deny 条目归一化到比 allow 条目更小的数值，这在不改变「优先级决定顺序」这一总规则的前提下，为常见的旧字段配对复现了今天的结果。
3. 冲突规则：一个既含任何旧网络字段**又**含非空 `policy.network` 的请求**必须**以 `400 POLICY_NETWORK_CONFLICT` 拒绝并列出冲突对。系统**不得**静默地挑一个优先级。
4. **`internal.mode: deny` 是今天的行为**，所以一个旧请求的私有网段可达性不变：先前是无条件拒绝，现在是一个在生效策略中可见、可由显式动作改变的拒绝。
5. 模板合并照旧适用：一个模板的网络配置成为模板级默认策略，请求规则按 §5 合并。

## 9. 验收标准

1. 当同样的值通过旧字段提供时，每一个既有出站行为测试原样通过。
2. 对每一种旧字段组合，通过 `policy.network` 提供等价值产生一份完全相同的生效配置。
3. 一个同时含 `network.allow_out` 与 `policy.network.egress.rules` 的请求以 `400 POLICY_NETWORK_CONFLICT` 拒绝。
4. **对称性。** 一条入站规则与一条同形状的出站规则都被接受，都带着优先级与来源出现在生效策略中，也都被强制。一条入站规则上的 `peer.domains` 条目以 `400 INVALID_POLICY` 拒绝。
5. **优先级排序。** 在一条优先级 100 的出站 `deny` 与一条 200 的、覆盖同一目的地、来自同一来源的 `allow` 下，连接被拒。把数值对调则放行。排序不依赖规则在列表中出现的顺序。
6. **优先级冲突。** 合并后一个方向内两条同优先级的规则以 `400 POLICY_NETWORK_PRIORITY_CONFLICT` 拒绝并指名两条规则及其来源 —— 包括一条来自模板、另一条来自请求时。
7. **优先级不授予权限。** 一条优先级 60000 的模板 `deny` 规则仍然拒绝一个优先级 1 的请求 `allow` 规则本会放行的连接（§4.6.2），且请求收到被遮蔽规则告警。
8. **四七层互斥。** 一条同时携带 `l4` 与 `l7` 的规则被拒；一条两者都不带的规则被拒。
9. **七层隐含连接。** 在 `egress.defaultAction: deny` 与一条针对 `https://api.example.com/v1`（PathPrefix）的 `l7` allow 规则下，到该主机 443 的 TLS 连接被建立，一个 `GET /v1/x` 成功，一个 `GET /other` 收到 `403` 而连接保持。
10. **七层匹配器。** 在 `method: GET`、`headers: [{Exact, X-Env, prod}]` 与 `queryParams: [{Exact, v, 1}]` 下，只有同时携带两者的 `GET` 匹配；缺其一的请求落到下一条规则。一个 `cookies` 条目匹配从 `Cookie` header 解析出的一个 cookie。
11. **`internal.mode`。** 在 `deny` 下，即使有一条优先级 1、指名 `10.0.0.5` 的出站 allow 规则，到它的连接也失败。在 `allow` 下，同一连接成功。在带一条指名某对象组的 `allowedPeers` 条目的 `identity` 下，该组中的一个沙箱可达，而同一网段中的任意地址不可达。
12. **元数据端点告警。** 一份带 `internal.mode: allow` 与一个 `proxy` 暴露密钥绑定的策略被接受并携带 `metadata_endpoint_reachable` 告警。在 `internal.mode: deny` 下，到 `169.254.169.254` 的连接失败。
13. **有状态性。** 在 `egress.defaultAction: deny`、一条针对某目的地的 allow 规则、以及同时设的 `ingress.defaultAction: deny` 下，一个到该目的地的出站 TCP 连接成功**且其响应被收到**，无入站规则存在（§4.7）。
14. **restricted 分级。** `tier: restricted` 且无网络字段解析为 `egress.defaultAction: deny`、`ingress.defaultAction: deny`、`internal.mode: deny`，且生效策略记录那些展开值。
15. **影子评估。** 在 `tier: baseline` 与 `auditTier: restricted` 下，到一个未具名公网目的地的连接**成功**并发出一个 `shadow: true` 事件，指名目的地与本会拒绝它的字段。沙箱内可观测到的一切都不变。每连接一个事件，或每个七层请求一个。
16. **违规动作。** 在 `onViolation: deny` 下，一个被拒连接失败而沙箱继续运行。在 `kill` 下，同一连接终止**沙箱**，终态指名目的地与匹配规则。一个设 `kill` 的模板不能被请求软化。
17. **在 `audit: none` 下违规仍被审计。** 一个被拒连接仍发出一个携带 `shadow: false`、方向与目的地的违规事件。
18. **域名强制是诚实的。** 一个无法保证自己是沙箱唯一解析器的部署把域名条目声明为 `unsupported`，而在 `enforcement: strict` 下一份指名域名的策略以 `400 POLICY_UNSUPPORTED` 拒绝（§4.3.1）。

## 10. 开放问题

1. **入站认证与暴露。** `ingress` 现在能表达端口、协议、来源与七层匹配器，这关闭了本模块过去承载的大部分不对称。它仍不能表达的是*认证*：令牌绑定、过期、吊销，以及「可达」与「可被一个已认证调用方访问」之间的差别。一个公共 URL 是一次能力授予，把它当作能力授予对待所需的最小语义记在 [overview.md](./overview.md) §11.18。
2. **响应侧七层规则。** 每个 `l7` 匹配器描述的是一个请求。一条规则是否应能匹配一个**响应** —— 状态、内容类型、大小 —— 以便一份策略能表达「可以调这个 API 但不能从它下载一个可执行文件」？
3. **优先级分配。** §4.5.3 拒绝冲突，这是安全的，但把优先级分配推给了组合模板与请求的那个人。平台是否应提供一个稀疏分配约定，或一个按来源的 `priorityBase`，使组合不需要协调？
4. **`internal.mode: identity` 与分组。** `allowedPeers` 预设了一个控制面尚未定义的沙箱分组概念。什么标识一个组、谁可以把一个沙箱加进去、成员身份本身是否是一个策略字段（[overview.md](./overview.md) §11.11）？
5. **速率与可达性。** 出站请求速率上限是一个 `resource.rate` 字段而可达性在这里（[overview.md](./overview.md) §11.9）。一条 `NetworkRule` 是否应携带自己的速率上限，还是那会重造这个统一对象存在的意义所要防止的方言问题？注意两者位于同一个七层强制点上（[resource.md](./resource.md) §5.1），所以障碍在对象模型而不在机制。
6. **流超时作为策略。** §4.7 要求无连接流有一个有文档记录的空闲超时，但把值留给平台。它是否应是一个策略字段？
7. **IPv6。** `peer.cidrs` 在 v1 是 IPv4，而 `internal` 指名的是 IPv4 私有网段。IPv6 需要它自己的网段集（`fc00::/7`、`fe80::/10`，以及某些云暴露的元数据地址）才能被诚实地支持。确认 v1 只支持 IPv4，且一个 IPv6 字面量被拒绝而非被忽略。

## 11. 非规范性说明

- **实现路径。** 四层规则、连接状态（§4.7）与优先级排序在两种基质上都是通用件（[overview.md](./overview.md) §12.2）：包过滤、conntrack 与一份有序规则集。有两个面不是。**域名条目**需要把名字解析时的学习接进过滤器，外加对解析器的独占控制（§4.3.1）。**七层匹配器**需要路径上一个终结连接的代理 —— 而对 `https`，那意味着终结 TLS，没有它就只有 SNI 可见，`path`、`headers`、`queryParams` 与 `cookies` 根本无法求值。一个终结 TLS 的部署在那一点以明文读取它租户的流量，这是一个自带合规分量的决定；一个不终结的部署**必须**把那些匹配器声明为 `unsupported`，而不是静默地只按 SNI 匹配。
- 本模块为 `l7` 规则所需的那个七层代理，正是 [identity.md](./identity.md) §3.1 为 `exposure: proxy` 所需、[resource.md](./resource.md) §14 为 Token 计量所需的同一个组件。一套机制，三个模块 —— 这是先建它的最强论据。
- **关于沿用 `HTTPRoute` 而非另起炉灶。** §2.4 的匹配器形状刻意就是 Gateway API 的，连 `type` 枚举都是，因为一位写过 `HTTPRoute` 的运维不该为同一件事学第二套语法。两处新增被作为新增陈述：`cookies`（§2.4.3），`HTTPRoute` 把它折进 header；以及 `action: deny`，`HTTPRoute` 没有这个概念，因为一条路由不是一道防火墙。
- **被拒的替代方案 —— 隐式隔离。** 一个 Kubernetes NetworkPolicy 一旦有任何策略选中它的目标，就把该方向翻成默认拒绝。它很有吸引力，因为它使常见意图无法被不完整地表达。它在此被拒，因为 `defaultAction` 在一处可见的地方显式说了同样的话，而隐式隔离会把每一份在通用互联网访问旁列出几条 allow 条目的既有配置，静默地转成一个全拒沙箱。
- **被拒的替代方案 —— 两个方向共用一份合并规则列表。** 一份带按规则 `direction` 字段的单一列表更紧凑，也是某些安全组 API 的做法。它在此被拒，因为优先级唯一性（§4.5.3）是按方向的，而一份共享列表要么使该约束全局化 —— 无理由地耦合入站与出站编号 —— 要么要求一个读者必须记住的复合键。
- **关于 `kill` 与归属。** §4.8 的沙箱级 `kill` 不是某一基质的缺陷。无论是 tap 设备上的一个包过滤器还是一条 CNI 数据路径，在一个连接被拒的那一点都没有可靠的进程上下文；两者都得猜。当强制点是一个共享网关时，该动作还额外是异步的（§4.8.3），这是偏好 `deny` 的第二个理由。
