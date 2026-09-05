# 规格：网络策略（Network Policy）

[提案 0001 — 沙箱安全策略](./overview.md) 的组成部分。本文档中的关键词 **必须（MUST）**、**不得（MUST NOT）**、**应该（SHOULD）**、**可以（MAY）** 依据 RFC 2119 解释。

---

## 1. 范围

本规格定义 `SandboxPolicy` 对象的网络子策略：

- **出站（Egress）** — L3/L4 可达性（IP/CIDR、基于域名的 DNS 学习）、端口与协议范围限定，以及 L7 HTTP/HTTPS 规则。
- **入站（Ingress）** — 对沙箱公开入站访问的门控。

求值是**有状态的**：规则描述的是连接，而一个已被放行连接的回程方向不需要自己对应的规则（§4.7）。这与云安全组提供的是同一份契约，也正是"一套可评审的规则"与"一套被临时端口区间反向条目撑满的规则"之间的分界。

本规格**不重新定义**既有出站语法。`allowOut` / `denyOut` 的目标语法、`rules` 的 L7 规则语法、DNS 白名单与学习行为、内置私网 CIDR 拒绝均已由[出站网络策略](../../../guide/network-policy.md)与[安全代理](../../../guide/security-proxy.md)规定；上述文档以引用方式并入本规格。本规格将其包装进统一策略对象，并定义合并、默认值与兼容性契约。

## 2. 对象模型

```yaml
policy:
  network:
    allowInternetAccess: bool          # 默认: true
    allowOut:      [string]            # IP / CIDR / 域名 / 前缀 "*." 通配域名
    denyOut:       [string]            # 仅 IPv4 / IPv4 CIDR
    portRules:     [PortRule]          # 按协议与端口限定范围的 L4 允许规则
    rules:         [EgressRule]        # L7 规则，首匹配生效（既有语法）
    onViolation:   deny | kill         # 默认：deny —— 见 §4.8
    audit:         none | metadata     # 默认：none
    ingress:
      allowPublicTraffic: bool         # 默认: true
      maskRequestHost:   string        # Host 权威模板，"${PORT}" 展开
```

### 2.1 `PortRule`

一条 `allowOut` 条目在**所有**端口上放行其目标。对于"让这个沙箱能访问我们的 API"来说这个形状是对的，而对于"让它只能用 TCP 访问这个数据库的 5432，别的都不行"来说就太粗了。`portRules` 就是那句更窄的表达。

```yaml
- name:      string       # 必填，在列表内唯一；用于错误与审计
  target:    string       # IP / CIDR / 域名 / 前缀 "*." 通配域名 —— 即 allowOut 语法
  protocols: [string]     # {tcp, udp} 的子集；默认：[tcp, udp]
  ports:     [string]     # "443" 或 "8000-8100"；默认：所有端口
```

1. 当目标、协议**且**端口全部匹配时，一条 `PortRule` 匹配该连接。匹配的规则以与 `allowOut` 条目完全相同的方式放行该连接（§4.1 第 3 步）。
2. 域名目标与 `allowOut` 域名条目一样参与 DNS 学习；学习到的地址继承该规则的协议与端口限定。
3. `portRules` 是**追加的允许面，而不是对 `allowOut` 的过滤器**。要把一个目标限制在特定端口上，就在 `portRules` 里指名它，并且**不要**在 `allowOut` 里写它。
4. 一个已被 `allowOut` 宽泛放行、同时又在某条更窄 `PortRule` 中被指名的目标，仍然在所有端口上可达：更宽的允许胜出，端口限定不起作用。这不是错误 —— 模板的宽泛允许与请求的窄规则必须能共存 —— 但平台**必须**将其作为 `policyWarnings` 条目 `{field: "policy.network.portRules", rule, reason: "shadowed_by_allow_out"}` 报告。一位作者以为某项端口限制正在生效而实际上并没有，正是原则 4 存在所要防止的那种失败。
5. 端口是 `1`–`65535` 范围内的单值或闭区间。格式错误的条目、逆序区间、以及 `{tcp, udp}` 之外的协议，**必须**以 `400 INVALID_POLICY` 拒绝。
6. `portRules` 无法收窄或解除内置私网 CIDR 拒绝与绑定性拒绝（§4.6）。那些先于它求值，且不受端口限定影响。

## 3. 字段规格

| 字段 | 类型 | 约束 | 默认值 | 语义 |
| --- | --- | --- | --- | --- |
| `allowInternetAccess` | `bool?` | — | `true` | 为 `false` 时安装 deny-all 出站兜底，仅显式 allow 条目与 L7 目标可打通。 |
| `allowOut` | `[string]?` | 每项：IPv4、IPv4 CIDR、合法 DNS 名称、前导 `*.` 通配 DNS 名称。非法条目**必须**导致校验失败。 | `[]` | 显式允许的出站目标。域名条目参与 DNS 学习。 |
| `denyOut` | `[string]?` | 每项：IPv4 或 IPv4 CIDR。域名**必须**以 `400 INVALID_POLICY` 拒绝。 | `[]` | 显式拒绝的出站目的地。 |
| `portRules` | `[PortRule]?` | 按 §2.1。`name` 在列表内**必须**唯一。 | `[]` | 按端口与协议限定范围的允许规则。 |
| `rules` | `[EgressRule]?` | 遵循既有 L7 规则语法：`name`、`match.{scheme,sni,host,method,path}`、`action.{allow,audit,inject}`。 | `[]` | L7 HTTP/HTTPS 规则，首匹配生效。 |
| `onViolation` | `enum?` | `deny` \| `kill` | `deny` | §4.8。注意 `kill` 结束的是**沙箱**，不是某个进程。 |
| `audit` | `enum?` | `none` \| `metadata` | `none` | **普通**连接活动的审计级别（§7）。它不压制违规事件（[overview.md](./overview.md) §8.1.4）。 |
| `ingress.allowPublicTraffic` | `bool?` | — | `true` | 为 `false` 时，公开入站访问需要携带有效的 traffic-access token。 |
| `ingress.maskRequestHost` | `string?` | Host 权威模板；`${PORT}` 展开为所请求的沙箱端口。 | 未设置 | 改写转发给沙箱服务的 Host 权威。仅作用于入站。 |

## 4. 求值语义

以引用方式并入既有出站规格；此处摘要为规范性锚点：

1. **出站判定顺序**对每个连接**必须**为：

   | 步骤 | 检查 | 结果 |
   | --- | --- | --- |
   | 1 | 内置私网 CIDR 拒绝（见下第 2 项） | 拒绝 —— 任何策略来源都不可覆盖 |
   | 2 | **绑定性拒绝（binding deny）**（§4.6）—— 由优先级低于请求的来源贡献的 `denyOut` 条目 | 拒绝 —— **不可**被请求级 `allowOut` 覆盖 |
   | 3 | 命中 `allowOut`，或 `portRules` 在目标 + 协议 + 端口上命中（§2.1） | 允许（带 L7 标记的目标其 HTTP/HTTPS 流量进入 L7 求值） |
   | 4 | 命中 `denyOut`（其余的、请求级条目） | 拒绝 |
   | 5 | 其他 | 允许 —— 除非 `allowInternetAccess: false` 已安装 deny-all 兜底 |

2. **内置拒绝。** 除非 `allowInternetAccess: false` 已安装 deny-all，沙箱私网与宿主内部 CIDR（`10.0.0.0/8`、`127.0.0.0/8`、`169.254.0.0/16`、`172.16.0.0/12`、`192.168.0.0/16`）**必须**保持拒绝，且不受用户策略影响。用户策略**不得**能够放行这些网段。
3. **域名语义。** 域名 allow 条目通过 DNS A 记录学习实现，产生按 TTL 过期的临时 allow 条目；此行为是规范性的且保持不变。
4. **条目上限。** 每沙箱最终唯一条目数**不得超过**：allow 表 8192、deny 表 8192、域名规则表 1024。`portRules` 条目在按其协议与端口区间展开后计入 **allow 表**，因为那正是它们被落实的地方。超限使创建请求失败，返回 `400 POLICY_NETWORK_LIMIT`，载荷 `{map, got, max}`。
5. `rules` 在合并后的规则列表上**首匹配生效**。

### 4.6 拒绝来源与绑定性拒绝

allow 先于 deny（第 3 步先于第 4 步）是今天的行为，予以保留 —— 因为模板刻意用「宽泛 `denyOut` + 精确 `allowOut`」打洞的配置依赖它。但这一顺序跨来源应用时，调用方只要在请求里内联一条 `allowOut`，就能放宽管理员设定的边界 —— 这与共享合并原则「高优先级只能收窄、不得放宽」（[overview.md](./overview.md) §5）正相反。来源标记（provenance）封堵该缺口：

1. 每个合并后的 `allowOut` / `denyOut` 条目**必须**保留其**来源**：`template`、`profile` 或 `request`。
2. 来源为 `template` 或 `profile` 的 `denyOut` 条目是**绑定性拒绝**。绑定性拒绝在所有 `allowOut` 条目之前求值，且**不得**被任何来源的 `allowOut` 条目覆盖。
3. 同一来源内部，allow 先于 deny 依然成立：`allowOut` 条目可以在**同一来源**贡献的 `denyOut` 条目上打洞。
4. 被绑定性拒绝完全遮蔽的请求级 `allowOut` 条目**不得**导致创建请求失败。它**必须**在创建响应中以 `policyWarnings` 条目 `{field: "policy.network.allowOut", entry, shadowedBy, source}` 呈现，并**必须**发出审计事件，使调用方得知其申请的洞并未打开（原则 4：拒绝必须可解释）。
5. 来源标记**必须**在策略 API 暴露的生效策略中保留，使运维方能看出每个条目由哪个来源贡献。

### 4.7 连接状态

§4 中的每一条规则描述的都是一个**连接**，而不是单个数据包。这个区分是规范性的，不是实现细节：

| | 要求 |
| --- | --- |
| 回程流量 | 属于一个已被 §4.1 放行的连接的流量，**必须**在该连接存续期间被允许通过，无需自己对应的匹配规则。 |
| 回程方向不是 ingress | 由沙箱发起的连接，其入向的那一半**不是** ingress，**不得**受 `ingress.allowPublicTraffic`（§3）约束。设置 `ingress.allowPublicTraffic: false` 绝不会破坏一次出站请求的响应。 |
| 无连接协议 | 对 UDP 与 ICMP，"连接"指由平台跟踪、带有已文档化空闲超时的一条流。回程方向的保证对这样一条流的适用方式，与对 TCP 完全相同。 |
| 端口规则 | 一条 `PortRule`（§2.1）限定的是出向那一半的**目标端**。它的回程流量抵达时源端口是临时端口，其通过依据的是连接状态，而不是第二条规则。 |

这一点被写下来而不是留给数据路径，因为它正是让一套规则可被评审的那个属性。在无状态模型下，每一条 `allowOut` 条目都需要配一条覆盖临时端口区间的反向条目 —— 而那既是每个作者都会忘掉的东西，又在一旦写出之后成为一个远比它本要服务的那条规则更宽的洞。云安全组正是因为这个原因而有状态，而本规格连同语法一并继承了这个预期（§1）。

### 4.8 违规动作

依 [overview.md](./overview.md) §8.1，`onViolation` 决定当 §4.1 拒绝一个连接时会发生什么：

| 动作 | 结果 |
| --- | --- |
| `deny`（默认） | 连接像今天一样失败：被拒 TCP 返回 `ECONNREFUSED` 类 RST，其余丢弃（§7）。 |
| `kill` | **沙箱**被终止。 |

第二行的粒度正是本小节的要点，而它是一个局限，不是一种设计偏好：

1. **这里的 `kill` 结束的是沙箱，而不是那个违规进程。** L3/L4 强制执行作用在数据包上。当一个连接被拒绝时，在那一层已经无法可靠地知道是哪个进程打开了这个 socket —— 而一次尽力而为的归因比不归因更糟，因为它会终止那个被猜中的进程。结束沙箱是这个强制执行点唯一能诚实采取的动作。
2. **因此一个设置 `kill` 的部署，选择的是"一个被拒连接终结整个沙箱"。** 对于一个本就绝不该访问未被指名目标的工作负载，这是一种正当的姿态；而对任何会做探测的东西，它是破坏性的。它**不得**在"以为它的行为像 `filesystem` 或 `process` 的 `kill`"的假设下被选择，那两者是进程级的（[overview.md](./overview.md) §8.1.3）。
3. **内置私网 CIDR 拒绝（§4.2）也参与其中。** 在 `kill` 之下，一次到 `169.254.169.254` 的连接尝试会终结沙箱。这是 `kill` 最站得住脚的场景 —— 没有任何正当的东西会去访问元数据端点 —— 同时也是最可能意外触发的场景，因为有些运行时会在启动时探测这类地址。请先影子那个分级（§6.1）。
4. 没有 `warn`，理由见 [overview.md](./overview.md) §8.1.2。`auditTier`（§6.1）才是一个部署用来弄清"一个更严的姿态会拒绝哪些目标"、同时让当前规则保持强制的方式。
5. 两种动作都会产生违规事件，且在任何审计级别下都产生（§7）。

## 5. 合并语义

在 [overview.md](./overview.md) §5 的共享规则之上：

| 字段 | 合并细化 |
| --- | --- |
| `allowInternetAccess` | 请求显式值覆盖模板/策略档；缺省保持低优先级值。当低优先级来源已设为 `false` 时，请求**不得**设为 `true` —— deny-all 兜底只能收紧、不能解除（以 `400 POLICY_NETWORK_CONFLICT` 拒绝）。 |
| `allowOut`、`denyOut` | 高优先级条目追加在低优先级条目之后，按规范化条目去重。每个条目保留其来源标记（§4.6）；去重时**必须**为重复条目保留**最低**优先级的来源标记，使拒绝保持绑定性。 |
| `portRules` | 按 `name` 追加并去重。条目保留来源标记，并与 `allowOut` 条目完全一样受绑定性拒绝约束（§4.6）：被绑定性拒绝遮蔽的 `portRule` 不会打开，且**必须**以 `policyWarnings` 条目上报。 |
| `rules` | 高优先级规则排在低优先级规则之前。同名规则**不**合并也不替换；两条都保留、请求侧在前，由首匹配决定实际结果。 |
| `onViolation` | `kill` 胜出（[overview.md](./overview.md) §8.1.7）。鉴于 §4.8，一个设置 `kill` 的模板会让由它创建的沙箱的每一次连接拒绝都成为致命的，而请求无法把它调软。 |
| `audit` | 更详细者胜出（`metadata` > `none`）。 |
| `ingress.*` | 标量语义；显式值覆盖。 |

### 5.1 可授权字段

依 [overview.md](./overview.md) §5.1.8，针对本模块的限时授权可以打开：

| 可授权 | 不可授权 |
| --- | --- |
| `allowOut` —— 具名目标 | `allowInternetAccess: true` |
| `portRules` —— 具名规则 | 移除任何 `denyOut` 条目 |

`allowInternetAccess: true` 被排除，因为它不是一个形状已知的洞（[overview.md](./overview.md) §5.1.4）：它一次性对所有目的地解除 deny-all 兜底。一个任务若需要多访问一个端点十分钟，那就申请那个端点。与所有地方一样，授权无法重新打开绑定性拒绝已关上的东西，也无法打开内置私网 CIDR 拒绝（§4.1 第 1 步）。

## 6. 默认值

缺省 `policy.network` 解析为服务端默认值，即 `baseline` 分级（[overview.md](./overview.md) §7.1）：

```yaml
network:
  allowInternetAccess: true
  allowOut: []
  denyOut: []            # 加内置私网 CIDR 拒绝
  portRules: []
  rules: []
  onViolation: deny
  audit: none
  ingress:
    allowPublicTraffic: true
```

这与今天不携带网络字段的请求行为逐字节一致。

在 `tier: restricted` 之下，同一批字段改为解析出 deny-all 姿态 —— `allowInternetAccess: false` 与 `ingress.allowPublicTraffic: false` —— 从而让「未经指名就不进不出」成为策略上的一个字段，而不是每个模块两个字段。分级只改这些默认值；§4 的每一条求值规则都不变，同一来源内的显式字段依然胜出（[overview.md](./overview.md) §7.1 规则 3）。`onViolation` 在 `restricted` 之下仍是 `deny`，依 [overview.md](./overview.md) §8.1.7 —— 而在这里尤其如此，因为一个把 deny-all 出站与 `kill` 配在一起的分级，会在沙箱访问第一个未被指名目标时就把它终结，而那离「给我一个被锁定的沙箱」这个诉求已经非常远了。

### 6.1 影子评估支持

依 [overview.md](./overview.md) §7.2.5，本模块在 `auditTier` 之下对其完整的出站与入站面支持影子评估。更严分级的规则集与被强制执行的那一套并行求值；影子集合本来会拒绝的连接**照常建立**，并产生一条 `shadow: true` 审计事件，指名目标、端口与协议，以及本来会拒绝它的那个影子字段。

这是本提案中最容易依据其发现采取行动的一处影子，因为发现本身*就是*修法：`auditTier: restricted` 下的一份影子报告，就是一份 deny-all 姿态需要写进 `allowOut` 或 `portRules` 的目标清单。运维可以把那份清单变成策略，然后再翻分级。

两点本模块专属：

1. 内置私网 CIDR 拒绝（§4.2）在每一个分级之下都生效，所以它们绝不会作为影子发现出现。今天被拒绝的目标在影子里也是被拒绝的；影子评估上报的是*会发生变化的东西*，而不是本来就成立的东西。
2. 有状态性（§4.7）同样适用于影子评估。一条影子发现在连接建立时产生一次，而不是每个数据包一次 —— 若非如此，[overview.md](./overview.md) §7.2.7 提到的事件量问题会让这个功能在任何真实工作负载上都不可用。

## 7. 错误

| 错误码 | HTTP | 载荷 | 时机 |
| --- | --- | --- | --- |
| `INVALID_POLICY` | 400 | `{field, reason}` | 条目格式错误（如 `denyOut` 中出现域名、非法 CIDR）。 |
| `POLICY_NETWORK_LIMIT` | 400 | `{map, got, max}` | 最终唯一条目数超过表上限。 |
| `POLICY_NETWORK_CONFLICT` | 400 | `{field, legacyField}` | 遗留字段与 `policy.network` 同时出现（§8）。 |

运行时的出站拒绝**不是** API 错误；与今天一致，它以连接失败的形式呈现给沙箱（被拒 TCP 返回 `ECONNREFUSED` 类 RST，其余丢弃）。在 `onViolation: kill`（§4.8）之下沙箱被终止，且终止状态把该目标与命中的规则记录为原因。

每一个被拒连接都**必须**在**任何**审计级别下产生一条违规事件，包括 `audit: none`（[overview.md](./overview.md) §8.1.4）：`{sandboxID, destination, port, protocol, rule?, provenance?, outcome: denied|killed, effectivePolicyVersion, shadow: false}`。而 `audit: metadata` 所增加的是对**普通**连接 —— 也就是被放行的那些 —— 的记录，那才是量大的部分，也是一个部署可能合理地不想要的部分。按连接一条事件，而不是按数据包，条件与 §6.1.2 相同。

非致命发现以 `policyWarnings` 数组随创建/更新响应返回。警告绝不改变请求的结果；它只说明所提交策略的某一部分不生效。已定义的警告：被绑定性拒绝遮蔽的 `allowOut` 条目（§4.6.4），以及被更宽的 `allowOut` 条目遮蔽的 `portRule`（§2.1.4）。

## 8. 兼容性与遗留字段映射

遗留面是永久保留的。每个遗留字段在 API 边界被规范化进策略对象；下游只有唯一一种表示。

| 遗留字段（请求） | 策略位置 |
| --- | --- |
| `allow_internet_access`（顶层） | `policy.network.allowInternetAccess` |
| `network.allow_out` | `policy.network.allowOut` |
| `network.deny_out` | `policy.network.denyOut` |
| `network.allow_public_traffic` | `policy.network.ingress.allowPublicTraffic` |
| `network.mask_request_host` | `policy.network.ingress.maskRequestHost` |
| `network.rules` | `policy.network.rules` |

冲突规则：同时包含任一遗留网络字段**和**非空 `policy.network` 的请求**必须**以 `400 POLICY_NETWORK_CONFLICT` 拒绝，并列出冲突字段对。系统**不得**静默选择优先级。

模板合并不受影响：模板的网络配置成为模板级默认策略；请求字段按 §5 合并，方式与今天完全相同。

## 9. 验收标准

1. 以遗留字段提供相同取值时，全部既有出站行为测试原样通过。
2. 对每一种遗留字段组合，通过 `policy.network` 提供等价取值后，产生的生效出站配置（允许/拒绝/L7 路由的可观测行为）完全一致。
3. 同时包含 `network.allow_out` 与 `policy.network.allowOut` 的请求被 `400 POLICY_NETWORK_CONFLICT` 拒绝。
4. `denyOut` 含域名被 `400 INVALID_POLICY` 拒绝。
5. 超限配置被 `POLICY_NETWORK_LIMIT` 拒绝且 `{map, got, max}` 正确。
6. `allowOut` 条目无法覆盖内置私网 CIDR 拒绝。
7. 缺省 `policy.network` 且缺省遗留字段 ⇒ 默认策略，与今天无字段时的行为一致。
8. **绑定性拒绝。** 模板（或策略档）的一条 `denyOut` 加上请求侧针对其覆盖地址的一条 `allowOut` ⇒ 连接被拒绝，且创建响应携带 `policyWarnings` 条目，指明被遮蔽的条目及遮蔽它的来源。
9. **同源打洞。** **同一**来源贡献的 `denyOut` 与 `allowOut`，其中 allow 被 deny 覆盖 ⇒ 连接被允许（今天的行为保持不变）。
10. 针对已设 `false` 的模板，请求设置 `allowInternetAccess: true` 被 `400 POLICY_NETWORK_CONFLICT` 拒绝。
11. **端口限定。** 在 `allowInternetAccess: false` 且仅有一条针对 `10.20.0.5`、`tcp`、`5432` 的 `portRule` 时，到该地址 5432 的连接成功，而 5433 与 UDP 5432 被拒绝。一条指定端口区间的 `portRule` 放行区间内每个端口，且不放行区间之外的任何端口。
12. **端口规则被遮蔽。** 同时出现在 `allowOut` 与一条更窄 `portRule` 中的目标在所有端口上可达，且创建响应携带指名该规则的 `shadowed_by_allow_out` 警告。
13. **端口规则不是逃逸口。** 一条指向内置私网 CIDR、或指向被绑定性拒绝关上的地址的 `portRule`，不会打开它。
14. **受限分级。** `tier: restricted` 且不带任何网络字段，解析为 `allowInternetAccess: false` 与 `ingress.allowPublicTraffic: false`，且生效策略记录这些展开值。某个来源同时设置 `tier: restricted` 与显式 `allowInternetAccess: true` 时，从该来源得到 `true`，但仍受对低优先级来源的只能收窄规则约束。
15. **有状态性。** 在 `allowInternetAccess: false` 且只有一条指向某个目标的 `allowOut` 条目时，一次到该目标的出站 TCP 连接成功**且能收到其响应**，全程不存在任何反向规则。由 `portRule` 放行的连接同样成立，其回程抵达时源端口是临时端口。同时设置 `ingress.allowPublicTraffic: false` 时，该响应仍然能收到 —— 回程方向不是 ingress（§4.7）。
16. **影子评估。** 在 `tier: baseline` 配 `auditTier: restricted` 下，一次到未被指名的公网目标的连接**成功**，并产生一条 `shadow: true` 事件，指名该目标以及本来会拒绝它的那个字段。一次到被内置拒绝的私网 CIDR 的连接像今天一样被拒绝，且**不**产生任何影子发现。沙箱内部可观察到的一切，与同一份配置不带 `auditTier` 时毫无差别。影子事件按连接产生一条，而不是按数据包。
17. **违规动作。** 在 `onViolation: deny`（默认）下，一个被拒连接失败而沙箱继续运行 —— 也就是今天的行为。在 `onViolation: kill` 下，同一个被拒连接终止**沙箱**，且终止状态指名该目标与命中的规则。一个设置 `kill` 的模板不能被请求调软成 `deny`。
18. **`audit: none` 下违规仍被审计。** 在默认的 `audit: none` 下，一个被拒连接仍然产生一条携带 `shadow: false` 与该目标的违规事件；`audit: none` 压掉的只是被放行连接的记录。事件按连接产生一条。

## 10. 开放问题

1. `ingress` 是否应在 v1 之后扩展（如源 CIDR 白名单、按端口的入站规则），还是 v1 保持最小面？注意出站现在有了端口与协议限定（§2.1）而入站没有，这让这处不对称比以前更显眼。
2. 域名 `denyOut`：今天按设计拒绝。未来是否应规范一种 DNS sinkhole 式拒绝（阻断指定域名的解析）？
3. IPv6/AAAA 在允许/拒绝与学习中的支持 —— v1 不在范围内；待确认。
4. **按端口拒绝。** §2.1 只给*允许*面加了端口限定。是否也该有一个按端口限定的 `denyOut`，还是说既然 deny-all 姿态只差一个分级，「指名什么可达」就已经够了？
5. **速率与可达性。** 带宽是 `resource.quota` 的一个维度，而可达性在本文档（[overview.md](./overview.md) §11.9）。一条 `PortRule` 是否应该能自带速率上限，还是那恰好重现了统一对象存在所要避免的方言问题？
6. **把流超时做成策略。** §4.7 要求为无连接的流提供一个已文档化的空闲超时，但把取值留给了平台。它是否应该成为一个策略字段？一个持有数千条空闲 UDP 流的工作负载是个资源问题，这支持把它完全排除在 `network` 之外 —— 但一条流过期带来的*可达性*后果落在本文档里。
7. **身份型目标。** 本规格里的每一个目标都是地址，或会解析到地址。对端组引用（安全组模型）与标签选择器（NetworkPolicy 模型）能在无人书写 CIDR 的前提下表达"这些工作负载之间可以互通"，而这正是多 Agent 场景需要的。跟踪于 [overview.md](./overview.md) §11.11，因为其阻塞性障碍是沙箱之间的流量正跑在 §4.2 无条件拒绝的那些网段上。

## 11. 非规范性说明

- 既有数据路径（eBPF L3/L4 强制 + L7 代理处理带标记的 HTTP/HTTPS）已满足总览原则 5 对本模块的要求；本规格不要求改变强制执行点。连接跟踪（§4.7）同样是既有路径本来就具备的属性 —— §4.7 是把它作为一项契约文档化，而不是在请求它。
- **§4.6 的被否决方案：** 无条件地让 `denyOut` 先于 `allowOut` 求值（全局 deny-first 模型）。它是更常见的安全模型，但会改变每一份「在宽泛 deny 上用 allow 打洞」的既有配置的含义，与 §9.1 与 §6 的兼容性承诺相冲突。绑定性拒绝在跨来源方向达成同等的防提权效果，同时让单来源语义逐字节保持不变。
- **被否决方案 —— 隐式隔离。** Kubernetes NetworkPolicy 只要有任何一份策略选中了目标，就把该目标在对应方向上翻成默认拒绝：写下一条 allow 规则就隐式拒绝了其他一切。这是个有吸引力的属性，因为它让最常见的那个意图（"只到这些目标"）不可能被表达得不完整。此处否决它的理由是：在本对象中，`allowOut` 条目按定义就是加法式的，而且早在本提案之前就是如此；采纳隐式隔离会静默地把每一份「列了几条 allow 条目、同时保留通用互联网访问」的既有配置转成一个 deny-all 沙箱，而那与 §9.1 恰好相反。显式的写法是 `allowInternetAccess: false`，而 `tier: restricted` 让它变成一个字段 —— 抵达同一个目的地，却无需重新解释任何人的既有策略。
