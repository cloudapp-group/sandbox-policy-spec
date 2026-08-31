# 规格：网络策略（Network Policy）

[提案 0001 — 沙箱安全策略](./overview.md) 的组成部分。本文档中的关键词 **必须（MUST）**、**不得（MUST NOT）**、**应该（SHOULD）**、**可以（MAY）** 依据 RFC 2119 解释。

---

## 1. 范围

本规格定义 `SandboxPolicy` 对象的网络子策略：

- **出站（Egress）** — L3/L4 可达性（IP/CIDR、基于域名的 DNS 学习）与 L7 HTTP/HTTPS 规则。
- **入站（Ingress）** — 对沙箱公开入站访问的门控。

本规格**不重新定义**既有出站语法。`allowOut` / `denyOut` 的目标语法、`rules` 的 L7 规则语法、DNS 白名单与学习行为、内置私网 CIDR 拒绝均已由[出站网络策略](../../../guide/network-policy.md)与[安全代理](../../../guide/security-proxy.md)规定；上述文档以引用方式并入本规格。本规格将其包装进统一策略对象，并定义合并、默认值与兼容性契约。

## 2. 对象模型

```yaml
policy:
  network:
    allowInternetAccess: bool          # 默认: true
    allowOut:      [string]            # IP / CIDR / 域名 / 前缀 "*." 通配域名
    denyOut:       [string]            # 仅 IPv4 / IPv4 CIDR
    rules:         [EgressRule]        # L7 规则，首匹配生效（既有语法）
    ingress:
      allowPublicTraffic: bool         # 默认: true
      maskRequestHost:   string        # Host 权威模板，"${PORT}" 展开
```

## 3. 字段规格

| 字段 | 类型 | 约束 | 默认值 | 语义 |
| --- | --- | --- | --- | --- |
| `allowInternetAccess` | `bool?` | — | `true` | 为 `false` 时安装 deny-all 出站兜底，仅显式 allow 条目与 L7 目标可打通。 |
| `allowOut` | `[string]?` | 每项：IPv4、IPv4 CIDR、合法 DNS 名称、前导 `*.` 通配 DNS 名称。非法条目**必须**导致校验失败。 | `[]` | 显式允许的出站目标。域名条目参与 DNS 学习。 |
| `denyOut` | `[string]?` | 每项：IPv4 或 IPv4 CIDR。域名**必须**以 `400 INVALID_POLICY` 拒绝。 | `[]` | 显式拒绝的出站目的地。 |
| `rules` | `[EgressRule]?` | 遵循既有 L7 规则语法：`name`、`match.{scheme,sni,host,method,path}`、`action.{allow,audit,inject}`。 | `[]` | L7 HTTP/HTTPS 规则，首匹配生效。 |
| `ingress.allowPublicTraffic` | `bool?` | — | `true` | 为 `false` 时，公开入站访问需要携带有效的 traffic-access token。 |
| `ingress.maskRequestHost` | `string?` | Host 权威模板；`${PORT}` 展开为所请求的沙箱端口。 | 未设置 | 改写转发给沙箱服务的 Host 权威。仅作用于入站。 |

## 4. 求值语义

以引用方式并入既有出站规格；此处摘要为规范性锚点：

1. **出站判定顺序**对每个连接**必须**为：

   | 步骤 | 检查 | 结果 |
   | --- | --- | --- |
   | 1 | 内置私网 CIDR 拒绝（见下第 2 项） | 拒绝 —— 任何策略来源都不可覆盖 |
   | 2 | **绑定性拒绝（binding deny）**（§4.6）—— 由优先级低于请求的来源贡献的 `denyOut` 条目 | 拒绝 —— **不可**被请求级 `allowOut` 覆盖 |
   | 3 | 命中 `allowOut` | 允许（带 L7 标记的目标其 HTTP/HTTPS 流量进入 L7 求值） |
   | 4 | 命中 `denyOut`（其余的、请求级条目） | 拒绝 |
   | 5 | 其他 | 允许 —— 除非 `allowInternetAccess: false` 已安装 deny-all 兜底 |

2. **内置拒绝。** 除非 `allowInternetAccess: false` 已安装 deny-all，沙箱私网与宿主内部 CIDR（`10.0.0.0/8`、`127.0.0.0/8`、`169.254.0.0/16`、`172.16.0.0/12`、`192.168.0.0/16`）**必须**保持拒绝，且不受用户策略影响。用户策略**不得**能够放行这些网段。
3. **域名语义。** 域名 allow 条目通过 DNS A 记录学习实现，产生按 TTL 过期的临时 allow 条目；此行为是规范性的且保持不变。
4. **条目上限。** 每沙箱最终唯一条目数**不得超过**：allow 表 8192、deny 表 8192、域名规则表 1024。超限使创建请求失败，返回 `400 POLICY_NETWORK_LIMIT`，载荷 `{map, got, max}`。
5. `rules` 在合并后的规则列表上**首匹配生效**。

### 4.6 拒绝来源与绑定性拒绝

allow 先于 deny（第 3 步先于第 4 步）是今天的行为，予以保留 —— 因为模板刻意用「宽泛 `denyOut` + 精确 `allowOut`」打洞的配置依赖它。但这一顺序跨来源应用时，调用方只要在请求里内联一条 `allowOut`，就能放宽管理员设定的边界 —— 这与共享合并原则「高优先级只能收窄、不得放宽」（[overview.md](./overview.md) §5）正相反。来源标记（provenance）封堵该缺口：

1. 每个合并后的 `allowOut` / `denyOut` 条目**必须**保留其**来源**：`template`、`profile` 或 `request`。
2. 来源为 `template` 或 `profile` 的 `denyOut` 条目是**绑定性拒绝**。绑定性拒绝在所有 `allowOut` 条目之前求值，且**不得**被任何来源的 `allowOut` 条目覆盖。
3. 同一来源内部，allow 先于 deny 依然成立：`allowOut` 条目可以在**同一来源**贡献的 `denyOut` 条目上打洞。
4. 被绑定性拒绝完全遮蔽的请求级 `allowOut` 条目**不得**导致创建请求失败。它**必须**在创建响应中以 `policyWarnings` 条目 `{field: "policy.network.allowOut", entry, shadowedBy, source}` 呈现，并**必须**发出审计事件，使调用方得知其申请的洞并未打开（原则 4：拒绝必须可解释）。
5. 来源标记**必须**在策略 API 暴露的生效策略中保留，使运维方能看出每个条目由哪个来源贡献。

## 5. 合并语义

在 [overview.md](./overview.md) §5 的共享规则之上：

| 字段 | 合并细化 |
| --- | --- |
| `allowInternetAccess` | 请求显式值覆盖模板/策略档；缺省保持低优先级值。当低优先级来源已设为 `false` 时，请求**不得**设为 `true` —— deny-all 兜底只能收紧、不能解除（以 `400 POLICY_NETWORK_CONFLICT` 拒绝）。 |
| `allowOut`、`denyOut` | 高优先级条目追加在低优先级条目之后，按规范化条目去重。每个条目保留其来源标记（§4.6）；去重时**必须**为重复条目保留**最低**优先级的来源标记，使拒绝保持绑定性。 |
| `rules` | 高优先级规则排在低优先级规则之前。同名规则**不**合并也不替换；两条都保留、请求侧在前，由首匹配决定实际结果。 |
| `ingress.*` | 标量语义；显式值覆盖。 |

## 6. 默认值

缺省 `policy.network` 解析为服务端默认值：

```yaml
network:
  allowInternetAccess: true
  allowOut: []
  denyOut: []            # 加内置私网 CIDR 拒绝
  rules: []
  ingress:
    allowPublicTraffic: true
```

这与今天不携带网络字段的请求行为逐字节一致。

## 7. 错误

| 错误码 | HTTP | 载荷 | 时机 |
| --- | --- | --- | --- |
| `INVALID_POLICY` | 400 | `{field, reason}` | 条目格式错误（如 `denyOut` 中出现域名、非法 CIDR）。 |
| `POLICY_NETWORK_LIMIT` | 400 | `{map, got, max}` | 最终唯一条目数超过表上限。 |
| `POLICY_NETWORK_CONFLICT` | 400 | `{field, legacyField}` | 遗留字段与 `policy.network` 同时出现（§8）。 |

运行时的出站拒绝**不是** API 错误；与今天一致，它以连接失败的形式呈现给沙箱（被拒 TCP 返回 `ECONNREFUSED` 类 RST，其余丢弃）。

非致命发现以 `policyWarnings` 数组随创建/更新响应返回。警告绝不改变请求的结果；它只说明所提交策略的某一部分不生效。已定义的警告：被绑定性拒绝遮蔽的 `allowOut` 条目（§4.6.4）。

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

## 10. 开放问题

1. `ingress` 是否应在 v1 之后扩展（如源 CIDR 白名单、按端口的入站规则），还是 v1 保持最小面？
2. 域名 `denyOut`：今天按设计拒绝。未来是否应规范一种 DNS sinkhole 式拒绝（阻断指定域名的解析）？
3. IPv6/AAAA 在允许/拒绝与学习中的支持 —— v1 不在范围内；待确认。

## 11. 非规范性说明

- 既有数据路径（eBPF L3/L4 强制 + L7 代理处理带标记的 HTTP/HTTPS）已满足总览原则 5 对本模块的要求；本规格不要求改变强制执行点。
- **§4.6 的被否决方案：** 无条件地让 `denyOut` 先于 `allowOut` 求值（全局 deny-first 模型）。它是更常见的安全模型，但会改变每一份「在宽泛 deny 上用 allow 打洞」的既有配置的含义，与 §9.1 与 §6 的兼容性承诺相冲突。绑定性拒绝在跨来源方向达成同等的防提权效果，同时让单来源语义逐字节保持不变。
