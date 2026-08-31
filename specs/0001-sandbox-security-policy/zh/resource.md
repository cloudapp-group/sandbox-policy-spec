# 规格：资源策略（Resource Policy）

[提案 0001 — 沙箱安全策略](./overview.md) 的组成部分。本文档中的关键词 **必须（MUST）**、**不得（MUST NOT）**、**应该（SHOULD）**、**可以（MAY）** 依据 RFC 2119 解释。

---

## 1. 范围

本规格定义 `SandboxPolicy` 对象的资源（`resource`）子策略。模块之所以命名为 **resource**，是因为它治理的正是"资源"：沙箱可以消耗什么。它包含三份契约：

- **配额（quota）** — 稳态*速率*：沙箱在任意时刻*可以*用多少（CPU、内存）。
- **限额（limits）** — 按窗口的*总量*：沙箱在每个 `minute`、`hour`、`day`、`week`、`month` 窗口内，或整个 `lifetime`（生命周期）内，总共可以消耗多少（CPU 秒数、出站字节、磁盘写入字节、LLM Token）。
- **治理（governance）** — 超限后会发生什么：警告、暂停、终止，或 **hold（挂起等待人工介入）**，以及让人及时知晓的通知（notification）机制。

速率节流与失控 Agent 防御都是"总量"问题，只是时间常数不同 —— 这正是限额按窗口配置、而非单一生命周期数字的原因。

不在范围内：计费与定价（本规格的用量暴露是计费可依赖的契约）；空闲超时与生命周期（既有行为不变 —— 但对处于 held 状态的沙箱仍然适用，见 §7）。

## 2. 对象模型

```yaml
policy:
  resource:
    quota:
      cpuMillicores:   int                  # 稳态 CPU 配额
      memoryMiB:       int                  # 稳态内存配额
    limits:
      cpuSeconds:                          # vCPU 秒数
        windows:  {minute?, hour?, day?, week?, month?, lifetime?}
        onExceeded?: action                # 可选，覆盖默认动作
      netEgressBytes:                      # 出站字节
        windows:  {minute?, hour?, day?, week?, month?, lifetime?}
        onExceeded?: action
      diskWriteBytes:                      # 写入块设备的字节
        windows:  {minute?, hour?, day?, week?, month?, lifetime?}
        onExceeded?: action
      llmTokens:
        input:                             # prompt Token
          windows:  {minute?, hour?, day?, week?, month?, lifetime?}
          onExceeded?: action
        output:                            # completion Token
          windows:  {minute?, hour?, day?, week?, month?, lifetime?}
          onExceeded?: action
        total:                             # 输入 + 输出
          windows:  {minute?, hour?, day?, week?, month?, lifetime?}
          onExceeded?: action
    onExceeded:        warn | pause | hold | kill    # 资源级默认动作
    notifications:
      thresholds:      [number]            # 各限额的阈值分数；默认 [0.8, 1.0]
      webhook:         URL                 # 可选的投递端点
```

维度：`cpuSeconds`、`netEgressBytes`、`diskWriteBytes`、`llmTokens.{input,output,total}`。三个 Token 维度相互独立：每个被设置的维度在自己的计数器上独立生效。

## 3. 字段规格

| 字段 | 类型 | 约束 | 默认值 | 语义 |
| --- | --- | --- | --- | --- |
| `quota.cpuMillicores` | `int?` | ≥ 0 | 模板值 | 稳态 CPU 配额（millicores）。 |
| `quota.memoryMiB` | `int?` | ≥ 0 | 模板值 | 稳态内存配额（MiB）。 |
| `limits.<维度>.windows` | `map?` | 键取自 `{minute, hour, day, week, month, lifetime}`；值 > 0。可同时设置多个窗口，各自独立生效。 | 未设置（不限） | 该维度每窗口的最大消耗量（§4）。 |
| `limits.<维度>.onExceeded` | `enum?` | `warn` \| `pause` \| `hold` \| `kill` | 资源级默认 | 该维度任一窗口超限时的动作。 |
| `onExceeded` | `enum?` | 同上 | `hold` | 资源级默认动作。 |
| `notifications.thresholds` | `[number]?` | 每项 ∈ (0, 1]。升序排列。 | `[0.8, 1.0]` | 触发通知的限额阈值分数。 |
| `notifications.webhook` | `string?` | `https` URL | 未设置 | 接收通知事件的端点（§8）。 |

零/负限额、空 `windows` 映射、(0, 1] 之外的阈值**必须**以 `400 INVALID_POLICY` 拒绝。

`lifetime` 是永不重置的窗口：针对沙箱整个存在期的限额。五个周期性窗口在其边界处重置（§4.1）。

## 4. 窗口语义

### 4.1 窗口定义与对齐

所有窗口均为固定窗口，按 UTC 对齐：

| 窗口 | 周期 | 重置时刻 |
| --- | --- | --- |
| `minute` | 60 秒 | 每个 UTC 分钟的整分 |
| `hour` | 3600 秒 | 每个 UTC 整点 |
| `day` | 24 小时 | 每天 UTC 00:00 |
| `week` | 7 天 | 每周一 UTC 00:00（ISO-8601） |
| `month` | 自然月 | 每个 UTC 月 1 日 00:00 |
| `lifetime` | — | 永不重置 |

### 4.2 计数器

1. 每个二元组（沙箱, 维度）持有一条只追加的用量流；某窗口的计数器 = 当前窗口周期内用量之和；`lifetime` 计数器 = 自沙箱创建以来的总量。
2. 窗口计数器在其窗口内**必须**单调不减，并在翻转（rollover）时归零；lifetime 计数器**必须**单调不减。
3. 计数器跨 pause/resume 持久；恢复永不清零用量。
4. 快照恢复 / 克隆：恢复出的沙箱继承来源的**策略**（限额、动作、通知）；全部计数器（含 lifetime）从恢复点起从零开始。（运维方是否可选择继承计数器，见开放问题 §13。）

### 4.3 强制执行

1. 每个被配置的窗口独立生效：任一窗口计数器首次达到其限额时，触发该维度的动作（§6）。
2. 同一维度的多个窗口共享该维度的 `onExceeded`。
3. 若多个维度/窗口在同一观测点超限，取其中最严重的动作：`kill` > `hold` > `pause` > `warn`。
4. 检查**应该**既周期性进行、也在每个计量边界即时进行，使分钟级限额及时起效。检查间隔内的超调**必须**被吸收：动作在首次观测到达到或超过限额时触发，上报用量**可以**超出限额最多一个观测粒度。
5. 周期性超限随窗口翻转自动重整（re-arm）：某维度在 10:07:30 耗尽其 `minute` 窗口、10:08:00 进入新窗口后可再次消耗；新窗口内再次超限是一个新的跃迁，产生自己的事件。

## 5. 计量语义

### 5.1 维度来源

| 维度 | 计量对象 |
| --- | --- |
| `cpuSeconds` | 沙箱全部进程消耗的 vCPU 时间。 |
| `netEgressBytes` | 离开沙箱网络接口的出站字节。 |
| `diskWriteBytes` | 写入沙箱可写块设备的字节。 |
| `llmTokens.*` | 按 §5.2 计量的 LLM API Token。 |

### 5.2 LLM Token 真值来源

显式优先级（Token 用量只能从 API 事务本身得知）：

1. **响应侧计量（首选）。** 当沙箱对 LLM API 的请求流经平台出站 HTTP/HTTPS 路径时，该请求响应中的 `usage` 字段即该次请求 Token 数的权威来源。
2. **显式上报（兜底）。** SDK 提供 `sandbox.report_usage()`，供调用方上报响应侧计量观测不到的用量（非 HTTP 供应商、不返回 `usage` 的供应商）。它**必须**以被授权管理该沙箱的主体身份认证，条件与审批 API（§7.4）相同 —— 沙箱内的不可信代码**不得**能够写自己的计数器。

### 5.3 流式、重试与部分消耗

实践中大部分 Token 开销是通过流式响应产生的，而流可能被重试或被中途切断。把这些情形留给实现，等于保证日后必有一场计费争议，所以口径在此写死。

| 情形 | 规则 |
| --- | --- |
| 非流式响应 | 响应的 `usage` 是权威；完成时计量一次。 |
| 正常完成的流式响应 | 流终止时计量；**末尾 chunk** 的 `usage` 载荷是权威。 |
| 终止时**没有** `usage` 载荷的流式响应 —— 客户端中断、沙箱超时、传输错误、供应商省略 | 用量仍**必须**被计量，依据从链路上实际观测到的内容推导出的**估算值**。计量**不得**被跳过：跳过会让「在末尾 chunk 之前中断」成为一种免费 Token 的绕过手段。 |
| 重试，无论是沙箱重试还是平台重试 | 每一次向供应商的尝试**独立**计量，因为供应商是按尝试计费的。 |
| 未产生任何 Token 的尝试 —— 连接失败，或在任何内容之前就返回 HTTP 错误 | 计量为零。 |
| 请求进行中沙箱被 kill 或 pause | 按上述规则计量。结束沙箱不会抹掉已经发生的消耗。 |

1. 估算值**必须**是实际用量的**下界**：它只计已观测到的部分，绝不追加投机性的加成。这使 §5.4 的修正保持为可加的，也使平台不会为自己的不确定性向用户多收费。
2. 平台内部发起的重试**必须**归属到引发它的沙箱。
3. 这些规则约束的是*计量*。某笔已计量的量是否*可计费*属于定价问题，不在范围内（§1）。

### 5.4 来源标记与修正

1. 每一笔计量量都带一个 `provenance` 标记：`response`（权威 `usage` 载荷）、`estimated`（§5.3）或 `reported`（§5.2.2）。
2. 来源标记**必须**通过用量接口暴露（§9），使平台能够对估算量与权威量分别计费、告警或对账。
3. 若某次请求的权威 `usage` 载荷在估算值已被计量之后才到达，差值**必须**以额外的**正**增量方式施加。**不得**施加负向修正，因为窗口与生命周期计数器是非递减的（§4.2.2）—— 正是 §5.3 第 1 条的下界要求，让这一点是自洽的而非仅仅方便。
4. 计数器**不得**被沙箱内的不可信代码自增。

## 6. 超限动作

| 动作 | 语义 |
| --- | --- |
| `warn` | 仅发出超限事件。用于可观测性试点，不是防护。 |
| `pause` | 暂停沙箱。当所有触发窗口均已翻转后，沙箱变为可恢复，且**应该**在此时自动恢复；策略更新调高限额同样可解除。分钟/小时窗口因此表现为节流阀，月/生命周期窗口表现为熔断器。 |
| `hold` | 暂停沙箱并等待人工决策（§7）。**不**随窗口翻转自动解除。 |
| `kill` | 立即终止；终态记录维度与窗口作为原因。 |

动作解析：`limits.<维度>.onExceeded`（若设置），否则资源级 `onExceeded`。

默认动作是 `hold`：配置限额即是选择接受治理，而 hold 是唯一既安全（消耗停止）又可逆（不丢数据）、同时把最终决定权交给人的动作。没有值守流程的部署**应该**显式设置为 `warn` 或 `pause` —— held 沙箱仍受标准空闲超时生命周期约束，无人处置的 hold 不会永久泄漏资源。

## 7. 人工介入（hold）

1. 触发 `hold` 动作时，沙箱进入 **held（待人工处置）** 状态：执行挂起（等效于 pause），并**必须**立即发出 `resource.hold_requested` 通知（不受 `notifications.thresholds` 约束）。
2. held 沙箱不自动解除。解除只能通过审批 API 或策略更新。
3. 审批 API：

   ```
   POST /sandboxes/{sandboxID}/resource/approval
   {
     "dimension":  "llmTokens.total",  // 可选；缺省表示对该沙箱当前全部 hold 做出决定
     "window":     "month",            // 可选；与 dimension 一起缺省 → 该维度的全部 hold
     "decision":   "approve" | "deny",
     "grant":      1000000,            // 仅 approve，可选：为当前窗口周期追加的额度
     "raiseLimit": 60000000            // 仅 approve，可选：对该沙箱持久提升限额
   }
   ```

   - `approve` 恢复沙箱。`grant` 仅增加当前窗口周期的额度（翻转时失效）；`raiseLimit` 持久更新该沙箱的生效限额。
   - 对 `lifetime` 窗口，grant 永不失效（lifetime 无翻转）：等价于对该沙箱剩余存在期的永久追加。
   - `deny` 终止沙箱。
4. 授权：审批**必须**经由控制面 API、由被授权管理该沙箱的已认证主体（属主/运维）执行。审批 API **不得**可在沙箱内部调用，也**不得**接受沙箱作用域凭据 —— 不可信的 Agent 代码必须无法批准自己的 hold。
5. 每次审批**必须**审计：审批人身份、目标、决定，以及任何 grant/raise。
6. held 沙箱仍适用标准空闲超时生命周期（空闲即 kill/pause），被遗弃的 hold 最终会被回收。

## 8. 通知

1. **阈值通知。** 任一（维度, 窗口）计数器越过其限额的某个已配置阈值分数时，**必须**发出 `resource.notification` 事件，且每个阈值每窗口周期至多一次：`{sandboxID, dimension, window, used, limit, threshold, at}`。
2. **超限事件。** 每次超限跃迁**必须**发出 `resource.exhausted`：`{sandboxID, dimension, window, used, limit, action}`。
3. **hold 事件。** 每次 hold 发出 `resource.hold_requested`（§7）；`resource.approved` / `resource.denied` 记录决定与审批人。
4. **投递。** 配置了 `notifications.webhook` 时，事件**必须**以 HTTPS POST + 上述 JSON 载荷投递，至少一次（at-least-once），重试有界。webhook 认证/签名为开放问题（§13）。无论 webhook 是否配置，事件都**必须**可从平台事件流获取。
5. 通知载荷**不得**包含计数器之外的沙箱数据。

## 9. 用量暴露

1. `GET /sandboxes/{sandboxID}` **必须**包含 `resource` 对象：

   ```json
   "resource": {
     "quota": {"cpuMillicores": 2000, "memoryMiB": 2048},
     "usage": {
       "cpuSeconds": {
         "current": {"minute": 12.3, "hour": 300.5, "lifetime": 12345.6},
         "limits":  {"hour": 600, "lifetime": 100000}
       },
       "llmTokens": {
         "total": {
           "current": {"minute": 3500, "day": 155000, "lifetime": 1200000},
           "limits":  {"minute": 10000, "day": 1000000, "month": 50000000},
           "provenance": {"response": 1150000, "estimated": 40000, "reported": 10000}
         }
       }
     },
     "state": {"held": false, "exhausted": []}
   }
   ```

2. `limits` 报告生效的已配置窗口；`current` 报告已配置窗口的窗口内计数器。即使未配置 lifetime 限额，lifetime 计数器也**必须**上报（计费需要它）。
3. 对 `llmTokens` 各维度，`provenance` 报告这些量是如何得知的生命周期分解（§5.4）。三个值**必须**加总等于 lifetime 计数器，使租户能看清一份账单中有多少建立在估算之上。
4. `state.exhausted` 列出当前已超限的（维度, 窗口）对；`state.held` 在 hold 待决期间为 true。
5. SDK 以 `sandbox.resource` 暴露同一对象。

## 10. 合并语义

在 [overview.md](./overview.md) §5 的基础上：

| 字段 | 合并细化 |
| --- | --- |
| `quota.*` | 显式值覆盖；缺省保持模板值。 |
| `limits.*.windows` | 按（维度, 窗口）：被设置值中的最小值胜出；无任何来源设置的维度为不限。高优先级来源不能*移除*低优先级来源设置的限额。 |
| `onExceeded`（默认与按维度） | 最严重者胜：`kill` > `hold` > `pause` > `warn`。 |
| `notifications.thresholds` | 各来源取并集，去重并升序排列。 |
| `notifications.webhook` | 各来源取并集（可加性观测）。 |

## 11. 错误

| 错误码 | 呈现面 | 载荷 | 时机 |
| --- | --- | --- | --- |
| `INVALID_POLICY` | 400 | `{field, reason}` | 非正限额、非法窗口键、(0, 1] 之外的阈值。 |
| `POLICY_RESOURCE_EXHAUSTED` | 终态 / 事件 | `{dimension, window, used, limit, action}` | 动作为 `kill`（或审批 `deny`）的超限。 |
| `POLICY_RESOURCE_HELD` | 沙箱状态 / 事件 | `{dimension, window, used, limit}` | 沙箱处于待审批的 held 状态。 |
| 审批错误 | 400 / 409 | `{reason}` | 审批目标不匹配任何当前 hold，或 grant/raise 非法。 |

## 12. 验收标准

1. 多窗口执行：`llmTokens.total` 同时配置 `minute` 限额（动作 `pause`）与 `month` 限额（动作 `hold`）时，超过分钟限额的突发会暂停沙箱，分钟翻转后可恢复（并自动恢复）；越过月限额则 hold 等待审批。
2. 翻转重整：minute 窗口重置后，在新限额内继续消耗不产生事件，直到新的阈值/超限跃迁。
3. hold 必须有人：held 沙箱不随窗口翻转恢复；`approve`（无论是否带 grant/raise）恢复之；`deny` 终止之；额度为 N 的 grant 在当前周期内至多再放行 N 个单位。
4. 审批 API 拒绝以沙箱作用域凭据发起的调用。
5. 阈值通知每阈值每窗口周期至多触发一次；超限与 hold 事件在每次跃迁时触发。
6. lifetime 计数器单调，且即使无 lifetime 限额也上报。
7. 同时超限解析为最严重动作。
8. 恢复/克隆：策略继承，全部计数器清零。
9. 合并后的每窗口限额取最小值；合并后的动作取最严重者。
10. **流式。** 正常完成的流以 `provenance: response` 计量其末尾 chunk 的 `usage`。同一个流若在末尾 chunk 之前被中断，仍以 `provenance: estimated` 计量出一个非零量，且该量不大于完整流所计量的量。
11. **重试。** 三次都返回 `usage` 的供应商尝试计量三次；在任何内容之前就失败的尝试计量为零。平台发起的重试归属到发起方沙箱。
12. **迟到修正。** 估算之后到达的权威 `usage` 只施加正增量；任何计数器都不曾下降。
13. **来源标记暴露。** `response` / `estimated` / `reported` 的分解被上报，且加总等于 lifetime 计数器。
14. 以沙箱作用域凭据调用 `report_usage` 被拒绝。

## 13. 开放问题

1. **时区。** 窗口按 UTC 对齐。部署方是否可将 `day`/`week`/`month` 对齐到本地时区？
2. **滑动窗口。** 固定窗口简单，但边界处允许 2× 突发（一个窗口末尾与下一个窗口开头各满额）。是否需要滑动窗口，还是 v1 接受该特性？
3. **自动恢复。** `pause` 是否应在翻转时自动恢复（本文提出 SHOULD），还是要求显式恢复？
4. **webhook 认证。** HMAC 签名方案？共享密钥存放于何处？
5. **审批 RBAC。** 哪些主体可以审批：仅沙箱属主、命名空间运维，还是任何集群管理员？
6. **grant 可见性。** grant 是否应体现在 `resource.usage`（如 `allowance` 字段），便于平台对批准的超额计费？
7. **按窗口的动作。** `onExceeded` 是否应支持按窗口设置而非按维度（如同一维度 `minute`→`pause`、`month`→`hold`）？
8. **恢复/克隆时的计数器继承。** 本文默认清零；继承是否应作为运维选项？
9. **估算方法。** §5.3 固定了估算值的*性质*（下界、由已观测内容推导）而非算法。算法及其预期误差是否应当公开，使租户能审计自己用量中被估算的那一部分？
10. **缓存 Token 与推理 Token。** 供应商越来越多地把缓存读取与推理 Token 单独计量。它们是应成为各自独立的维度，还是折入 `input` / `output`？

## 14. 非规范性说明

- 全部维度在沙箱自身的内核记账（CPU 时间、块 I/O、接口统计）或出站 HTTP 路径（LLM `usage` 字段）中都有天然来源；窗口计数器由这些用量流推导。本规格只固定上述语义。
