# Sandbox Security Policy 速览

[English](INTRO.md) | [中文](INTRO.zh-CN.md)

> 提案 0001 的一页介绍。完整规范见 [`specs/0001-sandbox-security-policy/zh/`](./specs/0001-sandbox-security-policy/zh/overview.md)，英文版为事实源。

**它是什么。** 云上每台 ECS 都带安全组 —— 一份声明式、可复用、默认启用的「这台机器能与谁通信」。本提案为沙箱定义对等物 `SandboxPolicy`，但把边界从网络扩展到完整执行面。

**为什么需要。** 沙箱跑的是 Agent 生成的、部分可信的代码，爆炸半径不止数据外泄，还有凭据窃取、提权、失控循环与 Token 烧钱。而命令白名单挡不住一个已被放行的解释器 —— 真正的边界在控制接口之下。

**六个模块。** `network`（出站/入站，有状态跟踪）、`filesystem`（路径级读/写/执行规则）、`exec`（控制接口门禁）、`process`（提权、持久化、系统调用）、`identity`（凭据以何种形式抵达沙箱）、`resource`（配额、窗口限额、Token 计量）。


## 几个例子

以下策略均通过仓库内的 JSON Schema 校验。

**只出不进的构建沙箱** —— 能拉依赖，但绝不可被公网拨入，写入只落在 `/workspace`：

```yaml
policy:
  tier: restricted            # 双向全拒，内网不可达
  network:
    egress:
      rules:
        - name: pypi
          priority: 100
          action: allow
          l4: { peer: { domains: ["*.pypi.org", "github.com"] } }
  filesystem:
    writableRoots: ["/workspace"]
```

**代理注入凭据、代码读不到** —— `proxy` 模式让密钥永不进入沙箱，只由平台在出站到 `api.openai.com` 时附加；Token 超预算则挂起等人工审批：

```yaml
policy:
  tier: restricted
  identity:
    secrets:
      - name: openai
        secretRef: vault://openai-key
        exposure: proxy
        destinations: ["api.openai.com"]
  resource:
    limits:
      llmTokens: { total: { day: 1000000, onExceeded: hold } }
```

**零能力、非 root、端口限定** —— 进程不以 root 起、不持任何 capability，出站只放行数据库的 5432/tcp：

```yaml
policy:
  tier: restricted
  process:
    runAsNonRoot: true
    allowedCapabilities: ["none"]   # 空集，最强加固
  network:
    egress:
      rules:
        - name: db
          priority: 100
          action: allow
          l4: { protocol: tcp, ports: ["5432"], peer: { cidrs: ["10.20.0.5"] } }
```

**边界也写清楚。** 行为检测不在范围内；无法强制之处明说，不用近似冒充。
