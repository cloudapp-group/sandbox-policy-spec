# Sandbox Security Policy Specification

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[English](README.md) | [中文](README.zh-CN.md)

This repository contains **Proposal 0001: Sandbox Security Policy** — a declarative, reusable, and safe-by-default policy framework for sandbox execution environments.

A sandbox is not just a network endpoint. It runs partially trusted, agent-generated code, so its capability boundary must cover **network, filesystem, execution, process behavior, and resource** consumption in a single, unified object.

---

## What is this?

This proposal defines the `SandboxPolicy` object: the equivalent of a cloud security group, but extended to the full execution surface of a sandbox.

| Module | Covers |
| --- | --- |
| **Network** | Egress allow/deny at L3/L4/L7, ingress gating, DNS learning, public traffic controls |
| **Filesystem** | Host-mount boundaries and in-sandbox path access policy (`denyPaths`, `readOnlyPaths`, `writableRoots`) |
| **Exec** | Command allowlist/denylist, user restriction, timeout ceiling, concurrency limits, audit |
| **Process** | Privilege gain, persistence, and system-call policy for already-running processes |
| **Resource** | CPU/memory quotas, bandwidth ceiling, windowed limits (minute–month + lifetime), LLM token accounting, exceed actions |

The specification is organized as a six-document set under `specs/0001-sandbox-security-policy/`.

---

## Motivation

Every cloud ECS instance ships with a security group: a declarative, reusable definition of *what the machine may talk to*. It works because it is:

- **Declarative** — users state intent, not mechanism.
- **Default-on** — every instance gets one, with a sane baseline.
- **Reusable** — one group binds many instances; changes propagate.
- **Uniform** — one grammar, one evaluation order, one audit story.

Sandboxes need exactly these properties — extended to the execution domain. Unlike an ECS instance, a sandbox runs **agent-generated, partially trusted code**. Its blast radius is broader: data exfiltration, credential theft, host-mount abuse, privilege escalation, runaway loops, and LLM token burn.

| ECS Instance | Sandbox |
| --- | --- |
| Runs human-authored, trusted workloads | Runs agent-generated, partially trusted code |
| Boundary = network reachability | Boundary = network **+ filesystem + exec + process + resource** |
| Blast radius: data exfiltration | Blast radius: exfiltration **+ credential theft, host-mount abuse, privilege escalation, runaway loops, token burn** |

### The gap today

The five capability domains are at very different levels of maturity:

| Module | What exists today | Gap |
| --- | --- | --- |
| **Network** | Egress allow/deny, domain allow-listing, L7 rules, ingress gating | Fields are scattered; no reusable policy object; no unified merge semantics |
| **Filesystem** | Host-mount prefix allowlist and `readOnly` per mount | No protection for sensitive in-sandbox paths; no path-level read-only/deny policy |
| **Exec** | Per-request `timeout`, `user`, `cwd` | No sandbox-level command policy, user restriction, concurrency cap, or audit |
| **Process** | Nothing user-facing | No policy surface for privilege gain, persistence, or system-call exposure |
| **Resource** | Steady-state CPU/memory quotas; idle timeout | No windowed limits, lifetime budgets, bandwidth ceiling, LLM token metering, or exceed actions |

Without a single policy object, every module grows its own config style, merge rules, defaults, and audit format. Users must reason about five half-systems; template authors cannot say "this template's sandboxes are locked down" in one place; and future modules would add a sixth and seventh dialect.

### Why a unified policy?

A unified `SandboxPolicy` gives the platform:

- **One mental model** — *"the sandbox may do exactly what its policy says."*
- **One merge story** — template default + profile + request override, shared by all modules.
- **One default security baseline** — safe by default, explicit opt-out.
- **One place to audit and observe** — every denial is explainable and structured.

The design is guided by six principles:

1. **Declarative** — state intent, not mechanism.
2. **Absent ≠ unrestricted** — missing fields resolve to documented safe defaults.
3. **Safe by default, explicit opt-out** — baseline protections are on unless positively disabled.
4. **Denials are explainable** — every denial carries the matched rule or exhausted dimension.
5. **Enforcement is mandatory** — every rule is enforced at a point the workload cannot bypass.
6. **One representation downstream** — legacy fields, inline policy, and profile all normalize to the same effective object.

---

## Repository layout

```
.
└── specs/0001-sandbox-security-policy/
    ├── en/
    │   ├── overview.md      # Shared model, merge semantics, principles, tiers, shadow evaluation, grants, compatibility
    │   ├── network.md       # Network sub-policy
    │   ├── filesystem.md    # Filesystem sub-policy
    │   ├── exec.md          # Command execution sub-policy
    │   ├── process.md       # Privilege, persistence, and system-call sub-policy
    │   └── resource.md      # Resource limits, governance, and LLM token accounting
    └── zh/
        ├── overview.md      # 共享模型、合并语义、原则、分级、影子评估、限时授权、兼容性
        ├── network.md       # 网络子策略
        ├── filesystem.md    # 文件系统子策略
        ├── exec.md          # 命令执行子策略
        ├── process.md       # 提权、持久化与系统调用子策略
        └── resource.md      # 资源限制、治理与 LLM Token 计量
```

---

## Language and source of truth

The English documents under `specs/0001-sandbox-security-policy/en/` are **the normative text**. The `zh/` set is a translation, maintained on a best-effort basis and therefore liable to lag behind. Where the two disagree, English wins.

This is a deliberate choice: two independently authoritative copies of a normative document drift, and a drifted normative document is worse than an untranslated one. Readers implementing the spec should work from `en/`; `zh/` exists to lower the cost of reading and reviewing it.

---

## Contributing

This proposal is in **Draft** status and under community discussion. Contributions are welcome:

1. Open or comment on the tracking issue.
2. Propose changes via pull request; please keep one logical change per PR.
3. Normative changes MUST land in `en/`. Updating `zh/` in the same PR is preferred; if you cannot, say so in the PR description so the gap is visible rather than silent.
4. A PR that changes only `zh/` is a translation fix and MUST NOT change meaning. If it does, it belongs in `en/` first.

When picking up a section, add yourself to the **Authors** field in `overview.md`.

---

## License

This project is licensed under the [Apache License, Version 2.0](LICENSE).
