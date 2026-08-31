# Sandbox Security Policy Specification

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[English](README.md) | [中文](README.zh-CN.md)

This repository contains **Proposal 0001: Sandbox Security Policy** — a declarative, reusable, and safe-by-default policy framework for sandbox execution environments.

A sandbox is not just a network endpoint. It runs partially trusted, agent-generated code, so its capability boundary must cover **network, filesystem, execution, and resource** consumption in a single, unified object.

---

## What is this?

This proposal defines the `SandboxPolicy` object: the equivalent of a cloud security group, but extended to the full execution surface of a sandbox.

| Module | Covers |
| --- | --- |
| **Network** | Egress allow/deny at L3/L4/L7, ingress gating, DNS learning, public traffic controls |
| **Filesystem** | Host-mount boundaries and in-sandbox path access policy (`denyPaths`, `readOnlyPaths`, `writableRoots`) |
| **Exec** | Command allowlist/denylist, user restriction, timeout ceiling, concurrency limits, audit |
| **Resource** | CPU/memory quotas, windowed limits (minute–month + lifetime), LLM token accounting, exceed actions |

The specification is organized as a five-document set under `specs/0001-sandbox-security-policy/`.

---

## Motivation

Every cloud ECS instance ships with a security group: a declarative, reusable definition of *what the machine may talk to*. It works because it is:

- **Declarative** — users state intent, not mechanism.
- **Default-on** — every instance gets one, with a sane baseline.
- **Reusable** — one group binds many instances; changes propagate.
- **Uniform** — one grammar, one evaluation order, one audit story.

Sandboxes need exactly these properties — extended to the execution domain. Unlike an ECS instance, a sandbox runs **agent-generated, partially trusted code**. Its blast radius is broader: data exfiltration, credential theft, host-mount abuse, runaway loops, and LLM token burn.

| ECS Instance | Sandbox |
| --- | --- |
| Runs human-authored, trusted workloads | Runs agent-generated, partially trusted code |
| Boundary = network reachability | Boundary = network **+ filesystem + exec + resource** |
| Blast radius: data exfiltration | Blast radius: exfiltration **+ credential theft, host-mount abuse, runaway loops, token burn** |

### The gap today

The four capability domains are at very different levels of maturity:

| Module | What exists today | Gap |
| --- | --- | --- |
| **Network** | Egress allow/deny, domain allow-listing, L7 rules, ingress gating | Fields are scattered; no reusable policy object; no unified merge semantics |
| **Filesystem** | Host-mount prefix allowlist and `readOnly` per mount | No protection for sensitive in-sandbox paths; no path-level read-only/deny policy |
| **Exec** | Per-request `timeout`, `user`, `cwd` | No sandbox-level command policy, user restriction, concurrency cap, or audit |
| **Resource** | Steady-state CPU/memory quotas; idle timeout | No windowed limits, lifetime budgets, LLM token metering, or exceed actions |

Without a single policy object, every module grows its own config style, merge rules, defaults, and audit format. Users must reason about four half-systems; template authors cannot say "this template's sandboxes are locked down" in one place; and future modules would add a fifth and sixth dialect.

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
├── specs/0001-sandbox-security-policy/
│   ├── overview.md      # Shared model, merge semantics, principles, compatibility
│   ├── network.md       # Network sub-policy
│   ├── filesystem.md    # Filesystem sub-policy
│   ├── exec.md          # Command execution sub-policy
│   └── resource.md      # Resource limits, governance, and LLM token accounting
└── zh/specs/0001-sandbox-security-policy/
    └── ...              # Chinese translations of the specs
```

---

## Contributing

This proposal is in **Draft** status and under community discussion. Contributions are welcome:

1. Open or comment on the tracking issue.
2. Propose changes via pull request; please keep one logical change per PR.
3. Update both the English and Chinese versions when modifying normative text.

When picking up a section, add yourself to the **Authors** field in `overview.md`.

---

## License

This project is licensed under the [Apache License, Version 2.0](LICENSE).
