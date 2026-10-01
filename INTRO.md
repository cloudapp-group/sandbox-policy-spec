# Sandbox Security Policy at a glance

[English](INTRO.md) | [中文](INTRO.zh-CN.md)

> A one-page introduction to Proposal 0001. The full specification lives in [`specs/0001-sandbox-security-policy/en/`](./specs/0001-sandbox-security-policy/en/overview.md), which is the normative text.

**What it is.** Every cloud instance ships with a security group — a declarative, reusable, default-on statement of *who this machine may talk to*. This proposal defines the equivalent for sandboxes, `SandboxPolicy`, but extends the boundary from network reachability to the full execution surface.

**Why it is needed.** A sandbox runs agent-generated, partially trusted code, so its blast radius is not only data exfiltration but credential theft, privilege escalation, runaway loops, and token burn. And a command allowlist does not contain an interpreter it already admitted — the boundary that matters sits *below* the control interface.

**Six modules.** `network` (egress/ingress, stateful), `filesystem` (path-level read/write/execute rules), `exec` (a control-interface gate), `process` (privilege, persistence, syscalls), `identity` (identity naming, which credentials reach the sandbox, and in what form), `resource` (rate ceilings, windowed token budgets, token accounting).


## A few examples

Every policy below validates against the JSON Schema in this repository.

**A build sandbox that reaches out but is never reached** — it can fetch dependencies, cannot be dialled in from the internet, and writes only under `/workspace`:

```yaml
policy:
  tier: restricted            # deny-all both directions, private network unreachable
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

**A credential the code can never read** — `proxy` exposure keeps the secret out of the sandbox entirely; the platform attaches it on the way out to `api.openai.com`. Exceeding the token budget holds the sandbox for a human decision:

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
      tokens:
        total: { windows: { day: 1000000 }, onExceeded: hold }
```

**Zero capabilities, non-root, one open port** — nothing starts as root or holds any capability, and egress opens only 5432/tcp to the database:

```yaml
policy:
  tier: restricted
  process:
    runAsNonRoot: true
    allowedCapabilities: ["none"]   # the empty set — the strongest form
  network:
    egress:
      rules:
        - name: db
          priority: 100
          action: allow
          l4: { protocol: tcp, ports: ["5432"], peer: { cidrs: ["10.20.0.5"] } }
```

**The limits are stated too.** Behavioural detection is out of scope for every module here; where a rule cannot be enforced, the spec says so instead of passing off an approximation as enforcement.


## Production evidence

The threats this proposal names are not hypothetical. DeepSeek's DSec platform — serving ~3 million sandboxes per day, ~380 000 concurrent, at 5 000+ creations/second across a 160-node unit — documents the same attack surface in production (Huang et al., *DSec: A Sandbox Infrastructure for Effective Agentic Training at Scale*, arXiv 2609.22978, Sep 2026):

| Observed agent behaviour | Module that answers it |
| --- | --- |
| Forging RPC messages to internal sockets; inspecting execution logs for leaked answers | `filesystem` (denyPaths), `process` (socket access via AppArmor) |
| Overwriting `/bin/bash` to bypass checks or inject commands | `filesystem` (readOnlyPaths on system binaries) |
| Using `XFS_IOC_SWAPEXT` ioctl to exchange protected file extents — corrupting XFS metadata and crashing the filesystem | `process` (syscall baseline) |
| Recursive `grep` from `/` traversing `/proc/kpagecgroup`, triggering a kernel crash | `filesystem` (denyPaths on `/proc`), `process` (syscall denylist) |
| Scanning ports and services to discover reachable mirrors | `network` (egress deny-default, L4 rules) |
| Using Go module proxies to retrieve GitHub-hosted code outside the intended sources | `network` (per-domain allowlist, dynamic eBPF enforcement) |
| Running `yes` until its captured stdout filled tens of GB of storage | `resource` (disk write rate ceiling) |

DSec's mitigations — per-sandbox eBPF network filtering by IP/port/protocol, AppArmor profiles for file and socket access control, dynamic policy updates as tasks move between stages — are exactly the enforcement mechanisms this spec's §12 substrate notes describe. The scale validates that declarative, per-sandbox policy is not an academic exercise but a production necessity.
