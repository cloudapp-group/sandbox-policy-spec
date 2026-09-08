# Sandbox Security Policy at a glance

[English](INTRO.md) | [中文](INTRO.zh-CN.md)

> A one-page introduction to Proposal 0001. The full specification lives in [`specs/0001-sandbox-security-policy/en/`](./specs/0001-sandbox-security-policy/en/overview.md), which is the normative text.

**What it is.** Every cloud instance ships with a security group — a declarative, reusable, default-on statement of *who this machine may talk to*. This proposal defines the equivalent for sandboxes, `SandboxPolicy`, but extends the boundary from network reachability to the full execution surface.

**Why it is needed.** A sandbox runs agent-generated, partially trusted code, so its blast radius is not only data exfiltration but credential theft, privilege escalation, runaway loops, and token burn. And a command allowlist does not contain an interpreter it already admitted — the boundary that matters sits *below* the control interface.

**Six modules.** `network` (egress/ingress, stateful), `filesystem` (paths and host mounts), `exec` (a control-interface gate), `process` (privilege, persistence, syscalls), `identity` (which credentials reach the sandbox, and in what form), `resource` (quotas, windowed limits, token accounting).


## A few examples

Every policy below validates against the JSON Schema in this repository.

**A build sandbox that reaches out but is never reached** — it can fetch dependencies, cannot be dialled in from the internet, and writes only under `/workspace`:

```yaml
policy:
  tier: restricted            # deny-all egress, no public ingress
  network:
    allowOut: ["*.pypi.org", "github.com"]
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
      llmTokens: { total: { day: 1000000, onExceeded: hold } }
```

**Zero capabilities, non-root, one open port** — nothing starts as root or holds any capability, and egress opens only 5432/tcp to the database:

```yaml
policy:
  tier: restricted
  process:
    runAsNonRoot: true
    allowedCapabilities: ["none"]   # the empty set — the strongest form
  network:
    portRules:
      - { name: db, target: 10.20.0.5, protocols: [tcp], ports: ["5432"] }
```

**The limits are stated too.** Behavioural detection is out of scope for every module here; where a rule cannot be enforced, the spec says so instead of passing off an approximation as enforcement.
