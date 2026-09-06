# Spec: Identity and Secrets Policy

Part of [Proposal 0001 — Sandbox Security Policy](./overview.md). The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as described in RFC 2119.

---

## 1. Scope

This spec defines the identity (`identity`) sub-policy of the `SandboxPolicy` object: **which credentials a sandbox may use, and in what form they reach it**. It governs three things:

- **Workload identity** — what the sandbox *is*, to the platform and to the services it calls.
- **Secret exposure** — whether a credential's value enters the sandbox at all, and if so how.
- **Credential scope and lifetime** — which destinations, methods, and paths a credential is good for, for how long, and how it is revoked.

This module exists because of a gap the rest of the proposal states outright and cannot close. [filesystem.md](./filesystem.md) §2.3 of the defense matrix concedes that path rules cannot protect "secrets already in process memory or passed as env vars" — and environment variables and files are exactly where credentials are today. A sandbox running agent-generated code with `AWS_SECRET_ACCESS_KEY` in its environment has a filesystem policy that denies `~/.aws/credentials` while the same secret sits one `os.environ` away. The deny is not wrong; it is answering a question the attacker is not asking.

The division of labour with the other modules is fixed:

| Question | Module |
| --- | --- |
| May this command be started through the API? | `exec` |
| May this running process run as this user, gain privilege, persist, or issue this syscall? | `process` |
| May it read or write this path? | `filesystem` |
| May it reach this destination? | `network` |
| **May it authenticate as this identity, and can it read the credential?** | `identity` (this spec) |
| May it consume this much? | `resource` |

Note the seam with `network`. `network` decides whether a packet may reach `api.example.com`; `identity` decides whether the sandbox holds a credential for it and whether that credential's bytes are visible to the workload. Both are needed: reaching a service without a credential accomplishes nothing, and holding a credential for an unreachable service accomplishes nothing. Neither implies the other.

Not in scope: the platform's own authentication of API callers, which is a control-plane concern and is bounded by [overview.md](./overview.md) §5.2; secret *storage*, which is a property of whatever vault the deployment runs; and detecting credential misuse after the fact, which is [overview.md](./overview.md) §2.3.1.

## 2. Object model

```yaml
policy:
  identity:
    mode:             managed | unrestricted     # default: managed
    workloadIdentity:
      enabled:        bool                       # default: true under managed
      audience:       [string]                   # required when enabled
      ttlSec:         int                        # default: 900
    defaultExposure:  proxy | file | env | none  # default: proxy
    secrets:          [SecretBinding]
    onViolation:      deny | kill                # default: deny
    audit:            none | metadata            # default: none
```

### 2.1 `SecretBinding`

A binding names one credential and states, in one place, what it is for and how much of it the workload may see.

```yaml
- name:        string        # required, unique within the list; used in errors and audit
  secretRef:   string        # required; opaque reference resolved by the platform
  exposure:    proxy | file | env | none   # default: identity.defaultExposure
  destinations: [string]     # required for exposure: proxy — the allowOut grammar
  methods:     [string]      # optional; subset of HTTP methods
  pathPrefixes: [string]     # optional; request-path prefixes
  ttlSec:      int           # default: 900
  path:        string        # required for exposure: file — absolute in-sandbox path
  envVar:      string        # required for exposure: env — variable name
```

1. `secretRef` is opaque to this spec. It names a credential the platform can resolve; how the platform stores it is out of scope (§1).
2. `name` MUST be unique within `secrets`. Errors and audit events identify a binding by `name`, never by `secretRef`, so that neither surface carries a value that hints at the secret's location.
3. A binding MUST NOT be accepted with fields that its `exposure` does not use — `path` under `exposure: env`, `envVar` under `exposure: file`, `destinations` under `exposure: none`. Accepting them would let an author believe a constraint is in force when the mode ignores it. Reject with `400 INVALID_POLICY` naming the field and the mode.

## 3. Exposure modes

`exposure` is the field this module exists for. It answers one question: **can code in the sandbox read the credential's bytes?**

| Mode | The workload sees | The credential is usable |
| --- | --- | --- |
| `proxy` | Nothing | Yes, for the declared destinations and scope (§4) |
| `file` | The value, at `path` | Yes, wherever the workload sends it |
| `env` | The value, in `envVar` | Yes, wherever the workload sends it |
| `none` | Nothing | No — the binding is declared but inactive |

1. Under `proxy`, the credential value MUST NOT be present anywhere in the sandbox: not in its filesystem, not in its environment, not in its process arguments, and not retrievable through any platform API the workload can reach. The platform attaches the credential to matching outbound requests at an enforcement point outside the sandbox.
2. Under `file` and `env`, the value is inside the sandbox and this module's guarantees end there. A credential the workload can read is a credential the workload can send anywhere `network` permits, log to stdout, or write into a file that a snapshot later carries out ([overview.md](./overview.md) §8.3.2). These modes exist because real workloads use SDKs that read `~/.aws/credentials` or `AWS_ACCESS_KEY_ID`, and a spec that only offered `proxy` would be ignored rather than adopted. They are not equivalent to `proxy`, and §6 makes the platform say so.
3. `none` exists so that a binding can be declared, reviewed, and version-controlled before it is switched on, and so that revoking one is a one-field change that leaves the declaration visible rather than deleting the evidence that it existed.
4. **Exposure is narrow-only in merge** (§8): the ordering is `none` > `proxy` > `file` > `env`. A lower-precedence source that chose `proxy` MUST NOT be widened to `file` or `env` by a higher-precedence one.

### 3.1 What `proxy` requires of the deployment, stated plainly

`proxy` is the mode this module recommends and the mode with real prerequisites. It needs an enforcement point in the egress path that can terminate the connection, match the request against the binding's scope, and attach the credential. That is the same component `network.rules` needs for L7 evaluation and the same one `resource` needs to meter LLM tokens ([resource.md](./resource.md) §14) — one mechanism, three modules.

A deployment without such a component MUST declare `exposure: proxy` `unsupported` ([overview.md](./overview.md) §8.2) rather than fall back to `file`. Silently downgrading the mode that hides the credential to a mode that hands it over is the exact failure §8.2.1 rule 4 forbids: an author who wrote `proxy` and got `env` has a policy whose central promise was inverted without an error.

## 4. Destination binding and scope

A credential under `exposure: proxy` is usable only where the binding says. Without this, `proxy` would merely relocate the secret — the workload could not read it but could still spend it anywhere.

1. `destinations` is REQUIRED for `exposure: proxy` and MUST be non-empty. It uses the `allowOut` target grammar ([network.md](./network.md) §2.1): addresses, CIDRs, DNS names, and leading-`*.` wildcards. An empty or absent `destinations` under `proxy` MUST be rejected with `400 INVALID_POLICY`; a credential attachable to any destination is an unscoped credential wearing a scope's field name.
2. The platform MUST attach the credential **only** to requests whose destination matches, whose method is in `methods` when set, and whose request path begins with an entry of `pathPrefixes` when set. A request that does not match MUST be forwarded **without** the credential rather than rejected — the workload is entitled to make unauthenticated requests, and rejecting them would make this module a second network policy.
3. Destination matching MUST be performed on the **resolved connection target**, not on a request header the workload controls. A `Host` header naming an allowed destination on a connection to another address MUST NOT attach the credential. This is the same requirement [exec.md](./exec.md) §3.2 makes for executable resolution, for the same reason.
4. `destinations` does not widen `network`. A destination permitted here but denied by `network` stays unreachable; the modules intersect. A binding whose destinations are entirely unreachable under the effective network policy MUST be reported as a `policyWarnings` entry `{field: "policy.identity.secrets", name, reason: "destinations_unreachable"}` — an author who believes a credential is in use when nothing can reach its destination should learn it at create time.
5. Where a credential is short-lived and the platform mints it (§5), the minted credential's own audience MUST be constrained to the binding's destinations where the issuing system supports it. Scope enforced at the token is stronger than scope enforced at the proxy, because it survives the proxy being wrong.

## 5. Workload identity and lifetime

1. When `workloadIdentity.enabled` is true, the platform MUST be able to present the sandbox to external services as a distinct, verifiable identity, and that identity MUST be scoped to `audience`. An identity with no audience is a bearer token with extra steps.
2. `audience` is REQUIRED when `enabled` is true. Rejecting an empty audience with `400 INVALID_POLICY` is deliberate: the failure mode of a missing audience is a credential accepted by a service nobody meant to authorize.
3. The identity MUST be bound to the sandbox instance, not to the template, the profile, or the caller. Two sandboxes from one template are two identities, so that revoking one does not revoke the other and an audit trail can attribute a request to a sandbox.
4. `ttlSec` bounds the lifetime of any credential the platform mints or attaches, defaulting to 900 seconds. A deployment-configured maximum applies on the same terms as the grant TTL ceiling ([overview.md](./overview.md) §5.1.2), and a value above it MUST be rejected.
5. **Renewal MUST NOT require the workload's cooperation.** The platform renews on its own schedule while the sandbox is entitled to the credential. A design in which the sandbox refreshes its own credential gives the sandbox a long-lived refresh capability, which is the thing `ttlSec` was meant to remove.
6. **Revocation MUST take effect within the sandbox's lifetime, not at the next restart.** Removing a binding, or revoking through the control plane, MUST stop the credential from being attached to subsequent requests and MUST invalidate any value already inside the sandbox where the issuing system permits it. Where it does not permit it, the effective policy MUST report the residual exposure rather than claim a revocation it cannot deliver.
7. Under `exposure: file` or `env`, rules 5 and 6 are **best-effort by construction** and the platform MUST say so: a value already read into the workload's memory cannot be recalled. This is the concrete cost of those modes, and it belongs in the capability report (§6), not in a footnote.

## 6. Field specification

| Field | Type | Constraints | Default | Semantics |
| --- | --- | --- | --- | --- |
| `mode` | `enum?` | `managed` \| `unrestricted` | `managed` | `managed` applies this module. `unrestricted` disables it entirely and MUST be explicit (principle 3). |
| `workloadIdentity.enabled` | `bool?` | — | `true` under `managed` | §5.1. |
| `workloadIdentity.audience` | `[string]?` | MUST be non-empty when `enabled` is true. | `[]` | §5.2. |
| `workloadIdentity.ttlSec` | `int?` | > 0, ≤ deployment maximum. | `900` | §5.4. |
| `defaultExposure` | `enum?` | `proxy` \| `file` \| `env` \| `none` | `proxy` | Default `exposure` for bindings that omit it. |
| `secrets` | `[SecretBinding]?` | Per §2.1. `name` unique. | `[]` | The declared credentials. |
| `onViolation` | `enum?` | `deny` \| `kill` | `deny` | §7. |
| `audit` | `enum?` | `none` \| `metadata` | `none` | Audit level for **ordinary** credential use (§9). It does not suppress violation events ([overview.md](./overview.md) §8.1.4). |

Under `mode: managed` with `defaultExposure: proxy`, a sandbox with no `secrets` entries holds no credentials at all. That is the intended `restricted`-tier posture ([overview.md](./overview.md) §7): a sandbox authenticates as nothing and carries nothing until a binding says otherwise.

### 6.1 Tier defaults

Which defaults apply is selected by `policy.tier` ([overview.md](./overview.md) §7.1):

| Field | `compatibility` | `baseline` | `restricted` |
| --- | --- | --- | --- |
| `mode` | `unrestricted` | `managed` | `managed` |
| `defaultExposure` | — | `file` | `proxy` |
| `workloadIdentity.enabled` | `false` | `true` | `true` |
| `audit` | `none` | `none` | `metadata` |

`compatibility` resolves to `unrestricted` because today's callers pass credentials as environment variables and files with no policy object at all; applying this module to them would break every one of them at once (§9 of [overview.md](./overview.md)). This is the third and last place in the proposal where a tier is deliberately a no-op, and unlike the other two it is not a no-op at `baseline`.

`baseline` sets `defaultExposure: file` rather than `proxy` for a reason worth stating: `proxy` requires an egress enforcement point (§3.1) that not every deployment has, and a tier that resolved to an `unsupported` field would make `tier: baseline` fail under `enforcement: strict` on those deployments. `file` at least makes the exposure explicit and auditable. `restricted` selects `proxy`, and a deployment that cannot enforce it finds out at create time — which is the correct moment.

### 6.2 Shadow evaluation support

Per [overview.md](./overview.md) §7.2.5, this module supports shadow evaluation under `auditTier` for `mode`, `defaultExposure`, and per-binding `exposure`. A credential that the shadow tier would have hidden is still exposed under the enforced tier, and a `shadow: true` event names the binding and the exposure the stricter tier would have required.

The finding is directly actionable and worth the effort: a shadow report under `auditTier: restricted` is a list of the bindings that would need to move to `proxy`, which is the migration plan for adopting this module. What shadow evaluation cannot tell an operator is whether a workload's SDK *can* work through a proxy — that is a property of the workload, not of the policy, and no amount of observation reveals it.

Shadow evaluation MUST NOT itself expose a credential. Evaluating "what would `proxy` have done" against a binding currently in `env` mode means reporting the difference, not minting a second credential to test it.

## 7. Violation actions

Per [overview.md](./overview.md) §8.1, `onViolation` decides what happens when this module refuses something:

| Action | Result |
| --- | --- |
| `deny` (default) | The request is forwarded without the credential (§4.2), or the operation fails with the module's error (§8). The process keeps running. |
| `kill` | The offending **process** is terminated. |

1. There is no `warn`, on the terms of [overview.md](./overview.md) §8.1.2. An action that detects an attempt to read a `proxy`-mode credential and then permits it has no meaning, because permitting it *is* the exposure.
2. `kill` is the appropriate choice for one case in particular: an attempt by the workload to read a credential that `proxy` mode was supposed to hide. Under `proxy` there is no legitimate reason for the workload to be looking, so the attempt is itself the signal — the same reasoning [filesystem.md](./filesystem.md) §4.5.1 applies to credential paths.
3. Either action emits a violation event, at every audit level (§9).

## 8. Errors

| Code | HTTP | Payload | When |
| --- | --- | --- | --- |
| `INVALID_POLICY` | 400 | `{field, reason}` | Empty `audience` with `enabled: true`; empty `destinations` under `proxy`; a field the mode does not use (§2.1.3); `ttlSec` above the deployment maximum. |
| `POLICY_IDENTITY_SECRET_UNRESOLVABLE` | 400 | `{name}` | `secretRef` names a credential the platform cannot resolve, or that this principal may not use (§5.2 of [overview.md](./overview.md)). Never echoes `secretRef`. |
| `POLICY_IDENTITY_EXPOSURE_DENIED` | OS-level failure or `403`; audit event | `{name, exposure, action}` | The workload attempted to read a credential whose exposure mode hides it (§3.1). |
| `POLICY_IDENTITY_DESTINATION_DENIED` | audit event only | `{name, destination}` | A credential was withheld because the destination did not match (§4.2). The request itself proceeds unauthenticated, so this is not an error to the caller. |
| `POLICY_UNSUPPORTED` | 400 | `{field, state, capabilityVersion}` | Under `enforcement: strict`, the policy uses an exposure mode this deployment declares `unsupported` — most often `proxy` (§3.1). |
| `POLICY_GRANT_INVALID` | 400 | `{field, reason}` | A grant targets a non-grantable field (§10.1). |

No error payload, warning, or audit event in this module MUST EVER contain a credential value, a `secretRef`, or any substring of either. Bindings are identified by `name`. This is stated as a requirement rather than assumed because error payloads are the most-copied text in any system, and a redaction rule that is not written down is a redaction rule that is not implemented.

## 9. Observability

1. Every violation MUST be emitted as a violation event with `{sandboxID, name, event, exposure, outcome: denied|killed, effectivePolicyVersion, shadow: false}`, at **every** audit level including `audit: none` ([overview.md](./overview.md) §8.1.4).
2. `audit: metadata` adds the record of **ordinary** credential use: which binding was attached to which destination, when, and under which identity. Not the credential.
3. Every credential the platform mints or attaches MUST be attributable to a sandbox, a binding `name`, and an `effectivePolicyVersion`. "Which sandbox used this credential at 14:03?" MUST be answerable from the audit stream, because that is the question an incident starts with.
4. A binding resolved to `exposure: file` or `env` MUST emit an audit event at sandbox creation recording the residual exposure (§5.7). Handing a readable credential to partially trusted code is an event, not a silent field — the same treatment [filesystem.md](./filesystem.md) §9.4 gives `baselineExceptions`.

## 10. Merge semantics

On top of the shared rules in [overview.md](./overview.md) §5:

| Field | Merge refinement |
| --- | --- |
| `mode` | Most restrictive wins: if any source says `managed`, the result is `managed`. |
| `defaultExposure` | Most restrictive wins: `none` > `proxy` > `file` > `env` (§3.4). |
| `secrets` | Append + deduplicate by `name`. A same-`name` binding from a higher-precedence source MUST NOT widen the lower-precedence one: `exposure` takes the most restrictive value, `destinations` **intersect**, and `ttlSec` takes the minimum. |
| `workloadIdentity.enabled` | `true` wins — having a scoped identity is the narrower posture than having none, because the alternative in practice is a shared static credential. |
| `workloadIdentity.audience` | **Intersection** across sources. A request cannot broaden the audience a template set. |
| `workloadIdentity.ttlSec` | Minimum wins. |
| `onViolation` | `kill` wins ([overview.md](./overview.md) §8.1.7). |
| `audit` | Most detailed wins (`metadata` > `none`). |

The `destinations` intersection deserves a note, because it is the one place this module's merge can produce something surprising: a template binding scoped to `*.example.com` and a request binding of the same `name` scoped to `api.other.com` intersect to **nothing**, and the binding attaches to no destination. That is the correct narrow-only outcome, and it MUST be reported as the `destinations_unreachable` warning (§4.4) rather than left for the workload to discover as an authentication failure.

### 10.1 Grantable fields

Per [overview.md](./overview.md) §5.1.8, a time-bounded grant against this module may open:

| Grantable | Not grantable |
| --- | --- |
| `secrets` — a named binding, for a bounded window | `mode: unrestricted` |
| `destinations` — named additions to an existing binding | `exposure` — any relaxation |
| `workloadIdentity.audience` — named additions | `workloadIdentity.ttlSec` — no increase |

`exposure` is not grantable, and this is the most important exclusion in the table. Temporarily moving a binding from `proxy` to `env` writes the credential into the sandbox, where the workload may read it in the first second and retain it forever. The grant would expire; the exposure would not. A grant whose effects outlive its TTL is not time-bounded, which is the whole premise of §5.1 — the same reason `process.runAsNonRoot: false` is not grantable ([process.md](./process.md) §8).

`ttlSec` is not grantable for the adjacent reason: a credential lifetime raised beyond the grant's own TTL outlives the grant that raised it.

Granting a **new binding** is permitted and is the intended shape for "this task needs to call one more API": the binding arrives with `exposure: proxy`, a scoped destination, and its own expiry, and it is gone afterwards. Subject to the ceiling like everything else — a grant MUST NOT reopen a binding a template or profile closed.

## 11. Acceptance criteria

1. **Proxy mode hides the value.** With `exposure: proxy`, the credential is absent from the sandbox's filesystem, environment, process arguments, and every API the workload can reach, while a request to a declared destination arrives at that destination authenticated.
2. **Destination scoping.** A `proxy` binding scoped to `api.example.com` attaches to a request for that host and is **withheld** from a request to any other host. The withheld request is forwarded unauthenticated, not rejected, and emits `POLICY_IDENTITY_DESTINATION_DENIED` to the audit stream only.
3. **Header spoofing does not attach.** A connection to an address outside `destinations` carrying a `Host` header that names an allowed destination does not receive the credential (§4.3).
4. **Method and path scoping.** With `methods: [GET]` and `pathPrefixes: [/v1/read]`, a `POST` to that prefix and a `GET` to another prefix both proceed without the credential.
5. **Unreachable destinations warn.** A binding whose destinations are all denied by the effective network policy is accepted, and the create response carries `destinations_unreachable` naming the binding.
6. **Audience is mandatory.** `workloadIdentity.enabled: true` with an empty `audience` is rejected with `400 INVALID_POLICY`.
7. **Identity is per instance.** Two sandboxes from one template present distinct identities, and revoking one leaves the other working.
8. **Renewal needs no cooperation.** A sandbox that makes authenticated requests across a period longer than `ttlSec` continues to succeed without performing any refresh itself (§5.5).
9. **Revocation is live.** Removing a binding stops subsequent requests from being authenticated, without restarting the sandbox (§5.6).
10. **Residual exposure is honest.** Under `exposure: env`, revocation does not retract a value the workload already read, the effective policy reports that residual exposure, and creation emitted the §9.4 event.
11. **No leakage in payloads.** No error, warning, or audit event produced by this module contains a credential value or a `secretRef`, including in the unresolvable-secret and exposure-denied cases (§8).
12. **Merge is narrow-only.** A template binding with `exposure: proxy` cannot be changed to `env` by a request of the same `name`; `destinations` intersect; `ttlSec` takes the minimum; `audience` intersects. A request that attempts to widen any of them is handled per [overview.md](./overview.md) §5 — rejected or reported, never silently applied.
13. **Grants.** A grant adding a `proxy` binding expires without action by the sandbox, after which requests are no longer authenticated. A grant attempting to change `exposure`, raise `ttlSec`, or set `mode: unrestricted` is rejected.
14. **Unsupported proxy fails closed.** On a deployment declaring `exposure: proxy` `unsupported`, a policy requesting it is rejected with `400 POLICY_UNSUPPORTED` under `enforcement: strict`, and under `bestEffort` is accepted with the binding reported inert — in neither case is it silently downgraded to `file` or `env`.
15. **Tier defaults.** `tier: restricted` with no identity fields resolves to `mode: managed`, `defaultExposure: proxy`, `workloadIdentity.enabled: true`, and no secrets — a sandbox that authenticates as nothing and holds nothing. `tier: compatibility` resolves to `mode: unrestricted` and changes nothing about today's behaviour.
16. **Shadow evaluation.** With `tier: baseline` and `auditTier: restricted`, a binding in `file` mode continues to work and emits a `shadow: true` finding naming the binding and `proxy`. No credential is minted for the shadow evaluation, and nothing observable inside the sandbox differs.
17. **Lifecycle.** A sandbox restored from a snapshot does not inherit secret bindings ([overview.md](./overview.md) §8.3); authenticated requests fail until the bindings are re-established.

## 12. Open questions

1. **Credential type taxonomy.** This spec treats every credential as an opaque value attached to outbound requests. Real credentials differ: a bearer token is attached to a header, an AWS signature is computed over the request, a client certificate is used in the handshake, and a database password is sent inside a protocol this module cannot parse. Does `SecretBinding` need a `type` with per-type attachment semantics, or is `proxy` mode honestly limited to HTTP-shaped credentials — in which case that limit MUST be stated in §3 rather than implied?
2. **Non-HTTP destinations.** §4 is written in terms of destinations, methods, and request paths, which presumes HTTP. A `proxy`-mode credential for a Postgres connection has no method or path, and the proxy would have to speak the wire protocol. Is `proxy` restricted to HTTP/HTTPS in v1, with non-HTTP credentials necessarily `file` or `env`?
3. **Who may reference a `secretRef`.** [overview.md](./overview.md) §5.2 says a caller cannot exceed its delegated authority, but this module does not say whether referencing a secret requires a distinct permission from creating a sandbox. It should: otherwise any caller who may create a sandbox may bind any secret the platform can resolve. This question blocks the module.
4. **Interaction with `filesystem` under `exposure: file`.** A credential written to `path` is subject to `filesystem` rules, and a `denyPaths` entry covering that path would make the credential unreadable — a policy that is internally contradictory but individually valid. Should the platform reject the pair at create time, or is the resulting failure legible enough?
5. **Per-request approval.** `resource` has a hold-and-approve flow for exceeding budgets ([resource.md](./resource.md) §7). Should an unusually scoped credential use — a first-time destination, an unusual hour — be able to trigger the same human gate, or is that detection (§2.3.1 of [overview.md](./overview.md)) rather than policy?
6. **Egress proxy trust.** `proxy` mode moves the credential into the egress path, which makes that component a high-value target holding every sandbox's credentials. The spec requires the enforcement point to exist but says nothing about its own isolation, key handling, or blast radius. That is arguably out of scope, but a deployment that reads this module and builds a single proxy holding every tenant's secrets has followed the letter of it.

## 13. Non-normative notes

- **Substrate mapping** ([overview.md](./overview.md) §12.2). The parts of this module that live outside the sandbox — identity minting, credential attachment, destination matching — are control-plane and egress-path concerns, and are therefore substrate-independent: the same proxy works for a MicroVM and for a container. The parts that live inside — writing a file, setting an environment variable — are equally available on both. This module has no VM/container divergence, which is unusual in this proposal and follows from its enforcement point being outside the sandbox rather than in the kernel.
- What this module *does* depend on is the presence of an egress enforcement point, which is the same dependency `network.rules` and `resource.llmTokens` have. A deployment that has none of the three has a coherent, weaker posture; a deployment that has it for one and not the others is probably misconfigured rather than deliberately limited.
- **On preferring `proxy` without mandating it.** An earlier draft of this module made `proxy` the only mode. It was rejected for the reason §3.2 gives: the SDK ecosystem reads credentials from files and environment variables, and a policy language that cannot express what deployments actually do gets bypassed rather than adopted. The compromise is that `file` and `env` remain available, remain audited at creation, and are described as what they are — the residual-exposure language in §5.7 and §9.4 is deliberately blunt.
- Analogues studied: Cloudflare's model of keeping the Worker outside the sandbox and injecting credentials from there; E2B's audience-bound workload identity; Daytona's proxy-side secret placeholders; OpenSandbox's credential vault with revision-checked updates. All four converged independently on "keep the secret outside, attach it on the way out", which is the strongest available argument for `proxy` being the default rather than an option.
