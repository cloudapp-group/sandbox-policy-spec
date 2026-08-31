# Spec: Network Policy

Part of [Proposal 0001 — Sandbox Security Policy](./overview.md). The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as described in RFC 2119.

---

## 1. Scope

This spec defines the network sub-policy of the `SandboxPolicy` object:

- **Egress** — L3/L4 reachability (IP/CIDR, domain-based with DNS learning) and L7 HTTP/HTTPS rules.
- **Ingress** — gating of public inbound access to the sandbox.

This spec **does not redefine** the existing egress grammar. The target syntax for `allowOut` / `denyOut`, the L7 rule grammar for `rules`, the DNS allow-listing and learning behavior, and the built-in private-CIDR denies are already specified by [Egress Network Policy](../../../guide/network-policy.md) and [Security Proxy](../../../guide/security-proxy.md). Those documents are incorporated by reference; this spec wraps them in the unified policy object and defines the merge, default, and compatibility contract.

## 2. Object model

```yaml
policy:
  network:
    allowInternetAccess: bool          # default: true
    allowOut:      [string]            # IP / CIDR / domain / leading "*." wildcard domain
    denyOut:       [string]            # IPv4 / IPv4 CIDR only
    rules:         [EgressRule]        # L7 rules, first-match-wins (existing grammar)
    ingress:
      allowPublicTraffic: bool         # default: true
      maskRequestHost:   string        # Host authority template, "${PORT}" expansion
```

## 3. Field specification

| Field | Type | Constraints | Default | Semantics |
| --- | --- | --- | --- | --- |
| `allowInternetAccess` | `bool?` | — | `true` | When `false`, a deny-all egress fallback is installed and only explicit allow entries and L7 targets may punch holes. |
| `allowOut` | `[string]?` | Each entry: IPv4, IPv4 CIDR, valid DNS name, or leading `*.` wildcard DNS name. Invalid entries MUST fail validation. | `[]` | Explicitly allowed egress targets. Domain entries participate in DNS learning. |
| `denyOut` | `[string]?` | Each entry: IPv4 or IPv4 CIDR. Domain names MUST be rejected with `400 INVALID_POLICY`. | `[]` | Explicitly denied egress destinations. |
| `rules` | `[EgressRule]?` | Per the existing L7 rule grammar: `name`, `match.{scheme,sni,host,method,path}`, `action.{allow,audit,inject}`. | `[]` | L7 HTTP/HTTPS rules, first-match-wins. |
| `ingress.allowPublicTraffic` | `bool?` | — | `true` | When `false`, inbound public access requires a valid traffic-access token. |
| `ingress.maskRequestHost` | `string?` | Host authority template; `${PORT}` expands to the requested sandbox port. | unset | Rewrites the Host authority forwarded to sandbox services. Ingress-only. |

## 4. Evaluation semantics

Incorporated by reference from the existing egress specification; summarized as normative anchors:

1. **Egress decision order** MUST be, for every connection:

   | Step | Check | Outcome |
   | --- | --- | --- |
   | 1 | Built-in private-CIDR denies (step 2 below) | reject — not overridable by any policy source |
   | 2 | **Binding denies** (§4.6) — `denyOut` entries contributed by a source of lower precedence than the request | reject — **not** overridable by a request-level `allowOut` |
   | 3 | `allowOut` match | allow (L7-flagged targets route HTTP/HTTPS through the L7 evaluation) |
   | 4 | `denyOut` match (remaining, request-level entries) | reject |
   | 5 | Otherwise | allow, unless a deny-all fallback was installed by `allowInternetAccess: false` |

2. **Built-in denies.** Unless `allowInternetAccess: false` already installed a deny-all, the sandbox-private and host-internal CIDRs (`10.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`) MUST remain denied regardless of user policy. User policy MUST NOT be able to allow these ranges.
3. **Domain semantics.** Domain allow entries are realized through DNS A-record learning with TTL-bounded temporary allow entries; this behavior is normative and unchanged.
4. **Entry limits.** The final unique entry counts per sandbox MUST NOT exceed: 8192 for the allow map, 8192 for the deny map, 1024 for the domain rule map. Violations fail the create request with `400 POLICY_NETWORK_LIMIT` carrying `{map, got, max}`.
5. **First-match-wins** for `rules` over the merged rule list.

### 4.6 Deny provenance and binding denies

Allow-before-deny (step 3 before step 4) is today's behavior and is preserved, because a template that intentionally pairs a broad `denyOut` with a narrow `allowOut` depends on it. Applied across sources, however, that order would let a caller widen an administrator's boundary simply by supplying an inline `allowOut` — the opposite of the shared merge principle that higher precedence may narrow but never widen ([overview.md](./overview.md) §5). Provenance closes that hole:

1. Every merged `allowOut` / `denyOut` entry MUST retain its **provenance**: `template`, `profile`, or `request`.
2. A `denyOut` entry whose provenance is `template` or `profile` is a **binding deny**. Binding denies are evaluated before all `allowOut` entries and MUST NOT be overridden by an `allowOut` entry of any provenance.
3. Within a single source, allow-before-deny still applies: an `allowOut` entry may punch a hole in a `denyOut` entry contributed by that **same** source.
4. A request-level `allowOut` entry that is fully shadowed by a binding deny MUST NOT fail the create request. It MUST be reported in the create response as a `policyWarnings` entry `{field: "policy.network.allowOut", entry, shadowedBy, source}` and MUST be emitted as an audit event, so the caller learns that the hole it asked for was not opened (principle 4: denials are explainable).
5. Provenance MUST be preserved in the effective policy exposed by the policy API, so an operator can see which source contributed each entry.

## 5. Merge semantics

On top of the shared rules in [overview.md](./overview.md) §5:

| Field | Merge refinement |
| --- | --- |
| `allowInternetAccess` | Explicit request value overrides template/profile; absent keeps the lower-precedence value. A request MUST NOT set `true` when a lower-precedence source set `false` — the deny-all fallback can only be tightened, never released (rejected with `400 POLICY_NETWORK_CONFLICT`). |
| `allowOut`, `denyOut` | Append higher-precedence entries after lower-precedence entries, deduplicate by normalized entry. Each entry retains its provenance (§4.6); deduplication MUST keep the **lowest**-precedence provenance for a duplicated entry, so a deny stays binding. |
| `rules` | Higher-precedence rules sort before lower-precedence rules. Same-`name` rules are **not** merged or replaced; both remain, request-first, and first-match-wins resolves the effective outcome. |
| `ingress.*` | Scalar semantics; explicit value overrides. |

## 6. Defaults

Absence of `policy.network` resolves to the server-side default:

```yaml
network:
  allowInternetAccess: true
  allowOut: []
  denyOut: []            # plus built-in private-CIDR denies
  rules: []
  ingress:
    allowPublicTraffic: true
```

This is byte-for-byte today's behavior for requests that carry no network fields.

## 7. Errors

| Code | HTTP | Payload | When |
| --- | --- | --- | --- |
| `INVALID_POLICY` | 400 | `{field, reason}` | Malformed entry (e.g. domain in `denyOut`, invalid CIDR). |
| `POLICY_NETWORK_LIMIT` | 400 | `{map, got, max}` | Final unique entry count exceeds a map limit. |
| `POLICY_NETWORK_CONFLICT` | 400 | `{field, legacyField}` | A legacy field and `policy.network` are both present (§8). |

Egress rejections at runtime are **not** API errors; they surface to the sandbox as connection failures (`ECONNREFUSED`-class TCP resets for rejected TCP, drops otherwise), exactly as today.

Non-fatal findings are returned in a `policyWarnings` array on the create/update response. A warning never changes the outcome of the request; it reports that part of the submitted policy has no effect. Defined warnings: an `allowOut` entry shadowed by a binding deny (§4.6.4).

## 8. Compatibility and legacy-field mapping

The legacy surface is permanent. Each legacy field is normalized into the policy object at the API boundary; there is exactly one representation downstream.

| Legacy field (request) | Policy location |
| --- | --- |
| `allow_internet_access` (top level) | `policy.network.allowInternetAccess` |
| `network.allow_out` | `policy.network.allowOut` |
| `network.deny_out` | `policy.network.denyOut` |
| `network.allow_public_traffic` | `policy.network.ingress.allowPublicTraffic` |
| `network.mask_request_host` | `policy.network.ingress.maskRequestHost` |
| `network.rules` | `policy.network.rules` |

Conflict rule: a request containing any legacy network field **and** a non-empty `policy.network` MUST be rejected with `400 POLICY_NETWORK_CONFLICT` listing the conflicting pair. The system MUST NOT silently pick a precedence.

Template merge applies unchanged: a template's network configuration becomes the template-level default policy; request fields merge per §5 exactly as they merge today.

## 9. Acceptance criteria

1. Every existing egress behavior test passes unmodified when the same values are supplied through legacy fields.
2. For every legacy-field combination, supplying the equivalent values through `policy.network` produces an identical effective egress configuration (allow/deny/L7 routing observable behavior).
3. A request with both `network.allow_out` and `policy.network.allowOut` is rejected with `400 POLICY_NETWORK_CONFLICT`.
4. `denyOut` containing a domain is rejected with `400 INVALID_POLICY`.
5. Over-limit configurations are rejected with `POLICY_NETWORK_LIMIT` and correct `{map, got, max}`.
6. Built-in private-CIDR denies cannot be overridden by `allowOut` entries.
7. Absent `policy.network` and absent legacy fields ⇒ default policy, identical to today's behavior with no fields.
8. **Binding deny.** A template (or profile) `denyOut` entry plus a request `allowOut` entry for an address covered by it ⇒ the connection is rejected, and the create response carries a `policyWarnings` entry naming the shadowed entry and its shadowing source.
9. **Same-source hole.** A `denyOut` and an `allowOut` contributed by the *same* source, where the allow is covered by the deny ⇒ the connection is allowed (today's behavior preserved).
10. A request setting `allowInternetAccess: true` against a template that set `false` is rejected with `400 POLICY_NETWORK_CONFLICT`.

## 10. Open questions

1. Should `ingress` grow beyond the public-traffic gate (e.g. source CIDR allowlist, per-port ingress rules), or stay minimal in v1?
2. Domain `denyOut`: rejected today by design. Should a DNS-sinkhole-style deny (block resolution of named domains) be specified later?
3. IPv6/AAAA support in allow/deny and learning — out of scope for v1; confirm.

## 11. Non-normative notes

- The existing data path (eBPF L3/L4 enforcement plus an L7 proxy for flagged HTTP/HTTPS) already satisfies overview principle 5 for this module; no enforcement-point change is required by this spec.
- **Rejected alternative for §4.6:** evaluating `denyOut` before `allowOut` unconditionally (a global deny-first model). It is the more familiar security model, but it changes the meaning of every existing configuration that punches an allow hole in a broad deny, which contradicts the compatibility promise in §9.1 and §6. Binding denies achieve the same protection against privilege escalation across sources while keeping single-source semantics byte-for-byte unchanged.
