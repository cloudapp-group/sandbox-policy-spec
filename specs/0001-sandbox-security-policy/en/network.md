# Spec: Network Policy

Part of [Proposal 0001 — Sandbox Security Policy](./overview.md). The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as described in RFC 2119.

---

## 1. Scope

This spec defines the network sub-policy of the `SandboxPolicy` object:

- **Egress** — L3/L4 reachability (IP/CIDR, domain-based with DNS learning), port and protocol scoping, and L7 HTTP/HTTPS rules.
- **Ingress** — gating of public inbound access to the sandbox.

Evaluation is **stateful**: rules describe connections, and the reply direction of an admitted connection needs no rule of its own (§4.7). This is the same contract a cloud security group offers, and it is what separates a reviewable rule set from one padded with reverse entries over the ephemeral port range.

This spec **does not redefine** the existing egress grammar. The target syntax for `allowOut` / `denyOut`, the L7 rule grammar for `rules`, the DNS allow-listing and learning behavior, and the built-in private-CIDR denies are already specified by [Egress Network Policy](../../../guide/network-policy.md) and [Security Proxy](../../../guide/security-proxy.md). Those documents are incorporated by reference; this spec wraps them in the unified policy object and defines the merge, default, and compatibility contract.

## 2. Object model

```yaml
policy:
  network:
    allowInternetAccess: bool          # default: true
    allowOut:      [string]            # IP / CIDR / domain / leading "*." wildcard domain
    denyOut:       [string]            # IPv4 / IPv4 CIDR only
    portRules:     [PortRule]          # L4 allow rules scoped by protocol and port
    rules:         [EgressRule]        # L7 rules, first-match-wins (existing grammar)
    onViolation:   deny | kill         # default: deny — see §4.8
    audit:         none | metadata     # default: none
    ingress:
      allowPublicTraffic: bool         # default: true
      maskRequestHost:   string        # Host authority template, "${PORT}" expansion
```

### 2.1 `PortRule`

An `allowOut` entry admits its target on **every** port. That is the right shape for "let this sandbox talk to our API" and far too coarse for "let it reach this database on 5432 over TCP and nothing else". `portRules` is that narrower statement.

```yaml
- name:      string       # required, unique within the list; used in errors and audit
  target:    string       # IP / CIDR / domain / leading "*." wildcard domain — the allowOut grammar
  protocols: [string]     # subset of {tcp, udp}; default: [tcp, udp]
  ports:     [string]     # "443" or "8000-8100"; default: all ports
```

1. A `PortRule` matches a connection when the target, the protocol, **and** the port all match. A matching rule admits the connection exactly as an `allowOut` entry would (§4.1 step 3).
2. Domain targets participate in DNS learning identically to `allowOut` domain entries; learned addresses inherit the rule's protocol and port scoping.
3. `portRules` is an **additional allow surface, not a filter over `allowOut`**. To restrict a target to specific ports, name it in `portRules` and **not** in `allowOut`.
4. A target admitted broadly by `allowOut` and also named in a narrower `PortRule` stays reachable on all ports: the broader allow wins and the port scoping has no effect. This is not an error — a template's broad allow and a request's narrow rule have to coexist — but the platform MUST report it as a `policyWarnings` entry `{field: "policy.network.portRules", rule, reason: "shadowed_by_allow_out"}`. An author who believes a port restriction is in force when it is not is exactly the failure principle 4 exists to prevent.
5. Ports are single values or inclusive ranges within `1`–`65535`. Malformed entries, reversed ranges, and protocols outside `{tcp, udp}` MUST be rejected with `400 INVALID_POLICY`.
6. `portRules` cannot narrow or lift the built-in private-CIDR denies or binding denies (§4.6). Those are evaluated first and are unaffected by port scoping.

## 3. Field specification

| Field | Type | Constraints | Default | Semantics |
| --- | --- | --- | --- | --- |
| `allowInternetAccess` | `bool?` | — | `true` | When `false`, a deny-all egress fallback is installed and only explicit allow entries and L7 targets may punch holes. |
| `allowOut` | `[string]?` | Each entry: IPv4, IPv4 CIDR, valid DNS name, or leading `*.` wildcard DNS name. Invalid entries MUST fail validation. | `[]` | Explicitly allowed egress targets. Domain entries participate in DNS learning. |
| `denyOut` | `[string]?` | Each entry: IPv4 or IPv4 CIDR. Domain names MUST be rejected with `400 INVALID_POLICY`. | `[]` | Explicitly denied egress destinations. |
| `portRules` | `[PortRule]?` | Per §2.1. `name` MUST be unique within the list. | `[]` | Port- and protocol-scoped allow rules. |
| `rules` | `[EgressRule]?` | Per the existing L7 rule grammar: `name`, `match.{scheme,sni,host,method,path}`, `action.{allow,audit,inject}`. | `[]` | L7 HTTP/HTTPS rules, first-match-wins. |
| `onViolation` | `enum?` | `deny` \| `kill` | `deny` | §4.8. Note `kill` ends the **sandbox**, not a process. |
| `audit` | `enum?` | `none` \| `metadata` | `none` | Audit level for **ordinary** connection activity (§7). It does not suppress violation events ([overview.md](./overview.md) §8.1.4). |
| `ingress.allowPublicTraffic` | `bool?` | — | `true` | When `false`, inbound public access requires a valid traffic-access token. |
| `ingress.maskRequestHost` | `string?` | Host authority template; `${PORT}` expands to the requested sandbox port. | unset | Rewrites the Host authority forwarded to sandbox services. Ingress-only. |

## 4. Evaluation semantics

Incorporated by reference from the existing egress specification; summarized as normative anchors:

1. **Egress decision order** MUST be, for every connection:

   | Step | Check | Outcome |
   | --- | --- | --- |
   | 1 | Built-in private-CIDR denies (step 2 below) | reject — not overridable by any policy source |
   | 2 | **Binding denies** (§4.6) — `denyOut` entries contributed by a source of lower precedence than the request | reject — **not** overridable by a request-level `allowOut` |
   | 3 | `allowOut` match, or `portRules` match on target + protocol + port (§2.1) | allow (L7-flagged targets route HTTP/HTTPS through the L7 evaluation) |
   | 4 | `denyOut` match (remaining, request-level entries) | reject |
   | 5 | Otherwise | allow, unless a deny-all fallback was installed by `allowInternetAccess: false` |

2. **Built-in denies.** Unless `allowInternetAccess: false` already installed a deny-all, the sandbox-private and host-internal CIDRs (`10.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.168.0.0/16`) MUST remain denied regardless of user policy. User policy MUST NOT be able to allow these ranges.
3. **Domain semantics.** Domain allow entries are realized through DNS A-record learning with TTL-bounded temporary allow entries; this behavior is normative and unchanged.
4. **Entry limits.** The final unique entry counts per sandbox MUST NOT exceed: 8192 for the allow map, 8192 for the deny map, 1024 for the domain rule map. `portRules` entries count against the allow map after expansion over their protocols and port ranges, since that is where they are realized. Violations fail the create request with `400 POLICY_NETWORK_LIMIT` carrying `{map, got, max}`.
5. **First-match-wins** for `rules` over the merged rule list.

### 4.6 Deny provenance and binding denies

Allow-before-deny (step 3 before step 4) is today's behavior and is preserved, because a template that intentionally pairs a broad `denyOut` with a narrow `allowOut` depends on it. Applied across sources, however, that order would let a caller widen an administrator's boundary simply by supplying an inline `allowOut` — the opposite of the shared merge principle that higher precedence may narrow but never widen ([overview.md](./overview.md) §5). Provenance closes that hole:

1. Every merged `allowOut` / `denyOut` entry MUST retain its **provenance**: `template`, `profile`, or `request`.
2. A `denyOut` entry whose provenance is `template` or `profile` is a **binding deny**. Binding denies are evaluated before all `allowOut` entries and MUST NOT be overridden by an `allowOut` entry of any provenance.
3. Within a single source, allow-before-deny still applies: an `allowOut` entry may punch a hole in a `denyOut` entry contributed by that **same** source.
4. A request-level `allowOut` entry that is fully shadowed by a binding deny MUST NOT fail the create request. It MUST be reported in the create response as a `policyWarnings` entry `{field: "policy.network.allowOut", entry, shadowedBy, source}` and MUST be emitted as an audit event, so the caller learns that the hole it asked for was not opened (principle 4: denials are explainable).
5. Provenance MUST be preserved in the effective policy exposed by the policy API, so an operator can see which source contributed each entry.

### 4.7 Connection state

Every rule in §4 describes a **connection**, not an individual packet. The distinction is normative, not an implementation detail:

| | Requirement |
| --- | --- |
| Return traffic | Traffic belonging to a connection already admitted by §4.1 MUST be permitted for the life of that connection, without a matching rule of its own. |
| Reply direction is not ingress | The inbound half of a sandbox-initiated connection is **not** ingress and MUST NOT be subject to `ingress.allowPublicTraffic` (§3). Setting `ingress.allowPublicTraffic: false` never breaks the response to an outbound request. |
| Connectionless protocols | For UDP and ICMP, "connection" means a flow tracked by the platform with a documented idle timeout. The reply-direction guarantee applies to such a flow exactly as it applies to TCP. |
| Port rules | A `PortRule` (§2.1) scopes the **destination** of the outbound half. Its reply traffic arrives on an ephemeral source port and is permitted by connection state, not by a second rule. |

This is written down rather than left to the data path because it is the property that makes a rule set reviewable. Under a stateless model every `allowOut` entry would need a companion reverse entry covering the ephemeral port range — which is simultaneously the thing every author forgets and, once written, a hole far wider than the rule it was meant to serve. Cloud security groups are stateful for exactly this reason, and this spec inherits the expectation along with the grammar (§1).

### 4.8 Violation actions

Per [overview.md](./overview.md) §8.1, `onViolation` decides what happens when §4.1 rejects a connection:

| Action | Result |
| --- | --- |
| `deny` (default) | The connection fails as it does today: a `ECONNREFUSED`-class TCP reset for rejected TCP, a drop otherwise (§7). |
| `kill` | The **sandbox** is terminated. |

The granularity in the second row is the point of this section, and it is a limitation rather than a design preference:

1. **`kill` here ends the sandbox, not the offending process.** L3/L4 enforcement operates on packets. By the time a connection is rejected, the process that opened the socket is not reliably knowable at that layer — and a best-effort attribution is worse than none, because it would terminate whichever process the guess landed on. Ending the sandbox is the only action this enforcement point can take honestly.
2. **A deployment setting `kill` is therefore choosing "one rejected connection ends the sandbox".** That is a legitimate posture for a workload that should never reach an unnamed destination, and a destructive one for anything that probes. It MUST NOT be selected on the assumption that it behaves like `filesystem`'s or `process`'s `kill`, which are process-scoped ([overview.md](./overview.md) §8.1.3).
3. **The built-in private-CIDR denies (§4.2) participate.** Under `kill`, a connection attempt to `169.254.169.254` ends the sandbox. This is the case `kill` is most defensible for — nothing legitimate reaches the metadata endpoint — and it is also the case most likely to fire unexpectedly, since some runtimes probe such addresses on startup. Shadow the tier first (§6.1).
4. There is no `warn`, on the terms of [overview.md](./overview.md) §8.1.2. `auditTier` (§6.1) is how a deployment learns which destinations a stricter posture would reject, while keeping the current rules enforced.
5. Either action emits a violation event, at every audit level (§7).

## 5. Merge semantics

On top of the shared rules in [overview.md](./overview.md) §5:

| Field | Merge refinement |
| --- | --- |
| `allowInternetAccess` | Explicit request value overrides template/profile; absent keeps the lower-precedence value. A request MUST NOT set `true` when a lower-precedence source set `false` — the deny-all fallback can only be tightened, never released (rejected with `400 POLICY_NETWORK_CONFLICT`). |
| `allowOut`, `denyOut` | Append higher-precedence entries after lower-precedence entries, deduplicate by normalized entry. Each entry retains its provenance (§4.6); deduplication MUST keep the **lowest**-precedence provenance for a duplicated entry, so a deny stays binding. |
| `portRules` | Append + deduplicate by `name`. Entries retain provenance and are subject to binding denies exactly as `allowOut` entries are (§4.6): a `portRule` shadowed by a binding deny does not open, and MUST be reported as a `policyWarnings` entry. |
| `rules` | Higher-precedence rules sort before lower-precedence rules. Same-`name` rules are **not** merged or replaced; both remain, request-first, and first-match-wins resolves the effective outcome. |
| `onViolation` | `kill` wins ([overview.md](./overview.md) §8.1.7). Given §4.8, a template setting `kill` makes every rejected connection fatal for sandboxes created from it, and a request cannot soften that. |
| `audit` | Most detailed wins (`metadata` > `none`). |
| `ingress.*` | Scalar semantics; explicit value overrides. |

### 5.1 Grantable fields

Per [overview.md](./overview.md) §5.1.8, a time-bounded grant against this module may open:

| Grantable | Not grantable |
| --- | --- |
| `allowOut` — named targets | `allowInternetAccess: true` |
| `portRules` — named rules | `denyOut` removal of any entry |

`allowInternetAccess: true` is excluded because it is not a hole of known shape ([overview.md](./overview.md) §5.1.4): it releases the deny-all fallback for every destination at once. A task that needs one more endpoint for ten minutes asks for that endpoint. As everywhere, a grant cannot reopen what a binding deny closed, nor the built-in private-CIDR denies (§4.1 step 1).

## 6. Defaults

Absence of `policy.network` resolves to the server-side default, which is the `baseline` tier ([overview.md](./overview.md) §7.1):

```yaml
network:
  allowInternetAccess: true
  allowOut: []
  denyOut: []            # plus built-in private-CIDR denies
  portRules: []
  rules: []
  onViolation: deny
  audit: none
  ingress:
    allowPublicTraffic: true
```

This is byte-for-byte today's behavior for requests that carry no network fields.

Under `tier: restricted` the same fields resolve to a deny-all posture instead — `allowInternetAccess: false` and `ingress.allowPublicTraffic: false` — so that "no inbound or outbound access unless named" is one field on the policy rather than two per module. The tier only changes these defaults; every evaluation rule in §4 is unchanged, and an explicit field in the same source still wins ([overview.md](./overview.md) §7.1 rule 3). `onViolation` stays `deny` under `restricted`, per [overview.md](./overview.md) §8.1.7 — and emphatically so here, since a tier that paired deny-all egress with `kill` would terminate a sandbox on its first unnamed destination, which is a very long way from what "give me a locked-down sandbox" asks for.

### 6.1 Shadow evaluation support

Per [overview.md](./overview.md) §7.2.5, this module supports shadow evaluation under `auditTier` for its full egress and ingress surface. The stricter tier's rule set is evaluated alongside the enforced one; a connection the shadow set would have rejected is **established anyway** and emits a `shadow: true` audit event naming the destination, the port and protocol, and the shadow field that would have rejected it.

This is the cheapest shadow in the proposal to act on, because the finding *is* the fix: a shadow report under `auditTier: restricted` is a list of the destinations a deny-all posture would need in `allowOut` or `portRules`. An operator can turn that list into the policy and then flip the tier.

Two module-specific points:

1. The built-in private-CIDR denies (§4.2) are in force under every tier, so they never appear as shadow findings. A destination denied today is denied in the shadow too; shadow evaluation reports what *would change*, not what already holds.
2. Statefulness (§4.7) applies to the shadow evaluation as well. A shadow finding is emitted once per connection at establishment, not once per packet — without which the volume concern in [overview.md](./overview.md) §7.2.7 would make this unusable on any real workload.

## 7. Errors

| Code | HTTP | Payload | When |
| --- | --- | --- | --- |
| `INVALID_POLICY` | 400 | `{field, reason}` | Malformed entry (e.g. domain in `denyOut`, invalid CIDR). |
| `POLICY_NETWORK_LIMIT` | 400 | `{map, got, max}` | Final unique entry count exceeds a map limit. |
| `POLICY_NETWORK_CONFLICT` | 400 | `{field, legacyField}` | A legacy field and `policy.network` are both present (§8). |

Egress rejections at runtime are **not** API errors; they surface to the sandbox as connection failures (`ECONNREFUSED`-class TCP resets for rejected TCP, drops otherwise), exactly as today. Under `onViolation: kill` (§4.8) the sandbox is terminated instead, and the terminal state records the destination and the matched rule as the cause.

Every rejected connection MUST emit a violation event at **every** audit level, including `audit: none` ([overview.md](./overview.md) §8.1.4): `{sandboxID, destination, port, protocol, rule?, provenance?, outcome: denied|killed, effectivePolicyVersion, shadow: false}`. What `audit: metadata` adds is the record of **ordinary** connections — the ones that were allowed — which is the high-volume part and the part a deployment may reasonably decline. One event per connection, not per packet, on the same terms as §6.1.2.

Non-fatal findings are returned in a `policyWarnings` array on the create/update response. A warning never changes the outcome of the request; it reports that part of the submitted policy has no effect. Defined warnings: an `allowOut` entry shadowed by a binding deny (§4.6.4), and a `portRule` shadowed by a broader `allowOut` entry (§2.1.4).

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
11. **Port scoping.** With `allowInternetAccess: false` and a single `portRule` for `10.20.0.5`, `tcp`, `5432`, a connection to that address on 5432 succeeds while 5433 and UDP 5432 are rejected. A `portRule` naming a port range admits every port in the range and nothing outside it.
12. **Port rule shadowing.** A target present in both `allowOut` and a narrower `portRule` is reachable on all ports, and the create response carries the `shadowed_by_allow_out` warning naming the rule.
13. **Port rules are not an escape.** A `portRule` targeting a built-in private CIDR, or an address closed by a binding deny, does not open it.
14. **Restricted tier.** `tier: restricted` with no network fields resolves to `allowInternetAccess: false` and `ingress.allowPublicTraffic: false`, and the effective policy records those expanded values. A source that sets `tier: restricted` and also `allowInternetAccess: true` explicitly gets `true` from that source, subject to the narrow-only rule against lower-precedence sources.
15. **Statefulness.** With `allowInternetAccess: false` and a single `allowOut` entry for one destination, an outbound TCP connection to it succeeds **and its response is received** with no reverse rule present. The same holds for a `portRule`-admitted connection, whose reply arrives on an ephemeral source port. With `ingress.allowPublicTraffic: false` set at the same time, that response is still received — the reply direction is not ingress (§4.7).
16. **Shadow evaluation.** With `tier: baseline` and `auditTier: restricted`, a connection to an unnamed public destination **succeeds** and emits a `shadow: true` event naming the destination and the field that would have rejected it. A connection to a built-in-denied private CIDR is rejected as it is today and emits **no** shadow finding. Nothing observable inside the sandbox differs from the same configuration without `auditTier`. One shadow event is emitted per connection, not per packet.
17. **Violation action.** With `onViolation: deny` (the default), a rejected connection fails and the sandbox keeps running — today's behavior. With `onViolation: kill`, the same rejected connection terminates the **sandbox**, and the terminal state names the destination and matched rule. A template setting `kill` cannot be softened to `deny` by a request.
18. **Violations are audited at `audit: none`.** With the default `audit: none`, a rejected connection still emits a violation event carrying `shadow: false` and the destination; what `audit: none` suppresses is only the record of allowed connections. Events are emitted once per connection.

## 10. Open questions

1. Should `ingress` grow beyond the public-traffic gate (e.g. source CIDR allowlist, per-port ingress rules), or stay minimal in v1? Note that egress now has port and protocol scoping (§2.1) while ingress does not, which makes the asymmetry more visible than it was.
2. Domain `denyOut`: rejected today by design. Should a DNS-sinkhole-style deny (block resolution of named domains) be specified later?
3. IPv6/AAAA support in allow/deny and learning — out of scope for v1; confirm.
4. **Denying by port.** §2.1 adds port scoping to the *allow* surface only. Should there be a port-scoped `denyOut` as well, or is "name what may be reached" sufficient given that a deny-all posture is one tier away?
5. **Rate and reachability.** Bandwidth is a `resource.quota` dimension while reachability is here ([overview.md](./overview.md) §11.9). Should a `PortRule` be able to carry its own rate ceiling, or does that recreate the dialect problem the unified object exists to prevent?
6. **Flow timeouts as policy.** §4.7 requires a documented idle timeout for connectionless flows but leaves the value to the platform. Should it be a policy field? A workload holding thousands of idle UDP flows is a resource question, which argues for leaving it out of `network` entirely — but the *reachability* consequence of an expiring flow lands here.
7. **Identity-based targets.** Every target in this spec is an address or resolves to one. Peer-group references (the security-group model) and label selectors (the NetworkPolicy model) express "these workloads may talk to each other" without anyone writing a CIDR, which is what the multi-agent case needs. Tracked as [overview.md](./overview.md) §11.11, because the blocking obstacle is that sandbox-to-sandbox traffic rides on the ranges §4.2 denies unconditionally.

## 11. Non-normative notes

- The existing data path (eBPF L3/L4 enforcement plus an L7 proxy for flagged HTTP/HTTPS) already satisfies overview principle 5 for this module; no enforcement-point change is required by this spec. Connection tracking (§4.7) is likewise a property the existing path already has — §4.7 documents it as a contract rather than requesting it.
- **Rejected alternative for §4.6:** evaluating `denyOut` before `allowOut` unconditionally (a global deny-first model). It is the more familiar security model, but it changes the meaning of every existing configuration that punches an allow hole in a broad deny, which contradicts the compatibility promise in §9.1 and §6. Binding denies achieve the same protection against privilege escalation across sources while keeping single-source semantics byte-for-byte unchanged.
- **Rejected alternative — implicit isolation.** A Kubernetes NetworkPolicy flips its target to default-deny for a direction as soon as any policy selects it: writing one allow rule implicitly denies everything else. It is an attractive property, because it makes the common intent ("only these destinations") impossible to express incompletely. It is rejected here because in this object an `allowOut` entry is additive by definition and has been since before this proposal: adopting implicit isolation would silently convert every existing configuration that lists a few allow entries alongside general internet access into a deny-all sandbox, which is the exact opposite of §9.1. The explicit form is `allowInternetAccess: false`, and `tier: restricted` makes it one field — the same destination reached without reinterpreting anyone's existing policy.
