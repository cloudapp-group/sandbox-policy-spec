# Spec: Network Policy

Part of [Proposal 0001 — Sandbox Security Policy](./overview.md). The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as described in RFC 2119.

---

## 1. Scope

This spec defines the network sub-policy of the `SandboxPolicy` object. It has three parts, and they are peers:

- **Egress** — what the sandbox may reach.
- **Ingress** — what may reach the sandbox.
- **Internal reachability** — whether the sandbox may reach the private network it sits inside at all (§2.2).

Egress and ingress are expressed with **one rule shape** (§2.1), each rule carries an explicit **priority**, and each rule states its match at **either layer 4 or layer 7**. The L4 form follows the cloud security-group model (direction, protocol, port range, authorised peer, priority, action). The L7 form follows the URL model for its target (scheme, host, port, path) and the Gateway API `HTTPRoute` model for its matchers (`path`, `headers`, `queryParams`, plus `cookies`).

Evaluation is **stateful**: rules describe connections, and the reply direction of an admitted connection needs no rule of its own (§4.7). This is the same contract a cloud security group offers, and it is what separates a reviewable rule set from one padded with reverse entries over the ephemeral port range.

An earlier revision of this module was asymmetric — egress had `allowOut`, `denyOut`, `portRules`, and L7 `rules`, while ingress had a single boolean and a host-rewrite string. That asymmetry was recorded as this module's largest open question and is now closed. The legacy fields remain permanently supported and are normalised into the structure below (§8).

> **Unresolved dependency — release blocker.** The documents that specify the existing DNS-learning behaviour and the current ingress token semantics ([Egress Network Policy](../../../guide/network-policy.md), [Security Proxy](../../../guide/security-proxy.md), [Restrict Public Access](../../../guide/restrict-public-access.md)) are **not part of this repository**, and the paths above resolve outside it. A reader with only this repository therefore cannot implement domain learning or the ingress token check: this document names them without defining them, which is not the same as incorporating them by reference. The resolution — a versioned bundle in-repository, or immutable URLs recorded with version and SHA-256, either way inside the conformance suite — is tracked as [overview.md](./overview.md) §11.15.

## 2. Object model

```yaml
policy:
  network:
    internal:
      mode:          deny | allow | identity   # default: deny — see §2.2
      allowedPeers:  [PeerRef]                 # identity mode only
    egress:
      defaultAction: allow | deny              # tier-selected; see §6
      rules:         [NetworkRule]
    ingress:
      defaultAction: allow | deny              # tier-selected; see §6
      rules:         [NetworkRule]
    onViolation:     deny | kill               # default: deny — see §4.8
    audit:           none | metadata           # default: none
```

`egress` and `ingress` are the same shape because they answer the same question in two directions. Neither is a subordinate of the other, and a field added to one MUST be added to the other or its absence justified in this document.

### 2.1 `NetworkRule`

```yaml
- name:     string          # required, unique within its list
  priority: int             # required, 1–65535; lower number = evaluated first
  action:   allow | deny
  l4:                       # mutually exclusive with l7
    protocol: tcp | udp | icmp | all      # default: all
    ports:    [string]                    # "443" or "8000-8100"; default: all ports
    peer:     Peer                        # required — see §2.3
  l7:                       # mutually exclusive with l4
    scheme:      http | https             # required
    hosts:       [string]                 # required; DNS names, leading "*." wildcard
    port:        int                      # default: 80 for http, 443 for https
    method:      string                   # GET | POST | ... ; default: any
    path:        HTTPMatch                # optional
    headers:     [NamedHTTPMatch]         # optional
    queryParams: [NamedHTTPMatch]         # optional
    cookies:     [NamedHTTPMatch]         # optional
```

1. `name` MUST be unique within its own list. Errors and audit events identify a rule by `{direction, name}`.
2. **`l4` and `l7` are mutually exclusive.** A rule carrying both MUST be rejected with `400 INVALID_POLICY`. A rule carrying neither MUST likewise be rejected: a rule that matches everything is `defaultAction`, and writing it as a rule hides it.
3. **An `l7` rule implicitly admits the connection it needs.** Matching `path` or a header requires an established, terminated connection, so an `l7` allow rule permits connection establishment to its `hosts` on its `port`, and then permits only the requests that match its matchers. Without this, an `l7` rule would describe a request that could never arrive.
4. Requests to an `l7` rule's `hosts:port` that do **not** match its matchers fall through to the remaining rules and then to `defaultAction`; they are not implicitly denied by the near-miss. A rule states what it admits, not what it forbids by omission.
5. `icmp` MUST NOT be combined with `ports`; such a rule is rejected with `400 INVALID_POLICY`.
6. Ports are single values or inclusive ranges within `1`–`65535`. Malformed entries and reversed ranges MUST be rejected with `400 INVALID_POLICY`.

### 2.2 `internal` — reachability of the private network

The private ranges a sandbox sits inside are the one part of the address space where "deny everything" and "allow everything" are both legitimate defaults for different deployments, and where the interesting answer is neither. `internal` states which of the three applies:

| `mode` | Meaning |
| --- | --- |
| `deny` (default) | No traffic to the private ranges of §4.2, in either direction. This is today's behaviour. |
| `allow` | The private ranges are reachable, subject to the ordinary rules of §4.1. |
| `identity` | Reachable only for the peers named in `allowedPeers`, resolved by the platform from sandbox identity rather than from an address. |

1. `internal` governs **`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `169.254.0.0/16`** (§4.2). It is evaluated before every rule, so under `deny` no `allow` rule of any priority or provenance reaches those ranges.
2. `identity` mode is how "these sandboxes may talk to each other" is expressed without anyone writing a CIDR. `allowedPeers` entries are resolved by the platform; a caller MUST NOT be able to name a peer it is not authorised to reach ([overview.md](./overview.md) §5.2).
3. **`mode: allow` includes the cloud metadata endpoint, and the cost of that is stated here rather than discovered.** `169.254.169.254` and its equivalents serve instance credentials. A sandbox that can reach them can obtain the instance role's credentials directly, which bypasses [identity.md](./identity.md) entirely — `exposure: proxy` keeps a secret out of the sandbox, and this setting hands over a different one. Therefore:
   - A policy with `internal.mode: allow` **and** any `identity.secrets` binding resolved to `exposure: proxy` MUST produce a `policyWarnings` entry `{field: "policy.network.internal.mode", reason: "metadata_endpoint_reachable"}`. The two are not contradictory enough to reject, but a deployment MUST NOT be able to configure this pair without being told.
   - Deployments **SHOULD** prefer `identity` mode with explicit peers over `allow` where the requirement is sandbox-to-sandbox traffic, because that requirement never needs the metadata endpoint.
4. `127.0.0.0/8` is **out of scope for this module**. Loopback inside a sandbox is communication between that sandbox's own processes, and on the container substrate between the containers of one Pod — which is inside the sandbox unit ([overview.md](./overview.md) §12.1), not across it. A network policy that claimed to govern it would be describing a boundary that does not exist there.
5. Merge takes the most restrictive mode: `deny` > `identity` > `allow`. `allowedPeers` intersects across sources.

### 2.3 `Peer` — the authorised object of an L4 rule

```yaml
peer:
  cidrs:        [string]      # IPv4 address or CIDR
  domains:      [string]      # DNS name or leading "*." wildcard — egress only
  sandboxGroup: string        # platform-resolved sandbox identity
```

1. At least one of the three MUST be present. An empty `peer` is rejected with `400 INVALID_POLICY`.
2. `domains` is meaningful on **egress only**. A domain on an ingress rule MUST be rejected with `400 INVALID_POLICY`: the source of an inbound connection is an address, and matching it against a name would require a reverse lookup the sender controls.
3. Domain entries are realised through DNS learning (§4.3), and this is the module's largest capability difference between deployments (§11).
4. `sandboxGroup` requires `internal.mode: identity` to have any effect; naming one under `deny` MUST produce a `policyWarnings` entry `{reason: "peer_unreachable_under_internal_deny"}` rather than a silent no-op.
5. This is the grammar other modules mean when they refer to a network target — [identity.md](./identity.md) §4.1 among them.

### 2.4 `HTTPMatch` and `NamedHTTPMatch`

The matcher shapes follow Gateway API `HTTPRoute`, so that an operator who knows one knows the other:

```yaml
HTTPMatch:                    # for path
  type:  Exact | PathPrefix | RegularExpression    # default: PathPrefix
  value: string

NamedHTTPMatch:               # for headers, queryParams, cookies
  type:  Exact | RegularExpression                 # default: Exact
  name:  string
  value: string
```

1. Header names are case-insensitive; header values, query parameter names and values, and cookie names and values are case-sensitive.
2. Multiple entries in one list are **ANDed**. A rule listing two headers matches a request carrying both.
3. `cookies` is a convenience form over the `Cookie` header, and this document says so rather than implying a separate dimension: a `cookies` entry matches when the named cookie parsed out of that header matches. `HTTPRoute` has no cookie matcher; this is an addition, not a borrowing.
4. `RegularExpression` support is **optional** for an implementation. A deployment that does not implement it MUST declare it `unsupported` ([overview.md](./overview.md) §8.2) rather than silently treating a pattern as a literal — which would turn a narrow rule into one that matches nothing, or a deny into a hole.
5. A `path` of type `PathPrefix` matches on whole path segments, not on string prefixes: `/v1` matches `/v1` and `/v1/x`, and does not match `/v11`.

## 3. Field specification

| Field | Type | Constraints | Default | Semantics |
| --- | --- | --- | --- | --- |
| `internal.mode` | `enum?` | `deny` \| `allow` \| `identity` | `deny` | §2.2. |
| `internal.allowedPeers` | `[PeerRef]?` | Meaningful only under `identity`. | `[]` | §2.2.2. |
| `egress.defaultAction` | `enum?` | `allow` \| `deny` | tier-selected (§6) | Verdict for a connection no rule matched. |
| `egress.rules` | `[NetworkRule]?` | Per §2.1. `name` unique; `priority` unique within the direction after merge (§5). | `[]` | Outbound rules. |
| `ingress.defaultAction` | `enum?` | `allow` \| `deny` | tier-selected (§6) | Verdict for an inbound connection no rule matched. |
| `ingress.rules` | `[NetworkRule]?` | Per §2.1; `peer.domains` MUST NOT be used (§2.3.2). | `[]` | Inbound rules. |
| `onViolation` | `enum?` | `deny` \| `kill` | `deny` | §4.8. Note `kill` ends the **sandbox**, not a process. |
| `audit` | `enum?` | `none` \| `metadata` | `none` | Audit level for **ordinary** connection activity (§7). It does not suppress violation events ([overview.md](./overview.md) §8.1.4). |

## 4. Evaluation semantics

### 4.1 Decision order

For every connection, and for every request on a connection admitted by an `l7` rule:

| Step | Check | Outcome |
| --- | --- | --- |
| 1 | `internal` (§2.2) — does the peer fall in a private range this mode forbids? | reject; not overridable by any rule, priority, or provenance |
| 2 | **Binding denies** (§4.6) — a `deny` rule contributed by `template` or `profile` | reject; not overridable by any `allow` rule at any priority |
| 3 | Remaining rules of the matching direction, in `priority` order (§4.5) | first match wins: `allow` admits, `deny` rejects |
| 4 | No rule matched | `defaultAction` for that direction |

Steps 1 and 2 sit before priority for the same reason: they are the parts of the policy a higher-precedence source is not permitted to widen ([overview.md](./overview.md) §5), and a priority number is written by whoever writes the rule.

### 4.2 The private ranges

`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, and `169.254.0.0/16` are governed by `internal` (§2.2) and by nothing else. Under `internal.mode: deny` — the default under every tier — they are unreachable regardless of any rule.

This replaces an unconditional deny that user policy could never lift. The change is deliberate: the previous rule made sandbox-to-sandbox traffic inexpressible and pushed users toward hand-writing private CIDRs that never worked, which is the failure §10.7 of the previous revision described. What is **not** softened is that reaching these ranges is now a decision someone has to make explicitly, in a field that appears in the effective policy, the snapshot, and the audit trail.

### 4.3 Domain semantics

Domain entries in `peer.domains` (§2.3) and `hosts` in an `l7` rule are realised through DNS A-record learning with TTL-bounded temporary entries. Two requirements make this enforceable rather than advisory:

1. The platform MUST be the sandbox's only path to name resolution. A workload that can query an external resolver directly — over UDP/TCP 53, DoT, or DoH — can resolve a name the policy never learned and then connect to the resulting address, which makes a domain rule advisory. A deployment that cannot ensure this MUST declare domain entries `unsupported` ([overview.md](./overview.md) §8.2) rather than enforce them partially.
2. Resolving a name once at admission time and pinning the address is **not** an implementation of a domain rule. It is an address rule with a domain's name on it, which §8.2.1 rule 4 of [overview.md](./overview.md) forbids reporting as enforcement.

### 4.4 Entry limits

The final unique entry counts per sandbox MUST NOT exceed: 8192 allow entries, 8192 deny entries, 1024 domain entries, and 256 rules per direction. L4 rules count against the allow or deny maps after expansion over protocols and port ranges, since that is where they are realised. Violations fail the create request with `400 POLICY_NETWORK_LIMIT` carrying `{map, got, max}`.

### 4.5 Priority

1. `priority` is an integer in `1`–`65535`. **Lower is evaluated first**, following the security-group convention.
2. Within a direction, evaluation is **first match wins** in priority order. Once a rule matches, no later rule is consulted.
3. After merge, two rules in the same direction MUST NOT share a priority. A collision MUST be rejected with `400 POLICY_NETWORK_PRIORITY_CONFLICT` carrying both rule names and their sources. This is deliberate and is the one place this module chooses an error over a convention: an implicit tie-break is the least debuggable behaviour a rule set can have, and every alternative — provenance order, name order, most-restrictive-first — produces a policy whose evaluation order is invisible in the document an operator reads.
4. Priority orders rules; it does not confer authority. Steps 1 and 2 of §4.1 are evaluated before any priority comparison, so a request-level rule cannot use a low number to reach past an administrator's deny.
5. Legacy fields normalise into reserved priority bands (§8) so that a legacy configuration and an explicit rule set can coexist without a collision.

### 4.6 Deny provenance and binding denies

1. Every merged rule MUST retain its **provenance**: `template`, `profile`, or `request`.
2. A `deny` rule whose provenance is `template` or `profile` is a **binding deny**. Binding denies are evaluated at step 2 of §4.1 and MUST NOT be overridden by any `allow` rule, of any provenance, at any priority.
3. Within a single source, ordinary priority order applies: an `allow` rule with a lower number than a `deny` rule from the **same** source wins.
4. A request-level `allow` rule fully shadowed by a binding deny MUST NOT fail the create request. It MUST be reported as a `policyWarnings` entry `{field, rule, shadowedBy, source}` and emitted as an audit event, so the caller learns that the hole it asked for was not opened.
5. Provenance MUST be preserved in the effective policy exposed by the API, so an operator can see which source contributed each rule.

### 4.7 Connection state

Every rule in §4 describes a **connection**, not an individual packet:

| | Requirement |
| --- | --- |
| Return traffic | Traffic belonging to a connection already admitted MUST be permitted for the life of that connection, without a matching rule of its own. |
| Reply direction is not ingress | The inbound half of a sandbox-initiated connection is **not** ingress and MUST NOT be evaluated against `ingress` rules or `ingress.defaultAction`. Setting `ingress.defaultAction: deny` never breaks the response to an outbound request. |
| Connectionless protocols | For UDP and ICMP, "connection" means a flow tracked by the platform with a documented idle timeout. The reply-direction guarantee applies to such a flow exactly as it applies to TCP. |
| L4 port scoping | An L4 rule scopes the **destination** of the direction it governs. Reply traffic on an ephemeral port is permitted by connection state, not by a second rule. |
| L7 requests | Statefulness applies to the connection. Individual requests on an admitted connection are evaluated per §4.1, so a connection may be established and a later request on it still refused. |

This is written down rather than left to the data path because it is the property that makes a rule set reviewable. Under a stateless model every allow rule would need a companion reverse entry covering the ephemeral port range — simultaneously the thing every author forgets and, once written, a hole far wider than the rule it was meant to serve.

### 4.8 Violation actions

Per [overview.md](./overview.md) §8.1, `onViolation` decides what happens when §4.1 rejects a connection or a request:

| Action | Result |
| --- | --- |
| `deny` (default) | The connection fails as it does today: an `ECONNREFUSED`-class TCP reset for rejected TCP, a drop otherwise. A rejected L7 request receives a `403`. |
| `kill` | The **sandbox** is terminated. |

1. **`kill` here ends the sandbox, not the offending process.** L4 enforcement operates on packets, and by the time a connection is rejected the process that opened the socket is not reliably knowable at that layer. A best-effort attribution is worse than none, because it would terminate whichever process the guess landed on.
2. **A deployment setting `kill` is choosing "one rejected connection ends the sandbox".** That is a legitimate posture for a workload that should never reach an unnamed destination, and a destructive one for anything that probes. It MUST NOT be selected on the assumption that it behaves like `filesystem`'s or `process`'s `kill`, which are process-scoped.
3. **Where the enforcement point is a shared gateway rather than the sandbox's own data path, `kill` is asynchronous.** The gateway rejects the connection and the sandbox is terminated by a subsequent control-plane action, so a window exists in which the connection is already refused and the sandbox is still running. A deployment in that shape MUST declare `onViolation: kill` `partial` and document the bound on that window; it MUST NOT report a delayed termination as an immediate one.
4. There is no `warn`, on the terms of [overview.md](./overview.md) §8.1.2. `auditTier` (§6.1) is how a deployment learns which destinations a stricter posture would reject while keeping the current rules enforced.
5. Either action emits a violation event, at every audit level (§7).

### 4.9 Enforcement scope

Every module in this proposal enforces at the sandbox unit, and this one is no exception — but only because the sandbox unit was chosen to make it true:

1. This policy is enforced on the **network namespace** the sandbox occupies. On the VM substrate that namespace belongs to exactly one sandbox. On the container substrate the sandbox unit is one Pod ([overview.md](./overview.md) §12.1), and a Pod owns exactly one network namespace. On both substrates, therefore, scope and sandbox coincide.
2. That coincidence is the reason §12.1 makes the Pod the unit rather than the container. A per-container unit would place this policy at a scope wider than the sandbox, and no correct behaviour is available there: an enforcement point in the datapath or the egress path attributes a connection by source address, and co-located containers share one, so the platform could not determine whose policy to apply.
3. A deployment MUST NOT place two sandboxes in one network namespace. Where an implementation nonetheless does, the create request MUST be rejected with `400 POLICY_NETWORK_SCOPE_CONFLICT` carrying the conflicting fields and the sandbox that established the current configuration, rather than proceeding.
4. The platform MUST NOT resolve such a case by taking the strictest value, the union, or the most recent. Each of those silently makes one sandbox's policy govern another's traffic, which is both a boundary this object does not describe and the least debuggable failure it could produce.
5. Rule 3 is a create-time check against *resolved* configurations, not a textual comparison.

What this arrangement does not solve is the *other* half of the co-location question. Containers inside one Pod are inside one sandbox, so they share this policy by construction; but they also share one `policy.process` and one `policy.filesystem`, expanded across containers that may legitimately need different postures. That tension moved rather than vanished, and it is tracked as [overview.md](./overview.md) §11.14.

## 5. Merge semantics

On top of the shared rules in [overview.md](./overview.md) §5:

| Field | Merge refinement |
| --- | --- |
| `internal.mode` | Most restrictive wins: `deny` > `identity` > `allow`. A request MUST NOT set `allow` where a lower-precedence source set `deny` or `identity`; such a request is rejected with `400 POLICY_NETWORK_CONFLICT`. |
| `internal.allowedPeers` | **Intersection** across sources. A request cannot add a peer the template did not permit. |
| `egress.defaultAction`, `ingress.defaultAction` | `deny` wins. A request MUST NOT set `allow` where a lower-precedence source set `deny` (rejected with `400 POLICY_NETWORK_CONFLICT`). |
| `egress.rules`, `ingress.rules` | Append across sources. Each rule retains its provenance (§4.6). Priorities MUST NOT collide after merge (§4.5.3). `deny` rules from `template` or `profile` become binding. |
| `onViolation` | `kill` wins ([overview.md](./overview.md) §8.1.7). Given §4.8, a template setting `kill` makes every rejected connection fatal for sandboxes created from it, and a request cannot soften that. |
| `audit` | Most detailed wins (`metadata` > `none`). |

Rules are never merged by `name`. Two sources contributing a rule with the same name produce two rules, distinguished by provenance, and their priorities must still differ.

### 5.1 Grantable fields

Per [overview.md](./overview.md) §5.1.8, a time-bounded grant against this module may open:

| Grantable | Not grantable |
| --- | --- |
| `egress.rules` — named `allow` rules | `egress.defaultAction` / `ingress.defaultAction` |
| `ingress.rules` — named `allow` rules | `internal.mode` — any relaxation |
| `internal.allowedPeers` — named peers under `identity` | Removal of any `deny` rule |

`defaultAction` is excluded because it is not a hole of known shape ([overview.md](./overview.md) §5.1.4): flipping it opens every destination at once. A task that needs one more endpoint for ten minutes asks for that endpoint. `internal.mode` is excluded for the same reason plus a second one — under §2.2.3 relaxing it exposes the metadata endpoint, and a credential obtained during a ten-minute grant does not expire with it.

## 6. Defaults

A request that carries no `policy` object at all resolves to `tier: compatibility` ([overview.md](./overview.md) §7), which is today's behaviour:

```yaml
network:                 # tier: compatibility — legacy path only
  internal:
    mode: deny
  egress:
    defaultAction: allow
    rules: []
  ingress:
    defaultAction: allow
    rules: []
  onViolation: deny
  audit: none
```

A `policy` object that omits `tier` resolves to `restricted`. Per tier:

| | `compatibility` | `baseline` | `restricted` (default) |
| --- | --- | --- | --- |
| `internal.mode` | `deny` | `deny` | `deny` |
| `egress.defaultAction` | `allow` | `allow` | `deny` |
| `ingress.defaultAction` | `allow` | `deny` | `deny` |
| `audit` | `none` | `none` | `metadata` |

`internal.mode` is `deny` under **every** tier, including `unrestricted`. A tier is a default selector, and no default should make the private network reachable — that is a decision about a deployment's topology, which a tier cannot know. Reaching the private network is therefore always an explicit act, visible in the effective policy.

**`compatibility` is the only tier that leaves `ingress.defaultAction` at `allow`**, and it is the only one with a compatibility justification for doing so: a default-reachable sandbox is an availability default rather than a security one ([overview.md](./overview.md) §7.1). `baseline` sits between the two — outbound on, inbound off — for the common case of a workload that must fetch dependencies but should never be dialled into.

`onViolation` stays `deny` under every tier, per [overview.md](./overview.md) §8.1.7 — and emphatically so here, since a tier that paired deny-all egress with `kill` would terminate a sandbox on its first unnamed destination.

### 6.1 Shadow evaluation support

Per [overview.md](./overview.md) §7.2.5, this module supports shadow evaluation under `auditTier` for its full surface: both directions, `defaultAction`, every rule, and `internal.mode`. A connection or request the shadow set would have rejected proceeds anyway and emits a `shadow: true` audit event naming the destination, the port and protocol or the request line, and the shadow rule that would have rejected it.

This is the cheapest shadow in the proposal to act on, because the finding *is* the fix: a shadow report under `auditTier: restricted` is a list of the rules a deny-all posture would need. An operator can turn that list into the policy and then flip the tier.

Two module-specific points:

1. Statefulness (§4.7) applies to the shadow evaluation. A shadow finding is emitted once per connection at establishment — or once per request for an L7 rule — not once per packet.
2. `internal.mode` is `deny` under every tier (§6), so a shadow of a stricter tier produces no `internal` findings. A deployment that wants to know what tightening `internal` would cost sets it to a stricter value in a non-production profile; there is no tier that shadows it.

## 7. Errors

| Code | HTTP | Payload | When |
| --- | --- | --- | --- |
| `INVALID_POLICY` | 400 | `{field, reason}` | `l4` and `l7` both present or both absent (§2.1.2); empty `peer`; domain in an ingress `peer` (§2.3.2); `icmp` with `ports`; malformed CIDR, port, or matcher. |
| `POLICY_NETWORK_LIMIT` | 400 | `{map, got, max}` | An entry or rule count exceeds a §4.4 limit. |
| `POLICY_NETWORK_PRIORITY_CONFLICT` | 400 | `{direction, priority, rules, sources}` | Two rules in one direction share a priority after merge (§4.5.3). |
| `POLICY_NETWORK_CONFLICT` | 400 | `{field, legacyField?}` | A legacy field and the corresponding structured field are both present (§8); or a higher-precedence source widens `defaultAction` or `internal.mode` (§5). |
| `POLICY_NETWORK_SCOPE_CONFLICT` | 400 | `{fields, establishedBy}` | A sandbox would be placed into a network namespace another sandbox already occupies (§4.9.3). |
| `POLICY_UNSUPPORTED` | 400 | `{field, state, capabilityVersion}` | Under `enforcement: strict`, the policy names a field this deployment declares `unsupported`. Domain entries (§4.3) and `RegularExpression` matchers (§2.4.4) are the fields most likely to be in that state. |

Runtime rejections are **not** API errors. An L4 rejection surfaces to the sandbox as a connection failure; an L7 rejection surfaces as a `403`. Under `onViolation: kill` (§4.8) the sandbox is terminated instead, and the terminal state records the destination and the matched rule as the cause.

Every rejection MUST emit a violation event at **every** audit level, including `audit: none` ([overview.md](./overview.md) §8.1.4): `{sandboxID, direction, destination, port, protocol, requestLine?, rule?, provenance?, outcome: denied|killed, effectivePolicyVersion, shadow: false}`. What `audit: metadata` adds is the record of **ordinary** traffic — the part a deployment may reasonably decline. One event per connection, or per rejected L7 request.

Non-fatal findings are returned in a `policyWarnings` array on the create/update response. Defined warnings: a rule shadowed by a binding deny (§4.6.4), a `sandboxGroup` peer unreachable under `internal.mode: deny` (§2.3.4), and `metadata_endpoint_reachable` (§2.2.3).

## 8. Compatibility and legacy-field mapping

The legacy surface is permanent. Each legacy field is normalised into the structure of §2 at the API boundary; there is exactly one representation downstream.

| Legacy field (request) | Normalises to |
| --- | --- |
| `allow_internet_access: false` | `egress.defaultAction: deny` |
| `allow_internet_access: true` | `egress.defaultAction: allow` |
| `network.allow_out: [t]` | one egress L4 rule per entry: `{action: allow, priority: 40000+n, l4: {protocol: all, peer: {cidrs\|domains: [t]}}}` |
| `network.deny_out: [t]` | one egress L4 rule per entry: `{action: deny, priority: 30000+n, l4: {protocol: all, peer: {cidrs: [t]}}}` |
| `network.allow_public_traffic` | `ingress.defaultAction` (`true` → `allow`, `false` → `deny`) |
| `network.rules` | egress L7 rules, in list order, at `priority: 20000+n` |
| `network.mask_request_host` | an ingress L7 rule at `priority: 60000` carrying a Host-rewrite filter |

1. **Reserved priority bands.** Legacy normalisation uses `20000`–`49999`. An explicitly written rule MAY use any priority in `1`–`65535`, but a deployment that mixes explicit rules with legacy fields SHOULD stay outside the reserved band to keep §4.5.3 collisions from appearing on an upgrade.
2. Deny entries normalise to a lower number than allow entries, which reproduces today's outcome for the common legacy pairing without changing the general rule that priority decides order.
3. Conflict rule: a request containing any legacy network field **and** a non-empty `policy.network` MUST be rejected with `400 POLICY_NETWORK_CONFLICT` listing the conflicting pair. The system MUST NOT silently pick a precedence.
4. **`internal.mode: deny` is today's behaviour**, so a legacy request's private-range reachability is unchanged: previously an unconditional deny, now a deny that is visible in the effective policy and can be changed by an explicit act.
5. Template merge applies unchanged: a template's network configuration becomes the template-level default policy, and request rules merge per §5.

## 9. Acceptance criteria

1. Every existing egress behaviour test passes unmodified when the same values are supplied through legacy fields.
2. For every legacy-field combination, supplying the equivalent values through `policy.network` produces an identical effective configuration.
3. A request with both `network.allow_out` and `policy.network.egress.rules` is rejected with `400 POLICY_NETWORK_CONFLICT`.
4. **Symmetry.** An ingress rule and an egress rule with the same shape are both accepted, both appear in the effective policy with their priority and provenance, and both are enforced. A `peer.domains` entry on an ingress rule is rejected with `400 INVALID_POLICY`.
5. **Priority ordering.** With an egress `deny` at priority 100 and an `allow` at 200 covering the same destination, from the same source, the connection is rejected. Reversing the numbers admits it. Ordering does not depend on the order the rules appear in the list.
6. **Priority collision.** Two rules in one direction at the same priority after merge are rejected with `400 POLICY_NETWORK_PRIORITY_CONFLICT` naming both rules and their sources — including when one comes from a template and the other from the request.
7. **Priority does not confer authority.** A template `deny` rule at priority 60000 still rejects a connection that a request `allow` rule at priority 1 would admit (§4.6.2), and the request receives the shadowed-rule warning.
8. **L4/L7 exclusivity.** A rule carrying both `l4` and `l7` is rejected; a rule carrying neither is rejected.
9. **L7 implicit connection.** With `egress.defaultAction: deny` and a single `l7` allow rule for `https://api.example.com/v1` (PathPrefix), a TLS connection to that host on 443 is established, a `GET /v1/x` succeeds, and a `GET /other` receives a `403` while the connection stays up.
10. **L7 matchers.** With `method: GET`, `headers: [{Exact, X-Env, prod}]`, and `queryParams: [{Exact, v, 1}]`, only a `GET` carrying both matches; a request missing either proceeds to the next rule. A `cookies` entry matches a cookie parsed from the `Cookie` header.
11. **`internal.mode`.** Under `deny`, a connection to `10.0.0.5` fails even with an egress allow rule naming it at priority 1. Under `allow`, the same connection succeeds. Under `identity` with an `allowedPeers` entry naming a peer group, a sandbox in that group is reachable and an arbitrary address in the same range is not.
12. **Metadata endpoint warning.** A policy with `internal.mode: allow` and a `proxy`-exposure secret binding is accepted and carries the `metadata_endpoint_reachable` warning. With `internal.mode: deny`, a connection to `169.254.169.254` fails.
13. **Statefulness.** With `egress.defaultAction: deny`, one allow rule for a destination, and `ingress.defaultAction: deny` set at the same time, an outbound TCP connection to that destination succeeds **and its response is received** with no ingress rule present (§4.7).
14. **Restricted tier.** `tier: restricted` with no network fields resolves to `egress.defaultAction: deny`, `ingress.defaultAction: deny`, `internal.mode: deny`, and the effective policy records those expanded values.
15. **Shadow evaluation.** With `tier: baseline` and `auditTier: restricted`, a connection to an unnamed public destination **succeeds** and emits a `shadow: true` event naming the destination and the field that would have rejected it. Nothing observable inside the sandbox differs. One event per connection, or per L7 request.
16. **Violation action.** With `onViolation: deny`, a rejected connection fails and the sandbox keeps running. With `kill`, the same connection terminates the **sandbox**, and the terminal state names the destination and matched rule. A template setting `kill` cannot be softened by a request.
17. **Violations are audited at `audit: none`.** A rejected connection still emits a violation event carrying `shadow: false`, the direction, and the destination.
18. **Domain enforcement is honest.** A deployment that cannot guarantee it is the sandbox's only resolver declares domain entries `unsupported`, and under `enforcement: strict` a policy naming one is rejected with `400 POLICY_UNSUPPORTED` (§4.3.1).

## 10. Open questions

1. **Ingress authentication and exposure.** `ingress` now expresses port, protocol, source, and L7 matchers, which closes most of the asymmetry this module used to carry. What it still does not express is *authentication*: token binding, expiry, revocation, and the difference between "reachable" and "reachable by an authenticated caller". A public URL is a capability grant, and the minimum semantics for treating it as one are recorded in [overview.md](./overview.md) §11.18.
2. **Response-side L7 rules.** Every `l7` matcher describes a request. Should a rule be able to match a **response** — status, content type, size — so that a policy can express "may call this API but not download an executable from it"?
3. **Priority allocation.** §4.5.3 rejects collisions, which is safe but pushes priority allocation onto whoever composes template and request. Should the platform offer a sparse allocation convention, or a `priorityBase` per source, so that composition does not require coordination?
4. **`internal.mode: identity` and grouping.** `allowedPeers` presumes a sandbox grouping concept the control plane does not yet define. What identifies a group, who may add a sandbox to one, and is membership itself a policy field ([overview.md](./overview.md) §11.11)?
5. **Rate and reachability.** The outbound request-rate ceiling is a `resource.rate` field while reachability is here ([overview.md](./overview.md) §11.9). Should a `NetworkRule` carry its own rate ceiling, or does that recreate the dialect problem the unified object exists to prevent? Note that both live on the same L7 enforcement point ([resource.md](./resource.md) §5.1), so the obstacle is the object model rather than the mechanism.
6. **Flow timeouts as policy.** §4.7 requires a documented idle timeout for connectionless flows but leaves the value to the platform. Should it be a policy field?
7. **IPv6.** `peer.cidrs` is IPv4 in v1, and `internal` names IPv4 private ranges. IPv6 needs its own range set (`fc00::/7`, `fe80::/10`, and the metadata address some clouds expose) before it can be supported honestly. Confirm that v1 is IPv4-only and that an IPv6 literal is rejected rather than ignored.

## 11. Non-normative notes

- **Implementation paths.** L4 rules, connection state (§4.7), and priority ordering are commodity on both substrates ([overview.md](./overview.md) §12.2): packet filtering, conntrack, and an ordered rule set. Two surfaces are not. **Domain entries** need name-resolution-time learning wired into the filter plus exclusive control of the resolver (§4.3.1). **L7 matchers** need a proxy in the path that terminates the connection — and for `https`, that means terminating TLS, without which only the SNI is visible and `path`, `headers`, `queryParams`, and `cookies` cannot be evaluated at all. A deployment that terminates TLS is reading its tenants' traffic in cleartext at that point, which is a decision with its own compliance weight; a deployment that does not MUST declare those matchers `unsupported` rather than silently matching on SNI alone.
- The L7 proxy this module needs for `l7` rules is the same component [identity.md](./identity.md) §3.1 needs for `exposure: proxy` and [resource.md](./resource.md) §14 needs for token metering. One mechanism, three modules — which is the strongest argument for building it first.
- **On following `HTTPRoute` rather than inventing.** The matcher shapes in §2.4 are deliberately Gateway API's, down to the `type` enums, because an operator who has written an `HTTPRoute` should not have to learn a second grammar for the same job. The two additions are stated as additions: `cookies` (§2.4.3), which `HTTPRoute` folds into headers, and `action: deny`, which `HTTPRoute` has no notion of because a route is not a firewall.
- **Rejected alternative — implicit isolation.** A Kubernetes NetworkPolicy flips its target to default-deny for a direction as soon as any policy selects it. It is attractive, because it makes the common intent impossible to express incompletely. It is rejected here because `defaultAction` says the same thing explicitly and in one visible place, whereas implicit isolation would silently convert every existing configuration that lists a few allow entries alongside general internet access into a deny-all sandbox.
- **Rejected alternative — one merged rule list for both directions.** A single list with a `direction` field per rule is more compact and is what some security-group APIs do. It is rejected because priority uniqueness (§4.5.3) is per direction, and a shared list would either make the constraint global — coupling inbound and outbound numbering for no reason — or require a compound key that readers would have to remember.
- **On `kill` and attribution.** §4.8's sandbox-scoped `kill` is not a shortcoming of one substrate. Neither a packet filter on a tap device nor a CNI datapath has reliable process context at the point a connection is rejected; both would have to guess. Where the enforcement point is a shared gateway, the action is additionally asynchronous (§4.8.3), which is a second reason to prefer `deny`.
