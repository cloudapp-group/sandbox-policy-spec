# Spec: Resource Policy

Part of [Proposal 0001 — Sandbox Security Policy](./overview.md). The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as described in RFC 2119.

---

## 1. Scope

This spec defines the `resource` sub-policy of the `SandboxPolicy` object. The module is named **resource** because that is exactly what it governs: what a sandbox may consume. It covers three contracts:

- **Rate ceilings** — how *fast* the sandbox may consume: outbound request rate and concurrency, disk read/write throughput and IOPS. A ceiling is **shaped**, never failed: excess is queued and paced down (§3.1).
- **Budgets** — windowed *amounts* of the one thing that accumulates irreversibly: LLM tokens, per `minute`, `hour`, `day`, `week`, or `month` window, or over the sandbox's whole `lifetime`.
- **Governance** — what happens when a budget is exhausted: warn, pause, terminate, or **hold for human intervention**, plus notifications so a human learns about it in time.

The rate/amount split is what decides where `onExceeded` lives. A ceiling cannot be exceeded — it is a speed, and traffic above it waits — so it has no action, no event, and no held state. A budget can be exhausted, and something has to happen when it is. Tokens are the only budget here, which is why `onExceeded` appears only under `tokens` (§6). That is a consequence of the structure rather than a rule to remember.

The same split is the seam between this module and `network`: `network` decides *what may be reached*, `resource` decides *how much may flow*. A request-rate ceiling is consumption, so it is a rate here rather than a field on an egress rule ([overview.md](./overview.md) §11.9).

**What this module deliberately no longer covers.** An earlier revision carried `quota.cpuMillicores`, `quota.memoryMiB`, `limits.cpuSeconds`, `limits.netEgressBytes`, and `limits.diskWriteBytes`. All are removed. Bounding CPU and memory is a standard operational action every orchestrator and VMM already performs — a Kubernetes `resources.limits` block, a Cloud Hypervisor `--cpus` / `--memory` argument — and restating it here made the policy object appear to own a decision it merely echoed. Byte totals went for a different reason: an accumulated byte count is a poor proxy for the harm it was standing in for. What actually degrades a shared substrate is *rate*, and what actually costs money is tokens. What remains is the consumption surface generic ops tooling does not bound.

The cost is stated rather than left to be discovered. `limits.cpuSeconds` was this proposal's only enforcement against runaway loops ([overview.md](./overview.md) §2.3). Containment for that threat now rests on the idle-timeout lifecycle and on the token budget, and for an agent loop the token budget is the binding constraint in practice: a loop that calls a model burns tokens, and a loop that does not burns CPU the orchestrator's own quota already caps. What is genuinely lost is the case in between — a sandbox spinning on local computation for hours, inside its CPU quota, calling nothing. That is now an operational concern and this object no longer claims otherwise.

Out of scope: billing and pricing (the usage exposure below is the contract billing builds on); idle timeouts and lifecycle (existing behavior, unchanged — except that it remains applicable to held sandboxes, §7).

## 2. Object model

```yaml
policy:
  resource:
    rate:                                  # ceilings: shaped, never exceeded (§3.1)
      network:
        requestsPerSecond:     int         # outbound requests/s
        maxConcurrentRequests: int         # outbound requests in flight
      disk:
        readBytesPerSec:       int
        writeBytesPerSec:      int
        readIops:              int
        writeIops:             int
    limits:
      tokens:
        onExceeded: warn | pause | hold | kill   # default for the three below
        input:                             # prompt tokens
          windows:  {minute?, hour?, day?, week?, month?, lifetime?}
          onExceeded?: action
        output:                            # completion tokens
          windows:  {minute?, hour?, day?, week?, month?, lifetime?}
          onExceeded?: action
        total:                             # input + output
          windows:  {minute?, hour?, day?, week?, month?, lifetime?}
          onExceeded?: action
    notifications:
      thresholds:      [number]            # fractions of each limit; default [0.8, 1.0]
      webhook:         URL                 # optional delivery endpoint
```

Budget dimensions: `tokens.input`, `tokens.output`, `tokens.total`. The three are independent: each configured dimension is enforced on its own counters.

## 3. Field specification

| Field | Type | Constraints | Default | Semantics |
| --- | --- | --- | --- | --- |
| `rate.network.requestsPerSecond` | `int?` | > 0 | unset = unlimited | Ceiling on outbound requests per second (§3.1, §5.1). |
| `rate.network.maxConcurrentRequests` | `int?` | > 0 | unset = unlimited | Ceiling on outbound requests in flight at once. |
| `rate.disk.readBytesPerSec` | `int?` | > 0 | unset = unlimited | Read throughput ceiling on the sandbox's block devices. |
| `rate.disk.writeBytesPerSec` | `int?` | > 0 | unset = unlimited | Write throughput ceiling. |
| `rate.disk.readIops` | `int?` | > 0 | unset = unlimited | Read operations per second ceiling. |
| `rate.disk.writeIops` | `int?` | > 0 | unset = unlimited | Write operations per second ceiling. |
| `limits.tokens.<dimension>.windows` | `map?` | Keys from `{minute, hour, day, week, month, lifetime}`; values > 0. Multiple windows MAY be set and are enforced independently. | unset (no limit) | Maximum token consumption per window (§4). |
| `limits.tokens.<dimension>.onExceeded` | `enum?` | `warn` \| `pause` \| `hold` \| `kill` | `limits.tokens.onExceeded` | Action when any window of this dimension is exhausted. |
| `limits.tokens.onExceeded` | `enum?` | same | `hold` | Default action for the three token dimensions. |
| `notifications.thresholds` | `[number]?` | Each in (0, 1]. Sorted ascending. | `[0.8, 1.0]` | Fractions of each configured limit at which a notification is emitted. |
| `notifications.webhook` | `string?` | `https` URL | unset | Endpoint receiving notification events (§8). |

Zero or negative rates and limits, empty `windows` maps, and thresholds outside (0, 1] MUST be rejected with `400 INVALID_POLICY`.

`lifetime` is the never-resetting window: a budget for the sandbox's whole existence. The five periodic windows reset at their boundaries (§4.1).

### 3.1 Rate ceiling semantics

Every field under `rate` is a ceiling, and ceilings behave unlike budgets in a way that has to be fixed here rather than per field: they do not have an exceedance transition, because they cannot be exceeded.

1. Work above the ceiling MUST be **shaped** — queued and paced down to the ceiling — not rejected. There is no `onExceeded` action for any `rate` field, no `resource.exhausted` event, and no held state. A sandbox at its ceiling is a slow sandbox, not a failing one.
2. **A ceiling is defined as an average over an interval, and the interval MUST be stated.** A deployment MUST meet each configured ceiling when averaged over any window of 1 second or longer, and MUST NOT deliver less than 90% of the configured rate to a workload that continuously demands at least the ceiling. Instantaneous bursts above the ceiling MAY occur and are not a violation.

   This clause exists because the common implementation is a token bucket with a refill period and a stall interval, and such a bucket can deliver a small fraction of its nominal rate when the refill period is short relative to the stall. A configured 1000 IOPS can arrive as 100 IOPS from a defensible-looking configuration. Without a stated averaging interval two deployments would resolve the same field to rates an order of magnitude apart and both would declare it `enforced` ([overview.md](./overview.md) §8.2), which is the failure that section exists to prevent.
3. Unset means unlimited: the sandbox is bounded only by the platform's own capacity. Zero MUST be rejected with `400 INVALID_POLICY` — a sandbox that may reach a destination (`network`) but may not send a request to it is a configuration whose failure mode is indistinguishable from a broken network, which principle 4 exists to prevent. "Send nothing" is expressed in `network`, where the denial is explainable.
4. **Shaping MUST be observable.** Each ceiling that has delayed work MUST report the accumulated delay it caused, per field, through usage exposure (§9.3). Shaping produces no events and no failures, which means an unobservable ceiling turns "my sandbox is slow" into a question nobody can answer from the platform's own records. Principle 4 requires a denial to be explainable; the same reasoning applied to a ceiling requires a slowdown to be attributable, and attributable means naming the field.
5. Ingress shaping is not specified. Inbound traffic is not the sandbox's consumption to control, and a ceiling the workload cannot influence is not a policy field (§13.11).
6. Ceilings and budgets are independent and MUST be enforceable together. A request-rate ceiling reduces the rate at which a token window fills; it never substitutes for the window.

## 4. Window semantics

### 4.1 Window definition and alignment

All windows are fixed and aligned to UTC:

| Window | Period | Resets at |
| --- | --- | --- |
| `minute` | 60 s | top of each UTC minute |
| `hour` | 3600 s | top of each UTC hour |
| `day` | 24 h | 00:00 UTC each day |
| `week` | 7 days | 00:00 UTC each Monday (ISO-8601) |
| `month` | calendar month | 00:00 UTC on the first day of each UTC month |
| `lifetime` | — | never resets |

### 4.2 Counters

1. Each (sandbox, dimension) pair has an append-only usage stream; a window's counter is the sum of usage within the current window period; the `lifetime` counter is the total since sandbox creation.
2. A window counter MUST be non-decreasing within its window and resets to zero at rollover. The lifetime counter MUST be monotonically non-decreasing.
3. Counters persist across pause/resume; resume never resets usage.
4. Snapshot restore / clone: the restored sandbox inherits the **policy** (limits, ceilings, actions, notifications) of the source; all counters, including lifetime, start from zero at the restore point. (Whether operators may choose counter inheritance instead is an open question, §13.)

### 4.3 Enforcement

1. Every configured window is enforced independently: when any window's counter first reaches its limit, that dimension's action (§6) triggers.
2. Multiple windows of the same dimension share the dimension's `onExceeded`.
3. If several dimensions or windows are exhausted at the same observation, the most severe action among them wins: `kill` > `hold` > `pause` > `warn`.
4. Checks SHOULD run both periodically and at each metering boundary so minute-granularity limits act promptly. Overshoot between checks MUST be absorbed: the action triggers on the first observation at-or-over the limit, and reported usage MAY exceed the limit by up to the observation granularity.
5. Periodic exhaustion is re-armed by rollover: a dimension that exhausts its `minute` window at 10:07:30 and rolls into a fresh window at 10:08:00 may consume again, and a new exhaustion in the fresh window is a new transition with its own events.

## 5. Metering semantics

### 5.1 Measurement points

| Surface | Measured where |
| --- | --- |
| `rate.network.*` | The platform's outbound request path — the same L7 enforcement point `network` L7 rules use ([network.md](./network.md) §2.4). A *request* is one HTTP request; connection reuse does not make several requests into one. |
| `rate.disk.*` | The sandbox's block layer, in each direction, counting operations issued to the device. |
| `tokens.*` | LLM API tokens, per §5.2. |

`rate.network.*` counts requests rather than connections deliberately. A single keep-alive connection can carry an unbounded number of requests, so a connection ceiling would not bound what these fields are for. The consequence is a real dependency and is not smoothed over: a deployment with no L7 enforcement point in the egress path cannot meter requests at all and MUST declare both `rate.network` fields `unsupported` ([overview.md](./overview.md) §8.2). Whether a connection-level ceiling should exist as a fallback for such deployments is an open question (§13.14).

### 5.2 LLM token truth sources

Explicit precedence, because token usage is knowable only from the API transaction itself:

1. **Response-side accounting (preferred).** When a sandbox request to an LLM API flows through the platform's outbound HTTP/HTTPS path, the `usage` field of the response is authoritative for that request's token counts.
2. **Explicit report (fallback).** `sandbox.report_usage()` on the SDK lets the caller report usage that response-side accounting cannot observe (non-HTTP providers, providers that omit `usage`). It MUST be authenticated as a principal authorized to manage the sandbox, on the same terms as the approval API (§7.4) — untrusted in-sandbox code MUST NOT be able to write its own counters.

### 5.3 Streaming, retries, and partial consumption

In practice most token spend arrives over streamed responses that may be retried or cut short. Leaving those cases to the implementation guarantees a billing dispute later, so the accounting is fixed here.

| Case | Rule |
| --- | --- |
| Non-streamed response | The response's `usage` is authoritative; metered once, on completion. |
| Streamed response completing normally | Metered when the stream terminates; the `usage` payload of the **final chunk** is authoritative. |
| Streamed response terminating **without** a `usage` payload — client abort, sandbox timeout, transport error, provider omission | Usage MUST still be metered, from an **estimate** derived from the content actually observed on the wire. Metering MUST NOT be skipped: skipping it would make "abort just before the final chunk" a free-token bypass. |
| Retry, whether the sandbox retried or the platform did | Each provider attempt is metered **independently**, because providers bill per attempt. |
| Attempt that produced no tokens — connection failure, or an HTTP error before any content | Meters zero. |
| Sandbox killed or paused mid-request | Metered by the rules above. Ending a sandbox does not erase consumption already incurred. |

1. An estimate MUST be a **lower bound** on actual usage: it counts what was observed and never adds a speculative markup. This keeps the corrections in §5.4 additive, and keeps the platform from over-charging for its own uncertainty.
2. Platform-internal retries MUST be attributed to the sandbox that caused them.
3. These rules govern *metering*. Whether a metered amount is *billable* is a pricing question and out of scope (§1).

### 5.4 Provenance and corrections

1. Every metered amount carries a `provenance` flag: `response` (an authoritative `usage` payload), `estimated` (§5.3), or `reported` (§5.2.2).
2. Provenance MUST be exposed through usage (§9) so a platform can bill, alert on, or reconcile estimated amounts differently from authoritative ones.
3. If an authoritative `usage` payload for a request arrives after an estimate was already metered, the difference MUST be applied as an additional **positive** delta. A negative correction MUST NOT be applied, because window and lifetime counters are non-decreasing (§4.2.2) — the lower-bound requirement of §5.3.1 is what makes this sound rather than merely convenient.
4. Counters MUST NOT be incremented from inside the sandbox by untrusted code.

## 6. Exceed actions

| Action | Semantics |
| --- | --- |
| `warn` | Emit the exhaustion event only. For observability pilots, not protection. |
| `pause` | Suspend the sandbox. It becomes resumable once every triggering window has rolled over, and SHOULD auto-resume at that point; a policy update raising the limit also releases it. Minute/hour windows therefore act as throttles, month/lifetime windows as circuit breakers. |
| `hold` | Suspend the sandbox and wait for a human decision (§7). Does **not** auto-release at window rollover. |
| `kill` | Terminate immediately; the terminal state records the dimension and window as the cause. |

Action resolution: `limits.tokens.<dimension>.onExceeded` if set, else `limits.tokens.onExceeded`.

`onExceeded` applies to token budgets and to nothing else. There is no resource-wide default because there is nothing else for it to default: `rate` fields are shaped and have no action (§3.1.1), so an action sitting at the top of the module would apply to exactly one subtree while appearing to apply to all of it. Deployments that later add a second budget dimension will need to decide whether the action moves up; until then it stays where it means something.

The default is `hold`: configuring a limit is opting into governance, and hold is the only action that is both safe (consumption stops) and reversible (no data loss) while leaving the final say to a human. Deployments without an on-call workflow SHOULD set `warn` or `pause` explicitly — held sandboxes remain subject to the standard idle-timeout lifecycle, so an unattended hold cannot leak resources forever.

`onExceeded` is this module's only response field: per [overview.md](./overview.md) §8.1.6, there is **no `onViolation` here**. The two are not alternatives that happened to land in different modules — they answer different questions, and §8.1.1 fixes which is which. An exhaustion means the workload stayed inside every boundary it was given and ran out of budget; a violation means it crossed one. That is why this action set has `warn` and `hold` while `onViolation` has neither: there is something for a human to decide about "needs more budget", and a warning about overspending leaves no protection disabled, because a budget was never a protection against intent.

The one action both sets share is `kill`, and even it differs in scope. Here it terminates the **sandbox**, because consumption is a sandbox-level quantity with no single guilty process — the same granularity `network` is forced into for a different reason ([overview.md](./overview.md) §8.1.3).

`policy.tier` ([overview.md](./overview.md) §7.1) does not change anything in this module. Every tier resolves to no ceilings, no windowed limits, and `onExceeded: hold` — the last of which is already the default above. This is stated rather than omitted because a reader who sees four modules shift under `tier: restricted` is entitled to know that the fifth deliberately does not: consumption budgets are workload-specific numbers, and there is no value for `tokens.total` that is "the restricted one". A tier that guessed would be a tier that breaks workloads for a security posture it cannot actually improve.

### 6.1 Shadow evaluation support

Per [overview.md](./overview.md) §7.2.5, this module states its position: **it has no shadow evaluation, because it has nothing to shadow.**

The reasoning is the paragraph above. Shadow evaluation compares an enforced tier against a stricter one, and no tier changes any field here. There is no stricter set of limits for `auditTier: restricted` to evaluate against, so `auditTier` naming this module resolves to no findings — not because the mechanism is missing, but because the comparison is empty.

This is not a gap to be closed later by adding shadow support. If it is ever worth answering "what would a tighter budget have blocked?", the answer already exists and is better: `onExceeded: warn` (§6) is that feature, arrived at from the other direction. A deployment that wants to observe a candidate limit sets the limit with `warn`, and gets exhaustion events with real counters rather than a parallel evaluation of a number nobody has chosen. Two mechanisms for one outcome is what §10.1 already declines for grants, and the reasoning transfers unchanged.

The distinction worth keeping straight: a shadow finding elsewhere in the proposal means "this operation would have been refused". Here the equivalent question is "this budget would have been exhausted", which is about a counter reaching a value rather than a decision about an operation — and counters are what this module exposes for real (§9) rather than in shadow.

## 7. Human intervention (hold)

1. On a `hold` action the sandbox enters the **held** state: execution suspended (pause-equivalent), and a `resource.hold_requested` notification MUST be emitted immediately (independent of `notifications.thresholds`).
2. Held sandboxes do not auto-release. Release happens only through the approval API or a policy update.
3. Approval API:

   ```yaml
   # POST /sandboxes/{sandboxID}/resource/approval
   dimension:  tokens.total      # optional; omit to decide all current holds
   window:     month             # optional; omitted with dimension → all holds of that dimension
   decision:   approve           # approve | deny
   allowance:  1000000           # approve only, optional: extra headroom for the current window period
   raiseLimit: 60000000          # approve only, optional: persistent limit raise for this sandbox
   ```

   - `approve` resumes the sandbox. `allowance` adds to the current window period's allowance only (reverts at rollover); `raiseLimit` updates the sandbox's effective limit persistently.
   - For a `lifetime` window an allowance never reverts (lifetime has no rollover): it is a permanent addition for the sandbox's remaining existence.
   - `deny` terminates the sandbox.
4. Authorization: approvals MUST be performed through the control-plane API by an authenticated principal authorized to manage the sandbox (owner/operator). The approval API MUST NOT be callable from within the sandbox or with sandbox-scoped credentials — untrusted agent code must not be able to approve its own hold.
5. Every approval MUST be audited: approver identity, target, decision, and any allowance/raise.
6. Held sandboxes remain subject to the standard idle-timeout lifecycle (kill/pause on idle), so abandoned holds are eventually reclaimed.

## 8. Notifications

1. **Threshold notifications.** When any (dimension, window) counter crosses a configured threshold fraction of its limit, a `resource.notification` event MUST be emitted, at most once per threshold per window period: `{sandboxID, dimension, window, used, limit, threshold, at}`.
2. **Exhaustion events.** Every exhaustion transition MUST emit `resource.exhausted`: `{sandboxID, dimension, window, used, limit, action}`.
3. **Hold events.** `resource.hold_requested` (§7) on every hold; `resource.approved` / `resource.denied` record the decision and the approver.
4. **Delivery.** When `notifications.webhook` is configured, events MUST be delivered as HTTPS POST with the JSON payload above, at-least-once, with bounded retries. Webhook authentication/signature is an open question (§13). Events MUST also be available through the platform's event stream regardless of webhook configuration.
5. Notification payloads MUST NOT include sandbox data beyond the counters themselves.
6. Shaping emits no events (§3.1.1). It is reported through usage (§9.3) instead, because a ceiling that delayed work has nothing for a recipient to act on — only something for an operator to look up.

## 9. Usage exposure

1. `GET /sandboxes/{sandboxID}` MUST include a `resource` object:

   ```yaml
   resource:
     rate:
       network: { requestsPerSecond: 50, maxConcurrentRequests: 16 }
       disk:    { writeBytesPerSec: 52428800, writeIops: 2000 }
     shaped:
       requestsPerSecond: { delayedSec: 12.4, delayedOps: 318 }
       writeBytesPerSec:  { delayedSec: 3.1,  delayedOps: 20481 }
     usage:
       tokens:
         total:
           current:    { minute: 3500, day: 155000, lifetime: 1200000 }
           limits:     { minute: 10000, day: 1000000, month: 50000000 }
           provenance: { response: 1150000, estimated: 40000, reported: 10000 }
     state: { held: false, exhausted: [] }
   ```

2. `limits` reports the effective configured windows; `current` reports the in-window counters for the configured windows. Lifetime counters MUST be reported even when no lifetime limit is configured (billing needs them).
3. `rate` reports the ceilings that are set and omits those that are unlimited. Ceilings have no `usage` entry — a rate has no counter (§3.1) — and are instead accompanied by `shaped`, which is keyed by the ceiling field that caused the delay. `delayedSec` is the lifetime-cumulative time work spent waiting on that ceiling and MUST be monotonically non-decreasing; `delayedOps` is the number of requests or I/O operations that waited. A ceiling that has never delayed anything MAY be omitted from `shaped`. Naming the field is the point: it is what turns "the sandbox is slow" into "the sandbox is at its write ceiling" (§3.1.4).
4. For token dimensions, `provenance` reports the lifetime split of how the amounts were learned (§5.4). The three values MUST sum to the lifetime counter, so a tenant can see how much of a bill rests on estimates.
5. `state.exhausted` lists the currently-exhausted (dimension, window) pairs; `state.held` is true while a hold is pending.
6. The SDK exposes the same object as `sandbox.resource`.

## 10. Merge semantics

On top of [overview.md](./overview.md) §5:

| Field | Merge refinement |
| --- | --- |
| `rate.*` | Minimum of the set values wins, per field. A source that sets nothing keeps the lower-precedence value. A higher-precedence source cannot *raise* a ceiling set by a lower-precedence source, nor unset it. |
| `limits.tokens.*.windows` | Per (dimension, window): minimum of set values wins; a dimension set by no source is unlimited. A higher-precedence source cannot *remove* a limit set by a lower-precedence source. |
| `onExceeded` (dimension default and per-dimension) | Most severe wins: `kill` > `hold` > `pause` > `warn`. |
| `notifications.thresholds` | Union across sources, deduplicated, sorted ascending. |
| `notifications.webhook` | Union across sources (additive observability). |

**This module now has no merge exception.** The previous revision carried one: `quota.cpuMillicores` and `quota.memoryMiB` kept override semantics rather than narrow-only, because that was the existing template behaviour and changing it would have broken callers ([overview.md](./overview.md) §9). Removing those fields (§1) removes the carve-out with them, so every field here is narrow-only and the shared merge principle holds without qualification — which is worth recording, because §5 of overview.md is easier to reason about with one fewer documented exception.

### 10.1 Grantable fields

Per [overview.md](./overview.md) §5.1.8 every module declares its grantable surface. **This module has none.** No `resource` field may be widened by a time-bounded grant.

Temporary additional consumption is already a first-class operation here, and it has a different shape from a grant: the approval API (§7.3) is driven by a **hold**, so a human decides at the moment the sandbox actually needs more, with the exhausted counters in front of them. A grant is a pre-authorization issued before the need is demonstrated. Adding grants to this module would give the same outcome two mechanisms, one of which discards the information the other is built on.

`rate` fields are not grantable either, and for them the reason is simpler: a grant relaxes a restriction for a bounded time, and a ceiling that is temporarily raised is just a different ceiling. Nothing is being refused, so there is nothing to relax.

> **Terminology.** The `allowance` field of the approval API (§7.3) is deliberately *not* called a grant. It adds headroom to a window counter and has no TTL of its own — it reverts at window rollover, or never, for `lifetime` — which makes it a different mechanism from the time-bounded grants of [overview.md](./overview.md) §5.1. Both were briefly named `grant`; this field was renamed rather than leave one word meaning two things in one object.

## 11. Errors

| Code | Surface | Payload | When |
| --- | --- | --- | --- |
| `INVALID_POLICY` | 400 | `{field, reason}` | Non-positive rate or limit, invalid window key, threshold outside (0, 1]. |
| `POLICY_RESOURCE_EXHAUSTED` | terminal state / event | `{dimension, window, used, limit, action}` | Exhaustion with action `kill` (or an approval `deny`). |
| `POLICY_RESOURCE_HELD` | sandbox state / event | `{dimension, window, used, limit}` | Sandbox held pending approval. |
| `POLICY_UNSUPPORTED` | 400 | `{field, capabilityVersion}` | A `rate` field this deployment declares `unsupported` was named under `enforcement: strict` ([overview.md](./overview.md) §8.2). |
| approval errors | 400 / 409 | `{reason}` | Approval targets no current hold, or invalid allowance/raise. |

No error exists for reaching a ceiling, because reaching a ceiling is not a failure (§3.1.1).

## 12. Acceptance criteria

1. Multi-window enforcement: with `tokens.total` limited per `minute` (action `pause`) and per `month` (action `hold`), a burst over the minute limit pauses the sandbox, which becomes resumable (and auto-resumes) at minute rollover; crossing the month limit holds it for approval.
2. Rollover re-arms: after the minute window resets, consumption up to the new limit proceeds without events until a new threshold/exhaustion transition.
3. Hold requires a human: a held sandbox does not resume at window rollover; `approve` (with or without allowance/raise) resumes it; `deny` terminates it; an allowance of N permits at most N further units in the current period.
4. The approval API rejects calls authenticated with sandbox-scoped credentials.
5. Threshold notifications fire at most once per threshold per window period; exhaustion and hold events fire on every transition.
6. Lifetime counters are monotonic and reported even without a lifetime limit.
7. Simultaneous exhaustion resolves to the most severe action.
8. Restore/clone: policy inherited, all counters zero.
9. Merged per-window limits and merged ceilings both take the minimum; merged actions take the most severe.
10. **Streaming.** A stream that completes normally meters the final chunk's `usage` with provenance `response`. The same stream aborted before its final chunk still meters a non-zero amount with provenance `estimated`, and that amount is no greater than what the completed stream metered.
11. **Retries.** Three provider attempts that each return `usage` meter three times; an attempt that fails before any content meters zero. Platform-initiated retries are attributed to the originating sandbox.
12. **Late correction.** An authoritative `usage` arriving after an estimate applies a positive delta only; no counter ever decreases.
13. **Provenance exposure.** The `response` / `estimated` / `reported` split is reported and sums to the lifetime counter.
14. `report_usage` called with sandbox-scoped credentials is rejected.
15. **Ceilings shape rather than fail.** With each `rate` field set in turn, a workload demanding more than the ceiling completes at approximately the configured rate; no request is refused, no I/O returns an error, no `resource.exhausted` event is emitted, and the sandbox is never paused, held, or killed by the ceiling. With the field unset, the same workload is not rate-limited.
16. **Ceiling accuracy.** For each `rate` field, a workload demanding at least the ceiling for 10 seconds achieves between 90% and 100% of the configured rate averaged over any 1-second interval within that period (§3.1.2). A deployment whose token bucket delivers materially less fails this criterion and MUST NOT declare the field `enforced`.
17. **Request counting.** With `requestsPerSecond: N`, N+1 HTTP requests issued over a **single** keep-alive connection are shaped as N+1 requests, not as one connection (§5.1).
18. **Shaping is attributable.** After a period of shaping, `resource.shaped` names the ceiling field that delayed the work, with a non-zero monotonic `delayedSec`. A ceiling that never delayed anything reports nothing.
19. **Ceilings and budgets are independent.** A sandbox with `rate.network.requestsPerSecond` set and a `tokens.total` window still triggers that window's action when the budget is reached; shaping only delays when that happens.
20. **Unsupported rate fields.** Under `enforcement: strict`, naming a `rate` field the deployment declares `unsupported` is rejected with `400 POLICY_UNSUPPORTED`; under `bestEffort` it is accepted and reported inert.

## 13. Open questions

1. **Timezone.** Windows align to UTC. Should deployments be able to align `day`/`week`/`month` to a local timezone?
2. **Sliding windows.** Fixed windows are simple but allow a 2× burst at boundaries (full quota at the end of one window and the start of the next). Are sliding windows needed, or is that acceptable for v1?
3. **Auto-resume.** Should `pause` auto-resume at rollover (proposed SHOULD) or require an explicit resume?
4. **Webhook authentication.** HMAC signature scheme? Where are shared secrets stored?
5. **Approval RBAC.** Which principals may approve: sandbox owner only, namespace operators, or anyone with cluster admin?
6. **Allowance visibility.** Should approved allowances appear in `resource.usage`, so platforms can bill for approved overage and an operator can see how much of the current window is headroom rather than budget? The naming collision that used to sit here is resolved: this field is `allowance`, and `grant` means only the time-bounded policy relaxation of [overview.md](./overview.md) §5.1.
7. **Per-window actions.** Should `onExceeded` be settable per window rather than per dimension (e.g. `minute`→`pause`, `month`→`hold` on the same dimension)?
8. **Counter inheritance on restore/clone.** Reset is proposed here; should inheritance be available as an operator choice?
9. **Estimation method.** §5.3 fixes the *properties* of an estimate (lower bound, derived from observed content) but not the algorithm. Should the algorithm and its expected error be published, so tenants can audit the estimated portion of their usage?
10. **Cached and reasoning tokens.** Providers increasingly meter cache reads and reasoning tokens separately. Do those become their own dimensions, or fold into `input` / `output`?
11. **Ingress shaping.** §3.1.5 specifies outbound only. Should an inbound ceiling exist for sandboxes that serve public traffic (`network.ingress`), and if so, is it a `resource` field at all, given that the sandbox does not choose how much arrives?
12. **Disk footprint, and writes the substrate cannot attribute.** Two gaps remain after the move from byte totals to rates. Nothing bounds total footprint on disk — a sandbox can fill a volume slowly and stay under every ceiling — so a size limit may still be needed, and it would be an amount rather than a rate, which is the one place a non-token budget would reappear. Separately, `rate.disk.*` is only enforceable where the substrate attributes I/O to the sandbox; §14 records where it does not. Should the spec require a deployment to state *which* writable areas its disk ceilings cover, the way [filesystem.md](./filesystem.md) requires path rules to be enumerated?
13. **Per-destination rate.** A request-rate ceiling is per sandbox. Whether a rate can be attached to a single egress rule is the mirror of this question and is tracked in [network.md](./network.md) §10.5; it must be answered once, not twice.
14. **Concurrency without an L7 enforcement point.** `rate.network.*` counts requests, so a deployment with no proxy in the egress path declares both fields `unsupported` (§5.1) and has no concurrency ceiling at all. A connection-level ceiling would be enforceable there from conntrack alone. Should one exist as a documented fallback, accepting that connections and requests are different quantities and that a keep-alive workload would slip past it?

## 14. Non-normative notes

- Token counters come from the outbound HTTP path; disk and request counters come from the substrate's own accounting. The spec fixes only the semantics above.
- Shaping is the one contract here that is enforced rather than metered: the platform paces the sandbox instead of counting it. The `shaped` counters of §9.3 exist so that pacing is still visible, which is why §3.1.4 makes them normative rather than leaving observability to each deployment.
- **Substrate mapping.** Both substrates expose byte-rate and operation-rate limits through a single interface, so `readIops` / `writeIops` cost a deployment nothing beyond `readBytesPerSec` / `writeBytesPerSec`. On the container substrate that interface is the cgroup v2 IO controller, whose `rbps` / `wbps` / `riops` / `wiops` keys delay I/O when a limit is reached — which is the shaping semantics of §3.1.1 rather than an approximation of it. On the VM substrate it is the VMM's per-disk rate limiter, with independent bandwidth and operation buckets. The VM case has a property worth noting because it inverts the pattern the rest of the proposal has: the limiter runs in the VMM, *outside* the guest, so unlike `process` and `filesystem` on that substrate ([overview.md](./overview.md) §12.2) these fields carry no trust precondition — a workload with root inside the guest cannot lift them.

  Three things to check before declaring any of these `enforced`:

  | Field | What to check |
  | --- | --- |
  | `rate.disk.write*` | Buffered writes are attributed to a cgroup only where the filesystem implements cgroup writeback. Where it does not, writeback I/O is attributed to the root cgroup and escapes the ceiling entirely. A container writing into a union filesystem's upper layer is the common case of this, so a deployment whose sandboxes write there declares `partial` and records in `knownLimitations` which writable areas *are* covered — per [overview.md](./overview.md) §8.2.1 rule 3, "some of your writes are paced" is unusable without knowing which. A dedicated volume on a filesystem with cgroup writeback support is the configuration where the field is fully enforceable. |
  | `rate.disk.read*` | Page-cache hits issue no I/O to the device, so a read ceiling bounds only reads that miss cache. A workload re-reading a hot file is unbounded on either substrate. This is inherent rather than a gap in any implementation, and it makes the read pair the one most deployments will declare `partial`. |
  | `rate.network.*` | These come from the outbound request path, not the kernel, so they require the same L7 enforcement point `network` L7 rules and token metering need. A deployment without one declares them `unsupported` (§5.1). Three surfaces, one mechanism — which is the strongest argument in the proposal for treating that proxy as core rather than optional infrastructure. |
- `rate.network.*` attaches to the sandbox's egress path and the disk ceilings to its block devices. On the container substrate the sandbox is one Pod ([network.md](./network.md) §4.9), so both belong to the sandbox and nothing else — the same arrangement the VM substrate has. This module therefore needs no scope caveat of its own: the egress path, the devices, the cgroup the counters rest on, and the policy's subject are all the same unit. Note that the containers *inside* one sandbox share all of them, which is correct rather than a problem, because a consumption budget is a property of the sandbox and not of the containers that make it up.
