# Spec: Resource Policy

Part of [Proposal 0001 — Sandbox Security Policy](./overview.md). The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as described in RFC 2119.

---

## 1. Scope

This spec defines the `resource` sub-policy of the `SandboxPolicy` object. The module is named **resource** because that is exactly what it governs: what a sandbox may consume. It covers three contracts:

- **Quota** — steady-state *rate*: how much the sandbox may use at any instant (CPU, memory, network bandwidth).
- **Limits** — windowed *amounts*: how much the sandbox may consume per `minute`, `hour`, `day`, `week`, or `month` window, or over its whole `lifetime` (CPU-seconds, egress bytes, disk-write bytes, LLM tokens).
- **Governance** — what happens when a limit is exceeded: warn, pause, terminate, or **hold for human intervention**, plus notifications so a human learns about it in time.

Rate throttling and runaway-agent protection are both amount problems with different time constants — that is why limits are windowed rather than a single lifetime number.

The rate/amount split is also the seam between this module and `network`: `network` decides *what may be reached*, `resource` decides *how much may flow*. A bandwidth ceiling is consumption, so it is a quota here rather than a field on an egress rule ([overview.md](./overview.md) §11.9).

Out of scope: billing and pricing (the usage exposure below is the contract billing builds on); idle timeouts and lifecycle (existing behavior, unchanged — except that it remains applicable to held sandboxes, §7).

## 2. Object model

```yaml
policy:
  resource:
    quota:
      cpuMillicores:      int               # steady-state CPU quota
      memoryMiB:          int               # steady-state memory quota
      netBandwidthKbps:   int               # steady-state egress bandwidth ceiling
    limits:
      cpuSeconds:                          # vCPU-seconds
        windows:  {minute?, hour?, day?, week?, month?, lifetime?}
        onExceeded?: action                # optional, overrides the default
      netEgressBytes:                      # outbound bytes
        windows:  {minute?, hour?, day?, week?, month?, lifetime?}
        onExceeded?: action
      diskWriteBytes:                      # bytes written to block devices
        windows:  {minute?, hour?, day?, week?, month?, lifetime?}
        onExceeded?: action
      llmTokens:
        input:                             # prompt tokens
          windows:  {minute?, hour?, day?, week?, month?, lifetime?}
          onExceeded?: action
        output:                            # completion tokens
          windows:  {minute?, hour?, day?, week?, month?, lifetime?}
          onExceeded?: action
        total:                             # input + output
          windows:  {minute?, hour?, day?, week?, month?, lifetime?}
          onExceeded?: action
    onExceeded:        warn | pause | hold | kill    # resource-wide default
    notifications:
      thresholds:      [number]            # fractions of each limit; default [0.8, 1.0]
      webhook:         URL                 # optional delivery endpoint
```

Dimensions: `cpuSeconds`, `netEgressBytes`, `diskWriteBytes`, and `llmTokens.{input,output,total}`. The three token dimensions are independent: each configured dimension is enforced on its own counters.

## 3. Field specification

| Field | Type | Constraints | Default | Semantics |
| --- | --- | --- | --- | --- |
| `quota.cpuMillicores` | `int?` | ≥ 0 | template value | Steady-state CPU quota (millicores). |
| `quota.memoryMiB` | `int?` | ≥ 0 | template value | Steady-state memory quota (MiB). |
| `quota.netBandwidthKbps` | `int?` | > 0 | template value; unset = unlimited | Steady-state egress bandwidth ceiling (kbit/s). Excess traffic is **shaped, not failed** (§3.1). |
| `limits.<dimension>.windows` | `map?` | Keys from `{minute, hour, day, week, month, lifetime}`; values > 0. Multiple windows MAY be set and are enforced independently. | unset (no limit) | Maximum consumption of the dimension per window (§4). |
| `limits.<dimension>.onExceeded` | `enum?` | `warn` \| `pause` \| `hold` \| `kill` | resource default | Action when any window of this dimension is exceeded. |
| `onExceeded` | `enum?` | same | `hold` | Resource-wide default action. |
| `notifications.thresholds` | `[number]?` | Each in (0, 1]. Sorted ascending. | `[0.8, 1.0]` | Fractions of each configured limit at which a notification is emitted. |
| `notifications.webhook` | `string?` | `https` URL | unset | Endpoint receiving notification events (§8). |

Zero/negative limits, empty `windows` maps, and thresholds outside (0, 1] MUST be rejected with `400 INVALID_POLICY`.

`lifetime` is the never-resetting window: a limit for the sandbox's whole existence. The five periodic windows reset at their boundaries (§4.1).

### 3.1 Bandwidth semantics

`quota.netBandwidthKbps` is a rate ceiling, and rate ceilings behave unlike every other field in this spec: they do not have an exceedance transition, because they cannot be exceeded.

1. Traffic above the ceiling MUST be **shaped** — queued and paced down to the ceiling — not rejected. There is no `onExceeded` action for bandwidth, no `resource.exhausted` event, and no held state. A sandbox at its bandwidth ceiling is a slow sandbox, not a failing one.
2. The ceiling applies to **egress** from the sandbox's network interface(s), measured at the same point as the `netEgressBytes` dimension (§5.1), so a tenant reading both numbers is reading one traffic stream.
3. Unset means unlimited: the sandbox is bounded only by the platform's own capacity. Zero MUST be rejected with `400 INVALID_POLICY` — a sandbox that may reach a destination (`network`) but may not send a byte to it is a configuration whose failure mode is indistinguishable from a broken network, which principle 4 exists to prevent. "Send nothing" is expressed in `network`, where the denial is explainable.
4. Bandwidth and `limits.netEgressBytes` are complementary and MUST be enforceable together: the quota bounds the instantaneous rate, the limit bounds the accumulated amount. Shaping reduces the rate at which a `netEgressBytes` window fills; it never substitutes for it.
5. Ingress shaping is not specified. Inbound traffic is not the sandbox's consumption to control, and a ceiling the workload cannot influence is not a policy field (§13.11).

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
4. Snapshot restore / clone: the restored sandbox inherits the **policy** (limits, actions, notifications) of the source; all counters, including lifetime, start from zero at the restore point. (Whether operators may choose counter inheritance instead is an open question, §13.)

### 4.3 Enforcement

1. Every configured window is enforced independently: when any window's counter first reaches its limit, that dimension's action (§6) triggers.
2. Multiple windows of the same dimension share the dimension's `onExceeded`.
3. If several dimensions/windows are exceeded at the same observation, the most severe action among them wins: `kill` > `hold` > `pause` > `warn`.
4. Checks SHOULD run both periodically and at each metering boundary so minute-granularity limits act promptly. Overshoot between checks MUST be absorbed: the action triggers on the first observation at-or-over the limit, and reported usage MAY exceed the limit by up to the observation granularity.
5. Periodic exceedance is re-armed by rollover: a dimension that exhausts its `minute` window at 10:07:30 and rolls into a fresh window at 10:08:00 may consume again, and a new exceedance in the fresh window is a new transition with its own events.

## 5. Metering semantics

### 5.1 Dimension sources

| Dimension | Measured quantity |
| --- | --- |
| `cpuSeconds` | vCPU time consumed by all sandbox processes. |
| `netEgressBytes` | Bytes leaving the sandbox's network interface(s). |
| `diskWriteBytes` | Bytes written to the sandbox's writable block devices. |
| `llmTokens.*` | LLM API tokens, per §5.2. |

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
| `warn` | Emit the exceedance event only. For observability pilots, not protection. |
| `pause` | Suspend the sandbox. It becomes resumable once every triggering window has rolled over, and SHOULD auto-resume at that point; a policy update raising the limit also releases it. Minute/hour windows therefore act as throttles, month/lifetime windows as circuit breakers. |
| `hold` | Suspend the sandbox and wait for a human decision (§7). Does **not** auto-release at window rollover. |
| `kill` | Terminate immediately; the terminal state records the dimension and window as the cause. |

Action resolution: `limits.<dimension>.onExceeded` if set, else the resource-wide `onExceeded`.

The default is `hold`: configuring a limit is opting into governance, and hold is the only action that is both safe (consumption stops) and reversible (no data loss) while leaving the final say to a human. Deployments without an on-call workflow SHOULD set `warn` or `pause` explicitly — held sandboxes remain subject to the standard idle-timeout lifecycle, so an unattended hold cannot leak resources forever.

`onExceeded` is this module's only response field: per [overview.md](./overview.md) §8.1.6, there is **no `onViolation` here**. The two are not alternatives that happened to land in different modules — they answer different questions, and §8.1.1 fixes which is which. An exceedance means the workload stayed inside every boundary it was given and ran out of budget; a violation means it crossed one. That is why this action set has `warn` and `hold` while `onViolation` has neither: there is something for a human to decide about "needs more budget", and a warning about overspending leaves no protection disabled, because a budget was never a protection against intent.

The one action both sets share is `kill`, and even it differs in scope. Here it terminates the **sandbox**, because consumption is a sandbox-level quantity with no single guilty process — the same granularity `network` is forced into for a different reason ([overview.md](./overview.md) §8.1.3).

`policy.tier` ([overview.md](./overview.md) §7.1) does not change anything in this module. Both `baseline` and `restricted` resolve to template quotas, no windowed limits, and `onExceeded: hold` — the last of which is already the default above. This is stated rather than omitted because a reader who sees four modules shift under `tier: restricted` is entitled to know that the fifth deliberately does not: consumption budgets are workload-specific numbers, and there is no value for `llmTokens.total` that is "the restricted one". A tier that guessed would be a tier that breaks workloads for a security posture it cannot actually improve.

### 6.1 Shadow evaluation support

Per [overview.md](./overview.md) §7.2.5, this module states its position: **it has no shadow evaluation, because it has nothing to shadow.**

The reasoning is the paragraph above. Shadow evaluation compares an enforced tier against a stricter one, and no tier changes any field here. There is no stricter set of limits for `auditTier: restricted` to evaluate against, so `auditTier` naming this module resolves to no findings — not because the mechanism is missing, but because the comparison is empty.

This is not a gap to be closed later by adding shadow support. If it is ever worth answering "what would a tighter budget have blocked?", the answer already exists and is better: `onExceeded: warn` (§6) is that feature, arrived at from the other direction. A deployment that wants to observe a candidate limit sets the limit with `warn`, and gets exceedance events with real counters rather than a parallel evaluation of a number nobody has chosen. Two mechanisms for one outcome is what §10.1 already declines for grants, and the reasoning transfers unchanged.

The distinction worth keeping straight: a shadow finding elsewhere in the proposal means "this operation would have been refused". Here the equivalent question is "this budget would have been exhausted", which is about a counter reaching a value rather than a decision about an operation — and counters are what this module exposes for real (§9) rather than in shadow.

## 7. Human intervention (hold)

1. On a `hold` action the sandbox enters the **held** state: execution suspended (pause-equivalent), and a `resource.hold_requested` notification MUST be emitted immediately (independent of `notifications.thresholds`).
2. Held sandboxes do not auto-release. Release happens only through the approval API or a policy update.
3. Approval API:

   ```
   POST /sandboxes/{sandboxID}/resource/approval
   {
     "dimension":  "llmTokens.total",  // optional; omit to decide all current holds
     "window":     "month",            // optional; omitted with dimension → all holds of that dimension
     "decision":   "approve" | "deny",
     "grant":      1000000,            // approve only, optional: extra allowance for the current window period
     "raiseLimit": 60000000            // approve only, optional: persistent limit raise for this sandbox
   }
   ```

   - `approve` resumes the sandbox. `grant` adds to the current window period's allowance only (reverts at rollover); `raiseLimit` updates the sandbox's effective limit persistently.
   - For a `lifetime` window a grant never reverts (lifetime has no rollover): it is a permanent addition for the sandbox's remaining existence.
   - `deny` terminates the sandbox.
4. Authorization: approvals MUST be performed through the control-plane API by an authenticated principal authorized to manage the sandbox (owner/operator). The approval API MUST NOT be callable from within the sandbox or with sandbox-scoped credentials — untrusted agent code must not be able to approve its own hold.
5. Every approval MUST be audited: approver identity, target, decision, and any grant/raise.
6. Held sandboxes remain subject to the standard idle-timeout lifecycle (kill/pause on idle), so abandoned holds are eventually reclaimed.

## 8. Notifications

1. **Threshold notifications.** When any (dimension, window) counter crosses a configured threshold fraction of its limit, a `resource.notification` event MUST be emitted, at most once per threshold per window period: `{sandboxID, dimension, window, used, limit, threshold, at}`.
2. **Exceedance events.** Every exceedance transition MUST emit `resource.exhausted`: `{sandboxID, dimension, window, used, limit, action}`.
3. **Hold events.** `resource.hold_requested` (§7) on every hold; `resource.approved` / `resource.denied` record the decision and the approver.
4. **Delivery.** When `notifications.webhook` is configured, events MUST be delivered as HTTPS POST with the JSON payload above, at-least-once, with bounded retries. Webhook authentication/signature is an open question (§13). Events MUST also be available through the platform's event stream regardless of webhook configuration.
5. Notification payloads MUST NOT include sandbox data beyond the counters themselves.

## 9. Usage exposure

1. `GET /sandboxes/{sandboxID}` MUST include a `resource` object:

   ```json
   "resource": {
     "quota": {"cpuMillicores": 2000, "memoryMiB": 2048, "netBandwidthKbps": 51200},
     "usage": {
       "cpuSeconds": {
         "current": {"minute": 12.3, "hour": 300.5, "lifetime": 12345.6},
         "limits":  {"hour": 600, "lifetime": 100000}
       },
       "llmTokens": {
         "total": {
           "current": {"minute": 3500, "day": 155000, "lifetime": 1200000},
           "limits":  {"minute": 10000, "day": 1000000, "month": 50000000},
           "provenance": {"response": 1150000, "estimated": 40000, "reported": 10000}
         }
       }
     },
     "state": {"held": false, "exhausted": []}
   }
   ```

2. `limits` reports the effective configured windows; `current` reports the in-window counters for the configured windows. Lifetime counters MUST be reported even when no lifetime limit is configured (billing needs them).
3. `quota.netBandwidthKbps` is reported when set and omitted when unlimited. It has no `usage` entry: a rate ceiling has no counter (§3.1). Accumulated egress is `usage.netEgressBytes`.
4. For `llmTokens` dimensions, `provenance` reports the lifetime split of how the amounts were learned (§5.4). The three values MUST sum to the lifetime counter, so a tenant can see how much of a bill rests on estimates.
5. `state.exhausted` lists the currently-exceeded (dimension, window) pairs; `state.held` is true while a hold is pending.
6. The SDK exposes the same object as `sandbox.resource`.

## 10. Merge semantics

On top of [overview.md](./overview.md) §5:

| Field | Merge refinement |
| --- | --- |
| `quota.cpuMillicores`, `quota.memoryMiB` | Explicit value overrides; absent keeps template value. |
| `quota.netBandwidthKbps` | Minimum of the set values wins; a source that sets nothing keeps the lower-precedence value. A higher-precedence source cannot *raise* a ceiling set by a lower-precedence source, nor unset it. |
| `limits.*.windows` | Per (dimension, window): minimum of set values wins; a dimension set by no source is unlimited. A higher-precedence source cannot *remove* a limit set by a lower-precedence source. |
| `onExceeded` (default and per-dimension) | Most severe wins: `kill` > `hold` > `pause` > `warn`. |
| `notifications.thresholds` | Union across sources, deduplicated, sorted ascending. |
| `notifications.webhook` | Union across sources (additive observability). |

`quota.cpuMillicores` and `quota.memoryMiB` keep override semantics because that is today's template behavior and changing it would break existing callers ([overview.md](./overview.md) §9). `netBandwidthKbps` is new, so it is narrow-only from the start — the shared merge principle applies wherever compatibility does not force otherwise.

### 10.1 Grantable fields

Per [overview.md](./overview.md) §5.1.8 every module declares its grantable surface. **This module has none.** No `resource` field may be widened by a time-bounded grant.

Temporary additional consumption is already a first-class operation here, and it has a different shape from a grant: the approval API (§7.3) is driven by a **hold**, so a human decides at the moment the sandbox actually needs more, with the exceeded counters in front of them. A grant is a pre-authorization issued before the need is demonstrated. Adding grants to this module would give the same outcome two mechanisms, one of which discards the information the other is built on.

> **Terminology.** The `grant` field of the approval API (§7.3) predates the time-bounded grants of [overview.md](./overview.md) §5.1 and is a different thing: an allowance added to a window counter, with no TTL of its own — it reverts at window rollover, or never, for `lifetime`. The collision is real and is recorded as an open question ([overview.md](./overview.md) §11.7).

## 11. Errors

| Code | Surface | Payload | When |
| --- | --- | --- | --- |
| `INVALID_POLICY` | 400 | `{field, reason}` | Non-positive limit, invalid window key, threshold outside (0, 1]. |
| `POLICY_RESOURCE_EXHAUSTED` | terminal state / event | `{dimension, window, used, limit, action}` | Exceedance with action `kill` (or an approval `deny`). |
| `POLICY_RESOURCE_HELD` | sandbox state / event | `{dimension, window, used, limit}` | Sandbox held pending approval. |
| approval errors | 400 / 409 | `{reason}` | Approval targets no current hold, or invalid grant/raise. |

## 12. Acceptance criteria

1. Multi-window enforcement: with `llmTokens.total` limited per `minute` (action `pause`) and per `month` (action `hold`), a burst over the minute limit pauses the sandbox, which becomes resumable (and auto-resumes) at minute rollover; crossing the month limit holds it for approval.
2. Rollover re-arms: after the minute window resets, consumption up to the new limit proceeds without events until a new threshold/exceedance transition.
3. Hold requires a human: a held sandbox does not resume at window rollover; `approve` (with or without grant/raise) resumes it; `deny` terminates it; a grant of N allows at most N further units in the current period.
4. The approval API rejects calls authenticated with sandbox-scoped credentials.
5. Threshold notifications fire at most once per threshold per window period; exceedance and hold events fire on every transition.
6. Lifetime counters are monotonic and reported even without a lifetime limit.
7. Simultaneous exceedance resolves to the most severe action.
8. Restore/clone: policy inherited, all counters zero.
9. Merged per-window limits take the minimum; merged actions take the most severe.
10. **Streaming.** A stream that completes normally meters the final chunk's `usage` with provenance `response`. The same stream aborted before its final chunk still meters a non-zero amount with provenance `estimated`, and that amount is no greater than what the completed stream metered.
11. **Retries.** Three provider attempts that each return `usage` meter three times; an attempt that fails before any content meters zero. Platform-initiated retries are attributed to the originating sandbox.
12. **Late correction.** An authoritative `usage` arriving after an estimate applies a positive delta only; no counter ever decreases.
13. **Provenance exposure.** The `response` / `estimated` / `reported` split is reported and sums to the lifetime counter.
14. `report_usage` called with sandbox-scoped credentials is rejected.
15. **Bandwidth shaping.** With `quota.netBandwidthKbps` set, a sustained transfer completes at approximately the configured rate; no connection is refused, no `resource.exhausted` event is emitted, and the sandbox is never paused, held, or killed by the ceiling. With the field unset, the same transfer is not rate-limited.
16. **Bandwidth is not a limit.** A sandbox with both `quota.netBandwidthKbps` and a `limits.netEgressBytes` window still triggers that window's action when the accumulated amount is reached; shaping only delays when that happens. `netBandwidthKbps: 0` is rejected with `400 INVALID_POLICY`.
17. **Bandwidth merge.** A request setting a higher `netBandwidthKbps` than the template's value resolves to the template's value; a lower value resolves to the request's.

## 13. Open questions

1. **Timezone.** Windows align to UTC. Should deployments be able to align `day`/`week`/`month` to a local timezone?
2. **Sliding windows.** Fixed windows are simple but allow a 2× burst at boundaries (full quota at the end of one window and the start of the next). Are sliding windows needed, or is that acceptable for v1?
3. **Auto-resume.** Should `pause` auto-resume at rollover (proposed SHOULD) or require an explicit resume?
4. **Webhook authentication.** HMAC signature scheme? Where are shared secrets stored?
5. **Approval RBAC.** Which principals may approve: sandbox owner only, namespace operators, or anyone with cluster admin?
6. **Grant visibility.** Should grants appear in `resource.usage` (e.g. an `allowance` field) so platforms can bill for approved overage? Note the naming collision with the time-bounded grants of [overview.md](./overview.md) §5.1, tracked as §11.7 there — whichever name survives, this field and that mechanism must not share it.
7. **Per-window actions.** Should `onExceeded` be settable per window rather than per dimension (e.g. `minute`→`pause`, `month`→`hold` on the same dimension)?
8. **Counter inheritance on restore/clone.** Reset is proposed here; should inheritance be available as an operator choice?
9. **Estimation method.** §5.3 fixes the *properties* of an estimate (lower bound, derived from observed content) but not the algorithm. Should the algorithm and its expected error be published, so tenants can audit the estimated portion of their usage?
10. **Cached and reasoning tokens.** Providers increasingly meter cache reads and reasoning tokens separately. Do those become their own dimensions, or fold into `input` / `output`?
11. **Ingress shaping.** §3.1.5 specifies egress only. Should an inbound ceiling exist for sandboxes that serve public traffic (`network.ingress`), and if so, is it a `resource` field at all, given that the sandbox does not choose how much arrives?
12. **Disk and IOPS quotas.** `diskWriteBytes` bounds the amount written but nothing bounds the *rate*, and nothing bounds total footprint on disk. Are `quota.diskIops` and a size ceiling needed, or is the write-amount limit enough in practice?
13. **Per-destination rate.** A bandwidth ceiling is per sandbox. Whether a rate can be attached to a single egress rule is the mirror of this question and is tracked in [network.md](./network.md) §10.5; it must be answered once, not twice.

## 14. Non-normative notes

- Every dimension has a natural source in the sandbox's own kernel accounting (CPU time, block I/O, interface statistics) or in the outbound HTTP path (LLM `usage` fields); window counters derive from those streams. The spec fixes only the semantics above.
- Bandwidth shaping is the one contract here that is enforced rather than metered: the platform paces the sandbox's egress instead of counting it. Because the mechanism sits on the same interface the `netEgressBytes` dimension is measured on, the two numbers stay consistent for free — which is the reason §3.1.2 fixes the measurement point rather than leaving it to the implementation.
