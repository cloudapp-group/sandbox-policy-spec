# Spec: Filesystem Policy

Part of [Proposal 0001 — Sandbox Security Policy](./overview.md). The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as described in RFC 2119.

---

## 1. Scope

This spec defines the filesystem sub-policy of the `SandboxPolicy` object: **which paths the sandbox may read, write, or execute**, applied to every process the sandbox runs. There is one subject and one language for it — a path — and that is deliberate.

An earlier revision of this module also governed the host boundary: which host paths could be mounted in, and with what default writability. Those fields are removed. The reason is that they were never really policy about the sandbox. A host-mount allowlist states *what the platform is willing to expose*, which is an admission decision belonging to the deployment (a Kubernetes admission controller, a VMM configuration), not a capability the sandbox holds. The old §4.4.4 conceded as much by intersecting the policy value with an operator-configured one, which means the policy field could never decide anything on its own.

Nothing is lost in expressiveness. A mount that should be read-only is `readOnlyPaths: [/mnt/data]`; a mount that should be unreadable is `denyPaths`. Once mounted, a path is a path, and this module no longer cares where it came from — which removes the second, parallel grammar that §2.2 of [overview.md](./overview.md) exists to prevent.

Out of scope: content inspection, quotas on file count and total size, image-layer construction, and **which host paths may be mounted at all**. I/O *rate* is bounded in [resource.md](./resource.md) §3.1; total footprint is bounded nowhere yet and is tracked as an open question there (§13.12). Also out of scope: detecting anomalous file access, which is an audit-stream concern rather than a policy field ([overview.md](./overview.md) §2.3.1).

Two adjacent surfaces belong to [process.md](./process.md) and are named here because policies that need one usually need the other. Whether a process may *gain privilege* is `process.noNewPrivileges`, not a path rule — a `setuid` binary under a readable path is still a privilege gain. Whether a process may *persist* is only partly `process.allowDaemonize`: autostart persistence is written to files (`crontab`, systemd units, shell profiles, XDG autostart), so blocking it is a `denyPaths`/`readOnlyPaths` decision made here ([process.md](./process.md) §3.4).

## 2. Object model

```yaml
policy:
  filesystem:
    mode:            baseline | unrestricted   # default: baseline
    baselineVersion: string                    # e.g. "baseline/1"; default: platform default
    baselineExceptions: [string]               # paths excluded from the baseline set
    denyPaths:       [string]                  # no access at all
    readOnlyPaths:   [string]                  # read allowed, writes denied
    writableRoots:   [string]                  # inverse form: writes allowed only under these roots
    implicitRuntimeWritable: bool              # default: true
    onViolation:     deny | kill               # default: deny
    audit:           none | metadata           # default: none
```

## 3. Path pattern syntax

All path fields use the same pattern syntax:

1. Patterns MUST be absolute paths.
2. `*` matches any sequence of characters **within a single path segment** (it MUST NOT match `/`).
3. Only a single `*` per segment is allowed; `?` and `**` are not defined in v1.
4. A pattern without wildcards matches exactly that path and everything beneath it (prefix semantics over path segments, not raw string prefix).
5. Matching is case-sensitive and operates on the **normalized** path (§4.1).

Examples:

| Pattern | Matches | Does not match |
| --- | --- | --- |
| `/etc` | `/etc`, `/etc/passwd`, `/etc/apt/...` | `/etcetera` |
| `/home/*/.ssh` | `/home/alice/.ssh`, `/home/bob/.ssh/keys` | `/home/.ssh`, `/home/a/b/.ssh` |
| `/root/.aws` | `/root/.aws`, `/root/.aws/credentials` | `/home/root/.aws` |

## 4. Evaluation semantics

### 4.1 Path normalization

Before matching, the accessed path MUST be normalized: resolve `.` and `..` lexically, then resolve symlinks. If a symlink target escapes the sandbox root, the resolved host-side path is used for host-boundary matching. Policy evaluated on the pre-normalization string MUST NOT be relied upon by implementations (i.e. traversal like `/home/x/../root/.ssh` MUST be judged on its resolved form).

### 4.2 Decision order

For any filesystem access by any sandbox process, the decision MUST be:

1. If the resolved path matches any `denyPaths` pattern, or any pattern of the effective baseline set (§6) → **deny all access** (`EACCES`).
2. Else if `writableRoots` is non-empty and the resolved path matches neither any `writableRoots` pattern nor the implicit runtime-writable set (§6.4) → **read-only** (writes fail with `EACCES`/`EROFS`).
3. Else if the resolved path matches any `readOnlyPaths` pattern → **read-only**.
4. Else → default (read-write, subject to image-layer permissions).

`denyPaths` always wins over `writableRoots`, `readOnlyPaths`, and the implicit runtime-writable set. Rule 2 and rule 3 are mutually exclusive formulations; see §5 constraints.

### 4.3 Enforcement requirements

1. The policy MUST be enforced at process level for **every process** the sandbox runs, not only for processes spawned through a specific entry point. A process that shells out to an arbitrary binary MUST inherit the same restrictions.
2. Enforcement MUST NOT depend on environment variables, `PATH` manipulation, or userspace-only interception.
3. `denyPaths` MUST deny reads even for the owning user identity inside the sandbox.
4. Effects apply to newly created processes from policy application onward. Whether a policy update can re-apply to already-running processes is an open question (§10).

### 4.4 Violation actions

Per [overview.md](./overview.md) §8.1, `onViolation` decides what happens when §4.2 refuses an access:

| Action | Result |
| --- | --- |
| `deny` (default) | The access fails with `EACCES` / `EROFS` per §8. The process keeps running and may handle the error. |
| `kill` | The **offending process** is terminated. Enforcement sits on the syscall/VFS path and therefore knows its caller exactly, so the termination is precise. |

1. `kill` is the right choice for a deployment that treats a touch of a credential path as disqualifying rather than as a recoverable error: a process that tried to read `~/.aws/credentials` has already told the operator what it is doing, and letting it continue only gives it more attempts.
2. `deny` remains the default because a great many benign programs probe paths they do not need — configuration lookups walk a list of candidate locations, and a build tool may stat directories that do not concern it. Under `kill` those probes become process deaths, which is why the aggressive value is opt-in.
3. There is no `warn`, on the terms of [overview.md](./overview.md) §8.1.2. To learn what a stricter path set *would* refuse without refusing it, use `auditTier` (§6.6) — which, unlike a `warn`, keeps the current rules enforced.
4. `onViolation` applies to the baseline deny set and to explicitly declared rules alike. Every rule in this module is evaluated on a filesystem access by a running process, so there is no create-time rejection for it to be inapplicable to.
5. Either action emits a violation event, at every audit level (§9).

## 5. Field specification and constraints

| Field | Type | Constraints | Default | Semantics |
| --- | --- | --- | --- | --- |
| `mode` | `enum?` | `baseline` \| `unrestricted` | `baseline` | `baseline` adds the built-in sensitive-path deny set (§6). `unrestricted` applies only explicitly declared rules. |
| `baselineVersion` | `string?` | A published baseline set identifier. An unknown value MUST be rejected with `400 INVALID_POLICY`. | platform default | Pins the built-in deny set (§6.2). |
| `baselineExceptions` | `[string]?` | Each entry MUST exactly match a pattern present in the pinned baseline set. | `[]` | Paths excluded from the baseline set (§6.3). |
| `denyPaths` | `[string]?` | Pattern syntax §3. | `[]` (+ baseline set) | No access whatsoever. |
| `readOnlyPaths` | `[string]?` | Pattern syntax §3. MUST be empty when `writableRoots` is non-empty. | `[]` | Reads allowed; writes/create/delete denied. |
| `writableRoots` | `[string]?` | Pattern syntax §3. MUST be empty when `readOnlyPaths` is non-empty. | `[]` | When non-empty, writes allowed only under these roots (plus §6.4). |
| `implicitRuntimeWritable` | `bool?` | — | `true` | Whether the runtime-writable set applies when `writableRoots` is non-empty (§6.4). |
| `onViolation` | `enum?` | `deny` \| `kill` | `deny` | §4.4. |
| `audit` | `enum?` | `none` \| `metadata` | `none` | Audit level for **ordinary** filesystem activity (§9). It does not suppress violation events ([overview.md](./overview.md) §8.1.4). |

Violating the `readOnlyPaths`/`writableRoots` mutual exclusion MUST fail with `400 INVALID_POLICY` naming both fields.

## 6. Defaults

### 6.1 Baseline deny set `baseline/1`

The built-in baseline deny set (active when `mode: baseline`):

```yaml
denyPaths:
  - /root/.ssh
  - /home/*/.ssh
  - /root/.aws
  - /home/*/.aws
  - /root/.gnupg
  - /home/*/.gnupg
  - /root/.config/gcloud
  - /home/*/.config/gcloud
  - /etc/shadow
  - /etc/gshadow
```

Baseline exists to stop in-sandbox credential theft: agent-generated code running as the sandbox user must not be able to read the very credentials that authenticate that user to external services.

The **effective baseline set** is the pinned version's set minus `baselineExceptions` (§6.3).

`mode: unrestricted` MUST be represented explicitly in the effective policy; it never results from omission.

### 6.2 Baseline versioning and evolution

Credential locations keep being invented, so the set has to grow. Growing a *fixed, unversioned* set would make every addition a breaking change for whichever template legitimately read that path. Versioning is therefore normative in v1, not deferred to implementation:

1. Baseline sets are **versioned and immutable**. `baseline/1` is the set in §6.1; a published version MUST NOT be changed in place.
2. A new version MUST only **add** paths. Removing a path weakens every policy resolving to that version and MUST go through an announced deprecation cycle instead.
3. `baselineVersion` pins the set. The effective policy MUST always record the **resolved** version explicitly — including when the policy did not pin one — so the version appears in the policy snapshot ([overview.md](./overview.md) §4.1).
4. A policy that pins no version resolves to the platform's **default baseline version**. Rolling that default forward is an announced platform change with a deprecation window; it MUST NOT happen silently, and it MUST NOT affect policies that pinned a version.
5. A sandbox keeps the version recorded in its effective policy for its lifetime. A new baseline version reaches a running sandbox only through a policy update, which produces a new `effectivePolicyVersion`.

A template that cannot tolerate any future addition pins a version. A template that wants to keep up with new credential locations pins nothing. Either way the choice is explicit and auditable.

### 6.3 Explicit opt-out: `baselineExceptions`

`baselineExceptions` is the narrow opt-out, for the case where one baseline path is legitimately needed and abandoning the whole baseline via `mode: unrestricted` would be disproportionate.

1. Each entry MUST exactly match a pattern present in the pinned baseline set. An entry that matches nothing MUST be rejected with `400 INVALID_POLICY` — otherwise an exception silently becomes dead configuration when the baseline evolves.
2. Exceptions apply **only** to the built-in set. They MUST NOT cancel an explicit `denyPaths` entry from any source.
3. Merge is **intersection**: an exception takes effect only if every contributing source declares it (narrow-only, [overview.md](./overview.md) §5).
4. Every effective exception MUST be recorded in the effective policy and MUST emit an audit event when the sandbox is created, so "this sandbox may read `/home/*/.aws`" is never invisible to an operator.

### 6.4 Implicit runtime-writable set

When `writableRoots` is non-empty, everything outside it becomes read-only — including the temporary directories ordinary toolchains assume they can write. A `writableRoots: [/workspace]` policy that does not account for this breaks `pip`, `npm`, compilers, and anything calling `mkstemp`, and it breaks them as confusing build failures rather than as legible policy denials.

Therefore, when `writableRoots` is non-empty, these paths are **implicitly writable** unless `implicitRuntimeWritable: false`:

```yaml
- /tmp
- /var/tmp
- /dev/shm
```

1. The implicit set is additive to `writableRoots`. It never overrides `denyPaths` or the baseline set, which still win at §4.2 step 1.
2. `implicitRuntimeWritable: false` removes the implicit set, for a policy that genuinely wants one writable root. Such a policy SHOULD list whichever temporary directories its image needs in `writableRoots`.
3. Enforcement MUST NOT consult `TMPDIR` or any other environment variable to discover a temporary directory: §4.3.2 forbids it, and an environment variable is workload-controlled. A deployment whose images point `TMPDIR` outside the implicit set MUST add that path to `writableRoots` explicitly; the platform SHOULD emit a `policyWarnings` entry `{reason: "tmpdir_outside_writable_roots"}` at create time where it can detect the mismatch from template configuration.

### 6.5 Tier defaults

Which defaults apply is selected by `policy.tier` ([overview.md](./overview.md) §7.1):

| | `tier: baseline` | `tier: restricted` (default) |
| --- | --- | --- |
| `mode` | `baseline` | `baseline` |
| `baselineVersion` | platform default | platform default |
| `onViolation` | `deny` | `deny` |
| `audit` | `none` | `metadata` |

Note that `baseline` and `restricted` share `mode: baseline`. That is deliberate and is one of only two places in the proposal where a module's `baseline` tier is not byte-for-byte today's behavior ([overview.md](./overview.md) §9): the sensitive-path deny set is on at the default tier, because a credential path a legitimate workload never reads is not a compatibility surface worth preserving. A deployment that disagrees pins `baselineExceptions` or sets `mode: unrestricted`, both of which are recorded and audited (§6.3.4).

`onViolation` is `deny` under both tiers, per [overview.md](./overview.md) §8.1.7 — and here the reason is especially concrete: benign path probing is common enough (§4.4.2) that a tier which selected `kill` would turn ordinary configuration lookups into process deaths.

**`tier: restricted` changes exactly one field here — `audit` — and after the removal of the mount fields (§1) that is the only difference between the two tiers in this module.** This is stated rather than left to be noticed, because a reader who watches four other modules tighten under `restricted` is entitled to know that the path rules do not.

The reason is the one §6.4 already gives: there is no useful guess to make. A tier that turned on `writableRoots` would have to invent the root, and inventing `/workspace` for an image that builds in `/src` produces exactly the confusing build failure this module works to avoid. What `restricted` supplies without guessing is the audit trail, so that is what it supplies — the same restraint `exec` is given for the same reason ([overview.md](./overview.md) §7.1).

What does the tightening in this module is therefore not the tier but the baseline set, which is on under **every** tier including `compatibility`. That is the deliberate exception recorded above, and it is where the module's protection actually comes from.

### 6.6 Shadow evaluation support

Per [overview.md](./overview.md) §7.2.5, this module supports shadow evaluation under `auditTier` for its full path surface: `mode`, the resolved baseline set, `denyPaths`, `readOnlyPaths`, and `writableRoots`. An access the shadow configuration would have refused **succeeds** and emits a `shadow: true` audit event carrying the path, the operation, and the shadow rule that would have refused it.

The path surface has a volume problem the other modules do not, and it has to be handled rather than noted. A build that walks a tree touches the same directories thousands of times, so a shadow finding emitted per access would bury the finding that matters. Implementations **SHOULD** therefore aggregate shadow findings by `{rule, operation}` and report the distinct paths involved up to a bounded count, rather than emitting one event per access ([overview.md](./overview.md) §7.2.7).

One asymmetry is worth stating, because it limits what a shadow report can promise here. A denied *read* is usually recoverable — the workload gets `EACCES` and fails visibly. A denied *write* may leave the workload in a state it cannot report, and a shadow evaluation cannot tell the difference: it observes the access, not the consequence. A clean shadow report therefore means "nothing would have been refused", not "the stricter policy is safe to adopt". Where the findings concern writes, read the report as a list of write locations to declare, not as a verdict.

## 7. Merge semantics

On top of [overview.md](./overview.md) §5:

| Field | Merge refinement |
| --- | --- |
| `mode` | Most restrictive wins: if any source says `baseline`, the result is `baseline`. |
| `baselineVersion` | The newest pinned version wins. Because versions only add paths (§6.2.2), newest is also most restrictive. |
| `baselineExceptions` | Intersection across sources: an exception applies only if every source declares it. |
| `denyPaths` | Append + deduplicate (including baseline set when active). |
| `readOnlyPaths` / `writableRoots` | Append + deduplicate. The mutual-exclusion constraint is validated on the **merged** result, not per source. |
| `implicitRuntimeWritable` | `false` wins (most restrictive). |
| `onViolation` | `kill` wins ([overview.md](./overview.md) §8.1.7). |
| `audit` | Most detailed wins (`metadata` > `none`). |

### 7.1 Grantable fields

Per [overview.md](./overview.md) §5.1.8, a time-bounded grant against this module may open:

| Grantable | Not grantable |
| --- | --- |
| `baselineExceptions` — named baseline paths | `mode: unrestricted` |
| `writableRoots` — named roots | `denyPaths` removal of any entry |
| `readOnlyPaths` — removal of a named entry | `implicitRuntimeWritable` |

One exclusion carries the weight. `denyPaths` is not grantable because an explicit deny is the one statement in this module whose author meant it literally; `baselineExceptions` already covers "one built-in path, temporarily", and it covers it with the audit trail of §6.3.4.

A grant of `writableRoots` when `writableRoots` was empty is a **narrowing**, not a widening: it switches the module from "writes allowed by default" to "writes allowed only here". A grant MUST NOT have that effect ([overview.md](./overview.md) §5.1.4 — a grant opens a hole of known shape, it does not change the shape of the policy). Such a request MUST be rejected with `400 POLICY_GRANT_INVALID`.

## 8. Errors

Configuration errors (create/update time): `400 INVALID_POLICY` (malformed pattern, mutual exclusion violated, unknown `baselineVersion`, `baselineExceptions` entry not present in the pinned baseline set), `400 POLICY_GRANT_INVALID` (a grant targeting a non-grantable field, or a `writableRoots` grant against an empty `writableRoots`, §7.1).

Enforcement errors are OS-level, not API-level, because the policy applies below the API surface:

| Access | Result |
| --- | --- |
| Read under `denyPaths` | `EACCES` |
| Write under `readOnlyPaths` / outside `writableRoots` | `EACCES` or `EROFS` |
| Create/delete/rename under read-only | `EACCES` |
| Directory listing of a denied directory | `EACCES` |

Under `onViolation: kill` (§4.4) the offending process is terminated instead of receiving any of the above.

Denials MUST NOT be distinguishable from ordinary permission failures in a way that leaks the rule identity to the sandbox process (no error-channel oracle); rule identity appears only in the audit stream (§9). `kill` does not breach this — a terminated process learns nothing — and the residual sibling-process signal is the accepted trade recorded in [overview.md](./overview.md) §8.1.5.

## 9. Observability

1. Every filesystem denial MUST be emitted as a violation event with `{sandboxID, rule (pattern), path, op (read|write|...), outcome: denied|killed, effectivePolicyVersion, shadow: false}`, at **every** audit level including `audit: none` ([overview.md](./overview.md) §8.1.4). `mode: unrestricted` removes the baseline set from evaluation, so it produces no baseline-set events — there is no denial to report — but it does not suppress events for explicitly declared `denyPaths`.
2. What `audit: metadata` adds is the record of **ordinary** access activity. That is the part a deployment may reasonably decline, and the part §8.1.4 leaves under this field's control.
3. Audit payloads MUST NOT include file contents.
4. Each effective `baselineExceptions` entry MUST emit an audit event at sandbox creation with `{sandboxID, baselineVersion, exception, sources}` (§6.3.4), independent of the audit level. Weakening the baseline is an event, not a silent field.
5. Denials of the same `{rule, op}` repeat readily — a configuration lookup walking candidate paths can produce many in a burst. Implementations **SHOULD** aggregate them on the same terms as shadow findings (§6.6), rather than emitting one event per access.

## 10. Open questions

1. **Hot application.** Can an updated filesystem policy apply to already-running processes, or only to new ones? Kernel rule-set re-application semantics differ per mechanism; the spec needs a stable answer.
2. **Default-version rollout.** §6.2.4 requires an announced deprecation window before the default baseline version moves. How long is it, and through which channel is it announced?
3. **Exec bit.** Should the spec distinguish execute permission from read? v1 ties execution to network/exec policy instead; confirm.
4. **Image-level declarations.** `baselineExceptions` is per-policy. If a future baseline version denies a path that a specific *image* legitimately needs, is a per-policy exception enough, or does the image need to declare it once so every policy using that image inherits it?
5. **Temporary-data cleanup at task end.** Nothing here states what happens to data a task wrote once the task is over. The implicit runtime-writable set (§6.4) and any `writableRoots` persist for the sandbox's lifetime, so a sandbox reused across tasks carries one task's scratch files, caches, and downloaded artifacts into the next. Is that a policy field (e.g. paths to wipe at task boundaries), a lifecycle operation outside this module, or deliberately the caller's job? The prior question is whether the platform even has a notion of a "task boundary" distinct from the sandbox lifetime — [overview.md](./overview.md) §11.8 tracks that, and this question cannot be answered before it.
6. **Snapshot and restore.** §4.2 governs access by processes inside the sandbox. A snapshot reads the filesystem from *outside* it, and a restore writes one. Neither passes through the decision order, so today a `denyPaths` entry does not prevent its contents from leaving in a snapshot image. Does snapshot/restore need its own declared permission — and if the answer is that `denyPaths` should exclude paths from snapshots, that is a substantial change to what the field means and belongs in a version of this spec that says so explicitly.
7. **Exec bit, revisited.** Question 3 defers execute permission to `exec` policy. With [process.md](./process.md) now specifying syscall-level enforcement, the alternative is clearer: deny-execute-by-path is a filesystem rule, while denying `execve` outright is a process rule, and neither is the `exec` control interface. Confirm that no-exec-by-path stays out of v1.

## 11. Non-normative notes

- Each sandbox owns a whole kernel on the VM substrate, so the requirements in §4.3 can be met by in-guest, unprivileged, per-process mechanisms (e.g. an LSM with per-process rule sets, or equivalent syscall-level enforcement). The spec intentionally mandates only the *properties*, not the mechanism. [process.md](./process.md) §4.5 states the same requirements for the syscall surface, and the two are expected to be satisfiable by one mechanism. Note that on that substrate the mechanism is installed from *inside* the guest, which attaches a trust precondition to the result rather than to the mechanism ([overview.md](./overview.md) §12.2): the rules hold while the workload cannot reach the process that installed them.
- **This module is one of the two places where the substrates genuinely differ** ([overview.md](./overview.md) §12.2), and it is worth being concrete about the shape of the difference rather than leaving it as "depends on the platform":

  | Path | How §4.2 is realized | Capability state to declare |
  | --- | --- | --- |
  | VM substrate, in-guest LSM with per-process rule sets | Directly: patterns become rule sets attached to each process | `enforced`, qualified by the §12.2 precondition |
  | Container substrate, unprivileged per-process path rule set in the kernel | Directly, within the operations that interface covers | `enforced`, or `partial` where the interface does not cover an operation the module specifies |
  | Container substrate, host-managed LSM profile generated per sandbox | Directly, but requires node-level cooperation the policy object cannot compel | `enforced` where the deployment controls its nodes |
  | Neither available | — | `unsupported` |

  The last row is the one that has to be handled honestly. A read-only bind mount is **not** an implementation of `denyPaths`: it changes writability, not visibility, so a credential file stays readable — which is the entire threat this module exists to answer ([overview.md](./overview.md) §2.3). Nor is it partial enforcement, since it does not narrow the specified rule, it substitutes a different one. §8.2.1 rule 4 requires such a deployment to declare the field `unsupported` and let `enforcement: strict` reject policies that name it.
- The `writableRoots` direction is the more portable half of this module. "Writes only under these roots" is expressible with a read-only root filesystem plus targeted writable mounts, which most runtimes offer directly, whereas `denyPaths` needs a real path-rule interface — so a deployment may well reach `enforced` on `writableRoots` while `denyPaths` and `readOnlyPaths` stay `unsupported`. Capability declarations are per field for exactly this reason.
- Removing the host-mount fields (§1) does not remove the host boundary; it relocates the statement of it. A deployment still constrains which host paths may be mounted, through whichever admission or VMM mechanism it already uses. What changed is that the sandbox policy no longer claims to be that constraint while being silently bounded by it.
