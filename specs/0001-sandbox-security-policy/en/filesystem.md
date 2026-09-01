# Spec: Filesystem Policy

Part of [Proposal 0001 — Sandbox Security Policy](./overview.md). The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as described in RFC 2119.

---

## 1. Scope

This spec defines the filesystem sub-policy of the `SandboxPolicy` object. The sandbox filesystem boundary is two-sided, and so is the policy:

1. **Host boundary** — which host paths may be mounted into the sandbox, and with what default writability. This formalizes the existing host-mount prefix allowlist as part of the user-facing policy.
2. **Sandbox boundary** — which paths *inside* the sandbox may be read, written, or executed, applied to every process the sandbox runs.

Out of scope: content inspection, quotas on file count/size (covered by resource limits for bytes written), and image-layer construction. Also out of scope: detecting anomalous file access, which is an audit-stream concern rather than a policy field ([overview.md](./overview.md) §2.3.1).

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
    mounts:
      allowedHostPrefixes: [string]            # host paths that may be mounted
      defaultReadOnly:     bool                # default: false
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

### 4.4 Host boundary semantics

1. A mount request whose host path does not fall under any `mounts.allowedHostPrefixes` entry MUST be rejected at create time with `400 POLICY_FS_MOUNT_FORBIDDEN`.
2. `mounts.defaultReadOnly: true` means mounts that do not explicitly request read-write are mounted read-only.
3. Prefix validation MUST resolve `..` before matching (path-traversal attempts rejected).
4. The cluster-side operator allowlist remains as a **bounding constraint**: the effective `allowedHostPrefixes` MUST be the intersection of policy-declared prefixes and operator-configured prefixes. Policy cannot widen what the operator forbids.

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
| `mounts.allowedHostPrefixes` | `[string]?` | Absolute host paths, no wildcards. | operator config | Which host paths may be mounted into this sandbox. |
| `mounts.defaultReadOnly` | `bool?` | — | `false` | Default writability of mounts without explicit mode. |

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

| | `tier: baseline` (default) | `tier: restricted` |
| --- | --- | --- |
| `mode` | `baseline` | `baseline` |
| `baselineVersion` | platform default | platform default |
| `mounts.defaultReadOnly` | `false` | `true` |

Note that `baseline` and `restricted` share `mode: baseline`. That is deliberate and is one of only two places in the proposal where a module's `baseline` tier is not byte-for-byte today's behavior ([overview.md](./overview.md) §9): the sensitive-path deny set is on at the default tier, because a credential path a legitimate workload never reads is not a compatibility surface worth preserving. A deployment that disagrees pins `baselineExceptions` or sets `mode: unrestricted`, both of which are recorded and audited (§6.3.4).

`tier: restricted` changes one field: mounts arrive read-only unless the mount request asks for write. It does not narrow the in-sandbox path rules, because there is no useful guess to make — a restricted tier that turned on `writableRoots` would have to invent the root, and inventing `/workspace` for an image that builds in `/src` is the confusing-build-failure outcome §6.4 exists to avoid.

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
| `mounts.allowedHostPrefixes` | Intersection across sources (mount surface can only narrow, never widen). |
| `mounts.defaultReadOnly` | `true` wins (most restrictive). |

### 7.1 Grantable fields

Per [overview.md](./overview.md) §5.1.8, a time-bounded grant against this module may open:

| Grantable | Not grantable |
| --- | --- |
| `baselineExceptions` — named baseline paths | `mode: unrestricted` |
| `writableRoots` — named roots | `denyPaths` removal of any entry |
| `readOnlyPaths` — removal of a named entry | `implicitRuntimeWritable` |
| | `mounts.allowedHostPrefixes` |

Two exclusions carry the weight. `denyPaths` is not grantable because an explicit deny is the one statement in this module whose author meant it literally; `baselineExceptions` already covers "one built-in path, temporarily", and it covers it with the audit trail of §6.3.4. `mounts.allowedHostPrefixes` is not grantable because the host boundary is bounded by operator configuration (§4.4.4), so a grant could not widen it in the first place — saying so is cheaper than letting someone discover it by trying.

A grant of `writableRoots` when `writableRoots` was empty is a **narrowing**, not a widening: it switches the module from "writes allowed by default" to "writes allowed only here". A grant MUST NOT have that effect ([overview.md](./overview.md) §5.1.4 — a grant opens a hole of known shape, it does not change the shape of the policy). Such a request MUST be rejected with `400 POLICY_GRANT_INVALID`.

## 8. Errors

Configuration errors (create/update time): `400 INVALID_POLICY` (malformed pattern, mutual exclusion violated, unknown `baselineVersion`, `baselineExceptions` entry not present in the pinned baseline set), `400 POLICY_FS_MOUNT_FORBIDDEN` (host path outside allowlist), `400 POLICY_GRANT_INVALID` (a grant targeting a non-grantable field, or a `writableRoots` grant against an empty `writableRoots`, §7.1).

Enforcement errors are OS-level, not API-level, because the policy applies below the API surface:

| Access | Result |
| --- | --- |
| Read under `denyPaths` | `EACCES` |
| Write under `readOnlyPaths` / outside `writableRoots` | `EACCES` or `EROFS` |
| Create/delete/rename under read-only | `EACCES` |
| Directory listing of a denied directory | `EACCES` |

Denials MUST NOT be distinguishable from ordinary permission failures in a way that leaks the rule identity to the sandbox process (no error-channel oracle); rule identity appears only in the audit stream (§9).

## 9. Observability

1. Filesystem denials SHOULD be reported as audit events with `{sandboxID, rule (pattern), path, op (read|write|...), outcome: denied}` at the module's configured audit level; `mode: unrestricted` disables baseline-set events but not explicit `denyPaths` events.
2. Audit payloads MUST NOT include file contents.
3. Each effective `baselineExceptions` entry MUST emit an audit event at sandbox creation with `{sandboxID, baselineVersion, exception, sources}` (§6.3.4). Weakening the baseline is an event, not a silent field.

## 10. Open questions

1. **Hot application.** Can an updated filesystem policy apply to already-running processes, or only to new ones? Kernel rule-set re-application semantics differ per mechanism; the spec needs a stable answer.
2. **Default-version rollout.** §6.2.4 requires an announced deprecation window before the default baseline version moves. How long is it, and through which channel is it announced?
3. **Exec bit.** Should the spec distinguish execute permission from read? v1 ties execution to network/exec policy instead; confirm.
4. **Image-level declarations.** `baselineExceptions` is per-policy. If a future baseline version denies a path that a specific *image* legitimately needs, is a per-policy exception enough, or does the image need to declare it once so every policy using that image inherits it?
5. **Temporary-data cleanup at task end.** Nothing here states what happens to data a task wrote once the task is over. The implicit runtime-writable set (§6.4) and any `writableRoots` persist for the sandbox's lifetime, so a sandbox reused across tasks carries one task's scratch files, caches, and downloaded artifacts into the next. Is that a policy field (e.g. paths to wipe at task boundaries), a lifecycle operation outside this module, or deliberately the caller's job? The prior question is whether the platform even has a notion of a "task boundary" distinct from the sandbox lifetime — [overview.md](./overview.md) §11.8 tracks that, and this question cannot be answered before it.
6. **Snapshot and restore.** §4.2 governs access by processes inside the sandbox. A snapshot reads the filesystem from *outside* it, and a restore writes one. Neither passes through the decision order, so today a `denyPaths` entry does not prevent its contents from leaving in a snapshot image. Does snapshot/restore need its own declared permission — and if the answer is that `denyPaths` should exclude paths from snapshots, that is a substantial change to what the field means and belongs in a version of this spec that says so explicitly.
7. **Exec bit, revisited.** Question 3 defers execute permission to `exec` policy. With [process.md](./process.md) now specifying syscall-level enforcement, the alternative is clearer: deny-execute-by-path is a filesystem rule, while denying `execve` outright is a process rule, and neither is the `exec` control interface. Confirm that no-exec-by-path stays out of v1.

## 11. Non-normative notes

- Each sandbox owns a whole kernel, so the requirements in §4.3 can be met by in-kernel, unprivileged, per-sandbox mechanisms (e.g. an LSM with per-process rule sets, or equivalent syscall-level enforcement). The spec intentionally mandates only the *properties*, not the mechanism. [process.md](./process.md) §4.5 states the same requirements for the syscall surface, and the two are expected to be satisfiable by one mechanism.
- The host-boundary rules formalize existing behavior (prefix allowlist + read-only remount) without changing it.
