# Spec: Filesystem Policy

Part of [Proposal 0001 — Sandbox Security Policy](./overview.md). The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as described in RFC 2119.

---

## 1. Scope

This spec defines the filesystem sub-policy of the `SandboxPolicy` object. The sandbox filesystem boundary is two-sided, and so is the policy:

1. **Host boundary** — which host paths may be mounted into the sandbox, and with what default writability. This formalizes the existing host-mount prefix allowlist as part of the user-facing policy.
2. **Sandbox boundary** — which paths *inside* the sandbox may be read, written, or executed, applied to every process the sandbox runs.

Out of scope: content inspection, quotas on file count/size (covered by resource limits for bytes written), and image-layer construction.

## 2. Object model

```yaml
policy:
  filesystem:
    mode:            baseline | unrestricted   # default: baseline
    denyPaths:       [string]                  # no access at all
    readOnlyPaths:   [string]                  # read allowed, writes denied
    writableRoots:   [string]                  # inverse form: writes allowed only under these roots
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

1. If the resolved path matches any `denyPaths` pattern (or the built-in baseline set, §6) → **deny all access** (`EACCES`).
2. Else if `writableRoots` is non-empty and the resolved path does not match any `writableRoots` pattern → **read-only** (writes fail with `EACCES`/`EROFS`).
3. Else if the resolved path matches any `readOnlyPaths` pattern → **read-only**.
4. Else → default (read-write, subject to image-layer permissions).

`denyPaths` always wins over `writableRoots` and `readOnlyPaths`. Rule 2 and rule 3 are mutually exclusive formulations; see §5 constraints.

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
| `denyPaths` | `[string]?` | Pattern syntax §3. | `[]` (+ baseline set) | No access whatsoever. |
| `readOnlyPaths` | `[string]?` | Pattern syntax §3. MUST be empty when `writableRoots` is non-empty. | `[]` | Reads allowed; writes/create/delete denied. |
| `writableRoots` | `[string]?` | Pattern syntax §3. MUST be empty when `readOnlyPaths` is non-empty. | `[]` | When non-empty, writes allowed only under these roots. |
| `mounts.allowedHostPrefixes` | `[string]?` | Absolute host paths, no wildcards. | operator config | Which host paths may be mounted into this sandbox. |
| `mounts.defaultReadOnly` | `bool?` | — | `false` | Default writability of mounts without explicit mode. |

Violating the `readOnlyPaths`/`writableRoots` mutual exclusion MUST fail with `400 INVALID_POLICY` naming both fields.

## 6. Defaults

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

Baseline exists to stop in-sandbox credential theft: agent-generated code running as the sandbox user must not be able to read the very credentials that authenticate that user to external services. It is deliberately a **fixed set** in v1 — not user-extensible without `denyPaths` — so that its meaning stays predictable.

`mode: unrestricted` MUST be represented explicitly in the effective policy; it never results from omission.

## 7. Merge semantics

On top of [overview.md](./overview.md) §5:

| Field | Merge refinement |
| --- | --- |
| `mode` | Most restrictive wins: if any source says `baseline`, the result is `baseline`. |
| `denyPaths` | Append + deduplicate (including baseline set when active). |
| `readOnlyPaths` / `writableRoots` | Append + deduplicate. The mutual-exclusion constraint is validated on the **merged** result, not per source. |
| `mounts.allowedHostPrefixes` | Intersection across sources (mount surface can only narrow, never widen). |
| `mounts.defaultReadOnly` | `true` wins (most restrictive). |

## 8. Errors

Configuration errors (create/update time): `400 INVALID_POLICY` (malformed pattern, mutual exclusion violated), `400 POLICY_FS_MOUNT_FORBIDDEN` (host path outside allowlist).

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

## 10. Open questions

1. **Hot application.** Can an updated filesystem policy apply to already-running processes, or only to new ones? Kernel rule-set re-application semantics differ per mechanism; the spec needs a stable answer.
2. **Baseline set evolution.** How does the built-in set get extended (new credential locations) without breaking templates that legitimately read one of them?
3. **Exec bit.** Should the spec distinguish execute permission from read? v1 ties execution to network/exec policy instead; confirm.
4. **Images that write `/etc`.** Some package managers write to `/etc`. Does `baseline` need an image-level annotation that opts specific paths out?

## 11. Non-normative notes

- Each sandbox owns a whole kernel, so the requirements in §4.3 can be met by in-kernel, unprivileged, per-sandbox mechanisms (e.g. an LSM with per-process rule sets, or equivalent syscall-level enforcement). The spec intentionally mandates only the *properties*, not the mechanism.
- The host-boundary rules formalize existing behavior (prefix allowlist + read-only remount) without changing it.
