# Spec: Process Policy

Part of [Proposal 0001 — Sandbox Security Policy](./overview.md). The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as described in RFC 2119.

---

## 1. Scope

This spec defines the process (`process`) sub-policy of the `SandboxPolicy` object: the constraints that apply to **a process that is already running inside the sandbox**, whichever way it was started. It governs three things:

- **Privilege gain** — whether a process may acquire privileges it did not start with.
- **Persistence** — whether a process may outlive the session that started it.
- **System calls** — which kernel entry points the sandbox may use at all.

This module exists because of a gap the rest of the proposal names explicitly. [exec.md](./exec.md) §1 and §3.6 state that `exec` policy is a control-interface gate and **not** a containment boundary: once a command is admitted, the process it starts may `fork`/`exec` anything without further `exec` evaluation, and for agent-generated code the admitted command is typically an interpreter. [overview.md](./overview.md) §2.3 draws the consequence — containment for self-started processes has to come from modules that enforce below the control interface.

`process` is that containment for the privilege and syscall surface, as `filesystem` is for paths and `network` is for destinations. The division of labour is fixed and not a matter of taste:

| Question | Module |
| --- | --- |
| May this command be started through the API? | `exec` |
| May this running process gain privilege, persist, or issue this syscall? | `process` (this spec) |
| May it read or write this path? | `filesystem` |
| May it reach this destination? | `network` |
| May it consume this much? | `resource` |

Not in scope: inter-sandbox and sandbox-to-host process isolation, which is a property of the sandbox model rather than a policy field ([overview.md](./overview.md) §12) — there is no field for it because there is nothing for a user to decide. Also not in scope: detecting anomalous, zombie, or malicious processes ([overview.md](./overview.md) §2.3.1), and process-count or CPU consumption, which are `resource` dimensions.

## 2. Object model

```yaml
policy:
  process:
    mode:                 baseline | unrestricted   # default: baseline
    noNewPrivileges:      bool                      # default: false
    allowDaemonize:       bool                      # default: true
    allowedCapabilities:  [string]                  # default: platform default set
    audit:                none | metadata           # default: none
    syscall:
      mode:                       baseline | denylist | allowlist   # default: baseline
      baselineVersion:            string            # e.g. "syscall/1"; default: platform default
      baselineExceptions:         [string]          # syscalls excluded from the baseline set
      deniedSyscalls:             [string]
      allowedSyscalls:            [string]
      implicitEssentialSyscalls:  bool              # default: true
      onViolation:                deny | kill       # default: deny
```

## 3. Privilege semantics

### 3.1 `noNewPrivileges`

When `true`, a process MUST NOT be able to acquire privileges it did not already hold:

1. `setuid` and `setgid` bits on executables MUST NOT take effect. An `execve` of such a binary either fails or proceeds with no privilege gain; which of the two is a mechanism choice, but the gain MUST NOT happen.
2. File capabilities MUST NOT take effect.
3. The property MUST be inherited by every descendant process and MUST NOT be droppable by the process itself. A restriction a process can lift is not a restriction.

The default is `false` at the `baseline` tier and `true` at `restricted` ([overview.md](./overview.md) §7.1). The default is permissive deliberately: `sudo` is a setuid binary, [exec.md](./exec.md) §3.4.2 lists it among the wrappers the platform is expected to parse, and images that use it are common. Denying privilege gain by default would break them at a point far from the policy that caused it. The credential-path precedent in [filesystem.md](./filesystem.md) §6.1 is different in kind — reading `~/.aws/credentials` is rare in a legitimate workload, whereas `sudo` is not.

### 3.2 `allowedCapabilities`

1. When non-empty, `allowedCapabilities` is the **complete** set of capabilities available to any process in the sandbox. Capabilities outside it MUST NOT be acquirable, including by a privileged user inside the sandbox.
2. Entries are capability names without a vendor prefix (`net_bind_service`, `sys_admin`, ...). Unknown names MUST be rejected with `400 INVALID_POLICY`.
3. An empty list means "platform default set", not "none". Removing every capability is expressed by an explicitly empty-of-privilege policy, i.e. by naming the small set the workload needs — never by omission (principle 2).

### 3.3 `allowDaemonize`

When `false`, a process MUST NOT outlive the session that started it:

1. Detaching from the controlling session (`setsid`), orphaning by double-`fork`, and reparenting to the init process MUST be denied.
2. When a session or an `exec` invocation terminates, its entire process group MUST be terminated with it.
3. Denial surfaces per §6.

### 3.4 The honest limitation: persistence is broader than this module

`allowDaemonize: false` stops a process from *detaching*. It does not stop a workload from arranging to be restarted, and this spec MUST NOT be read as if it did.

1. Autostart persistence is written to **files**: `crontab` entries, systemd units, shell profile scripts, `~/.bashrc`, XDG autostart entries. Blocking it is a `filesystem` concern (`denyPaths`, `readOnlyPaths`), not a syscall or session concern, because there is no kernel entry point that means "register yourself for later".
2. A policy that sets `allowDaemonize: false` and leaves those paths writable has closed one door. Deployments that care about persistence **SHOULD** pair it with `filesystem` denies for the persistence locations their image supports.
3. This module therefore constrains *this* process's lifetime, not the workload's ability to come back. Saying so is the point: the alternative is a field named after a guarantee it cannot make.

## 4. System call semantics

### 4.1 Modes

| Mode | Verdict for each system call |
| --- | --- |
| `baseline` | Denied if in the effective baseline set (§4.3). Otherwise allowed. |
| `denylist` | Denied if in the effective baseline set **or** in `deniedSyscalls`. Otherwise allowed. |
| `allowlist` | Allowed only if in `allowedSyscalls` or in the implicit essential set (§4.4), **and** not in the effective baseline set. Otherwise denied. |

The baseline set applies in all three modes, including `allowlist`. An allowlist that happens to name a baseline-denied syscall does not admit it; escaping the baseline is done through `baselineExceptions` (§4.3.3), where it is visible and audited, and nowhere else.

`mode: unrestricted` on the `process` object disables §3 and §4 in their entirety and MUST be represented explicitly in the effective policy; it never arises from omission.

### 4.2 Syscall names

1. Entries are architecture-independent syscall names as published by the platform (`init_module`, `bpf`, ...). Numeric syscall identifiers MUST NOT be accepted: they differ across architectures, and a policy that means different things on `arm64` and `x86_64` is a policy nobody can review.
2. Unknown names MUST be rejected with `400 INVALID_POLICY` naming the entry. Silently ignoring an unknown name would turn a typo in a denylist into a hole.
3. Where a syscall has multiple numbered variants on an architecture, naming it MUST cover all of them. A policy author writing `clone` MUST NOT have to know that `clone3` exists to be protected; the platform publishes the grouping.

### 4.3 The baseline set `syscall/1`

The built-in baseline deny set, in force whenever `mode` is not `unrestricted`:

```yaml
deniedSyscalls:
  - init_module
  - finit_module
  - delete_module
  - kexec_load
  - kexec_file_load
  - bpf
  - perf_event_open
  - pivot_root
  - setns
  - reboot
  - open_by_handle_at
  - iopl
  - ioperm
  - swapon
  - swapoff
  - add_key
  - keyctl
  - request_key
```

The selection rule is the same one that produced `baseline/1` in [filesystem.md](./filesystem.md) §6.1: deny what is dangerous *and* absent from legitimate application workloads. Loading a kernel module, replacing the running kernel, joining another process's namespace, or programming the I/O ports is not something an agent's Python script does on the way to a correct answer.

Three deliberate **exclusions**, recorded here so that nobody assumes they were forgotten:

| Excluded | Why |
| --- | --- |
| `ptrace` | Debuggers use it, and [exec.md](./exec.md) §3.4.2 lists `strace` and `ltrace` among the wrappers the platform parses. Denying it in the baseline would contradict a surface the proposal already expects to work. |
| `unshare`, `chroot` | Creating one's *own* namespace or root is what legitimate in-workload sandboxing tools do, and `chroot` and `unshare` are both in the `exec` wrapper set. Note the asymmetry with `setns`, which is denied: creating a new namespace is a workload activity, whereas *joining an existing* one is only useful for reaching something outside your boundary. |
| `mount`, `umount2` | Used by build and packaging tooling often enough that a baseline deny would produce confusing failures. Deployments that do not need it **SHOULD** add it via `deniedSyscalls`. |

Versioning follows [filesystem.md](./filesystem.md) §6.2 exactly, and for the same reason — new escape surfaces keep being discovered, so the set must be able to grow without breaking policies that resolved against an older one:

1. Baseline sets are **versioned and immutable**. `syscall/1` is the set above; a published version MUST NOT be modified in place.
2. New versions MUST only **add** entries. Removing one weakens every policy that resolves to that version and MUST go through an announced deprecation cycle.
3. `baselineVersion` pins the set. The effective policy MUST always record the **resolved** version, including when the policy did not pin one, so the version appears in the policy snapshot ([overview.md](./overview.md) §4.1).
4. An unpinned policy resolves to the platform's **default baseline version**. Rolling that default forward is an announced platform change with a deprecation window; it MUST NOT happen silently and MUST NOT affect pinned policies.
5. A sandbox keeps the version recorded in its effective policy for its whole lifetime. A new version reaches a running sandbox only through a policy update, which produces a new `effectivePolicyVersion`.

`baselineExceptions` is the narrow opt-out, on the same terms as [filesystem.md](./filesystem.md) §6.3:

1. Each entry MUST match an entry in the pinned baseline set exactly. An entry matching nothing MUST be rejected with `400 INVALID_POLICY`, so an exception cannot silently become dead configuration as the set evolves.
2. Exceptions apply **only** to the built-in set. They MUST NOT cancel an explicit `deniedSyscalls` entry from any source.
3. They merge as an **intersection**: an exception takes effect only if every contributing source declares it (narrow-only, [overview.md](./overview.md) §5).
4. Every effective exception MUST be recorded in the effective policy and MUST emit an audit event at sandbox creation. "This sandbox may call `bpf`" is never invisible to an operator.

### 4.4 The implicit essential set

`allowlist` mode has the same trap `writableRoots` has ([filesystem.md](./filesystem.md) §6.4): a list written to describe *what the workload does* omits everything the runtime does underneath it, and the result is not a readable policy denial but a process that cannot start.

Therefore, when `syscall.mode` is `allowlist`, a versioned **essential set** — the syscalls without which no process can be created, run, or exit (`execve`, `exit_group`, `mmap`, `brk`, `rt_sigreturn`, and their kin) — is implicitly allowed unless `implicitEssentialSyscalls: false`.

1. The essential set is additive to `allowedSyscalls` and is versioned alongside the baseline set. It never overrides the baseline deny set, which still wins under §4.1.
2. `implicitEssentialSyscalls: false` exists for policies built against a fully enumerated image profile. Such policies MUST list every syscall their runtime needs, and **SHOULD** be generated from an observed profile rather than written by hand.
3. The platform MUST record which essential-set version was applied in the effective policy.

### 4.5 Enforcement requirements

1. The policy MUST apply to **every process** the sandbox runs, not only to processes descended from a particular entry point. A process that shells out to an arbitrary binary MUST inherit the same restrictions.
2. Enforcement MUST NOT depend on environment variables, `LD_PRELOAD`, `PATH` manipulation, or any userspace-only interception — the same requirement as [filesystem.md](./filesystem.md) §4.3.2, and for the same reason: all of those are under the workload's control.
3. The restriction MUST be installed before the first instruction of the target program runs, and MUST be irreversible for the process and its descendants.
4. `onViolation: deny` surfaces the denial to the calling process as `EPERM`. `onViolation: kill` terminates the offending process instead. `kill` turns an exploited process into a dead process rather than one that learned which syscalls are filtered; `deny` keeps ill-fitting-but-honest workloads running. Neither is universally right, which is why it is a field.
5. Denials MUST NOT leak the identity of the matched rule to the sandbox in a way distinguishable from an ordinary permission failure. Rule identity belongs in the audit stream (§6), not in a side channel the workload can probe.

## 5. Field specification

| Field | Type | Constraints | Default | Semantics |
| --- | --- | --- | --- | --- |
| `mode` | `enum?` | `baseline` \| `unrestricted` | `baseline` | §4.1. `unrestricted` disables §3 and §4. |
| `noNewPrivileges` | `bool?` | — | `false` | §3.1. |
| `allowDaemonize` | `bool?` | — | `true` | §3.3. |
| `allowedCapabilities` | `[string]?` | Known capability names. | `[]` = platform default set | §3.2. |
| `audit` | `enum?` | `none` \| `metadata` | `none` | Audit level for process-policy events (§6). |
| `syscall.mode` | `enum?` | `baseline` \| `denylist` \| `allowlist` | `baseline` | §4.1. |
| `syscall.baselineVersion` | `string?` | A published set identifier. Unknown values MUST be rejected with `400 INVALID_POLICY`. | platform default | §4.3. |
| `syscall.baselineExceptions` | `[string]?` | Each entry MUST match an entry of the pinned set exactly. | `[]` | §4.3. |
| `syscall.deniedSyscalls` | `[string]?` | Meaningful only when `mode: denylist`. | `[]` | Additional denied syscalls. |
| `syscall.allowedSyscalls` | `[string]?` | Meaningful only when `mode: allowlist`; MUST be non-empty then. | `[]` | The permitted set, plus §4.4. |
| `syscall.implicitEssentialSyscalls` | `bool?` | — | `true` | §4.4. |
| `syscall.onViolation` | `enum?` | `deny` \| `kill` | `deny` | §4.5.4. |

Setting `allowedSyscalls` under `mode: denylist`, or `deniedSyscalls` under `mode: allowlist`, MUST be rejected with `400 INVALID_POLICY`: the field has no meaning in that mode, and accepting it would let an author believe a list is in force when it is not.

### 5.1 Tier defaults

Which defaults apply is selected by `policy.tier` ([overview.md](./overview.md) §7.1):

| Field | `tier: baseline` (default) | `tier: restricted` |
| --- | --- | --- |
| `mode` | `baseline` | `baseline` |
| `syscall.mode` | `baseline` | `baseline` |
| `noNewPrivileges` | `false` | `true` |
| `allowDaemonize` | `true` | `false` |
| `audit` | `none` | `metadata` |

Both tiers put the `syscall/1` deny set in force. Only privilege gain and persistence differ, because those are the two decisions that can be made without knowing the workload: an image either needs `sudo` or it does not, and the failure is immediate and legible either way. The syscall surface is not a tier decision for the opposite reason — narrowing it further requires knowing which syscalls the image uses, and a tier that guessed would produce the unstartable-process failure §4.4 exists to prevent. Whether `restricted` should pull in a second, larger baseline set is recorded as §10.2.

`tier: baseline` here is not byte-for-byte today's behavior — the `syscall/1` set is new, and this module did not exist before. It is one of the two deliberate exceptions to the compatibility rule ([overview.md](./overview.md) §9), and it is bounded the same way the other one is: the set is versioned, pinnable, and escapable per entry through `baselineExceptions` (§4.3).

## 6. Errors and observability

| Code | Surface | Payload | When |
| --- | --- | --- | --- |
| `POLICY_PROCESS_SYSCALL_DENIED` | `EPERM` to the process; audit event | `{syscall, mode, source}` | A syscall was denied under §4.1. |
| `POLICY_PROCESS_PRIVILEGE_DENIED` | OS-level failure; audit event | `{operation, binary?}` | Privilege gain denied under §3.1 or a capability denied under §3.2. |
| `POLICY_PROCESS_PERSISTENCE_DENIED` | OS-level failure; audit event | `{operation}` | Detach or reparent denied under §3.3. |
| `INVALID_POLICY` | `400` | `{field, reason}` | Unknown syscall or capability name, exception not present in the pinned set, empty `allowedSyscalls` under `allowlist`, field meaningless for the mode. |

As with `filesystem`, enforcement errors are OS-level rather than API-level, because the policy applies below the API surface.

Audit events at `audit: metadata`: `{sandboxID, event: syscall_denied|privilege_denied|persistence_denied, syscall?, operation?, pid, comm, outcome: denied|killed, effectivePolicyVersion}`. Every effective `baselineExceptions` entry emits `{sandboxID, baselineVersion, exception, sources}` at creation (§4.3). Audit events MUST NOT be written inside the sandbox.

A workload that trips a syscall denial usually trips it repeatedly. Implementations **SHOULD** aggregate identical `{syscall, pid}` denials rather than emitting one event per call, so an audit stream stays legible under a tight `allowlist`.

## 7. Merge semantics

On top of the shared rules in [overview.md](./overview.md) §5:

| Field | Merge refinement |
| --- | --- |
| `mode` | Most restrictive wins: if any source says `baseline`, the result is `baseline`. |
| `noNewPrivileges` | `true` wins. |
| `allowDaemonize` | `false` wins. |
| `allowedCapabilities` | **Intersection** across sources (narrow-only). A request cannot add a capability the template did not permit. |
| `syscall.mode` | Most restrictive wins: `allowlist` > `denylist` > `baseline`. |
| `syscall.baselineVersion` | The latest pinned version wins; since versions only add entries (§4.3.2), latest is also most restrictive. |
| `syscall.baselineExceptions` | Intersection: an exception takes effect only if every source declares it. |
| `syscall.deniedSyscalls` | Append + deduplicate. |
| `syscall.allowedSyscalls` | **Intersection** across sources: a higher-precedence source can only shrink the permitted set. Appending would let a request widen an administrator's allowlist, which §5 forbids. |
| `syscall.implicitEssentialSyscalls` | `false` wins (most restrictive). |
| `syscall.onViolation` | `kill` wins. |
| `audit` | Most detailed wins (`metadata` > `none`). |

## 8. Grantable fields

Per [overview.md](./overview.md) §5.1.8, this module names what a time-bounded grant may open:

| Grantable | Not grantable |
| --- | --- |
| `syscall.baselineExceptions` — named entries, for a bounded window | `mode: unrestricted` |
| `syscall.allowedSyscalls` — named additions to the permitted set | `noNewPrivileges: false` |
| `allowedCapabilities` — named capabilities | `syscall.implicitEssentialSyscalls` |
| `allowDaemonize: true` | |

`mode: unrestricted` and `noNewPrivileges: false` are excluded because a grant must be "a hole of known shape" ([overview.md](./overview.md) §5.1.4). Flipping `noNewPrivileges` opens every setuid binary and every file capability in the image at once; the operator approving it cannot know what they approved. A task that genuinely needs elevated privilege for ten minutes asks for the capability it needs, which is reviewable, and gets it back at expiry.

Every grant here remains subject to the ceiling ([overview.md](./overview.md) §5.1.3): a grant MUST NOT reopen a capability or syscall that a template or profile closed.

## 9. Acceptance criteria

1. **Universal application.** A process started through `exec`, a process it `fork`/`exec`s, and a process started by an interpreter admitted under an `exec` allowlist are all subject to identical `process` policy. Specifically: with `syscall/1` in force, `init_module` is denied whether it is reached from the control interface or from inside an admitted `python -c` script.
2. **Baseline survives allowlist.** A policy with `syscall.mode: allowlist` naming `bpf` in `allowedSyscalls` still denies `bpf`, because the baseline set wins (§4.1). Admitting it requires a `baselineExceptions` entry, which produces the creation-time audit event.
3. **Deliberate exclusions.** With only the baseline in force, `ptrace`, `unshare`, and `chroot` succeed while `setns` is denied.
4. **Irreversibility.** A process cannot lift `noNewPrivileges`, cannot regain a capability outside `allowedCapabilities`, and cannot remove its syscall filter. Descendants inherit all three.
5. **Privilege gain.** With `noNewPrivileges: true`, executing a `setuid` binary yields no privilege gain; with `noNewPrivileges: false` (the baseline-tier default), the same binary behaves as it does today.
6. **Persistence.** With `allowDaemonize: false`, `setsid` and double-`fork` orphaning are denied, and terminating a session terminates its whole process group. With the default `true`, both work as today.
7. **Names, not numbers.** A policy using a numeric syscall identifier is rejected; a policy naming a syscall with multiple numbered variants covers all of them on every supported architecture.
8. **Unknown entries.** An unknown syscall name, an unknown capability name, and a `baselineExceptions` entry absent from the pinned set are each rejected with `400 INVALID_POLICY` and a `field` pointer.
9. **Essential set.** `syscall.mode: allowlist` with `allowedSyscalls: [read, write]` starts a process successfully with `implicitEssentialSyscalls: true`, and the effective policy records the applied essential-set version. With `implicitEssentialSyscalls: false` and the same list, process creation fails as a policy denial with an audit event — not as an unexplained crash.
10. **Violation action.** `onViolation: deny` returns `EPERM` and leaves the process running; `onViolation: kill` terminates it. Both emit an audit event carrying `effectivePolicyVersion`.
11. **Version pinning.** A sandbox pinned to `syscall/1` is unaffected when the platform default rolls to `syscall/2`; an unpinned sandbox records the resolved version in its effective policy and snapshot either way.
12. **Merge.** `allowedCapabilities` and `allowedSyscalls` are intersected across sources — a request cannot widen either. `noNewPrivileges: true`, `allowDaemonize: false`, `onViolation: kill`, and the most restrictive `syscall.mode` each win from any source.
13. **Exception intersection.** A `baselineExceptions` entry declared by the request but not by the template does not take effect, and its ineffectiveness is reported per [overview.md](./overview.md) §5.
14. **Grants.** A grant adding a named capability expires without any action by the sandbox or the task, after which the capability is unavailable again; a grant attempting `mode: unrestricted` or `noNewPrivileges: false` is rejected; a grant attempting to reopen a capability the template closed is rejected with `POLICY_GRANT_EXCEEDS_CEILING`.
15. **No side channel.** A denied syscall is indistinguishable from an ordinary permission failure from inside the sandbox; the matched rule appears only in the audit stream.

## 10. Open questions

1. **Process count and fork bombs.** A process-count ceiling is consumption, so it belongs in `resource` by the seam this proposal draws — but it is enforced at process creation, like everything here. Which module gets it?
2. **Restricted-tier syscall set.** `tier: restricted` currently expands to the same baseline set as `tier: baseline` ([overview.md](./overview.md) §7.1). Should `restricted` pull in a second, larger versioned set (adding `mount`, `umount2`, `unshare`) rather than only tightening privilege and persistence?
3. **Profile generation.** §4.4.2 recommends generating `allowlist` policies from an observed profile. Should the platform offer that observation as a supported feature (a "record syscalls, emit candidate policy" mode), or is a hand-written allowlist the only supported path?
4. **Capability defaults.** §3.2.3 leaves "platform default set" to the platform. Should the default set itself be a versioned, published set, on the same terms as the syscall baseline, so that it is pinnable and auditable?
5. **Persistence path set.** §3.4 pushes autostart persistence to `filesystem`. Should the filesystem baseline gain a versioned persistence-path set (`crontab`, systemd units, shell profiles), so that `allowDaemonize: false` has a documented companion instead of a recommendation?
6. **Hot application.** Can an updated process policy apply to already-running processes, or only to new ones? Syscall filters are typically installed at process creation and are irreversible by design, which suggests "new processes only" — and per [overview.md](./overview.md) §11.2 that would mean this module cannot accept grants against already-running processes. This spec MUST NOT ship without a stated answer.

## 11. Non-normative notes

- Every requirement here is expressible with per-process, unprivileged, per-sandbox mechanisms (a seccomp-style filter installed at process creation, the kernel's no-new-privileges flag, a bounding capability set, per-session process-group tracking). As elsewhere in this proposal, the spec fixes *properties* and leaves mechanism selection open.
- The one-kernel-per-sandbox model is what makes a syscall policy affordable: the filter is scoped to a single tenant's kernel, so narrowing it cannot destabilise a neighbour ([overview.md](./overview.md) §12).
- Analogues studied: Kubernetes Pod Security Standards and `seccompProfile`, Docker's default seccomp profile and `--security-opt no-new-privileges`, systemd unit sandboxing directives.
