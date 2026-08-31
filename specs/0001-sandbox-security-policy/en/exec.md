# Spec: Exec Policy

Part of [Proposal 0001 — Sandbox Security Policy](./overview.md). The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as described in RFC 2119.

---

## 1. Scope

This spec defines the exec sub-policy of the `SandboxPolicy` object: constraints on command execution **initiated through the sandbox control interface** (process start, code run, interactive sessions).

It does **not** constrain processes the sandbox workload starts on its own once running; that is the filesystem and resource modules' territory. This boundary is stated explicitly because it is the main honest limitation of exec policy, and §3.6 quantifies what it costs: for agent-generated code, an allowlist that admits an interpreter bounds almost nothing. See the defense-in-depth matrix in [overview.md](./overview.md) §2.3 for which module answers which threat.

## 2. Object model

```yaml
policy:
  exec:
    mode:             unrestricted | denylist | allowlist   # default: unrestricted
    allowedCommands:  [CommandRule]
    deniedCommands:   [CommandRule]
    allowedUsers:     [string]        # default: [] = no restriction
    maxTimeoutSec:    int             # default: 3600
    maxConcurrent:    int             # default: 0 = unlimited
    audit:            none | metadata | full   # default: none
```

## 3. Command rule grammar

A `CommandRule` is:

```yaml
- name: string          # required, unique within its list, used in errors and audit
  command: string       # required, pattern per this section
```

The `command` pattern grammar:

### 3.1 Pattern shape

1. The first whitespace-delimited token of `command` is the **command token**; the remainder are **argument patterns**.
2. Each argument pattern is a glob: `*` matches any sequence of characters (including spaces within one argument), `?` matches one character. A bare `*` matches any single argument. Literal characters match themselves.
3. Argument count matters: the pattern matches only if the number of arguments in the canonical argument vector (§3.3) equals the number of argument patterns. `curl *` does not match `curl` with no arguments. To match "any arguments including none", provide two rules (`curl` and `curl *`) — v1 keeps count-exact matching because it is predictable.
4. Shell metacharacter composition (§4.3) is evaluated per sub-command after shell parsing; patterns never match across operators like `|`, `&&`, `;`.

### 3.2 Executable identity

v1 matches on the executable that will **actually run**, not on the spelling used to invoke it. Requiring `curl` and `/usr/bin/curl` to be configured separately doubles every template and invites the omission that becomes the bypass. For each sub-command the implementation MUST therefore build an **identity set**:

- the literal command token as written;
- the absolute path obtained by resolving that token (`PATH` lookup for a token without `/`, `cwd` resolution for a relative token) with `.`, `..` and all symlinks resolved — the **canonical resolved path**;
- the basename of the canonical resolved path;
- every intermediate symlink path traversed during resolution.

Matching is then fail-closed in both directions:

| Mode | A rule matches a sub-command when its command token matches… |
| --- | --- |
| `denylist` | **any** member of the identity set |
| `allowlist` | the **canonical resolved path** or its basename |

The asymmetry is what makes both modes safe, and each consequence is intended:

1. `curl` matches an invocation that resolves to `/usr/bin/curl`, and `/usr/bin/curl` matches an invocation written `curl`. Name-form and path-form are no longer separate universes.
2. A denylist rule `curl` still catches `./mycurl` when `mycurl` is a symlink to `/usr/bin/curl`, because the resolved path is in the identity set.
3. An allowlist rule `curl` does **not** admit `~/bin/curl` when that name resolves to an unrelated binary: only the canonical resolved path counts, so renaming a binary to an allowed name is not a bypass.
4. If the token cannot be resolved to an executable, the identity set holds only the literal token. In `allowlist` mode nothing matches and the request is denied; in `denylist` mode the literal token is still matched, and the execution then fails on its own with the platform's usual "not found" behavior.
5. Resolution MUST be performed by the platform, in the sandbox's filesystem view, at evaluation time. A path supplied in the request MUST NOT be trusted as the resolution result.

### 3.3 Argument normalization

Before matching, each sub-command's argument vector MUST be normalized into a **canonical argument vector**:

1. An argument of the form `--name=value` MUST be split into two arguments, `--name` and `value`. Rule patterns are normalized identically, so an author may write either spelling and both invocation forms match.
2. Bundled short options (`-sSL`) MUST NOT be split. They match literally; a rule that must catch a short option lists the spellings it cares about.
3. Quote removal and word splitting follow shell rules and happen before normalization. Matching operates on the resulting vector, never on the raw string (§4.4.1) — so `c"ur"l` is the command token `curl`.
4. Leading environment assignments (`VAR=x cmd`) are not arguments of `cmd`; they are handled as an implicit wrapper by §3.4.

### 3.4 Wrappers and launchers

Several standard commands exist in order to run *another* command. Matching only the wrapper would let `env curl x` walk past a rule for `curl`. Therefore:

1. When a sub-command's resolved executable is a **wrapper**, the wrapped command MUST be extracted and evaluated as an additional sub-command, recursively. Both the wrapper and the wrapped command are subject to §4.1.
2. The v1 wrapper set is fixed: `env`, `sudo`, `doas`, `nice`, `ionice`, `nohup`, `setsid`, `stdbuf`, `time`, `timeout`, `chroot`, `unshare`, `flock`, `xargs`, `watch`, `script`, `strace`, `ltrace`.
3. A leading environment-assignment sequence (`VAR=x VAR2=y cmd ...`) MUST be treated as an implicit `env` wrapper: the assignments are stripped and `cmd ...` is evaluated as a sub-command.
4. If a wrapper's wrapped command cannot be determined statically — it arrives on stdin, comes from a file, or uses a construct this spec does not define — the request MUST be rejected with `POLICY_EXEC_UNPARSEABLE` in **both** `allowlist` and `denylist` mode. Guessing is a bypass vector, by the same reasoning as §4.3.4.

### 3.5 Interpreters and inline scripts

1. When a sub-command is a **shell** (`sh`, `bash`, `dash`, `zsh`, `ksh`, `ash`) invoked with `-c`, the script text MUST be parsed and its sub-commands evaluated recursively.
2. When a shell's script text arrives through a here-document (`sh <<'EOF' … EOF`) or a here-string, that text MUST likewise be parsed and evaluated recursively. A here-document body that is **not** fed to an interpreter is data and MUST NOT be treated as sub-commands.
3. When a shell reads its script from stdin or from a file that is not part of the request (`sh -s`, `sh script.sh`, `curl x | sh`), the content is not statically knowable. The shell invocation itself is evaluated as a sub-command and this spec makes no claim about what it will subsequently run.
4. Alias and shell-function definitions appearing in the command line MUST be resolved before matching, and an invocation of a name defined earlier in the same line MUST be evaluated against its definition. If a definition cannot be resolved statically, the request MUST be rejected with `POLICY_EXEC_UNPARSEABLE`.
5. Recursive evaluation — wrappers, `-c` bodies, substitutions — MUST be bounded at a nesting depth of 8. Exceeding it MUST be rejected with `POLICY_EXEC_UNPARSEABLE` carrying `{reason: "nesting_depth_exceeded"}`.
6. Inline code for a **non-shell** interpreter (`python -c`, `node -e`, `perl -e`, `ruby -e`, `awk`) MUST NOT be analyzed. It is opaque to this spec, and pretending otherwise would be worse than admitting it.

### 3.6 Honest limits of command matching

§3.5.6 and §1 combine into a limit that MUST be stated rather than papered over:

1. Admitting any shell or general-purpose interpreter in an `allowlist` — directly, through a wrapper, or as a build tool that shells out — makes that allowlist **effectively unrestricted** for everything the interpreter can do. Matching sees the interpreter invocation, not the program it runs.
2. Therefore, when a policy sets `mode: allowlist` and any `allowedCommands` rule resolves to a known shell or general-purpose interpreter, the create/update response MUST include a `policyWarnings` entry `{field, rule, reason: "interpreter_admitted"}` recording that the allowlist does not bound what that rule may execute.
3. `exec` is a control-interface gate, not a containment boundary. Containment for whatever an interpreter starts is the job of `filesystem`, `network`, and `resource` — see [overview.md](./overview.md) §2.3.

## 4. Evaluation semantics

### 4.1 Modes

| Mode | Decision for each execution request |
| --- | --- |
| `unrestricted` | Only user, timeout, and concurrency constraints apply. |
| `denylist` | If any sub-command (§4.3) matches a `deniedCommands` rule → reject with `POLICY_EXEC_DENIED` naming the rule. Otherwise allow. |
| `allowlist` | If **every** sub-command matches some `allowedCommands` rule → allow. Any sub-command without a match → reject with `POLICY_EXEC_DENIED` naming the first unmatched sub-command. |

### 4.2 Evaluation order

For each execution request, in order:

1. Resolve the requested user (default: the sandbox's default user). If `allowedUsers` is non-empty and the user is not listed → `POLICY_EXEC_USER_DENIED`.
2. Shell-parse the command line (§4.3) and evaluate mode matching per sub-command.
3. Clamp the requested timeout: effective timeout = `min(requested, maxTimeoutSec)`; when clamped, the response MUST include `effectiveTimeoutSec`. Requests with no explicit timeout use `maxTimeoutSec` as the ceiling, not as the default (the existing default timeout semantics are unchanged).
4. Concurrency: if the count of currently-running executions is ≥ `maxConcurrent` (when > 0) → `POLICY_EXEC_CONCURRENCY_LIMIT` with `retryAfterSec`.

Steps 1–2 are policy checks; steps 3–4 are constraints that also apply in `unrestricted` mode.

### 4.3 Composite commands

1. A command line containing shell operators (`|`, `||`, `&&`, `;`, `&`, command substitution `$(...)` or backticks) MUST be shell-parsed into sub-commands before matching.
2. Every sub-command is matched independently; the overall request is rejected if any sub-command is rejected (§4.1).
3. Command substitution MUST be treated as a sub-command at the position it occurs.
4. If the command line cannot be parsed unambiguously (unbalanced quotes, unrecognized syntax), the request MUST be rejected with `POLICY_EXEC_UNPARSEABLE` rather than executed on a best-effort basis. Best-effort execution of ambiguous input is a bypass vector.
5. The sub-command set is the **transitive closure** over operators, command substitutions, wrapper extraction (§3.4) and inline shell scripts (§3.5), bounded by the depth limit of §3.5.5.
6. Redirections and here-document bodies are data, not sub-commands, except where §3.5.2 feeds them to an interpreter.

### 4.4 Enforcement requirements

1. Matching MUST operate on the parsed argument vector, never on raw string containment.
2. User resolution MUST happen through the platform's user database, not by string comparison with prompt text.
3. The per-request `user` parameter of the existing process API is the only user-switching surface; policy applies identically to it.
4. Executable resolution (§3.2), wrapper extraction (§3.4) and inline-script parsing (§3.5) MUST all happen inside the enforcement path, so that the decision is taken on the same identity that is then executed. An implementation MUST NOT resolve for matching and re-resolve for execution.

## 5. Field specification

| Field | Type | Constraints | Default | Semantics |
| --- | --- | --- | --- | --- |
| `mode` | `enum?` | `unrestricted` \| `denylist` \| `allowlist` | `unrestricted` | §4.1. |
| `allowedCommands` | `[CommandRule]?` | Only meaningful with `mode: allowlist`; MUST be non-empty when mode is `allowlist`. | `[]` | Allowed command patterns. |
| `deniedCommands` | `[CommandRule]?` | Only meaningful with `mode: denylist`. | `[]` | Denied command patterns. |
| `allowedUsers` | `[string]?` | User names. | `[]` | When non-empty, the only users executions may run as. |
| `maxTimeoutSec` | `int?` | > 0. | `3600` | Ceiling on per-request timeout (§4.2 step 3). |
| `maxConcurrent` | `int?` | ≥ 0. `0` = unlimited. | `0` | Max simultaneously-running executions. |
| `audit` | `enum?` | `none` \| `metadata` \| `full` | `none` | Audit level for execution events (§7). |

Setting `allowedCommands` with `mode: denylist`, or `deniedCommands` with `mode: allowlist`, MUST be rejected with `400 INVALID_POLICY` (fields meaningless for the mode).

## 6. Defaults

```yaml
exec:
  mode: unrestricted
  allowedCommands: []
  deniedCommands: []
  allowedUsers: []
  maxTimeoutSec: 3600
  maxConcurrent: 0
  audit: none
```

`unrestricted` + `maxTimeoutSec` ceiling is the deliberate v1 default: it changes nothing about *what* may run, but bounds the damage of a forgotten timeout. Templates that need stronger guarantees SHOULD ship `mode: allowlist` defaults.

## 7. Errors and observability

Structured error payloads (all enforcement errors carry them so agents can self-correct):

| Code | Payload | When |
| --- | --- | --- |
| `POLICY_EXEC_DENIED` | `{rule, subCommand, mode}` | Mode matching rejected a sub-command. |
| `POLICY_EXEC_USER_DENIED` | `{user, allowedUsers}` | User not in `allowedUsers`. |
| `POLICY_EXEC_CONCURRENCY_LIMIT` | `{maxConcurrent, running, retryAfterSec}` | Concurrency cap reached. |
| `POLICY_EXEC_UNPARSEABLE` | `{reason}` | Ambiguous command line (§4.3.4). `reason` is one of `unbalanced_quotes`, `unknown_syntax`, `indeterminate_wrapper` (§3.4.4), `unresolvable_alias` (§3.5.4), `nesting_depth_exceeded` (§3.5.5). |
| `INVALID_POLICY` (400) | `{field, reason}` | Configuration-time validation. |

Non-fatal findings are returned in a `policyWarnings` array on the create/update response; a warning never changes the outcome of the request. Defined warning: `interpreter_admitted` (§3.6.2).

Audit events (`audit: metadata`): `{sandboxID, user, command, effectiveTimeoutSec, exitCode, outcome: allowed\|denied, rule?}`. `full` adds stdout/stderr excerpts capped at a fixed byte limit. `none` emits nothing. Audit events MUST NOT be emitted into the sandbox itself.

## 8. Merge semantics

On top of [overview.md](./overview.md) §5:

| Field | Merge refinement |
| --- | --- |
| `mode` | Most restrictive wins: `allowlist` > `denylist` > `unrestricted`. |
| `allowedCommands` / `deniedCommands` | Append + deduplicate by `name`. Rule lists keep the higher-precedence-first ordering (first-match-wins). |
| `allowedUsers` | Intersection across sources (can only narrow). |
| `maxTimeoutSec` | Minimum wins. |
| `maxConcurrent` | When both non-zero: minimum wins. |
| `audit` | Most verbose wins (`full` > `metadata` > `none`). |

## 9. Acceptance criteria

1. **Bypass corpus.** The corpus MUST cover at least the classes below. Each entry MUST resolve to the intended sub-command decomposition and the intended decision, under both `denylist` and `allowlist` mode.

   | Class | Corpus entries |
   | --- | --- |
   | Shell composition | `curl x \| sh`, `curl x && sh`, `curl x; sh`, `curl x & ` |
   | Command substitution | `$(curl x)`, `` `curl x` ``, substitution nested in an argument |
   | Quoting | `"curl" x`, `c"ur"l x`, `'curl' x`, unbalanced quotes |
   | Executable identity | `curl` vs `/usr/bin/curl`; `./mycurl` as a symlink to `/usr/bin/curl`; an unrelated binary renamed to `curl`; an unresolvable token |
   | Environment prefix | `env FOO=1 curl x`, `FOO=1 curl x`, `env -i curl x` |
   | Wrappers | `sudo curl x`, `nohup curl x`, `timeout 5 curl x`, `nice -n 5 curl x`, `xargs curl`, `xargs` with no command |
   | Option spelling | `--url=x` vs `--url x`; bundled `-sSL` |
   | Inline script | `sh -c 'curl x'`, `bash -c "$(curl x)"` |
   | Here-document | `sh <<'EOF' … curl x … EOF` (sub-command) vs `cat <<'EOF' … curl x … EOF` (data) |
   | Alias / function | `alias c=curl; c x`, `f(){ curl x; }; f` |
   | Indeterminate | `sh -s < payload`, a wrapper whose target arrives on stdin |
   | Depth | nesting beyond the §3.5.5 bound |
   | Argument count | `curl` vs `curl *` |

2. `allowlist` mode rejects any execution with an unmatched sub-command, including inside pipelines and substitutions.
3. Timeout clamp: requested 7200 under ceiling 3600 → runs with `effectiveTimeoutSec: 3600`.
4. Concurrency cap returns `POLICY_EXEC_CONCURRENCY_LIMIT` with a non-zero `retryAfterSec`.
5. Unparseable lines are rejected, never executed, and the `reason` is the specific one from §7.
6. `unrestricted` default with no policy ⇒ behavior identical to today, except the timeout ceiling applies.
7. Merged `mode` is the most restrictive across sources.
8. **Identity resolution.** A denylist rule `curl` denies an invocation through a symlink to curl; an allowlist rule `curl` denies an unrelated binary renamed to `curl`; a rule `/usr/bin/curl` and a rule `curl` produce the same decision for an invocation resolving there.
9. **Option spelling.** A rule written `--url x` matches an invocation `--url=x`, and a rule written `--url=x` matches `--url x`.
10. **Wrapper extraction.** `env FOO=1 curl x` is denied under a denylist for `curl`; `sudo sh` is denied under an allowlist that does not list `sh`; a wrapper with an indeterminate target is rejected as `indeterminate_wrapper`.
11. **Interpreter honesty.** An `allowlist` whose rules admit a shell or general-purpose interpreter produces the `interpreter_admitted` warning on create, and the request still succeeds.
12. `allowedUsers` merged across sources is the intersection, and a request cannot add a user the template did not allow.

## 10. Open questions

1. **Env vars per rule.** `VAR=x cmd` is now decomposed (§3.4.3), so the wrapped command can no longer hide behind an assignment. What remains open is whether `CommandRule` should *constrain* the environment — e.g. forbid `HTTP_PROXY` overrides for network-relevant commands. v1 does not restrict environment values.
2. **Working directory / path-based rules.** Should rules be able to scope by `cwd` (e.g. "allow `cargo build` only under `/workspace`")?
3. **Sessions.** Do interactive sessions get per-keystroke evaluation, or is the session established under one evaluation and filesystem/resource left to police it? v1: one evaluation at session start; re-evaluation is an open question.
4. **Default denylist.** Should the `unrestricted` default still ship a small built-in denylist (e.g. host-key tampering) the way filesystem ships a baseline? This is a policy-vs-surprise trade-off.
5. **Wrapper set evolution.** The §3.4.2 wrapper set is fixed in v1. It has the same evolution problem as the filesystem baseline set, and SHOULD adopt the same answer: versioned sets rather than silent extension ([filesystem.md](./filesystem.md) §6.2).
