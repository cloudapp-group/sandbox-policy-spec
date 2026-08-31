# Spec: Exec Policy

Part of [Proposal 0001 — Sandbox Security Policy](./overview.md). The key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are to be interpreted as described in RFC 2119.

---

## 1. Scope

This spec defines the exec sub-policy of the `SandboxPolicy` object: constraints on command execution **initiated through the sandbox control interface** (process start, code run, interactive sessions).

It does **not** constrain processes the sandbox workload starts on its own once running; that is the filesystem and resource modules' territory (an allowlist exec policy is the tool for keeping unvetted code from running at all). This boundary is stated explicitly because it is the main honest limitation of exec policy.

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

1. The first whitespace-delimited token is the **command token**; the remainder are **argument patterns**.
2. A command token without `/` matches by command **name** (basename). A command token containing `/` matches by resolved absolute path. Name-form and path-form never match each other (`curl` does not match `/usr/bin/curl`).
3. Each argument pattern is a glob: `*` matches any sequence of characters (including spaces within one argument), `?` matches one character. A bare `*` matches any single argument. Literal characters match themselves.
4. Argument count matters: the pattern matches only if the number of arguments equals the number of argument patterns. `curl *` does not match `curl` with no arguments. To match "any arguments including none", provide two rules (`curl` and `curl *`) — v1 keeps count-exact matching because it is predictable.
5. Shell metacharacter composition (§4.3) is evaluated per sub-command after shell parsing; patterns never match across operators like `|`, `&&`, `;`.

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

### 4.4 Enforcement requirements

1. Matching MUST operate on the parsed argument vector, never on raw string containment.
2. User resolution MUST happen through the platform's user database, not by string comparison with prompt text.
3. The per-request `user` parameter of the existing process API is the only user-switching surface; policy applies identically to it.

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
| `POLICY_EXEC_UNPARSEABLE` | `{reason}` | Ambiguous command line (§4.3.4). |
| `INVALID_POLICY` (400) | `{field, reason}` | Configuration-time validation. |

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

1. Bypass corpus: for `denylist` mode, the corpus MUST include at least — shell composition (`curl x | sh`), command substitution (`$(curl x)`), quoting variants, name-form vs path-form (`sh` vs `/bin/sh`), argument-count mismatches — and each corpus entry MUST resolve to the intended sub-command decomposition and decision.
2. `allowlist` mode rejects any execution with an unmatched sub-command, including inside pipelines and substitutions.
3. Timeout clamp: requested 7200 under ceiling 3600 → runs with `effectiveTimeoutSec: 3600`.
4. Concurrency cap returns `POLICY_EXEC_CONCURRENCY_LIMIT` with a non-zero `retryAfterSec`.
5. Unparseable lines are rejected, never executed.
6. `unrestricted` default with no policy ⇒ behavior identical to today, except the timeout ceiling applies.
7. Merged `mode` is the most restrictive across sources.

## 10. Open questions

1. **Env vars per rule.** Should `CommandRule` grow per-rule environment constraints (e.g. forbid `HTTP_PROXY` overrides for network-relevant commands)? v1 leaves environment untouched.
2. **Working directory / path-based rules.** Should rules be able to scope by `cwd` (e.g. "allow `cargo build` only under `/workspace`")?
3. **Sessions.** Do interactive sessions get per-keystroke evaluation, or is the session established under one evaluation and filesystem/resource left to police it? v1: one evaluation at session start; re-evaluation is an open question.
4. **Default denylist.** Should the `unrestricted` default still ship a small built-in denylist (e.g. host-key tampering) the way filesystem ships a baseline? This is a policy-vs-surprise trade-off.
