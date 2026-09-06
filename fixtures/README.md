# Conformance fixtures — Proposal 0001

These fixtures exist to answer one question: **does every implementation resolve the same inputs into the same effective policy?** They are the concrete form of [overview.md](../specs/0001-sandbox-security-policy/en/overview.md) §11.16, and they are deliberately adapter-independent — nothing here names a runtime.

## Shape

Each fixture is a single YAML document with three parts:

```yaml
name:        # stable identifier, referenced by conformance results
spec:        # the normative section(s) under test
given:       # inputs: policy sources, capability set, clock
expect:      # required output: effective policy, decision, or error
```

`given` is a complete input, not a fragment. An evaluator MUST be able to produce `expect` from `given` alone, with no deployment context beyond what `given.capabilities` states. That is what makes a disagreement between two implementations a bug in one of them rather than a difference of configuration.

## Coverage status

The suite is **incomplete**, and this file tracks that honestly rather than implying a passing grade. The categories below are the minimum set §11.16 requires before the document set can be offered as implementable.

| Category | Fixtures | Status |
| --- | --- | --- |
| Tier resolution and the `compatibility` split (§7) | `tier-*.yaml` | Started |
| Source merge and narrow-only (§5) | `merge-*.yaml` | Started |
| Binding denies and provenance (network §4.6) | `binding-deny-*.yaml` | Started |
| Capability states and `enforcement` (§8.2) | `capability-*.yaml` | Started |
| Grant issuance, ceiling, expiry (§5.1) | — | **Missing** |
| Shadow evaluation output (§7.2) | — | **Missing** |
| Snapshot, clone, restore (§8.3) | — | **Missing** |
| Concurrent update and CAS (§4.2) | — | **Missing** |
| Canonical serialization and policy hash (§4.3.3) | — | **Missing** — blocked on the canonicalization rules themselves |
| Anything incorporated by reference (network §1) | — | **Blocked** on §11.15 |

The last two rows are the important ones. A hash whose canonicalization is undefined cannot be tested, and a dependency that is not published cannot be tested at all — which is exactly why §11.15 and §11.16 are release blockers rather than nice-to-haves.

## Running them

There is no reference evaluator in this repository yet. Until there is, these fixtures are a specification of expected behaviour that implementers can read and encode against their own evaluator. A fixture that no implementation has ever executed is a claim, not a test, and this file does not pretend otherwise.
