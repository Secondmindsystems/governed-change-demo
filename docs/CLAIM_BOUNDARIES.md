# Claim Boundaries

## Supported after the published verification commands pass

This repository may state that it demonstrates:

- deterministic evaluation of declared candidate-change snapshots;
- explicit separation between presented authority and CAP admissibility;
- a Context and Authority Precheck before domain policy gates;
- two heterogeneous repository policy gates;
- fail-closed `PASS`, `BLOCK`, and `HOLD` behavior;
- CAP short-circuit behavior;
- bounded repair followed by full CAP and gate re-evaluation;
- canonical hash-linked receipts;
- deterministic replay;
- product-local automated tests; and
- standalone reproduction without private dependencies.

Counts, receipt identities, hashes, and host-specific results must come from
[Verified Metrics](VERIFIED_METRICS.md) after regeneration.

## Not supported

Do not claim that this repository establishes:

- production or deployment readiness;
- cryptographic security or tamper-proof enforcement;
- branch protection or centralized enterprise enforcement;
- legal, regulatory, or contractual compliance;
- certification, endorsement, or audit approval;
- customer, market, revenue, adoption, or external validation;
- correctness of arbitrary prose, omitted claims, or external evidence;
- live repository enforcement;
- autonomous execution authority;
- that CAP grants authority;
- that a receipt certifies itself; or
- that Claims Gate determines arbitrary factual truth.

## Plain-language boundary

The prototype shows how one fixed, declared candidate snapshot can be checked
for admissibility before two different deterministic repository policies run,
then receive a traceable decision and linked repair history.

It does not prove that a live repository is protected, that presented
authority is legitimate outside the declared inputs, that the policies are
right for a real organization, or that a resulting change is safe to execute.
