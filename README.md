# One Change, Two Gates, One Receipt

A deterministic, standalone demonstration of governed repository-change
evaluation:

```text
candidate-change snapshot
-> Authority Manifest
-> Context and Authority Precheck (CAP)
-> Path Gate + Claims Gate
-> Combined Decision
-> hash-linked Governed Receipt
```

The original revision is blocked for two independent reasons. A bounded repair
increments the revision, re-enters through CAP, reruns both gates, and passes.
The new receipt preserves the prior decision by receipt ID and full SHA-256
hash.

If you want the shorter evidence-led overview before running the code, start
with the
[Governed AI Systems Portfolio](https://github.com/Secondmindsystems/governed-ai-systems-portfolio).

## What CAP means here

**Context and Authority Precheck (CAP)** is a deterministic precheck performed
before repository policy gates run. It checks whether the declared proposal,
authority, source basis, evidence state, policy versions, and required gates
are admissible for evaluation.

Some generated compatibility text retains internal source-project identifiers
where changing the strings would alter verified deterministic outputs. Those
identifiers are proof-preserving residue, not public dependencies or product
names. The public label describes the exported mechanism; it does not create
execution authority.

CAP does not execute a change, grant authority, certify the presented
authority, or predetermine either domain gate.

## Five-minute run

Requirements: Python 3.11 or newer. No installation, network, credentials,
provider, repository hook, or external service is required.

76 automated tests pass in the current published validation suite.

```bash
python3 -B -m governed_change_demo validate --fixture blocked --cap-policy policies/cap-policy.v1.json
python3 -B -m governed_change_demo demo --cap-policy policies/cap-policy.v1.json --output-dir evidence/demo-run
python3 -B -m governed_change_demo replay --fixture repaired --cap-policy policies/cap-policy.v1.json --runs 5
python3 -B -m unittest discover -s tests -v
```

Expected replay identity:

```text
sha256:10a2135e3e8127ab8ed9d17759d8507e424d0aba2ad73afaa183bf9cf00778f4
```

If you were not involved in building or reviewing this demo, you can
[return an independent PASS, FAIL, or CONFUSED report](https://github.com/Secondmindsystems/governed-change-demo/issues/1).

Independent third-party reproduction on separate hardware remains pending.

The numeric and receipt claims on this page are bound to the
[machine-readable public claims manifest](evidence/public-claims.v1.json).
CI reruns the executable evidence check on every change:

```bash
python3 -B tools/verify_public_claims.py
```

Expected canonical replay size: `25,194 bytes`.

The integrated demo should also report:

```text
demo: PASS
blocked receipt: receipt-2bbc3c4b0305f8394b83
repaired receipt: receipt-51bbb2e71998a45e59ff
repaired receipt hash: sha256:54346099dfef791368c87c2b259e6399ebb683ec4a37e90880c0d05989e6e8d8
```

## Bundled cases

| Fixture | Expected decision | Purpose |
| --- | --- | --- |
| `blocked` | `BLOCK` / exit `2` | CAP-admissible revision with independent Path and Claims failures |
| `repaired` | `PASS` / exit `0` | Incremented repair with CAP recheck and both gates passing |
| `cap-block` | `BLOCK` / exit `2` | CAP rejects admissibility; both domain gates are `NOT_EVALUATED` |
| `context-update` | `HOLD` / exit `3` | Source basis requires refresh |
| `hold` | `HOLD` / exit `3` | Required evidence is explicitly refreshable but unavailable |

`HOLD` is fail-closed. It is never a soft pass.

## Six contracts

The strict JSON Schema 2020-12 contracts under [`contracts/`](contracts/) are:

1. Shared Change Envelope
2. Authority Manifest
3. CAP Decision
4. Gate Result
5. Combined Decision
6. Governed Receipt

Runtime validation uses only the Python standard library.

## Two genuinely different gates

- **Path Gate** checks repository-relative paths and operations against
  explicit authority and path policy.
- **Claims Gate** checks a structured claim inventory against closed evidence,
  qualifier, limitation, and prohibited-claim rules.

They share a result contract but retain different policy logic and evidence.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Five-minute demo](docs/FIVE_MINUTE_DEMO.md)
- [Reproduction](docs/REPRODUCTION.md)
- [Outsider reproduction](docs/OUTSIDER_REPRODUCTION.md)
- [Adversarial test pack](docs/ADVERSARIAL_TEST_PACK.md)
- [Local prototype timings](docs/LOCAL_PROTOTYPE_TIMINGS.md)
- [Public validation campaign state](docs/PUBLIC_VALIDATION_CAMPAIGN_STATE.md)
- [Verified metrics](docs/VERIFIED_METRICS.md)
- [Limitations](docs/LIMITATIONS.md)
- [Claim boundaries](docs/CLAIM_BOUNDARIES.md)
- [Authorship and AI collaboration](docs/AUTHORSHIP_AND_AI_DISCLOSURE.md)

## Claim ceiling

This repository demonstrates deterministic evaluation of declared
candidate-change snapshots under fixed inputs, policies, evaluator versions,
and `evaluation_as_of`. It does not establish production or deployment
readiness, security, tamper resistance, branch protection, regulatory
compliance, certification, customer or market validation, live repository
enforcement, or execution authority.

See [Verified Metrics](docs/VERIFIED_METRICS.md) for observed results and
[Claim Boundaries](docs/CLAIM_BOUNDARIES.md) for the complete boundary.

## License

Licensed under the [Apache License 2.0](LICENSE). The license applies only to
the contents of this standalone repository. It grants no trademark,
certification, endorsement, or managed-service rights.
