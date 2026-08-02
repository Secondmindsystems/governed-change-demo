# Verified Metrics

Status: `VERIFIED_STANDALONE_DETERMINISTIC_PROTOTYPE`

These results describe fixed prototype inputs only.

## Acceptance baseline

| Check | Observed result |
| --- | --- |
| Six-contract validation | `PASS`; six schemas; zero reported issues |
| Integrated demo | revision 1 `BLOCK`; revision 2 `PASS` |
| Repaired replay | five runs; byte-identical; 25,194 canonical bytes |
| Reversed gate order | same decision, receipt identity, and replay identity |
| Test suite | 73 run; 73 passed; zero failures, errors, or skips |
| Standalone reproduction | validation, demo, replay, workflow parse, and all tests passed in an isolated copy |

No network, package installation, provider, credential, private repository, or
private runtime dependency was used.

## Flagship receipt evidence

| Revision | CAP | Path | Claims | Combined | Receipt ID | Receipt hash |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | `PASS` | `BLOCK` | `BLOCK` | `BLOCK` | `receipt-2bbc3c4b0305f8394b83` | `sha256:1a2dd8d031b21da78390bbbcdb626bbdfa89ba628520194de17d69607fc9f505` |
| 2 | `PASS` | `PASS` | `PASS` | `PASS` | `receipt-51bbb2e71998a45e59ff` | `sha256:54346099dfef791368c87c2b259e6399ebb683ec4a37e90880c0d05989e6e8d8` |

Revision 2 records `cap_rechecked: true` and links the prior receipt by both ID
and full hash.

Replay identity:

```text
sha256:10a2135e3e8127ab8ed9d17759d8507e424d0aba2ad73afaa183bf9cf00778f4
```

## CAP short-circuit evidence

| Case | CAP | Combined | Domain gates |
| --- | --- | --- | --- |
| Inadmissible proposal | `BLOCK` | `BLOCK` | both `NOT_EVALUATED` |
| Source basis requires refresh | `HOLD:CONTEXT_UPDATE_REQUIRED` | `HOLD` | both `NOT_EVALUATED` |
| Refreshable evidence unavailable | `HOLD:CONTEXT_UPDATE_REQUIRED` | `HOLD` | both `NOT_EVALUATED` |

Both skipped gate records use `CAP_NOT_PASSED`. Neither permits evaluation or
execution.

## Policy-byte identity

```text
CAP:    sha256:32537c05c37be5a419790b4576edb9901b3ae1418f5693c75c1a01c8ef86f6b3
Path:   sha256:cc3e424331e5eff147dc5192ee97a2907533f953eb029c41fde5f8d569a0cfeb
Claims: sha256:d7210ff1bd1244bff5620cded67e041105389089bb6e1184774204b583f33098
```

Changing policy bytes while retaining the same version label changes the
policy hash and replay identity.

## Evidence boundary

These are deterministic prototype metrics, not production, deployment,
security, compliance, customer, market, adoption, or external-validation
metrics. Outsider reproduction remains a separate evidence milestone.
