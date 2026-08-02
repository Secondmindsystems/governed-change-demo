# Five-Minute Demo

## 0:00 — State the promise

> One logical change. One Context and Authority Precheck. Two heterogeneous
> repository policy gates. One consolidated receipt per revision. The original
> blocks, the bounded repair re-enters through CAP and passes, and linked
> hashes preserve why.

CAP determines whether a proposal is admissible for evaluation. It does not
execute the proposal, create authority, certify the authority issuer, or
replace either gate.

## 0:30 — Validate the six contracts

```bash
python3 -B -m governed_change_demo validate \
  --fixture blocked \
  --cap-policy policies/cap-policy.v1.json
```

Expected: `contract_validation: PASS` and `schema_count: 6`. Contract validity
does not imply that the proposed change is allowed.

## 1:00 — Inspect the declared snapshot

The Shared Change Envelope contains a fixed candidate snapshot: logical change
ID, revision, source basis, repository-relative paths, before/after hashes,
proposed content, structured claims, policies, evidence requirements, and
supplied `evaluation_as_of`.

The original revision gives each domain gate an independent reason to block:

- Path Gate finds an endpoint outside permitted scope and within a denied
  prefix.
- Claims Gate finds a prohibited or unsupported high-authority assertion.

## 1:45 — Run BLOCK, repair, and PASS

```bash
python3 -B -m governed_change_demo demo \
  --cap-policy policies/cap-policy.v1.json \
  --output-dir evidence/demo-run
```

Expected sequence:

- revision 1: CAP `PASS`, Path `BLOCK`, Claims `BLOCK`, Combined `BLOCK`;
- revision 2: same change ID, incremented revision, new envelope hash, and
  full CAP recheck;
- revision 2: Path `PASS`, Claims `PASS`, Combined `PASS`;
- revision 2 receipt links revision 1 by ID and full SHA-256 hash.

## 3:00 — Show short-circuit and HOLD

```bash
python3 -B -m governed_change_demo evaluate \
  --fixture cap-block \
  --cap-policy policies/cap-policy.v1.json

python3 -B -m governed_change_demo evaluate \
  --fixture context-update \
  --cap-policy policies/cap-policy.v1.json
```

The first returns Combined `BLOCK`. The second returns CAP
`HOLD:CONTEXT_UPDATE_REQUIRED` and Combined `HOLD`. In both cases, Path and
Claims are `NOT_EVALUATED / CAP_NOT_PASSED`.

The separate `hold` fixture reaches the same fail-closed HOLD with a current
source basis and evidence explicitly marked `REFRESHABLE_UNAVAILABLE`.

## 4:00 — Replay fixed identity

```bash
python3 -B -m governed_change_demo replay \
  --fixture repaired \
  --cap-policy policies/cap-policy.v1.json \
  --runs 5
```

Expected:

```text
replay: PASS
sha256:10a2135e3e8127ab8ed9d17759d8507e424d0aba2ad73afaa183bf9cf00778f4
25,194 canonical bytes
```

## 4:30 — Run all tests

```bash
python3 -B -m unittest discover -s tests -v
```

Expected: 73 tests pass.

## Close

This is deterministic demonstration evidence for fixed declared inputs. It is
not production, deployment, security, compliance, customer, market, or
external-validation evidence.
