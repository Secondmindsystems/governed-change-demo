# Reproduction

## Requirements

- Python 3.11 or newer
- this product directory copied as a standalone folder
- no network, credentials, providers, Git repository, Node, PyYAML, or package
  installation

All commands run from the product root. The implementation uses only the
Python standard library.

On macOS or Linux:

```bash
python3 --version
```

On Windows PowerShell, choose the interpreter explicitly rather than relying
on a potentially ambiguous `python` command:

```powershell
$PythonExe = "C:\Path\To\python.exe"
& $PythonExe --version
```

The multiline blocks below use Bash `\` continuation. PowerShell equivalents
are provided at the end.

## Validate the six contracts and fixed policies

```bash
python3 -B -m governed_change_demo validate \
  --fixture blocked \
  --cap-policy policies/cap-policy.v1.json

python3 -B -m governed_change_demo validate \
  --fixture repaired \
  --cap-policy policies/cap-policy.v1.json

python3 -B -m governed_change_demo validate \
  --fixture cap-block \
  --cap-policy policies/cap-policy.v1.json

python3 -B -m governed_change_demo validate \
  --fixture context-update \
  --cap-policy policies/cap-policy.v1.json
```

Successful contract validation reports six schema contracts. It does not imply
that the candidate change receives CAP or domain-gate acceptance.

## Evaluate the original BLOCK

```bash
python3 -B -m governed_change_demo evaluate \
  --fixture blocked \
  --cap-policy policies/cap-policy.v1.json \
  --output-dir evidence/manual-run/blocked
```

Expected exit code: `2`. The supplied candidate snapshot passes CAP, then the
Path and Claims gates independently block it. Exit `2` is a policy decision,
not a process malfunction.

## Evaluate the bounded repair

```bash
python3 -B -m governed_change_demo evaluate \
  --fixture repaired \
  --cap-policy policies/cap-policy.v1.json \
  --prior-receipt evidence/manual-run/blocked/governed-receipt.json \
  --output-dir evidence/manual-run/repaired
```

Expected exit code: `0`. The repaired revision must have the same logical
change ID, an incremented revision, a new envelope hash, a fresh authority and
context assessment, and a new CAP `PASS` before either domain gate runs.

## Run the integrated BLOCK-to-repair-to-PASS demo

```bash
python3 -B -m governed_change_demo demo \
  --cap-policy policies/cap-policy.v1.json \
  --output-dir evidence/demo-run
```

This performs the two evaluations in lineage order and emits one consolidated
receipt per revision.

Expected summary fields:

```text
demo: PASS
blocked.status: BLOCK
blocked.receipt_id: receipt-2bbc3c4b0305f8394b83
repaired.status: PASS
repaired.receipt_id: receipt-51bbb2e71998a45e59ff
repaired.receipt_hash: sha256:54346099dfef791368c87c2b259e6399ebb683ec4a37e90880c0d05989e6e8d8
repair_lineage.cap_rechecked: true
```

## Reproduce CAP short-circuit

CAP `BLOCK`:

```bash
python3 -B -m governed_change_demo evaluate \
  --fixture cap-block \
  --cap-policy policies/cap-policy.v1.json \
  --output-dir evidence/manual-run/cap-block
```

Stale source basis:

```bash
python3 -B -m governed_change_demo evaluate \
  --fixture context-update \
  --cap-policy policies/cap-policy.v1.json \
  --output-dir evidence/manual-run/context-update
```

Refreshable evidence temporarily unavailable:

```bash
python3 -B -m governed_change_demo evaluate \
  --fixture hold \
  --cap-policy policies/cap-policy.v1.json \
  --output-dir evidence/manual-run/refreshable-evidence-hold
```

The first exits `2` with combined `BLOCK`. The second and third exit `3` with
CAP `HOLD:CONTEXT_UPDATE_REQUIRED` and Combined Decision `HOLD`. The third has
a current source basis and evidence explicitly marked
`REFRESHABLE_UNAVAILABLE`. In all three cases the Path and Claims gate result
records must be `NOT_EVALUATED` with `CAP_NOT_PASSED`.

## Replay and compare

```bash
python3 -B -m governed_change_demo replay \
  --fixture blocked \
  --cap-policy policies/cap-policy.v1.json \
  --runs 3

python3 -B -m governed_change_demo replay \
  --fixture repaired \
  --cap-policy policies/cap-policy.v1.json \
  --runs 3

python3 -B -m governed_change_demo replay \
  --fixture context-update \
  --cap-policy policies/cap-policy.v1.json \
  --runs 3
```

Replay compares canonical CAP Decision, both Gate Results, Combined Decision,
and Governed Receipt bytes. Identity is fixed by candidate inputs, canonical
CAP/Path/Claims policy bytes, evaluator versions, and supplied
`evaluation_as_of`.

For the repaired fixture with five runs, expect:

```text
replay: PASS
runs: 5
canonical_bytes: 25194
replay_identity: sha256:10a2135e3e8127ab8ed9d17759d8507e424d0aba2ad73afaa183bf9cf00778f4
```

## Reverse domain-gate order

Gate-order invariance is meaningful only for a CAP-admissible case:

```bash
python3 -B -m governed_change_demo replay \
  --fixture repaired \
  --cap-policy policies/cap-policy.v1.json \
  --gate-order claims_gate,path_gate \
  --runs 3
```

The material Combined Decision and receipt identity must match the default
domain-gate order.

## Explicit candidate bundle

```bash
python3 -B -m governed_change_demo evaluate \
  --envelope fixtures/blocked-envelope.json \
  --authority fixtures/authority-manifest.json \
  --cap-policy policies/cap-policy.v1.json \
  --path-policy policies/path-policy.v1.json \
  --claims-policy policies/claims-policy.v1.json \
  --output-dir evidence/manual-run/explicit-blocked
```

The envelope describes the candidate-change snapshot. Evaluation never reads a
live worktree to decide the v0.1 result.

Malformed or missing required files, unknown policy versions, invalid policy
hashes, invalid/revoked authority, and other non-refreshable required-input
failures produce canonical `BLOCK` evaluation artifacts and exit `2`. A stale
source basis or explicitly declared refreshable-unavailable evidence follows
the explicit HOLD route instead. The `validate` command returns exit `4` when
validation itself cannot complete.

## Output files

An evaluation output directory contains:

```text
cap-decision.json
combined-decision.json
governed-receipt.json
gate-results/claims-gate.json
gate-results/path-gate.json
```

The two Gate Result files are present even after CAP short-circuits; their
canonical status is `NOT_EVALUATED`.

Avoid output directory names commonly ignored in host repositories, including
`build`, `dist`, `logs`, `temp`, and `proof_packets`. These examples use
product-local `evidence/`.

## Run all tests

```bash
python3 -B -m unittest discover -s tests -v
```

## Complete PowerShell command set

```powershell
& $PythonExe -B -m governed_change_demo validate --fixture blocked --cap-policy policies/cap-policy.v1.json
& $PythonExe -B -m governed_change_demo validate --fixture repaired --cap-policy policies/cap-policy.v1.json
& $PythonExe -B -m governed_change_demo validate --fixture cap-block --cap-policy policies/cap-policy.v1.json
& $PythonExe -B -m governed_change_demo validate --fixture context-update --cap-policy policies/cap-policy.v1.json
& $PythonExe -B -m governed_change_demo evaluate --fixture blocked --cap-policy policies/cap-policy.v1.json --output-dir evidence/manual-run/blocked
& $PythonExe -B -m governed_change_demo evaluate --fixture repaired --cap-policy policies/cap-policy.v1.json --prior-receipt evidence/manual-run/blocked/governed-receipt.json --output-dir evidence/manual-run/repaired
& $PythonExe -B -m governed_change_demo demo --cap-policy policies/cap-policy.v1.json --output-dir evidence/demo-run
& $PythonExe -B -m governed_change_demo evaluate --fixture cap-block --cap-policy policies/cap-policy.v1.json --output-dir evidence/manual-run/cap-block
& $PythonExe -B -m governed_change_demo evaluate --fixture context-update --cap-policy policies/cap-policy.v1.json --output-dir evidence/manual-run/context-update
& $PythonExe -B -m governed_change_demo replay --fixture blocked --cap-policy policies/cap-policy.v1.json --runs 3
& $PythonExe -B -m governed_change_demo replay --fixture repaired --cap-policy policies/cap-policy.v1.json --runs 3
& $PythonExe -B -m governed_change_demo replay --fixture context-update --cap-policy policies/cap-policy.v1.json --runs 3
& $PythonExe -B -m governed_change_demo replay --fixture repaired --cap-policy policies/cap-policy.v1.json --gate-order claims_gate,path_gate --runs 3
& $PythonExe -B -m governed_change_demo evaluate --envelope fixtures/blocked-envelope.json --authority fixtures/authority-manifest.json --cap-policy policies/cap-policy.v1.json --path-policy policies/path-policy.v1.json --claims-policy policies/claims-policy.v1.json --output-dir evidence/manual-run/explicit-blocked
& $PythonExe -B -m unittest discover -s tests -v
```

## Clean-copy check

Copy only this product directory to a fresh temporary location, run the
validation, demo, replay, and test commands there, and confirm no import or file
reference escapes the copy. This proves only the tested standalone boundary;
it is not external or platform validation.
