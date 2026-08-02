# Outsider reproduction

This route is for a person who did not construct or review this candidate and
wants to test the public repository from a clean clone.

```bash
git clone https://github.com/Secondmindsystems/governed-change-demo.git
cd governed-change-demo
git rev-parse HEAD
python3 --version
python3 -B -m governed_change_demo validate --fixture blocked --cap-policy policies/cap-policy.v1.json
python3 -B -m governed_change_demo demo --cap-policy policies/cap-policy.v1.json --output-dir evidence/outsider-demo
python3 -B -m governed_change_demo replay --fixture repaired --cap-policy policies/cap-policy.v1.json --runs 5
python3 -B tools/run_adversarial_pack.py
python3 -B -m unittest discover -s tests -v
```

Expected fixed replay values:

```text
canonical_bytes: 25194
replay_identity: sha256:10a2135e3e8127ab8ed9d17759d8507e424d0aba2ad73afaa183bf9cf00778f4
```

The repaired receipt must remain:

```text
receipt-51bbb2e71998a45e59ff
sha256:54346099dfef791368c87c2b259e6399ebb683ec4a37e90880c0d05989e6e8d8
```

Return the result using the repository's **Public reproduction report** issue
form. Choose `PASS`, `FAIL`, or `CONFUSED`; all three are useful evidence.

Running these commands demonstrates reproducibility only for the reported
environment and commit. A returned issue becomes outsider evidence only when
the reporter was not part of candidate construction or review and the report's
commit, commands, outputs, and fixed identities are internally consistent.

This does not establish security, compliance, production readiness, deployment
readiness, customer validation, or general platform support.
