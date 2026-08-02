# Adversarial test pack

Run the named pressure pack from the repository root:

```bash
python3 -B tools/run_adversarial_pack.py
```

The pack promotes existing contract and negative tests into a stable public
review surface. It checks these failure classes:

| Pressure | Required result |
| --- | --- |
| CAP rejection | domain gates remain `NOT_EVALUATED`; combined result blocks |
| stale source basis | `HOLD`, never implicit pass |
| unknown policy version | `BLOCK` |
| revoked or expired authority | `BLOCK` |
| traversal, absolute, drive, UNC, URI, or empty path forms | `BLOCK` |
| undeclared required gate | CAP `BLOCK` |
| altered policy bytes | identity changes or binding fails closed |
| reversed gate order | same material decision and receipt identity |
| unexpected gate state | combined precedence falls closed |
| prohibited claim category | Claims Gate `BLOCK` |
| missing claim evidence | Claims Gate `BLOCK` |
| malformed or ambiguous JSON/Unicode | deterministic failure |

The runner names individual tests rather than copying their logic. The complete
suite remains authoritative:

```bash
python3 -B -m unittest discover -s tests -v
```

A passing pack demonstrates that the named prototype behaviors held for the
tested commit and environment. It is not a penetration test, security audit,
certification, production benchmark, or deployment-readiness result.
