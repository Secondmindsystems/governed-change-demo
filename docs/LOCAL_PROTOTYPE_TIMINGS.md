# Local prototype timings

Measured source commit: `01baf8cea1bc03a18855979f148640effe2dd1cb`

Measured source tree: `c7285d3bf71d047ecd0cd9fc3c4aaf479ef3e084`

The measured worktree was clean on tracked files when the tool captured the
source identity.

## Environment

- Platform: Windows 11 (`10.0.26100`), AMD64
- Processor string: Intel64 Family 6 Model 198 Stepping 2, GenuineIntel
- Python: CPython 3.12.13
- Clock: `time.perf_counter_ns`

## Method

Command:

```powershell
python -B tools/benchmark_local.py --evaluation-runs 200 --demo-runs 20 --warmups 5
```

The evaluation measurements include fixture JSON loading, CAP derivation, both
domain gates, the Combined Decision, and the Governed Receipt. The integrated
demo measurements start a fresh Python process, run BLOCK → repair → PASS, and
write evidence into a fresh temporary directory.

Five unreported warm-up runs preceded each measured operation.

## Observed results

All values are milliseconds.

| Operation | Runs | Minimum | Median | Mean | p95 | Maximum |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| CAP-admissible BLOCK evaluation | 200 | 3.303 | 3.413 | 3.460 | 3.766 | 4.057 |
| CAP + both gates PASS evaluation | 200 | 3.292 | 3.396 | 3.445 | 3.804 | 4.286 |
| Integrated BLOCK → repair → PASS process | 20 | 101.331 | 104.854 | 104.763 | 107.132 | 108.033 |

The PASS timing uses the repository's lineage-free PASS test bundle so it
measures CAP and gate evaluation without pretending revision 2 can bypass its
required prior BLOCK receipt. The integrated demo measures the actual linked
repair sequence.

## Claim ceiling

These are local prototype timings on the stated environment. They are not
production benchmarks, comparative performance claims, scalability evidence,
capacity guarantees, or deployment-readiness claims.
