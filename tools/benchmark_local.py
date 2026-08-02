"""Measure bounded local prototype timings; this is not a benchmark claim."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from governed_change_demo.orchestrator import evaluate_bundle  # noqa: E402
from tests.helpers import evaluation_bundle, pass_bundle  # noqa: E402


CLAIM_CEILING = (
    "These are local prototype timings on the stated environment. They are "
    "not production benchmarks, comparative performance claims, scalability "
    "evidence, capacity guarantees, or deployment-readiness claims."
)


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return ordered[index]


def summarize(values: list[float]) -> dict[str, float | int]:
    return {
        "runs": len(values),
        "min_ms": round(min(values), 3),
        "median_ms": round(statistics.median(values), 3),
        "mean_ms": round(statistics.fmean(values), 3),
        "p95_ms": round(percentile(values, 0.95), 3),
        "max_ms": round(max(values), 3),
    }


def timed_evaluation(fixture: str) -> float:
    started = time.perf_counter_ns()
    inputs = pass_bundle() if fixture == "pass" else evaluation_bundle(fixture)
    outcome = evaluate_bundle(*inputs)
    elapsed = (time.perf_counter_ns() - started) / 1_000_000
    expected = "PASS" if fixture == "pass" else "BLOCK"
    if outcome.status != expected:
        raise RuntimeError(f"unexpected {fixture} status: {outcome.status}")
    return elapsed


def timed_demo() -> float:
    with tempfile.TemporaryDirectory(prefix="governed-change-demo-bench-") as tmp:
        command = [
            sys.executable,
            "-B",
            "-m",
            "governed_change_demo",
            "demo",
            "--cap-policy",
            "policies/cap-policy.v1.json",
            "--output-dir",
            str(Path(tmp) / "evidence"),
        ]
        started = time.perf_counter_ns()
        completed = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            check=False,
            text=True,
        )
        elapsed = (time.perf_counter_ns() - started) / 1_000_000
        if completed.returncode != 0 or '"demo": "PASS"' not in completed.stdout:
            raise RuntimeError(
                f"demo failed: exit={completed.returncode} stderr={completed.stderr}"
            )
        return elapsed


def git_value(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, check=True, text=True
    )
    return completed.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evaluation-runs", type=int, default=200)
    parser.add_argument("--demo-runs", type=int, default=20)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if min(args.evaluation_runs, args.demo_runs, args.warmups) < 1:
        parser.error("run counts must be positive")

    for _ in range(args.warmups):
        timed_evaluation("blocked")
        timed_evaluation("pass")
        timed_demo()

    report = {
        "schema": "governed-change-demo.local-timings/v1",
        "claim_ceiling": CLAIM_CEILING,
        "source": {
            "commit": git_value("rev-parse", "HEAD"),
            "tree": git_value("rev-parse", "HEAD^{tree}"),
            "dirty": bool(git_value("status", "--short", "--untracked-files=no")),
        },
        "environment": {
            "platform": platform.platform(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "python_implementation": platform.python_implementation(),
            "python_version": platform.python_version(),
        },
        "method": {
            "clock": "time.perf_counter_ns",
            "warmups": args.warmups,
            "evaluation_scope": "fixture JSON load, CAP derivation, two-gate evaluation, combined decision, and receipt",
            "demo_scope": "fresh Python process, BLOCK-to-repair-to-PASS demo, and temporary evidence writes",
        },
        "results": {
            "blocked_evaluation": summarize(
                [timed_evaluation("blocked") for _ in range(args.evaluation_runs)]
            ),
            "pass_evaluation": summarize(
                [timed_evaluation("pass") for _ in range(args.evaluation_runs)]
            ),
            "integrated_demo_process": summarize(
                [timed_demo() for _ in range(args.demo_runs)]
            ),
        },
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
