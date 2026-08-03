"""Verify the public claims manifest against executable repository evidence."""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "evidence" / "public-claims.v1.json"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _run_json(*arguments: str) -> dict:
    completed = subprocess.run(
        [sys.executable, "-B", "-m", "governed_change_demo", *arguments],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return json.loads(completed.stdout)


def _test_count() -> int:
    suite = unittest.defaultTestLoader.discover(
        str(ROOT / "tests"), top_level_dir=str(ROOT)
    )
    return suite.countTestCases()


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    manifest = _load_json(MANIFEST_PATH)
    claims = manifest["deterministic_prototype"]
    blocked_claims = claims["blocked_revision"]
    repaired_claims = claims["repaired_revision"]

    validation = _run_json(
        "validate",
        "--fixture",
        "blocked",
        "--cap-policy",
        "policies/cap-policy.v1.json",
    )
    demo = _run_json(
        "demo",
        "--cap-policy",
        "policies/cap-policy.v1.json",
    )
    replay = _run_json(
        "replay",
        "--fixture",
        "repaired",
        "--cap-policy",
        "policies/cap-policy.v1.json",
        "--runs",
        str(claims["replay_runs"]),
    )

    _require(validation["contract_validation"] == "PASS", "contract validation did not PASS")
    _require(validation["schema_count"] == claims["contract_count"], "contract count drift")
    _require(_test_count() == claims["test_count"], "test count drift")
    _require(replay["replay"] == "PASS", "replay did not PASS")
    _require(replay["runs"] == claims["replay_runs"], "replay run-count drift")
    _require(replay["replay_identity"] == claims["replay_identity"], "replay identity drift")
    _require(replay["canonical_bytes"] == claims["canonical_replay_bytes"], "canonical replay size drift")

    blocked = demo["blocked"]
    repaired = demo["repaired"]
    _require(demo["demo"] == "PASS", "integrated demo did not PASS")
    _require(blocked["cap"]["decision"] == blocked_claims["cap"], "blocked CAP drift")
    _require(blocked["gate_statuses"]["path_gate"] == blocked_claims["path_gate"], "blocked Path Gate drift")
    _require(blocked["gate_statuses"]["claims_gate"] == blocked_claims["claims_gate"], "blocked Claims Gate drift")
    _require(blocked["status"] == blocked_claims["combined"], "blocked combined decision drift")
    _require(blocked["receipt_id"] == blocked_claims["receipt_id"], "blocked receipt ID drift")
    _require(blocked["receipt_hash"] == blocked_claims["receipt_hash"], "blocked receipt hash drift")
    _require(repaired["cap"]["decision"] == repaired_claims["cap"], "repaired CAP drift")
    _require(repaired["gate_statuses"]["path_gate"] == repaired_claims["path_gate"], "repaired Path Gate drift")
    _require(repaired["gate_statuses"]["claims_gate"] == repaired_claims["claims_gate"], "repaired Claims Gate drift")
    _require(repaired["status"] == repaired_claims["combined"], "repaired combined decision drift")
    _require(repaired["receipt_id"] == repaired_claims["receipt_id"], "repaired receipt ID drift")
    _require(repaired["receipt_hash"] == repaired_claims["receipt_hash"], "repaired receipt hash drift")
    _require(demo["repair_lineage"]["cap_rechecked"] is repaired_claims["cap_rechecked"], "CAP recheck drift")
    _require(demo["repair_lineage"]["unchanged_policy_hashes"] == claims["policy_hashes"], "policy hash drift")

    blocked_fixture = _load_json(ROOT / "fixtures" / "blocked-envelope.json")
    repaired_fixture = _load_json(ROOT / "fixtures" / "repaired-envelope.json")
    fixture_claims = manifest["fixture_claims"]
    blocked_change = blocked_fixture["changes"][0]
    repaired_change = repaired_fixture["changes"][0]
    _require(blocked_change["path"] == fixture_claims["blocked_path"], "blocked path drift")
    _require(blocked_change["claims"][0]["statement"] == fixture_claims["blocked_claim"], "blocked claim drift")
    _require(repaired_change["path"] == fixture_claims["repaired_path"], "repaired path drift")

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    limitation = manifest["reproduction_state"]["required_limitation"]
    _require(limitation in readme, "required outsider-reproduction limitation missing from README")
    for relative_path in manifest["verification"].values():
        _require((ROOT / relative_path).is_file(), f"missing verification artifact: {relative_path}")

    print("PUBLIC_CLAIMS_MANIFEST_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
