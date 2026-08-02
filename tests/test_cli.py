from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from governed_change_demo.cli import _load_json

from tests.helpers import ROOT, cap_for, inputs


CAP_POLICY = ROOT / "policies" / "cap-policy.v1.json"


def run_cli(*args: str, cwd: Path = ROOT) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-B", "-m", "governed_change_demo", *args],
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


class SixContractCliTests(unittest.TestCase):
    def test_validate_reports_all_six_contracts_and_generated_cap(self) -> None:
        result = run_cli(
            "validate",
            "--fixture",
            "blocked",
            "--cap-policy",
            str(CAP_POLICY),
        )
        self.assertEqual(0, result.returncode, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual("PASS", payload["contract_validation"])
        self.assertEqual("BLOCK", payload["fixture_decision"])
        self.assertEqual("VALID", payload["cap"]["input_status"])
        self.assertEqual("PASS", payload["cap"]["decision"])
        self.assertTrue(payload["domain_gates_executed"])
        self.assertEqual(6, payload["schema_count"])
        self.assertEqual(
            {
                "authority-manifest.v1.schema.json",
                "cap-decision.v1.schema.json",
                "combined-decision.v1.schema.json",
                "gate-result.v1.schema.json",
                "governed-receipt.v1.schema.json",
                "shared-change-envelope.v1.schema.json",
            },
            set(payload["schemas_loaded"]),
        )

    def test_explicit_bundle_generates_cap_without_cap_argument(self) -> None:
        result = run_cli(
            "evaluate",
            "--envelope",
            str(ROOT / "fixtures" / "blocked-envelope.json"),
            "--authority",
            str(ROOT / "fixtures" / "authority-manifest.json"),
            "--cap-policy",
            str(CAP_POLICY),
        )
        self.assertEqual(2, result.returncode, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual("VALID", payload["cap"]["input_status"])
        self.assertEqual("PASS", payload["cap"]["decision"])
        self.assertTrue(payload["domain_gates_executed"])

        missing_authority = run_cli(
            "evaluate",
            "--envelope",
            str(ROOT / "fixtures" / "blocked-envelope.json"),
            "--cap-policy",
            str(CAP_POLICY),
        )
        self.assertEqual(64, missing_authority.returncode)
        self.assertIn(
            "--authority is required with --envelope",
            missing_authority.stderr,
        )

    def test_cli_generated_cap_matches_mechanical_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "evidence"
            result = run_cli(
                "evaluate",
                "--fixture",
                "blocked",
                "--cap-policy",
                str(CAP_POLICY),
                "--output-dir",
                str(output),
            )
            self.assertEqual(2, result.returncode, result.stderr)
            envelope, authority, cap_policy, path_policy, claims_policy = (
                inputs("blocked")
            )
            expected = cap_for(
                envelope,
                authority,
                cap_policy,
                path_policy,
                claims_policy,
            )
            actual = json.loads(
                (output / "cap-decision.json").read_text(encoding="utf-8")
            )
            self.assertEqual(expected, actual)

    def test_semantic_exit_codes_and_cap_short_circuit_are_stable(self) -> None:
        cases = (
            ("blocked", 2, "PASS", True, "BLOCK"),
            ("cap-block", 2, "BLOCK", False, "BLOCK"),
            (
                "context-update",
                3,
                "HOLD:CONTEXT_UPDATE_REQUIRED",
                False,
                "HOLD",
            ),
        )
        for fixture, code, cap_decision, executed, status in cases:
            with self.subTest(fixture=fixture):
                result = run_cli(
                    "evaluate",
                    "--fixture",
                    fixture,
                    "--cap-policy",
                    str(CAP_POLICY),
                )
                self.assertEqual(code, result.returncode, result.stderr)
                payload = json.loads(result.stdout)
                self.assertEqual(status, payload["status"])
                self.assertEqual(cap_decision, payload["cap"]["decision"])
                self.assertIs(
                    cap_decision == "PASS",
                    payload["cap"]["domain_gates_may_run"],
                )
                self.assertIs(executed, payload["domain_gates_executed"])
                self.assertFalse(payload["cap"]["execution_authority"])
                if not executed:
                    self.assertEqual(
                        {
                            "claims_gate": "NOT_EVALUATED",
                            "path_gate": "NOT_EVALUATED",
                        },
                        payload["gate_statuses"],
                    )

    def test_short_circuit_still_writes_all_canonical_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            for fixture in ("cap-block", "context-update"):
                with self.subTest(fixture=fixture):
                    output = Path(directory) / fixture
                    result = run_cli(
                        "evaluate",
                        "--fixture",
                        fixture,
                        "--cap-policy",
                        str(CAP_POLICY),
                        "--output-dir",
                        str(output),
                    )
                    self.assertIn(result.returncode, {2, 3}, result.stderr)
                    expected = {
                        "cap-decision.json",
                        "combined-decision.json",
                        "governed-receipt.json",
                        "gate-results/claims-gate.json",
                        "gate-results/path-gate.json",
                    }
                    actual = {
                        path.relative_to(output).as_posix()
                        for path in output.rglob("*")
                        if path.is_file()
                    }
                    self.assertEqual(expected, actual)
                    for gate_id in ("claims", "path"):
                        gate_result = json.loads(
                            (
                                output
                                / "gate-results"
                                / f"{gate_id}-gate.json"
                            ).read_text(encoding="utf-8")
                        )
                        self.assertEqual(
                            "NOT_EVALUATED",
                            gate_result["status"],
                        )
                        self.assertEqual(
                            ["CAP_NOT_PASSED"],
                            gate_result["reason_codes"],
                        )

    def test_demo_and_byte_replay_succeed(self) -> None:
        demo = run_cli(
            "demo",
            "--cap-policy",
            str(CAP_POLICY),
        )
        replay = run_cli(
            "replay",
            "--fixture",
            "context-update",
            "--cap-policy",
            str(CAP_POLICY),
            "--runs",
            "4",
        )
        self.assertEqual(0, demo.returncode, demo.stderr)
        self.assertEqual(0, replay.returncode, replay.stderr)
        demo_payload = json.loads(demo.stdout)
        replay_payload = json.loads(replay.stdout)
        self.assertEqual("PASS", demo_payload["demo"])
        self.assertEqual("PASS", demo_payload["blocked"]["cap"]["decision"])
        self.assertEqual("PASS", demo_payload["repaired"]["cap"]["decision"])
        self.assertTrue(demo_payload["blocked"]["domain_gates_executed"])
        self.assertTrue(demo_payload["repaired"]["domain_gates_executed"])
        self.assertEqual("PASS", replay_payload["replay"])
        self.assertEqual(
            "HOLD:CONTEXT_UPDATE_REQUIRED",
            replay_payload["cap"]["decision"],
        )
        self.assertFalse(replay_payload["domain_gates_executed"])
        self.assertIsNotNone(replay_payload["cap"]["decision_id"])
        self.assertIsNotNone(replay_payload["cap"]["canonical_hash"])

    def test_malformed_candidate_fails_closed_without_static_cap(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory) / "bad.json"
            bad.write_text("{not-json", encoding="utf-8")
            evaluate = run_cli(
                "evaluate",
                "--envelope",
                str(bad),
                "--authority",
                str(ROOT / "fixtures" / "authority-manifest.json"),
                "--cap-policy",
                str(CAP_POLICY),
            )
            validate = run_cli(
                "validate",
                "--envelope",
                str(bad),
                "--authority",
                str(ROOT / "fixtures" / "authority-manifest.json"),
                "--cap-policy",
                str(CAP_POLICY),
            )
            self.assertEqual(2, evaluate.returncode, evaluate.stderr)
            self.assertEqual("BLOCK", json.loads(evaluate.stdout)["status"])
            self.assertEqual(4, validate.returncode, validate.stderr)

    def test_strict_json_loader_rejects_duplicates_numbers_and_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            duplicate = root / "duplicate.json"
            duplicate.write_text(
                '{"contract_version":"first","contract_version":"second"}',
                encoding="utf-8",
            )
            value, issues = _load_json(duplicate, "shared_change_envelope")
            self.assertIsNone(value)
            self.assertEqual(
                ["JSON_DUPLICATE_KEY"],
                [item.code for item in issues],
            )

            for index, token in enumerate(
                ("1.5", "1e2", "NaN", "Infinity", "-Infinity")
            ):
                with self.subTest(token=token):
                    bad_number = root / f"number-{index}.json"
                    bad_number.write_text(
                        f'{{"revision":{token}}}',
                        encoding="utf-8",
                    )
                    value, issues = _load_json(
                        bad_number,
                        "shared_change_envelope",
                    )
                    self.assertIsNone(value)
                    self.assertEqual(
                        ["JSON_NUMBER_UNSUPPORTED"],
                        [item.code for item in issues],
                    )

            invalid_utf8 = root / "invalid-utf8.json"
            invalid_utf8.write_bytes(b'{"contract_version":"\xff"}')
            value, issues = _load_json(
                invalid_utf8,
                "shared_change_envelope",
            )
            self.assertIsNone(value)
            self.assertEqual(
                ["INPUT_FILE_NOT_UTF8"],
                [item.code for item in issues],
            )

    def test_validate_rejects_missing_or_drifted_schema(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            export_root = Path(directory) / "governed-change-demo"
            shutil.copytree(
                ROOT,
                export_root,
                ignore=shutil.ignore_patterns(
                    "__pycache__",
                    "*.pyc",
                    "evidence",
                    "runs",
                ),
            )
            missing = (
                export_root
                / "contracts"
                / "gate-result.v1.schema.json"
            )
            missing.unlink()
            result = run_cli(
                "validate",
                "--fixture",
                "blocked",
                "--cap-policy",
                str(export_root / "policies" / "cap-policy.v1.json"),
                cwd=export_root,
            )
            self.assertEqual(4, result.returncode, result.stderr)
            payload = json.loads(result.stdout)
            self.assertIn(
                "SCHEMA_FILE_MISSING",
                {item["code"] for item in payload["schema_issues"]},
            )

            shutil.copy(
                ROOT / "contracts" / "gate-result.v1.schema.json",
                missing,
            )
            cap_schema_path = (
                export_root
                / "contracts"
                / "cap-decision.v1.schema.json"
            )
            cap_schema = json.loads(
                cap_schema_path.read_text(encoding="utf-8")
            )
            cap_schema["properties"]["contract_version"]["const"] = "wrong"
            cap_schema_path.write_text(
                json.dumps(cap_schema),
                encoding="utf-8",
            )
            result = run_cli(
                "validate",
                "--fixture",
                "blocked",
                "--cap-policy",
                str(export_root / "policies" / "cap-policy.v1.json"),
                cwd=export_root,
            )
            self.assertEqual(4, result.returncode, result.stderr)
            payload = json.loads(result.stdout)
            self.assertIn(
                "SCHEMA_CONTRACT_VERSION_MISMATCH",
                {item["code"] for item in payload["schema_issues"]},
            )


if __name__ == "__main__":
    unittest.main()
