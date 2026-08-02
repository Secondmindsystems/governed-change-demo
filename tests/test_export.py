from __future__ import annotations

import ast
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests.helpers import ROOT


class ExportTests(unittest.TestCase):
    def test_required_public_documentation_surfaces_exist(self) -> None:
        required = {
            "LICENSE",
            "README.md",
            "docs/ARCHITECTURE.md",
            "docs/FIVE_MINUTE_DEMO.md",
            "docs/REPRODUCTION.md",
            "docs/AUTHORSHIP_AND_AI_DISCLOSURE.md",
            "docs/VERIFIED_METRICS.md",
            "docs/LIMITATIONS.md",
            "docs/CLAIM_BOUNDARIES.md",
        }
        self.assertEqual(
            set(),
            {relative for relative in required if not (ROOT / relative).is_file()},
        )

    def test_required_authorship_disclosure_is_preserved(self) -> None:
        text = (ROOT / "docs" / "AUTHORSHIP_AND_AI_DISCLOSURE.md").read_text(
            encoding="utf-8"
        )
        for fragment in (
            "I defined the objectives, architecture, constraints, acceptance gates, claim",
            "boundaries, and integration decisions.",
            "AI agents implemented and reviewed",
            "bounded work under those controls.",
            "Each case distinguishes my decisions from",
            "agent-generated implementation.",
        ):
            self.assertIn(fragment, text)

    def test_export_has_lf_policy_and_apache_license(self) -> None:
        attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")
        license_text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        self.assertIn("* text eol=lf", attributes)
        self.assertIn("Apache License", license_text)
        self.assertIn("Version 2.0, January 2004", license_text)
        pending_license = ROOT / ("LICENSE-" + "DECISION-PENDING.md")
        self.assertFalse(pending_license.exists())
        forbidden = (
            "C:/" + "Users/",
            "C:" + "\\Users\\",
            "/" + "." + "codex/",
            "\\" + "." + "codex\\",
            "LICENSE-" + "DECISION-PENDING",
            "OPERATOR_" + "DECISION_REQUIRED",
        )
        for path in sorted(ROOT.rglob("*")):
            if not path.is_file() or ".git" in path.parts:
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for marker in forbidden:
                self.assertNotIn(marker, text, f"{path} contains {marker}")

    def test_python_uses_only_stdlib_and_product_package_imports(self) -> None:
        allowed_local = {"governed_change_demo"}
        for path in sorted((ROOT / "governed_change_demo").glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    roots = {alias.name.split(".")[0] for alias in node.names}
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    roots = {node.module.split(".")[0]}
                else:
                    continue
                for root in roots:
                    self.assertTrue(
                        root in sys.stdlib_module_names or root in allowed_local,
                        f"{path.name} imports non-stdlib dependency {root}",
                    )

    def test_export_workflow_is_json_encoded_valid_yaml_subset(self) -> None:
        path = ROOT / ".github" / "workflows" / "flagship-validation.yml"
        workflow = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual("Governed Change Flagship Validation", workflow["name"])
        self.assertEqual({"contents": "read"}, workflow["permissions"])
        job = workflow["jobs"]["validate"]
        self.assertEqual("ubuntu-latest", job["runs-on"])
        self.assertTrue(any(step.get("uses") == "actions/checkout@v4" for step in job["steps"]))
        self.assertTrue(
            all("secrets." not in json.dumps(step) for step in job["steps"])
        )

    def test_clean_copy_demo_and_replay_have_no_private_repo_dependency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            export_root = Path(directory) / "governed-change-demo"
            shutil.copytree(
                ROOT,
                export_root,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "evidence", "runs"),
            )
            demo = subprocess.run(
                [sys.executable, "-B", "-m", "governed_change_demo", "demo"],
                cwd=export_root,
                text=True,
                capture_output=True,
                check=False,
            )
            replay = subprocess.run(
                [
                    sys.executable,
                    "-B",
                    "-m",
                    "governed_change_demo",
                    "replay",
                    "--fixture",
                    "repaired",
                    "--runs",
                    "3",
                ],
                cwd=export_root,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, demo.returncode, demo.stderr)
            self.assertEqual(0, replay.returncode, replay.stderr)
            self.assertEqual("PASS", json.loads(demo.stdout)["demo"])
            self.assertEqual("PASS", json.loads(replay.stdout)["replay"])

if __name__ == "__main__":
    unittest.main()
