"""Run the named public adversarial test pack using only stdlib unittest."""

from __future__ import annotations

import unittest
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


TESTS = (
    "tests.test_orchestrator.SixContractAddendumTests.test_01_cap_block_short_circuits_both_domain_gates",
    "tests.test_orchestrator.SixContractAddendumTests.test_02_stale_basis_is_cap_and_combined_hold",
    "tests.test_orchestrator.SixContractAddendumTests.test_07_unknown_cap_policy_version_blocks",
    "tests.test_orchestrator.SixContractAddendumTests.test_08_revoked_authority_blocks",
    "tests.test_orchestrator.SixContractAddendumTests.test_10_evaluation_as_of_at_expiry_blocks",
    "tests.test_orchestrator.SixContractAddendumTests.test_11_traversal_path_blocks",
    "tests.test_orchestrator.SixContractAddendumTests.test_12_underdeclared_required_gate_blocks_cap",
    "tests.test_orchestrator.SixContractAddendumTests.test_14_same_policy_version_altered_content_changes_identity",
    "tests.test_orchestrator.SixContractAddendumTests.test_15_gate_order_is_materially_invariant_after_cap_pass",
    "tests.test_orchestrator.SixContractAddendumTests.test_combined_precedence_blocks_not_evaluated_and_fallback_states",
    "tests.test_gates.HeterogeneousGateTests.test_absolute_drive_unc_uri_and_empty_segment_forms_are_rejected",
    "tests.test_gates.HeterogeneousGateTests.test_each_claim_boundary_mutation_blocks_independently",
    "tests.test_gates.HeterogeneousGateTests.test_missing_evidence_never_becomes_hold_or_pass",
    "tests.test_contracts.SixContractValidationTests.test_changed_policy_bytes_without_rebinding_fail_closed",
    "tests.test_cli.SixContractCliTests.test_strict_json_loader_rejects_duplicates_numbers_and_utf8",
)


def main() -> int:
    suite = unittest.defaultTestLoader.loadTestsFromNames(TESTS)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
