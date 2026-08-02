from __future__ import annotations

from copy import deepcopy
import unittest

from governed_change_demo.canonical import canonical_bytes
from governed_change_demo.contracts import (
    validate_cap_decision,
    validate_combined_decision,
    validate_gate_result,
    validate_receipt,
)
from governed_change_demo.orchestrator import _combined_status, evaluate_bundle

from tests.helpers import (
    bind_policy,
    cap_for,
    evaluation_bundle,
    inputs,
    pass_bundle,
)


def evaluate(
    values: tuple[dict, dict, dict, dict, dict, dict],
    *,
    prior_receipt=None,
    gate_order=("path_gate", "claims_gate"),
):
    return evaluate_bundle(
        *values,
        prior_receipt=prior_receipt,
        gate_order=gate_order,
    )


def gate_statuses(outcome) -> dict[str, str]:
    return {
        result["gate_id"]: result["status"]
        for result in outcome.gate_results
    }


def assert_cap_short_circuit(
    case: unittest.TestCase,
    outcome,
) -> None:
    case.assertFalse(outcome.combined_decision["domain_gates_executed"])
    case.assertEqual(2, len(outcome.gate_results))
    for result in outcome.gate_results:
        case.assertEqual("NOT_EVALUATED", result["status"])
        case.assertEqual(["CAP_NOT_PASSED"], result["reason_codes"])


class SixContractAddendumTests(unittest.TestCase):
    def test_01_cap_block_short_circuits_both_domain_gates(self) -> None:
        outcome = evaluate(evaluation_bundle("cap-block"))
        self.assertEqual("BLOCK", outcome.cap_decision["decision"])
        self.assertEqual("BLOCK", outcome.status)
        assert_cap_short_circuit(self, outcome)

    def test_02_stale_basis_is_cap_and_combined_hold(self) -> None:
        outcome = evaluate(evaluation_bundle("context-update"))
        self.assertEqual(
            "HOLD:CONTEXT_UPDATE_REQUIRED",
            outcome.cap_decision["decision"],
        )
        self.assertEqual("HOLD", outcome.status)
        self.assertIn(
            "CAP_SOURCE_BASIS_STALE",
            outcome.cap_decision["reason_codes"],
        )
        assert_cap_short_circuit(self, outcome)

    def test_03_cap_pass_path_block_claims_pass_combines_to_block(self) -> None:
        envelope, authority, _, cap_policy, path_policy, claims_policy = (
            pass_bundle()
        )
        envelope["changes"][0]["path"] = "config/path-gate-block.md"
        cap_decision = cap_for(
            envelope,
            authority,
            cap_policy,
            path_policy,
            claims_policy,
        )
        outcome = evaluate(
            (
                envelope,
                authority,
                cap_decision,
                cap_policy,
                path_policy,
                claims_policy,
            )
        )
        self.assertEqual("PASS", cap_decision["decision"])
        self.assertEqual(
            {"claims_gate": "PASS", "path_gate": "BLOCK"},
            gate_statuses(outcome),
        )
        self.assertEqual("BLOCK", outcome.status)

    def test_04_cap_pass_path_pass_claims_block_combines_to_block(self) -> None:
        envelope, authority, _, cap_policy, path_policy, claims_policy = (
            pass_bundle()
        )
        envelope["changes"][0]["claims"][0]["claim_tag"] = "SECURITY"
        cap_decision = cap_for(
            envelope,
            authority,
            cap_policy,
            path_policy,
            claims_policy,
        )
        outcome = evaluate(
            (
                envelope,
                authority,
                cap_decision,
                cap_policy,
                path_policy,
                claims_policy,
            )
        )
        self.assertEqual("PASS", cap_decision["decision"])
        self.assertEqual(
            {"claims_gate": "BLOCK", "path_gate": "PASS"},
            gate_statuses(outcome),
        )
        self.assertEqual("BLOCK", outcome.status)

    def test_05_cap_and_both_domain_gates_pass(self) -> None:
        outcome = evaluate(pass_bundle())
        self.assertEqual("PASS", outcome.cap_decision["decision"])
        self.assertEqual(
            {"claims_gate": "PASS", "path_gate": "PASS"},
            gate_statuses(outcome),
        )
        self.assertEqual("PASS", outcome.status)
        self.assertEqual(
            [],
            validate_cap_decision(
                outcome.cap_decision,
                raise_on_error=False,
            ),
        )
        self.assertEqual(
            [],
            validate_combined_decision(
                outcome.combined_decision,
                raise_on_error=False,
            ),
        )
        self.assertEqual(
            [],
            validate_receipt(outcome.receipt, raise_on_error=False),
        )
        for result in outcome.gate_results:
            self.assertEqual(
                [],
                validate_gate_result(result, raise_on_error=False),
            )

    def test_06_missing_cap_evidence_blocks_before_domain_gates(self) -> None:
        envelope, authority, cap_policy, path_policy, claims_policy = inputs(
            "repaired"
        )
        envelope["revision"] = 1
        envelope["fixture"]["state"] = "ORIGINAL_BLOCK"
        envelope["repair_summary"] = None
        envelope["evidence"] = []
        envelope["changes"][0]["claims"][0]["evidence_refs"] = []
        cap_decision = cap_for(
            envelope,
            authority,
            cap_policy,
            path_policy,
            claims_policy,
        )
        outcome = evaluate(
            (
                envelope,
                authority,
                cap_decision,
                cap_policy,
                path_policy,
                claims_policy,
            )
        )
        self.assertEqual("BLOCK", cap_decision["decision"])
        self.assertIn(
            "CAP_REQUIRED_EVIDENCE_MISSING",
            cap_decision["reason_codes"],
        )
        self.assertEqual("BLOCK", outcome.status)
        assert_cap_short_circuit(self, outcome)

    def test_07_unknown_cap_policy_version_blocks(self) -> None:
        envelope, authority, _, cap_policy, path_policy, claims_policy = (
            pass_bundle()
        )
        cap_policy["policy_version"] = "governed-repo.cap-policy/v9.9.9"
        bind_policy("cap_policy", cap_policy, envelope, authority)
        cap_decision = cap_for(
            envelope,
            authority,
            cap_policy,
            path_policy,
            claims_policy,
        )
        outcome = evaluate(
            (
                envelope,
                authority,
                cap_decision,
                cap_policy,
                path_policy,
                claims_policy,
            )
        )
        self.assertEqual("BLOCK", cap_decision["decision"])
        self.assertIn(
            "CAP_CAP_POLICY_VERSION_UNKNOWN",
            cap_decision["reason_codes"],
        )
        self.assertEqual("BLOCK", outcome.status)
        assert_cap_short_circuit(self, outcome)

    def test_08_revoked_authority_blocks(self) -> None:
        envelope, authority, _, cap_policy, path_policy, claims_policy = (
            pass_bundle()
        )
        authority["state"] = "REVOKED"
        authority["revocation_status"] = "REVOKED"
        cap_decision = cap_for(
            envelope,
            authority,
            cap_policy,
            path_policy,
            claims_policy,
        )
        outcome = evaluate(
            (
                envelope,
                authority,
                cap_decision,
                cap_policy,
                path_policy,
                claims_policy,
            )
        )
        self.assertEqual("BLOCK", cap_decision["decision"])
        self.assertIn("CAP_AUTHORITY_REVOKED", cap_decision["reason_codes"])
        self.assertEqual("BLOCK", outcome.status)
        assert_cap_short_circuit(self, outcome)

    def test_09_evaluation_as_of_before_expiry_is_valid(self) -> None:
        envelope, authority, _, cap_policy, path_policy, claims_policy = (
            pass_bundle()
        )
        envelope["requested_at"] = "2026-07-29T12:00:00Z"
        envelope["evaluation_as_of"] = "2026-07-29T12:05:00Z"
        cap_decision = cap_for(
            envelope,
            authority,
            cap_policy,
            path_policy,
            claims_policy,
        )
        outcome = evaluate(
            (
                envelope,
                authority,
                cap_decision,
                cap_policy,
                path_policy,
                claims_policy,
            )
        )
        self.assertEqual("PASS", cap_decision["decision"])
        self.assertEqual("VALID", outcome.combined_decision["authority_status"])
        self.assertEqual("PASS", outcome.status)

    def test_10_evaluation_as_of_at_expiry_blocks(self) -> None:
        envelope, authority, _, cap_policy, path_policy, claims_policy = (
            pass_bundle()
        )
        envelope["requested_at"] = "2026-07-29T12:00:00Z"
        envelope["evaluation_as_of"] = authority["expires_at"]
        cap_decision = cap_for(
            envelope,
            authority,
            cap_policy,
            path_policy,
            claims_policy,
        )
        outcome = evaluate(
            (
                envelope,
                authority,
                cap_decision,
                cap_policy,
                path_policy,
                claims_policy,
            )
        )
        self.assertEqual("BLOCK", cap_decision["decision"])
        self.assertIn(
            "CAP_AUTHORITY_TIME_INVALID",
            cap_decision["reason_codes"],
        )
        self.assertEqual("BLOCK", outcome.status)
        assert_cap_short_circuit(self, outcome)

    def test_11_traversal_path_blocks(self) -> None:
        invalid_paths = (
            "docs/public/../secrets/value.md",
            "docs/public/bad\x85name.md",
            "docs/public/bad\x9fname.md",
        )
        for invalid_path in invalid_paths:
            with self.subTest(path=repr(invalid_path)):
                envelope, authority, _, cap_policy, path_policy, claims_policy = (
                    pass_bundle()
                )
                envelope["changes"][0]["path"] = invalid_path
                cap_decision = cap_for(
                    envelope,
                    authority,
                    cap_policy,
                    path_policy,
                    claims_policy,
                )
                outcome = evaluate(
                    (
                        envelope,
                        authority,
                        cap_decision,
                        cap_policy,
                        path_policy,
                        claims_policy,
                    )
                )
                self.assertEqual("BLOCK", cap_decision["decision"])
                self.assertIn(
                    "CAP_REQUESTED_PATH_INVALID",
                    cap_decision["reason_codes"],
                )
                self.assertEqual("BLOCK", outcome.status)
                assert_cap_short_circuit(self, outcome)

    def test_12_underdeclared_required_gate_blocks_cap(self) -> None:
        envelope, authority, _, cap_policy, path_policy, claims_policy = (
            pass_bundle()
        )
        authority["applicable_gates"] = [
            item
            for item in authority["applicable_gates"]
            if item["gate_id"] != "claims_gate"
        ]
        cap_decision = cap_for(
            envelope,
            authority,
            cap_policy,
            path_policy,
            claims_policy,
        )
        outcome = evaluate(
            (
                envelope,
                authority,
                cap_decision,
                cap_policy,
                path_policy,
                claims_policy,
            )
        )
        self.assertEqual("BLOCK", cap_decision["decision"])
        self.assertIn(
            "CAP_REQUIRED_GATE_SET_UNDERDECLARED",
            cap_decision["reason_codes"],
        )
        self.assertEqual("BLOCK", outcome.status)
        assert_cap_short_circuit(self, outcome)

    def test_cap_blocks_task_outside_authority_scope(self) -> None:
        envelope, authority, _, cap_policy, path_policy, claims_policy = (
            pass_bundle()
        )
        envelope["task"]["task_id"] = "outside-authority-task-999"
        cap_decision = cap_for(
            envelope,
            authority,
            cap_policy,
            path_policy,
            claims_policy,
        )
        outcome = evaluate(
            (
                envelope,
                authority,
                cap_decision,
                cap_policy,
                path_policy,
                claims_policy,
            )
        )
        self.assertEqual("BLOCK", cap_decision["decision"])
        self.assertIn("CAP_TASK_SCOPE_EXCEEDED", cap_decision["reason_codes"])
        self.assertEqual("BLOCK", outcome.status)
        assert_cap_short_circuit(self, outcome)

    def test_13_repair_reruns_cap_and_hash_links_prior_block(self) -> None:
        blocked = evaluate(evaluation_bundle("blocked"))
        repaired = evaluate(
            evaluation_bundle("repaired"),
            prior_receipt=blocked.receipt,
        )
        self.assertEqual("BLOCK", blocked.status)
        self.assertEqual("PASS", repaired.status)
        self.assertNotEqual(
            blocked.cap_decision["canonical_hash"],
            repaired.cap_decision["canonical_hash"],
        )
        lineage = repaired.receipt["repair_lineage"]
        self.assertTrue(lineage["cap_rechecked"])
        self.assertEqual(
            blocked.receipt["receipt_id"],
            lineage["prior_receipt_id"],
        )
        self.assertEqual(
            blocked.receipt["receipt_hash"],
            lineage["prior_receipt_hash"],
        )
        self.assertEqual(
            blocked.receipt["input_hashes"]["cap_decision"],
            lineage["changed_input_hashes"]["prior_cap_decision"],
        )
        self.assertEqual(
            repaired.receipt["input_hashes"]["cap_decision"],
            lineage["changed_input_hashes"]["current_cap_decision"],
        )
        self.assertEqual(
            repaired.receipt["policy_hashes"],
            lineage["unchanged_policy_hashes"],
        )

    def test_14_same_policy_version_altered_content_changes_identity(self) -> None:
        baseline_values = pass_bundle()
        baseline = evaluate(baseline_values)
        (
            envelope,
            authority,
            _,
            cap_policy,
            path_policy,
            claims_policy,
        ) = deepcopy(baseline_values)
        old_version = path_policy["policy_version"]
        old_hash = path_policy["policy_hash"]
        path_policy["protected_rules"].append(
            {
                "match": "SUBTREE",
                "path": "docs/alternate",
                "rule_id": "alternate-content-byte-identity",
            }
        )
        new_hash = bind_policy(
            "path_gate",
            path_policy,
            envelope,
            authority,
        )
        cap_decision = cap_for(
            envelope,
            authority,
            cap_policy,
            path_policy,
            claims_policy,
        )
        changed = evaluate(
            (
                envelope,
                authority,
                cap_decision,
                cap_policy,
                path_policy,
                claims_policy,
            )
        )
        self.assertEqual(old_version, path_policy["policy_version"])
        self.assertNotEqual(old_hash, new_hash)
        self.assertEqual("PASS", baseline.status)
        self.assertEqual("PASS", changed.status)
        self.assertNotEqual(
            baseline.cap_decision["canonical_hash"],
            changed.cap_decision["canonical_hash"],
        )
        self.assertNotEqual(
            baseline.receipt["receipt_hash"],
            changed.receipt["receipt_hash"],
        )

    def test_15_gate_order_is_materially_invariant_after_cap_pass(self) -> None:
        values = pass_bundle()
        forward = evaluate(
            values,
            gate_order=("path_gate", "claims_gate"),
        )
        reverse = evaluate(
            values,
            gate_order=("claims_gate", "path_gate"),
        )
        self.assertEqual(forward.gate_results, reverse.gate_results)
        self.assertEqual(
            forward.combined_decision,
            reverse.combined_decision,
        )
        self.assertEqual(forward.receipt, reverse.receipt)

    def test_16_hold_emits_canonical_receipt_and_never_passes(self) -> None:
        outcome = evaluate(evaluation_bundle("hold"))
        self.assertEqual(
            "HOLD:CONTEXT_UPDATE_REQUIRED",
            outcome.cap_decision["decision"],
        )
        self.assertIn(
            "CAP_REFRESHABLE_EVIDENCE_UNAVAILABLE",
            outcome.cap_decision["reason_codes"],
        )
        source_check = next(
            check
            for check in outcome.cap_decision["checks"]
            if check["check_id"] == "SOURCE_BASIS"
        )
        self.assertEqual("PASS", source_check["status"])
        self.assertEqual("HOLD", outcome.status)
        self.assertNotEqual("PASS", outcome.status)
        self.assertEqual("HOLD", outcome.receipt["decision"]["status"])
        self.assertEqual(
            [],
            validate_receipt(outcome.receipt, raise_on_error=False),
        )
        assert_cap_short_circuit(self, outcome)

    def test_required_domain_gate_hold_is_preserved_in_receipt(self) -> None:
        envelope, authority, _, cap_policy, path_policy, claims_policy = (
            pass_bundle()
        )
        envelope["evidence"][0]["evidence_state"] = "INCONCLUSIVE"
        cap_decision = cap_for(
            envelope,
            authority,
            cap_policy,
            path_policy,
            claims_policy,
        )
        outcome = evaluate(
            (
                envelope,
                authority,
                cap_decision,
                cap_policy,
                path_policy,
                claims_policy,
            )
        )
        self.assertEqual("PASS", cap_decision["decision"])
        self.assertEqual(
            {"claims_gate": "HOLD", "path_gate": "PASS"},
            gate_statuses(outcome),
        )
        self.assertEqual("HOLD", outcome.status)
        self.assertEqual("HOLD", outcome.receipt["decision"]["status"])
        self.assertNotEqual("PASS", outcome.status)

    def test_combined_precedence_blocks_not_evaluated_and_fallback_states(
        self,
    ) -> None:
        common = {
            "input_status": "VALID",
            "authority_status": "VALID",
            "cap_input_status": "VALID",
            "cap_decision": {"decision": "PASS"},
            "domain_gates_executed": True,
        }
        not_evaluated = [
            {
                "required": True,
                "applicable": True,
                "status": "NOT_EVALUATED",
            },
            {"required": True, "applicable": True, "status": "PASS"},
        ]
        fallback = [
            {"required": True, "applicable": True, "status": "UNKNOWN"},
            {"required": True, "applicable": True, "status": "PASS"},
        ]
        self.assertEqual(
            "BLOCK",
            _combined_status(
                **common,
                gate_results=not_evaluated,
            ),
        )
        self.assertEqual(
            "BLOCK",
            _combined_status(
                **common,
                gate_results=fallback,
            ),
        )

    def test_17_fixed_inputs_replay_byte_identically(self) -> None:
        values = pass_bundle()
        first = evaluate(values)
        expected = canonical_bytes(
            {
                "cap_decision": first.cap_decision,
                "gate_results": list(first.gate_results),
                "combined_decision": first.combined_decision,
                "receipt": first.receipt,
            }
        )
        for _ in range(5):
            replay = evaluate(deepcopy(values))
            actual = canonical_bytes(
                {
                    "cap_decision": replay.cap_decision,
                    "gate_results": list(replay.gate_results),
                    "combined_decision": replay.combined_decision,
                    "receipt": replay.receipt,
                }
            )
            self.assertEqual(expected, actual)


if __name__ == "__main__":
    unittest.main()
