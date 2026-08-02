from __future__ import annotations

from copy import deepcopy
import unittest

from governed_change_demo.canonical import canonical_hash
from governed_change_demo.claims_gate import evaluate_claims_gate
from governed_change_demo.path_gate import evaluate_path_gate, normalize_repo_path
from governed_change_demo.policies import policy_content_hash

from tests.helpers import bundle


class HeterogeneousGateTests(unittest.TestCase):
    def test_original_exercises_two_distinct_blocking_evidence_surfaces(self) -> None:
        envelope, authority, _, path_policy, claims_policy = bundle("blocked")
        path_result = evaluate_path_gate(envelope, authority, path_policy)
        claims_result = evaluate_claims_gate(envelope, authority, claims_policy)
        self.assertEqual("BLOCK", path_result["status"])
        self.assertEqual("BLOCK", claims_result["status"])
        self.assertIn("protected_hits", path_result["evidence"])
        self.assertIn("authority_matches", path_result["evidence"])
        self.assertIn("claims", claims_result["evidence"])
        self.assertIn("claim_inventory_hash", claims_result["evidence"])
        self.assertNotEqual(
            set(path_result["evidence"]), set(claims_result["evidence"])
        )

    def test_repaired_revision_passes_both_gates(self) -> None:
        envelope, authority, _, path_policy, claims_policy = bundle("repaired")
        self.assertEqual("PASS", evaluate_path_gate(envelope, authority, path_policy)["status"])
        self.assertEqual(
            "PASS", evaluate_claims_gate(envelope, authority, claims_policy)["status"]
        )

    def test_gate_results_bind_policy_payload_without_embedded_self_hash(self) -> None:
        envelope, authority, _, path_policy, claims_policy = bundle("repaired")
        for evaluator, policy in (
            (evaluate_path_gate, path_policy),
            (evaluate_claims_gate, claims_policy),
        ):
            with self.subTest(gate=policy["policy_id"]):
                result = evaluator(envelope, authority, policy)
                self.assertEqual(
                    policy_content_hash(policy),
                    result["policy_hash"],
                )
                self.assertNotEqual(canonical_hash(policy), result["policy_hash"])

    def test_parent_traversal_is_invalid(self) -> None:
        with self.assertRaises(ValueError):
            normalize_repo_path("docs/public/../../secrets/value.txt")

    def test_parent_traversal_blocks_path_gate(self) -> None:
        envelope, authority, _, path_policy, _ = bundle("repaired")
        envelope["changes"][0]["path"] = "docs/public/../secrets/value.txt"
        result = evaluate_path_gate(envelope, authority, path_policy)
        self.assertEqual("BLOCK", result["status"])
        self.assertIn("PATH_FORM_INVALID", result["reason_codes"])

    def test_subtree_matching_respects_segment_boundaries(self) -> None:
        envelope, authority, _, path_policy, _ = bundle("repaired")
        envelope["changes"][0]["path"] = "docs/publicity/not-public.md"
        result = evaluate_path_gate(envelope, authority, path_policy)
        self.assertEqual("BLOCK", result["status"])
        self.assertIn("PATH_OUTSIDE_AUTHORITY", result["reason_codes"])
        self.assertEqual(
            ["docs/publicity/not-public.md"],
            result["evidence"]["denied_paths"],
        )

    def test_dot_segments_collapse_without_broadening_authority(self) -> None:
        envelope, authority, _, path_policy, _ = bundle("repaired")
        envelope["changes"][0]["path"] = (
            "docs/./public/./governed-change-result.md"
        )
        result = evaluate_path_gate(envelope, authority, path_policy)
        self.assertEqual("PASS", result["status"])
        self.assertEqual(
            ["docs/public/governed-change-result.md"],
            result["evidence"]["normalized_paths"],
        )

    def test_backslashes_canonicalize_to_repository_separators(self) -> None:
        envelope, authority, _, path_policy, _ = bundle("repaired")
        envelope["changes"][0]["path"] = (
            r"docs\public\governed-change-result.md"
        )
        result = evaluate_path_gate(envelope, authority, path_policy)
        self.assertEqual("PASS", result["status"])
        self.assertEqual(
            ["docs/public/governed-change-result.md"],
            result["evidence"]["normalized_paths"],
        )

    def test_control_characters_block_as_unknown_path_forms(self) -> None:
        for control in ("\x00", "\x01", "\x1f", "\x7f", "\x85", "\x9f"):
            with self.subTest(control=repr(control)):
                envelope, authority, _, path_policy, _ = bundle("repaired")
                envelope["changes"][0]["path"] = (
                    f"docs/public/bad{control}name.md"
                )
                result = evaluate_path_gate(envelope, authority, path_policy)
                self.assertEqual("BLOCK", result["status"])
                self.assertIn("PATH_FORM_INVALID", result["reason_codes"])

    def test_absolute_drive_unc_uri_and_empty_segment_forms_are_rejected(self) -> None:
        invalid = (
            "/docs/public/file.md",
            "C:/docs/public/file.md",
            r"\\server\share\file.md",
            "file://docs/public/file.md",
            "docs//public/file.md",
            ".",
        )
        for path in invalid:
            with self.subTest(path=path):
                with self.assertRaises(ValueError):
                    normalize_repo_path(path)
                envelope, authority, _, path_policy, _ = bundle("repaired")
                envelope["changes"][0]["path"] = path
                result = evaluate_path_gate(envelope, authority, path_policy)
                self.assertEqual("BLOCK", result["status"])
                self.assertIn("PATH_FORM_INVALID", result["reason_codes"])

    def test_path_canonicalization_does_not_trim_whitespace(self) -> None:
        self.assertEqual(
            " docs/public/file.md ",
            normalize_repo_path(" docs/public/file.md "),
        )
        envelope, authority, _, path_policy, _ = bundle("repaired")
        envelope["changes"][0]["path"] = "docs/public/governed-change-result.md "
        authority["permitted_paths"] = [
            {
                "actions": ["CREATE"],
                "allow_protected": False,
                "match": "EXACT",
                "path": "docs/public/governed-change-result.md",
                "rule_id": "exact-unspaced-target",
            }
        ]
        result = evaluate_path_gate(envelope, authority, path_policy)
        self.assertEqual("BLOCK", result["status"])
        self.assertIn("PATH_OUTSIDE_AUTHORITY", result["reason_codes"])

    def test_unknown_case_and_match_modes_block(self) -> None:
        envelope, authority, _, path_policy, _ = bundle("repaired")
        unknown_case = deepcopy(path_policy)
        unknown_case["case_mode"] = "UNKNOWN"
        case_result = evaluate_path_gate(envelope, authority, unknown_case)
        self.assertEqual("BLOCK", case_result["status"])
        self.assertIn("PATH_POLICY_CASE_MODE_INVALID", case_result["reason_codes"])

        unknown_match = deepcopy(authority)
        unknown_match["permitted_paths"][1]["match"] = "PREFIX"
        match_result = evaluate_path_gate(envelope, unknown_match, path_policy)
        self.assertEqual("BLOCK", match_result["status"])
        self.assertIn(
            "AUTHORITY_PATH_MATCH_MODE_INVALID",
            match_result["reason_codes"],
        )

    def test_declared_case_policy_controls_matching(self) -> None:
        envelope, authority, _, path_policy, _ = bundle("repaired")
        envelope["changes"][0]["path"] = (
            "DOCS/PUBLIC/governed-change-result.md"
        )
        sensitive = evaluate_path_gate(envelope, authority, path_policy)
        self.assertEqual("BLOCK", sensitive["status"])
        self.assertIn("PATH_OUTSIDE_AUTHORITY", sensitive["reason_codes"])

        insensitive_policy = deepcopy(path_policy)
        insensitive_policy["case_mode"] = "INSENSITIVE"
        insensitive = evaluate_path_gate(
            envelope,
            authority,
            insensitive_policy,
        )
        self.assertEqual("PASS", insensitive["status"])

    def test_authority_window_uses_evaluation_as_of_not_requested_at(self) -> None:
        envelope, authority, _, path_policy, claims_policy = bundle("repaired")
        envelope["requested_at"] = "2035-01-01T00:00:00Z"
        envelope["evaluation_as_of"] = "2026-07-29T12:00:00Z"
        self.assertEqual(
            "PASS",
            evaluate_path_gate(envelope, authority, path_policy)["status"],
        )
        self.assertEqual(
            "PASS",
            evaluate_claims_gate(envelope, authority, claims_policy)["status"],
        )

        envelope["requested_at"] = "2026-07-29T12:00:00Z"
        envelope["evaluation_as_of"] = "2035-01-01T00:00:00Z"
        path_result = evaluate_path_gate(envelope, authority, path_policy)
        claims_result = evaluate_claims_gate(envelope, authority, claims_policy)
        self.assertEqual("BLOCK", path_result["status"])
        self.assertEqual("BLOCK", claims_result["status"])
        self.assertIn("AUTHORITY_STALE", path_result["reason_codes"])
        self.assertIn("AUTHORITY_STALE", claims_result["reason_codes"])

    def test_rename_evaluates_both_endpoints(self) -> None:
        envelope, authority, _, path_policy, _ = bundle("repaired")
        change = envelope["changes"][0]
        change["operation"] = "RENAME"
        change["destination_path"] = "config/moved.md"
        authority["permitted_actions"].append("RENAME")
        authority["permitted_paths"][0]["actions"].append("RENAME")
        result = evaluate_path_gate(envelope, authority, path_policy)
        roles = {item["endpoint_role"] for item in result["evidence"]["evaluated_endpoints"]}
        self.assertEqual({"source", "destination"}, roles)
        self.assertEqual("BLOCK", result["status"])
        self.assertIn("PROTECTED_PATH_BLOCKED", result["reason_codes"])

    def test_claim_inventory_must_match_content(self) -> None:
        envelope, authority, _, _, claims_policy = bundle("repaired")
        envelope["changes"][0]["claims"][0]["statement"] = "A missing sentence."
        result = evaluate_claims_gate(envelope, authority, claims_policy)
        self.assertEqual("BLOCK", result["status"])
        self.assertIn("CLAIM_NOT_PRESENT_IN_CONTENT", result["reason_codes"])

    def test_required_caveat_must_be_at_claim_site(self) -> None:
        envelope, authority, _, _, claims_policy = bundle("repaired")
        caveat = envelope["changes"][0]["claims"][0]["caveats"][0]
        envelope["changes"][0]["content"] = envelope["changes"][0]["content"].replace(
            caveat, ""
        )
        result = evaluate_claims_gate(envelope, authority, claims_policy)
        self.assertEqual("BLOCK", result["status"])
        self.assertIn(
            "REQUIRED_CAVEAT_NOT_PRESENT_AT_CLAIM_SITE", result["reason_codes"]
        )

    def test_caveat_elsewhere_in_content_is_not_at_claim_site(self) -> None:
        envelope, authority, _, _, claims_policy = bundle("repaired")
        change = envelope["changes"][0]
        claim = change["claims"][0]
        caveat = claim["caveats"][0]
        content_without_caveat = change["content"].replace(caveat, "")
        change["content"] = f"{caveat}\n\n{content_without_caveat}"
        result = evaluate_claims_gate(envelope, authority, claims_policy)
        self.assertEqual("BLOCK", result["status"])
        self.assertIn(
            "REQUIRED_CAVEAT_NOT_PRESENT_AT_CLAIM_SITE",
            result["reason_codes"],
        )

    def test_required_caveat_must_also_be_declared(self) -> None:
        envelope, authority, _, _, claims_policy = bundle("repaired")
        envelope["changes"][0]["claims"][0]["caveats"] = []
        result = evaluate_claims_gate(envelope, authority, claims_policy)
        self.assertEqual("BLOCK", result["status"])
        self.assertIn("REQUIRED_CAVEAT_NOT_DECLARED", result["reason_codes"])

    def test_each_claim_boundary_mutation_blocks_independently(self) -> None:
        def prohibited_tag(envelope: dict) -> None:
            envelope["changes"][0]["claims"][0]["claim_tag"] = "SECURITY"

        def unknown_tag(envelope: dict) -> None:
            envelope["changes"][0]["claims"][0]["claim_tag"] = "UNDECLARED"

        def missing_reference(envelope: dict) -> None:
            envelope["changes"][0]["claims"][0]["evidence_refs"] = []

        def unknown_reference(envelope: dict) -> None:
            envelope["changes"][0]["claims"][0]["evidence_refs"] = [
                "missing-evidence"
            ]

        def wrong_evidence_class(envelope: dict) -> None:
            envelope["evidence"][0]["evidence_class"] = "PREFERENCE"

        def refuted_evidence(envelope: dict) -> None:
            envelope["evidence"][0]["evidence_state"] = "REFUTED"

        def partial_evidence(envelope: dict) -> None:
            envelope["evidence"][0]["evidence_state"] = "PARTIALLY_SUPPORTED"

        def unknown_evidence_state(envelope: dict) -> None:
            envelope["evidence"][0]["evidence_state"] = "UNDECLARED"

        def unknown_claim_kind(envelope: dict) -> None:
            envelope["changes"][0]["claims"][0]["claim_kind"] = "UNDECLARED"

        cases = (
            ("prohibited_tag", prohibited_tag, "CLAIM_TAG_PROHIBITED"),
            ("unknown_tag", unknown_tag, "CLAIM_TAG_UNKNOWN"),
            ("missing_reference", missing_reference, "EVIDENCE_REFERENCE_MISSING"),
            ("unknown_reference", unknown_reference, "EVIDENCE_REFERENCE_UNKNOWN"),
            ("wrong_evidence_class", wrong_evidence_class, "EVIDENCE_CLASS_MISMATCH"),
            ("refuted_evidence", refuted_evidence, "EVIDENCE_REFUTES_CLAIM"),
            ("partial_evidence", partial_evidence, "EVIDENCE_NOT_SUPPORTED"),
            (
                "unknown_evidence_state",
                unknown_evidence_state,
                "EVIDENCE_STATE_UNKNOWN",
            ),
            ("unknown_claim_kind", unknown_claim_kind, "CLAIM_KIND_UNKNOWN"),
        )
        for name, mutate, expected_reason in cases:
            with self.subTest(name=name):
                envelope, authority, _, _, claims_policy = bundle("repaired")
                mutate(envelope)
                result = evaluate_claims_gate(envelope, authority, claims_policy)
                self.assertEqual("BLOCK", result["status"])
                self.assertIn(expected_reason, result["reason_codes"])

    def test_duplicate_evidence_id_makes_reference_ambiguous(self) -> None:
        envelope, authority, _, _, claims_policy = bundle("repaired")
        envelope["evidence"].append(deepcopy(envelope["evidence"][0]))
        result = evaluate_claims_gate(envelope, authority, claims_policy)
        self.assertEqual("BLOCK", result["status"])
        self.assertIn("EVIDENCE_REFERENCE_AMBIGUOUS", result["reason_codes"])

    def test_claims_gate_does_not_infer_prohibited_tags_from_prose(self) -> None:
        envelope, authority, _, _, claims_policy = bundle("repaired")
        change = envelope["changes"][0]
        claim = change["claims"][0]
        old_statement = claim["statement"]
        claim["statement"] = (
            "The word SECURITY appears only as a literal policy example."
        )
        change["content"] = change["content"].replace(
            old_statement,
            claim["statement"],
        )
        result = evaluate_claims_gate(envelope, authority, claims_policy)
        self.assertEqual("PASS", result["status"])
        self.assertNotIn("CLAIM_TAG_PROHIBITED", result["reason_codes"])

    def test_missing_evidence_never_becomes_hold_or_pass(self) -> None:
        envelope, authority, _, _, claims_policy = bundle("repaired")
        envelope["evidence"] = []
        result = evaluate_claims_gate(envelope, authority, claims_policy)
        self.assertEqual("BLOCK", result["status"])
        self.assertIn("EVIDENCE_REFERENCE_UNKNOWN", result["reason_codes"])

    def test_explicit_inconclusive_evidence_is_hold(self) -> None:
        envelope, authority, _, _, claims_policy = bundle("repaired")
        envelope["evidence"][0]["evidence_state"] = "INCONCLUSIVE"
        result = evaluate_claims_gate(envelope, authority, claims_policy)
        self.assertEqual("HOLD", result["status"])
        self.assertNotEqual("PASS", result["status"])

    def test_revoked_authority_blocks_each_gate(self) -> None:
        envelope, authority, _, path_policy, claims_policy = bundle("repaired")
        authority["state"] = "REVOKED"
        self.assertEqual("BLOCK", evaluate_path_gate(envelope, authority, path_policy)["status"])
        self.assertEqual(
            "BLOCK", evaluate_claims_gate(envelope, authority, claims_policy)["status"]
        )


if __name__ == "__main__":
    unittest.main()
