from __future__ import annotations

from copy import deepcopy
import json
import unittest

from governed_change_demo.canonical import (
    hash_without_fields,
    stable_identifier,
)
from governed_change_demo.contracts import (
    AUTHORITY_VERSION,
    CAP_VERSION,
    COMBINED_DECISION_VERSION,
    ENVELOPE_VERSION,
    GATE_RESULT_VERSION,
    RECEIPT_VERSION,
    validate_authority,
    validate_cap_decision,
    validate_contract,
    validate_envelope,
)
from governed_change_demo.orchestrator import evaluate_bundle

from tests.helpers import ROOT, evaluation_bundle, pass_bundle


SCHEMA_VERSIONS = {
    "authority-manifest.v1.schema.json": AUTHORITY_VERSION,
    "cap-decision.v1.schema.json": CAP_VERSION,
    "combined-decision.v1.schema.json": COMBINED_DECISION_VERSION,
    "gate-result.v1.schema.json": GATE_RESULT_VERSION,
    "governed-receipt.v1.schema.json": RECEIPT_VERSION,
    "shared-change-envelope.v1.schema.json": ENVELOPE_VERSION,
}


def evaluate(
    values: tuple[dict, dict, dict, dict, dict, dict],
    *,
    prior_receipt=None,
):
    return evaluate_bundle(*values, prior_receipt=prior_receipt)


def assert_short_circuit(
    case: unittest.TestCase,
    outcome,
) -> None:
    case.assertFalse(outcome.combined_decision["domain_gates_executed"])
    case.assertEqual(2, len(outcome.gate_results))
    case.assertEqual(
        {"claims_gate", "path_gate"},
        {result["gate_id"] for result in outcome.gate_results},
    )
    for result in outcome.gate_results:
        case.assertEqual("NOT_EVALUATED", result["status"])
        case.assertEqual(["CAP_NOT_PASSED"], result["reason_codes"])


class SixContractValidationTests(unittest.TestCase):
    def test_exactly_six_schemas_declare_the_locked_contract_versions(
        self,
    ) -> None:
        schema_dir = ROOT / "contracts"
        schemas = {
            path.name: json.loads(path.read_text(encoding="utf-8"))
            for path in schema_dir.glob("*.schema.json")
        }
        self.assertEqual(set(SCHEMA_VERSIONS), set(schemas))
        for name, expected_version in SCHEMA_VERSIONS.items():
            schema = schemas[name]
            self.assertEqual(
                "https://json-schema.org/draft/2020-12/schema",
                schema["$schema"],
            )
            self.assertFalse(schema["additionalProperties"])
            self.assertEqual(
                expected_version,
                schema["properties"]["contract_version"]["const"],
            )

    def test_bundled_inputs_and_mechanically_generated_caps_validate(
        self,
    ) -> None:
        for name in (
            "blocked",
            "repaired",
            "cap-block",
            "context-update",
            "hold",
        ):
            with self.subTest(fixture=name):
                (
                    envelope,
                    authority,
                    cap_decision,
                    _,
                    _,
                    _,
                ) = evaluation_bundle(name)
                self.assertEqual(
                    [],
                    validate_envelope(envelope, raise_on_error=False),
                )
                self.assertEqual(
                    [],
                    validate_authority(authority, raise_on_error=False),
                )
                self.assertEqual(
                    [],
                    validate_cap_decision(
                        cap_decision,
                        raise_on_error=False,
                    ),
                )

    def test_all_six_runtime_contract_kinds_validate_for_real_outcomes(
        self,
    ) -> None:
        blocked = evaluate(evaluation_bundle("blocked"))
        repaired = evaluate(
            evaluation_bundle("repaired"),
            prior_receipt=blocked.receipt,
        )
        for outcome in (blocked, repaired, evaluate(pass_bundle())):
            with self.subTest(status=outcome.status):
                self.assertEqual(
                    [],
                    validate_contract("cap_decision", outcome.cap_decision),
                )
                for result in outcome.gate_results:
                    self.assertEqual(
                        [],
                        validate_contract("gate_result", result),
                    )
                self.assertEqual(
                    [],
                    validate_contract(
                        "combined_decision",
                        outcome.combined_decision,
                    ),
                )
                self.assertEqual(
                    [],
                    validate_contract("receipt", outcome.receipt),
                )

    def test_unknown_envelope_field_is_rejected(self) -> None:
        envelope, _, _, _, _, _ = evaluation_bundle()
        envelope["silent_extension"] = True
        codes = {
            item.code
            for item in validate_envelope(envelope, raise_on_error=False)
        }
        self.assertIn("UNKNOWN_FIELD", codes)

    def test_timestamps_require_strict_rfc3339_utc_z_form(self) -> None:
        invalid_values = (
            "2026-07-29 12:05:00Z",
            "2026-W31-3T12:05:00Z",
            "2026-07-29T12:05Z",
            "2026-07-29T12:05:00+00:00",
        )
        for invalid in invalid_values:
            for field in ("requested_at", "evaluation_as_of"):
                with self.subTest(contract="envelope", field=field, value=invalid):
                    envelope, _, _, _, _, _ = evaluation_bundle()
                    envelope[field] = invalid
                    pointers = {
                        item.pointer
                        for item in validate_envelope(
                            envelope,
                            raise_on_error=False,
                        )
                        if item.code == "UTC_TIMESTAMP_INVALID"
                    }
                    self.assertIn(f"/{field}", pointers)
            for field in ("issued_at", "expires_at"):
                with self.subTest(contract="authority", field=field, value=invalid):
                    _, authority, _, _, _, _ = evaluation_bundle()
                    authority[field] = invalid
                    pointers = {
                        item.pointer
                        for item in validate_authority(
                            authority,
                            raise_on_error=False,
                        )
                        if item.code == "UTC_TIMESTAMP_INVALID"
                    }
                    self.assertIn(f"/{field}", pointers)

    def test_missing_required_authority_field_is_rejected(self) -> None:
        _, authority, _, _, _, _ = evaluation_bundle()
        authority.pop("applicable_gates")
        codes = {
            item.code
            for item in validate_authority(
                authority,
                raise_on_error=False,
            )
        }
        self.assertIn("REQUIRED_FIELD_MISSING", codes)

    def test_malformed_envelope_fails_closed_deterministically(self) -> None:
        _, authority, cap_decision, cap_policy, path_policy, claims_policy = (
            evaluation_bundle()
        )
        malformed = {"contract_version": "wrong"}
        first = evaluate_bundle(
            malformed,
            authority,
            cap_decision,
            cap_policy,
            path_policy,
            claims_policy,
        )
        second = evaluate_bundle(
            deepcopy(malformed),
            deepcopy(authority),
            deepcopy(cap_decision),
            deepcopy(cap_policy),
            deepcopy(path_policy),
            deepcopy(claims_policy),
        )
        self.assertEqual("BLOCK", first.status)
        self.assertEqual(
            "INVALID",
            first.combined_decision["input_status"],
        )
        self.assertEqual(
            "INVALID",
            first.combined_decision["cap_input_status"],
        )
        assert_short_circuit(self, first)
        self.assertEqual(first.combined_decision, second.combined_decision)
        self.assertEqual(first.receipt, second.receipt)
        self.assertEqual(
            [],
            validate_contract("receipt", first.receipt),
        )

    def test_missing_authority_and_cap_evidence_fail_closed(self) -> None:
        envelope, _, cap_decision, cap_policy, path_policy, claims_policy = (
            evaluation_bundle()
        )
        missing_authority = evaluate_bundle(
            envelope,
            None,
            cap_decision,
            cap_policy,
            path_policy,
            claims_policy,
        )
        self.assertEqual("BLOCK", missing_authority.status)
        self.assertEqual(
            "MISSING",
            missing_authority.combined_decision["authority_status"],
        )
        assert_short_circuit(self, missing_authority)

        envelope, authority, _, cap_policy, path_policy, claims_policy = (
            evaluation_bundle()
        )
        missing_cap = evaluate_bundle(
            envelope,
            authority,
            None,
            cap_policy,
            path_policy,
            claims_policy,
        )
        self.assertEqual("BLOCK", missing_cap.status)
        self.assertEqual(
            "MISSING",
            missing_cap.combined_decision["cap_input_status"],
        )
        self.assertIn(
            "CAP_DECISION_MISSING",
            missing_cap.combined_decision["reason_codes"],
        )
        assert_short_circuit(self, missing_cap)
        self.assertEqual(
            [],
            validate_contract("receipt", missing_cap.receipt),
        )

    def test_semantically_tampered_cap_is_rederived_and_rejected(self) -> None:
        (
            envelope,
            authority,
            cap_decision,
            cap_policy,
            path_policy,
            claims_policy,
        ) = pass_bundle()
        cap_decision["next_lawful_move"] = "Skip the declared controls."
        cap_body = {
            key: value
            for key, value in cap_decision.items()
            if key not in {"cap_decision_id", "canonical_hash"}
        }
        cap_decision["cap_decision_id"] = stable_identifier(
            "cap",
            cap_body,
        )
        cap_decision["canonical_hash"] = hash_without_fields(
            cap_decision,
            {"canonical_hash"},
        )
        self.assertEqual(
            [],
            validate_cap_decision(
                cap_decision,
                raise_on_error=False,
            ),
        )
        outcome = evaluate_bundle(
            envelope,
            authority,
            cap_decision,
            cap_policy,
            path_policy,
            claims_policy,
        )
        self.assertEqual("BLOCK", outcome.status)
        self.assertEqual(
            "INVALID",
            outcome.combined_decision["cap_input_status"],
        )
        self.assertIn(
            "CAP_SEMANTIC_REDERIVATION_MISMATCH",
            outcome.combined_decision["reason_codes"],
        )
        assert_short_circuit(self, outcome)

    def test_changed_policy_bytes_without_rebinding_fail_closed(self) -> None:
        (
            envelope,
            authority,
            cap_decision,
            cap_policy,
            path_policy,
            claims_policy,
        ) = pass_bundle()
        path_policy["protected_rules"].append(
            {
                "match": "SUBTREE",
                "path": "docs/alternate",
                "rule_id": "same-version-content-change",
            }
        )
        outcome = evaluate_bundle(
            envelope,
            authority,
            cap_decision,
            cap_policy,
            path_policy,
            claims_policy,
        )
        self.assertEqual("BLOCK", outcome.status)
        self.assertIn(
            "ENVELOPE_POLICY_HASH_MISMATCH",
            outcome.combined_decision["reason_codes"],
        )
        self.assertIn(
            "AUTHORITY_POLICY_HASH_MISMATCH",
            outcome.combined_decision["reason_codes"],
        )
        assert_short_circuit(self, outcome)

    def test_stale_policy_fails_closed_before_domain_gates(self) -> None:
        (
            envelope,
            authority,
            cap_decision,
            cap_policy,
            path_policy,
            claims_policy,
        ) = pass_bundle()
        path_policy["expires_at"] = envelope["evaluation_as_of"]
        outcome = evaluate_bundle(
            envelope,
            authority,
            cap_decision,
            cap_policy,
            path_policy,
            claims_policy,
        )
        self.assertEqual("BLOCK", outcome.status)
        self.assertIn(
            "POLICY_STALE",
            outcome.combined_decision["reason_codes"],
        )
        assert_short_circuit(self, outcome)

    def test_non_integer_and_invalid_unicode_inputs_fail_closed(self) -> None:
        values = list(evaluation_bundle())
        values[0]["revision"] = 1.5
        non_integer = evaluate_bundle(*values)
        self.assertEqual("BLOCK", non_integer.status)
        self.assertEqual(
            "INVALID",
            non_integer.combined_decision["input_status"],
        )
        assert_short_circuit(self, non_integer)

        values = list(evaluation_bundle())
        values[0]["task"]["summary"] = "\ud800"
        invalid_unicode = evaluate_bundle(*values)
        self.assertEqual("BLOCK", invalid_unicode.status)
        self.assertEqual(
            "INVALID",
            invalid_unicode.combined_decision["input_status"],
        )
        assert_short_circuit(self, invalid_unicode)

    def test_revision_requires_integer_not_boolean(self) -> None:
        envelope, _, _, _, _, _ = evaluation_bundle()
        envelope["revision"] = True
        codes = {
            item.code
            for item in validate_envelope(envelope, raise_on_error=False)
        }
        self.assertIn("TYPE_INTEGER_REQUIRED", codes)


if __name__ == "__main__":
    unittest.main()
