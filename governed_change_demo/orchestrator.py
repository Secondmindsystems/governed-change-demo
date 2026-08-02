"""Deterministic CAP precheck, two-gate orchestration, and receipts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from .canonical import (
    canonical_hash_or_fingerprint,
    hash_without_fields,
    stable_identifier,
)
from .cap_adapter import CapAssessment, assess_cap_decision
from .claims_gate import (
    ADAPTER_VERSION as CLAIMS_ADAPTER_VERSION,
    evaluate_claims_gate,
)
from .contracts import (
    COMBINED_DECISION_VERSION,
    GATE_RESULT_VERSION,
    KNOWN_POLICY_VERSIONS,
    RECEIPT_VERSION,
    ContractIssue,
    parse_utc,
    validate_authority,
    validate_combined_decision,
    validate_envelope,
    validate_gate_result,
    validate_receipt,
)
from .gate_result import build_gate_result
from .path_gate import (
    ADAPTER_VERSION as PATH_ADAPTER_VERSION,
    evaluate_path_gate,
)
from .policies import (
    PolicyAssessment,
    assess_cap_policy,
    assess_claims_policy,
    assess_path_policy,
    policy_content_hash,
)


DECISION_LOGIC_VERSION = "governed-repo.cap-two-gate-decision/v1.0.0"
EXPECTED_GATES = ("claims_gate", "path_gate")
CLAIM_BOUNDARIES = [
    (
        "The Codex Alignment Packet (CAP) mechanically checks declared source, "
        "authority, scope, evidence, and policy inputs before domain gates; it "
        "never grants execution authority."
    ),
    (
        "A PASS is deterministic product-local proof for the fixed candidate "
        "snapshot, evaluator versions, evaluation_as_of, and policy bytes only."
    ),
    (
        "This prototype does not establish security, compliance, production "
        "readiness, deployment readiness, customer validation, market demand, "
        "or external validation."
    ),
    (
        "This prototype neither executes repository changes nor qualifies P11, "
        "GASS runtime behavior, or any other autonomous runtime."
    ),
]


@dataclass(frozen=True)
class EvaluationOutcome:
    """The complete deterministic result for one evaluated revision."""

    cap_decision: Any
    gate_results: tuple[dict[str, Any], ...]
    combined_decision: dict[str, Any]
    receipt: dict[str, Any]

    @property
    def status(self) -> str:
        return self.combined_decision["status"]

    @property
    def exit_code(self) -> int:
        return {"PASS": 0, "BLOCK": 2, "HOLD": 3}[self.status]


def _fallback_subject(envelope: Any) -> tuple[str, int]:
    if isinstance(envelope, dict):
        change_id = envelope.get("change_id")
        revision = envelope.get("revision")
        safe_change_id = (
            change_id
            if isinstance(change_id, str) and change_id
            else "unknown-change"
        )
        safe_revision = (
            revision
            if isinstance(revision, int)
            and not isinstance(revision, bool)
            and revision >= 0
            else 0
        )
        return safe_change_id, safe_revision
    return "unknown-change", 0


def _issue(
    code: str,
    message: str,
    *,
    document: str = "orchestration",
    pointer: str = "",
) -> ContractIssue:
    return ContractIssue(document, code, pointer, message)


def _dedupe_issues(issues: Iterable[ContractIssue]) -> list[ContractIssue]:
    return sorted(
        set(issues),
        key=lambda item: (item.document, item.pointer, item.code, item.message),
    )


def _policy_hash(policy: Any) -> str:
    try:
        return policy_content_hash(policy)
    except (TypeError, ValueError, UnicodeError):
        return canonical_hash_or_fingerprint(policy)


def _policy_version(policy: Any, policy_key: str) -> str:
    if isinstance(policy, dict):
        version = policy.get("policy_version")
        if isinstance(version, str) and version:
            return version
    return KNOWN_POLICY_VERSIONS[policy_key]


def _evaluation_time(envelope: Any):
    if not isinstance(envelope, dict):
        return None
    return parse_utc(envelope.get("evaluation_as_of"))


def _policy_issues(
    cap_policy: Any,
    path_policy: Any,
    claims_policy: Any,
    evaluation_as_of: Any,
) -> tuple[list[ContractIssue], dict[str, PolicyAssessment]]:
    assessments = {
        "cap_policy": assess_cap_policy(cap_policy, evaluation_as_of),
        "path_gate": assess_path_policy(path_policy, evaluation_as_of),
        "claims_gate": assess_claims_policy(claims_policy, evaluation_as_of),
    }
    issues: list[ContractIssue] = []
    for policy_key, assessment in assessments.items():
        issues.extend(assessment.issues)
        if assessment.stale:
            issues.append(
                _issue(
                    "POLICY_STALE",
                    f"{policy_key} policy is inactive at evaluation_as_of",
                    document=f"{policy_key}_policy",
                )
            )
    return issues, assessments


def _policy_binding_issues(
    envelope: Any,
    authority: Any,
    cap_policy: Any,
    path_policy: Any,
    claims_policy: Any,
) -> list[ContractIssue]:
    """Check that both contracts bind the exact evaluated policy bytes."""

    if not isinstance(envelope, dict) or not isinstance(authority, dict):
        return []
    envelope_versions = envelope.get("policy_versions")
    authority_versions = authority.get("policy_versions")
    envelope_hashes = envelope.get("policy_hashes")
    authority_hashes = authority.get("policy_hashes")
    policies = {
        "cap_policy": cap_policy,
        "claims_gate": claims_policy,
        "path_gate": path_policy,
    }
    issues: list[ContractIssue] = []
    for policy_key in ("cap_policy", "claims_gate", "path_gate"):
        policy = policies[policy_key]
        version = (
            policy.get("policy_version")
            if isinstance(policy, dict)
            else None
        )
        content_hash = _policy_hash(policy)
        if (
            not isinstance(envelope_versions, dict)
            or envelope_versions.get(policy_key) != version
        ):
            issues.append(
                _issue(
                    "ENVELOPE_POLICY_VERSION_MISMATCH",
                    f"envelope does not bind the evaluated {policy_key} version",
                )
            )
        if (
            not isinstance(authority_versions, dict)
            or authority_versions.get(policy_key) != version
        ):
            issues.append(
                _issue(
                    "AUTHORITY_POLICY_VERSION_MISMATCH",
                    f"authority does not bind the evaluated {policy_key} version",
                )
            )
        if (
            not isinstance(envelope_hashes, dict)
            or envelope_hashes.get(policy_key) != content_hash
        ):
            issues.append(
                _issue(
                    "ENVELOPE_POLICY_HASH_MISMATCH",
                    f"envelope does not bind the evaluated {policy_key} bytes",
                )
            )
        if (
            not isinstance(authority_hashes, dict)
            or authority_hashes.get(policy_key) != content_hash
        ):
            issues.append(
                _issue(
                    "AUTHORITY_POLICY_HASH_MISMATCH",
                    f"authority does not bind the evaluated {policy_key} bytes",
                )
            )
    return issues


def _prior_receipt_issues(
    envelope: Any,
    prior_receipt: Any,
    policy_hashes: dict[str, str],
) -> list[ContractIssue]:
    if not isinstance(envelope, dict):
        return []
    revision = envelope.get("revision")
    if (
        not isinstance(revision, int)
        or isinstance(revision, bool)
        or revision <= 1
    ):
        return []
    if prior_receipt is None:
        return [
            _issue(
                "REPAIR_LINEAGE_REQUIRED",
                "every repaired revision requires the prior BLOCK receipt",
            )
        ]
    issues = list(validate_receipt(prior_receipt, raise_on_error=False))
    if issues:
        issues.append(
            _issue(
                "PRIOR_RECEIPT_INVALID",
                "prior receipt failed canonical validation",
            )
        )
        return issues
    if prior_receipt.get("change_id") != envelope.get("change_id"):
        issues.append(
            _issue(
                "REPAIR_CHANGE_ID_MISMATCH",
                "repair must preserve the logical change id",
            )
        )
    prior_revision = prior_receipt.get("revision")
    if (
        not isinstance(prior_revision, int)
        or isinstance(prior_revision, bool)
        or prior_revision >= revision
    ):
        issues.append(
            _issue(
                "REPAIR_REVISION_ORDER_INVALID",
                "repair revision must be greater than the prior revision",
            )
        )
    decision = prior_receipt.get("decision")
    if not isinstance(decision, dict) or decision.get("status") != "BLOCK":
        issues.append(
            _issue(
                "REPAIR_PRIOR_DECISION_NOT_BLOCK",
                "bounded repair must link to a prior BLOCK receipt",
            )
        )
    if prior_receipt.get("policy_hashes") != policy_hashes:
        issues.append(
            _issue(
                "REPAIR_POLICY_HASHES_CHANGED",
                "bounded repair replay requires unchanged CAP and gate policies",
            )
        )
    return issues


def _authority_status(
    envelope: Any,
    authority: Any,
    authority_contract_issues: Sequence[ContractIssue],
) -> str:
    if authority is None:
        return "MISSING"
    if not isinstance(authority, dict) or authority_contract_issues:
        return "INVALID"
    if (
        authority.get("state") == "REVOKED"
        or authority.get("revocation_status") == "REVOKED"
    ):
        return "REVOKED"
    if (
        authority.get("state") == "PENDING_REVIEW"
        or authority.get("revocation_status") == "UNKNOWN"
    ):
        return "UNRESOLVED"
    evaluation_as_of = _evaluation_time(envelope)
    issued = parse_utc(authority.get("issued_at"))
    expires = parse_utc(authority.get("expires_at"))
    if (
        evaluation_as_of is None
        or issued is None
        or expires is None
        or not (issued <= evaluation_as_of < expires)
    ):
        return "STALE"
    return "VALID"


def _cap_input_status(
    cap_decision: Any,
    assessment: CapAssessment,
    initial_load_issues: Sequence[ContractIssue],
) -> str:
    if cap_decision is None:
        unreadable = any(
            issue.document == "cap_decision"
            and issue.code != "INPUT_FILE_NOT_SPECIFIED"
            for issue in initial_load_issues
        )
        return "INVALID" if unreadable else "MISSING"
    return "VALID" if assessment.valid else "INVALID"


def _cap_reference(
    cap_decision: Any,
    assessment: CapAssessment,
) -> dict[str, Any] | None:
    if not assessment.valid or not isinstance(cap_decision, dict):
        return None
    return {
        "cap_decision_id": cap_decision["cap_decision_id"],
        "canonical_hash": cap_decision["canonical_hash"],
        "decision": cap_decision["decision"],
        "domain_gates_may_run": cap_decision["domain_gates_may_run"],
        "execution_authority": False,
    }


def _placeholder_result(
    gate_id: str,
    *,
    change_id: str,
    revision: int,
    cap_decision: Any,
    policy: Any,
) -> dict[str, Any]:
    cap_state = (
        cap_decision.get("decision")
        if isinstance(cap_decision, dict)
        else "MISSING_OR_INVALID"
    )
    if gate_id == "path_gate":
        evidence = {
            "evaluation_state": "NOT_EVALUATED",
            "cap_decision": cap_state,
            "candidate_paths_examined": [],
            "authority_rules_examined": [],
            "checks_run": [],
        }
        adapter_version = PATH_ADAPTER_VERSION
        policy_key = "path_gate"
        limitation = (
            "Path jurisdiction was not evaluated because CAP did not pass."
        )
    else:
        evidence = {
            "evaluation_state": "NOT_EVALUATED",
            "cap_decision": cap_state,
            "claims_examined": [],
            "evidence_links_examined": [],
            "checks_run": [],
        }
        adapter_version = CLAIMS_ADAPTER_VERSION
        policy_key = "claims_gate"
        limitation = (
            "Claim and evidence policy was not evaluated because CAP did not pass."
        )
    result = build_gate_result(
        gate_id=gate_id,
        adapter_version=adapter_version,
        policy_version=_policy_version(policy, policy_key),
        policy=policy,
        change_id=change_id,
        revision=revision,
        applicable=True,
        required=True,
        status="NOT_EVALUATED",
        reason_codes=["CAP_NOT_PASSED"],
        evidence=evidence,
        limitations=[limitation],
        repair_actions=[],
    )
    validate_gate_result(result)
    return result


def _gate_results(
    *,
    envelope: Any,
    authority: Any,
    cap_decision: Any,
    cap_assessment: CapAssessment,
    cap_input_status: str,
    path_policy: Any,
    claims_policy: Any,
    gate_order: Sequence[str],
) -> tuple[list[dict[str, Any]], bool]:
    change_id, revision = _fallback_subject(envelope)
    cap_pass = (
        cap_input_status == "VALID"
        and cap_assessment.valid
        and cap_assessment.effective_decision == "PASS"
        and cap_assessment.domain_gates_may_run
    )
    if not cap_pass:
        placeholders = [
            _placeholder_result(
                "claims_gate",
                change_id=change_id,
                revision=revision,
                cap_decision=cap_decision,
                policy=claims_policy,
            ),
            _placeholder_result(
                "path_gate",
                change_id=change_id,
                revision=revision,
                cap_decision=cap_decision,
                policy=path_policy,
            ),
        ]
        return placeholders, False

    adapters = {
        "path_gate": lambda: evaluate_path_gate(
            envelope, authority, path_policy
        ),
        "claims_gate": lambda: evaluate_claims_gate(
            envelope, authority, claims_policy
        ),
    }
    effective_order = (
        tuple(gate_order)
        if len(gate_order) == 2 and set(gate_order) == set(EXPECTED_GATES)
        else EXPECTED_GATES
    )
    results = [adapters[gate_id]() for gate_id in effective_order]
    results = sorted(results, key=lambda item: item["gate_id"])
    for result in results:
        validate_gate_result(result)
    return results, True


def _combined_status(
    *,
    input_status: str,
    authority_status: str,
    cap_input_status: str,
    cap_decision: Any,
    gate_results: Sequence[dict[str, Any]],
    domain_gates_executed: bool,
) -> str:
    """Apply the campaign's exact fail-closed precedence."""

    if input_status != "VALID":
        return "BLOCK"
    if authority_status != "VALID":
        return "BLOCK"
    if cap_input_status != "VALID" or not isinstance(cap_decision, dict):
        return "BLOCK"
    cap_status = cap_decision.get("decision")
    if cap_status == "BLOCK":
        return "BLOCK"
    if cap_status == "HOLD:CONTEXT_UPDATE_REQUIRED":
        return "HOLD"
    if cap_status != "PASS":
        return "BLOCK"
    required = [
        result
        for result in gate_results
        if result.get("required") is True and result.get("applicable") is True
    ]
    statuses = [result.get("status") for result in required]
    if "BLOCK" in statuses:
        return "BLOCK"
    if "HOLD" in statuses:
        return "HOLD"
    if (
        not domain_gates_executed
        or len(required) != 2
        or "NOT_EVALUATED" in statuses
    ):
        return "BLOCK"
    if all(status == "PASS" for status in statuses):
        return "PASS"
    return "BLOCK"


def _next_lawful_move(
    status: str,
    *,
    input_status: str,
    cap_input_status: str,
    cap_decision: Any,
    gate_results: Sequence[dict[str, Any]],
) -> str:
    if input_status != "VALID":
        return (
            "Repair the invalid contract, policy, replay, or lineage input; "
            "then rebuild CAP and evaluate the full sequence."
        )
    if cap_input_status != "VALID":
        return (
            "Supply a valid mechanically derived CAP decision, then evaluate "
            "the full sequence."
        )
    if (
        isinstance(cap_decision, dict)
        and cap_decision.get("decision") != "PASS"
    ):
        return cap_decision["next_lawful_move"]
    if status == "PASS":
        return (
            "Preserve this receipt; any repository mutation still requires "
            "separate execution authority."
        )
    if status == "HOLD":
        return (
            "Resolve the explicit gate evidence hold, then rebuild CAP and "
            "re-evaluate both domain gates."
        )
    repair_actions = sorted(
        {
            action
            for result in gate_results
            for action in result.get("repair_actions", [])
        }
    )
    if repair_actions:
        return " ".join(repair_actions)
    return "Repair the reported failure, rebuild CAP, and re-evaluate both gates."


def _build_combined_decision(
    *,
    change_id: str,
    revision: int,
    input_status: str,
    authority_status: str,
    cap_input_status: str,
    cap_decision: Any,
    cap_assessment: CapAssessment,
    gate_results: Sequence[dict[str, Any]],
    domain_gates_executed: bool,
    failures: Sequence[ContractIssue],
) -> dict[str, Any]:
    cap_ref = _cap_reference(cap_decision, cap_assessment)
    status = _combined_status(
        input_status=input_status,
        authority_status=authority_status,
        cap_input_status=cap_input_status,
        cap_decision=cap_decision if cap_ref is not None else None,
        gate_results=gate_results,
        domain_gates_executed=domain_gates_executed,
    )
    reason_codes = {issue.code for issue in failures}
    for result in gate_results:
        reason_codes.update(result.get("reason_codes", []))
    if cap_ref is not None:
        reason_codes.update(cap_decision.get("reason_codes", []))
    if cap_input_status == "MISSING":
        reason_codes.add("CAP_DECISION_MISSING")
    elif cap_input_status == "INVALID":
        reason_codes.add("CAP_DECISION_INVALID")
    if status == "PASS":
        reason_codes.add("ALL_REQUIRED_GATES_PASS")
    elif status == "HOLD":
        reason_codes.add("EXPLICIT_HOLD_PRESERVED")
    else:
        reason_codes.add("FAIL_CLOSED_BLOCK")

    gate_refs = [
        {
            "gate_id": result["gate_id"],
            "result_id": result["result_id"],
            "result_hash": result["result_hash"],
            "status": result["status"],
            "reason_codes": result["reason_codes"],
            "required": result["required"],
        }
        for result in sorted(gate_results, key=lambda item: item["gate_id"])
    ]
    body = {
        "contract_version": COMBINED_DECISION_VERSION,
        "logic_version": DECISION_LOGIC_VERSION,
        "change_id": change_id,
        "revision": revision,
        "input_status": input_status,
        "authority_status": authority_status,
        "cap_input_status": cap_input_status,
        "cap_decision_ref": cap_ref,
        "domain_gates_executed": domain_gates_executed,
        "required_gates": list(EXPECTED_GATES),
        "gate_result_refs": gate_refs,
        "status": status,
        "reason_codes": sorted(reason_codes),
        "limitations": list(CLAIM_BOUNDARIES),
        "next_lawful_move": _next_lawful_move(
            status,
            input_status=input_status,
            cap_input_status=cap_input_status,
            cap_decision=cap_decision,
            gate_results=gate_results,
        ),
    }
    decision_id = stable_identifier("decision", body)
    decision = {
        **body,
        "decision_id": decision_id,
        "decision_hash": "",
    }
    decision["decision_hash"] = hash_without_fields(
        decision, {"decision_hash"}
    )
    validate_combined_decision(decision)
    return decision


def _valid_prior_for_lineage(
    envelope: Any,
    prior_receipt: Any,
    policy_hashes: dict[str, str],
) -> bool:
    return (
        isinstance(envelope, dict)
        and isinstance(envelope.get("revision"), int)
        and not isinstance(envelope.get("revision"), bool)
        and envelope["revision"] > 1
        and isinstance(prior_receipt, dict)
        and not validate_receipt(prior_receipt, raise_on_error=False)
        and prior_receipt.get("change_id") == envelope.get("change_id")
        and isinstance(prior_receipt.get("revision"), int)
        and prior_receipt["revision"] < envelope["revision"]
        and isinstance(prior_receipt.get("decision"), dict)
        and prior_receipt["decision"].get("status") == "BLOCK"
        and prior_receipt.get("policy_hashes") == policy_hashes
    )


def _repair_lineage(
    *,
    envelope: Any,
    prior_receipt: Any,
    input_hashes: dict[str, str],
    policy_hashes: dict[str, str],
) -> dict[str, Any] | None:
    if not _valid_prior_for_lineage(
        envelope, prior_receipt, policy_hashes
    ):
        return None
    return {
        "relationship": "BOUNDED_REPAIR_OF",
        "prior_receipt_id": prior_receipt["receipt_id"],
        "prior_receipt_hash": prior_receipt["receipt_hash"],
        "prior_revision": prior_receipt["revision"],
        "cap_rechecked": True,
        "changed_input_hashes": {
            "prior_shared_change_envelope": prior_receipt["input_hashes"][
                "shared_change_envelope"
            ],
            "current_shared_change_envelope": input_hashes[
                "shared_change_envelope"
            ],
            "prior_cap_decision": prior_receipt["input_hashes"][
                "cap_decision"
            ],
            "current_cap_decision": input_hashes["cap_decision"],
        },
        "unchanged_policy_hashes": dict(policy_hashes),
    }


def _build_receipt(
    *,
    envelope: Any,
    authority: Any,
    cap_decision: Any,
    cap_policy: Any,
    path_policy: Any,
    claims_policy: Any,
    cap_assessment: CapAssessment,
    cap_input_status: str,
    gate_results: Sequence[dict[str, Any]],
    decision: dict[str, Any],
    prior_receipt: Any,
) -> dict[str, Any]:
    cap_input_hash = canonical_hash_or_fingerprint(cap_decision)
    input_hashes = {
        "shared_change_envelope": canonical_hash_or_fingerprint(envelope),
        "authority_manifest": canonical_hash_or_fingerprint(authority),
        "cap_decision": cap_input_hash,
        "cap_policy": _policy_hash(cap_policy),
    }
    policy_hashes = {
        "cap_policy": _policy_hash(cap_policy),
        "claims_gate": _policy_hash(claims_policy),
        "path_gate": _policy_hash(path_policy),
    }
    cap_ref = _cap_reference(cap_decision, cap_assessment)
    lineage = _repair_lineage(
        envelope=envelope,
        prior_receipt=prior_receipt,
        input_hashes=input_hashes,
        policy_hashes=policy_hashes,
    )
    limitations = sorted(
        {
            *CLAIM_BOUNDARIES,
            *(
                limitation
                for result in gate_results
                for limitation in result.get("limitations", [])
            ),
            *(
                cap_decision.get("limitations", [])
                if isinstance(cap_decision, dict) and cap_ref is not None
                else []
            ),
        }
    )
    repair_summary = (
        envelope.get("repair_summary")
        if lineage is not None and isinstance(envelope, dict)
        else None
    )
    body = {
        "contract_version": RECEIPT_VERSION,
        "change_id": decision["change_id"],
        "revision": decision["revision"],
        "decision": decision,
        "cap_decision": (
            cap_decision
            if cap_input_status == "VALID" and cap_ref is not None
            else None
        ),
        "cap_record": {
            "input_status": cap_input_status,
            "input_hash": cap_input_hash,
            "decision_ref": cap_ref,
            "domain_gates_executed": decision["domain_gates_executed"],
            "execution_authority": False,
        },
        "input_hashes": input_hashes,
        "policy_hashes": policy_hashes,
        "gate_results": list(
            sorted(gate_results, key=lambda item: item["gate_id"])
        ),
        "limitations": limitations,
        "claim_boundaries": list(CLAIM_BOUNDARIES),
        "next_lawful_move": decision["next_lawful_move"],
        "repair_summary": repair_summary,
        "repair_lineage": lineage,
    }
    receipt_id = stable_identifier("receipt", body)
    receipt = {
        **body,
        "receipt_id": receipt_id,
        "receipt_hash": "",
    }
    receipt["receipt_hash"] = hash_without_fields(
        receipt, {"receipt_hash"}
    )
    validate_receipt(receipt)
    return receipt


def evaluate_bundle(
    envelope: Any,
    authority: Any,
    cap_decision: Any,
    cap_policy: Any,
    path_policy: Any,
    claims_policy: Any,
    *,
    prior_receipt: Any = None,
    gate_order: Iterable[str] = ("path_gate", "claims_gate"),
    load_issues: Iterable[ContractIssue] = (),
) -> EvaluationOutcome:
    """Evaluate one candidate snapshot without executing repository writes."""

    change_id, revision = _fallback_subject(envelope)
    initial_load_issues = list(load_issues)
    envelope_issues = validate_envelope(envelope, raise_on_error=False)
    authority_issues = validate_authority(authority, raise_on_error=False)
    evaluation_as_of = _evaluation_time(envelope)
    policy_issues, _ = _policy_issues(
        cap_policy,
        path_policy,
        claims_policy,
        evaluation_as_of,
    )
    policy_hashes = {
        "cap_policy": _policy_hash(cap_policy),
        "claims_gate": _policy_hash(claims_policy),
        "path_gate": _policy_hash(path_policy),
    }
    base_failures: list[ContractIssue] = [
        *initial_load_issues,
        *envelope_issues,
        *authority_issues,
        *policy_issues,
        *_policy_binding_issues(
            envelope,
            authority,
            cap_policy,
            path_policy,
            claims_policy,
        ),
        *_prior_receipt_issues(envelope, prior_receipt, policy_hashes),
    ]

    requested_order = tuple(gate_order)
    if (
        len(requested_order) != 2
        or set(requested_order) != set(EXPECTED_GATES)
    ):
        base_failures.append(
            _issue(
                "GATE_ORDER_INVALID",
                "gate order must contain claims_gate and path_gate exactly once",
            )
        )

    cap_assessment = assess_cap_decision(
        cap_decision,
        envelope,
        authority,
        cap_policy,
        path_policy,
        claims_policy,
    )
    cap_input_status = _cap_input_status(
        cap_decision, cap_assessment, initial_load_issues
    )
    all_failures = _dedupe_issues(
        [*base_failures, *cap_assessment.issues]
    )
    authority_status = _authority_status(
        envelope, authority, authority_issues
    )

    gate_results, domain_gates_executed = _gate_results(
        envelope=envelope,
        authority=authority,
        cap_decision=cap_decision,
        cap_assessment=cap_assessment,
        cap_input_status=cap_input_status,
        path_policy=path_policy,
        claims_policy=claims_policy,
        gate_order=requested_order,
    )
    input_status = "VALID" if not base_failures else "INVALID"
    decision = _build_combined_decision(
        change_id=change_id,
        revision=revision,
        input_status=input_status,
        authority_status=authority_status,
        cap_input_status=cap_input_status,
        cap_decision=cap_decision,
        cap_assessment=cap_assessment,
        gate_results=gate_results,
        domain_gates_executed=domain_gates_executed,
        failures=all_failures,
    )
    receipt = _build_receipt(
        envelope=envelope,
        authority=authority,
        cap_decision=cap_decision,
        cap_policy=cap_policy,
        path_policy=path_policy,
        claims_policy=claims_policy,
        cap_assessment=cap_assessment,
        cap_input_status=cap_input_status,
        gate_results=gate_results,
        decision=decision,
        prior_receipt=prior_receipt,
    )
    return EvaluationOutcome(
        cap_decision,
        tuple(gate_results),
        decision,
        receipt,
    )
