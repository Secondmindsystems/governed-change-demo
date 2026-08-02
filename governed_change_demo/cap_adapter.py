"""Mechanical CAP decision adapter for the declared candidate snapshot.

The CAP decision is a pre-domain jurisdiction result. It may permit the Path
Gate and Claims Gate to evaluate a change; it never authorizes repository
execution.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

from .canonical import (
    canonical_hash,
    canonical_hash_or_fingerprint,
    hash_without_fields,
    stable_identifier,
)
from .contracts import (
    CAP_VERSION,
    KNOWN_POLICY_VERSIONS,
    ContractIssue,
    parse_utc,
    validate_authority,
    validate_cap_decision,
    validate_envelope,
)
from .policies import (
    CAP_CHECK_ORDER,
    REQUIRED_DOMAIN_GATES,
    assess_cap_policy,
    assess_claims_policy,
    assess_path_policy,
    policy_content_hash,
)


CAP_STAGE_ID = "cap_decision"
CAP_EVALUATOR_VERSION = "governed-repo.cap-adapter/v1.0.0"
DOMAIN_GATE_IDS = REQUIRED_DOMAIN_GATES

_DRIVE_PATH = re.compile(r"^[A-Za-z]:")
_URI_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_CASE_MODES = {"SENSITIVE", "INSENSITIVE"}


@dataclass(frozen=True)
class CapAssessment:
    """Result of validating and independently re-deriving a CAP decision."""

    issues: tuple[ContractIssue, ...]
    effective_outcome: str
    domain_gates_may_run: bool

    @property
    def effective_decision(self) -> str:
        return self.effective_outcome

    @property
    def valid(self) -> bool:
        return not self.issues


def _issue(code: str, pointer: str, message: str) -> ContractIssue:
    return ContractIssue("cap_decision", code, pointer, message)


def _check(
    check_id: str,
    status: str,
    reason_codes: list[str],
    evidence_refs: list[str],
) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "status": status,
        "reason_codes": sorted(set(reason_codes)),
        "evidence_refs": sorted(set(evidence_refs)),
    }


def _normalize_repo_path(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    if any(
        ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        for character in value
    ):
        return None
    normalized = value.replace("\\", "/")
    if (
        normalized.startswith("//")
        or normalized.startswith("/")
        or _DRIVE_PATH.match(normalized)
        or _URI_SCHEME.match(normalized)
    ):
        return None
    parts: list[str] = []
    for part in normalized.split("/"):
        if part == ".":
            continue
        if not part or part == "..":
            return None
        parts.append(part)
    if not parts:
        return None
    return "/".join(parts)


def _fold(value: str, case_mode: str) -> str | None:
    if case_mode == "SENSITIVE":
        return value
    if case_mode == "INSENSITIVE":
        return value.casefold()
    return None


def _is_within(path: str, root: str, case_mode: str) -> bool:
    candidate = _fold(path, case_mode)
    boundary = _fold(root, case_mode)
    if candidate is None or boundary is None:
        return False
    return candidate == boundary or candidate.startswith(boundary + "/")


def _rule_matches(
    path: str,
    operation: str,
    rule: dict[str, Any],
    case_mode: str,
) -> bool:
    root = _normalize_repo_path(rule.get("path"))
    if root is None or operation not in rule.get("actions", []):
        return False
    if rule.get("match") == "EXACT":
        candidate = _fold(path, case_mode)
        boundary = _fold(root, case_mode)
        return (
            candidate is not None
            and boundary is not None
            and candidate == boundary
        )
    if rule.get("match") == "SUBTREE":
        return _is_within(path, root, case_mode)
    return False


def _policy_reference(
    policy: Any, policy_key: str
) -> dict[str, str]:
    if not isinstance(policy, dict):
        return {
            "policy_id": f"invalid-{policy_key}-policy",
            "policy_version": "UNKNOWN",
            "policy_hash": canonical_hash_or_fingerprint(policy),
        }
    policy_id = policy.get("policy_id")
    if not isinstance(policy_id, str) or not policy_id:
        policy_id = f"invalid-{policy_key}-policy"
    policy_version = policy.get("policy_version")
    if not isinstance(policy_version, str) or not policy_version:
        policy_version = "UNKNOWN"
    try:
        policy_hash = policy_content_hash(policy)
    except (TypeError, ValueError, UnicodeError):
        policy_hash = canonical_hash_or_fingerprint(policy)
    return {
        "policy_id": policy_id,
        "policy_version": policy_version,
        "policy_hash": policy_hash,
    }


def _evidence_basis(envelope: dict[str, Any]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for item in envelope["evidence"]:
        body = {
            "availability": item["availability"],
            "evidence_id": item["evidence_id"],
            "evidence_class": item["evidence_class"],
            "evidence_state": item["evidence_state"],
            "source_ref": item["source_ref"],
            "summary": item["summary"],
        }
        records.append(
            {
                **body,
                "evidence_hash": canonical_hash(body),
            }
        )
    return sorted(records, key=lambda item: item["evidence_id"])


def _policy_integrity_reasons(
    *,
    envelope: dict[str, Any],
    authority: dict[str, Any],
    cap_policy: Any,
    path_policy: Any,
    claims_policy: Any,
    evaluation_as_of: Any,
) -> list[str]:
    assessments = {
        "cap_policy": assess_cap_policy(cap_policy, evaluation_as_of),
        "path_gate": assess_path_policy(path_policy, evaluation_as_of),
        "claims_gate": assess_claims_policy(
            claims_policy, evaluation_as_of
        ),
    }
    policies = {
        "cap_policy": cap_policy,
        "path_gate": path_policy,
        "claims_gate": claims_policy,
    }
    reasons: list[str] = []
    for policy_key in ("cap_policy", "claims_gate", "path_gate"):
        assessment = assessments[policy_key]
        if assessment.issues:
            reasons.append(f"CAP_{policy_key.upper()}_INTEGRITY_INVALID")
        if assessment.stale:
            reasons.append(f"CAP_{policy_key.upper()}_OUTSIDE_TIME_WINDOW")
        policy = policies[policy_key]
        try:
            expected_hash = policy_content_hash(policy)
        except (TypeError, ValueError, UnicodeError):
            expected_hash = None
        if expected_hash is None:
            continue
        if envelope["policy_hashes"].get(policy_key) != expected_hash:
            reasons.append(
                f"CAP_{policy_key.upper()}_ENVELOPE_HASH_MISMATCH"
            )
        if authority["policy_hashes"].get(policy_key) != expected_hash:
            reasons.append(
                f"CAP_{policy_key.upper()}_AUTHORITY_HASH_MISMATCH"
            )
    return sorted(set(reasons))


def _version_reasons(
    *,
    envelope: dict[str, Any],
    authority: dict[str, Any],
    cap_policy: Any,
    path_policy: Any,
    claims_policy: Any,
) -> list[str]:
    policies = {
        "cap_policy": cap_policy,
        "path_gate": path_policy,
        "claims_gate": claims_policy,
    }
    reasons: list[str] = []
    for policy_key in ("cap_policy", "claims_gate", "path_gate"):
        expected = KNOWN_POLICY_VERSIONS[policy_key]
        policy = policies[policy_key]
        observed = (
            policy.get("policy_version")
            if isinstance(policy, dict)
            else None
        )
        if observed != expected:
            reasons.append(f"CAP_{policy_key.upper()}_VERSION_UNKNOWN")
        if envelope["policy_versions"].get(policy_key) != expected:
            reasons.append(
                f"CAP_{policy_key.upper()}_ENVELOPE_VERSION_UNKNOWN"
            )
        if authority["policy_versions"].get(policy_key) != expected:
            reasons.append(
                f"CAP_{policy_key.upper()}_AUTHORITY_VERSION_UNKNOWN"
            )
        if (
            envelope["policy_versions"].get(policy_key)
            != authority["policy_versions"].get(policy_key)
        ):
            reasons.append(
                f"CAP_{policy_key.upper()}_VERSION_BINDING_MISMATCH"
            )
    return sorted(set(reasons))


def build_cap_decision(
    envelope: dict[str, Any],
    authority: dict[str, Any],
    cap_policy: Any,
    path_policy: Any,
    claims_policy: Any,
) -> dict[str, Any]:
    """Build a deterministic CAP decision from explicit governed inputs."""

    validate_envelope(envelope)
    validate_authority(authority)

    evaluation_as_of = parse_utc(envelope["evaluation_as_of"])
    envelope_hash = canonical_hash(envelope)
    authority_hash = canonical_hash(authority)
    policy_basis = {
        "cap_policy": _policy_reference(cap_policy, "cap_policy"),
        "claims_gate": _policy_reference(claims_policy, "claims_gate"),
        "path_gate": _policy_reference(path_policy, "path_gate"),
    }
    evidence_basis = _evidence_basis(envelope)
    source_refs = ["authority_manifest", "shared_change_envelope"]
    case_mode = (
        path_policy.get("case_mode")
        if isinstance(path_policy, dict)
        else None
    )
    effective_case_mode = (
        case_mode if case_mode in _CASE_MODES else "SENSITIVE"
    )

    if envelope["source_basis"] != authority["required_source_basis"]:
        source_check = _check(
            "SOURCE_BASIS",
            "HOLD:CONTEXT_UPDATE_REQUIRED",
            ["CAP_SOURCE_BASIS_STALE"],
            source_refs,
        )
    else:
        source_check = _check(
            "SOURCE_BASIS",
            "PASS",
            ["CAP_SOURCE_BASIS_CURRENT"],
            source_refs,
        )

    scope_reasons: list[str] = []
    if envelope["authority_ref"] != authority["manifest_id"]:
        scope_reasons.append("CAP_AUTHORITY_REFERENCE_MISMATCH")
    if envelope["actor"]["actor_id"] not in authority["subject_actor_ids"]:
        scope_reasons.append("CAP_ACTOR_NOT_AUTHORIZED")
    if envelope["task"]["task_id"] not in authority["permitted_task_ids"]:
        scope_reasons.append("CAP_TASK_SCOPE_EXCEEDED")
    for change in envelope["changes"]:
        operation = change["operation"]
        if operation not in authority["permitted_actions"]:
            scope_reasons.append("CAP_REQUESTED_ACTION_NOT_PERMITTED")
        endpoints = [change["path"]]
        if change["destination_path"] is not None:
            endpoints.append(change["destination_path"])
        for endpoint in endpoints:
            normalized = _normalize_repo_path(endpoint)
            if normalized is None:
                scope_reasons.append("CAP_REQUESTED_PATH_INVALID")
            elif not any(
                _rule_matches(
                    normalized,
                    operation,
                    rule,
                    effective_case_mode,
                )
                for rule in authority["permitted_paths"]
            ):
                scope_reasons.append("CAP_REQUESTED_PATH_OUTSIDE_SCOPE")
    authority_scope = (
        _check(
            "AUTHORITY_SCOPE",
            "BLOCK",
            scope_reasons,
            source_refs,
        )
        if scope_reasons
        else _check(
            "AUTHORITY_SCOPE",
            "PASS",
            ["CAP_AUTHORITY_SCOPE_VALID"],
            source_refs,
        )
    )

    issued_at = parse_utc(authority["issued_at"])
    expires_at = parse_utc(authority["expires_at"])
    if (
        evaluation_as_of is None
        or issued_at is None
        or expires_at is None
        or not (issued_at <= evaluation_as_of < expires_at)
    ):
        authority_time = _check(
            "AUTHORITY_TIME",
            "BLOCK",
            ["CAP_AUTHORITY_TIME_INVALID"],
            source_refs,
        )
    else:
        authority_time = _check(
            "AUTHORITY_TIME",
            "PASS",
            ["CAP_AUTHORITY_TIME_VALID"],
            source_refs,
        )

    revocation = authority["revocation_status"]
    if revocation == "NOT_REVOKED" and authority["state"] == "ACTIVE":
        authority_revocation = _check(
            "AUTHORITY_REVOCATION",
            "PASS",
            ["CAP_AUTHORITY_NOT_REVOKED"],
            ["authority_manifest"],
        )
    else:
        reason = (
            "CAP_AUTHORITY_REVOKED"
            if revocation == "REVOKED"
            else "CAP_AUTHORITY_REVOCATION_UNKNOWN"
        )
        authority_revocation = _check(
            "AUTHORITY_REVOCATION",
            "BLOCK",
            [reason],
            ["authority_manifest"],
        )

    evidence_ids = {item["evidence_id"] for item in envelope["evidence"]}
    refreshable_unavailable_ids = sorted(
        item["evidence_id"]
        for item in envelope["evidence"]
        if item["availability"] == "REFRESHABLE_UNAVAILABLE"
    )
    missing_evidence = not evidence_ids
    for change in envelope["changes"]:
        for claim in change["claims"]:
            refs = claim["evidence_refs"]
            if not refs or not set(refs).issubset(evidence_ids):
                missing_evidence = True
    if missing_evidence:
        evidence_presence = _check(
            "EVIDENCE_PRESENCE",
            "BLOCK",
            ["CAP_REQUIRED_EVIDENCE_MISSING"],
            sorted(evidence_ids) or ["shared_change_envelope"],
        )
    elif refreshable_unavailable_ids:
        evidence_presence = _check(
            "EVIDENCE_PRESENCE",
            "HOLD:CONTEXT_UPDATE_REQUIRED",
            ["CAP_REFRESHABLE_EVIDENCE_UNAVAILABLE"],
            refreshable_unavailable_ids,
        )
    else:
        evidence_presence = _check(
            "EVIDENCE_PRESENCE",
            "PASS",
            ["CAP_REQUIRED_EVIDENCE_PRESENT"],
            sorted(evidence_ids),
        )

    declared_gates = {
        item["gate_id"]: item["required"]
        for item in authority["applicable_gates"]
    }
    policy_gates = (
        cap_policy.get("required_domain_gates")
        if isinstance(cap_policy, dict)
        else None
    )
    if (
        declared_gates != {"claims_gate": True, "path_gate": True}
        or policy_gates != list(REQUIRED_DOMAIN_GATES)
    ):
        gate_applicability = _check(
            "GATE_APPLICABILITY",
            "BLOCK",
            ["CAP_REQUIRED_GATE_SET_UNDERDECLARED"],
            ["authority_manifest", policy_basis["cap_policy"]["policy_id"]],
        )
    else:
        gate_applicability = _check(
            "GATE_APPLICABILITY",
            "PASS",
            ["CAP_REQUIRED_GATE_SET_COMPLETE"],
            ["authority_manifest", policy_basis["cap_policy"]["policy_id"]],
        )

    normalized_no_touch: list[str] = []
    invalid_no_touch = False
    for raw_path in authority["no_touch_paths"]:
        normalized = _normalize_repo_path(raw_path)
        if normalized is None:
            invalid_no_touch = True
        else:
            normalized_no_touch.append(normalized)
    no_touch_reasons: list[str] = []
    if invalid_no_touch:
        no_touch_reasons.append("CAP_NO_TOUCH_DECLARATION_INVALID")
    for change in envelope["changes"]:
        endpoints = [change["path"]]
        if change["destination_path"] is not None:
            endpoints.append(change["destination_path"])
        for endpoint in endpoints:
            normalized = _normalize_repo_path(endpoint)
            if normalized is None:
                no_touch_reasons.append("CAP_REQUESTED_PATH_INVALID")
            elif any(
                _is_within(
                    normalized,
                    root,
                    effective_case_mode,
                )
                for root in normalized_no_touch
            ):
                no_touch_reasons.append("CAP_NO_TOUCH_PATH_REQUESTED")
    no_touch = (
        _check(
            "NO_TOUCH",
            "BLOCK",
            no_touch_reasons,
            source_refs,
        )
        if no_touch_reasons
        else _check(
            "NO_TOUCH",
            "PASS",
            ["CAP_NO_TOUCH_CLEAR"],
            source_refs,
        )
    )

    integrity_reasons = _policy_integrity_reasons(
        envelope=envelope,
        authority=authority,
        cap_policy=cap_policy,
        path_policy=path_policy,
        claims_policy=claims_policy,
        evaluation_as_of=evaluation_as_of,
    )
    policy_integrity = (
        _check(
            "POLICY_INTEGRITY",
            "BLOCK",
            integrity_reasons,
            sorted(
                reference["policy_id"]
                for reference in policy_basis.values()
            ),
        )
        if integrity_reasons
        else _check(
            "POLICY_INTEGRITY",
            "PASS",
            ["CAP_POLICY_INTEGRITY_VALID"],
            sorted(
                reference["policy_id"]
                for reference in policy_basis.values()
            ),
        )
    )

    version_reasons = _version_reasons(
        envelope=envelope,
        authority=authority,
        cap_policy=cap_policy,
        path_policy=path_policy,
        claims_policy=claims_policy,
    )
    version_recognition = (
        _check(
            "VERSION_RECOGNITION",
            "BLOCK",
            version_reasons,
            sorted(
                reference["policy_id"]
                for reference in policy_basis.values()
            ),
        )
        if version_reasons
        else _check(
            "VERSION_RECOGNITION",
            "PASS",
            ["CAP_POLICY_VERSIONS_RECOGNIZED"],
            sorted(
                reference["policy_id"]
                for reference in policy_basis.values()
            ),
        )
    )

    checks_by_id = {
        item["check_id"]: item
        for item in (
            authority_revocation,
            authority_scope,
            authority_time,
            evidence_presence,
            gate_applicability,
            no_touch,
            policy_integrity,
            source_check,
            version_recognition,
        )
    }
    checks = [checks_by_id[check_id] for check_id in CAP_CHECK_ORDER]
    statuses = [item["status"] for item in checks]
    if "BLOCK" in statuses:
        decision_value = "BLOCK"
    elif "HOLD:CONTEXT_UPDATE_REQUIRED" in statuses:
        decision_value = "HOLD:CONTEXT_UPDATE_REQUIRED"
    else:
        decision_value = "PASS"
    next_moves = {
        "PASS": (
            "Run the required Path Gate and Claims Gate; do not execute "
            "repository writes."
        ),
        "BLOCK": (
            "Repair the blocked CAP input within declared authority, then "
            "re-evaluate all CAP checks."
        ),
        "HOLD:CONTEXT_UPDATE_REQUIRED": (
            "Refresh every stale source-basis or explicitly unavailable "
            "refreshable evidence input, then re-evaluate CAP."
        ),
    }
    body: dict[str, Any] = {
        "contract_version": CAP_VERSION,
        "cap_contract_version": CAP_VERSION,
        "packet_type": "CAP_DECISION",
        "stage_id": CAP_STAGE_ID,
        "evaluator_version": CAP_EVALUATOR_VERSION,
        "cap_policy_version": policy_basis["cap_policy"]["policy_version"],
        "change_id": envelope["change_id"],
        "revision": envelope["revision"],
        "shared_change_envelope_hash": envelope_hash,
        "source_basis": envelope["source_basis"],
        "authority_manifest_reference": {
            "manifest_id": authority["manifest_id"],
            "manifest_hash": authority_hash,
            "required_source_basis": authority["required_source_basis"],
        },
        "evaluation_as_of": envelope["evaluation_as_of"],
        "policy_basis": policy_basis,
        "checks": checks,
        "evidence_basis": evidence_basis,
        "decision": decision_value,
        "reason_codes": sorted(
            {
                code
                for check in checks
                for code in check["reason_codes"]
            }
        ),
        "failed_checks": sorted(
            check["check_id"]
            for check in checks
            if check["status"] != "PASS"
        ),
        "limitations": sorted(
            [
                (
                    "This decision evaluates only the declared product-local "
                    "candidate snapshot."
                ),
                (
                    "This decision permits domain-gate evaluation only; it "
                    "never authorizes repository execution."
                ),
            ]
        ),
        "next_lawful_move": next_moves[decision_value],
        "domain_gate_ids": list(DOMAIN_GATE_IDS),
        "domain_gates_may_run": decision_value == "PASS",
        "execution_authority": False,
    }
    decision = dict(body)
    decision["cap_decision_id"] = stable_identifier("cap", body)
    decision["canonical_hash"] = hash_without_fields(
        decision, {"canonical_hash"}
    )
    validate_cap_decision(decision)
    return decision


def domain_gates_may_run(cap_decision: Any) -> bool:
    """Return whether a valid CAP decision intrinsically permits gate runs."""

    return (
        isinstance(cap_decision, dict)
        and not validate_cap_decision(
            cap_decision, raise_on_error=False
        )
        and cap_decision.get("decision") == "PASS"
        and cap_decision.get("domain_gates_may_run") is True
        and cap_decision.get("execution_authority") is False
    )


def assess_cap_decision(
    cap_decision: Any,
    envelope: Any,
    authority: Any,
    cap_policy: Any,
    path_policy: Any,
    claims_policy: Any,
) -> CapAssessment:
    """Validate, cross-bind, and semantically re-derive an explicit CAP."""

    issues = list(
        validate_cap_decision(cap_decision, raise_on_error=False)
    )
    envelope_issues = validate_envelope(
        envelope, raise_on_error=False
    )
    authority_issues = validate_authority(
        authority, raise_on_error=False
    )
    issues.extend(envelope_issues)
    issues.extend(authority_issues)
    if (
        envelope_issues
        or authority_issues
        or not isinstance(cap_decision, dict)
    ):
        return CapAssessment(tuple(issues), "BLOCK", False)
    try:
        expected = build_cap_decision(
            envelope,
            authority,
            cap_policy,
            path_policy,
            claims_policy,
        )
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        issues.append(
            _issue(
                "CAP_REDERIVATION_FAILED",
                "",
                (
                    "could not independently derive the CAP decision: "
                    f"{type(exc).__name__}"
                ),
            )
        )
        return CapAssessment(tuple(issues), "BLOCK", False)
    for field in sorted(
        set(expected) - {"cap_decision_id", "canonical_hash"}
    ):
        if cap_decision.get(field) != expected[field]:
            issues.append(
                _issue(
                    "CAP_SEMANTIC_REDERIVATION_MISMATCH",
                    f"/{field}",
                    (
                        "provided value does not match the independently "
                        "derived value"
                    ),
                )
            )
    if issues:
        return CapAssessment(tuple(issues), "BLOCK", False)
    effective = expected["decision"]
    return CapAssessment(
        tuple(),
        effective,
        effective == "PASS" and domain_gates_may_run(cap_decision),
    )
