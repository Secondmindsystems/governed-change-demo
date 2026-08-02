"""Versioned public-safe policy loading and integrity validation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .canonical import canonical_hash
from .contracts import ContractIssue, HASH_RE, KNOWN_POLICY_VERSIONS, parse_utc


CAP_POLICY_CONTRACT = "governed-repo.cap-policy/v1"
PATH_POLICY_CONTRACT = "governed-repo.path-policy/v1"
CLAIMS_POLICY_CONTRACT = "governed-repo.claims-policy/v1"

CAP_CHECK_ORDER = (
    "AUTHORITY_REVOCATION",
    "AUTHORITY_SCOPE",
    "AUTHORITY_TIME",
    "EVIDENCE_PRESENCE",
    "GATE_APPLICABILITY",
    "NO_TOUCH",
    "POLICY_INTEGRITY",
    "SOURCE_BASIS",
    "VERSION_RECOGNITION",
)
REQUIRED_DOMAIN_GATES = ("claims_gate", "path_gate")
CAP_DECISION_PRECEDENCE = (
    "BLOCK",
    "HOLD:CONTEXT_UPDATE_REQUIRED",
    "PASS",
)
CAP_MECHANICAL_RULES = {
    "authority_revocation_unknown": "BLOCK",
    "authority_revoked": "BLOCK",
    "authority_scope_failure": "BLOCK",
    "authority_time_failure": "BLOCK",
    "gate_set_underdeclared": "BLOCK",
    "missing_evidence": "BLOCK",
    "no_touch_violation": "BLOCK",
    "policy_integrity_failure": "BLOCK",
    "refreshable_evidence_unavailable": "HOLD:CONTEXT_UPDATE_REQUIRED",
    "source_basis_mismatch": "HOLD:CONTEXT_UPDATE_REQUIRED",
    "unknown_policy_version": "BLOCK",
}


@dataclass(frozen=True)
class PolicyAssessment:
    issues: tuple[ContractIssue, ...]
    stale: bool

    @property
    def valid(self) -> bool:
        return not self.issues and not self.stale


def policy_content_hash(value: Any) -> str:
    """Hash a policy's canonical content while excluding its self hash."""

    if not isinstance(value, dict):
        raise TypeError("policy must be an object")
    return canonical_hash(
        {key: child for key, child in value.items() if key != "policy_hash"}
    )


def _issue(
    issues: list[ContractIssue],
    document: str,
    code: str,
    pointer: str,
    message: str,
) -> None:
    issues.append(ContractIssue(document, code, pointer, message))


def _strict_object(
    value: Any,
    *,
    document: str,
    required: set[str],
    issues: list[ContractIssue],
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        _issue(issues, document, "TYPE_OBJECT_REQUIRED", "", "policy must be an object")
        return None
    for key in sorted(required - value.keys()):
        _issue(
            issues,
            document,
            "REQUIRED_FIELD_MISSING",
            f"/{key}",
            "required field is missing",
        )
    for key in sorted(value.keys() - required):
        _issue(
            issues,
            document,
            "UNKNOWN_FIELD",
            f"/{key}",
            "additional properties are not allowed",
        )
    return value


def _nonempty_string(
    value: Any,
    document: str,
    pointer: str,
    issues: list[ContractIssue],
) -> str | None:
    if not isinstance(value, str) or not value:
        _issue(
            issues,
            document,
            "TYPE_STRING_REQUIRED",
            pointer,
            "expected non-empty string",
        )
        return None
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        _issue(
            issues,
            document,
            "UNICODE_SCALAR_INVALID",
            pointer,
            "string contains an invalid Unicode surrogate",
        )
        return None
    return value


def _string_list(
    value: Any,
    document: str,
    pointer: str,
    issues: list[ContractIssue],
    *,
    minimum: int = 0,
) -> list[str]:
    if not isinstance(value, list):
        _issue(issues, document, "TYPE_ARRAY_REQUIRED", pointer, "expected an array")
        return []
    if len(value) < minimum:
        _issue(
            issues,
            document,
            "ARRAY_TOO_SHORT",
            pointer,
            f"minimum length is {minimum}",
        )
    result: list[str] = []
    for index, item in enumerate(value):
        parsed = _nonempty_string(item, document, f"{pointer}/{index}", issues)
        if parsed is not None:
            result.append(parsed)
    if len(result) != len(set(result)):
        _issue(
            issues,
            document,
            "ARRAY_ITEMS_NOT_UNIQUE",
            pointer,
            "items must be unique",
        )
    return result


def _time_window(
    obj: dict[str, Any],
    document: str,
    evaluation_as_of: datetime | None,
    issues: list[ContractIssue],
) -> bool:
    starts = parse_utc(obj.get("effective_from"))
    expires = parse_utc(obj.get("expires_at"))
    if starts is None:
        _issue(
            issues,
            document,
            "UTC_TIMESTAMP_INVALID",
            "/effective_from",
            "invalid effective_from",
        )
    if expires is None:
        _issue(
            issues,
            document,
            "UTC_TIMESTAMP_INVALID",
            "/expires_at",
            "invalid expires_at",
        )
    if starts and expires and expires <= starts:
        _issue(
            issues,
            document,
            "POLICY_TIME_RANGE_INVALID",
            "/expires_at",
            "expiry must follow effective time",
        )
    return bool(
        evaluation_as_of
        and starts
        and expires
        and not (starts <= evaluation_as_of < expires)
    )


def _validate_identity_and_integrity(
    obj: dict[str, Any],
    *,
    document: str,
    contract_version: str,
    policy_key: str,
    issues: list[ContractIssue],
) -> None:
    if obj.get("contract_version") != contract_version:
        _issue(
            issues,
            document,
            "POLICY_CONTRACT_VERSION_UNKNOWN",
            "/contract_version",
            f"expected {contract_version}",
        )
    _nonempty_string(obj.get("policy_id"), document, "/policy_id", issues)
    if obj.get("policy_version") != KNOWN_POLICY_VERSIONS[policy_key]:
        _issue(
            issues,
            document,
            "UNKNOWN_POLICY_VERSION",
            "/policy_version",
            f"expected {KNOWN_POLICY_VERSIONS[policy_key]}",
        )
    embedded = obj.get("policy_hash")
    if not isinstance(embedded, str) or not HASH_RE.fullmatch(embedded):
        _issue(
            issues,
            document,
            "POLICY_HASH_FORMAT_INVALID",
            "/policy_hash",
            "expected sha256:<64 lowercase hex characters>",
        )
        return
    try:
        expected = policy_content_hash(obj)
    except (TypeError, ValueError, UnicodeError):
        _issue(
            issues,
            document,
            "POLICY_HASH_DERIVATION_UNAVAILABLE",
            "/policy_hash",
            "malformed policy content cannot be hashed",
        )
    else:
        if embedded != expected:
            _issue(
                issues,
                document,
                "POLICY_HASH_MISMATCH",
                "/policy_hash",
                "embedded policy hash does not match canonical policy content",
            )


def assess_cap_policy(
    value: Any, evaluation_as_of: datetime | None
) -> PolicyAssessment:
    document = "cap_policy"
    issues: list[ContractIssue] = []
    required = {
        "contract_version",
        "policy_id",
        "policy_version",
        "policy_hash",
        "effective_from",
        "expires_at",
        "check_order",
        "required_domain_gates",
        "decision_precedence",
        "mechanical_rules",
    }
    obj = _strict_object(value, document=document, required=required, issues=issues)
    if obj is None:
        return PolicyAssessment(tuple(issues), stale=False)
    _validate_identity_and_integrity(
        obj,
        document=document,
        contract_version=CAP_POLICY_CONTRACT,
        policy_key="cap_policy",
        issues=issues,
    )
    checks = _string_list(
        obj.get("check_order"),
        document,
        "/check_order",
        issues,
        minimum=len(CAP_CHECK_ORDER),
    )
    if checks != list(CAP_CHECK_ORDER):
        _issue(
            issues,
            document,
            "CAP_POLICY_CHECK_ORDER_INVALID",
            "/check_order",
            "CAP checks must be the closed canonical set in canonical order",
        )
    gates = _string_list(
        obj.get("required_domain_gates"),
        document,
        "/required_domain_gates",
        issues,
        minimum=len(REQUIRED_DOMAIN_GATES),
    )
    if gates != list(REQUIRED_DOMAIN_GATES):
        _issue(
            issues,
            document,
            "CAP_POLICY_GATE_SET_INVALID",
            "/required_domain_gates",
            "claims_gate and path_gate must be required in canonical order",
        )
    precedence = _string_list(
        obj.get("decision_precedence"),
        document,
        "/decision_precedence",
        issues,
        minimum=len(CAP_DECISION_PRECEDENCE),
    )
    if precedence != list(CAP_DECISION_PRECEDENCE):
        _issue(
            issues,
            document,
            "CAP_POLICY_PRECEDENCE_INVALID",
            "/decision_precedence",
            "decision precedence must be BLOCK, HOLD, PASS",
        )
    rules = obj.get("mechanical_rules")
    if not isinstance(rules, dict) or rules != CAP_MECHANICAL_RULES:
        _issue(
            issues,
            document,
            "CAP_POLICY_RULE_SET_INVALID",
            "/mechanical_rules",
            "mechanical rules must equal the closed public-safe rule set",
        )
    stale = _time_window(obj, document, evaluation_as_of, issues)
    return PolicyAssessment(tuple(issues), stale=stale)


def assess_path_policy(
    value: Any, evaluation_as_of: datetime | None
) -> PolicyAssessment:
    document = "path_policy"
    issues: list[ContractIssue] = []
    required = {
        "contract_version",
        "policy_id",
        "policy_version",
        "policy_hash",
        "effective_from",
        "expires_at",
        "case_mode",
        "path_form",
        "rename_semantics",
        "protected_rules",
        "self_protected_paths",
    }
    obj = _strict_object(value, document=document, required=required, issues=issues)
    if obj is None:
        return PolicyAssessment(tuple(issues), stale=False)
    _validate_identity_and_integrity(
        obj,
        document=document,
        contract_version=PATH_POLICY_CONTRACT,
        policy_key="path_gate",
        issues=issues,
    )
    if obj.get("case_mode") not in {"SENSITIVE", "INSENSITIVE"}:
        _issue(
            issues,
            document,
            "CASE_MODE_UNKNOWN",
            "/case_mode",
            "expected SENSITIVE or INSENSITIVE",
        )
    if obj.get("path_form") != "REPO_RELATIVE_POSIX":
        _issue(
            issues,
            document,
            "PATH_FORM_UNKNOWN",
            "/path_form",
            "expected REPO_RELATIVE_POSIX",
        )
    if obj.get("rename_semantics") != "EVALUATE_BOTH_ENDPOINTS":
        _issue(
            issues,
            document,
            "RENAME_SEMANTICS_UNKNOWN",
            "/rename_semantics",
            "expected EVALUATE_BOTH_ENDPOINTS",
        )
    rules = obj.get("protected_rules")
    rule_ids: list[str] = []
    if not isinstance(rules, list):
        _issue(
            issues,
            document,
            "TYPE_ARRAY_REQUIRED",
            "/protected_rules",
            "expected array",
        )
    else:
        for index, rule in enumerate(rules):
            pointer = f"/protected_rules/{index}"
            if not isinstance(rule, dict):
                _issue(
                    issues,
                    document,
                    "TYPE_OBJECT_REQUIRED",
                    pointer,
                    "expected object",
                )
                continue
            if set(rule) != {"rule_id", "path", "match"}:
                _issue(
                    issues,
                    document,
                    "POLICY_RULE_SHAPE_INVALID",
                    pointer,
                    "expected rule_id, path, and match only",
                )
            rule_id = _nonempty_string(
                rule.get("rule_id"), document, f"{pointer}/rule_id", issues
            )
            if rule_id:
                rule_ids.append(rule_id)
            _nonempty_string(rule.get("path"), document, f"{pointer}/path", issues)
            if rule.get("match") not in {"EXACT", "SUBTREE"}:
                _issue(
                    issues,
                    document,
                    "MATCH_MODE_UNKNOWN",
                    f"{pointer}/match",
                    "expected EXACT or SUBTREE",
                )
    if len(rule_ids) != len(set(rule_ids)):
        _issue(
            issues,
            document,
            "POLICY_RULE_ID_DUPLICATE",
            "/protected_rules",
            "rule ids must be unique",
        )
    _string_list(
        obj.get("self_protected_paths"),
        document,
        "/self_protected_paths",
        issues,
    )
    stale = _time_window(obj, document, evaluation_as_of, issues)
    return PolicyAssessment(tuple(issues), stale=stale)


def assess_claims_policy(
    value: Any, evaluation_as_of: datetime | None
) -> PolicyAssessment:
    document = "claims_policy"
    issues: list[ContractIssue] = []
    required = {
        "contract_version",
        "policy_id",
        "policy_version",
        "policy_hash",
        "effective_from",
        "expires_at",
        "claim_kind_evidence_classes",
        "allowed_claim_tags",
        "prohibited_claim_tags",
        "required_caveats_by_tag",
        "explicit_hold_evidence_states",
    }
    obj = _strict_object(value, document=document, required=required, issues=issues)
    if obj is None:
        return PolicyAssessment(tuple(issues), stale=False)
    _validate_identity_and_integrity(
        obj,
        document=document,
        contract_version=CLAIMS_POLICY_CONTRACT,
        policy_key="claims_gate",
        issues=issues,
    )
    mapping = obj.get("claim_kind_evidence_classes")
    expected_kinds = {
        "DESCRIPTIVE",
        "DIAGNOSTIC_HYPOTHESIS",
        "COMMERCIAL_PREFERENCE",
        "ACTION_EVIDENCE",
        "OUTCOME_SUPPORTED",
    }
    if not isinstance(mapping, dict) or set(mapping) != expected_kinds:
        _issue(
            issues,
            document,
            "CLAIM_EVIDENCE_MAPPING_INVALID",
            "/claim_kind_evidence_classes",
            "mapping must define exactly the five supported claim kinds",
        )
    else:
        for key, item in mapping.items():
            _string_list(
                item,
                document,
                f"/claim_kind_evidence_classes/{key}",
                issues,
                minimum=1,
            )
    allowed = _string_list(
        obj.get("allowed_claim_tags"),
        document,
        "/allowed_claim_tags",
        issues,
        minimum=1,
    )
    prohibited = _string_list(
        obj.get("prohibited_claim_tags"),
        document,
        "/prohibited_claim_tags",
        issues,
        minimum=1,
    )
    if set(allowed) & set(prohibited):
        _issue(
            issues,
            document,
            "CLAIM_TAG_POLICY_OVERLAP",
            "/allowed_claim_tags",
            "allowed and prohibited tags must not overlap",
        )
    caveats = obj.get("required_caveats_by_tag")
    if not isinstance(caveats, dict):
        _issue(
            issues,
            document,
            "TYPE_OBJECT_REQUIRED",
            "/required_caveats_by_tag",
            "expected object",
        )
    else:
        unknown_caveat_tags = set(caveats) - set(allowed)
        if unknown_caveat_tags:
            _issue(
                issues,
                document,
                "CAVEAT_TAG_UNKNOWN",
                "/required_caveats_by_tag",
                f"unknown tags: {sorted(unknown_caveat_tags)}",
            )
        for tag, item in caveats.items():
            _string_list(
                item,
                document,
                f"/required_caveats_by_tag/{tag}",
                issues,
            )
    hold_states = _string_list(
        obj.get("explicit_hold_evidence_states"),
        document,
        "/explicit_hold_evidence_states",
        issues,
    )
    if not set(hold_states) <= {"INCONCLUSIVE", "CONFOUNDED"}:
        _issue(
            issues,
            document,
            "HOLD_EVIDENCE_STATE_INVALID",
            "/explicit_hold_evidence_states",
            "only INCONCLUSIVE or CONFOUNDED may explicitly produce HOLD",
        )
    stale = _time_window(obj, document, evaluation_as_of, issues)
    return PolicyAssessment(tuple(issues), stale=stale)
