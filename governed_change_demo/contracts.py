"""Strict product-local contract validation.

The bundled JSON Schemas are the portable contract descriptions. These
standard-library validators provide the same fail-closed checks at runtime
without downloading a schema engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import re
from typing import Any, Callable, Iterable

from .canonical import (
    canonical_hash_or_fingerprint,
    stable_identifier,
    verify_embedded_hash,
)


ENVELOPE_VERSION = "governed-repo.shared-change-envelope/v1"
AUTHORITY_VERSION = "governed-repo.authority-manifest/v1"
GATE_RESULT_VERSION = "governed-repo.gate-result/v1"
COMBINED_DECISION_VERSION = "governed-repo.combined-decision/v1"
RECEIPT_VERSION = "governed-repo.governed-receipt/v1"
CAP_VERSION = "governed-repo.cap-decision/v1"

KNOWN_POLICY_VERSIONS = {
    "cap_policy": "governed-repo.cap-policy/v1.0.0",
    "path_gate": "governed-repo.path-policy/v1.0.0",
    "claims_gate": "governed-repo.claims-policy/v1.0.0",
}

CHANGE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,95}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
HASH_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
RFC3339_UTC_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$"
)


@dataclass(frozen=True)
class ContractIssue:
    document: str
    code: str
    pointer: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {
            "document": self.document,
            "code": self.code,
            "pointer": self.pointer,
            "message": self.message,
        }


class ContractValidationError(ValueError):
    def __init__(self, issues: Iterable[ContractIssue]):
        self.issues = tuple(issues)
        super().__init__("; ".join(f"{item.document}{item.pointer}: {item.code}" for item in self.issues))


def _issue(
    issues: list[ContractIssue],
    document: str,
    code: str,
    pointer: str,
    message: str,
) -> None:
    issues.append(ContractIssue(document, code, pointer, message))


def _object(
    value: Any,
    document: str,
    pointer: str,
    issues: list[ContractIssue],
) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        _issue(issues, document, "TYPE_OBJECT_REQUIRED", pointer, "expected an object")
        return None
    return value


def _strict_keys(
    value: dict[str, Any],
    required: set[str],
    document: str,
    pointer: str,
    issues: list[ContractIssue],
) -> None:
    for key in sorted(required - value.keys()):
        _issue(
            issues,
            document,
            "REQUIRED_FIELD_MISSING",
            f"{pointer}/{key}",
            "required field is missing",
        )
    for key in sorted(value.keys() - required):
        _issue(
            issues,
            document,
            "UNKNOWN_FIELD",
            f"{pointer}/{key}",
            "additional properties are not allowed",
        )


def _string(
    value: Any,
    document: str,
    pointer: str,
    issues: list[ContractIssue],
    *,
    pattern: re.Pattern[str] | None = None,
    allow_empty: bool = False,
) -> str | None:
    if not isinstance(value, str) or (not allow_empty and not value):
        _issue(issues, document, "TYPE_STRING_REQUIRED", pointer, "expected a non-empty string")
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
    if pattern and not pattern.fullmatch(value):
        _issue(issues, document, "STRING_PATTERN_MISMATCH", pointer, "string has invalid form")
    return value


def _enum(
    value: Any,
    allowed: set[str],
    document: str,
    pointer: str,
    issues: list[ContractIssue],
) -> str | None:
    result = _string(value, document, pointer, issues)
    if result is not None and result not in allowed:
        _issue(
            issues,
            document,
            "ENUM_VALUE_UNKNOWN",
            pointer,
            f"expected one of {sorted(allowed)}",
        )
    return result


def _boolean(
    value: Any,
    document: str,
    pointer: str,
    issues: list[ContractIssue],
) -> bool | None:
    if not isinstance(value, bool):
        _issue(issues, document, "TYPE_BOOLEAN_REQUIRED", pointer, "expected a boolean")
        return None
    return value


def _integer(
    value: Any,
    document: str,
    pointer: str,
    issues: list[ContractIssue],
    *,
    minimum: int,
) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int):
        _issue(issues, document, "TYPE_INTEGER_REQUIRED", pointer, "expected an integer")
        return None
    if value < minimum:
        _issue(issues, document, "INTEGER_BELOW_MINIMUM", pointer, f"minimum is {minimum}")
    return value


def _array(
    value: Any,
    document: str,
    pointer: str,
    issues: list[ContractIssue],
    *,
    minimum: int = 0,
) -> list[Any] | None:
    if not isinstance(value, list):
        _issue(issues, document, "TYPE_ARRAY_REQUIRED", pointer, "expected an array")
        return None
    if len(value) < minimum:
        _issue(issues, document, "ARRAY_TOO_SHORT", pointer, f"minimum length is {minimum}")
    return value


def _string_array(
    value: Any,
    document: str,
    pointer: str,
    issues: list[ContractIssue],
    *,
    minimum: int = 0,
    unique: bool = True,
    pattern: re.Pattern[str] | None = None,
) -> list[str]:
    raw = _array(value, document, pointer, issues, minimum=minimum)
    if raw is None:
        return []
    result: list[str] = []
    for index, item in enumerate(raw):
        parsed = _string(
            item,
            document,
            f"{pointer}/{index}",
            issues,
            pattern=pattern,
        )
        if parsed is not None:
            result.append(parsed)
    if unique and len(result) != len(set(result)):
        _issue(issues, document, "ARRAY_ITEMS_NOT_UNIQUE", pointer, "items must be unique")
    return result


def parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not RFC3339_UTC_RE.fullmatch(value):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def utf8_content_hash(value: str) -> str:
    """Return the deterministic SHA-256 of the exact UTF-8 content bytes."""

    if not isinstance(value, str):
        raise TypeError("content must be a string")
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _validate_basis(
    value: Any,
    document: str,
    pointer: str,
    issues: list[ContractIssue],
) -> dict[str, Any] | None:
    basis = _object(value, document, pointer, issues)
    if basis is None:
        return None
    _strict_keys(basis, {"basis_id", "basis_hash"}, document, pointer, issues)
    _string(
        basis.get("basis_id"),
        document,
        f"{pointer}/basis_id",
        issues,
        pattern=TOKEN_RE,
    )
    _hash_string(
        basis.get("basis_hash"),
        document,
        f"{pointer}/basis_hash",
        issues,
    )
    return basis


def _timestamp(
    value: Any,
    document: str,
    pointer: str,
    issues: list[ContractIssue],
) -> datetime | None:
    result = parse_utc(value)
    if result is None:
        _issue(
            issues,
            document,
            "UTC_TIMESTAMP_INVALID",
            pointer,
            "expected RFC3339 UTC in YYYY-MM-DDTHH:MM:SS[.fraction]Z form",
        )
    return result


def _version(
    value: Any,
    expected: str,
    document: str,
    issues: list[ContractIssue],
) -> None:
    if value != expected:
        _issue(
            issues,
            document,
            "CONTRACT_VERSION_UNKNOWN",
            "/contract_version",
            f"expected {expected}",
        )


def _validate_actor(
    value: Any,
    document: str,
    pointer: str,
    issues: list[ContractIssue],
    allowed_types: set[str],
) -> None:
    obj = _object(value, document, pointer, issues)
    if obj is None:
        return
    _strict_keys(obj, {"actor_id", "actor_type"}, document, pointer, issues)
    _string(obj.get("actor_id"), document, f"{pointer}/actor_id", issues, pattern=TOKEN_RE)
    _enum(obj.get("actor_type"), allowed_types, document, f"{pointer}/actor_type", issues)


def validate_envelope(value: Any, *, raise_on_error: bool = True) -> list[ContractIssue]:
    document = "shared_change_envelope"
    issues: list[ContractIssue] = []
    obj = _object(value, document, "", issues)
    if obj is None:
        return _finish(issues, raise_on_error)
    required = {
        "contract_version",
        "change_id",
        "revision",
        "actor",
        "task",
        "assumptions_to_validate",
        "authority_ref",
        "requested_at",
        "evaluation_as_of",
        "source_basis",
        "repair_summary",
        "changes",
        "evidence",
        "policy_versions",
        "policy_hashes",
        "fixture",
        "evidence_requirements",
    }
    _strict_keys(obj, required, document, "", issues)
    _version(obj.get("contract_version"), ENVELOPE_VERSION, document, issues)
    _string(obj.get("change_id"), document, "/change_id", issues, pattern=CHANGE_ID_RE)
    _integer(obj.get("revision"), document, "/revision", issues, minimum=1)
    _validate_actor(
        obj.get("actor"),
        document,
        "/actor",
        issues,
        {"HUMAN", "AI_AGENT", "AUTOMATION"},
    )

    task = _object(obj.get("task"), document, "/task", issues)
    if task is not None:
        _strict_keys(task, {"task_id", "summary"}, document, "/task", issues)
        _string(task.get("task_id"), document, "/task/task_id", issues, pattern=TOKEN_RE)
        _string(task.get("summary"), document, "/task/summary", issues)
    _string_array(
        obj.get("assumptions_to_validate"),
        document,
        "/assumptions_to_validate",
        issues,
        minimum=1,
    )
    _string(obj.get("authority_ref"), document, "/authority_ref", issues, pattern=TOKEN_RE)
    requested_at = _timestamp(
        obj.get("requested_at"), document, "/requested_at", issues
    )
    evaluation_as_of = _timestamp(
        obj.get("evaluation_as_of"), document, "/evaluation_as_of", issues
    )
    if (
        requested_at is not None
        and evaluation_as_of is not None
        and evaluation_as_of < requested_at
    ):
        _issue(
            issues,
            document,
            "EVALUATION_PRECEDES_REQUEST",
            "/evaluation_as_of",
            "evaluation_as_of must not precede requested_at",
        )
    _validate_basis(obj.get("source_basis"), document, "/source_basis", issues)
    repair_summary = obj.get("repair_summary")
    if repair_summary is not None:
        _string(
            repair_summary,
            document,
            "/repair_summary",
            issues,
            allow_empty=True,
        )

    changes = _array(obj.get("changes"), document, "/changes", issues, minimum=1)
    claim_ids: list[str] = []
    if changes is not None:
        for index, raw_change in enumerate(changes):
            pointer = f"/changes/{index}"
            change = _object(raw_change, document, pointer, issues)
            if change is None:
                continue
            change_keys = {
                "operation",
                "path",
                "destination_path",
                "content",
                "content_encoding",
                "before_content_hash",
                "after_content_hash",
                "claims",
            }
            _strict_keys(change, change_keys, document, pointer, issues)
            operation = _enum(
                change.get("operation"),
                {"CREATE", "UPDATE", "DELETE", "RENAME"},
                document,
                f"{pointer}/operation",
                issues,
            )
            path = _string(
                change.get("path"), document, f"{pointer}/path", issues
            )
            destination = change.get("destination_path")
            if operation == "RENAME":
                parsed_destination = _string(
                    destination,
                    document,
                    f"{pointer}/destination_path",
                    issues,
                )
                if (
                    path is not None
                    and parsed_destination is not None
                    and path == parsed_destination
                ):
                    _issue(
                        issues,
                        document,
                        "RENAME_ENDPOINTS_IDENTICAL",
                        f"{pointer}/destination_path",
                        "rename destination must differ from the source path",
                    )
            elif destination is not None:
                _issue(
                    issues,
                    document,
                    "DESTINATION_ONLY_FOR_RENAME",
                    f"{pointer}/destination_path",
                    "destination_path must be null unless operation is RENAME",
                )
            content = _string(
                change.get("content"),
                document,
                f"{pointer}/content",
                issues,
                allow_empty=operation == "DELETE",
            )
            if change.get("content_encoding") != "utf-8":
                _issue(
                    issues,
                    document,
                    "CONTENT_ENCODING_UNKNOWN",
                    f"{pointer}/content_encoding",
                    "only utf-8 is supported",
                )
            before_hash = change.get("before_content_hash")
            after_hash = change.get("after_content_hash")
            if before_hash is not None:
                _hash_string(
                    before_hash,
                    document,
                    f"{pointer}/before_content_hash",
                    issues,
                )
            if after_hash is not None:
                _hash_string(
                    after_hash,
                    document,
                    f"{pointer}/after_content_hash",
                    issues,
                )
            expected_after: str | None = None
            if content is not None:
                try:
                    expected_after = utf8_content_hash(content)
                except UnicodeEncodeError:
                    expected_after = None
            if operation == "CREATE":
                if before_hash is not None:
                    _issue(
                        issues,
                        document,
                        "CREATE_BEFORE_HASH_MUST_BE_NULL",
                        f"{pointer}/before_content_hash",
                        "CREATE has no prior content",
                    )
                if expected_after is not None and after_hash != expected_after:
                    _issue(
                        issues,
                        document,
                        "AFTER_CONTENT_HASH_MISMATCH",
                        f"{pointer}/after_content_hash",
                        "after_content_hash must hash the exact UTF-8 content bytes",
                    )
            elif operation == "UPDATE":
                if not isinstance(before_hash, str):
                    _issue(
                        issues,
                        document,
                        "UPDATE_BEFORE_HASH_REQUIRED",
                        f"{pointer}/before_content_hash",
                        "UPDATE requires the prior content hash",
                    )
                if expected_after is not None and after_hash != expected_after:
                    _issue(
                        issues,
                        document,
                        "AFTER_CONTENT_HASH_MISMATCH",
                        f"{pointer}/after_content_hash",
                        "after_content_hash must hash the exact UTF-8 content bytes",
                    )
            elif operation == "DELETE":
                if not isinstance(before_hash, str):
                    _issue(
                        issues,
                        document,
                        "DELETE_BEFORE_HASH_REQUIRED",
                        f"{pointer}/before_content_hash",
                        "DELETE requires the prior content hash",
                    )
                if after_hash is not None:
                    _issue(
                        issues,
                        document,
                        "DELETE_AFTER_HASH_MUST_BE_NULL",
                        f"{pointer}/after_content_hash",
                        "DELETE has no resulting content",
                    )
                if content != "":
                    _issue(
                        issues,
                        document,
                        "DELETE_CONTENT_MUST_BE_EMPTY",
                        f"{pointer}/content",
                        "DELETE content must be the empty UTF-8 string",
                    )
            elif operation == "RENAME":
                if not isinstance(before_hash, str):
                    _issue(
                        issues,
                        document,
                        "RENAME_BEFORE_HASH_REQUIRED",
                        f"{pointer}/before_content_hash",
                        "RENAME requires the prior content hash",
                    )
                if before_hash != after_hash:
                    _issue(
                        issues,
                        document,
                        "RENAME_CONTENT_HASH_CHANGED",
                        f"{pointer}/after_content_hash",
                        "RENAME must preserve the content hash",
                    )
                if expected_after is not None and after_hash != expected_after:
                    _issue(
                        issues,
                        document,
                        "AFTER_CONTENT_HASH_MISMATCH",
                        f"{pointer}/after_content_hash",
                        "after_content_hash must hash the exact UTF-8 content bytes",
                    )
            claims = _array(change.get("claims"), document, f"{pointer}/claims", issues)
            if claims is not None:
                for claim_index, raw_claim in enumerate(claims):
                    claim_pointer = f"{pointer}/claims/{claim_index}"
                    claim = _object(raw_claim, document, claim_pointer, issues)
                    if claim is None:
                        continue
                    claim_keys = {
                        "claim_id",
                        "statement",
                        "claim_kind",
                        "claim_tag",
                        "evidence_refs",
                        "caveats",
                    }
                    _strict_keys(claim, claim_keys, document, claim_pointer, issues)
                    claim_id = _string(
                        claim.get("claim_id"),
                        document,
                        f"{claim_pointer}/claim_id",
                        issues,
                        pattern=TOKEN_RE,
                    )
                    if claim_id:
                        claim_ids.append(claim_id)
                    _string(claim.get("statement"), document, f"{claim_pointer}/statement", issues)
                    _enum(
                        claim.get("claim_kind"),
                        {
                            "DESCRIPTIVE",
                            "DIAGNOSTIC_HYPOTHESIS",
                            "COMMERCIAL_PREFERENCE",
                            "ACTION_EVIDENCE",
                            "OUTCOME_SUPPORTED",
                        },
                        document,
                        f"{claim_pointer}/claim_kind",
                        issues,
                    )
                    _string(
                        claim.get("claim_tag"),
                        document,
                        f"{claim_pointer}/claim_tag",
                        issues,
                        pattern=TOKEN_RE,
                    )
                    _string_array(
                        claim.get("evidence_refs"),
                        document,
                        f"{claim_pointer}/evidence_refs",
                        issues,
                    )
                    _string_array(
                        claim.get("caveats"),
                        document,
                        f"{claim_pointer}/caveats",
                        issues,
                    )
    if len(claim_ids) != len(set(claim_ids)):
        _issue(issues, document, "CLAIM_ID_DUPLICATE", "/changes", "claim ids must be unique")

    evidence = _array(obj.get("evidence"), document, "/evidence", issues)
    evidence_ids: list[str] = []
    if evidence is not None:
        for index, raw_item in enumerate(evidence):
            pointer = f"/evidence/{index}"
            item = _object(raw_item, document, pointer, issues)
            if item is None:
                continue
            keys = {
                "availability",
                "evidence_id",
                "evidence_class",
                "evidence_state",
                "summary",
                "source_ref",
            }
            _strict_keys(item, keys, document, pointer, issues)
            evidence_id = _string(
                item.get("evidence_id"),
                document,
                f"{pointer}/evidence_id",
                issues,
                pattern=TOKEN_RE,
            )
            if evidence_id:
                evidence_ids.append(evidence_id)
            _enum(
                item.get("evidence_class"),
                {
                    "SOURCE_OBSERVATION",
                    "DIAGNOSTIC_INFERENCE",
                    "PREFERENCE",
                    "ACTION_EVENT",
                    "OUTCOME_MEASUREMENT",
                },
                document,
                f"{pointer}/evidence_class",
                issues,
            )
            _enum(
                item.get("availability"),
                {"AVAILABLE", "REFRESHABLE_UNAVAILABLE"},
                document,
                f"{pointer}/availability",
                issues,
            )
            _enum(
                item.get("evidence_state"),
                {
                    "SUPPORTED",
                    "PARTIALLY_SUPPORTED",
                    "REFUTED",
                    "INCONCLUSIVE",
                    "CONFOUNDED",
                },
                document,
                f"{pointer}/evidence_state",
                issues,
            )
            _string(item.get("summary"), document, f"{pointer}/summary", issues)
            _string(item.get("source_ref"), document, f"{pointer}/source_ref", issues)
    if len(evidence_ids) != len(set(evidence_ids)):
        _issue(issues, document, "EVIDENCE_ID_DUPLICATE", "/evidence", "evidence ids must be unique")

    policy_versions = _object(obj.get("policy_versions"), document, "/policy_versions", issues)
    if policy_versions is not None:
        _strict_keys(
            policy_versions,
            {"cap_policy", "path_gate", "claims_gate"},
            document,
            "/policy_versions",
            issues,
        )
        for key in ("cap_policy", "path_gate", "claims_gate"):
            _string(
                policy_versions.get(key),
                document,
                f"/policy_versions/{key}",
                issues,
                pattern=TOKEN_RE,
            )
    _validate_hash_map(
        obj.get("policy_hashes"),
        {"cap_policy", "path_gate", "claims_gate"},
        document,
        "/policy_hashes",
        issues,
    )

    fixture = _object(obj.get("fixture"), document, "/fixture", issues)
    if fixture is not None:
        _strict_keys(fixture, {"fixture_id", "fixture_version", "state"}, document, "/fixture", issues)
        _string(fixture.get("fixture_id"), document, "/fixture/fixture_id", issues, pattern=TOKEN_RE)
        _string(
            fixture.get("fixture_version"),
            document,
            "/fixture/fixture_version",
            issues,
            pattern=TOKEN_RE,
        )
        _enum(
            fixture.get("state"),
            {"ORIGINAL_BLOCK", "BOUNDED_REPAIR", "MODELED_HOLD"},
            document,
            "/fixture/state",
            issues,
        )
    _string_array(
        obj.get("evidence_requirements"),
        document,
        "/evidence_requirements",
        issues,
        minimum=1,
    )
    return _finish(issues, raise_on_error)


def validate_authority(value: Any, *, raise_on_error: bool = True) -> list[ContractIssue]:
    document = "authority_manifest"
    issues: list[ContractIssue] = []
    obj = _object(value, document, "", issues)
    if obj is None:
        return _finish(issues, raise_on_error)
    required = {
        "contract_version",
        "manifest_id",
        "issuer",
        "subject_actor_ids",
        "state",
        "revocation_status",
        "issued_at",
        "expires_at",
        "required_source_basis",
        "permitted_task_ids",
        "permitted_paths",
        "no_touch_paths",
        "permitted_actions",
        "applicable_gates",
        "stop_conditions",
        "policy_versions",
        "policy_hashes",
        "receipt_requirements",
    }
    _strict_keys(obj, required, document, "", issues)
    _version(obj.get("contract_version"), AUTHORITY_VERSION, document, issues)
    _string(obj.get("manifest_id"), document, "/manifest_id", issues, pattern=TOKEN_RE)
    _validate_actor(obj.get("issuer"), document, "/issuer", issues, {"OPERATOR", "ORGANIZATION"})
    _string_array(
        obj.get("subject_actor_ids"),
        document,
        "/subject_actor_ids",
        issues,
        minimum=1,
    )
    state = _enum(
        obj.get("state"),
        {"ACTIVE", "PENDING_REVIEW", "REVOKED"},
        document,
        "/state",
        issues,
    )
    revocation_status = _enum(
        obj.get("revocation_status"),
        {"NOT_REVOKED", "REVOKED", "UNKNOWN"},
        document,
        "/revocation_status",
        issues,
    )
    expected_revocation = {
        "ACTIVE": "NOT_REVOKED",
        "PENDING_REVIEW": "UNKNOWN",
        "REVOKED": "REVOKED",
    }.get(state)
    if (
        expected_revocation is not None
        and revocation_status is not None
        and revocation_status != expected_revocation
    ):
        _issue(
            issues,
            document,
            "REVOCATION_STATE_INCOHERENT",
            "/revocation_status",
            f"state {state} requires revocation_status {expected_revocation}",
        )
    issued_at = _timestamp(obj.get("issued_at"), document, "/issued_at", issues)
    expires_at = _timestamp(obj.get("expires_at"), document, "/expires_at", issues)
    if issued_at and expires_at and expires_at <= issued_at:
        _issue(
            issues,
            document,
            "AUTHORITY_TIME_RANGE_INVALID",
            "/expires_at",
            "expiry must be after issuance",
        )
    _validate_basis(
        obj.get("required_source_basis"),
        document,
        "/required_source_basis",
        issues,
    )
    _string_array(
        obj.get("permitted_task_ids"),
        document,
        "/permitted_task_ids",
        issues,
        minimum=1,
        pattern=TOKEN_RE,
    )
    permitted_actions = _string_array(
        obj.get("permitted_actions"),
        document,
        "/permitted_actions",
        issues,
        minimum=1,
    )
    for index, action in enumerate(permitted_actions):
        if action not in {"CREATE", "UPDATE", "DELETE", "RENAME"}:
            _issue(
                issues,
                document,
                "ACTION_UNKNOWN",
                f"/permitted_actions/{index}",
                "unknown repository action",
            )
    paths = _array(obj.get("permitted_paths"), document, "/permitted_paths", issues, minimum=1)
    rule_ids: list[str] = []
    if paths is not None:
        for index, raw_rule in enumerate(paths):
            pointer = f"/permitted_paths/{index}"
            rule = _object(raw_rule, document, pointer, issues)
            if rule is None:
                continue
            _strict_keys(
                rule,
                {"rule_id", "path", "match", "actions", "allow_protected"},
                document,
                pointer,
                issues,
            )
            rule_id = _string(
                rule.get("rule_id"), document, f"{pointer}/rule_id", issues, pattern=TOKEN_RE
            )
            if rule_id:
                rule_ids.append(rule_id)
            _string(rule.get("path"), document, f"{pointer}/path", issues)
            _enum(
                rule.get("match"),
                {"EXACT", "SUBTREE"},
                document,
                f"{pointer}/match",
                issues,
            )
            actions = _string_array(
                rule.get("actions"), document, f"{pointer}/actions", issues, minimum=1
            )
            _boolean(
                rule.get("allow_protected"),
                document,
                f"{pointer}/allow_protected",
                issues,
            )
            for action_index, action in enumerate(actions):
                if action not in {"CREATE", "UPDATE", "DELETE", "RENAME"}:
                    _issue(
                        issues,
                        document,
                        "ACTION_UNKNOWN",
                        f"{pointer}/actions/{action_index}",
                        "unknown repository action",
                    )
    if len(rule_ids) != len(set(rule_ids)):
        _issue(
            issues,
            document,
            "PATH_RULE_ID_DUPLICATE",
            "/permitted_paths",
            "rule ids must be unique",
        )
    _string_array(
        obj.get("no_touch_paths"),
        document,
        "/no_touch_paths",
        issues,
        minimum=1,
    )
    gates = _array(obj.get("applicable_gates"), document, "/applicable_gates", issues, minimum=1)
    gate_ids: list[str] = []
    if gates is not None:
        for index, raw_gate in enumerate(gates):
            pointer = f"/applicable_gates/{index}"
            gate = _object(raw_gate, document, pointer, issues)
            if gate is None:
                continue
            _strict_keys(gate, {"gate_id", "required"}, document, pointer, issues)
            gate_id = _enum(
                gate.get("gate_id"),
                {"path_gate", "claims_gate"},
                document,
                f"{pointer}/gate_id",
                issues,
            )
            if gate_id:
                gate_ids.append(gate_id)
            _boolean(gate.get("required"), document, f"{pointer}/required", issues)
    if len(gate_ids) != len(set(gate_ids)):
        _issue(
            issues,
            document,
            "GATE_ID_DUPLICATE",
            "/applicable_gates",
            "gate ids must be unique",
        )
    _string_array(
        obj.get("stop_conditions"), document, "/stop_conditions", issues, minimum=1
    )
    policy_versions = _object(obj.get("policy_versions"), document, "/policy_versions", issues)
    if policy_versions is not None:
        _strict_keys(
            policy_versions,
            {"cap_policy", "path_gate", "claims_gate"},
            document,
            "/policy_versions",
            issues,
        )
        for key in ("cap_policy", "path_gate", "claims_gate"):
            _string(
                policy_versions.get(key),
                document,
                f"/policy_versions/{key}",
                issues,
                pattern=TOKEN_RE,
            )
    _validate_hash_map(
        obj.get("policy_hashes"),
        {"cap_policy", "path_gate", "claims_gate"},
        document,
        "/policy_hashes",
        issues,
    )
    receipt = _object(
        obj.get("receipt_requirements"), document, "/receipt_requirements", issues
    )
    if receipt is not None:
        _strict_keys(
            receipt,
            {"canonical_hash", "repair_lineage", "preserve_gate_evidence"},
            document,
            "/receipt_requirements",
            issues,
        )
        for key in ("canonical_hash", "repair_lineage", "preserve_gate_evidence"):
            _boolean(receipt.get(key), document, f"/receipt_requirements/{key}", issues)
    return _finish(issues, raise_on_error)


def _require_canonical_string_order(
    values: list[str],
    document: str,
    pointer: str,
    issues: list[ContractIssue],
) -> None:
    if values != sorted(values):
        _issue(
            issues,
            document,
            "ARRAY_ORDER_NONCANONICAL",
            pointer,
            "items must be sorted lexicographically",
        )


def validate_cap_decision(
    value: Any, *, raise_on_error: bool = True
) -> list[ContractIssue]:
    """Validate the neutral, mechanical CAP decision contract."""

    document = "cap_decision"
    required = {
        "contract_version",
        "cap_contract_version",
        "packet_type",
        "stage_id",
        "evaluator_version",
        "cap_policy_version",
        "cap_decision_id",
        "canonical_hash",
        "change_id",
        "revision",
        "shared_change_envelope_hash",
        "source_basis",
        "authority_manifest_reference",
        "evaluation_as_of",
        "policy_basis",
        "checks",
        "evidence_basis",
        "decision",
        "reason_codes",
        "failed_checks",
        "limitations",
        "next_lawful_move",
        "domain_gate_ids",
        "domain_gates_may_run",
        "execution_authority",
    }
    issues = _validate_proof_contract(
        value,
        document=document,
        expected_version=CAP_VERSION,
        required=required,
        hash_field="canonical_hash",
        raise_on_error=False,
    )
    if not isinstance(value, dict):
        return _finish(issues, raise_on_error)

    if value.get("cap_contract_version") != CAP_VERSION:
        _issue(
            issues,
            document,
            "CAP_CONTRACT_VERSION_UNKNOWN",
            "/cap_contract_version",
            f"expected {CAP_VERSION}",
        )
    if value.get("packet_type") != "CAP_DECISION":
        _issue(
            issues,
            document,
            "CAP_PACKET_TYPE_INVALID",
            "/packet_type",
            "expected CAP_DECISION",
        )
    if value.get("stage_id") != "cap_decision":
        _issue(
            issues,
            document,
            "CAP_STAGE_ID_INVALID",
            "/stage_id",
            "expected cap_decision",
        )
    if value.get("evaluator_version") != "governed-repo.cap-adapter/v1.0.0":
        _issue(
            issues,
            document,
            "CAP_EVALUATOR_VERSION_UNKNOWN",
            "/evaluator_version",
            "expected governed-repo.cap-adapter/v1.0.0",
        )
    _string(
        value.get("cap_policy_version"),
        document,
        "/cap_policy_version",
        issues,
        pattern=TOKEN_RE,
    )
    cap_id = _string(
        value.get("cap_decision_id"),
        document,
        "/cap_decision_id",
        issues,
        pattern=TOKEN_RE,
    )
    _string(
        value.get("change_id"),
        document,
        "/change_id",
        issues,
        pattern=CHANGE_ID_RE,
    )
    _integer(value.get("revision"), document, "/revision", issues, minimum=1)
    _hash_string(
        value.get("shared_change_envelope_hash"),
        document,
        "/shared_change_envelope_hash",
        issues,
    )
    _validate_basis(value.get("source_basis"), document, "/source_basis", issues)
    _timestamp(
        value.get("evaluation_as_of"),
        document,
        "/evaluation_as_of",
        issues,
    )

    authority_ref = _object(
        value.get("authority_manifest_reference"),
        document,
        "/authority_manifest_reference",
        issues,
    )
    if authority_ref is not None:
        _strict_keys(
            authority_ref,
            {"manifest_id", "manifest_hash", "required_source_basis"},
            document,
            "/authority_manifest_reference",
            issues,
        )
        _string(
            authority_ref.get("manifest_id"),
            document,
            "/authority_manifest_reference/manifest_id",
            issues,
            pattern=TOKEN_RE,
        )
        _hash_string(
            authority_ref.get("manifest_hash"),
            document,
            "/authority_manifest_reference/manifest_hash",
            issues,
        )
        _validate_basis(
            authority_ref.get("required_source_basis"),
            document,
            "/authority_manifest_reference/required_source_basis",
            issues,
        )

    policy_basis = _object(
        value.get("policy_basis"), document, "/policy_basis", issues
    )
    if policy_basis is not None:
        policy_keys = {"cap_policy", "claims_gate", "path_gate"}
        _strict_keys(
            policy_basis, policy_keys, document, "/policy_basis", issues
        )
        for policy_key in sorted(policy_keys):
            pointer = f"/policy_basis/{policy_key}"
            reference = _object(
                policy_basis.get(policy_key), document, pointer, issues
            )
            if reference is None:
                continue
            _strict_keys(
                reference,
                {"policy_id", "policy_version", "policy_hash"},
                document,
                pointer,
                issues,
            )
            _string(
                reference.get("policy_id"),
                document,
                f"{pointer}/policy_id",
                issues,
                pattern=TOKEN_RE,
            )
            policy_version = _string(
                reference.get("policy_version"),
                document,
                f"{pointer}/policy_version",
                issues,
                pattern=TOKEN_RE,
            )
            _hash_string(
                reference.get("policy_hash"),
                document,
                f"{pointer}/policy_hash",
                issues,
            )
        cap_reference = policy_basis.get("cap_policy")
        if (
            isinstance(cap_reference, dict)
            and cap_reference.get("policy_version")
            != value.get("cap_policy_version")
        ):
            _issue(
                issues,
                document,
                "CAP_POLICY_VERSION_REFERENCE_MISMATCH",
                "/cap_policy_version",
                "cap_policy_version must match policy_basis.cap_policy",
            )

    evidence_ids: list[str] = []
    evidence = _array(
        value.get("evidence_basis"), document, "/evidence_basis", issues
    )
    if evidence is not None:
        for index, raw_item in enumerate(evidence):
            pointer = f"/evidence_basis/{index}"
            item = _object(raw_item, document, pointer, issues)
            if item is None:
                continue
            keys = {
                "availability",
                "evidence_id",
                "evidence_class",
                "evidence_state",
                "source_ref",
                "evidence_hash",
                "summary",
            }
            _strict_keys(item, keys, document, pointer, issues)
            evidence_id = _string(
                item.get("evidence_id"),
                document,
                f"{pointer}/evidence_id",
                issues,
                pattern=TOKEN_RE,
            )
            if evidence_id:
                evidence_ids.append(evidence_id)
            _enum(
                item.get("evidence_class"),
                {
                    "SOURCE_OBSERVATION",
                    "DIAGNOSTIC_INFERENCE",
                    "PREFERENCE",
                    "ACTION_EVENT",
                    "OUTCOME_MEASUREMENT",
                },
                document,
                f"{pointer}/evidence_class",
                issues,
            )
            _enum(
                item.get("availability"),
                {"AVAILABLE", "REFRESHABLE_UNAVAILABLE"},
                document,
                f"{pointer}/availability",
                issues,
            )
            _enum(
                item.get("evidence_state"),
                {
                    "SUPPORTED",
                    "PARTIALLY_SUPPORTED",
                    "REFUTED",
                    "INCONCLUSIVE",
                    "CONFOUNDED",
                },
                document,
                f"{pointer}/evidence_state",
                issues,
            )
            _string(
                item.get("source_ref"),
                document,
                f"{pointer}/source_ref",
                issues,
            )
            _string(
                item.get("summary"),
                document,
                f"{pointer}/summary",
                issues,
            )
            _hash_string(
                item.get("evidence_hash"),
                document,
                f"{pointer}/evidence_hash",
                issues,
            )
            try:
                expected_evidence_hash = canonical_hash_or_fingerprint(
                    {
                        key: child
                        for key, child in item.items()
                        if key != "evidence_hash"
                    }
                )
            except (TypeError, ValueError, UnicodeError):
                expected_evidence_hash = None
            if (
                expected_evidence_hash is not None
                and item.get("evidence_hash") != expected_evidence_hash
            ):
                _issue(
                    issues,
                    document,
                    "CAP_EVIDENCE_HASH_MISMATCH",
                    f"{pointer}/evidence_hash",
                    "evidence hash must bind the canonical evidence record",
                )
    if len(evidence_ids) != len(set(evidence_ids)):
        _issue(
            issues,
            document,
            "CAP_EVIDENCE_ID_DUPLICATE",
            "/evidence_basis",
            "evidence ids must be unique",
        )
    _require_canonical_string_order(
        evidence_ids, document, "/evidence_basis", issues
    )

    required_check_ids = {
        "AUTHORITY_REVOCATION",
        "AUTHORITY_SCOPE",
        "AUTHORITY_TIME",
        "EVIDENCE_PRESENCE",
        "GATE_APPLICABILITY",
        "NO_TOUCH",
        "POLICY_INTEGRITY",
        "SOURCE_BASIS",
        "VERSION_RECOGNITION",
    }
    check_ids: list[str] = []
    statuses: dict[str, str] = {}
    check_reason_codes: list[str] = []
    checks = _array(
        value.get("checks"),
        document,
        "/checks",
        issues,
        minimum=len(required_check_ids),
    )
    if checks is not None:
        for index, raw_check in enumerate(checks):
            pointer = f"/checks/{index}"
            check = _object(raw_check, document, pointer, issues)
            if check is None:
                continue
            _strict_keys(
                check,
                {"check_id", "status", "reason_codes", "evidence_refs"},
                document,
                pointer,
                issues,
            )
            check_id = _enum(
                check.get("check_id"),
                required_check_ids,
                document,
                f"{pointer}/check_id",
                issues,
            )
            status = _enum(
                check.get("status"),
                {"PASS", "BLOCK", "HOLD:CONTEXT_UPDATE_REQUIRED"},
                document,
                f"{pointer}/status",
                issues,
            )
            if check_id:
                check_ids.append(check_id)
                if status:
                    statuses[check_id] = status
            codes = _string_array(
                check.get("reason_codes"),
                document,
                f"{pointer}/reason_codes",
                issues,
                minimum=1,
            )
            _require_canonical_string_order(
                codes, document, f"{pointer}/reason_codes", issues
            )
            check_reason_codes.extend(codes)
            refs = _string_array(
                check.get("evidence_refs"),
                document,
                f"{pointer}/evidence_refs",
                issues,
                minimum=1,
            )
            _require_canonical_string_order(
                refs, document, f"{pointer}/evidence_refs", issues
            )
    if set(check_ids) != required_check_ids or len(check_ids) != len(
        required_check_ids
    ):
        _issue(
            issues,
            document,
            "CAP_CHECK_SET_INVALID",
            "/checks",
            "the nine mechanical CAP checks must appear exactly once",
        )
    _require_canonical_string_order(check_ids, document, "/checks", issues)

    decision = _enum(
        value.get("decision"),
        {"PASS", "BLOCK", "HOLD:CONTEXT_UPDATE_REQUIRED"},
        document,
        "/decision",
        issues,
    )
    if "BLOCK" in statuses.values():
        expected_decision = "BLOCK"
    elif "HOLD:CONTEXT_UPDATE_REQUIRED" in statuses.values():
        expected_decision = "HOLD:CONTEXT_UPDATE_REQUIRED"
    elif len(statuses) == len(required_check_ids) and all(
        status == "PASS" for status in statuses.values()
    ):
        expected_decision = "PASS"
    else:
        expected_decision = "BLOCK"
    if decision is not None and decision != expected_decision:
        _issue(
            issues,
            document,
            "CAP_DECISION_DERIVATION_MISMATCH",
            "/decision",
            "decision must follow BLOCK, HOLD, PASS precedence",
        )
    if (
        statuses.get("SOURCE_BASIS") == "HOLD:CONTEXT_UPDATE_REQUIRED"
        and expected_decision != "HOLD:CONTEXT_UPDATE_REQUIRED"
        and "BLOCK" not in statuses.values()
    ):
        _issue(
            issues,
            document,
            "CAP_SOURCE_HOLD_DERIVATION_MISMATCH",
            "/decision",
            "a stale source basis requires the explicit context-update hold",
        )

    reason_codes = _string_array(
        value.get("reason_codes"),
        document,
        "/reason_codes",
        issues,
        minimum=1,
    )
    _require_canonical_string_order(
        reason_codes, document, "/reason_codes", issues
    )
    if reason_codes != sorted(set(check_reason_codes)):
        _issue(
            issues,
            document,
            "CAP_REASON_CODE_SET_MISMATCH",
            "/reason_codes",
            "top-level reason codes must equal the check reason-code union",
        )
    failed_checks = _string_array(
        value.get("failed_checks"),
        document,
        "/failed_checks",
        issues,
    )
    _require_canonical_string_order(
        failed_checks, document, "/failed_checks", issues
    )
    expected_failed = sorted(
        check_id
        for check_id, status in statuses.items()
        if status != "PASS"
    )
    if failed_checks != expected_failed:
        _issue(
            issues,
            document,
            "CAP_FAILED_CHECK_SET_MISMATCH",
            "/failed_checks",
            "failed_checks must list exactly the non-PASS checks",
        )
    _string_array(
        value.get("limitations"),
        document,
        "/limitations",
        issues,
        minimum=1,
    )
    _string(
        value.get("next_lawful_move"),
        document,
        "/next_lawful_move",
        issues,
    )
    domain_gate_ids = _string_array(
        value.get("domain_gate_ids"),
        document,
        "/domain_gate_ids",
        issues,
        minimum=2,
    )
    if domain_gate_ids != ["claims_gate", "path_gate"]:
        _issue(
            issues,
            document,
            "CAP_DOMAIN_GATE_SET_INVALID",
            "/domain_gate_ids",
            "claims_gate and path_gate are required in canonical order",
        )
    may_run = _boolean(
        value.get("domain_gates_may_run"),
        document,
        "/domain_gates_may_run",
        issues,
    )
    if may_run is not None and may_run != (decision == "PASS"):
        _issue(
            issues,
            document,
            "CAP_GATE_RUN_FLAG_MISMATCH",
            "/domain_gates_may_run",
            "domain gates may run only for CAP PASS",
        )
    execution_authority = _boolean(
        value.get("execution_authority"),
        document,
        "/execution_authority",
        issues,
    )
    if execution_authority is True:
        _issue(
            issues,
            document,
            "CAP_EXECUTION_AUTHORITY_FORBIDDEN",
            "/execution_authority",
            "CAP never authorizes repository execution",
        )
    if cap_id is not None:
        try:
            expected_cap_id = stable_identifier(
                "cap",
                {
                    key: child
                    for key, child in value.items()
                    if key not in {"cap_decision_id", "canonical_hash"}
                },
            )
        except (TypeError, ValueError, UnicodeError):
            _issue(
                issues,
                document,
                "CAP_DECISION_ID_DERIVATION_UNAVAILABLE",
                "/cap_decision_id",
                "malformed content prevents deterministic id derivation",
            )
        else:
            if cap_id != expected_cap_id:
                _issue(
                    issues,
                    document,
                    "CAP_DECISION_ID_MISMATCH",
                    "/cap_decision_id",
                    "CAP decision id does not match its canonical body",
                )
    return _finish(issues, raise_on_error)


def validate_gate_result(value: Any, *, raise_on_error: bool = True) -> list[ContractIssue]:
    document = "gate_result"
    issues = _validate_proof_contract(
        value,
        document=document,
        expected_version=GATE_RESULT_VERSION,
        required={
            "contract_version",
            "result_id",
            "result_hash",
            "gate_id",
            "adapter_version",
            "policy_version",
            "policy_hash",
            "change_id",
            "revision",
            "applicable",
            "required",
            "status",
            "reason_codes",
            "evidence",
            "limitations",
            "repair_actions",
        },
        hash_field="result_hash",
        raise_on_error=False,
    )
    if isinstance(value, dict):
        result_id = _string(
            value.get("result_id"), document, "/result_id", issues, pattern=TOKEN_RE
        )
        _enum(
            value.get("gate_id"),
            {"path_gate", "claims_gate"},
            document,
            "/gate_id",
            issues,
        )
        _string(value.get("adapter_version"), document, "/adapter_version", issues)
        _string(value.get("policy_version"), document, "/policy_version", issues)
        _hash_string(value.get("policy_hash"), document, "/policy_hash", issues)
        _string(value.get("change_id"), document, "/change_id", issues)
        _integer(value.get("revision"), document, "/revision", issues, minimum=0)
        applicable = _boolean(
            value.get("applicable"), document, "/applicable", issues
        )
        required = _boolean(
            value.get("required"), document, "/required", issues
        )
        status = _enum(
            value.get("status"),
            {"PASS", "BLOCK", "HOLD", "NOT_EVALUATED"},
            document,
            "/status",
            issues,
        )
        reason_codes = _string_array(
            value.get("reason_codes"), document, "/reason_codes", issues
        )
        if status == "NOT_EVALUATED":
            if applicable is not True or required is not True:
                _issue(
                    issues,
                    document,
                    "NOT_EVALUATED_GATE_FLAGS_INVALID",
                    "/status",
                    "CAP-blocked placeholders must remain applicable and required",
                )
            if reason_codes != ["CAP_NOT_PASSED"]:
                _issue(
                    issues,
                    document,
                    "NOT_EVALUATED_REASON_INVALID",
                    "/reason_codes",
                    "NOT_EVALUATED requires the canonical CAP_NOT_PASSED reason",
                )
        if not isinstance(value.get("evidence"), dict):
            _issue(
                issues,
                document,
                "TYPE_OBJECT_REQUIRED",
                "/evidence",
                "gate-specific evidence must be an object",
            )
        _string_array(value.get("limitations"), document, "/limitations", issues)
        _string_array(value.get("repair_actions"), document, "/repair_actions", issues)
        if result_id is not None:
            try:
                expected_result_id = stable_identifier(
                    f"gate-{value.get('gate_id')}",
                    {
                        "gate_id": value.get("gate_id"),
                        "policy_hash": value.get("policy_hash"),
                        "change_id": value.get("change_id"),
                        "revision": value.get("revision"),
                        "status": value.get("status"),
                        "reason_codes": value.get("reason_codes"),
                        "evidence": value.get("evidence"),
                    },
                )
            except (TypeError, ValueError, UnicodeError):
                _issue(
                    issues,
                    document,
                    "GATE_RESULT_ID_DERIVATION_UNAVAILABLE",
                    "/result_id",
                    "malformed content prevents deterministic id derivation",
                )
            else:
                if result_id != expected_result_id:
                    _issue(
                        issues,
                        document,
                        "GATE_RESULT_ID_MISMATCH",
                        "/result_id",
                        "result id does not match its canonical derivation seed",
                    )
    return _finish(issues, raise_on_error)


def _validate_cap_reference(
    value: Any,
    *,
    document: str,
    pointer: str,
    issues: list[ContractIssue],
) -> tuple[str | None, bool | None]:
    """Validate the neutral CAP reference embedded in proof contracts."""

    reference = _object(value, document, pointer, issues)
    if reference is None:
        return None, None
    _strict_keys(
        reference,
        {
            "cap_decision_id",
            "canonical_hash",
            "decision",
            "domain_gates_may_run",
            "execution_authority",
        },
        document,
        pointer,
        issues,
    )
    _string(
        reference.get("cap_decision_id"),
        document,
        f"{pointer}/cap_decision_id",
        issues,
        pattern=TOKEN_RE,
    )
    _hash_string(
        reference.get("canonical_hash"),
        document,
        f"{pointer}/canonical_hash",
        issues,
    )
    decision = _enum(
        reference.get("decision"),
        {"PASS", "BLOCK", "HOLD:CONTEXT_UPDATE_REQUIRED"},
        document,
        f"{pointer}/decision",
        issues,
    )
    may_run = _boolean(
        reference.get("domain_gates_may_run"),
        document,
        f"{pointer}/domain_gates_may_run",
        issues,
    )
    execution = _boolean(
        reference.get("execution_authority"),
        document,
        f"{pointer}/execution_authority",
        issues,
    )
    if execution is True:
        _issue(
            issues,
            document,
            "CAP_EXECUTION_AUTHORITY_FORBIDDEN",
            f"{pointer}/execution_authority",
            "CAP never authorizes repository execution",
        )
    expected_may_run = decision == "PASS" if decision is not None else None
    if (
        expected_may_run is not None
        and may_run is not None
        and may_run != expected_may_run
    ):
        _issue(
            issues,
            document,
            "CAP_GATE_RUN_FLAG_MISMATCH",
            f"{pointer}/domain_gates_may_run",
            "CAP gate-run flag must match the CAP decision",
        )
    return decision, may_run


def validate_combined_decision(
    value: Any, *, raise_on_error: bool = True
) -> list[ContractIssue]:
    document = "combined_decision"
    required = {
        "contract_version",
        "decision_id",
        "decision_hash",
        "logic_version",
        "change_id",
        "revision",
        "input_status",
        "authority_status",
        "cap_input_status",
        "cap_decision_ref",
        "domain_gates_executed",
        "required_gates",
        "gate_result_refs",
        "status",
        "reason_codes",
        "limitations",
        "next_lawful_move",
    }
    issues = _validate_proof_contract(
        value,
        document=document,
        expected_version=COMBINED_DECISION_VERSION,
        required=required,
        hash_field="decision_hash",
        raise_on_error=False,
    )
    if not isinstance(value, dict):
        return _finish(issues, raise_on_error)
    decision_id = _string(
        value.get("decision_id"),
        document,
        "/decision_id",
        issues,
        pattern=TOKEN_RE,
    )
    _string(value.get("logic_version"), document, "/logic_version", issues)
    _string(
        value.get("change_id"),
        document,
        "/change_id",
        issues,
        pattern=CHANGE_ID_RE,
    )
    _integer(value.get("revision"), document, "/revision", issues, minimum=0)
    input_status = _enum(
        value.get("input_status"),
        {"VALID", "INVALID"},
        document,
        "/input_status",
        issues,
    )
    authority_status = _enum(
        value.get("authority_status"),
        {"VALID", "MISSING", "INVALID", "STALE", "REVOKED", "UNRESOLVED"},
        document,
        "/authority_status",
        issues,
    )
    cap_input_status = _enum(
        value.get("cap_input_status"),
        {"VALID", "INVALID", "MISSING"},
        document,
        "/cap_input_status",
        issues,
    )
    cap_ref = value.get("cap_decision_ref")
    cap_decision: str | None = None
    cap_may_run: bool | None = None
    if cap_ref is not None:
        cap_decision, cap_may_run = _validate_cap_reference(
            cap_ref,
            document=document,
            pointer="/cap_decision_ref",
            issues=issues,
        )
    if cap_input_status == "VALID" and not isinstance(cap_ref, dict):
        _issue(
            issues,
            document,
            "CAP_DECISION_REF_REQUIRED",
            "/cap_decision_ref",
            "a valid CAP input requires a decision reference",
        )
    if cap_input_status in {"MISSING", "INVALID"} and cap_ref is not None:
        _issue(
            issues,
            document,
            "CAP_NONVALID_REF_FORBIDDEN",
            "/cap_decision_ref",
            "a missing or invalid CAP input cannot have a trusted reference",
        )

    domain_executed = _boolean(
        value.get("domain_gates_executed"),
        document,
        "/domain_gates_executed",
        issues,
    )
    required_gates = _string_array(
        value.get("required_gates"),
        document,
        "/required_gates",
        issues,
        minimum=2,
    )
    if required_gates != ["claims_gate", "path_gate"]:
        _issue(
            issues,
            document,
            "REQUIRED_GATE_SET_INVALID",
            "/required_gates",
            "claims_gate and path_gate are required in canonical order",
        )

    refs = _array(
        value.get("gate_result_refs"),
        document,
        "/gate_result_refs",
        issues,
        minimum=2,
    )
    ref_gate_ids: list[str] = []
    ref_statuses: dict[str, str] = {}
    ref_reasons: dict[str, list[str]] = {}
    ref_required: dict[str, bool] = {}
    if refs is not None:
        if len(refs) != 2:
            _issue(
                issues,
                document,
                "GATE_RESULT_REF_COUNT_INVALID",
                "/gate_result_refs",
                "exactly two canonical gate references are required",
            )
        for index, raw_ref in enumerate(refs):
            pointer = f"/gate_result_refs/{index}"
            ref = _object(raw_ref, document, pointer, issues)
            if ref is None:
                continue
            _strict_keys(
                ref,
                {
                    "gate_id",
                    "result_id",
                    "result_hash",
                    "status",
                    "reason_codes",
                    "required",
                },
                document,
                pointer,
                issues,
            )
            gate_id = _enum(
                ref.get("gate_id"),
                {"claims_gate", "path_gate"},
                document,
                f"{pointer}/gate_id",
                issues,
            )
            _string(
                ref.get("result_id"),
                document,
                f"{pointer}/result_id",
                issues,
                pattern=TOKEN_RE,
            )
            _hash_string(
                ref.get("result_hash"),
                document,
                f"{pointer}/result_hash",
                issues,
            )
            gate_status = _enum(
                ref.get("status"),
                {"PASS", "BLOCK", "HOLD", "NOT_EVALUATED"},
                document,
                f"{pointer}/status",
                issues,
            )
            reasons = _string_array(
                ref.get("reason_codes"),
                document,
                f"{pointer}/reason_codes",
                issues,
            )
            required_flag = _boolean(
                ref.get("required"),
                document,
                f"{pointer}/required",
                issues,
            )
            if gate_id:
                ref_gate_ids.append(gate_id)
                if gate_status:
                    ref_statuses[gate_id] = gate_status
                ref_reasons[gate_id] = reasons
                if required_flag is not None:
                    ref_required[gate_id] = required_flag
    if ref_gate_ids != ["claims_gate", "path_gate"]:
        _issue(
            issues,
            document,
            "GATE_RESULT_REF_SET_INVALID",
            "/gate_result_refs",
            "claims_gate and path_gate references are required in canonical order",
        )
    if any(flag is not True for flag in ref_required.values()) or len(
        ref_required
    ) != 2:
        _issue(
            issues,
            document,
            "REQUIRED_GATE_REF_FLAG_INVALID",
            "/gate_result_refs",
            "both gate references must be required",
        )

    cap_nonpass = (
        cap_input_status != "VALID"
        or cap_decision in {"BLOCK", "HOLD:CONTEXT_UPDATE_REQUIRED"}
    )
    if cap_nonpass:
        if domain_executed is not False:
            _issue(
                issues,
                document,
                "CAP_NONPASS_GATE_EXECUTION_FORBIDDEN",
                "/domain_gates_executed",
                "domain gates cannot execute unless CAP passes",
            )
        for gate_id in ("claims_gate", "path_gate"):
            if ref_statuses.get(gate_id) != "NOT_EVALUATED":
                _issue(
                    issues,
                    document,
                    "CAP_NONPASS_PLACEHOLDER_REQUIRED",
                    "/gate_result_refs",
                    "CAP non-PASS requires two NOT_EVALUATED gate references",
                )
                break
            if ref_reasons.get(gate_id) != ["CAP_NOT_PASSED"]:
                _issue(
                    issues,
                    document,
                    "CAP_NONPASS_REASON_INVALID",
                    "/gate_result_refs",
                    "CAP non-PASS gate references require CAP_NOT_PASSED",
                )
                break
    elif cap_decision == "PASS":
        if cap_may_run is not True:
            _issue(
                issues,
                document,
                "CAP_PASS_GATE_RUN_FLAG_INVALID",
                "/cap_decision_ref/domain_gates_may_run",
                "CAP PASS must permit domain-gate evaluation",
            )

    combined_status = _enum(
        value.get("status"),
        {"PASS", "BLOCK", "HOLD"},
        document,
        "/status",
        issues,
    )
    if (
        input_status != "VALID"
        or authority_status != "VALID"
        or cap_input_status != "VALID"
    ):
        expected_status = "BLOCK"
    elif cap_decision == "BLOCK":
        expected_status = "BLOCK"
    elif cap_decision == "HOLD:CONTEXT_UPDATE_REQUIRED":
        expected_status = "HOLD"
    elif cap_decision == "PASS":
        statuses = list(ref_statuses.values())
        if (
            domain_executed is not True
            or len(statuses) != 2
            or "NOT_EVALUATED" in statuses
        ):
            expected_status = "BLOCK"
        elif "BLOCK" in statuses:
            expected_status = "BLOCK"
        elif "HOLD" in statuses:
            expected_status = "HOLD"
        elif all(status == "PASS" for status in statuses):
            expected_status = "PASS"
        else:
            expected_status = "BLOCK"
    else:
        expected_status = "BLOCK"
    if combined_status is not None and combined_status != expected_status:
        _issue(
            issues,
            document,
            "COMBINED_STATUS_DERIVATION_MISMATCH",
            "/status",
            "combined status does not match CAP and required-gate state",
        )
    _string_array(
        value.get("reason_codes"), document, "/reason_codes", issues
    )
    _string_array(
        value.get("limitations"), document, "/limitations", issues
    )
    _string(
        value.get("next_lawful_move"),
        document,
        "/next_lawful_move",
        issues,
    )
    if decision_id is not None:
        try:
            expected_decision_id = stable_identifier(
                "decision",
                {
                    key: child
                    for key, child in value.items()
                    if key not in {"decision_id", "decision_hash"}
                },
            )
        except (TypeError, ValueError, UnicodeError):
            _issue(
                issues,
                document,
                "COMBINED_DECISION_ID_DERIVATION_UNAVAILABLE",
                "/decision_id",
                "malformed content prevents deterministic id derivation",
            )
        else:
            if decision_id != expected_decision_id:
                _issue(
                    issues,
                    document,
                    "COMBINED_DECISION_ID_MISMATCH",
                    "/decision_id",
                    "decision id does not match its canonical body",
                )
    return _finish(issues, raise_on_error)


def validate_receipt(
    value: Any, *, raise_on_error: bool = True
) -> list[ContractIssue]:
    document = "governed_receipt"
    required = {
        "contract_version",
        "receipt_id",
        "receipt_hash",
        "change_id",
        "revision",
        "decision",
        "cap_decision",
        "cap_record",
        "input_hashes",
        "policy_hashes",
        "gate_results",
        "limitations",
        "claim_boundaries",
        "next_lawful_move",
        "repair_summary",
        "repair_lineage",
    }
    issues = _validate_proof_contract(
        value,
        document=document,
        expected_version=RECEIPT_VERSION,
        required=required,
        hash_field="receipt_hash",
        raise_on_error=False,
    )
    if not isinstance(value, dict):
        return _finish(issues, raise_on_error)
    receipt_id = _string(
        value.get("receipt_id"),
        document,
        "/receipt_id",
        issues,
        pattern=TOKEN_RE,
    )
    _string(
        value.get("change_id"),
        document,
        "/change_id",
        issues,
        pattern=CHANGE_ID_RE,
    )
    _integer(value.get("revision"), document, "/revision", issues, minimum=0)

    combined = value.get("decision")
    for issue in validate_combined_decision(combined, raise_on_error=False):
        issues.append(
            ContractIssue(
                document,
                issue.code,
                f"/decision{issue.pointer}",
                issue.message,
            )
        )

    cap_decision = value.get("cap_decision")
    cap_issues: list[ContractIssue] = []
    if cap_decision is not None:
        cap_issues = validate_cap_decision(
            cap_decision, raise_on_error=False
        )
        for issue in cap_issues:
            issues.append(
                ContractIssue(
                    document,
                    issue.code,
                    f"/cap_decision{issue.pointer}",
                    issue.message,
                )
            )

    cap_record = _object(
        value.get("cap_record"), document, "/cap_record", issues
    )
    cap_input_status: str | None = None
    cap_input_hash: Any = None
    cap_ref: Any = None
    cap_ref_decision: str | None = None
    cap_domain_executed: bool | None = None
    if cap_record is not None:
        _strict_keys(
            cap_record,
            {
                "input_status",
                "input_hash",
                "decision_ref",
                "domain_gates_executed",
                "execution_authority",
            },
            document,
            "/cap_record",
            issues,
        )
        cap_input_status = _enum(
            cap_record.get("input_status"),
            {"VALID", "INVALID", "MISSING"},
            document,
            "/cap_record/input_status",
            issues,
        )
        cap_input_hash = cap_record.get("input_hash")
        _hash_string(
            cap_input_hash,
            document,
            "/cap_record/input_hash",
            issues,
        )
        cap_ref = cap_record.get("decision_ref")
        if cap_ref is not None:
            cap_ref_decision, _ = _validate_cap_reference(
                cap_ref,
                document=document,
                pointer="/cap_record/decision_ref",
                issues=issues,
            )
        cap_domain_executed = _boolean(
            cap_record.get("domain_gates_executed"),
            document,
            "/cap_record/domain_gates_executed",
            issues,
        )
        execution = _boolean(
            cap_record.get("execution_authority"),
            document,
            "/cap_record/execution_authority",
            issues,
        )
        if execution is True:
            _issue(
                issues,
                document,
                "CAP_RECORD_EXECUTION_AUTHORITY_FORBIDDEN",
                "/cap_record/execution_authority",
                "receipt CAP record cannot authorize repository execution",
            )
        if cap_input_status == "VALID" and not isinstance(cap_ref, dict):
            _issue(
                issues,
                document,
                "CAP_RECORD_VALID_REF_REQUIRED",
                "/cap_record/decision_ref",
                "a valid CAP record requires a decision reference",
            )
        if cap_input_status in {"INVALID", "MISSING"} and cap_ref is not None:
            _issue(
                issues,
                document,
                "CAP_RECORD_NONVALID_REF_FORBIDDEN",
                "/cap_record/decision_ref",
                "a missing or invalid CAP input cannot have a trusted reference",
            )

    input_hashes = value.get("input_hashes")
    _validate_hash_map(
        input_hashes,
        {
            "authority_manifest",
            "cap_decision",
            "cap_policy",
            "shared_change_envelope",
        },
        document,
        "/input_hashes",
        issues,
    )
    policy_hashes = value.get("policy_hashes")
    _validate_hash_map(
        policy_hashes,
        {"cap_policy", "claims_gate", "path_gate"},
        document,
        "/policy_hashes",
        issues,
    )
    if isinstance(input_hashes, dict) and cap_record is not None:
        if input_hashes.get("cap_decision") != cap_input_hash:
            _issue(
                issues,
                document,
                "CAP_INPUT_HASH_RECORD_MISMATCH",
                "/input_hashes/cap_decision",
                "receipt input hash must match the CAP record",
            )

    results = _array(
        value.get("gate_results"),
        document,
        "/gate_results",
        issues,
        minimum=2,
    )
    result_by_gate: dict[str, dict[str, Any]] = {}
    result_order: list[str] = []
    if results is not None:
        if len(results) != 2:
            _issue(
                issues,
                document,
                "GATE_RESULT_COUNT_INVALID",
                "/gate_results",
                "exactly two canonical gate results are required",
            )
        for index, result in enumerate(results):
            for issue in validate_gate_result(result, raise_on_error=False):
                issues.append(
                    ContractIssue(
                        document,
                        issue.code,
                        f"/gate_results/{index}{issue.pointer}",
                        issue.message,
                    )
                )
            if isinstance(result, dict) and isinstance(
                result.get("gate_id"), str
            ):
                gate_id = result["gate_id"]
                result_order.append(gate_id)
                if gate_id in result_by_gate:
                    _issue(
                        issues,
                        document,
                        "GATE_RESULT_DUPLICATE",
                        "/gate_results",
                        "gate results must be unique by gate id",
                    )
                result_by_gate[gate_id] = result
    if result_order != ["claims_gate", "path_gate"]:
        _issue(
            issues,
            document,
            "GATE_RESULT_SET_INVALID",
            "/gate_results",
            "claims_gate and path_gate results are required in canonical order",
        )

    cap_nonpass = (
        cap_input_status != "VALID"
        or cap_ref_decision in {"BLOCK", "HOLD:CONTEXT_UPDATE_REQUIRED"}
    )
    if cap_nonpass:
        if cap_domain_executed is not False:
            _issue(
                issues,
                document,
                "CAP_NONPASS_GATE_EXECUTION_FORBIDDEN",
                "/cap_record/domain_gates_executed",
                "domain gates cannot execute unless CAP passes",
            )
        for gate_id in ("claims_gate", "path_gate"):
            result = result_by_gate.get(gate_id, {})
            if (
                result.get("status") != "NOT_EVALUATED"
                or result.get("reason_codes") != ["CAP_NOT_PASSED"]
            ):
                _issue(
                    issues,
                    document,
                    "CAP_NONPASS_GATE_RESULT_INVALID",
                    "/gate_results",
                    "CAP non-PASS requires two canonical NOT_EVALUATED/CAP_NOT_PASSED results",
                )
                break
    if (
        cap_ref_decision == "PASS"
        and any(
            result.get("status") == "NOT_EVALUATED"
            for result in result_by_gate.values()
        )
        and isinstance(combined, dict)
        and combined.get("status") != "BLOCK"
    ):
        _issue(
            issues,
            document,
            "CAP_PASS_NOT_EVALUATED_MUST_BLOCK",
            "/decision/status",
            "an unexpected NOT_EVALUATED result after CAP PASS must combine to BLOCK",
        )

    _string_array(
        value.get("limitations"), document, "/limitations", issues
    )
    _string_array(
        value.get("claim_boundaries"),
        document,
        "/claim_boundaries",
        issues,
        minimum=1,
    )
    _string(
        value.get("next_lawful_move"),
        document,
        "/next_lawful_move",
        issues,
    )
    repair_summary = value.get("repair_summary")
    if repair_summary is not None:
        _string(
            repair_summary,
            document,
            "/repair_summary",
            issues,
            allow_empty=True,
        )
    _validate_repair_lineage(
        value.get("repair_lineage"), document, issues
    )

    if isinstance(combined, dict):
        if value.get("change_id") != combined.get("change_id"):
            _issue(
                issues,
                document,
                "RECEIPT_DECISION_CHANGE_ID_MISMATCH",
                "/change_id",
                "receipt and decision change ids must match",
            )
        if value.get("revision") != combined.get("revision"):
            _issue(
                issues,
                document,
                "RECEIPT_DECISION_REVISION_MISMATCH",
                "/revision",
                "receipt and decision revisions must match",
            )
        refs = combined.get("gate_result_refs")
        if isinstance(refs, list):
            for index, ref in enumerate(refs):
                if not isinstance(ref, dict):
                    continue
                result = result_by_gate.get(ref.get("gate_id"))
                if result is None:
                    _issue(
                        issues,
                        document,
                        "DECISION_GATE_RESULT_MISSING",
                        f"/decision/gate_result_refs/{index}",
                        "decision references a missing gate result",
                    )
                    continue
                expected_ref = {
                    "gate_id": result.get("gate_id"),
                    "result_id": result.get("result_id"),
                    "result_hash": result.get("result_hash"),
                    "status": result.get("status"),
                    "reason_codes": result.get("reason_codes"),
                    "required": result.get("required"),
                }
                if ref != expected_ref:
                    _issue(
                        issues,
                        document,
                        "DECISION_GATE_RESULT_REF_MISMATCH",
                        f"/decision/gate_result_refs/{index}",
                        "decision reference does not match embedded gate result",
                    )
        if cap_record is not None:
            if cap_input_status != combined.get("cap_input_status"):
                _issue(
                    issues,
                    document,
                    "CAP_RECORD_INPUT_STATUS_MISMATCH",
                    "/cap_record/input_status",
                    "CAP record and combined decision input status must match",
                )
            if cap_ref != combined.get("cap_decision_ref"):
                _issue(
                    issues,
                    document,
                    "CAP_RECORD_DECISION_REF_MISMATCH",
                    "/cap_record/decision_ref",
                    "CAP record and combined decision reference must match",
                )
            if cap_domain_executed != combined.get(
                "domain_gates_executed"
            ):
                _issue(
                    issues,
                    document,
                    "CAP_RECORD_GATE_EXECUTION_MISMATCH",
                    "/cap_record/domain_gates_executed",
                    "CAP record and combined decision gate execution must match",
                )

    if cap_input_status == "VALID":
        if not isinstance(cap_decision, dict) or cap_issues:
            _issue(
                issues,
                document,
                "VALID_CAP_DECISION_REQUIRED",
                "/cap_decision",
                "a VALID CAP record requires a valid embedded CAP decision",
            )
        else:
            expected_cap_ref = {
                "cap_decision_id": cap_decision.get("cap_decision_id"),
                "canonical_hash": cap_decision.get("canonical_hash"),
                "decision": cap_decision.get("decision"),
                "domain_gates_may_run": cap_decision.get(
                    "domain_gates_may_run"
                ),
                "execution_authority": cap_decision.get(
                    "execution_authority"
                ),
            }
            if cap_ref != expected_cap_ref:
                _issue(
                    issues,
                    document,
                    "CAP_RECORD_EMBEDDED_DECISION_MISMATCH",
                    "/cap_record/decision_ref",
                    "CAP record does not reference the embedded CAP decision",
                )
            expected_cap_input_hash = canonical_hash_or_fingerprint(
                cap_decision
            )
            if cap_input_hash != expected_cap_input_hash:
                _issue(
                    issues,
                    document,
                    "CAP_RECORD_INPUT_HASH_MISMATCH",
                    "/cap_record/input_hash",
                    "CAP record hash does not bind the embedded CAP decision",
                )
            if isinstance(input_hashes, dict):
                authority_reference = cap_decision.get(
                    "authority_manifest_reference"
                )
                if (
                    isinstance(authority_reference, dict)
                    and authority_reference.get("manifest_hash")
                    != input_hashes.get("authority_manifest")
                ):
                    _issue(
                        issues,
                        document,
                        "CAP_AUTHORITY_INPUT_HASH_MISMATCH",
                        "/cap_decision/authority_manifest_reference/manifest_hash",
                        "CAP and receipt must bind the same authority input",
                    )
                if (
                    cap_decision.get("shared_change_envelope_hash")
                    != input_hashes.get("shared_change_envelope")
                ):
                    _issue(
                        issues,
                        document,
                        "CAP_ENVELOPE_INPUT_HASH_MISMATCH",
                        "/cap_decision/shared_change_envelope_hash",
                        "CAP and receipt must bind the same envelope input",
                    )
            if value.get("change_id") != cap_decision.get("change_id"):
                _issue(
                    issues,
                    document,
                    "RECEIPT_CAP_CHANGE_ID_MISMATCH",
                    "/change_id",
                    "receipt and CAP change ids must match",
                )
            if value.get("revision") != cap_decision.get("revision"):
                _issue(
                    issues,
                    document,
                    "RECEIPT_CAP_REVISION_MISMATCH",
                    "/revision",
                    "receipt and CAP revisions must match",
                )
    elif cap_input_status in {"MISSING", "INVALID"}:
        if cap_decision is not None:
            _issue(
                issues,
                document,
                "NONVALID_CAP_DECISION_MUST_BE_NULL",
                "/cap_decision",
                "missing or invalid CAP input is represented by null",
            )
        if cap_input_status == "MISSING":
            expected_missing = canonical_hash_or_fingerprint(None)
            if cap_input_hash != expected_missing:
                _issue(
                    issues,
                    document,
                    "MISSING_CAP_INPUT_HASH_MISMATCH",
                    "/cap_record/input_hash",
                    "missing CAP input must use the canonical null hash",
                )

    if isinstance(policy_hashes, dict):
        for gate_id, result in result_by_gate.items():
            if policy_hashes.get(gate_id) != result.get("policy_hash"):
                _issue(
                    issues,
                    document,
                    "RECEIPT_POLICY_HASH_MISMATCH",
                    f"/policy_hashes/{gate_id}",
                    "receipt policy hash does not match gate result",
                )
        if isinstance(cap_decision, dict):
            policy_basis = cap_decision.get("policy_basis")
            if isinstance(policy_basis, dict):
                for policy_key in ("cap_policy", "claims_gate", "path_gate"):
                    reference = policy_basis.get(policy_key)
                    if (
                        isinstance(reference, dict)
                        and reference.get("policy_hash")
                        != policy_hashes.get(policy_key)
                    ):
                        _issue(
                            issues,
                            document,
                            "CAP_POLICY_HASH_MISMATCH",
                            f"/policy_hashes/{policy_key}",
                            "CAP and receipt policy hashes must match",
                        )

    lineage = value.get("repair_lineage")
    if lineage is None:
        if repair_summary is not None:
            _issue(
                issues,
                document,
                "REPAIR_SUMMARY_WITHOUT_LINEAGE",
                "/repair_summary",
                "repair_summary must be null without repair lineage",
            )
    elif isinstance(lineage, dict):
        if not isinstance(repair_summary, str) or not repair_summary:
            _issue(
                issues,
                document,
                "REPAIR_SUMMARY_REQUIRED",
                "/repair_summary",
                "a repaired receipt requires a non-empty repair summary",
            )
        changed = lineage.get("changed_input_hashes")
        if isinstance(changed, dict) and isinstance(input_hashes, dict):
            if (
                changed.get("current_shared_change_envelope")
                != input_hashes.get("shared_change_envelope")
            ):
                _issue(
                    issues,
                    document,
                    "REPAIR_CURRENT_ENVELOPE_HASH_MISMATCH",
                    "/repair_lineage/changed_input_hashes/current_shared_change_envelope",
                    "repair lineage must bind the current envelope hash",
                )
            if (
                changed.get("current_cap_decision")
                != input_hashes.get("cap_decision")
            ):
                _issue(
                    issues,
                    document,
                    "REPAIR_CURRENT_CAP_HASH_MISMATCH",
                    "/repair_lineage/changed_input_hashes/current_cap_decision",
                    "repair lineage must bind the current CAP input hash",
                )
            if (
                changed.get("prior_shared_change_envelope")
                == changed.get("current_shared_change_envelope")
            ):
                _issue(
                    issues,
                    document,
                    "REPAIR_ENVELOPE_HASH_UNCHANGED",
                    "/repair_lineage/changed_input_hashes",
                    "repair lineage must identify a changed envelope input",
                )
            if changed.get("prior_cap_decision") == changed.get(
                "current_cap_decision"
            ):
                _issue(
                    issues,
                    document,
                    "REPAIR_CAP_HASH_UNCHANGED",
                    "/repair_lineage/changed_input_hashes",
                    "repair lineage must identify a rechecked CAP input",
                )
        unchanged = lineage.get("unchanged_policy_hashes")
        if (
            isinstance(unchanged, dict)
            and isinstance(policy_hashes, dict)
            and unchanged != policy_hashes
        ):
            _issue(
                issues,
                document,
                "REPAIR_POLICY_HASHES_CHANGED",
                "/repair_lineage/unchanged_policy_hashes",
                "repair lineage must preserve all three policy hashes",
            )
        prior_revision = lineage.get("prior_revision")
        if (
            isinstance(prior_revision, int)
            and isinstance(value.get("revision"), int)
            and prior_revision >= value["revision"]
        ):
            _issue(
                issues,
                document,
                "REPAIR_REVISION_NOT_ADVANCED",
                "/repair_lineage/prior_revision",
                "repair revision must advance beyond the prior revision",
            )

    if receipt_id is not None:
        try:
            expected_receipt_id = stable_identifier(
                "receipt",
                {
                    key: child
                    for key, child in value.items()
                    if key not in {"receipt_id", "receipt_hash"}
                },
            )
        except (TypeError, ValueError, UnicodeError):
            _issue(
                issues,
                document,
                "RECEIPT_ID_DERIVATION_UNAVAILABLE",
                "/receipt_id",
                "malformed content prevents deterministic id derivation",
            )
        else:
            if receipt_id != expected_receipt_id:
                _issue(
                    issues,
                    document,
                    "RECEIPT_ID_MISMATCH",
                    "/receipt_id",
                    "receipt id does not match its canonical body",
                )
    return _finish(issues, raise_on_error)


def _hash_string(
    value: Any,
    document: str,
    pointer: str,
    issues: list[ContractIssue],
) -> None:
    if not isinstance(value, str) or not HASH_RE.fullmatch(value):
        _issue(issues, document, "HASH_FORMAT_INVALID", pointer, "invalid SHA-256")


def _validate_hash_map(
    value: Any,
    required: set[str],
    document: str,
    pointer: str,
    issues: list[ContractIssue],
) -> None:
    obj = _object(value, document, pointer, issues)
    if obj is None:
        return
    _strict_keys(obj, required, document, pointer, issues)
    for key in sorted(required):
        _hash_string(obj.get(key), document, f"{pointer}/{key}", issues)


def _validate_repair_lineage(
    value: Any,
    document: str,
    issues: list[ContractIssue],
) -> None:
    if value is None:
        return
    pointer = "/repair_lineage"
    obj = _object(value, document, pointer, issues)
    if obj is None:
        return
    required = {
        "relationship",
        "prior_receipt_id",
        "prior_receipt_hash",
        "prior_revision",
        "cap_rechecked",
        "changed_input_hashes",
        "unchanged_policy_hashes",
    }
    _strict_keys(obj, required, document, pointer, issues)
    if obj.get("relationship") != "BOUNDED_REPAIR_OF":
        _issue(
            issues,
            document,
            "REPAIR_RELATIONSHIP_INVALID",
            f"{pointer}/relationship",
            "expected BOUNDED_REPAIR_OF",
        )
    _string(
        obj.get("prior_receipt_id"),
        document,
        f"{pointer}/prior_receipt_id",
        issues,
        pattern=TOKEN_RE,
    )
    _hash_string(
        obj.get("prior_receipt_hash"),
        document,
        f"{pointer}/prior_receipt_hash",
        issues,
    )
    _integer(
        obj.get("prior_revision"),
        document,
        f"{pointer}/prior_revision",
        issues,
        minimum=1,
    )
    cap_rechecked = _boolean(
        obj.get("cap_rechecked"),
        document,
        f"{pointer}/cap_rechecked",
        issues,
    )
    if cap_rechecked is False:
        _issue(
            issues,
            document,
            "CAP_RECHECK_REQUIRED",
            f"{pointer}/cap_rechecked",
            "bounded repair requires a fresh CAP check",
        )
    _validate_hash_map(
        obj.get("changed_input_hashes"),
        {
            "prior_shared_change_envelope",
            "current_shared_change_envelope",
            "prior_cap_decision",
            "current_cap_decision",
        },
        document,
        f"{pointer}/changed_input_hashes",
        issues,
    )
    _validate_hash_map(
        obj.get("unchanged_policy_hashes"),
        {"cap_policy", "claims_gate", "path_gate"},
        document,
        f"{pointer}/unchanged_policy_hashes",
        issues,
    )


def _validate_proof_contract(
    value: Any,
    *,
    document: str,
    expected_version: str,
    required: set[str],
    hash_field: str,
    raise_on_error: bool,
) -> list[ContractIssue]:
    issues: list[ContractIssue] = []
    obj = _object(value, document, "", issues)
    if obj is None:
        return _finish(issues, raise_on_error)
    _strict_keys(obj, required, document, "", issues)
    _version(obj.get("contract_version"), expected_version, document, issues)
    embedded_hash = obj.get(hash_field)
    if not isinstance(embedded_hash, str) or not HASH_RE.fullmatch(embedded_hash):
        _issue(issues, document, "HASH_FORMAT_INVALID", f"/{hash_field}", "invalid SHA-256")
    elif not verify_embedded_hash(obj, hash_field):
        _issue(
            issues,
            document,
            "EMBEDDED_HASH_MISMATCH",
            f"/{hash_field}",
            "embedded hash does not match canonical content",
        )
    return _finish(issues, raise_on_error)


def _finish(
    issues: list[ContractIssue], raise_on_error: bool
) -> list[ContractIssue]:
    if issues and raise_on_error:
        raise ContractValidationError(issues)
    return issues


VALIDATORS: dict[str, Callable[..., list[ContractIssue]]] = {
    "envelope": validate_envelope,
    "authority": validate_authority,
    "cap_decision": validate_cap_decision,
    "gate_result": validate_gate_result,
    "combined_decision": validate_combined_decision,
    "receipt": validate_receipt,
}


def validate_contract(kind: str, value: Any) -> list[ContractIssue]:
    if kind not in VALIDATORS:
        raise KeyError(f"unknown contract kind: {kind}")
    return VALIDATORS[kind](value, raise_on_error=False)
