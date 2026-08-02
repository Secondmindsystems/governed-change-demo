"""Deterministic repository-path jurisdiction adapter."""

from __future__ import annotations

import re
from typing import Any

from .contracts import parse_utc
from .gate_result import build_gate_result


ADAPTER_VERSION = "governed-repo.path-gate-adapter/v1.0.0"
_DRIVE_RE = re.compile(r"^[A-Za-z]:")
_URI_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
_CASE_MODES = {"SENSITIVE", "INSENSITIVE"}
_MATCH_MODES = {"EXACT", "SUBTREE"}


class PathFormError(ValueError):
    pass


def normalize_repo_path(raw: Any) -> str:
    if not isinstance(raw, str) or not raw:
        raise PathFormError("path must be a non-empty string")
    if any(
        ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        for character in raw
    ):
        raise PathFormError("C0, C1, and DEL control characters are not allowed")
    path = raw.replace("\\", "/")
    if path.startswith("//"):
        raise PathFormError("UNC path is not allowed")
    if path.startswith("/"):
        raise PathFormError("absolute path is not allowed")
    if _DRIVE_RE.match(path):
        raise PathFormError("drive-qualified path is not allowed")
    if _URI_SCHEME_RE.match(path):
        raise PathFormError("URI-shaped path is not allowed")
    parts: list[str] = []
    for part in path.split("/"):
        if part == ".":
            continue
        if not part:
            raise PathFormError("empty path segments are not allowed")
        if part == "..":
            raise PathFormError("parent traversal is not allowed")
        parts.append(part)
    if not parts:
        raise PathFormError("path resolves to an empty value")
    return "/".join(parts)


def _fold(value: str, case_mode: str) -> str:
    if case_mode == "INSENSITIVE":
        return value.casefold()
    if case_mode == "SENSITIVE":
        return value
    raise PathFormError("unknown case mode")


def path_matches(candidate: str, rule_path: str, match: str, case_mode: str) -> bool:
    candidate_cmp = _fold(candidate, case_mode)
    rule_cmp = _fold(rule_path, case_mode)
    if match == "EXACT":
        return candidate_cmp == rule_cmp
    if match == "SUBTREE":
        return candidate_cmp == rule_cmp or candidate_cmp.startswith(rule_cmp + "/")
    raise PathFormError("unknown path match mode")


def _gate_config(authority: dict[str, Any]) -> tuple[bool, bool]:
    for item in authority["applicable_gates"]:
        if item["gate_id"] == "path_gate":
            return True, item["required"]
    return False, False


def evaluate_path_gate(
    envelope: dict[str, Any],
    authority: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    applicable, required = _gate_config(authority)
    change_id = envelope["change_id"]
    revision = envelope["revision"]
    reasons: list[str] = []
    repairs: list[str] = []
    invalid_paths: list[dict[str, str]] = []
    endpoints: list[dict[str, str]] = []
    authority_matches: list[dict[str, Any]] = []
    denied_paths: list[str] = []
    action_denials: list[dict[str, str]] = []
    protected_hits: list[dict[str, Any]] = []

    if not applicable:
        return build_gate_result(
            gate_id="path_gate",
            adapter_version=ADAPTER_VERSION,
            policy_version=policy["policy_version"],
            policy=policy,
            change_id=change_id,
            revision=revision,
            applicable=False,
            required=False,
            status="PASS",
            reason_codes=["GATE_NOT_APPLICABLE"],
            evidence={
                "proposed_paths": [],
                "normalized_paths": [],
                "evaluated_endpoints": [],
                "authority_matches": [],
                "denied_paths": [],
                "action_denials": [],
                "protected_hits": [],
                "invalid_paths": [],
                "checks_run": [],
                "case_mode": policy["case_mode"],
                "rename_semantics": policy["rename_semantics"],
            },
            limitations=["No path-jurisdiction conclusion was made because the gate was not applicable."],
            repair_actions=[],
        )

    evaluation_as_of = parse_utc(envelope.get("evaluation_as_of"))
    issued = parse_utc(authority["issued_at"])
    expires = parse_utc(authority["expires_at"])
    if envelope["authority_ref"] != authority["manifest_id"]:
        reasons.append("AUTHORITY_REFERENCE_MISMATCH")
    if envelope["actor"]["actor_id"] not in authority["subject_actor_ids"]:
        reasons.append("ACTOR_NOT_AUTHORIZED")
    if (
        evaluation_as_of is None
        or issued is None
        or expires is None
        or not (issued <= evaluation_as_of < expires)
    ):
        reasons.append("AUTHORITY_STALE")
    if authority["state"] == "REVOKED":
        reasons.append("AUTHORITY_REVOKED")
    authority_hold = authority["state"] == "PENDING_REVIEW"
    if authority_hold:
        reasons.append("AUTHORITY_EXPLICITLY_UNRESOLVED")

    case_mode = policy.get("case_mode")
    if case_mode not in _CASE_MODES:
        reasons.append("PATH_POLICY_CASE_MODE_INVALID")
        effective_case_mode = "SENSITIVE"
    else:
        effective_case_mode = case_mode
    normalized_authority_rules: list[dict[str, Any]] = []
    for rule in authority["permitted_paths"]:
        if rule.get("match") not in _MATCH_MODES:
            reasons.append("AUTHORITY_PATH_MATCH_MODE_INVALID")
            continue
        try:
            normalized_rule_path = normalize_repo_path(rule.get("path"))
        except PathFormError:
            reasons.append("AUTHORITY_PATH_RULE_INVALID")
            continue
        normalized_authority_rules.append({**rule, "path": normalized_rule_path})

    normalized_protected_rules: list[dict[str, str]] = []
    for rule in policy["protected_rules"]:
        if rule.get("match") not in _MATCH_MODES:
            reasons.append("PATH_POLICY_MATCH_MODE_INVALID")
            continue
        try:
            normalized_rule_path = normalize_repo_path(rule.get("path"))
        except PathFormError:
            reasons.append("PATH_POLICY_RULE_INVALID")
            continue
        normalized_protected_rules.append({**rule, "path": normalized_rule_path})
    for index, raw_path in enumerate(policy["self_protected_paths"]):
        try:
            normalized_path = normalize_repo_path(raw_path)
        except PathFormError:
            reasons.append("PATH_POLICY_SELF_PROTECTION_INVALID")
            continue
        normalized_protected_rules.append(
            {
                "rule_id": f"self-protected-{index + 1:02d}",
                "path": normalized_path,
                "match": "SUBTREE",
            }
        )

    proposed_paths: list[str] = []
    for change in envelope["changes"]:
        raw_endpoints = [("source", change["path"])]
        if change["operation"] == "RENAME":
            raw_endpoints.append(("destination", change["destination_path"]))
        for endpoint_role, raw_path in raw_endpoints:
            proposed_paths.append(str(raw_path))
            try:
                normalized = normalize_repo_path(raw_path)
            except PathFormError as exc:
                invalid_paths.append(
                    {
                        "path": str(raw_path),
                        "endpoint_role": endpoint_role,
                        "reason": str(exc),
                    }
                )
                reasons.append("PATH_FORM_INVALID")
                continue
            endpoint = {
                "operation": change["operation"],
                "endpoint_role": endpoint_role,
                "proposed_path": raw_path,
                "normalized_path": normalized,
            }
            endpoints.append(endpoint)

            matching_authority = [
                rule
                for rule in normalized_authority_rules
                if path_matches(
                    normalized,
                    rule["path"],
                    rule["match"],
                    effective_case_mode,
                )
            ]
            matching_authority = sorted(matching_authority, key=lambda item: item["rule_id"])
            action_matches = [
                rule
                for rule in matching_authority
                if change["operation"] in rule["actions"]
                and change["operation"] in authority["permitted_actions"]
            ]
            authority_matches.append(
                {
                    "path": normalized,
                    "operation": change["operation"],
                    "matching_rule_ids": [rule["rule_id"] for rule in matching_authority],
                    "action_rule_ids": [rule["rule_id"] for rule in action_matches],
                }
            )
            if not matching_authority:
                denied_paths.append(normalized)
                reasons.append("PATH_OUTSIDE_AUTHORITY")
                repairs.append("Move the change to a manifest-permitted repository path.")
            elif not action_matches:
                action_denials.append(
                    {"path": normalized, "operation": change["operation"]}
                )
                reasons.append("ACTION_OUTSIDE_AUTHORITY")
                repairs.append("Use only an action explicitly permitted for the target path.")

            matched_protected = [
                rule
                for rule in normalized_protected_rules
                if path_matches(
                    normalized,
                    rule["path"],
                    rule["match"],
                    effective_case_mode,
                )
            ]
            if matched_protected:
                protected_override_rules = [
                    rule["rule_id"] for rule in action_matches if rule["allow_protected"]
                ]
                protected_hits.append(
                    {
                        "path": normalized,
                        "policy_rule_ids": sorted(rule["rule_id"] for rule in matched_protected),
                        "authority_override_rule_ids": sorted(protected_override_rules),
                    }
                )
                if not protected_override_rules:
                    reasons.append("PROTECTED_PATH_BLOCKED")
                    repairs.append(
                        "Remove the protected-path write or obtain an explicit bounded authority rule."
                    )

    hard_block_reasons = [reason for reason in reasons if reason != "AUTHORITY_EXPLICITLY_UNRESOLVED"]
    if hard_block_reasons:
        status = "BLOCK"
    elif authority_hold:
        status = "HOLD"
    else:
        status = "PASS"
        reasons.append("PATH_JURISDICTION_SATISFIED")

    evidence = {
        "proposed_paths": sorted(proposed_paths),
        "normalized_paths": sorted({item["normalized_path"] for item in endpoints}),
        "evaluated_endpoints": sorted(
            endpoints,
            key=lambda item: (
                item["normalized_path"],
                item["operation"],
                item["endpoint_role"],
            ),
        ),
        "authority_matches": sorted(authority_matches, key=lambda item: item["path"]),
        "denied_paths": sorted(set(denied_paths)),
        "action_denials": sorted(
            action_denials, key=lambda item: (item["path"], item["operation"])
        ),
        "protected_hits": sorted(protected_hits, key=lambda item: item["path"]),
        "invalid_paths": sorted(
            invalid_paths, key=lambda item: (item["path"], item["endpoint_role"])
        ),
        "checks_run": [
            "authority_action_check",
            "authority_path_check",
            "canonical_path_check",
            "policy_self_protection_check",
            "protected_prefix_check",
            "rename_endpoint_check",
        ],
        "case_mode": case_mode,
        "rename_semantics": policy["rename_semantics"],
    }
    return build_gate_result(
        gate_id="path_gate",
        adapter_version=ADAPTER_VERSION,
        policy_version=policy["policy_version"],
        policy=policy,
        change_id=change_id,
        revision=revision,
        applicable=True,
        required=required,
        status=status,
        reason_codes=reasons,
        evidence=evidence,
        limitations=[
            "This adapter evaluates declared paths and actions; it does not enforce filesystem or Git operations.",
            "Protected-path matching is a product-local deterministic policy check, not a security claim.",
        ],
        repair_actions=repairs,
    )
