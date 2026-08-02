"""Shared gate-result construction with heterogeneous evidence preserved."""

from __future__ import annotations

from typing import Any, Iterable

from .canonical import (
    canonical_hash_or_fingerprint,
    hash_without_fields,
    stable_identifier,
)
from .contracts import GATE_RESULT_VERSION
from .policies import policy_content_hash


def build_gate_result(
    *,
    gate_id: str,
    adapter_version: str,
    policy_version: str,
    policy: Any,
    change_id: str,
    revision: int,
    applicable: bool,
    required: bool,
    status: str,
    reason_codes: Iterable[str],
    evidence: dict[str, Any],
    limitations: Iterable[str],
    repair_actions: Iterable[str],
) -> dict[str, Any]:
    normalized_reason_codes = sorted(set(reason_codes))
    normalized_limitations = sorted(set(limitations))
    normalized_repair_actions = sorted(set(repair_actions))
    try:
        policy_hash = policy_content_hash(policy)
    except (TypeError, ValueError, UnicodeError):
        policy_hash = canonical_hash_or_fingerprint(policy)
    seed = {
        "gate_id": gate_id,
        "policy_hash": policy_hash,
        "change_id": change_id,
        "revision": revision,
        "status": status,
        "reason_codes": normalized_reason_codes,
        "evidence": evidence,
    }
    result = {
        "contract_version": GATE_RESULT_VERSION,
        "result_id": stable_identifier(f"gate-{gate_id}", seed),
        "result_hash": "",
        "gate_id": gate_id,
        "adapter_version": adapter_version,
        "policy_version": policy_version,
        "policy_hash": policy_hash,
        "change_id": change_id,
        "revision": revision,
        "applicable": applicable,
        "required": required,
        "status": status,
        "reason_codes": normalized_reason_codes,
        "evidence": evidence,
        "limitations": normalized_limitations,
        "repair_actions": normalized_repair_actions,
    }
    result["result_hash"] = hash_without_fields(result, {"result_hash"})
    return result
