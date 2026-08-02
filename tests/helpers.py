from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
from typing import Any

from governed_change_demo.cap_adapter import build_cap_decision
from governed_change_demo.policies import policy_content_hash


ROOT = Path(__file__).resolve().parents[1]
POLICY_KEYS = ("cap_policy", "path_gate", "claims_gate")


def load(relative: str) -> Any:
    return json.loads((ROOT / relative).read_text(encoding="utf-8"))


def inputs(
    name: str = "blocked",
) -> tuple[dict, dict, dict, dict, dict]:
    """Return envelope, authority, and the three canonical policy payloads."""

    authority_name = (
        "hold-authority-manifest.json"
        if name == "hold"
        else "authority-manifest.json"
    )
    return (
        deepcopy(load(f"fixtures/{name}-envelope.json")),
        deepcopy(load(f"fixtures/{authority_name}")),
        deepcopy(load("policies/cap-policy.v1.json")),
        deepcopy(load("policies/path-policy.v1.json")),
        deepcopy(load("policies/claims-policy.v1.json")),
    )


def bind_policy(
    policy_key: str,
    policy: dict,
    envelope: dict,
    authority: dict,
) -> str:
    """Recompute one policy payload hash and update both declared bindings."""

    if policy_key not in POLICY_KEYS:
        raise ValueError(f"unknown policy key: {policy_key}")
    digest = policy_content_hash(policy)
    policy["policy_hash"] = digest
    envelope["policy_hashes"][policy_key] = digest
    authority["policy_hashes"][policy_key] = digest
    envelope["policy_versions"][policy_key] = policy["policy_version"]
    authority["policy_versions"][policy_key] = policy["policy_version"]
    return digest


def cap_for(
    envelope: dict,
    authority: dict,
    cap_policy: dict,
    path_policy: dict,
    claims_policy: dict,
) -> dict:
    return build_cap_decision(
        envelope,
        authority,
        cap_policy,
        path_policy,
        claims_policy,
    )


def evaluation_bundle(
    name: str = "blocked",
) -> tuple[dict, dict, dict, dict, dict, dict]:
    """Return the active six-contract evaluation bundle.

    Static historical CAP result fixtures are intentionally not consumed.
    Every test derives CAP mechanically from the candidate snapshot, authority,
    and canonical policy payloads.
    """

    envelope, authority, cap_policy, path_policy, claims_policy = inputs(name)
    cap_decision = cap_for(
        envelope,
        authority,
        cap_policy,
        path_policy,
        claims_policy,
    )
    return (
        envelope,
        authority,
        cap_decision,
        cap_policy,
        path_policy,
        claims_policy,
    )


def bundle(
    name: str = "blocked",
) -> tuple[dict, dict, dict, dict, dict]:
    """Return the domain-gate helper shape retained for adapter tests."""

    (
        envelope,
        authority,
        cap_decision,
        _,
        path_policy,
        claims_policy,
    ) = evaluation_bundle(name)
    return (
        envelope,
        authority,
        cap_decision,
        path_policy,
        claims_policy,
    )


def pass_bundle() -> tuple[dict, dict, dict, dict, dict, dict]:
    """Return a revision-one CAP/domain-gate PASS candidate without lineage."""

    envelope, authority, cap_policy, path_policy, claims_policy = inputs(
        "repaired"
    )
    envelope["revision"] = 1
    envelope["fixture"]["state"] = "ORIGINAL_BLOCK"
    envelope["repair_summary"] = None
    cap_decision = cap_for(
        envelope,
        authority,
        cap_policy,
        path_policy,
        claims_policy,
    )
    return (
        envelope,
        authority,
        cap_decision,
        cap_policy,
        path_policy,
        claims_policy,
    )
