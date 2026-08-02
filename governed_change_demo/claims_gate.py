"""Deterministic structured-claim and evidence adapter."""

from __future__ import annotations

from typing import Any

from .canonical import canonical_hash
from .contracts import parse_utc
from .gate_result import build_gate_result


ADAPTER_VERSION = "governed-repo.claims-gate-adapter/v1.0.0"
_EVIDENCE_STATES = {
    "SUPPORTED",
    "PARTIALLY_SUPPORTED",
    "REFUTED",
    "INCONCLUSIVE",
    "CONFOUNDED",
}


def _gate_config(authority: dict[str, Any]) -> tuple[bool, bool]:
    for item in authority["applicable_gates"]:
        if item["gate_id"] == "claims_gate":
            return True, item["required"]
    return False, False


def _missing_claim_site_caveats(
    content: str,
    statement: str,
    required_caveats: list[str],
) -> list[str]:
    """Return caveats not adjacent to an exact statement occurrence.

    A claim site is deliberately structural rather than semantic: the exact
    statement must be followed by every required caveat in policy order, with
    whitespace-only separation. The adapter never infers truth or claim class
    from surrounding prose.
    """

    if not required_caveats:
        return []
    search_from = 0
    best_matched = 0
    while True:
        statement_index = content.find(statement, search_from)
        if statement_index < 0:
            break
        cursor = statement_index + len(statement)
        matched = 0
        for caveat in required_caveats:
            while cursor < len(content) and content[cursor].isspace():
                cursor += 1
            if not content.startswith(caveat, cursor):
                break
            matched += 1
            cursor += len(caveat)
        if matched == len(required_caveats):
            return []
        best_matched = max(best_matched, matched)
        search_from = statement_index + 1
    return required_caveats[best_matched:]


def _authority_state(
    envelope: dict[str, Any],
    authority: dict[str, Any],
) -> tuple[list[str], bool]:
    reasons: list[str] = []
    if envelope.get("authority_ref") != authority.get("manifest_id"):
        reasons.append("AUTHORITY_REFERENCE_MISMATCH")
    actor = envelope.get("actor")
    actor_id = actor.get("actor_id") if isinstance(actor, dict) else None
    if actor_id not in authority.get("subject_actor_ids", []):
        reasons.append("ACTOR_NOT_AUTHORIZED")
    evaluation_as_of = parse_utc(envelope.get("evaluation_as_of"))
    issued = parse_utc(authority.get("issued_at"))
    expires = parse_utc(authority.get("expires_at"))
    if (
        evaluation_as_of is None
        or issued is None
        or expires is None
        or not (issued <= evaluation_as_of < expires)
    ):
        reasons.append("AUTHORITY_STALE")
    state = authority.get("state")
    if state == "REVOKED":
        reasons.append("AUTHORITY_REVOKED")
    authority_hold = state == "PENDING_REVIEW"
    if authority_hold:
        reasons.append("AUTHORITY_EXPLICITLY_UNRESOLVED")
    return reasons, authority_hold


def evaluate_claims_gate(
    envelope: dict[str, Any],
    authority: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    applicable, required = _gate_config(authority)
    change_id = envelope["change_id"]
    revision = envelope["revision"]
    if not applicable:
        return build_gate_result(
            gate_id="claims_gate",
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
                "content_hashes": [],
                "claim_inventory_hash": canonical_hash([]),
                "claims": [],
                "checks_run": [],
            },
            limitations=["No claim conclusion was made because the gate was not applicable."],
            repair_actions=[],
        )

    evidence_by_id: dict[str, dict[str, Any]] = {}
    duplicate_evidence_ids: set[str] = set()
    for item in envelope["evidence"]:
        evidence_id = item["evidence_id"]
        if evidence_id in evidence_by_id:
            duplicate_evidence_ids.add(evidence_id)
        else:
            evidence_by_id[evidence_id] = item
    allowed_tags = set(policy["allowed_claim_tags"])
    prohibited_tags = set(policy["prohibited_claim_tags"])
    evidence_mapping = policy["claim_kind_evidence_classes"]
    hold_states = set(policy["explicit_hold_evidence_states"])
    required_caveats = policy["required_caveats_by_tag"]

    authority_reasons, authority_hold = _authority_state(envelope, authority)
    reasons: list[str] = list(authority_reasons)
    repairs: list[str] = []
    claim_results: list[dict[str, Any]] = []
    content_hashes: list[dict[str, str]] = []
    any_hold = authority_hold

    for change in envelope["changes"]:
        content = change["content"]
        content_hashes.append(
            {"path": change["path"], "content_hash": canonical_hash(content)}
        )
        for claim in change["claims"]:
            claim_reasons: list[str] = []
            claim_repairs: list[str] = []
            claim_hold = False
            tag = claim["claim_tag"]
            if tag in prohibited_tags:
                claim_reasons.append("CLAIM_TAG_PROHIBITED")
                claim_repairs.append("Remove or narrow the prohibited claim.")
            elif tag not in allowed_tags:
                claim_reasons.append("CLAIM_TAG_UNKNOWN")
                claim_repairs.append("Use a policy-declared claim tag.")

            if claim["statement"] not in content:
                claim_reasons.append("CLAIM_NOT_PRESENT_IN_CONTENT")
                claim_repairs.append(
                    "Keep the structured claim inventory synchronized with proposed content."
                )

            tag_caveats = required_caveats.get(tag, [])
            missing_declared = sorted(set(tag_caveats) - set(claim["caveats"]))
            missing_from_content = sorted(
                _missing_claim_site_caveats(
                    content,
                    claim["statement"],
                    tag_caveats,
                )
            )
            if missing_declared:
                claim_reasons.append("REQUIRED_CAVEAT_NOT_DECLARED")
                claim_repairs.append("Declare every policy-required caveat on the claim.")
            if missing_from_content:
                claim_reasons.append("REQUIRED_CAVEAT_NOT_PRESENT_AT_CLAIM_SITE")
                claim_repairs.append("Place required caveats in the same proposed content.")

            refs = claim["evidence_refs"]
            referenced: list[dict[str, Any]] = []
            if not refs:
                claim_reasons.append("EVIDENCE_REFERENCE_MISSING")
                claim_repairs.append("Attach at least one traceable evidence reference.")
            for evidence_ref in refs:
                if evidence_ref in duplicate_evidence_ids:
                    claim_reasons.append("EVIDENCE_REFERENCE_AMBIGUOUS")
                    claim_repairs.append(
                        "Use an evidence id that resolves to exactly one evidence item."
                    )
                    continue
                item = evidence_by_id.get(evidence_ref)
                if item is None:
                    claim_reasons.append("EVIDENCE_REFERENCE_UNKNOWN")
                    claim_repairs.append("Repair the missing evidence reference.")
                else:
                    referenced.append(item)

            allowed_class_values = evidence_mapping.get(claim["claim_kind"])
            if not isinstance(allowed_class_values, list):
                claim_reasons.append("CLAIM_KIND_UNKNOWN")
                claim_repairs.append("Use a policy-declared claim kind.")
                allowed_classes: set[str] = set()
            else:
                allowed_classes = set(allowed_class_values)
            for item in referenced:
                if item["evidence_class"] not in allowed_classes:
                    claim_reasons.append("EVIDENCE_CLASS_MISMATCH")
                    claim_repairs.append(
                        "Use evidence from the class admitted for this claim kind."
                    )
                if item["evidence_state"] == "REFUTED":
                    claim_reasons.append("EVIDENCE_REFUTES_CLAIM")
                    claim_repairs.append("Withdraw or materially revise the refuted claim.")
                elif item["evidence_state"] not in _EVIDENCE_STATES:
                    claim_reasons.append("EVIDENCE_STATE_UNKNOWN")
                    claim_repairs.append("Use a declared evidence state.")

            eligible = [
                item for item in referenced if item["evidence_class"] in allowed_classes
            ]
            if eligible and not any(item["evidence_state"] == "SUPPORTED" for item in eligible):
                if all(item["evidence_state"] in hold_states for item in eligible):
                    claim_hold = True
                    claim_reasons.append("EVIDENCE_EXPLICITLY_UNRESOLVED")
                    claim_repairs.append("Resolve the declared evidence state before PASS.")
                elif not any(
                    reason
                    in {
                        "EVIDENCE_REFUTES_CLAIM",
                        "EVIDENCE_REFERENCE_UNKNOWN",
                    }
                    for reason in claim_reasons
                ):
                    claim_reasons.append("EVIDENCE_NOT_SUPPORTED")
                    claim_repairs.append("Supply supported evidence or narrow the claim.")
            elif referenced and not eligible:
                claim_reasons.append("NO_ADMISSIBLE_EVIDENCE")

            blocking_reasons = [
                reason
                for reason in claim_reasons
                if reason != "EVIDENCE_EXPLICITLY_UNRESOLVED"
            ]
            if blocking_reasons:
                claim_status = "BLOCK"
            elif claim_hold:
                claim_status = "HOLD"
                any_hold = True
            else:
                claim_status = "PASS"
                claim_reasons.append("CLAIM_WITHIN_EVIDENCE_BOUNDARY")

            claim_result = {
                "claim_id": claim["claim_id"],
                "location": {"path": change["path"]},
                "statement": claim["statement"],
                "claim_kind": claim["claim_kind"],
                "claim_tag": tag,
                "evidence_refs": sorted(refs),
                "evidence_classes": sorted(
                    {item["evidence_class"] for item in referenced}
                ),
                "evidence_states": sorted(
                    {item["evidence_state"] for item in referenced}
                ),
                "required_caveats": sorted(tag_caveats),
                "declared_caveats": sorted(claim["caveats"]),
                "missing_declared_caveats": missing_declared,
                "missing_claim_site_caveats": missing_from_content,
                "status": claim_status,
                "reason_codes": sorted(set(claim_reasons)),
                "repair_actions": sorted(set(claim_repairs)),
            }
            claim_results.append(claim_result)
            reasons.extend(claim_reasons)
            repairs.extend(claim_repairs)

    hard_authority_reasons = [
        reason
        for reason in authority_reasons
        if reason != "AUTHORITY_EXPLICITLY_UNRESOLVED"
    ]
    if (
        any(item["status"] == "BLOCK" for item in claim_results)
        or hard_authority_reasons
    ):
        status = "BLOCK"
    elif any_hold:
        status = "HOLD"
    else:
        status = "PASS"
        reasons.append("ALL_DECLARED_CLAIMS_WITHIN_POLICY")

    sorted_claims = sorted(claim_results, key=lambda item: item["claim_id"])
    gate_evidence = {
        "content_hashes": sorted(content_hashes, key=lambda item: item["path"]),
        "claim_inventory_hash": canonical_hash(sorted_claims),
        "claims": sorted_claims,
        "checks_run": [
            "claim_inventory_sync",
            "claim_tag_policy",
            "claim_site_caveat_check",
            "evidence_class_separation",
            "evidence_state_check",
            "evidence_trace_check",
        ],
    }
    return build_gate_result(
        gate_id="claims_gate",
        adapter_version=ADAPTER_VERSION,
        policy_version=policy["policy_version"],
        policy=policy,
        change_id=change_id,
        revision=revision,
        applicable=True,
        required=required,
        status=status,
        reason_codes=reasons,
        evidence=gate_evidence,
        limitations=[
            "The adapter evaluates an explicit structured claim inventory; it is not a general semantic truth detector.",
            "A PASS means declared claims satisfy this fixed product-local policy, not that the product or claim is externally validated.",
        ],
        repair_actions=repairs,
    )
