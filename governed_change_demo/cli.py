"""Command-line interface for the standalone public export."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

from .canonical import canonical_bytes, canonical_hash, write_json
from .cap_adapter import build_cap_decision
from .contracts import ContractIssue
from .orchestrator import EvaluationOutcome, evaluate_bundle


EXIT_PASS = 0
EXIT_BLOCK = 2
EXIT_HOLD = 3
EXIT_VALIDATION_ERROR = 4
EXIT_REPLAY_MISMATCH = 5
EXIT_DEMO_INVARIANT = 6
EXIT_USAGE = 64
EXIT_INTERNAL = 70

PRODUCT_ROOT = Path(__file__).resolve().parents[1]
JSON_SCHEMA_DRAFT = "https://json-schema.org/draft/2020-12/schema"
EXPECTED_SCHEMA_CONTRACTS = {
    "authority-manifest.v1.schema.json": "governed-repo.authority-manifest/v1",
    "cap-decision.v1.schema.json": "governed-repo.cap-decision/v1",
    "combined-decision.v1.schema.json": "governed-repo.combined-decision/v1",
    "gate-result.v1.schema.json": "governed-repo.gate-result/v1",
    "governed-receipt.v1.schema.json": "governed-repo.governed-receipt/v1",
    "shared-change-envelope.v1.schema.json": "governed-repo.shared-change-envelope/v1",
}
FIXTURE_MAP = {
    "blocked": (
        PRODUCT_ROOT / "fixtures" / "blocked-envelope.json",
        PRODUCT_ROOT / "fixtures" / "authority-manifest.json",
    ),
    "repaired": (
        PRODUCT_ROOT / "fixtures" / "repaired-envelope.json",
        PRODUCT_ROOT / "fixtures" / "authority-manifest.json",
    ),
    "hold": (
        PRODUCT_ROOT / "fixtures" / "hold-envelope.json",
        PRODUCT_ROOT / "fixtures" / "hold-authority-manifest.json",
    ),
    "cap-block": (
        PRODUCT_ROOT / "fixtures" / "cap-block-envelope.json",
        PRODUCT_ROOT / "fixtures" / "authority-manifest.json",
    ),
    "context-update": (
        PRODUCT_ROOT / "fixtures" / "context-update-envelope.json",
        PRODUCT_ROOT / "fixtures" / "authority-manifest.json",
    ),
}
DEFAULT_CAP_POLICY = PRODUCT_ROOT / "policies" / "cap-policy.v1.json"
DEFAULT_PATH_POLICY = PRODUCT_ROOT / "policies" / "path-policy.v1.json"
DEFAULT_CLAIMS_POLICY = PRODUCT_ROOT / "policies" / "claims-policy.v1.json"


class StableArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: error: {message}\n")


class DuplicateJsonKeyError(ValueError):
    def __init__(self, key: str):
        self.key = key
        super().__init__(f"duplicate JSON object key: {key}")


class UnsupportedJsonNumberError(ValueError):
    def __init__(self, token: str):
        self.token = token
        super().__init__(f"unsupported JSON number: {token}")


def _strict_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, child in pairs:
        if key in value:
            raise DuplicateJsonKeyError(key)
        value[key] = child
    return value


def _reject_json_number(token: str) -> Any:
    raise UnsupportedJsonNumberError(token)


def _load_json(
    path: Path | None, document: str
) -> tuple[Any, list[ContractIssue]]:
    if path is None:
        return None, [
            ContractIssue(
                document,
                "INPUT_FILE_NOT_SPECIFIED",
                "",
                "required input path was not supplied",
            )
        ]
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None, [
            ContractIssue(
                document,
                "INPUT_FILE_MISSING",
                "",
                "required input file is missing",
            )
        ]
    except UnicodeDecodeError:
        return None, [
            ContractIssue(
                document,
                "INPUT_FILE_NOT_UTF8",
                "",
                "input file is not valid UTF-8",
            )
        ]
    except OSError as exc:
        return None, [
            ContractIssue(
                document,
                "INPUT_FILE_UNREADABLE",
                "",
                type(exc).__name__,
            )
        ]
    try:
        value = json.loads(
            raw,
            object_pairs_hook=_strict_json_object,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_number,
        )
        canonical_bytes(value)
        return value, []
    except DuplicateJsonKeyError as exc:
        return None, [
            ContractIssue(
                document,
                "JSON_DUPLICATE_KEY",
                "",
                f"duplicate object key is not allowed: {exc.key}",
            )
        ]
    except UnsupportedJsonNumberError as exc:
        return None, [
            ContractIssue(
                document,
                "JSON_NUMBER_UNSUPPORTED",
                "",
                f"floating-point and non-finite numbers are not allowed: {exc.token}",
            )
        ]
    except json.JSONDecodeError as exc:
        return None, [
            ContractIssue(
                document,
                "JSON_MALFORMED",
                f"/line/{exc.lineno}/column/{exc.colno}",
                "input is not valid JSON",
            )
        ]
    except (ValueError, UnicodeError) as exc:
        return None, [
            ContractIssue(
                document,
                "JSON_VALUE_NOT_CANONICAL",
                "",
                type(exc).__name__,
            )
        ]


def _schema_issue(
    filename: str, code: str, pointer: str, message: str
) -> ContractIssue:
    return ContractIssue(f"json_schema:{filename}", code, pointer, message)


def _validate_schema_shape(
    filename: str, value: Any, expected_contract_version: str
) -> list[ContractIssue]:
    issues: list[ContractIssue] = []
    if not isinstance(value, dict):
        return [
            _schema_issue(
                filename,
                "SCHEMA_SHAPE_INVALID",
                "",
                "schema root must be an object",
            )
        ]
    if value.get("$schema") != JSON_SCHEMA_DRAFT:
        issues.append(
            _schema_issue(
                filename,
                "SCHEMA_DRAFT_MISMATCH",
                "/$schema",
                f"expected {JSON_SCHEMA_DRAFT}",
            )
        )
    if value.get("type") != "object":
        issues.append(
            _schema_issue(
                filename,
                "SCHEMA_SHAPE_INVALID",
                "/type",
                "schema root type must be object",
            )
        )
    if value.get("additionalProperties") is not False:
        issues.append(
            _schema_issue(
                filename,
                "SCHEMA_SHAPE_INVALID",
                "/additionalProperties",
                "schema root must reject additional properties",
            )
        )
    properties = value.get("properties")
    if not isinstance(properties, dict):
        issues.append(
            _schema_issue(
                filename,
                "SCHEMA_SHAPE_INVALID",
                "/properties",
                "schema properties must be an object",
            )
        )
    else:
        contract_version = properties.get("contract_version")
        if (
            not isinstance(contract_version, dict)
            or contract_version.get("const") != expected_contract_version
        ):
            issues.append(
                _schema_issue(
                    filename,
                    "SCHEMA_CONTRACT_VERSION_MISMATCH",
                    "/properties/contract_version/const",
                    f"expected {expected_contract_version}",
                )
            )
    required = value.get("required")
    if not isinstance(required, list) or "contract_version" not in required:
        issues.append(
            _schema_issue(
                filename,
                "SCHEMA_SHAPE_INVALID",
                "/required",
                "schema must require contract_version",
            )
        )
    return issues


def _validate_bundled_schemas() -> tuple[list[str], list[ContractIssue]]:
    schema_dir = PRODUCT_ROOT / "contracts"
    actual = {
        path.name: path
        for path in schema_dir.glob("*.schema.json")
        if path.is_file()
    }
    issues: list[ContractIssue] = []
    loaded: list[str] = []
    for filename, contract_version in sorted(
        EXPECTED_SCHEMA_CONTRACTS.items()
    ):
        path = actual.get(filename)
        if path is None:
            issues.append(
                _schema_issue(
                    filename,
                    "SCHEMA_FILE_MISSING",
                    "",
                    "required contract schema is missing",
                )
            )
            continue
        value, load_issues = _load_json(
            path, f"json_schema:{filename}"
        )
        issues.extend(load_issues)
        if load_issues:
            continue
        shape_issues = _validate_schema_shape(
            filename, value, contract_version
        )
        issues.extend(shape_issues)
        if not shape_issues:
            loaded.append(filename)
    for filename in sorted(
        set(actual) - set(EXPECTED_SCHEMA_CONTRACTS)
    ):
        issues.append(
            _schema_issue(
                filename,
                "SCHEMA_FILE_UNEXPECTED",
                "",
                "unexpected contract schema file is not allowed",
            )
        )
    return loaded, issues


def _source_paths(
    args: argparse.Namespace,
) -> tuple[Path | None, Path | None]:
    if args.fixture:
        return FIXTURE_MAP[args.fixture]
    return args.envelope, args.authority


def _load_bundle(
    args: argparse.Namespace,
) -> tuple[Any, Any, Any, Any, Any, Any, Any, list[ContractIssue]]:
    envelope_path, authority_path = _source_paths(args)
    envelope, envelope_issues = _load_json(
        envelope_path, "shared_change_envelope"
    )
    authority, authority_issues = _load_json(
        authority_path, "authority_manifest"
    )
    cap_policy, cap_policy_issues = _load_json(
        args.cap_policy, "cap_policy"
    )
    path_policy, path_policy_issues = _load_json(
        args.path_policy, "path_policy"
    )
    claims_policy, claims_policy_issues = _load_json(
        args.claims_policy, "claims_policy"
    )
    prior_receipt, prior_issues = (
        _load_json(args.prior_receipt, "prior_receipt")
        if args.prior_receipt
        else (None, [])
    )
    issues = [
        *envelope_issues,
        *authority_issues,
        *cap_policy_issues,
        *path_policy_issues,
        *claims_policy_issues,
        *prior_issues,
    ]
    if getattr(args, "cap", None) is not None:
        cap_decision, cap_issues = _load_json(args.cap, "cap_decision")
        issues.extend(cap_issues)
    elif not any(
        issue.document
        in {
            "shared_change_envelope",
            "authority_manifest",
            "cap_policy",
            "path_policy",
            "claims_policy",
        }
        for issue in issues
    ):
        try:
            cap_decision = build_cap_decision(
                envelope,
                authority,
                cap_policy,
                path_policy,
                claims_policy,
            )
        except (KeyError, TypeError, ValueError, UnicodeError) as exc:
            cap_decision = None
            issues.append(
                ContractIssue(
                    "cap_decision",
                    "CAP_BUILD_FAILED",
                    "",
                    f"mechanical CAP derivation failed: {type(exc).__name__}",
                )
            )
    else:
        cap_decision = None
    return (
        envelope,
        authority,
        cap_decision,
        cap_policy,
        path_policy,
        claims_policy,
        prior_receipt,
        issues,
    )


def _bundled_block_receipt(
    *,
    cap_policy_path: Path,
    path_policy_path: Path,
    claims_policy_path: Path,
    gate_order: str,
) -> dict[str, Any]:
    class FixtureArgs:
        fixture = "blocked"
        envelope = None
        authority = None
        cap = None
        cap_policy = cap_policy_path
        path_policy = path_policy_path
        claims_policy = claims_policy_path
        prior_receipt = None

    args = FixtureArgs()
    (
        envelope,
        authority,
        cap_decision,
        cap_policy,
        path_policy,
        claims_policy,
        _,
        issues,
    ) = _load_bundle(args)
    return evaluate_bundle(
        envelope,
        authority,
        cap_decision,
        cap_policy,
        path_policy,
        claims_policy,
        gate_order=tuple(gate_order.split(",")),
        load_issues=issues,
    ).receipt


def _evaluate(
    args: argparse.Namespace, *, auto_prior: bool = False
) -> EvaluationOutcome:
    (
        envelope,
        authority,
        cap_decision,
        cap_policy,
        path_policy,
        claims_policy,
        prior_receipt,
        issues,
    ) = _load_bundle(args)
    if auto_prior and args.fixture == "repaired" and prior_receipt is None:
        prior_receipt = _bundled_block_receipt(
            cap_policy_path=args.cap_policy,
            path_policy_path=args.path_policy,
            claims_policy_path=args.claims_policy,
            gate_order=args.gate_order,
        )
    return evaluate_bundle(
        envelope,
        authority,
        cap_decision,
        cap_policy,
        path_policy,
        claims_policy,
        prior_receipt=prior_receipt,
        gate_order=tuple(args.gate_order.split(",")),
        load_issues=issues,
    )


def _cap_summary(outcome: EvaluationOutcome) -> dict[str, Any]:
    reference = outcome.combined_decision.get("cap_decision_ref")
    if not isinstance(reference, dict):
        reference = {}
    return {
        "input_status": outcome.combined_decision.get("cap_input_status"),
        "decision_id": reference.get("cap_decision_id"),
        "canonical_hash": reference.get("canonical_hash"),
        "decision": reference.get("decision"),
        "domain_gates_may_run": reference.get("domain_gates_may_run"),
        "execution_authority": reference.get("execution_authority"),
    }


def _summary(outcome: EvaluationOutcome) -> dict[str, Any]:
    return {
        "status": outcome.status,
        "exit_code": outcome.exit_code,
        "decision_id": outcome.combined_decision["decision_id"],
        "decision_hash": outcome.combined_decision["decision_hash"],
        "receipt_id": outcome.receipt["receipt_id"],
        "receipt_hash": outcome.receipt["receipt_hash"],
        "gate_statuses": {
            result["gate_id"]: result["status"]
            for result in outcome.gate_results
        },
        "cap": _cap_summary(outcome),
        "domain_gates_executed": outcome.combined_decision[
            "domain_gates_executed"
        ],
        "next_lawful_move": outcome.combined_decision[
            "next_lawful_move"
        ],
    }


def _print_json(value: Any) -> None:
    print(
        json.dumps(
            value,
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
            allow_nan=False,
        )
    )


def _write_outcome(output_dir: Path, outcome: EvaluationOutcome) -> None:
    write_json(output_dir / "cap-decision.json", outcome.cap_decision)
    for result in outcome.gate_results:
        write_json(
            output_dir
            / "gate-results"
            / f"{result['gate_id'].replace('_', '-')}.json",
            result,
        )
    write_json(
        output_dir / "combined-decision.json",
        outcome.combined_decision,
    )
    write_json(
        output_dir / "governed-receipt.json", outcome.receipt
    )


def command_validate(args: argparse.Namespace) -> int:
    outcome = _evaluate(args, auto_prior=True)
    schemas, schema_contract_issues = _validate_bundled_schemas()
    schema_issues = [
        issue.as_dict() for issue in schema_contract_issues
    ]
    valid = (
        outcome.combined_decision["input_status"] == "VALID"
        and outcome.combined_decision["cap_input_status"] == "VALID"
        and not schema_issues
        and len(schemas) == len(EXPECTED_SCHEMA_CONTRACTS)
    )
    _print_json(
        {
            "contract_validation": "PASS" if valid else "BLOCK",
            "fixture_decision": outcome.status,
            "cap": _cap_summary(outcome),
            "domain_gates_executed": outcome.combined_decision[
                "domain_gates_executed"
            ],
            "schemas_loaded": schemas,
            "schema_count": len(schemas),
            "schema_issues": schema_issues,
            "receipt_hash": outcome.receipt["receipt_hash"],
        }
    )
    return EXIT_PASS if valid else EXIT_VALIDATION_ERROR


def command_evaluate(args: argparse.Namespace) -> int:
    outcome = _evaluate(args)
    if args.output_dir:
        _write_outcome(args.output_dir, outcome)
    _print_json(_summary(outcome))
    return outcome.exit_code


def command_demo(args: argparse.Namespace) -> int:
    class BlockArgs:
        fixture = "blocked"
        envelope = None
        authority = None
        cap = None
        cap_policy = args.cap_policy
        path_policy = args.path_policy
        claims_policy = args.claims_policy
        prior_receipt = None
        gate_order = args.gate_order

    block = _evaluate(BlockArgs())

    class RepairArgs:
        fixture = "repaired"
        envelope = None
        authority = None
        cap = None
        cap_policy = args.cap_policy
        path_policy = args.path_policy
        claims_policy = args.claims_policy
        prior_receipt = None
        gate_order = args.gate_order

    repair_args = RepairArgs()
    (
        envelope,
        authority,
        cap_decision,
        cap_policy,
        path_policy,
        claims_policy,
        _,
        issues,
    ) = _load_bundle(repair_args)
    repaired = evaluate_bundle(
        envelope,
        authority,
        cap_decision,
        cap_policy,
        path_policy,
        claims_policy,
        prior_receipt=block.receipt,
        gate_order=tuple(args.gate_order.split(",")),
        load_issues=issues,
    )
    if args.output_dir:
        _write_outcome(args.output_dir / "blocked", block)
        _write_outcome(args.output_dir / "repaired", repaired)
    lineage = repaired.receipt["repair_lineage"]
    invariant_ok = (
        block.status == "BLOCK"
        and repaired.status == "PASS"
        and block.combined_decision["cap_input_status"] == "VALID"
        and repaired.combined_decision["cap_input_status"] == "VALID"
        and block.combined_decision["domain_gates_executed"] is True
        and repaired.combined_decision["domain_gates_executed"] is True
        and block.cap_decision["decision"] == "PASS"
        and repaired.cap_decision["decision"] == "PASS"
        and isinstance(lineage, dict)
        and lineage["prior_receipt_id"] == block.receipt["receipt_id"]
        and lineage["prior_receipt_hash"]
        == block.receipt["receipt_hash"]
        and lineage["cap_rechecked"] is True
        and lineage["unchanged_policy_hashes"]
        == repaired.receipt["policy_hashes"]
    )
    _print_json(
        {
            "demo": "PASS" if invariant_ok else "BLOCK",
            "blocked": _summary(block),
            "repaired": _summary(repaired),
            "repair_lineage": lineage,
        }
    )
    return EXIT_PASS if invariant_ok else EXIT_DEMO_INVARIANT


def command_replay(args: argparse.Namespace) -> int:
    runs = [_evaluate(args, auto_prior=True) for _ in range(args.runs)]

    def replay_bytes(outcome: EvaluationOutcome) -> bytes:
        return canonical_bytes(
            {
                "cap_decision": outcome.cap_decision,
                "gate_results": list(outcome.gate_results),
                "decision": outcome.combined_decision,
                "receipt": outcome.receipt,
            }
        )

    baseline = replay_bytes(runs[0])
    stable = all(replay_bytes(outcome) == baseline for outcome in runs[1:])
    _print_json(
        {
            "replay": "PASS" if stable else "MISMATCH",
            "runs": args.runs,
            "fixture": args.fixture or str(args.envelope),
            "status": runs[0].status,
            "cap": _cap_summary(runs[0]),
            "domain_gates_executed": runs[0].combined_decision[
                "domain_gates_executed"
            ],
            "receipt_id": runs[0].receipt["receipt_id"],
            "receipt_hash": runs[0].receipt["receipt_hash"],
            "replay_identity": canonical_hash(
                {
                    "evaluation_as_of": (
                        runs[0].cap_decision.get("evaluation_as_of")
                        if isinstance(runs[0].cap_decision, dict)
                        else None
                    ),
                    "evaluator_versions": {
                        "cap": (
                            runs[0].cap_decision.get("evaluator_version")
                            if isinstance(runs[0].cap_decision, dict)
                            else None
                        ),
                        "decision": runs[0].combined_decision[
                            "logic_version"
                        ],
                        "gates": {
                            result["gate_id"]: result["adapter_version"]
                            for result in runs[0].gate_results
                        },
                    },
                    "input_hashes": runs[0].receipt["input_hashes"],
                    "policy_hashes": runs[0].receipt["policy_hashes"],
                }
            ),
            "canonical_bytes": len(baseline),
        }
    )
    return EXIT_PASS if stable else EXIT_REPLAY_MISMATCH


def _add_source_args(parser: argparse.ArgumentParser) -> None:
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--fixture", choices=sorted(FIXTURE_MAP))
    source.add_argument("--envelope", type=Path)
    parser.add_argument("--authority", type=Path)
    parser.add_argument(
        "--cap",
        type=Path,
        help=(
            "optional explicit CAP Decision; when omitted it is derived "
            "mechanically from the declared inputs"
        ),
    )
    parser.add_argument(
        "--cap-policy", type=Path, default=DEFAULT_CAP_POLICY
    )
    parser.add_argument(
        "--path-policy", type=Path, default=DEFAULT_PATH_POLICY
    )
    parser.add_argument(
        "--claims-policy", type=Path, default=DEFAULT_CLAIMS_POLICY
    )
    parser.add_argument("--prior-receipt", type=Path)
    parser.add_argument(
        "--gate-order",
        default="path_gate,claims_gate",
        help="claims_gate and path_gate exactly once, in either order",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = StableArgumentParser(
        prog="governed-change-demo",
        description="One Change, Two Gates, One Receipt.",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s 0.1.0"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser(
        "validate", help="validate contracts, policies, and schemas"
    )
    _add_source_args(validate_parser)
    validate_parser.set_defaults(handler=command_validate)

    evaluate_parser = subparsers.add_parser(
        "evaluate",
        help="evaluate one candidate snapshot and emit canonical artifacts",
    )
    _add_source_args(evaluate_parser)
    evaluate_parser.add_argument("--output-dir", type=Path)
    evaluate_parser.set_defaults(handler=command_evaluate)

    demo_parser = subparsers.add_parser(
        "demo", help="run the bundled BLOCK then bounded-repair PASS"
    )
    demo_parser.add_argument(
        "--cap-policy", type=Path, default=DEFAULT_CAP_POLICY
    )
    demo_parser.add_argument(
        "--path-policy", type=Path, default=DEFAULT_PATH_POLICY
    )
    demo_parser.add_argument(
        "--claims-policy", type=Path, default=DEFAULT_CLAIMS_POLICY
    )
    demo_parser.add_argument(
        "--gate-order", default="path_gate,claims_gate"
    )
    demo_parser.add_argument("--output-dir", type=Path)
    demo_parser.set_defaults(handler=command_demo)

    replay_parser = subparsers.add_parser(
        "replay",
        help="prove byte-identical output across repeated evaluations",
    )
    _add_source_args(replay_parser)
    replay_parser.add_argument("--runs", type=int, default=3)
    replay_parser.set_defaults(handler=command_replay)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if hasattr(args, "runs") and args.runs < 2:
        parser.error("--runs must be at least 2")
    if getattr(args, "envelope", None) is not None:
        if getattr(args, "authority", None) is None:
            parser.error("--authority is required with --envelope")
    elif getattr(args, "fixture", None) is not None and (
        getattr(args, "authority", None) is not None
        or getattr(args, "cap", None) is not None
    ):
        parser.error(
            "--authority and --cap cannot be combined with --fixture"
        )
    try:
        return int(args.handler(args))
    except BrokenPipeError:
        return EXIT_PASS
    except Exception as exc:  # pragma: no cover - last-resort boundary
        print(
            json.dumps(
                {
                    "status": "INTERNAL_ERROR",
                    "error_type": type(exc).__name__,
                    "message": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return EXIT_INTERNAL


if __name__ == "__main__":
    raise SystemExit(main())
