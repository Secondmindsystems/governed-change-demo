"""Canonical JSON and hash helpers used by every proof-bearing artifact."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Iterable


HASH_PREFIX = "sha256:"


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented by the canonical profile."""


def _reject_unsupported(value: Any, pointer: str = "$") -> None:
    if isinstance(value, float):
        raise CanonicalizationError(f"{pointer}: floating-point values are not allowed")
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise CanonicalizationError(
                f"{pointer}: string is not valid Unicode scalar text"
            ) from exc
        return
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError(f"{pointer}: object keys must be strings")
            _reject_unsupported(child, f"{pointer}.{key}")
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            _reject_unsupported(child, f"{pointer}[{index}]")
        return
    if value is not None and not isinstance(value, (str, int, bool)):
        raise CanonicalizationError(
            f"{pointer}: unsupported canonical type {type(value).__name__}"
        )


def canonical_bytes(value: Any) -> bytes:
    """Return RFC-8259-compatible UTF-8 bytes under the product profile.

    The profile fixes key order, separators, Unicode handling, and numeric
    behavior. Floating-point numbers are intentionally excluded so replay does
    not depend on platform-specific numeric rendering.
    """

    _reject_unsupported(value)
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError(str(exc)) from exc
    return rendered.encode("utf-8")


def canonical_hash(value: Any) -> str:
    return HASH_PREFIX + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _diagnostic_value(value: Any, seen: set[int] | None = None) -> Any:
    """Return a stable JSON-safe description of a non-canonical input.

    Invalid inputs still need a deterministic fail-closed receipt. This
    description is evidence of the rejected shape; it is never treated as the
    input becoming valid canonical JSON.
    """

    active = seen if seen is not None else set()
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, str):
        return {
            "invalid_string_escape": value.encode(
                "unicode_escape", errors="backslashreplace"
            ).decode("ascii")
        }
    if isinstance(value, float):
        return {"invalid_number": repr(value)}
    identity = id(value)
    if identity in active:
        return {"invalid_cycle": type(value).__name__}
    active.add(identity)
    try:
        if isinstance(value, list):
            return [_diagnostic_value(item, active) for item in value]
        if isinstance(value, dict):
            items = []
            for key, child in value.items():
                key_text = (
                    key
                    if isinstance(key, str)
                    else f"<{type(key).__name__}:{repr(key)}>"
                )
                items.append(
                    {
                        "key": key_text.encode(
                            "unicode_escape", errors="backslashreplace"
                        ).decode("ascii"),
                        "value": _diagnostic_value(child, active),
                    }
                )
            return sorted(items, key=lambda item: item["key"])
        return {"unsupported_type": type(value).__name__}
    finally:
        active.remove(identity)


def canonical_hash_or_fingerprint(value: Any) -> str:
    """Hash canonical input or a deterministic diagnostic for invalid input."""

    try:
        return canonical_hash(value)
    except (CanonicalizationError, UnicodeError, ValueError, TypeError) as exc:
        return canonical_hash(
            {
                "canonical_input": False,
                "error_type": type(exc).__name__,
                "diagnostic": _diagnostic_value(value),
            }
        )


def hash_without_fields(value: dict[str, Any], fields: Iterable[str]) -> str:
    excluded = set(fields)
    return canonical_hash({key: child for key, child in value.items() if key not in excluded})


def verify_embedded_hash(
    value: dict[str, Any], hash_field: str, excluded_fields: Iterable[str] = ()
) -> bool:
    embedded = value.get(hash_field)
    excluded = set(excluded_fields)
    excluded.add(hash_field)
    if not isinstance(embedded, str):
        return False
    try:
        return embedded == hash_without_fields(value, excluded)
    except (CanonicalizationError, UnicodeError, ValueError, TypeError):
        return False


def stable_identifier(prefix: str, value: Any, length: int = 20) -> str:
    digest = canonical_hash(value).removeprefix(HASH_PREFIX)
    return f"{prefix}-{digest[:length]}"


def write_json(path: Path, value: Any) -> None:
    """Write readable stable JSON; hashes always use ``canonical_bytes``."""

    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(
        value,
        sort_keys=True,
        indent=2,
        ensure_ascii=False,
        allow_nan=False,
    )
    path.write_text(rendered + "\n", encoding="utf-8", newline="\n")
