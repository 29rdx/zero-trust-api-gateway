"""Deep JSON Payload Sanitizer against Prototype Pollution, NoSQL Operators, and Nesting DoS."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, List


class PayloadSanitizationError(ValueError):
    """Raised when a payload violates depth, key, or operator security constraints."""


@dataclass(frozen=True)
class SanitizedPayload:
    """Result of sanitizing an untrusted JSON payload."""

    data: Any
    stripped_keys: int


_PROTO_KEYS = {"__proto__", "constructor", "prototype"}


def sanitize_payload(
    payload: Any,
    *,
    max_depth: int = 16,
    block_nosql_operators: bool = True,
    strip_prototype_keys: bool = True,
) -> SanitizedPayload:
    """
    Recursively sanitizes parsed JSON data structures:
    - Enforces maximum nesting depth to prevent stack/CPU DoS.
    - Strips prototype-pollution keys (__proto__, constructor, prototype).
    - Rejects MongoDB/NoSQL `$` operator keys when enabled.
    """
    stripped_count = 0

    def _walk(node: Any, depth: int) -> Any:
        nonlocal stripped_count
        if depth > max_depth:
            raise PayloadSanitizationError(f"Payload exceeds maximum nesting depth ({max_depth})")

        if isinstance(node, dict):
            cleaned = {}
            for k, v in node.items():
                key_str = str(k)
                if strip_prototype_keys and key_str in _PROTO_KEYS:
                    stripped_count += 1
                    continue
                if block_nosql_operators and key_str.startswith("$"):
                    raise PayloadSanitizationError(f"Blocked NoSQL operator key: {key_str}")
                cleaned[key_str] = _walk(v, depth + 1)
            return cleaned

        if isinstance(node, list):
            result: List[Any] = []
            for item in node:
                result.append(_walk(item, depth + 1))
            return result

        if isinstance(node, str):
            # Strip null bytes from string values
            return node.replace("\x00", "")

        return node

    sanitized = _walk(payload, 0)
    return SanitizedPayload(data=sanitized, stripped_keys=stripped_count)
