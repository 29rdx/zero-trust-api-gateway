"""Strict CORS Origin Validator preventing wildcard-credential and suffix-bypass attacks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Tuple
from urllib.parse import urlparse


class CORSPolicyError(ValueError):
    """Raised when a CORS origin or configuration violates Zero-Trust rules."""


@dataclass(frozen=True)
class CORSDecision:
    """Evaluated CORS response policy for a given Origin header."""

    allowed: bool
    allow_origin: str
    allow_credentials: bool
    reason: str


def evaluate_cors_origin(
    origin: str,
    allowed_origins: Iterable[str],
    *,
    allow_credentials: bool = True,
) -> CORSDecision:
    """
    Validates an HTTP `Origin` header against an exact scheme+host+port allowlist.
    - Rejects `"null"` origins (sandboxed iframe / redirect bypass).
    - Rejects wildcard `"*"` when `allow_credentials=True`.
    - Prevents suffix bypasses (e.g. `https://evil-example.com` vs `https://example.com`).
    """
    if not origin or not isinstance(origin, str):
        raise CORSPolicyError("Missing or empty Origin header")

    cleaned_origin = origin.strip()
    if cleaned_origin.lower() == "null":
        raise CORSPolicyError("Origin 'null' is forbidden under Zero-Trust CORS policy")

    parsed = urlparse(cleaned_origin)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise CORSPolicyError(f"Malformed Origin header: {cleaned_origin}")

    normalized_origin = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
    allowlist: Tuple[str, ...] = tuple(o.strip().lower().rstrip("/") for o in allowed_origins if o.strip())

    if "*" in allowlist:
        if allow_credentials:
            raise CORSPolicyError("Wildcard '*' CORS origin cannot be combined with allow_credentials=True")
        return CORSDecision(
            allowed=True,
            allow_origin="*",
            allow_credentials=False,
            reason="wildcard_non_credentialed",
        )

    if normalized_origin in allowlist:
        return CORSDecision(
            allowed=True,
            allow_origin=normalized_origin,
            allow_credentials=allow_credentials,
            reason="exact_allowlist_match",
        )

    raise CORSPolicyError(f"Origin '{normalized_origin}' is not in the explicit allowlist")
