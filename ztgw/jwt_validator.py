"""Hardened JWT Validator (HS256/HS384/HS512) with alg=none & kid traversal protection."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional


class JWTValidationError(ValueError):
    """Raised when a JWT fails structural, cryptographic, or claim validation."""


@dataclass(frozen=True)
class VerifiedJWT:
    """Decoded and verified JWT header and claims."""

    header: Dict[str, Any]
    claims: Dict[str, Any]


_HMAC_ALGS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _b64url_decode(segment: str) -> bytes:
    if not segment or not isinstance(segment, str):
        raise JWTValidationError("Empty JWT segment")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception as exc:
        raise JWTValidationError(f"Malformed base64url segment: {exc}") from exc


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def encode_hs_jwt(
    claims: Dict[str, Any],
    secret: bytes | str,
    *,
    alg: str = "HS256",
    kid: Optional[str] = None,
) -> str:
    """Helper to sign a JWT with HS256/HS384/HS512 for testing and internal tokens."""
    if alg not in _HMAC_ALGS:
        raise JWTValidationError(f"Unsupported signing algorithm: {alg}")
    header: Dict[str, Any] = {"alg": alg, "typ": "JWT"}
    if kid is not None:
        header["kid"] = kid
    key_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    sig = hmac.new(key_bytes, signing_input, _HMAC_ALGS[alg]).digest()
    return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"


def verify_jwt(
    token: str,
    secret: bytes | str,
    *,
    allowed_algs: Iterable[str] = ("HS256", "HS384", "HS512"),
    expected_issuer: Optional[str] = None,
    expected_audience: Optional[str] = None,
    leeway_seconds: int = 30,
    now: Optional[float] = None,
) -> VerifiedJWT:
    """
    Validates a JWT token against strict Zero-Trust rules:
    - Rejects alg=none (any casing) and disallowed algorithms.
    - Rejects kid containing path traversal (../, \\, null bytes).
    - Verifies HMAC signature in constant time.
    - Enforces exp and nbf claims with configurable leeway.
    """
    if not token or not isinstance(token, str):
        raise JWTValidationError("Token must be a non-empty string")

    parts = token.strip().split(".")
    if len(parts) != 3:
        raise JWTValidationError("JWT must contain exactly 3 dot-separated segments")

    h_seg, p_seg, s_seg = parts
    try:
        header = json.loads(_b64url_decode(h_seg).decode("utf-8"))
        claims = json.loads(_b64url_decode(p_seg).decode("utf-8"))
    except JWTValidationError:
        raise
    except Exception as exc:
        raise JWTValidationError(f"Invalid UTF-8/JSON in JWT: {exc}") from exc

    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise JWTValidationError("JWT header and claims must be JSON objects")

    alg = header.get("alg")
    if not isinstance(alg, str) or alg.strip().lower() == "none":
        raise JWTValidationError("Insecure or missing 'alg' header (alg=none rejected)")

    allowed = set(allowed_algs)
    if alg not in allowed or alg not in _HMAC_ALGS:
        raise JWTValidationError(f"Disallowed JWT algorithm '{alg}'")

    kid = header.get("kid")
    if kid is not None:
        if not isinstance(kid, str) or "\x00" in kid or ".." in kid or "/" in kid or "\\" in kid:
            raise JWTValidationError("Unsafe 'kid' header (path traversal / null byte rejected)")

    key_bytes = secret.encode("utf-8") if isinstance(secret, str) else secret
    if len(key_bytes) < 16:
        raise JWTValidationError("HMAC secret must be at least 16 bytes")

    signing_input = f"{h_seg}.{p_seg}".encode("ascii")
    expected_sig = hmac.new(key_bytes, signing_input, _HMAC_ALGS[alg]).digest()
    actual_sig = _b64url_decode(s_seg)
    if not hmac.compare_digest(expected_sig, actual_sig):
        raise JWTValidationError("Invalid JWT signature")

    current_ts = time.time() if now is None else now

    exp = claims.get("exp")
    if exp is None or not isinstance(exp, (int, float)):
        raise JWTValidationError("Missing or non-numeric 'exp' claim")
    if current_ts > float(exp) + leeway_seconds:
        raise JWTValidationError("JWT has expired")

    nbf = claims.get("nbf")
    if nbf is not None:
        if not isinstance(nbf, (int, float)):
            raise JWTValidationError("Non-numeric 'nbf' claim")
        if current_ts + leeway_seconds < float(nbf):
            raise JWTValidationError("JWT is not yet valid (nbf)")

    if expected_issuer is not None and claims.get("iss") != expected_issuer:
        raise JWTValidationError("JWT issuer mismatch")

    if expected_audience is not None:
        aud = claims.get("aud")
        aud_list = aud if isinstance(aud, list) else [aud]
        if expected_audience not in aud_list:
            raise JWTValidationError("JWT audience mismatch")

    return VerifiedJWT(header=header, claims=claims)
