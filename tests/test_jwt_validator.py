"""Unit tests for Hardened JWT Validator."""

import base64
import json
import pytest

from ztgw.jwt_validator import JWTValidationError, encode_hs_jwt, verify_jwt

STRONG_SECRET = "super-secret-zero-trust-signing-key-2026"


def _raw_b64(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def test_valid_hs256_jwt_passes():
    token = encode_hs_jwt(
        {"sub": "user-42", "iss": "auth.ztgw.io", "aud": "api", "exp": 2000000000},
        STRONG_SECRET,
        kid="key-2026-01",
    )
    verified = verify_jwt(
        token,
        STRONG_SECRET,
        expected_issuer="auth.ztgw.io",
        expected_audience="api",
        now=1999999000,
    )
    assert verified.claims["sub"] == "user-42"


def test_rejects_alg_none_case_variants():
    for variant in ["none", "NONE", "NoNe"]:
        token = f"{_raw_b64({'alg': variant, 'typ': 'JWT'})}.{_raw_b64({'sub': 'admin', 'exp': 2000000000})}."
        with pytest.raises(JWTValidationError, match="alg"):
            verify_jwt(token, STRONG_SECRET, now=1999999000)


def test_rejects_kid_path_traversal():
    token = encode_hs_jwt(
        {"sub": "user-1", "exp": 2000000000},
        STRONG_SECRET,
        kid="../../etc/passwd",
    )
    with pytest.raises(JWTValidationError, match="kid"):
        verify_jwt(token, STRONG_SECRET, now=1999999000)


def test_rejects_tampered_signature_and_expired_token():
    token = encode_hs_jwt({"sub": "user-1", "exp": 1000}, STRONG_SECRET)
    with pytest.raises(JWTValidationError, match="expired"):
        verify_jwt(token, STRONG_SECRET, now=2000)

    tampered = token[:-4] + "AAAA"
    with pytest.raises(JWTValidationError, match="signature"):
        verify_jwt(tampered, STRONG_SECRET, now=500)


def test_rejects_weak_hmac_secret():
    token = encode_hs_jwt({"sub": "u", "exp": 2000000000}, "short")
    with pytest.raises(JWTValidationError, match="16 bytes"):
        verify_jwt(token, "short", now=1999999000)
