"""Unit tests for Strict CORS Origin Validator."""

import pytest

from ztgw.cors_guard import CORSPolicyError, evaluate_cors_origin


def test_allows_exact_origin_match_case_insensitive():
    decision = evaluate_cors_origin(
        "HTTPS://App.Example.COM",
        ["https://app.example.com"],
        allow_credentials=True,
    )
    assert decision.allowed is True
    assert decision.allow_origin == "https://app.example.com"
    assert decision.allow_credentials is True


def test_blocks_null_origin_and_suffix_bypass():
    with pytest.raises(CORSPolicyError, match="null"):
        evaluate_cors_origin("null", ["https://example.com"])

    with pytest.raises(CORSPolicyError, match="not in the explicit allowlist"):
        evaluate_cors_origin("https://evil-example.com", ["https://example.com"])


def test_blocks_wildcard_with_credentials():
    with pytest.raises(CORSPolicyError, match="allow_credentials=True"):
        evaluate_cors_origin("https://app.example.com", ["*"], allow_credentials=True)

    decision = evaluate_cors_origin("https://app.example.com", ["*"], allow_credentials=False)
    assert decision.allow_origin == "*"
    assert decision.allow_credentials is False
