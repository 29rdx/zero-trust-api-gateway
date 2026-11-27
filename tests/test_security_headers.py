"""Unit tests for HTTP Security Headers Enforcer and CSP Auditor."""

from ztgw.security_headers import apply_security_headers, audit_security_headers


def test_apply_security_headers_passes_audit():
    secured = apply_security_headers({"Content-Type": "application/json"})
    res = audit_security_headers(secured)
    assert res.passed is True
    assert res.findings == []


def test_audit_flags_missing_headers_and_unsafe_csp():
    res = audit_security_headers(
        {
            "Strict-Transport-Security": "max-age=0",
            "Content-Security-Policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
        }
    )
    assert res.passed is False
    msgs = " | ".join(f.message for f in res.findings)
    assert "HSTS" in msgs
    assert "nosniff" in msgs
    assert "clickjacking" in msgs
    assert "'unsafe-inline'" in msgs
    assert "'unsafe-eval'" in msgs
