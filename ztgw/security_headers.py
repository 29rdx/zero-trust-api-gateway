"""HTTP Security Headers Enforcer and CSP Directive Auditor."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Mapping


@dataclass(frozen=True)
class HeaderFinding:
    """Represents a missing or misconfigured HTTP security header."""

    header: str
    severity: str
    message: str


@dataclass
class HeaderAuditResult:
    """Audit result for HTTP response security headers."""

    passed: bool
    findings: List[HeaderFinding] = field(default_factory=list)


DEFAULT_SECURITY_HEADERS: Dict[str, str] = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Content-Security-Policy": "default-src 'self'; object-src 'none'; frame-ancestors 'none'",
}


def apply_security_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Returns a copy of headers with missing Zero-Trust security headers populated."""
    merged = dict(headers)
    existing_lower = {k.lower() for k in merged}
    for key, default_val in DEFAULT_SECURITY_HEADERS.items():
        if key.lower() not in existing_lower:
            merged[key] = default_val
    return merged


def audit_security_headers(headers: Mapping[str, str]) -> HeaderAuditResult:
    """Audits HTTP response headers for missing protections and unsafe CSP directives."""
    normalized = {k.lower(): v.strip() for k, v in headers.items()}
    findings: List[HeaderFinding] = []

    hsts = normalized.get("strict-transport-security", "")
    if not hsts or "max-age=0" in hsts.lower():
        findings.append(
            HeaderFinding(
                header="Strict-Transport-Security",
                severity="HIGH",
                message="Missing or disabled HSTS header.",
            )
        )

    if normalized.get("x-content-type-options", "").lower() != "nosniff":
        findings.append(
            HeaderFinding(
                header="X-Content-Type-Options",
                severity="MEDIUM",
                message="X-Content-Type-Options must be set to 'nosniff'.",
            )
        )

    xfo = normalized.get("x-frame-options", "").upper()
    if xfo not in {"DENY", "SAMEORIGIN"}:
        findings.append(
            HeaderFinding(
                header="X-Frame-Options",
                severity="MEDIUM",
                message="X-Frame-Options must be DENY or SAMEORIGIN to prevent clickjacking.",
            )
        )

    csp = normalized.get("content-security-policy", "")
    if not csp:
        findings.append(
            HeaderFinding(
                header="Content-Security-Policy",
                severity="HIGH",
                message="Missing Content-Security-Policy header.",
            )
        )
    else:
        lower_csp = csp.lower()
        for unsafe_token in ("'unsafe-inline'", "'unsafe-eval'", "default-src *"):
            if unsafe_token in lower_csp:
                findings.append(
                    HeaderFinding(
                        header="Content-Security-Policy",
                        severity="HIGH",
                        message=f"Unsafe CSP directive detected: {unsafe_token}",
                    )
                )

    return HeaderAuditResult(passed=len(findings) == 0, findings=findings)
