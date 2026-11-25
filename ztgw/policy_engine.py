"""Unified Zero-Trust Policy Engine composing SSRF, JWT, RateLimit, HMAC, and Sanitizer."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from ztgw.jwt_validator import JWTValidationError, verify_jwt
from ztgw.payload_sanitizer import PayloadSanitizationError, sanitize_payload
from ztgw.rate_limiter import SlidingWindowRateLimiter
from ztgw.ssrf_guard import SSRFBlockedError, validate_outbound_url
from ztgw.webhook_verifier import WebhookVerificationError, verify_webhook_signature


@dataclass(frozen=True)
class GatewayRequest:
    """Incoming or proxied API request evaluated by the Zero-Trust gateway."""

    client_id: str
    jwt_token: str
    outbound_url: Optional[str] = None
    webhook_body: Optional[str] = None
    webhook_sig_header: Optional[str] = None
    json_payload: Optional[Any] = None


@dataclass
class GatewayDecision:
    """Structured audit decision from ZeroTrustPolicyEngine."""

    allowed: bool
    status_code: int
    reason: str
    sanitized_payload: Any = None
    audit_trail: List[str] = field(default_factory=list)


class ZeroTrustPolicyEngine:
    """Enforces layered Zero-Trust security controls in fail-closed order."""

    def __init__(
        self,
        *,
        jwt_secret: str,
        webhook_secret: Optional[str] = None,
        rate_limiter: Optional[SlidingWindowRateLimiter] = None,
        dns_resolver: Optional[Callable[[str, int], List[str]]] = None,
    ) -> None:
        self._jwt_secret = jwt_secret
        self._webhook_secret = webhook_secret
        self._rate_limiter = rate_limiter or SlidingWindowRateLimiter(100, 60.0)
        self._dns_resolver = dns_resolver

    def evaluate(self, req: GatewayRequest, *, now: Optional[float] = None) -> GatewayDecision:
        trail: List[str] = []

        # 1. Rate Limit Check
        rl = self._rate_limiter.check_and_consume(req.client_id)
        if not rl.allowed:
            trail.append("rate_limit:blocked")
            return GatewayDecision(
                allowed=False,
                status_code=429,
                reason=f"Rate limit exceeded; retry after {rl.retry_after_seconds}s",
                audit_trail=trail,
            )
        trail.append("rate_limit:ok")

        # 2. JWT Authentication
        try:
            verify_jwt(req.jwt_token, self._jwt_secret, now=now)
            trail.append("jwt:ok")
        except JWTValidationError as exc:
            trail.append("jwt:blocked")
            return GatewayDecision(
                allowed=False,
                status_code=401,
                reason=str(exc),
                audit_trail=trail,
            )

        # 3. Optional Webhook HMAC Verification
        if req.webhook_body is not None:
            if not self._webhook_secret or not req.webhook_sig_header:
                trail.append("webhook:blocked")
                return GatewayDecision(
                    allowed=False,
                    status_code=401,
                    reason="Missing webhook secret or signature header",
                    audit_trail=trail,
                )
            try:
                verify_webhook_signature(
                    req.webhook_body,
                    req.webhook_sig_header,
                    self._webhook_secret,
                    now=int(now) if now is not None else None,
                )
                trail.append("webhook:ok")
            except WebhookVerificationError as exc:
                trail.append("webhook:blocked")
                return GatewayDecision(
                    allowed=False,
                    status_code=401,
                    reason=str(exc),
                    audit_trail=trail,
                )

        # 4. Outbound SSRF Guard
        if req.outbound_url is not None:
            try:
                validate_outbound_url(req.outbound_url, resolver=self._dns_resolver)
                trail.append("ssrf:ok")
            except SSRFBlockedError as exc:
                trail.append("ssrf:blocked")
                return GatewayDecision(
                    allowed=False,
                    status_code=403,
                    reason=str(exc),
                    audit_trail=trail,
                )

        # 5. Deep Payload Sanitization
        cleaned_data = None
        if req.json_payload is not None:
            try:
                sanitized = sanitize_payload(req.json_payload)
                cleaned_data = sanitized.data
                trail.append(f"sanitizer:ok(stripped={sanitized.stripped_keys})")
            except PayloadSanitizationError as exc:
                trail.append("sanitizer:blocked")
                return GatewayDecision(
                    allowed=False,
                    status_code=400,
                    reason=str(exc),
                    audit_trail=trail,
                )

        return GatewayDecision(
            allowed=True,
            status_code=200,
            reason="allowed",
            sanitized_payload=cleaned_data,
            audit_trail=trail,
        )
