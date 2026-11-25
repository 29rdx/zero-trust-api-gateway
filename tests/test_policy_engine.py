"""End-to-end integration tests for ZeroTrustPolicyEngine."""

from ztgw.jwt_validator import encode_hs_jwt
from ztgw.policy_engine import GatewayRequest, ZeroTrustPolicyEngine
from ztgw.rate_limiter import SlidingWindowRateLimiter
from ztgw.webhook_verifier import sign_webhook_payload

JWT_SECRET = "ztgw-master-jwt-secret-key-2026-prod"
WH_SECRET = "ztgw-webhook-hmac-secret-2026"


def _pub_dns(host: str, port: int):
    return ["93.184.216.34"]


def test_full_pipeline_allows_valid_request_and_sanitizes_payload():
    engine = ZeroTrustPolicyEngine(
        jwt_secret=JWT_SECRET,
        webhook_secret=WH_SECRET,
        rate_limiter=SlidingWindowRateLimiter(5, 60.0),
        dns_resolver=_pub_dns,
    )
    token = encode_hs_jwt({"sub": "svc-a", "exp": 2000000000}, JWT_SECRET)
    body = '{"action":"sync"}'
    sig = sign_webhook_payload(body, WH_SECRET, timestamp=1999999000)

    decision = engine.evaluate(
        GatewayRequest(
            client_id="svc-a",
            jwt_token=token,
            outbound_url="https://api.partner.com/callback",
            webhook_body=body,
            webhook_sig_header=sig,
            json_payload={"id": 1, "__proto__": {"polluted": True}},
        ),
        now=1999999010,
    )
    assert decision.allowed is True
    assert decision.status_code == 200
    assert decision.sanitized_payload == {"id": 1}
    assert "sanitizer:ok(stripped=1)" in decision.audit_trail


def test_pipeline_blocks_ssrf_even_with_valid_jwt():
    engine = ZeroTrustPolicyEngine(jwt_secret=JWT_SECRET, dns_resolver=_pub_dns)
    token = encode_hs_jwt({"sub": "svc-b", "exp": 2000000000}, JWT_SECRET)

    decision = engine.evaluate(
        GatewayRequest(
            client_id="svc-b",
            jwt_token=token,
            outbound_url="https://169.254.169.254/latest/meta-data/",
        ),
        now=1999999000,
    )
    assert decision.allowed is False
    assert decision.status_code == 403
    assert "ssrf:blocked" in decision.audit_trail
