"""Unit tests for HMAC-SHA256 Webhook Signature Verifier."""

import pytest

from ztgw.webhook_verifier import (
    WebhookVerificationError,
    sign_webhook_payload,
    verify_webhook_signature,
)

SECRET = "whsec_zero_trust_webhook_secret_key"


def test_valid_webhook_signature_passes():
    body = '{"event":"payment.settled","amount":1500}'
    hdr = sign_webhook_payload(body, SECRET, timestamp=1700000000)
    res = verify_webhook_signature(body, hdr, SECRET, now=1700000050)
    assert res.timestamp == 1700000000
    assert len(res.signature_hex) == 64


def test_rejects_replay_expired_timestamp():
    body = '{"event":"refund"}'
    hdr = sign_webhook_payload(body, SECRET, timestamp=1700000000)
    with pytest.raises(WebhookVerificationError, match="expired"):
        verify_webhook_signature(body, hdr, SECRET, max_age_seconds=300, now=1700000500)


def test_rejects_future_clock_skew_and_tampered_body():
    body = '{"event":"payout"}'
    hdr = sign_webhook_payload(body, SECRET, timestamp=1700000500)
    with pytest.raises(WebhookVerificationError, match="future clock skew"):
        verify_webhook_signature(body, hdr, SECRET, now=1700000000)

    valid_hdr = sign_webhook_payload(body, SECRET, timestamp=1700000000)
    with pytest.raises(WebhookVerificationError, match="Invalid webhook"):
        verify_webhook_signature('{"event":"payout","amount":999999}', valid_hdr, SECRET, now=1700000010)
