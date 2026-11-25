"""Constant-time HMAC-SHA256 Webhook Signature Verifier with Replay Protection."""

from __future__ import annotations

import hashlib
import hmac
import time
from dataclasses import dataclass
from typing import Optional


class WebhookVerificationError(ValueError):
    """Raised when webhook signature or timestamp validation fails."""


@dataclass(frozen=True)
class WebhookVerificationResult:
    """Verified webhook metadata."""

    timestamp: int
    signature_hex: str


def sign_webhook_payload(
    payload: bytes | str,
    secret: bytes | str,
    timestamp: Optional[int] = None,
) -> str:
    """Generates a `t=<ts>,v1=<hex>` signature header for a webhook payload."""
    ts = int(time.time()) if timestamp is None else int(timestamp)
    body = payload.encode("utf-8") if isinstance(payload, str) else payload
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    signed_content = f"{ts}.".encode("ascii") + body
    sig = hmac.new(key, signed_content, hashlib.sha256).hexdigest()
    return f"t={ts},v1={sig}"


def verify_webhook_signature(
    payload: bytes | str,
    signature_header: str,
    secret: bytes | str,
    *,
    max_age_seconds: int = 300,
    max_future_skew_seconds: int = 60,
    now: Optional[int] = None,
) -> WebhookVerificationResult:
    """
    Verifies a webhook signature header (`t=<ts>,v1=<hex>`) in constant time
    and enforces replay/future-skew timestamp bounds.
    """
    if not signature_header or not isinstance(signature_header, str):
        raise WebhookVerificationError("Missing webhook signature header")

    parts = {}
    for item in signature_header.split(","):
        if "=" in item:
            k, v = item.strip().split("=", 1)
            parts[k.strip()] = v.strip()

    ts_raw = parts.get("t")
    v1_sig = parts.get("v1")
    if not ts_raw or not v1_sig:
        raise WebhookVerificationError("Malformed signature header; expected t=<ts>,v1=<hex>")

    try:
        ts = int(ts_raw)
    except ValueError as exc:
        raise WebhookVerificationError("Non-integer webhook timestamp") from exc

    current_ts = int(time.time()) if now is None else int(now)
    age = current_ts - ts
    if age > max_age_seconds:
        raise WebhookVerificationError(f"Webhook timestamp expired (age={age}s > {max_age_seconds}s)")
    if ts - current_ts > max_future_skew_seconds:
        raise WebhookVerificationError("Webhook timestamp exceeds allowed future clock skew")

    body = payload.encode("utf-8") if isinstance(payload, str) else payload
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    signed_content = f"{ts}.".encode("ascii") + body
    expected_sig = hmac.new(key, signed_content, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected_sig, v1_sig.lower()):
        raise WebhookVerificationError("Invalid webhook HMAC-SHA256 signature")

    return WebhookVerificationResult(timestamp=ts, signature_hex=v1_sig.lower())
