# Zero-Trust API Security Gateway (`zero-trust-api-gateway`)

Production-grade Python security middleware and policy enforcement engine for modern APIs.

## Core Capabilities
- **SSRF & DNS Rebinding Guard**: Blocks RFC1918, loopback, link-local (`169.254.169.254`), and IPv6 ULA targets before outbound HTTP dispatch.
- **JWT / JWK Hardened Validator**: Rejects `alg=none`, algorithm confusion (`RS256` -> `HS256`), `kid` path traversal, and expired/untrusted tokens.
- **Sliding-Window Token Bucket Rate Limiter**: Thread-safe per-tenant burst & sustained rate enforcement.
- **HMAC-SHA256 Webhook Verifier**: Constant-time signature verification with timestamp replay window protection.
- **Payload & Prototype-Pollution Sanitizer**: Deep-key sanitization against `__proto__`, `constructor`, and MongoDB `$` operator injection.

## Running Tests
```bash
pytest -v
```
