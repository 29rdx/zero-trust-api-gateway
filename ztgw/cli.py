"""CLI Audit Runner for Zero-Trust API Security Gateway."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from ztgw.cors_guard import CORSPolicyError, evaluate_cors_origin
from ztgw.payload_sanitizer import PayloadSanitizationError, sanitize_payload
from ztgw.ssrf_guard import SSRFBlockedError, validate_outbound_url


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ztgw",
        description="Zero-Trust API Security Gateway CLI Auditor",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    url_p = sub.add_parser("check-url", help="Validate an outbound URL against SSRF policy")
    url_p.add_argument("url")
    url_p.add_argument("--no-dns", action="store_true", help="Skip live DNS resolution")

    cors_p = sub.add_parser("check-cors", help="Validate an Origin header against an allowlist")
    cors_p.add_argument("origin")
    cors_p.add_argument("--allow", required=True, help="Comma-separated allowed origins")
    cors_p.add_argument("--no-credentials", action="store_true")

    json_p = sub.add_parser("sanitize-json", help="Sanitize a JSON payload string")
    json_p.add_argument("payload")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    if args.command == "check-url":
        try:
            res = validate_outbound_url(args.url, resolve_dns=not args.no_dns)
            print(json.dumps({"allowed": res.allowed, "hostname": res.hostname}))
            return 0
        except SSRFBlockedError as exc:
            print(json.dumps({"allowed": False, "error": str(exc)}))
            return 1

    if args.command == "check-cors":
        try:
            origins = [o.strip() for o in args.allow.split(",") if o.strip()]
            dec = evaluate_cors_origin(
                args.origin,
                origins,
                allow_credentials=not args.no_credentials,
            )
            print(json.dumps({"allowed": dec.allowed, "allow_origin": dec.allow_origin}))
            return 0
        except CORSPolicyError as exc:
            print(json.dumps({"allowed": False, "error": str(exc)}))
            return 1

    if args.command == "sanitize-json":
        try:
            raw = json.loads(args.payload)
            sanitized = sanitize_payload(raw)
            print(json.dumps({"allowed": True, "stripped_keys": sanitized.stripped_keys, "data": sanitized.data}))
            return 0
        except (json.JSONDecodeError, PayloadSanitizationError) as exc:
            print(json.dumps({"allowed": False, "error": str(exc)}))
            return 1

    return 2


if __name__ == "__main__":
    sys.exit(main())
