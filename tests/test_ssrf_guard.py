"""Unit tests for SSRF and DNS-Rebinding Guard."""

import pytest

from ztgw.ssrf_guard import SSRFBlockedError, validate_outbound_url


def _public_resolver(hostname: str, port: int):
    return ["93.184.216.34"]


def test_allows_valid_https_public_url():
    res = validate_outbound_url(
        "https://api.example.com/v1/webhooks",
        resolver=_public_resolver,
    )
    assert res.allowed is True
    assert res.hostname == "api.example.com"
    assert res.resolved_ips == ("93.184.216.34",)


@pytest.mark.parametrize(
    "bad_url",
    [
        "http://api.example.com/insecure",
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_INFO",
        "https://user:pass@api.example.com/resource",
        "https://169.254.169.254/latest/meta-data/",
        "https://127.0.0.1:8080/admin",
        "https://[::1]/admin",
        "https://[::ffff:127.0.0.1]/admin",
        "https://10.0.0.5/internal",
        "https://192.168.1.1/router",
        "https://100.64.0.1/cgnat",
        "https://metadata.google.internal/computeMetadata/v1/",
        "https://0x7f000001/",
        "https://2130706433/",
    ],
)
def test_blocks_ssrf_schemes_internal_ips_and_bypasses(bad_url):
    with pytest.raises(SSRFBlockedError):
        validate_outbound_url(bad_url, resolver=_public_resolver)


def test_blocks_dns_rebinding_to_private_ip():
    def rebind_resolver(hostname: str, port: int):
        return ["93.184.216.34", "169.254.169.254"]

    with pytest.raises(SSRFBlockedError, match="DNS rebinding"):
        validate_outbound_url("https://rebind.attacker.com/hook", resolver=rebind_resolver)
