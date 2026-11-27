"""Unit tests for Zero-Trust CLI Audit Runner."""

import json
from ztgw.cli import main


def test_cli_check_url_blocks_imds(capsys):
    rc = main(["check-url", "https://169.254.169.254/latest/meta-data/", "--no-dns"])
    assert rc == 1
    out = json.loads(capsys.readouterr().out)
    assert out["allowed"] is False


def test_cli_check_cors_allows_exact_match(capsys):
    rc = main(["check-cors", "https://app.example.com", "--allow", "https://app.example.com"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["allowed"] is True


def test_cli_sanitize_json_strips_proto_and_blocks_nosql(capsys):
    rc = main(["sanitize-json", '{"a":1,"__proto__":{"x":1}}'])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out["stripped_keys"] == 1
    assert out["data"] == {"a": 1}

    rc_bad = main(["sanitize-json", '{"user":{"$ne":null}}'])
    assert rc_bad == 1
