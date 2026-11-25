"""Unit tests for Deep JSON Payload Sanitizer."""

import pytest

from ztgw.payload_sanitizer import PayloadSanitizationError, sanitize_payload


def test_strips_prototype_pollution_and_null_bytes():
    raw = {
        "user": "alice\x00",
        "__proto__": {"isAdmin": True},
        "nested": {"constructor": {"x": 1}, "role": "viewer"},
    }
    res = sanitize_payload(raw)
    assert res.stripped_keys == 2
    assert res.data == {"user": "alice", "nested": {"role": "viewer"}}


def test_blocks_nosql_operator_injection():
    with pytest.raises(PayloadSanitizationError, match="NoSQL"):
        sanitize_payload({"username": {"$ne": None}})


def test_enforces_maximum_nesting_depth():
    deep: dict = {"leaf": 1}
    for _ in range(20):
        deep = {"wrap": deep}
    with pytest.raises(PayloadSanitizationError, match="maximum nesting depth"):
        sanitize_payload(deep, max_depth=16)
