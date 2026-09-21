"""Description: Policy constraints and malformed requests must not silently widen access."""

import pytest

from wakindex.capability_policy import PolicyError, Request, evaluate, validate_revision


def document(match, capability="file.read"):
    return {
        "revision": 1,
        "created_at": "2026-09-20T18:00:00Z",
        "created_by": "principal:uid:1000",
        "rules": [
            {
                "id": "allow",
                "effect": "allow",
                "capability": capability,
                "match": match,
                "reason_code": "ALLOW_RULE",
            }
        ],
        "budgets": {"pids": 1},
    }


@pytest.mark.parametrize(
    "match",
    [
        {"path_prefix": "/safe", "host": "restricted.invalid"},
        {"path": "/safe", "method": "read"},
        {"host": "restricted.invalid", "tool": "fs"},
        {"tool": "fs"},
    ],
)
def test_invalid_selector_combinations_reject_the_revision(match):
    with pytest.raises(PolicyError):
        validate_revision(document(match))


@pytest.mark.parametrize(
    "resource", ["resource:file:relative", "resource:file:/a\0b", "tool_server:mcp:fs"]
)
def test_any_rule_cannot_allow_invalid_file_identity(resource):
    result = evaluate(
        validate_revision(document({"any": True})), Request("s:test", "file.read", resource)
    )
    assert not result.allowed


@pytest.mark.parametrize(
    "usage", [{"pids": -1}, {"pids": float("nan")}, {"pids": True}, {"pids": "1"}, {"pid": 0}, []]
)
def test_bad_usage_rejected_cleanly(usage):
    with pytest.raises(PolicyError):
        evaluate(
            validate_revision(document({"any": True})),
            Request("s:test", "file.read", "resource:file:/safe", usage),
        )


def test_usage_cannot_be_corrupted_after_request_validation():
    request = Request("s:test", "file.read", "resource:file:/safe", {"pids": 0})
    request.usage["pids"] = -1
    with pytest.raises(PolicyError):
        evaluate(validate_revision(document({"any": True})), request)
