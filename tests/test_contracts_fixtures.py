"""Description: Structural conformance tests for the ALP-158 golden contract fixtures."""

import json
import re
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "contracts"

RELATIONS = {
    "can-read",
    "can-write",
    "can-execute",
    "can-connect",
    "can-invoke",
    "can-delegate",
    "inherits",
    "grants",
    "contains",
    "revokes",
}
CLASSIFICATIONS = {"declared", "observed", "inferred", "enforced"}
ENFORCEMENT_STATUSES = {"enforced", "unenforced", "unsupported", "unknown"}
ENFORCEMENT_MECHANISMS = {
    "landlock-fs",
    "landlock-net",
    "landlock-scope",
    "netns",
    "mountns",
    "pidns",
    "cgroup-v2",
    "broker",
    "none",
}
UNKNOWN_CODES = {
    "collector_permission_denied",
    "collector_timeout",
    "collector_bounded_out",
    "unsupported_platform",
    "partial_enumeration",
    "agent_config_unreadable",
}
REASON_CODES = {
    "ALLOW_RULE",
    "DENY_DEFAULT",
    "DENY_EXPLICIT_RULE",
    "DENY_BUDGET_EXCEEDED",
    "DENY_SESSION_STOPPING",
    "DENY_REVISION_MISMATCH",
    "DENY_UNSUPPORTED_ENFORCEMENT",
    "DENY_LEASE_EXPIRED",
    "DENY_SCHEMA_INCOMPATIBLE",
}
NODE_KINDS = {
    "environment",
    "principal",
    "session",
    "process_identity",
    "resource",
    "tool_server",
    "credential_ref",
    "policy_revision",
    "enforcement_boundary",
}
SCHEMA_VERSION = re.compile(r"^\d+\.\d+$")

# Values that must never appear in a fixture. Evidence records carry references, never secrets.
SECRET_MARKERS = (
    "BEGIN PRIVATE KEY",
    "ghp_",
    "github_pat_",
    "sk-",
    "AKIA",
    "xoxb-",
    "password=",
)


def load(name):
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


def fixture_names():
    return sorted(path.name for path in FIXTURE_DIR.glob("*.json"))


def test_every_documented_fixture_is_present():
    assert fixture_names() == [
        "g1-classification-coverage.json",
        "g2-precedence-conflict.json",
        "g3-deny-beats-specificity.json",
        "g4-concurrent-kill.json",
        "g5-diff-indeterminacy.json",
        "g6-reconciliation.json",
    ]


@pytest.mark.parametrize("name", fixture_names())
def test_fixture_carries_no_secret_values(name):
    raw = (FIXTURE_DIR / name).read_text(encoding="utf-8")
    for marker in SECRET_MARKERS:
        assert marker not in raw, f"{name} contains a secret-shaped value: {marker}"


@pytest.mark.parametrize("name", fixture_names())
def test_fixture_is_stably_serializable(name):
    """A fixture must survive a parse and canonical re-serialize unchanged in content."""
    parsed = load(name)
    once = json.dumps(parsed, sort_keys=True, separators=(",", ":"))
    twice = json.dumps(json.loads(once), sort_keys=True, separators=(",", ":"))
    assert once == twice


def test_g1_covers_every_classification_and_keeps_the_unknown():
    data = load("g1-classification-coverage.json")
    findings = data["findings"]

    assert {finding["classification"] for finding in findings} == CLASSIFICATIONS

    for finding in findings:
        assert SCHEMA_VERSION.match(finding["schema_version"])
        assert finding["relation"] in RELATIONS
        assert finding["subject"].split(":")[0] in NODE_KINDS
        assert finding["object"].split(":")[0] in NODE_KINDS
        assert finding["enforcement"]["status"] in ENFORCEMENT_STATUSES
        assert finding["enforcement"]["mechanism"] in ENFORCEMENT_MECHANISMS
        assert finding["evidence"], "a finding must carry at least one piece of evidence"
        assert finding["freshness"]["stale"] is False

    # Only an enforced classification supports a negative claim, so anything not enforced must
    # not be recorded as though a boundary covered it.
    for finding in findings:
        if finding["classification"] == "declared":
            assert finding["enforcement"]["status"] == "unenforced"

    unknowns = data["unknowns"]
    assert len(unknowns) == 1
    assert unknowns[0]["code"] in UNKNOWN_CODES
    assert unknowns[0]["scope"]["object_prefix"].startswith("resource:file:/proc")


@pytest.mark.parametrize("name", ["g2-precedence-conflict.json", "g3-deny-beats-specificity.json"])
def test_policy_fixture_cases_follow_documented_precedence(name):
    data = load(name)
    rule_ids = {rule["id"] for rule in data["policy"]["rules"]}

    for rule in data["policy"]["rules"]:
        assert rule["effect"] in {"allow", "deny"}
        assert rule["reason_code"] in REASON_CODES

    for case in data["cases"]:
        expected = case["expected"]
        assert expected["effect"] in {"allow", "deny"}
        assert expected["reason_code"] in REASON_CODES

        if expected["reason_code"] == "DENY_DEFAULT":
            assert expected["matched_rule_id"] is None, "a default deny names no rule"
        else:
            assert expected["matched_rule_id"] in rule_ids

        # Deny always wins: if any deny rule covers this capability, the case must be a deny.
        deny_rules = [
            rule
            for rule in data["policy"]["rules"]
            if rule["effect"] == "deny" and rule["capability"] == case["capability"]
        ]
        if any(rule["match"].get("any") for rule in deny_rules):
            assert expected["effect"] == "deny", f"{case['name']}: a blanket deny must win"


def test_g3_records_that_specificity_does_not_override_deny():
    data = load("g3-deny-beats-specificity.json")
    case = data["cases"][0]
    assert case["expected"]["effect"] == "deny"
    assert case["expected"]["matched_rule_id"] == "r-deny-all-reads"


def test_g4_concurrent_kills_converge_on_one_incident():
    data = load("g4-concurrent-kill.json")
    expected = data["expected"]

    assert len(data["requests"]) == 3
    assert expected["incident_count"] == 1
    assert {response["incident_id"] for response in expected["responses"]} == {
        expected["incident_id"]
    }

    creators = [r["request_id"] for r in expected["responses"] if r["created_incident"]]
    assert creators == [expected["deadline_set_by"]], "only the first request creates the incident"
    assert expected["state_sequence"] == ["running", "stopping", "stopped"]


def test_g5_failed_collector_yields_indeterminate_not_removed():
    data = load("g5-diff-indeterminacy.json")
    diff = data["expected_diff"]

    ids_a = {f["finding_id"] for f in data["snapshot_a"]["normalized"]}
    ids_b = {f["finding_id"] for f in data["snapshot_b"]["normalized"]}
    missing = ids_a - ids_b

    assert diff["removed"] == [], "a scan failure must never be reported as revoked access"
    assert set(diff["indeterminate"]) == missing
    assert diff["carried_unknowns"] == [u["unknown_id"] for u in data["snapshot_b"]["unknowns"]]


def test_g5_normalized_form_excludes_volatile_fields():
    """Normalized entries must hold no timestamps, pids or inodes, or diffs cannot be stable."""
    data = load("g5-diff-indeterminacy.json")
    volatile = ("collected_at", "valid_until", "pid", "inode", "evidence")

    for snapshot in (data["snapshot_a"], data["snapshot_b"]):
        for entry in snapshot["normalized"]:
            for field in volatile:
                assert field not in entry, f"{field} must live in the evidence sidecar"


def test_g5_normalized_entries_are_sorted_by_finding_id():
    data = load("g5-diff-indeterminacy.json")
    for snapshot in (data["snapshot_a"], data["snapshot_b"]):
        ids = [entry["finding_id"] for entry in snapshot["normalized"]]
        assert ids == sorted(ids)


def test_g6_reconciliation_never_returns_to_running():
    data = load("g6-reconciliation.json")
    expected = data["expected"]

    assert data["persisted_state"]["state"] == "running"
    assert data["observed_after_restart"]["surviving_pids"] == []
    assert expected["state"] == "stopped"
    assert expected["reason"] == "reconciled"
    assert "running" in expected["forbidden_states"]
    assert expected["relaunched"] is False
