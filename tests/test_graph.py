"""Description: Tests for access graph records, snapshot normalization, and diff semantics."""

import json
from pathlib import Path

import pytest

from wakindex.graph import (
    AccessFinding,
    AccessUnknown,
    ContractError,
    Enforcement,
    Evidence,
    Freshness,
    SchemaIncompatible,
    SecretInEvidence,
    Snapshot,
    diff,
)

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "contracts"


def make_finding(
    finding_id="f:0001",
    relation="can-read",
    obj="resource:file:/home/op/project/README.md",
    classification="observed",
    status="enforced",
    mechanism="landlock-fs",
    revision=4,
):
    return AccessFinding(
        finding_id=finding_id,
        session_id="s:01JBQ2ZK4M",
        subject="session:01JBQ2ZK4M",
        relation=relation,
        object=obj,
        classification=classification,
        confidence="high",
        evidence=(Evidence("proc_fd", "collect.files", "2026-09-20T17:40:03Z", "fd 7"),),
        freshness=Freshness("2026-09-20T17:40:03Z", "2026-09-20T17:45:03Z"),
        enforcement=Enforcement(status, mechanism, revision),
    )


def make_unknown(unknown_id="u:1", relation="can-read", prefix="resource:file:/proc"):
    return AccessUnknown(
        unknown_id=unknown_id,
        session_id="s:01JBQ2ZK4M",
        relation=relation,
        object_prefix=prefix,
        code="collector_permission_denied",
        detail="opendir /proc/1: EACCES",
        collected_at="2026-09-20T17:50:00Z",
    )


# -- record validation --------------------------------------------------------------------


def test_finding_rejects_unknown_relation():
    with pytest.raises(ContractError, match="relation"):
        make_finding(relation="can-teleport")


def test_finding_rejects_object_without_a_known_node_kind():
    with pytest.raises(ContractError, match="object"):
        make_finding(obj="file:/etc/passwd")


def test_finding_rejects_a_major_schema_mismatch():
    with pytest.raises(SchemaIncompatible):
        AccessFinding(
            finding_id="f:x",
            session_id="s:1",
            subject="session:1",
            relation="can-read",
            object="resource:file:/tmp/x",
            classification="observed",
            confidence="high",
            evidence=(Evidence("a", "b", "c", "d"),),
            freshness=Freshness("2026-09-20T13:00:00Z", "2026-09-20T14:00:00Z"),
            enforcement=Enforcement("unenforced", "none"),
            schema_version="2.0",
        )


def test_finding_requires_evidence():
    with pytest.raises(ContractError, match="must carry evidence"):
        AccessFinding(
            finding_id="f:x",
            session_id="s:1",
            subject="session:1",
            relation="can-read",
            object="resource:file:/tmp/x",
            classification="observed",
            confidence="high",
            evidence=(),
            freshness=Freshness("2026-09-20T13:00:00Z", "2026-09-20T14:00:00Z"),
            enforcement=Enforcement("unenforced", "none"),
        )


def test_enforced_classification_requires_an_installed_boundary():
    """Only an installed boundary supports a negative claim, so the two must agree."""
    with pytest.raises(ContractError, match="classification 'enforced'"):
        make_finding(classification="enforced", status="unenforced", mechanism="none")


def test_enforced_status_requires_a_mechanism():
    with pytest.raises(ContractError, match="requires a mechanism"):
        Enforcement("enforced", "none", 1)


@pytest.mark.parametrize(
    "secret",
    [
        "token=ghp_abcdefghijklmnopqrstuvwxyz0123",
        "-----BEGIN RSA PRIVATE KEY-----",
        "AKIAIOSFODNN7EXAMPLE",
        "password: hunter2345",
    ],
)
def test_evidence_rejects_credential_shaped_values(secret):
    with pytest.raises(SecretInEvidence):
        Evidence("agent_config", "collect.creds", "2026-09-20T17:40:03Z", secret)


def test_unknown_rejects_credential_shaped_values():
    with pytest.raises(SecretInEvidence):
        AccessUnknown(
            unknown_id="u:1",
            session_id="s:1",
            relation="can-read",
            object_prefix="resource:file:/x",
            code="collector_timeout",
            detail="failed reading token=ghp_abcdefghijklmnopqrstuvwxyz0123",
            collected_at="2026-09-20T17:50:00Z",
        )


def test_snapshot_rejects_duplicate_finding_ids():
    with pytest.raises(ContractError, match="duplicate finding_id"):
        Snapshot("s:1", (make_finding("f:a"), make_finding("f:a")))


# -- normalization ------------------------------------------------------------------------


def test_normalized_form_is_stable_across_repeated_scans():
    """Two collection passes over an unchanged environment must produce equal bytes."""
    first = Snapshot("s:1", (make_finding("f:b"), make_finding("f:a")))
    second = Snapshot("s:1", (make_finding("f:a"), make_finding("f:b")))
    assert first.normalized_json() == second.normalized_json()


def test_normalized_form_ignores_volatile_evidence():
    """Re-collecting the same access at a later time is not a change."""
    early = Snapshot("s:1", (make_finding(),))
    later_finding = AccessFinding(
        finding_id="f:0001",
        session_id="s:01JBQ2ZK4M",
        subject="session:01JBQ2ZK4M",
        relation="can-read",
        object="resource:file:/home/op/project/README.md",
        classification="observed",
        confidence="low",
        evidence=(Evidence("proc_fd", "collect.files", "2026-09-20T23:00:00Z", "fd 9"),),
        freshness=Freshness("2026-09-20T23:00:00Z", "2026-09-20T23:05:00Z"),
        enforcement=Enforcement("enforced", "landlock-fs", 4),
    )
    later = Snapshot("s:1", (later_finding,))
    assert early.normalized_json() == later.normalized_json()
    assert early.evidence_sidecar() != later.evidence_sidecar()


def test_normalized_entries_carry_no_timestamps():
    entry = Snapshot("s:1", (make_finding(),)).normalized()[0]
    for volatile in ("collected_at", "valid_until", "evidence", "confidence"):
        assert volatile not in entry


def test_normalized_entries_are_sorted_by_finding_id():
    snapshot = Snapshot("s:1", (make_finding("f:c"), make_finding("f:a"), make_finding("f:b")))
    assert [e["finding_id"] for e in snapshot.normalized()] == ["f:a", "f:b", "f:c"]


def test_marked_stale_sets_the_flag_once_the_window_closes():
    snapshot = Snapshot("s:1", (make_finding(),))
    assert snapshot.marked_stale("2026-09-20T17:44:00Z").findings[0].freshness.stale is False
    assert snapshot.marked_stale("2026-09-20T18:00:00Z").findings[0].freshness.stale is True


def test_marked_stale_does_not_change_the_normalized_form():
    """Staleness is a freshness property. If it moved the normalized form, diffs would churn."""
    snapshot = Snapshot("s:1", (make_finding(),))
    stale = snapshot.marked_stale("2026-09-21T00:00:00Z")
    assert snapshot.normalized_json() == stale.normalized_json()


def test_round_trip_through_dict_preserves_the_record():
    snapshot = Snapshot("s:1", (make_finding(),), (make_unknown(),))
    restored = Snapshot.from_dict(json.loads(json.dumps(snapshot.as_dict())))
    assert restored.as_dict() == snapshot.as_dict()


# -- diff ---------------------------------------------------------------------------------


def test_diff_reports_added_and_removed():
    before = Snapshot("s:1", (make_finding("f:a"),))
    after = Snapshot("s:1", (make_finding("f:b"),))
    result = diff(before, after)
    assert result.added == ("f:b",)
    assert result.removed == ("f:a",)
    assert result.indeterminate == ()


def test_diff_reports_a_changed_enforcement_status():
    before = Snapshot("s:1", (make_finding("f:a", status="enforced", mechanism="landlock-fs"),))
    after = Snapshot("s:1", (make_finding("f:a", status="unenforced", mechanism="none"),))
    result = diff(before, after)
    assert result.changed == ("f:a",)
    assert result.added == () and result.removed == ()


def test_diff_marks_a_failed_scope_indeterminate_rather_than_removed():
    """A collector failure is not evidence that access was revoked."""
    lost = make_finding("f:proc", obj="resource:file:/proc/1/environ", status="unenforced",
                        mechanism="none", classification="observed")
    before = Snapshot("s:1", (lost, make_finding("f:keep")))
    after = Snapshot("s:1", (make_finding("f:keep"),), (make_unknown("u:proc"),))

    result = diff(before, after)
    assert result.removed == ()
    assert result.indeterminate == ("f:proc",)
    assert result.carried_unknowns == ("u:proc",)


def test_diff_still_reports_removal_outside_the_failed_scope():
    """An unknown over /proc must not make an unrelated removal indeterminate too."""
    elsewhere = make_finding("f:home", obj="resource:file:/home/op/gone")
    before = Snapshot("s:1", (elsewhere,))
    after = Snapshot("s:1", (), (make_unknown("u:proc"),))

    result = diff(before, after)
    assert result.removed == ("f:home",)
    assert result.indeterminate == ()


def test_diff_unknown_scope_matches_on_relation_too():
    """An unknown about reads says nothing about writes over the same path."""
    written = make_finding("f:w", relation="can-write", obj="resource:file:/proc/sys/x")
    before = Snapshot("s:1", (written,))
    after = Snapshot("s:1", (), (make_unknown("u:proc", relation="can-read"),))

    result = diff(before, after)
    assert result.removed == ("f:w",)
    assert result.indeterminate == ()


def test_diff_of_identical_snapshots_is_empty():
    snapshot = Snapshot("s:1", (make_finding("f:a"), make_finding("f:b")))
    assert diff(snapshot, snapshot).is_empty


# -- golden fixtures ----------------------------------------------------------------------


def test_g1_fixture_loads_through_the_record_types():
    data = json.loads((FIXTURE_DIR / "g1-classification-coverage.json").read_text())
    snapshot = Snapshot.from_dict(data)
    assert {f.classification for f in snapshot.findings} == {
        "declared",
        "observed",
        "inferred",
        "enforced",
    }
    assert len(snapshot.unknowns) == 1


def test_g5_fixture_diff_matches_its_expected_result():
    """The implementation must agree with the approved fixture, not merely with itself."""
    data = json.loads((FIXTURE_DIR / "g5-diff-indeterminacy.json").read_text())

    def rebuild(part):
        findings = tuple(
            make_finding(
                finding_id=entry["finding_id"],
                relation=entry["relation"],
                obj=entry["object"],
                classification=entry["classification"],
                status=entry["enforcement_status"],
                mechanism=entry["enforcement_mechanism"],
                revision=entry["policy_revision"],
            )
            for entry in part["normalized"]
        )
        unknowns = tuple(AccessUnknown.from_dict(item) for item in part["unknowns"])
        return Snapshot("s:01JBQ2ZK4M", findings, unknowns)

    result = diff(rebuild(data["snapshot_a"]), rebuild(data["snapshot_b"]))
    expected = data["expected_diff"]
    assert list(result.added) == expected["added"]
    assert list(result.removed) == expected["removed"]
    assert list(result.changed) == expected["changed"]
    assert list(result.indeterminate) == expected["indeterminate"]
    assert list(result.carried_unknowns) == expected["carried_unknowns"]
