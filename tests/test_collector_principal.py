"""Description: Tests for the principal, group, and capability collector."""

import os

from wakindex.collectors.base import Budget, CollectorContext, run_collectors
from wakindex.collectors.principal import PrincipalCollector

NOW = "2026-09-20T18:00:00Z"
UNTIL = "2026-09-20T18:05:00Z"


def make_context(budget=None):
    return CollectorContext("s:test", NOW, UNTIL, budget=budget or Budget())


def objects(snapshot, prefix):
    return {f.object for f in snapshot.findings if f.object.startswith(prefix)}


def test_real_and_effective_authority_are_recorded_separately():
    """Collapsing the two would hide a process running with authority it was not given."""
    snapshot = run_collectors([PrincipalCollector(os.getpid())], make_context())

    kinds = {
        f.finding_id.rsplit("-", 1)[-1]
        for f in snapshot.findings
        if ":uid:" in f.object and "shares-operator" not in f.finding_id
    }
    assert {"real", "effective", "saved", "filesystem"} <= kinds


def test_uids_and_gids_match_the_running_process():
    snapshot = run_collectors([PrincipalCollector(os.getpid())], make_context())

    assert f"principal:uid:{os.getuid()}" in objects(snapshot, "principal:uid:")
    assert f"principal:gid:{os.getgid()}" in objects(snapshot, "principal:gid:")


def test_supplementary_groups_are_recorded():
    snapshot = run_collectors([PrincipalCollector(os.getpid())], make_context())
    recorded = objects(snapshot, "principal:gid:")

    for gid in os.getgroups():
        assert f"principal:gid:{gid}" in recorded


def test_every_finding_carries_provenance_and_a_timestamp():
    snapshot = run_collectors([PrincipalCollector(os.getpid())], make_context())

    assert snapshot.findings
    for finding in snapshot.findings:
        assert finding.evidence
        assert finding.evidence[0].source == "proc_status"
        assert finding.evidence[0].collector == "collect.principal"
        assert finding.freshness.collected_at == NOW


def test_effective_capabilities_are_recorded():
    snapshot = run_collectors([PrincipalCollector(os.getpid())], make_context())
    assert objects(snapshot, "principal:capability:effective/")


def test_an_unreadable_capability_line_is_unknown_not_an_empty_set():
    """An empty capability set and an unreadable one must not look the same.

    Reporting "no capabilities" for a process nobody could read understates what it can do, which
    is the direction of error this system must never take.
    """
    context = make_context()
    PrincipalCollector(os.getpid())._record_capabilities(context, {}, "process_identity:pid:1")

    snapshot = context.snapshot()
    assert snapshot.findings == ()
    assert snapshot.unknowns[0].object_prefix == "principal:capability:"
    assert snapshot.unknowns[0].code == "collector_permission_denied"


def test_a_missing_uid_line_is_unknown_not_an_absent_principal():
    context = make_context()
    PrincipalCollector(1)._record_ids(context, {}, "process_identity:pid:1", "Uid", "uid")

    snapshot = context.snapshot()
    assert snapshot.findings == ()
    assert snapshot.unknowns[0].code == "partial_enumeration"


def test_a_process_that_does_not_exist_produces_unknowns_over_every_scope():
    """A vanished process must leave its scopes marked unseen, not silently empty."""
    collector = PrincipalCollector(2**30)
    snapshot = run_collectors([collector], make_context())

    assert snapshot.findings == ()
    prefixes = {unknown.object_prefix for unknown in snapshot.unknowns}
    assert "principal:uid:" in prefixes


def test_sharing_the_operator_identity_is_recorded_as_a_finding():
    """The unsupported profile is recorded, not left for a reader to notice."""
    snapshot = run_collectors(
        [PrincipalCollector(os.getpid(), operator_uid=os.getuid())], make_context()
    )

    shared = [f for f in snapshot.findings if "shares-operator-identity" in f.finding_id]
    assert len(shared) == 1
    assert shared[0].relation == "can-delegate"
    assert "cannot be contained" in shared[0].evidence[0].detail


def test_a_different_operator_uid_produces_no_shared_identity_finding():
    snapshot = run_collectors(
        [PrincipalCollector(os.getpid(), operator_uid=os.getuid() + 1)], make_context()
    )
    assert not [f for f in snapshot.findings if "shares-operator-identity" in f.finding_id]


def test_group_enumeration_is_bounded():
    context = make_context(budget=Budget(max_entries_per_scope=1))
    PrincipalCollector(os.getpid())._record_groups(
        context, {"Groups": "1 2 3 4 5"}, "process_identity:pid:1"
    )

    snapshot = context.snapshot()
    assert len(objects(snapshot, "principal:gid:")) == 1
    assert snapshot.unknowns[0].code == "collector_bounded_out"


def test_repeated_passes_produce_the_same_normalized_form():
    first = run_collectors([PrincipalCollector(os.getpid())], make_context())
    second = run_collectors([PrincipalCollector(os.getpid())], make_context())
    assert first.normalized_json() == second.normalized_json()


def test_a_repeated_supplementary_group_is_recorded_once():
    """Inside a user namespace the unmapped gid repeats in Groups; that is one grant, not two."""
    context = make_context()
    PrincipalCollector(1)._record_groups(
        context, {"Groups": "65534 65534 65534"}, "process_identity:pid:1"
    )

    snapshot = context.snapshot()
    assert len(snapshot.findings) == 1
    assert snapshot.findings[0].object == "principal:gid:65534"
