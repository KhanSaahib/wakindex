"""Description: End-to-end test from seeded capabilities through collectors to a stored diff."""

import os
import time

import pytest

from wakindex.collectors import (
    Budget,
    CollectorContext,
    LineageCollector,
    MountCollector,
    PrincipalCollector,
    run_collectors,
)
from wakindex.store import open_store

NOW = "2026-09-20T18:00:00Z"
UNTIL = "2026-09-20T18:05:00Z"


@pytest.fixture
def seeded_capabilities(tmp_path):
    """Seed capabilities a collector should find: a child process and an open descriptor."""
    marker = tmp_path / "seeded-resource.txt"
    marker.write_text("seeded")
    handle = open(marker)  # noqa: SIM115 - held open so it appears as an inherited descriptor

    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - runs only in the forked child
        os.close(write_fd)
        try:
            os.read(read_fd, 1)
        finally:
            os._exit(0)

    os.close(read_fd)
    for _ in range(100):
        if os.path.exists(f"/proc/{pid}/fd"):
            break
        time.sleep(0.01)
    try:
        yield {"pid": pid, "path": str(marker)}
    finally:
        os.close(write_fd)
        os.waitpid(pid, 0)
        handle.close()


def collect(budget=None):
    context = CollectorContext("s:integration", NOW, UNTIL, budget=budget or Budget())
    return run_collectors(
        [
            PrincipalCollector(os.getpid(), operator_uid=os.getuid()),
            LineageCollector(os.getpid()),
            MountCollector(),
        ],
        context,
    )


def test_seeded_capabilities_appear_as_graph_edges(seeded_capabilities):
    snapshot = collect()
    objects = {finding.object for finding in snapshot.findings}

    assert f"principal:uid:{os.getuid()}" in objects
    assert f"process_identity:pid:{seeded_capabilities['pid']}" in objects
    assert f"resource:file:{seeded_capabilities['path']}" in objects
    assert "resource:mount:/" in objects


def test_every_edge_carries_provenance_and_a_timestamp():
    snapshot = collect()

    assert snapshot.findings
    for finding in snapshot.findings:
        assert finding.evidence, f"{finding.finding_id} has no evidence"
        assert finding.evidence[0].collected_at == NOW
        assert finding.evidence[0].collector.startswith("collect.")
        assert finding.freshness.collected_at == NOW
        assert finding.freshness.valid_until == UNTIL


def test_no_edge_claims_enforcement_that_no_collector_observed():
    """These collectors read /proc. None of them installs or inspects a boundary."""
    snapshot = collect()
    assert all(finding.enforcement.status == "unknown" for finding in snapshot.findings)
    assert all(finding.classification != "enforced" for finding in snapshot.findings)


def test_a_full_pass_round_trips_through_the_store(tmp_path):
    snapshot = collect()
    with open_store(tmp_path / "graph.db", NOW) as store:
        restored = store.get_snapshot(store.put_snapshot(snapshot, NOW))

    assert restored.as_dict() == snapshot.as_dict()


def test_two_passes_over_an_unchanged_process_diff_to_nothing_but_descriptors(tmp_path):
    """Process identity, groups and mounts must be stable between passes on a quiet system."""
    with open_store(tmp_path / "graph.db", NOW) as store:
        before = store.put_snapshot(collect(), NOW)
        after = store.put_snapshot(collect(), NOW)
        result = store.diff_snapshots(before, after)

    churn = [
        finding_id
        for finding_id in result.added + result.removed + result.changed
        if ":fd-" not in finding_id
    ]
    assert churn == [], f"unexpected churn between identical passes: {churn}"


def test_a_starved_budget_reports_unknowns_rather_than_a_short_clean_snapshot(tmp_path):
    """A truncated pass must not read back as a small, complete inventory."""
    snapshot = collect(budget=Budget(max_entries_per_scope=1, max_findings=3))

    assert snapshot.unknowns, "a starved collection recorded nothing about what it skipped"
    assert len(snapshot.findings) <= 3
