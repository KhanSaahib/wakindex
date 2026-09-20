"""Description: Tests for the lineage collector, including fork and rename races."""

import os
import time

import pytest

from wakindex.collectors.base import Budget, CollectorContext, run_collectors
from wakindex.collectors.lineage import LineageCollector
from wakindex.graph import AccessFinding, Enforcement, Evidence, Freshness

NOW = "2026-09-20T18:00:00Z"
UNTIL = "2026-09-20T18:05:00Z"


def make_context(budget=None):
    return CollectorContext("s:test", NOW, UNTIL, budget=budget or Budget())


def objects(snapshot, relation=None):
    return {f.object for f in snapshot.findings if relation is None or f.relation == relation}


@pytest.fixture
def child_tree():
    """A real child process holding a real open descriptor, reaped at the end of the test."""
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:  # pragma: no cover - runs only in the forked child
        os.close(write_fd)
        try:
            os.read(read_fd, 1)
        finally:
            os._exit(0)

    os.close(read_fd)
    # Give the child a moment to reach its blocking read so /proc reflects it.
    for _ in range(100):
        if os.path.exists(f"/proc/{pid}/fd"):
            break
        time.sleep(0.01)
    try:
        yield pid
    finally:
        os.close(write_fd)
        os.waitpid(pid, 0)


# -- the tree ------------------------------------------------------------------------------


def test_the_root_process_is_recorded():
    snapshot = run_collectors([LineageCollector(os.getpid())], make_context())
    assert f"process_identity:pid:{os.getpid()}" in objects(snapshot, "contains")


def test_a_forked_child_is_recorded_as_contained(child_tree):
    snapshot = run_collectors([LineageCollector(os.getpid())], make_context())
    assert f"process_identity:pid:{child_tree}" in objects(snapshot, "contains")


def test_working_directory_and_root_are_recorded():
    snapshot = run_collectors([LineageCollector(os.getpid())], make_context())
    recorded = objects(snapshot, "can-read")

    assert f"resource:file:{os.getcwd()}" in recorded
    assert "resource:file:/" in recorded


def test_inherited_descriptors_are_recorded():
    snapshot = run_collectors([LineageCollector(os.getpid())], make_context())
    fd_findings = [f for f in snapshot.findings if f.evidence[0].source == "proc_fd"]
    assert fd_findings


def test_every_finding_carries_provenance_and_a_timestamp():
    snapshot = run_collectors([LineageCollector(os.getpid())], make_context())
    assert snapshot.findings
    for finding in snapshot.findings:
        assert finding.evidence
        assert finding.evidence[0].collector == "collect.lineage"
        assert finding.freshness.collected_at == NOW


# -- races ---------------------------------------------------------------------------------


def test_a_process_that_exits_mid_walk_does_not_abort_the_collection():
    """A descendant that exits must not cost the rest of the tree its record."""
    context = make_context()
    collector = LineageCollector(os.getpid())

    # 2**30 was alive as far as the walk is concerned and is gone by the time it is recorded.
    collector._record_process(context, 2**30)
    collector._record_process(context, os.getpid())

    snapshot = context.snapshot()
    assert f"process_identity:pid:{os.getpid()}" in objects(snapshot, "contains")


def test_a_process_that_exits_mid_walk_is_recorded_as_unknown_not_dropped():
    """It existed. Dropping it silently would understate what the tree contained."""
    context = make_context()
    LineageCollector(os.getpid())._record_process(context, 2**30)

    snapshot = context.snapshot()
    assert snapshot.findings == ()
    unknown = snapshot.unknowns[0]
    assert unknown.code == "partial_enumeration"
    assert "exited between the walk and the record" in unknown.detail


def test_a_tree_that_grows_during_the_walk_records_a_partial_enumeration(monkeypatch):
    """An agent that forks while being read must not hide a descendant for free."""
    context = make_context()
    collector = LineageCollector(os.getpid())

    passes = iter([[os.getpid()], [os.getpid(), 4242]])

    def changing(_context, _pid, seen):
        seen.extend(next(passes))
        return seen

    monkeypatch.setattr(collector, "_descendants", changing)
    collector._walk_tree(context)

    unknown = context.snapshot().unknowns[0]
    assert unknown.code == "partial_enumeration"
    assert "changed during the walk" in unknown.detail


def test_a_stable_tree_records_no_partial_enumeration():
    """The race detector must not fire on a tree that did not move, or it is noise."""
    context = make_context()
    LineageCollector(os.getpid())._walk_tree(context)

    assert not [u for u in context.snapshot().unknowns if u.code == "partial_enumeration"]


def test_a_renamed_descriptor_target_is_reported_as_observed_not_guessed(tmp_path):
    """After a rename the kernel's answer is the only honest one.

    Reconstructing a path would name a file that may now be something else entirely, which is
    precisely the substitution an adversary would arrange.
    """
    target = tmp_path / "original.txt"
    target.write_text("x")
    handle = open(target)  # noqa: SIM115 - held open deliberately across the rename
    try:
        target.rename(tmp_path / "renamed.txt")

        context = make_context()
        collector = LineageCollector(os.getpid())
        observed = collector._read_link(context, f"/proc/self/fd/{handle.fileno()}")

        assert observed is not None
        assert observed.endswith("renamed.txt")
        assert "original.txt" not in observed
    finally:
        handle.close()


def test_a_deleted_descriptor_target_keeps_the_kernels_deleted_marker(tmp_path):
    target = tmp_path / "gone.txt"
    target.write_text("x")
    handle = open(target)  # noqa: SIM115 - held open deliberately across the unlink
    try:
        target.unlink()

        context = make_context()
        observed = LineageCollector(os.getpid())._read_link(
            context, f"/proc/self/fd/{handle.fileno()}"
        )

        assert observed is not None
        assert "(deleted)" in observed
    finally:
        handle.close()


def test_a_vanished_link_yields_nothing_rather_than_an_invented_path():
    context = make_context()
    observed = LineageCollector(os.getpid())._read_link(context, "/proc/self/fd/999999")
    assert observed is None


def test_a_denied_link_read_records_an_unknown_that_can_cover_a_file_finding(monkeypatch):
    """The unknown from a failed link read must be able to cover a can-read/file finding.

    Regression: this used to scope the unknown to the process identity
    ("process_identity:pid:N"), but every can-read finding this collector emits is named by its
    *target* path under "resource:file:...". The two namespaces never overlapped, so
    AccessUnknown.covers could never match -- a link readable on one scan and denied on the next
    would report as `removed` (a real access change) instead of `indeterminate` (a scan failure),
    the opposite of what this mechanism exists to prevent.
    """

    def deny(path):
        raise PermissionError(13, "denied")

    monkeypatch.setattr(os, "readlink", deny)
    context = make_context()
    LineageCollector(os.getpid())._read_link(context, "/proc/self/cwd")

    snapshot = context.snapshot()
    assert len(snapshot.unknowns) == 1
    unknown = snapshot.unknowns[0]
    assert unknown.relation == "can-read"
    assert unknown.object_prefix == "resource:file:"

    would_be_finding = AccessFinding(
        finding_id="f:cwd",
        session_id="s:test",
        subject="process_identity:pid:1",
        relation="can-read",
        object="resource:file:/home/op/project",
        classification="observed",
        confidence="high",
        evidence=(Evidence("proc_cwd", "collect.lineage", NOW, "cwd of pid 1"),),
        freshness=Freshness(NOW, UNTIL),
        enforcement=Enforcement("unknown", "none"),
    )
    assert unknown.covers(would_be_finding)


# -- bounds ----------------------------------------------------------------------------------


def test_descendant_enumeration_is_bounded():
    context = make_context(budget=Budget(max_entries_per_scope=1))
    run_collectors([LineageCollector(os.getpid())], context)

    snapshot = context.snapshot()
    bounded = [u for u in snapshot.unknowns if u.code == "collector_bounded_out"]
    assert bounded


def test_repeated_passes_over_a_stable_process_produce_stable_process_records():
    """Descriptor churn is expected; the process containment records must not churn with it."""
    first = run_collectors([LineageCollector(os.getpid())], make_context())
    second = run_collectors([LineageCollector(os.getpid())], make_context())

    assert objects(first, "contains") == objects(second, "contains")
