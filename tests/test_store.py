"""Description: Tests for access snapshot persistence, migrations, and stored diffs."""

import sqlite3

import pytest

from wakindex.graph import AccessFinding, AccessUnknown, Enforcement, Evidence, Freshness, Snapshot
from wakindex.store import (
    MIGRATIONS,
    STORE_VERSION,
    GraphStore,
    Migration,
    MigrationFailed,
    StoreError,
    StoreIncompatible,
    open_store,
)

NOW = "2026-09-20T18:00:00Z"


def make_finding(finding_id="f:0001", obj="resource:file:/home/op/project/README.md"):
    return AccessFinding(
        finding_id=finding_id,
        session_id="s:01JBQ2ZK4M",
        subject="session:01JBQ2ZK4M",
        relation="can-read",
        object=obj,
        classification="observed",
        confidence="high",
        evidence=(
            Evidence("proc_fd", "collect.files", "2026-09-20T17:40:03Z", "fd 7"),
            Evidence("mount_table", "collect.files", "2026-09-20T17:40:03Z", "rw on /home"),
        ),
        freshness=Freshness("2026-09-20T17:40:03Z", "2026-09-20T17:45:03Z"),
        enforcement=Enforcement("enforced", "landlock-fs", 4),
    )


def make_unknown(unknown_id="u:proc"):
    return AccessUnknown(
        unknown_id=unknown_id,
        session_id="s:01JBQ2ZK4M",
        relation="can-read",
        object_prefix="resource:file:/proc",
        code="collector_permission_denied",
        detail="opendir /proc/1: EACCES",
        collected_at="2026-09-20T17:50:00Z",
    )


@pytest.fixture
def store(tmp_path):
    with open_store(tmp_path / "graph.db", NOW) as opened:
        yield opened


# -- migrations ---------------------------------------------------------------------------


def test_open_store_migrates_to_the_current_version(tmp_path):
    with open_store(tmp_path / "graph.db", NOW) as opened:
        assert opened.current_version() == STORE_VERSION


def test_migrate_is_idempotent(store):
    assert store.migrate(NOW) == STORE_VERSION
    assert store.migrate(NOW) == STORE_VERSION


def test_a_newer_store_is_refused_rather_than_read_on_a_guess(tmp_path):
    path = tmp_path / "graph.db"
    with open_store(path, NOW):
        pass

    connection = sqlite3.connect(path)
    connection.execute(
        "INSERT INTO schema_migrations (version, description, applied_at) VALUES (?, ?, ?)",
        (STORE_VERSION + 1, "written by a newer build", NOW),
    )
    connection.commit()
    connection.close()

    with pytest.raises(StoreIncompatible):
        open_store(path, NOW)


def test_a_migration_that_would_drop_evidence_is_rolled_back(tmp_path, monkeypatch):
    path = tmp_path / "graph.db"
    with open_store(path, NOW) as opened:
        opened.put_snapshot(Snapshot("s:01JBQ2ZK4M", (make_finding(),)), NOW)
        assert opened._evidence_count() == 2

    destructive = Migration(
        version=STORE_VERSION + 1,
        description="drops evidence",
        statements=("DELETE FROM evidence",),
    )
    monkeypatch.setattr("wakindex.store.MIGRATIONS", (*MIGRATIONS, destructive))
    monkeypatch.setattr("wakindex.store.STORE_VERSION", destructive.version)

    with GraphStore(path) as opened:
        with pytest.raises(MigrationFailed):
            opened.migrate(NOW)
        # The rollback must leave both the evidence and the prior schema version intact.
        assert opened._evidence_count() == 2
        assert opened.current_version() == STORE_VERSION


def test_writes_are_refused_before_migration(tmp_path):
    with GraphStore(tmp_path / "graph.db") as opened:
        with pytest.raises(StoreError, match="not migrated"):
            opened.put_snapshot(Snapshot("s:1", (make_finding(),)), NOW)


# -- round trip ---------------------------------------------------------------------------


def test_snapshot_round_trips_with_evidence_and_unknowns(store):
    original = Snapshot("s:01JBQ2ZK4M", (make_finding(),), (make_unknown(),))
    snapshot_id = store.put_snapshot(original, NOW)

    restored = store.get_snapshot(snapshot_id)
    assert restored.as_dict() == original.as_dict()
    assert len(restored.findings[0].evidence) == 2
    assert restored.unknowns[0].code == "collector_permission_denied"


def test_evidence_order_is_preserved(store):
    snapshot_id = store.put_snapshot(Snapshot("s:1", (make_finding(),)), NOW)
    restored = store.get_snapshot(snapshot_id)
    assert [item.source for item in restored.findings[0].evidence] == ["proc_fd", "mount_table"]


def test_repeated_storage_of_an_unchanged_scan_reads_back_identically(store):
    snapshot = Snapshot("s:01JBQ2ZK4M", (make_finding("f:b"), make_finding("f:a")))
    first = store.get_snapshot(store.put_snapshot(snapshot, NOW))
    second = store.get_snapshot(store.put_snapshot(snapshot, "2026-09-20T19:00:00Z"))
    assert first.normalized_json() == second.normalized_json()


def test_a_rejected_snapshot_leaves_no_partial_rows(store):
    """A write that fails partway must not leave a snapshot missing its unknowns.

    Such a snapshot would read back as a complete scan with nothing unseen, which is exactly the
    false clean bill of health the contract forbids. The findings and evidence here are inserted
    before the failing unknown, so only a real rollback can satisfy this test.
    """
    before = store.snapshot_ids("s:1")
    duplicated = make_unknown("u:same")
    doomed = Snapshot("s:1", (make_finding(),), (duplicated, duplicated))

    with pytest.raises(sqlite3.IntegrityError):
        store.put_snapshot(doomed, NOW)

    assert store.snapshot_ids("s:1") == before
    assert store._evidence_count() == 0


def test_missing_snapshot_raises(store):
    with pytest.raises(StoreError, match="no snapshot"):
        store.get_snapshot(4242)


# -- queries ------------------------------------------------------------------------------


def test_snapshot_ids_are_scoped_to_a_session(store):
    store.put_snapshot(Snapshot("s:a", (make_finding(),)), NOW)
    store.put_snapshot(Snapshot("s:b", (make_finding(),)), NOW)
    store.put_snapshot(Snapshot("s:a", (make_finding(),)), NOW)

    assert len(store.snapshot_ids("s:a")) == 2
    assert len(store.snapshot_ids("s:b")) == 1


def test_latest_snapshot_returns_none_for_an_unknown_session(store):
    assert store.latest_snapshot("s:never") is None


def test_stored_diff_marks_a_failed_scope_indeterminate(store):
    lost = make_finding("f:proc", obj="resource:file:/proc/1/environ")
    before_id = store.put_snapshot(Snapshot("s:1", (lost, make_finding("f:keep"))), NOW)
    after_id = store.put_snapshot(
        Snapshot("s:1", (make_finding("f:keep"),), (make_unknown(),)), NOW
    )

    result = store.diff_snapshots(before_id, after_id)
    assert result.removed == ()
    assert result.indeterminate == ("f:proc",)
    assert result.carried_unknowns == ("u:proc",)


def test_stored_diff_reports_a_real_removal(store):
    before_id = store.put_snapshot(
        Snapshot("s:1", (make_finding("f:gone"), make_finding("f:keep"))), NOW
    )
    after_id = store.put_snapshot(Snapshot("s:1", (make_finding("f:keep"),)), NOW)

    result = store.diff_snapshots(before_id, after_id)
    assert result.removed == ("f:gone",)
    assert result.indeterminate == ()
