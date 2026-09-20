"""Description: Forward-compatible evidence round trips and migration regression tests."""

import copy
import sqlite3

import pytest
from test_store import NOW, make_finding, make_unknown

from wakindex.graph import ContractError, SecretInEvidence, Snapshot
from wakindex.store import MIGRATIONS, GraphStore, StoreError, open_store


def extended_snapshot():
    data = Snapshot("s:01JBQ2ZK4M", (make_finding(),), (make_unknown(),)).as_dict()
    data["schema_version"] = "1.1"
    finding = data["findings"][0]
    for index, record in enumerate(
        (
            data,
            finding,
            finding["evidence"][0],
            finding["freshness"],
            finding["enforcement"],
            data["unknowns"][0],
            data["unknowns"][0]["scope"],
        )
    ):
        record["future_evidence"] = {"index": index, "nested": [True, None, "proof"]}
    return data


def test_decode_and_export_preserve_all_additive_evidence():
    data = extended_snapshot()
    assert Snapshot.from_dict(data).as_dict() == data


def test_store_preserves_all_additive_evidence_after_reopen(tmp_path):
    data = extended_snapshot()
    path = tmp_path / "graph.db"
    with open_store(path, NOW) as store:
        snapshot_id = store.put_snapshot(Snapshot.from_dict(data), NOW)
    with open_store(path, NOW) as store:
        assert store.get_snapshot(snapshot_id).as_dict() == data


def test_marking_stale_keeps_extension_evidence():
    data = extended_snapshot()
    expected = copy.deepcopy(data)
    expected["findings"][0]["freshness"]["stale"] = True
    assert Snapshot.from_dict(data).marked_stale(NOW).as_dict() == expected


def test_decoded_extensions_do_not_alias_input():
    data = extended_snapshot()
    snapshot = Snapshot.from_dict(data)
    data["future_evidence"]["nested"].append("later mutation")
    assert snapshot.as_dict()["future_evidence"]["nested"] == [True, None, "proof"]


def test_secret_shaped_extension_is_rejected():
    data = extended_snapshot()
    data["future_evidence"]["nested"].append("ghp_" + "A" * 30)
    with pytest.raises(SecretInEvidence):
        Snapshot.from_dict(data)


def test_version_one_store_upgrades_without_losing_evidence(tmp_path):
    path = tmp_path / "graph.db"
    connection = sqlite3.connect(path)
    for statement in MIGRATIONS[0].statements:
        connection.execute(statement)
    connection.execute("INSERT INTO schema_migrations VALUES (1, 'initial', ?)", (NOW,))
    connection.execute("INSERT INTO snapshots VALUES (1, 'legacy', '1.0', ?)", (NOW,))
    connection.commit()
    connection.close()
    with open_store(path, NOW) as store:
        assert store.get_snapshot(1).as_dict() == Snapshot("legacy", ()).as_dict()
        data = extended_snapshot()
        snapshot_id = store.put_snapshot(Snapshot.from_dict(data), NOW)
        assert store.get_snapshot(snapshot_id).as_dict() == data


def test_extension_corruption_fails_instead_of_silently_dropping_it(tmp_path):
    path = tmp_path / "graph.db"
    with open_store(path, NOW) as store:
        snapshot_id = store.put_snapshot(Snapshot.from_dict(extended_snapshot()), NOW)
    connection = sqlite3.connect(path)
    connection.execute("UPDATE snapshots SET document_json = 'not-json'")
    connection.commit()
    connection.close()
    with GraphStore(path) as store, pytest.raises(ValueError):
        store.get_snapshot(snapshot_id)


def test_version_one_evidence_survives_upgrade(tmp_path):
    path = tmp_path / "legacy.db"
    original = Snapshot("s:01JBQ2ZK4M", (make_finding(),), (make_unknown(),))
    with open_store(path, NOW) as store:
        snapshot_id = store.put_snapshot(original, NOW)
    connection = sqlite3.connect(path)
    connection.execute("ALTER TABLE snapshots DROP COLUMN document_json")
    connection.execute("DELETE FROM schema_migrations WHERE version = 2")
    connection.commit()
    connection.close()
    with open_store(path, NOW) as store:
        assert store.get_snapshot(snapshot_id).as_dict() == original.as_dict()


def test_index_and_document_disagreement_is_rejected(tmp_path):
    path = tmp_path / "graph.db"
    with open_store(path, NOW) as store:
        snapshot_id = store.put_snapshot(Snapshot.from_dict(extended_snapshot()), NOW)
    connection = sqlite3.connect(path)
    connection.execute("UPDATE evidence SET detail = 'altered evidence'")
    connection.commit()
    connection.close()
    with open_store(path, NOW) as store, pytest.raises(StoreError, match="disagrees"):
        store.get_snapshot(snapshot_id)


def test_extensions_cannot_override_known_fields():
    with pytest.raises(ContractError, match="override"):
        Snapshot("s:1", (), extensions={"session_id": "s:other"}).as_dict()


def test_secret_added_after_decode_is_rejected_before_store(tmp_path):
    snapshot = Snapshot.from_dict(extended_snapshot())
    snapshot.extensions["later"] = "ghp_" + "A" * 30
    with open_store(tmp_path / "graph.db", NOW) as store:
        with pytest.raises(SecretInEvidence):
            store.put_snapshot(snapshot, NOW)
        assert store.snapshot_ids(snapshot.session_id) == ()


def test_unknown_record_order_survives_index_sorting(tmp_path):
    snapshot = Snapshot("s:1", (), (make_unknown("u:z"), make_unknown("u:a")))
    with open_store(tmp_path / "graph.db", NOW) as store:
        snapshot_id = store.put_snapshot(snapshot, NOW)
        assert store.get_snapshot(snapshot_id).as_dict() == snapshot.as_dict()
