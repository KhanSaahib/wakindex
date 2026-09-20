"""Description: Transactional local persistence and versioned migrations for access snapshots."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from dataclasses import dataclass, fields, is_dataclass, replace
from pathlib import Path
from typing import Any

from wakindex.graph import (
    AccessFinding,
    AccessUnknown,
    ContractError,
    Enforcement,
    Evidence,
    Freshness,
    Snapshot,
    SnapshotDiff,
    diff,
)

# The store version this build understands. A store at a higher version is refused rather than
# read on a guess; a downgrade that silently ignored newer columns would drop evidence.
STORE_VERSION = 2


class StoreError(RuntimeError):
    """The store cannot be used as requested."""


class StoreIncompatible(StoreError):
    """The store was written by a newer build than this one."""


class MigrationFailed(StoreError):
    """A migration was rolled back because it would not have preserved evidence."""


@dataclass(frozen=True)
class Migration:
    """One forward step in the store schema."""

    version: int
    description: str
    statements: tuple[str, ...]


MIGRATIONS: tuple[Migration, ...] = (
    Migration(
        version=1,
        description="initial access graph tables",
        statements=(
            """
            CREATE TABLE snapshots (
                snapshot_id    INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id     TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                created_at     TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE findings (
                snapshot_id            INTEGER NOT NULL REFERENCES snapshots(snapshot_id),
                finding_id             TEXT NOT NULL,
                session_id             TEXT NOT NULL,
                subject                TEXT NOT NULL,
                relation               TEXT NOT NULL,
                object                 TEXT NOT NULL,
                classification         TEXT NOT NULL,
                confidence             TEXT NOT NULL,
                enforcement_status     TEXT NOT NULL,
                enforcement_mechanism  TEXT NOT NULL,
                policy_revision        INTEGER,
                schema_version         TEXT NOT NULL,
                PRIMARY KEY (snapshot_id, finding_id)
            )
            """,
            """
            CREATE TABLE evidence (
                snapshot_id  INTEGER NOT NULL,
                finding_id   TEXT NOT NULL,
                ordinal      INTEGER NOT NULL,
                source       TEXT NOT NULL,
                collector    TEXT NOT NULL,
                collected_at TEXT NOT NULL,
                detail       TEXT NOT NULL,
                PRIMARY KEY (snapshot_id, finding_id, ordinal)
            )
            """,
            """
            CREATE TABLE freshness (
                snapshot_id  INTEGER NOT NULL,
                finding_id   TEXT NOT NULL,
                collected_at TEXT NOT NULL,
                valid_until  TEXT NOT NULL,
                stale        INTEGER NOT NULL,
                PRIMARY KEY (snapshot_id, finding_id)
            )
            """,
            """
            CREATE TABLE unknowns (
                snapshot_id    INTEGER NOT NULL REFERENCES snapshots(snapshot_id),
                unknown_id     TEXT NOT NULL,
                session_id     TEXT NOT NULL,
                relation       TEXT NOT NULL,
                object_prefix  TEXT NOT NULL,
                code           TEXT NOT NULL,
                detail         TEXT NOT NULL,
                collected_at   TEXT NOT NULL,
                schema_version TEXT NOT NULL,
                PRIMARY KEY (snapshot_id, unknown_id)
            )
            """,
            """
            CREATE TABLE schema_migrations (
                version     INTEGER PRIMARY KEY,
                description TEXT NOT NULL,
                applied_at  TEXT NOT NULL
            )
            """,
            "CREATE INDEX idx_snapshots_session ON snapshots(session_id, snapshot_id)",
        ),
    ),
    Migration(
        version=2,
        description="preserve additive evidence in a full snapshot document",
        statements=("ALTER TABLE snapshots ADD COLUMN document_json TEXT",),
    ),
)


class GraphStore:
    """Append-only local storage for access snapshots.

    Every write is a single transaction. A snapshot is stored whole or not at all, so a crash
    mid-write cannot leave a snapshot that is missing its unknowns and therefore looks complete.
    """

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._connection = sqlite3.connect(self.path, isolation_level=None)
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA journal_mode = WAL")

    def __enter__(self) -> GraphStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def close(self) -> None:
        self._connection.close()

    # -- schema ---------------------------------------------------------------------------

    def current_version(self) -> int:
        tables = self._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
        ).fetchone()
        if tables is None:
            return 0
        row = self._connection.execute(
            "SELECT MAX(version) AS version FROM schema_migrations"
        ).fetchone()
        return int(row["version"] or 0)

    def migrate(self, now: str) -> int:
        """Apply pending migrations. Each runs in its own transaction and preserves evidence."""
        version = self.current_version()
        if version > STORE_VERSION:
            raise StoreIncompatible(
                f"store is at version {version}; this build understands {STORE_VERSION}"
            )

        for migration in MIGRATIONS:
            if migration.version <= version:
                continue
            before = self._evidence_count()
            self._connection.execute("BEGIN")
            try:
                for statement in migration.statements:
                    self._connection.execute(statement)
                self._connection.execute(
                    "INSERT INTO schema_migrations (version, description, applied_at) "
                    "VALUES (?, ?, ?)",
                    (migration.version, migration.description, now),
                )
                after = self._evidence_count()
                if after < before:
                    raise MigrationFailed(
                        f"migration {migration.version} would drop evidence "
                        f"({before} rows before, {after} after)"
                    )
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
            self._connection.execute("COMMIT")
            version = migration.version
        return version

    def _evidence_count(self) -> int:
        table = self._connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='evidence'"
        ).fetchone()
        if table is None:
            return 0
        return int(self._connection.execute("SELECT COUNT(*) AS n FROM evidence").fetchone()["n"])

    def _require_ready(self) -> None:
        if self.current_version() > STORE_VERSION:
            raise StoreIncompatible("store is newer than this build")
        if self.current_version() < STORE_VERSION:
            raise StoreError("store is not migrated; call migrate() first")

    # -- writes ---------------------------------------------------------------------------

    def put_snapshot(self, snapshot: Snapshot, now: str) -> int:
        """Store a snapshot and return its id. Whole snapshot or nothing."""
        self._require_ready()
        self._connection.execute("BEGIN")
        try:
            cursor = self._connection.execute(
                "INSERT INTO snapshots (session_id, schema_version, created_at, document_json) "
                "VALUES (?, ?, ?, ?)",
                (
                    snapshot.session_id,
                    snapshot.schema_version,
                    now,
                    json.dumps(snapshot.as_dict(), allow_nan=False),
                ),
            )
            snapshot_id = int(cursor.lastrowid)

            for finding in snapshot.findings:
                self._connection.execute(
                    "INSERT INTO findings (snapshot_id, finding_id, session_id, subject, relation,"
                    " object, classification, confidence, enforcement_status,"
                    " enforcement_mechanism, policy_revision, schema_version)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        snapshot_id,
                        finding.finding_id,
                        finding.session_id,
                        finding.subject,
                        finding.relation,
                        finding.object,
                        finding.classification,
                        finding.confidence,
                        finding.enforcement.status,
                        finding.enforcement.mechanism,
                        finding.enforcement.policy_revision,
                        finding.schema_version,
                    ),
                )
                self._connection.execute(
                    "INSERT INTO freshness (snapshot_id, finding_id, collected_at, valid_until,"
                    " stale) VALUES (?, ?, ?, ?, ?)",
                    (
                        snapshot_id,
                        finding.finding_id,
                        finding.freshness.collected_at,
                        finding.freshness.valid_until,
                        int(finding.freshness.stale),
                    ),
                )
                for ordinal, item in enumerate(finding.evidence):
                    self._connection.execute(
                        "INSERT INTO evidence (snapshot_id, finding_id, ordinal, source, collector,"
                        " collected_at, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (
                            snapshot_id,
                            finding.finding_id,
                            ordinal,
                            item.source,
                            item.collector,
                            item.collected_at,
                            item.detail,
                        ),
                    )

            for unknown in snapshot.unknowns:
                self._connection.execute(
                    "INSERT INTO unknowns (snapshot_id, unknown_id, session_id, relation,"
                    " object_prefix, code, detail, collected_at, schema_version)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        snapshot_id,
                        unknown.unknown_id,
                        unknown.session_id,
                        unknown.relation,
                        unknown.object_prefix,
                        unknown.code,
                        unknown.detail,
                        unknown.collected_at,
                        unknown.schema_version,
                    ),
                )
        except Exception:
            self._connection.execute("ROLLBACK")
            raise
        self._connection.execute("COMMIT")
        return snapshot_id

    # -- reads ----------------------------------------------------------------------------

    def get_snapshot(self, snapshot_id: int) -> Snapshot:
        self._require_ready()
        header = self._connection.execute(
            "SELECT session_id, schema_version, document_json FROM snapshots WHERE snapshot_id = ?",
            (snapshot_id,),
        ).fetchone()
        if header is None:
            raise StoreError(f"no snapshot {snapshot_id}")

        findings = tuple(self._read_findings(snapshot_id))
        unknowns = tuple(self._read_unknowns(snapshot_id))
        indexed = Snapshot(
            session_id=header["session_id"],
            findings=findings,
            unknowns=unknowns,
            schema_version=header["schema_version"],
        )
        # Version-one rows have only relational evidence. New rows retain the complete JSON
        # document too, so future additive fields cannot disappear at a relational boundary.
        if header["document_json"] is None:
            return indexed
        document = Snapshot.from_dict(json.loads(header["document_json"]))
        known = _known_record(document)
        known = replace(
            known, unknowns=tuple(sorted(known.unknowns, key=lambda row: row.unknown_id))
        )
        if known.as_dict() != indexed.as_dict():
            raise StoreError("snapshot document disagrees with indexed evidence")
        return document

    def _read_findings(self, snapshot_id: int) -> Iterator[AccessFinding]:
        rows = self._connection.execute(
            "SELECT * FROM findings WHERE snapshot_id = ? ORDER BY finding_id", (snapshot_id,)
        ).fetchall()
        for row in rows:
            evidence_rows = self._connection.execute(
                "SELECT source, collector, collected_at, detail FROM evidence"
                " WHERE snapshot_id = ? AND finding_id = ? ORDER BY ordinal",
                (snapshot_id, row["finding_id"]),
            ).fetchall()
            fresh = self._connection.execute(
                "SELECT collected_at, valid_until, stale FROM freshness"
                " WHERE snapshot_id = ? AND finding_id = ?",
                (snapshot_id, row["finding_id"]),
            ).fetchone()
            if fresh is None or not evidence_rows:
                raise StoreError(
                    f"snapshot {snapshot_id} finding {row['finding_id']} lost its sidecar"
                )
            yield AccessFinding(
                finding_id=row["finding_id"],
                session_id=row["session_id"],
                subject=row["subject"],
                relation=row["relation"],
                object=row["object"],
                classification=row["classification"],
                confidence=row["confidence"],
                evidence=tuple(
                    Evidence(
                        source=item["source"],
                        collector=item["collector"],
                        collected_at=item["collected_at"],
                        detail=item["detail"],
                    )
                    for item in evidence_rows
                ),
                freshness=Freshness(
                    collected_at=fresh["collected_at"],
                    valid_until=fresh["valid_until"],
                    stale=bool(fresh["stale"]),
                ),
                enforcement=Enforcement(
                    status=row["enforcement_status"],
                    mechanism=row["enforcement_mechanism"],
                    policy_revision=row["policy_revision"],
                ),
                schema_version=row["schema_version"],
            )

    def _read_unknowns(self, snapshot_id: int) -> Iterator[AccessUnknown]:
        rows = self._connection.execute(
            "SELECT * FROM unknowns WHERE snapshot_id = ? ORDER BY unknown_id", (snapshot_id,)
        ).fetchall()
        for row in rows:
            yield AccessUnknown(
                unknown_id=row["unknown_id"],
                session_id=row["session_id"],
                relation=row["relation"],
                object_prefix=row["object_prefix"],
                code=row["code"],
                detail=row["detail"],
                collected_at=row["collected_at"],
                schema_version=row["schema_version"],
            )

    def snapshot_ids(self, session_id: str) -> tuple[int, ...]:
        self._require_ready()
        rows = self._connection.execute(
            "SELECT snapshot_id FROM snapshots WHERE session_id = ? ORDER BY snapshot_id",
            (session_id,),
        ).fetchall()
        return tuple(int(row["snapshot_id"]) for row in rows)

    def latest_snapshot(self, session_id: str) -> Snapshot | None:
        ids = self.snapshot_ids(session_id)
        return self.get_snapshot(ids[-1]) if ids else None

    def diff_snapshots(self, before_id: int, after_id: int) -> SnapshotDiff:
        """Diff two stored snapshots, honouring unknowns recorded in the later one."""
        return diff(self.get_snapshot(before_id), self.get_snapshot(after_id))


def open_store(path: Path | str, now: str) -> GraphStore:
    """Open a store and bring it to the current schema version."""
    store = GraphStore(path)
    try:
        store.migrate(now)
    except (StoreError, ContractError):
        store.close()
        raise
    return store


def _known_record(value: Any) -> Any:
    """Compare the understood projection without discarding extensions from the real record."""
    if isinstance(value, tuple):
        return tuple(_known_record(item) for item in value)
    if is_dataclass(value) and not isinstance(value, type):
        return replace(
            value,
            **{
                item.name: (
                    {}
                    if item.name in {"extensions", "scope_extensions"}
                    else _known_record(getattr(value, item.name))
                )
                for item in fields(value)
            },
        )
    return value
