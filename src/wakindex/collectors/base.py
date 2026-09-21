"""Description: Bounded collector framework that records collection failures as unknowns."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from wakindex.graph import (
    AccessFinding,
    AccessUnknown,
    Enforcement,
    Evidence,
    Freshness,
    Snapshot,
)

# Reading a discovered file's contents is how a collector becomes an execution path for whatever
# wrote that file. Collectors read process metadata under /proc only, and only up to this size.
MAX_PROC_READ_BYTES = 256 * 1024


class CollectorBudgetExceeded(RuntimeError):
    """The collection deadline passed. Raised inside a guard, recorded as a timeout unknown."""


@dataclass(frozen=True)
class Budget:
    """Limits the framework enforces, so no collector has to remember to check them."""

    deadline_seconds: float = 5.0
    max_findings: int = 10_000
    max_entries_per_scope: int = 1_000


@dataclass
class CollectorContext:
    """Collection state for one pass: what was found, what could not be seen, and the budget.

    `now` and `valid_until` are supplied by the caller rather than computed here, so a collector
    cannot disagree with the supervisor about when this pass happened or how long it may be
    trusted.
    """

    session_id: str
    now: str
    valid_until: str
    budget: Budget = field(default_factory=Budget)
    clock: Callable[[], float] = time.monotonic

    def __post_init__(self) -> None:
        self._started = self.clock()
        self._findings: list[AccessFinding] = []
        self._finding_ids: set[str] = set()
        self._unknowns: list[AccessUnknown] = []
        self._unknown_keys: set[tuple[str, str, str]] = set()
        self._unknown_seq = 0

    # -- budget ---------------------------------------------------------------------------

    @property
    def elapsed(self) -> float:
        return self.clock() - self._started

    @property
    def deadline_passed(self) -> bool:
        return self.elapsed >= self.budget.deadline_seconds

    def check_deadline(self) -> None:
        if self.deadline_passed:
            raise CollectorBudgetExceeded(
                f"collection deadline of {self.budget.deadline_seconds}s passed"
            )

    # -- recording ------------------------------------------------------------------------

    def finding_id(self, collector: str, discriminator: str) -> str:
        """A stable id for a finding within a session, so repeated scans produce equal ids."""
        return f"f:{collector}:{discriminator}"

    def emit(
        self,
        *,
        collector: str,
        discriminator: str,
        subject: str,
        relation: str,
        object: str,
        classification: str,
        confidence: str,
        evidence: Iterable[Evidence],
        enforcement: Enforcement | None = None,
    ) -> None:
        """Record one finding, or an unknown when a budget stops it from being recorded."""
        if self.deadline_passed:
            self.unknown(
                relation=relation,
                object_prefix=object,
                code="collector_timeout",
                detail=f"{collector}: deadline passed before this finding was recorded",
            )
            return
        finding_id = self.finding_id(collector, discriminator)
        if finding_id in self._finding_ids:
            # The same fact recorded twice is still one fact. Letting a duplicate through would
            # fail the whole snapshot at construction, costing the pass everything it did see.
            return
        if len(self._findings) >= self.budget.max_findings:
            self.unknown(
                relation=relation,
                object_prefix=object,
                code="collector_bounded_out",
                detail=f"{collector}: finding cap of {self.budget.max_findings} reached",
            )
            return
        self._findings.append(
            AccessFinding(
                finding_id=finding_id,
                session_id=self.session_id,
                subject=subject,
                relation=relation,
                object=object,
                classification=classification,
                confidence=confidence,
                evidence=tuple(evidence),
                freshness=Freshness(self.now, self.valid_until),
                enforcement=enforcement or Enforcement("unknown", "none"),
            )
        )
        self._finding_ids.add(finding_id)

    def unknown(self, *, relation: str, object_prefix: str, code: str, detail: str) -> None:
        """Record a scope that could not be seen. Never call this with a secret in `detail`.

        Repeats of the same code over the same scope are dropped. One scope that timed out is one
        fact; recording it once per attempt would bury the rest of the snapshot in restatements.
        """
        key = (relation, object_prefix, code)
        if key in self._unknown_keys:
            return
        self._unknown_keys.add(key)
        self._unknown_seq += 1
        self._unknowns.append(
            AccessUnknown(
                unknown_id=f"u:{self._unknown_seq:04d}",
                session_id=self.session_id,
                relation=relation,
                object_prefix=object_prefix,
                code=code,
                detail=detail,
                collected_at=self.now,
            )
        )

    # -- failure handling -----------------------------------------------------------------

    @contextmanager
    def guard(self, *, relation: str, object_prefix: str, detail: str) -> Iterator[None]:
        """Run a collection step, converting any failure into an unknown over its scope.

        Silence is the one outcome a collector must never produce: a scope that failed and was
        not recorded is indistinguishable from a scope with nothing in it.

        The deadline is not checked here. A context manager cannot skip its own body, so the
        budget is enforced where recording happens instead: emit, bounded, and run_collectors.
        """
        try:
            yield
        except Exception as err:  # noqa: BLE001 - every failure becomes a recorded unknown
            code, reason = _classify(err)
            self.unknown(
                relation=relation,
                object_prefix=object_prefix,
                code=code,
                detail=f"{detail}: {reason}",
            )

    def bounded(
        self, entries: Iterable[str], *, relation: str, object_prefix: str, detail: str
    ) -> Iterator[str]:
        """Yield at most the per-scope cap, recording an unknown when entries are left over."""
        count = 0
        iterator = iter(entries)
        for entry in iterator:
            if count >= self.budget.max_entries_per_scope:
                self.unknown(
                    relation=relation,
                    object_prefix=object_prefix,
                    code="collector_bounded_out",
                    detail=f"{detail}: stopped after {count} entries",
                )
                return
            if self.deadline_passed:
                self.unknown(
                    relation=relation,
                    object_prefix=object_prefix,
                    code="collector_timeout",
                    detail=f"{detail}: deadline passed after {count} entries",
                )
                return
            count += 1
            yield entry

    # -- bounded reads --------------------------------------------------------------------

    def read_proc_text(self, path: Path) -> str:
        """Read a bounded amount of process metadata.

        Only paths under /proc are accepted. A collector that could read arbitrary files would be
        reading content it discovered, which is the behaviour the architecture forbids.

        The check resolves the path first rather than testing the string as given: a lexical
        check alone accepts a traversal segment such as `/proc/self/../../../../etc/passwd`
        (which is still a string starting with `/proc/`) and would also follow a magic symlink
        such as `/proc/<pid>/cwd` to whatever it points at outside /proc. No current caller
        constructs a path like that, but the guarantee this function exists to provide should
        hold structurally, not by accident of what callers happen to pass today.
        """
        resolved = Path(path).resolve()
        if not str(resolved).startswith("/proc/"):
            raise ValueError(f"collectors read only /proc metadata, not {resolved}")
        with resolved.open("rb") as handle:
            return handle.read(MAX_PROC_READ_BYTES).decode("utf-8", errors="replace")

    # -- result ---------------------------------------------------------------------------

    def snapshot(self) -> Snapshot:
        return Snapshot(
            session_id=self.session_id,
            findings=tuple(self._findings),
            unknowns=tuple(self._unknowns),
        )


class Collector(Protocol):
    """A collection step. Implementations record through the context and return nothing.

    `scopes` declares the (relation, object_prefix) pairs this collector is responsible for. When
    it fails outright, the framework records an unknown over each of them. A collector that
    declared no scope would fail invisibly: its findings would be missing from the next snapshot
    with nothing covering them, and a diff would report them as access that had been removed.
    """

    name: str
    scopes: tuple[tuple[str, str], ...]

    def collect(self, context: CollectorContext) -> None: ...


def run_collectors(collectors: Iterable[Collector], context: CollectorContext) -> Snapshot:
    """Run every collector, isolating each one's failure to the scopes it declared.

    One collector raising must not cost the others their results, and must not cost its own
    scopes their visibility.
    """
    for collector in collectors:
        if not collector.scopes:
            raise ValueError(f"collector {collector.name} declares no scopes")
        try:
            context.check_deadline()
            collector.collect(context)
        except Exception as err:  # noqa: BLE001 - every failure becomes a recorded unknown
            code, reason = _classify(err)
            for relation, object_prefix in collector.scopes:
                context.unknown(
                    relation=relation,
                    object_prefix=object_prefix,
                    code=code,
                    detail=f"collector {collector.name}: {reason}",
                )
    return context.snapshot()


def _classify(err: Exception) -> tuple[str, str]:
    """Map a collection failure onto a documented unknown code."""
    if isinstance(err, CollectorBudgetExceeded):
        return "collector_timeout", str(err)
    if isinstance(err, PermissionError):
        return "collector_permission_denied", err.strerror or "permission denied"
    if isinstance(err, TimeoutError):
        return "collector_timeout", err.strerror or "timed out"
    return "partial_enumeration", type(err).__name__
