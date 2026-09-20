"""Description: Tests that the collector framework records every failure instead of going silent."""

from pathlib import Path

import pytest

from wakindex.collectors.base import (
    Budget,
    CollectorBudgetExceeded,
    CollectorContext,
    run_collectors,
)
from wakindex.graph import Enforcement, Evidence

NOW = "2026-09-20T18:00:00Z"
UNTIL = "2026-09-20T18:05:00Z"
SCOPE = {"relation": "can-read", "object_prefix": "resource:file:/proc"}


class FakeClock:
    """A clock the test advances by hand, so deadline tests do not sleep."""

    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def make_context(budget=None, clock=None):
    return CollectorContext(
        session_id="s:test",
        now=NOW,
        valid_until=UNTIL,
        budget=budget or Budget(),
        clock=clock or FakeClock(),
    )


def evidence():
    return (Evidence("proc_status", "collect.test", NOW, "seeded fixture"),)


class StubCollector:
    def __init__(self, name, scopes, action=None):
        self.name = name
        self.scopes = scopes
        self._action = action or (lambda context: None)

    def collect(self, context):
        self._action(context)


# -- recording ----------------------------------------------------------------------------


def test_emit_records_a_finding_with_the_caller_supplied_freshness():
    context = make_context()
    context.emit(
        collector="test",
        discriminator="0001",
        subject="session:test",
        relation="can-read",
        object="resource:file:/etc/hosts",
        classification="observed",
        confidence="high",
        evidence=evidence(),
    )

    finding = context.snapshot().findings[0]
    assert finding.finding_id == "f:test:0001"
    assert finding.freshness.collected_at == NOW
    assert finding.freshness.valid_until == UNTIL


def test_finding_ids_are_stable_across_identical_passes():
    """Unstable ids would make every scan look like a complete replacement of the graph."""
    first = make_context()
    second = make_context()
    for context in (first, second):
        context.emit(
            collector="test",
            discriminator="pid-42",
            subject="session:test",
            relation="can-read",
            object="resource:file:/etc/hosts",
            classification="observed",
            confidence="high",
            evidence=evidence(),
        )
    assert first.snapshot().normalized_json() == second.snapshot().normalized_json()


def test_a_finding_defaults_to_unknown_enforcement_not_to_safe():
    """A collector that says nothing about enforcement must not imply a boundary exists."""
    context = make_context()
    context.emit(
        collector="test",
        discriminator="0001",
        subject="session:test",
        relation="can-read",
        object="resource:file:/etc/hosts",
        classification="observed",
        confidence="high",
        evidence=evidence(),
    )
    assert context.snapshot().findings[0].enforcement.status == "unknown"


def test_enforcement_can_be_stated_when_a_boundary_is_known():
    context = make_context()
    context.emit(
        collector="test",
        discriminator="0001",
        subject="session:test",
        relation="can-read",
        object="resource:file:/home/op",
        classification="enforced",
        confidence="high",
        evidence=evidence(),
        enforcement=Enforcement("enforced", "landlock-fs", 4),
    )
    assert context.snapshot().findings[0].enforcement.mechanism == "landlock-fs"


# -- failure becomes an unknown ------------------------------------------------------------


def test_guard_turns_permission_denied_into_an_unknown():
    context = make_context()
    with context.guard(**SCOPE, detail="reading /proc/1/fd"):
        raise PermissionError(13, "Permission denied")

    unknown = context.snapshot().unknowns[0]
    assert unknown.code == "collector_permission_denied"
    assert unknown.object_prefix == "resource:file:/proc"


def test_guard_turns_an_unexpected_exception_into_an_unknown():
    """An unexpected bug must cost a scope its certainty, not its visibility."""
    context = make_context()
    with context.guard(**SCOPE, detail="parsing"):
        raise KeyError("uid")

    assert context.snapshot().unknowns[0].code == "partial_enumeration"


def test_guard_lets_the_collection_continue_after_a_failure():
    context = make_context()
    with context.guard(**SCOPE, detail="first"):
        raise OSError("boom")
    context.emit(
        collector="test",
        discriminator="after",
        subject="session:test",
        relation="can-read",
        object="resource:file:/etc/hosts",
        classification="observed",
        confidence="high",
        evidence=evidence(),
    )

    snapshot = context.snapshot()
    assert len(snapshot.findings) == 1
    assert len(snapshot.unknowns) == 1


def test_emit_after_the_deadline_records_a_timeout_instead_of_the_finding():
    """A collector that loops without bounded() must still be stopped by the budget."""
    clock = FakeClock()
    context = make_context(budget=Budget(deadline_seconds=1.0), clock=clock)
    clock.advance(2.0)

    context.emit(
        collector="test",
        discriminator="late",
        subject="session:test",
        relation="can-read",
        object="resource:file:/etc/hosts",
        classification="observed",
        confidence="high",
        evidence=evidence(),
    )

    snapshot = context.snapshot()
    assert snapshot.findings == ()
    assert snapshot.unknowns[0].code == "collector_timeout"


def test_repeated_unknowns_over_one_scope_are_recorded_once():
    """One scope that timed out is one fact, not one fact per attempt."""
    context = make_context()
    for attempt in range(5):
        context.unknown(**SCOPE, code="collector_timeout", detail=f"attempt {attempt}")

    assert len(context.snapshot().unknowns) == 1


def test_a_different_code_over_the_same_scope_is_still_recorded():
    context = make_context()
    context.unknown(**SCOPE, code="collector_timeout", detail="slow")
    context.unknown(**SCOPE, code="collector_permission_denied", detail="denied")

    assert len(context.snapshot().unknowns) == 2


def test_check_deadline_raises_before_the_deadline_is_swallowed():
    clock = FakeClock()
    context = make_context(budget=Budget(deadline_seconds=1.0), clock=clock)
    clock.advance(1.5)
    with pytest.raises(CollectorBudgetExceeded):
        context.check_deadline()


# -- bounds --------------------------------------------------------------------------------


def test_bounded_stops_at_the_cap_and_says_so():
    context = make_context(budget=Budget(max_entries_per_scope=3))
    seen = list(context.bounded([str(n) for n in range(10)], **SCOPE, detail="fd walk"))

    assert seen == ["0", "1", "2"]
    unknown = context.snapshot().unknowns[0]
    assert unknown.code == "collector_bounded_out"
    assert "stopped after 3 entries" in unknown.detail


def test_bounded_stops_at_the_deadline_and_says_so():
    clock = FakeClock()
    context = make_context(budget=Budget(deadline_seconds=1.0), clock=clock)

    def entries():
        for index in range(10):
            if index == 2:
                clock.advance(5.0)
            yield str(index)

    seen = list(context.bounded(entries(), **SCOPE, detail="fd walk"))
    assert seen == ["0", "1"]
    assert context.snapshot().unknowns[0].code == "collector_timeout"


def test_emit_past_the_finding_cap_records_an_unknown_rather_than_dropping_silently():
    context = make_context(budget=Budget(max_findings=1))
    for index in range(3):
        context.emit(
            collector="test",
            discriminator=str(index),
            subject="session:test",
            relation="can-read",
            object=f"resource:file:/etc/hosts{index}",
            classification="observed",
            confidence="high",
            evidence=evidence(),
        )

    snapshot = context.snapshot()
    assert len(snapshot.findings) == 1
    assert len(snapshot.unknowns) == 2
    assert all(unknown.code == "collector_bounded_out" for unknown in snapshot.unknowns)


# -- bounded reads ---------------------------------------------------------------------------


def test_read_proc_text_refuses_a_path_outside_proc(tmp_path):
    """A collector that could read discovered paths would be reading content it was handed."""
    target = tmp_path / "secret.txt"
    target.write_text("data")
    context = make_context()

    with pytest.raises(ValueError, match="only /proc metadata"):
        context.read_proc_text(target)


def test_read_proc_text_reads_process_metadata():
    context = make_context()
    assert "Name:" in context.read_proc_text(Path("/proc/self/status"))


def test_read_proc_text_is_size_bounded(monkeypatch):
    monkeypatch.setattr("wakindex.collectors.base.MAX_PROC_READ_BYTES", 16)
    context = make_context()
    assert len(context.read_proc_text(Path("/proc/self/status"))) <= 16


# -- runner ----------------------------------------------------------------------------------


def test_run_collectors_records_a_failing_collector_over_its_declared_scopes():
    """The unknown must cover what the collector was responsible for.

    An unknown over some unrelated scope would leave the collector's findings uncovered, and the
    next diff would report them as access that had been removed rather than as unseen.
    """

    def explode(context):
        raise PermissionError(13, "Permission denied")

    failing = StubCollector(
        "lineage",
        (("can-read", "resource:file:/proc"), ("contains", "process_identity:pid:")),
        explode,
    )
    snapshot = run_collectors([failing], make_context())

    prefixes = {unknown.object_prefix for unknown in snapshot.unknowns}
    assert prefixes == {"resource:file:/proc", "process_identity:pid:"}
    assert all(u.code == "collector_permission_denied" for u in snapshot.unknowns)


def test_run_collectors_isolates_one_failure_from_the_others():
    def explode(context):
        raise RuntimeError("bad parse")

    def succeed(context):
        context.emit(
            collector="mounts",
            discriminator="0001",
            subject="session:test",
            relation="can-read",
            object="resource:file:/",
            classification="declared",
            confidence="high",
            evidence=evidence(),
        )

    snapshot = run_collectors(
        [
            StubCollector("broken", (("can-read", "resource:file:/proc"),), explode),
            StubCollector("mounts", (("can-read", "resource:file:/"),), succeed),
        ],
        make_context(),
    )

    assert len(snapshot.findings) == 1
    assert len(snapshot.unknowns) == 1
    assert snapshot.unknowns[0].code == "partial_enumeration"


def test_run_collectors_rejects_a_collector_that_declares_no_scope():
    """A scopeless collector could fail invisibly, so this is refused rather than tolerated."""
    with pytest.raises(ValueError, match="declares no scopes"):
        run_collectors([StubCollector("nameless", ())], make_context())


def test_run_collectors_records_a_timeout_when_the_budget_is_already_spent():
    clock = FakeClock()
    context = make_context(budget=Budget(deadline_seconds=1.0), clock=clock)
    clock.advance(2.0)

    ran = []
    snapshot = run_collectors(
        [StubCollector("late", (("can-read", "resource:file:/proc"),), lambda c: ran.append(1))],
        context,
    )

    assert ran == []
    assert snapshot.unknowns[0].code == "collector_timeout"


# -- the collectors must never execute what they discover -------------------------------------


def test_collectors_package_imports_no_execution_module():
    """A collector that can execute is an execution path for whatever wrote the config it read."""
    import ast

    package = Path(__file__).parent.parent / "src" / "wakindex" / "collectors"
    forbidden = {"subprocess", "os.system", "pty", "shlex", "runpy", "importlib"}

    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name not in forbidden, f"{path.name} imports {alias.name}"
            elif isinstance(node, ast.ImportFrom) and node.module:
                assert node.module not in forbidden, f"{path.name} imports from {node.module}"


def test_collectors_package_calls_no_execution_api():
    import ast

    package = Path(__file__).parent.parent / "src" / "wakindex" / "collectors"
    forbidden = {"system", "popen", "execv", "execve", "execvp", "spawnv", "fork", "eval", "exec"}

    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            assert name not in forbidden, f"{path.name} calls {name}"


def test_the_same_finding_recorded_twice_is_kept_once():
    """A duplicate id would fail the whole snapshot, costing the pass everything it did see."""
    context = make_context()
    for _ in range(3):
        context.emit(
            collector="test",
            discriminator="same",
            subject="session:test",
            relation="grants",
            object="principal:gid:65534",
            classification="observed",
            confidence="high",
            evidence=evidence(),
        )

    snapshot = context.snapshot()
    assert len(snapshot.findings) == 1
    assert snapshot.unknowns == ()
