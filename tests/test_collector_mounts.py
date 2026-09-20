"""Description: Tests for the mount collector, propagation mode, and read-only detection."""

import pytest

from wakindex.collectors.base import Budget, CollectorContext, run_collectors
from wakindex.collectors.mounts import MountCollector, parse_mountinfo_line

NOW = "2026-09-20T18:00:00Z"
UNTIL = "2026-09-20T18:05:00Z"

ROOT_LINE = "23 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw"
RO_LINE = "24 23 0:36 / /usr/lib/wsl/drivers ro,nosuid - 9p drivers ro,aname=drivers"
SHARED_LINE = "25 23 0:34 / /mnt/wsl rw,relatime shared:1 - tmpfs none rw"
SLAVE_LINE = "26 23 0:35 / /mnt/host rw,relatime master:12 - tmpfs none rw"
RO_SUPERBLOCK_LINE = "27 23 8:2 / /snap/core rw,relatime - squashfs /dev/loop0 ro"


def make_context(budget=None):
    return CollectorContext("s:test", NOW, UNTIL, budget=budget or Budget())


# -- parsing --------------------------------------------------------------------------------


def test_parses_a_plain_mount():
    parsed = parse_mountinfo_line(ROOT_LINE)
    assert parsed["mount_point"] == "/"
    assert parsed["fs_type"] == "ext4"
    assert parsed["source"] == "/dev/sda1"
    assert parsed["writable"] is True
    assert parsed["propagation"] == "private"


def test_a_read_only_mount_is_not_reported_as_writable():
    assert parse_mountinfo_line(RO_LINE)["writable"] is False


def test_a_read_only_superblock_overrides_a_writable_mount_option():
    """rw at the mount point over a ro superblock is still not writable."""
    assert parse_mountinfo_line(RO_SUPERBLOCK_LINE)["writable"] is False


@pytest.mark.parametrize(
    ("line", "expected"),
    [(SHARED_LINE, "shared:1"), (SLAVE_LINE, "master:12"), (ROOT_LINE, "private")],
)
def test_propagation_mode_is_named(line, expected):
    """A shared mount can carry a new host mount into the perimeter after launch."""
    assert parse_mountinfo_line(line)["propagation"] == expected


def test_optional_fields_of_varying_count_do_not_shift_the_parse():
    """The optional field count varies, so the separator is found rather than an index assumed."""
    many = "28 23 0:37 / /x rw,relatime shared:2 master:3 propagate_from:4 - tmpfs none rw"
    parsed = parse_mountinfo_line(many)

    assert parsed["fs_type"] == "tmpfs"
    assert parsed["mount_point"] == "/x"
    assert parsed["propagation"] == "shared:2,master:3,propagate_from:4"


@pytest.mark.parametrize("line", ["", "not a mount line", "23 1 8:1 / / rw,relatime", "- - -"])
def test_a_malformed_line_is_skipped_rather_than_guessed(line):
    assert parse_mountinfo_line(line) is None


# -- collection -----------------------------------------------------------------------------


def test_the_real_mount_table_is_recorded():
    snapshot = run_collectors([MountCollector()], make_context())
    assert snapshot.findings
    assert any(f.object == "resource:mount:/" for f in snapshot.findings)


def test_every_mount_finding_is_declared_with_provenance():
    snapshot = run_collectors([MountCollector()], make_context())
    for finding in snapshot.findings:
        assert finding.classification == "declared"
        assert finding.evidence[0].source == "proc_mountinfo"
        assert finding.freshness.collected_at == NOW


def test_evidence_names_the_propagation_mode():
    snapshot = run_collectors([MountCollector()], make_context())
    assert all("propagation" in f.evidence[0].detail for f in snapshot.findings)


def test_a_writable_mount_is_recorded_as_can_write():
    context = make_context()
    MountCollector()._record_mount(context, ROOT_LINE)
    assert context.snapshot().findings[0].relation == "can-write"


def test_a_read_only_mount_is_recorded_as_can_read():
    context = make_context()
    MountCollector()._record_mount(context, RO_LINE)
    assert context.snapshot().findings[0].relation == "can-read"


def test_an_unreadable_mount_table_is_unknown_not_an_empty_filesystem():
    """Returning no mounts would say the process sees no filesystem, which is the reassuring lie."""
    snapshot = run_collectors([MountCollector(pid=2**30)], make_context())

    assert snapshot.findings == ()
    unknown = snapshot.unknowns[0]
    assert unknown.object_prefix == "resource:mount:"
    assert unknown.code in {"collector_permission_denied", "partial_enumeration"}


def test_mount_enumeration_is_bounded():
    context = make_context(budget=Budget(max_entries_per_scope=2))
    run_collectors([MountCollector()], context)

    snapshot = context.snapshot()
    assert len(snapshot.findings) <= 2
    assert any(u.code == "collector_bounded_out" for u in snapshot.unknowns)


def test_repeated_passes_produce_the_same_normalized_form():
    first = run_collectors([MountCollector()], make_context())
    second = run_collectors([MountCollector()], make_context())
    assert first.normalized_json() == second.normalized_json()
