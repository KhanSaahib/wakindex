"""Description: Failed and bounded inventory reads must not claim access was revoked."""
import os

import pytest

from wakindex.collectors.base import Budget, CollectorContext, run_collectors
from wakindex.collectors.mounts import MountCollector
from wakindex.collectors.principal import PrincipalCollector
from wakindex.graph import diff


def context(**limits):
    return CollectorContext(
        "s:test", "2026-09-20T18:00:00Z", "2026-09-20T18:05:00Z", Budget(**limits)
    )


@pytest.mark.parametrize("status", [PermissionError(13, "denied"), "", "Uid: 1000\n"])
def test_shared_operator_authority_remains_unknown_after_partial_status(monkeypatch, status):
    collector = PrincipalCollector(os.getpid(), operator_uid=1000)
    before = context()
    monkeypatch.setattr(before, "read_proc_text", lambda path: "Uid: 1000 1000 1000 1000\n")
    original = run_collectors([collector], before)
    after = context()

    def read(path):
        if isinstance(status, Exception):
            raise status
        return status

    monkeypatch.setattr(after, "read_proc_text", read)
    result = diff(original, run_collectors([collector], after))
    shared = next(f.finding_id for f in original.findings if f.relation == "can-delegate")
    assert shared in result.indeterminate
    assert shared not in result.removed


@pytest.mark.parametrize("failure", ["denied", "cap", "malformed", "truncated"])
def test_writable_mounts_remain_indeterminate_after_incomplete_scan(monkeypatch, failure):
    table = "23 1 8:1 / / rw - ext4 /dev/sda1 rw\n24 1 8:2 / /data rw - ext4 /dev/sdb1 rw\n"
    before = context()
    monkeypatch.setattr(before, "read_proc_text", lambda path: table)
    original = run_collectors([MountCollector()], before)
    after = context(max_entries_per_scope=1 if failure == "cap" else 1000)

    def read(path):
        if failure == "denied":
            raise PermissionError(13, "denied")
        if failure == "malformed":
            return "invalid mount record\n"
        if failure == "truncated":
            return "23 1 8:1 / / rw - ext4"
        return table

    monkeypatch.setattr(after, "read_proc_text", read)
    result = diff(original, run_collectors([MountCollector()], after))
    assert not result.removed
    assert result.indeterminate


def test_actual_mount_read_byte_cap_preserves_unknown_write_scope(monkeypatch):
    original = run_collectors([MountCollector()], context())
    assert any(f.relation == "can-write" for f in original.findings)
    monkeypatch.setattr("wakindex.collectors.base.MAX_PROC_READ_BYTES", 16)
    after = run_collectors([MountCollector()], context())
    assert all(u.code == "collector_bounded_out" for u in after.unknowns)
    assert not diff(original, after).removed
    assert diff(original, after).indeterminate
