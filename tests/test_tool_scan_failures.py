"""Description: Failed tool scans must not turn missing observations into revoked access."""

import json

import pytest
from test_collector_tools import collect

from wakindex.collectors.base import Budget
from wakindex.collectors.tools import ToolCollector
from wakindex.graph import diff
from wakindex.models import Finding


def write_config(path, name="sample"):
    path.write_text(
        json.dumps(
            {
                "mcpServers": {
                    name: {"command": "node", "args": ["sample.js"]},
                    name + "-remote": {"url": "https://example.invalid/mcp"},
                }
            }
        )
    )


@pytest.mark.parametrize("failure", ["missing", "malformed", "denied"])
def test_failed_scan_makes_previous_capabilities_indeterminate(tmp_path, monkeypatch, failure):
    path = tmp_path / "mcp.json"
    write_config(path)
    before = collect([path], tmp_path)
    assert {f.relation for f in before.findings} >= {"can-invoke", "can-execute", "can-connect"}
    if failure == "missing":
        path.unlink()
    elif failure == "malformed":
        path.write_text("{broken")
    else:

        def denied(*args, **kwargs):
            raise PermissionError("fixture permission failure")

        monkeypatch.setattr("wakindex.collectors.tools.scan_config_file", denied)
    after = collect([path], tmp_path)
    result = diff(before, after)
    assert not result.removed
    assert set(result.indeterminate) == {f.finding_id for f in before.findings}


def test_one_failed_config_does_not_discard_successful_config(tmp_path):
    failed = tmp_path / "failed.json"
    healthy = tmp_path / "healthy.json"
    write_config(failed, "failed")
    write_config(healthy, "healthy")
    before = collect([failed, healthy], tmp_path)
    failed.unlink()
    after = collect([failed, healthy], tmp_path)
    assert any(f.object == "tool_server:mcp:healthy" for f in after.findings)
    assert not diff(before, after).removed
    assert diff(before, after).indeterminate


def test_capped_scan_covers_every_unenumerated_capability(tmp_path):
    path = tmp_path / "mcp.json"
    write_config(path)
    before = collect([path], tmp_path)
    after = collect([path], tmp_path, Budget(max_entries_per_scope=1))
    result = diff(before, after)
    assert result.indeterminate
    assert not result.removed


def test_runner_failure_covers_declared_filesystem_relations(tmp_path, monkeypatch):
    path = tmp_path / "mcp.json"
    write_config(path)
    findings = tuple(
        Finding(permission, "/workspace", str(path), "fixture", "low", {"path": "/workspace"})
        for permission in ("filesystem.read", "filesystem.write")
    )
    monkeypatch.setattr("wakindex.collectors.tools.scan_config_file", lambda *a, **kw: findings)
    before = collect([path], tmp_path)
    assert {f.relation for f in before.findings} == {"can-read", "can-write"}

    def failed_collect(self, context):
        raise RuntimeError("fixture runner failure")

    monkeypatch.setattr(ToolCollector, "collect", failed_collect)
    result = diff(before, collect([path], tmp_path))
    assert not result.removed
    assert len(result.indeterminate) == 2
