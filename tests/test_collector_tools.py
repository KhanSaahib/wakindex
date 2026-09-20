"""Description: Tests that configured tool and MCP transports are recorded as declared access."""

import json
from pathlib import Path

from wakindex.collectors.base import Budget, CollectorContext, run_collectors
from wakindex.collectors.tools import ToolCollector

NOW = "2026-09-20T18:00:00Z"
UNTIL = "2026-09-20T18:05:00Z"

FIXTURES = Path(__file__).parent / "fixtures"
RISKY = FIXTURES / "risky_repo"


def make_context(budget=None):
    return CollectorContext("s:test", NOW, UNTIL, budget=budget or Budget())


def objects(snapshot, prefix=""):
    return {f.object for f in snapshot.findings if f.object.startswith(prefix)}


def collect(paths, root, budget=None):
    return run_collectors([ToolCollector(tuple(paths), root)], make_context(budget))


def test_configured_mcp_servers_are_recorded():
    snapshot = collect([RISKY / ".vscode" / "mcp.json"], RISKY)
    assert objects(snapshot, "tool_server:mcp:")


def test_a_configured_server_is_declared_never_observed():
    """A configuration file says what was asked for. It cannot show that anything happened."""
    snapshot = collect([RISKY / ".vscode" / "mcp.json", RISKY / ".claude" / "settings.json"], RISKY)

    assert snapshot.findings
    assert all(f.classification == "declared" for f in snapshot.findings)


def test_a_stdio_transport_is_recorded_as_an_executable():
    snapshot = collect([RISKY / ".vscode" / "mcp.json"], RISKY)
    executables = {f.object for f in snapshot.findings if f.relation == "can-execute"}
    assert executables


def test_an_http_transport_is_recorded_as_a_host():
    snapshot = collect([RISKY / ".vscode" / "mcp.json"], RISKY)
    assert objects(snapshot, "resource:net:host/")


def test_no_configured_finding_claims_enforcement():
    """Configuration says nothing about whether a boundary will permit any of it."""
    snapshot = collect([RISKY / ".vscode" / "mcp.json"], RISKY)
    assert all(f.enforcement.status == "unknown" for f in snapshot.findings)


def test_every_finding_names_the_file_it_came_from():
    snapshot = collect([RISKY / ".vscode" / "mcp.json"], RISKY)
    for finding in snapshot.findings:
        assert "mcp.json" in finding.evidence[0].detail
        assert finding.evidence[0].source == "agent_config"


# -- the collector must not execute what it reads ----------------------------------------------


def test_a_discovered_command_is_recorded_as_text_and_not_run(tmp_path):
    """A config file is written by whoever controls the workspace. Running its contents is the
    whole attack."""
    marker = tmp_path / "executed-marker"
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    "hostile": {
                        "command": "sh",
                        "args": ["-c", f"touch {marker}"],
                    }
                }
            }
        )
    )

    snapshot = collect([config], tmp_path)

    assert not marker.exists(), "the collector executed a discovered command"
    assert objects(snapshot, "tool_server:mcp:") == {"tool_server:mcp:hostile"}


# -- failure paths ---------------------------------------------------------------------------------


def test_a_missing_configuration_file_is_unknown_not_an_absent_server(tmp_path):
    snapshot = collect([tmp_path / "absent.json"], tmp_path)

    assert snapshot.findings == ()
    assert snapshot.unknowns[0].code == "agent_config_unreadable"


def test_a_malformed_configuration_file_is_unknown_not_an_absent_server(tmp_path):
    """An unparseable file and a file declaring nothing must not look the same."""
    config = tmp_path / "mcp.json"
    config.write_text("{ this is not json")

    snapshot = collect([config], tmp_path)

    assert snapshot.findings == ()
    assert snapshot.unknowns[0].code == "agent_config_unreadable"
    assert "unparseable" in snapshot.unknowns[0].detail


def test_an_empty_configuration_file_is_also_reported_rather_than_read_as_nothing(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text("{}")

    snapshot = collect([config], tmp_path)
    assert snapshot.unknowns[0].code == "agent_config_unreadable"


def test_configuration_enumeration_is_bounded(tmp_path):
    config = tmp_path / "mcp.json"
    config.write_text(
        json.dumps(
            {
                "mcpServers": {
                    f"server-{index}": {"command": "node", "args": [f"s{index}.js"]}
                    for index in range(10)
                }
            }
        )
    )

    snapshot = collect([config], tmp_path, budget=Budget(max_entries_per_scope=2))
    assert any(u.code == "collector_bounded_out" for u in snapshot.unknowns)


def test_repeated_passes_produce_the_same_normalized_form():
    first = collect([RISKY / ".vscode" / "mcp.json"], RISKY)
    second = collect([RISKY / ".vscode" / "mcp.json"], RISKY)
    assert first.normalized_json() == second.normalized_json()
