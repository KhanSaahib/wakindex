"""Description: Collector for configured tool and MCP transports, recorded as declared access."""

from __future__ import annotations

from pathlib import Path

from wakindex.collectors.base import CollectorContext, _classify
from wakindex.graph import Evidence
from wakindex.scanners import scan_config_file

# Permission ids the repository's configuration scanner already produces, mapped onto access
# graph relations. Reusing that scanner rather than writing a second parser for the same files is
# deliberate: two parsers for one format eventually disagree about what an agent can reach, and
# the disagreement is invisible until it matters.
_RELATION_FOR = {
    "process.execute": "can-execute",
    "process.shell": "can-execute",
    "network.access": "can-connect",
    "filesystem.read": "can-read",
    "filesystem.write": "can-write",
    "filesystem.outside_workspace": "can-read",
}


class ToolCollector:
    """Record the tool and MCP servers a session is configured to reach.

    Everything here is `declared`. A configuration file states what was asked for, not what
    happened and not what will be permitted -- the broker and the policy engine decide that. A
    configured server recorded as `observed` would claim the agent used it, which the file cannot
    show.

    Discovered commands are recorded as text. The scanner this delegates to never executes them,
    which is the property that makes reading an agent's own configuration safe at all.
    """

    name = "tools"
    scopes = (
        ("can-invoke", "tool_server:"),
        ("can-execute", "resource:file:"),
        ("can-connect", "resource:net:"),
        ("can-read", "resource:file:"),
        ("can-write", "resource:file:"),
    )

    def __init__(self, config_paths: tuple[Path, ...], workspace_root: Path) -> None:
        self.config_paths = config_paths
        self.workspace_root = workspace_root

    def collect(self, context: CollectorContext) -> None:
        for path in self.config_paths:
            try:
                context.check_deadline()
                self._record_config(context, path)
            except Exception as err:  # noqa: BLE001 - failed config must cover every output scope
                code, _ = _classify(err)
                self._unknown_scopes(context, code, "configuration scan failed")
                if context.deadline_passed:
                    break

    def _unknown_scopes(self, context: CollectorContext, code: str, detail: str) -> None:
        # Until source-specific coverage is stored, a failed config can affect any capability
        # this collector reports. A config-path prefix cannot cover an MCP server or file edge.
        for relation, prefix in self.scopes:
            context.unknown(relation=relation, object_prefix=prefix, code=code, detail=detail)

    def _record_config(self, context: CollectorContext, path: Path) -> None:
        if not path.exists():
            self._unknown_scopes(
                context, "agent_config_unreadable", "configured path does not exist"
            )
            return

        findings = scan_config_file(
            path,
            workspace_root=self.workspace_root,
            source=str(path),
            provider=_provider_for(path),
            scope="workspace",
            redact_prefix=None,
        )

        if not findings:
            # A file that parsed to nothing and a file that could not be parsed look identical
            # from here, so neither is reported as "this agent reaches nothing".
            self._unknown_scopes(
                context, "agent_config_unreadable", "configuration may be empty or unparseable"
            )
            return

        servers: set[str] = set()
        visited = 0
        for finding in context.bounded(
            [str(index) for index in range(len(findings))],
            relation="can-invoke",
            object_prefix="tool_server:",
            detail=f"configuration entries in {path.name}",
        ):
            self._record_finding(context, findings[int(finding)], path, servers)
            visited += 1
        if visited < len(findings):
            code = "collector_timeout" if context.deadline_passed else "collector_bounded_out"
            self._unknown_scopes(context, code, "configuration enumeration was incomplete")

    def _record_finding(self, context, finding, path: Path, servers: set[str]) -> None:
        server = finding.metadata.get("server")
        if server and server not in servers:
            servers.add(server)
            context.emit(
                collector=self.name,
                discriminator=f"server-{server}",
                subject=f"session:{context.session_id}",
                relation="can-invoke",
                object=f"tool_server:mcp:{server}",
                classification="declared",
                confidence="high",
                evidence=(
                    Evidence(
                        source="agent_config",
                        collector=f"collect.{self.name}",
                        collected_at=context.now,
                        detail=f"server {server} declared in {path.name}",
                    ),
                ),
            )

        relation = _RELATION_FOR.get(finding.permission)
        if relation is None:
            return

        object_id = _object_for(finding)
        if object_id is None:
            return

        context.emit(
            collector=self.name,
            discriminator=f"{finding.permission}-{server or 'agent'}-{finding.resource}",
            subject=f"tool_server:mcp:{server}" if server else f"session:{context.session_id}",
            relation=relation,
            object=object_id,
            classification="declared",
            confidence="medium",
            evidence=(
                Evidence(
                    source="agent_config",
                    collector=f"collect.{self.name}",
                    collected_at=context.now,
                    detail=f"{finding.permission} declared in {path.name}: {finding.evidence}",
                ),
            ),
        )


def _object_for(finding) -> str | None:
    """Map a scanner finding onto an access graph object id."""
    metadata = finding.metadata
    if finding.permission == "network.access":
        host = metadata.get("host")
        return f"resource:net:host/{host}" if host else None
    if finding.permission in {"process.execute", "process.shell"}:
        command = metadata.get("command") or finding.resource
        return f"resource:file:{command}"
    path = metadata.get("path")
    return f"resource:file:{path}" if path else None


def _provider_for(path: Path) -> str:
    """Name the provider a configuration file belongs to, for the scanner's own dispatch."""
    if path.suffix.lower() == ".toml":
        return "codex"
    name = path.name.lower()
    if "claude" in name:
        return "claude"
    if "gemini" in name:
        return "gemini"
    if "cursor" in name:
        return "cursor"
    return "generic"
