"""Description: Safe static scanners for agent, MCP, skill, workflow, and Codex configuration."""

from __future__ import annotations

import fnmatch
import json
import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlparse

from wakindex.models import Finding, Manifest

ENV_PATTERN = re.compile(
    r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)|%([A-Za-z_][A-Za-z0-9_]*)%"
)
SHELL_PATTERN = re.compile(r"(?:\b(?:bash|sh|zsh|cmd|powershell|pwsh)\b|[|;&]{1,2})", re.IGNORECASE)
NETWORK_PATTERN = re.compile(r"https?://", re.IGNORECASE)
SECRET_NAME_PATTERN = re.compile(
    r"(?:TOKEN|SECRET|PASSWORD|PASS|KEY|CREDENTIAL|DATABASE_URL)", re.IGNORECASE
)
SENSITIVE_HEADER_PATTERN = re.compile(
    r"(?:authorization|api[-_]?key|token|secret|credential)", re.IGNORECASE
)
WINDOWS_ABSOLUTE_PATTERN = re.compile(r"^[A-Za-z]:[\\/]")


@dataclass(frozen=True, order=True)
class WorkspaceConfigTarget:
    """One supported workspace configuration file with normalized attribution."""

    source: str
    provider: str
    path: Path


def _relative(path: Path, root: Path) -> str:
    return path.resolve().relative_to(root.resolve()).as_posix()


def _finding(
    permission: str,
    resource: str,
    source: str,
    evidence: str,
    risk: str,
    **metadata: Any,
) -> Finding:
    return Finding(permission, resource, source, evidence[:240], risk, metadata)


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _load_toml(path: Path) -> dict[str, Any] | None:
    try:
        with path.open("rb") as stream:
            payload = tomllib.load(stream)
    except (OSError, tomllib.TOMLDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _environment_names(value: Any) -> set[str]:
    text = json.dumps(value, sort_keys=True)
    return {next(part for part in match.groups() if part) for match in ENV_PATTERN.finditer(text)}


def _safe_host(url: str) -> str | None:
    parsed = urlparse(url)
    return parsed.hostname if parsed.scheme in {"http", "https"} else None


def _redact_text(text: str, prefix: Path | None) -> str:
    if prefix is None:
        return text
    candidates = {str(prefix), prefix.as_posix()}
    redacted = text
    for candidate in sorted(candidates, key=len, reverse=True):
        if candidate:
            flags = re.IGNORECASE if WINDOWS_ABSOLUTE_PATTERN.match(candidate) else 0
            redacted = re.sub(re.escape(candidate), "~", redacted, flags=flags)
    return redacted


def _with_context(
    findings: Iterable[Finding],
    *,
    provider: str,
    scope: str,
    source: str | None = None,
    redact_prefix: Path | None = None,
) -> Iterable[Finding]:
    for finding in findings:
        metadata = {
            key: _redact_text(value, redact_prefix) if isinstance(value, str) else value
            for key, value in finding.metadata.items()
        }
        metadata.update({"provider": provider, "scope": scope})
        yield Finding(
            permission=finding.permission,
            resource=_redact_text(finding.resource, redact_prefix),
            source=source or finding.source,
            evidence=_redact_text(finding.evidence, redact_prefix),
            risk=finding.risk,
            metadata=metadata,
        )


def _declared_environment_names(config: dict[str, Any]) -> set[str]:
    names = _environment_names(config)
    env_vars = config.get("env_vars", [])
    if isinstance(env_vars, list):
        for entry in env_vars:
            if isinstance(entry, str):
                names.add(entry)
            elif isinstance(entry, dict) and isinstance(entry.get("name"), str):
                names.add(entry["name"])
    bearer = config.get("bearer_token_env_var")
    if isinstance(bearer, str):
        names.add(bearer)
    env_headers = config.get("env_http_headers", {})
    if isinstance(env_headers, dict):
        names.update(value for value in env_headers.values() if isinstance(value, str))
    return names


def _embedded_secret_fields(config: dict[str, Any]) -> Iterable[tuple[str, str]]:
    env = config.get("env", {})
    if isinstance(env, dict):
        for name, value in sorted(env.items()):
            if (
                isinstance(name, str)
                and SECRET_NAME_PATTERN.search(name)
                and isinstance(value, str)
                and value
                and not ENV_PATTERN.search(value)
            ):
                yield "environment variable", name
    for section_name in ("headers", "http_headers"):
        headers = config.get(section_name, {})
        if not isinstance(headers, dict):
            continue
        for name, value in sorted(headers.items()):
            if (
                isinstance(name, str)
                and SENSITIVE_HEADER_PATTERN.search(name)
                and isinstance(value, str)
                and value
                and not ENV_PATTERN.search(value)
            ):
                yield "HTTP header", name


def _hook_commands(value: Any) -> Iterable[str]:
    if isinstance(value, list):
        for item in value:
            yield from _hook_commands(item)
    elif isinstance(value, dict):
        if value.get("type") == "command" and isinstance(value.get("command"), str):
            yield value["command"]
        for nested in value.values():
            if isinstance(nested, (dict, list)):
                yield from _hook_commands(nested)


def _command_executable(command: str) -> str:
    """Return a non-executing, argument-free label for a configured command."""
    match = re.match(r"""^\s*(?:"([^"]+)"|'([^']+)'|(\S+))""", command)
    if match is None:
        return "configured-command"
    return next(part for part in match.groups() if part)


def _path_escapes_workspace(value: str, _config_dir: Path, workspace_root: Path) -> bool:
    if ENV_PATTERN.search(value) or value.startswith(("http://", "https://")):
        return False
    if ".." in PurePosixPath(value).parts or ".." in PureWindowsPath(value).parts:
        return True
    windows_candidate = PureWindowsPath(value)
    if windows_candidate.is_absolute():
        try:
            windows_candidate.relative_to(PureWindowsPath(str(workspace_root)))
        except ValueError:
            return True
        return False
    candidate = Path(value)
    if not candidate.is_absolute():
        return False
    try:
        candidate.resolve().relative_to(workspace_root.resolve())
    except (OSError, ValueError):
        return True
    return False


def _scan_mcp(
    path: Path,
    source_root: Path,
    workspace_root: Path,
    payload: dict[str, Any],
) -> Iterable[Finding]:
    source = _relative(path, source_root)
    servers = payload.get("mcpServers", payload.get("servers", {}))
    if not isinstance(servers, dict):
        return
    for name, config in sorted(servers.items()):
        if not isinstance(name, str) or not isinstance(config, dict):
            continue
        if config.get("enabled") is False or config.get("disabled") is True:
            continue
        metadata = {"server": name}
        command = config.get("command")
        args = config.get("args", [])
        if isinstance(command, str):
            # An argument-free label, not the raw command: a `command` field is conventionally
            # just the executable, but nothing stops a misconfigured entry from putting a literal
            # secret after it, and the raw string would then flow verbatim into evidence and,
            # through ToolCollector, into this finding's access-graph object id. Hooks already
            # use this same truncation for the same reason; MCP `command` should not be the one
            # path left echoing whatever text was written there.
            executable = _command_executable(command)
            yield _finding(
                "process.execute",
                name,
                source,
                f"command: {executable}",
                "medium",
                command=executable,
                **metadata,
            )
            command_line = " ".join([command, *[str(arg) for arg in args if isinstance(arg, str)]])
            if SHELL_PATTERN.search(command_line):
                yield _finding(
                    "process.shell",
                    name,
                    source,
                    "shell-capable command",
                    "high",
                    **metadata,
                )
        approval_mode = config.get("default_tools_approval_mode")
        if config.get("trust") is True or approval_mode in {"auto", "approve"}:
            yield _finding(
                "agent.auto_approve",
                name,
                source,
                "MCP tools can run without normal confirmation",
                "high",
                approval_mode=str(approval_mode or "trusted"),
                **metadata,
            )
        endpoint = config.get("url", config.get("httpUrl"))
        if isinstance(endpoint, str):
            host = _safe_host(endpoint)
            if host:
                yield _finding(
                    "network.access",
                    name,
                    source,
                    f"remote MCP host: {host}",
                    "medium",
                    host=host,
                    **metadata,
                )
        for env_name in sorted(_declared_environment_names(config)):
            yield _finding(
                "secrets.inherit",
                name,
                source,
                f"inherits environment variable: {env_name}",
                "high" if SECRET_NAME_PATTERN.search(env_name) else "medium",
                environment_variable=env_name,
                **metadata,
            )
        for field_type, field_name in _embedded_secret_fields(config):
            yield _finding(
                "secrets.embedded",
                name,
                source,
                f"literal credential material in {field_type}: {field_name}",
                "high",
                field=field_name,
                **metadata,
            )
        path_values = (
            [arg for arg in args if isinstance(arg, str)] if isinstance(args, list) else []
        )
        cwd = config.get("cwd")
        if isinstance(cwd, str):
            path_values.append(cwd)
        for value in path_values:
            if not _path_escapes_workspace(value, path.parent, workspace_root):
                continue
            yield _finding(
                "filesystem.outside_workspace",
                name,
                source,
                f"path escapes workspace: {value}",
                "high",
                path=value,
                **metadata,
            )


def _scan_agent_settings(
    path: Path,
    source_root: Path,
    payload: dict[str, Any],
) -> Iterable[Finding]:
    source = _relative(path, source_root)
    if (
        payload.get("dangerouslySkipPermissions") is True
        or payload.get("permissionMode") == "bypassPermissions"
    ):
        yield _finding(
            "agent.unrestricted",
            "agent",
            source,
            "permission checks are bypassed",
            "high",
        )
    general = payload.get("general", {})
    if isinstance(general, dict) and general.get("defaultApprovalMode") == "auto_edit":
        yield _finding(
            "agent.auto_approve",
            "agent",
            source,
            "edit tools are approved by default",
            "high",
            approval_mode="auto_edit",
        )
    for env_name in sorted(_declared_environment_names({"env": payload.get("env", {})})):
        yield _finding(
            "secrets.inherit",
            "agent",
            source,
            f"inherits environment variable: {env_name}",
            "high" if SECRET_NAME_PATTERN.search(env_name) else "medium",
            environment_variable=env_name,
        )
    for field_type, field_name in _embedded_secret_fields({"env": payload.get("env", {})}):
        yield _finding(
            "secrets.embedded",
            "agent",
            source,
            f"literal credential material in {field_type}: {field_name}",
            "high",
            field=field_name,
        )
    for command in sorted(set(_hook_commands(payload.get("hooks", {})))):
        executable = _command_executable(command)
        yield _finding(
            "process.execute",
            "hook",
            source,
            f"agent hook command configured: {executable}",
            "medium",
            command=executable,
        )
        if SHELL_PATTERN.search(command):
            yield _finding(
                "process.shell",
                "hook",
                source,
                "agent hook uses a shell-capable command",
                "high",
                command=executable,
            )
    permissions = payload.get("permissions", {})
    if not isinstance(permissions, dict):
        return
    for tool in permissions.get("allow", []):
        if not isinstance(tool, str):
            continue
        lowered = tool.lower()
        if lowered.startswith("read"):
            permission, risk = "filesystem.read", "low"
        elif lowered.startswith(("write", "edit")):
            permission, risk = "filesystem.write", "medium"
        elif lowered.startswith("bash"):
            permission, risk = "process.shell", "high"
        else:
            permission, risk = "process.execute", "medium"
        yield _finding(permission, tool, source, f"allowed tool: {tool}", risk, tool=tool)


def _scan_codex(
    path: Path,
    source_root: Path,
    workspace_root: Path,
    payload: dict[str, Any],
) -> Iterable[Finding]:
    source = _relative(path, source_root)
    sandbox_mode = payload.get("sandbox_mode")
    default_permissions = payload.get("default_permissions")
    if sandbox_mode is None and isinstance(default_permissions, str):
        sandbox_mode = {
            ":read-only": "read-only",
            ":workspace": "workspace-write",
            ":danger-full-access": "danger-full-access",
        }.get(default_permissions)
    if sandbox_mode in {"read-only", "workspace-write", "danger-full-access"}:
        yield _finding(
            "filesystem.read",
            "codex-sandbox",
            source,
            f"Codex sandbox mode permits repository reads: {sandbox_mode}",
            "low",
            sandbox_mode=sandbox_mode,
        )
    if sandbox_mode in {"workspace-write", "danger-full-access"}:
        yield _finding(
            "filesystem.write",
            "codex-sandbox",
            source,
            f"Codex sandbox mode permits filesystem writes: {sandbox_mode}",
            "medium" if sandbox_mode == "workspace-write" else "high",
            sandbox_mode=sandbox_mode,
        )
    if sandbox_mode == "danger-full-access":
        yield _finding(
            "agent.unrestricted",
            "codex",
            source,
            "Codex sandbox permits unrestricted host access",
            "high",
            sandbox_mode=sandbox_mode,
        )
        yield _finding(
            "network.access",
            "codex-sandbox",
            source,
            "unrestricted Codex sandbox permits outbound network access",
            "high",
            host="*",
        )
    if payload.get("approval_policy") == "never":
        yield _finding(
            "agent.auto_approve",
            "codex",
            source,
            "Codex is configured not to request command approval",
            "high",
            approval_mode="never",
        )
    workspace = payload.get("sandbox_workspace_write", {})
    if isinstance(workspace, dict):
        if workspace.get("network_access") is True and sandbox_mode != "danger-full-access":
            yield _finding(
                "network.access",
                "codex-sandbox",
                source,
                "workspace sandbox permits outbound network access",
                "medium",
                host="*",
            )
        writable_roots = workspace.get("writable_roots", [])
        if isinstance(writable_roots, list):
            for writable_root in writable_roots:
                if not isinstance(writable_root, str):
                    continue
                yield _finding(
                    "filesystem.write",
                    "codex-sandbox",
                    source,
                    f"additional writable root: {writable_root}",
                    "medium",
                    path=writable_root,
                )
                if _path_escapes_workspace(writable_root, path.parent, workspace_root):
                    yield _finding(
                        "filesystem.outside_workspace",
                        "codex-sandbox",
                        source,
                        f"writable root escapes workspace: {writable_root}",
                        "high",
                        path=writable_root,
                    )
    servers = payload.get("mcp_servers", {})
    if isinstance(servers, dict):
        yield from _scan_mcp(
            path,
            source_root,
            workspace_root,
            {"mcpServers": servers},
        )


def _scan_skill(path: Path, root: Path) -> Iterable[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    source = _relative(path, root)
    lowered = text.lower()
    if re.search(r"allowed-tools\s*:[\s\S]{0,300}\b(?:bash|shell)\b", text, re.IGNORECASE):
        yield _finding(
            "process.shell", path.parent.name, source, "skill declares shell tool", "high"
        )
    if NETWORK_PATTERN.search(text):
        yield _finding(
            "network.access", path.parent.name, source, "skill references a network URL", "medium"
        )
    for env_name in sorted(_environment_names(text)):
        if SECRET_NAME_PATTERN.search(env_name):
            yield _finding(
                "secrets.inherit",
                path.parent.name,
                source,
                f"skill references environment variable: {env_name}",
                "high",
                environment_variable=env_name,
            )
    if "curl " in lowered and ("| bash" in lowered or "| sh" in lowered):
        yield _finding(
            "process.shell",
            path.parent.name,
            source,
            "skill pipes network content to a shell",
            "high",
        )


def _scan_workflow(path: Path, root: Path) -> Iterable[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return
    source = _relative(path, root)
    if re.search(r"(?m)^\s*permissions\s*:\s*write-all\s*(?:#.*)?$", text):
        yield _finding(
            "github.token",
            "GITHUB_TOKEN",
            source,
            "workflow requests write-all",
            "high",
            github_scope="write-all",
        )
    for match in re.finditer(r"(?m)^\s{0,8}([a-z-]+)\s*:\s*write\s*(?:#.*)?$", text):
        token_scope = match.group(1)
        if token_scope not in {"run", "uses", "name"}:
            yield _finding(
                "github.token",
                "GITHUB_TOKEN",
                source,
                f"workflow requests {token_scope}: write",
                "high",
                github_scope=token_scope,
            )


def _provider_for(path: Path) -> str:
    parts = {part.lower() for part in path.parts}
    name = path.name.lower()
    if name == "claude_desktop_config.json":
        return "claude-desktop"
    if ".codex" in parts:
        return "codex"
    if ".claude" in parts or name == ".claude.json":
        return "claude"
    if ".cursor" in parts:
        return "cursor"
    if ".gemini" in parts:
        return "gemini"
    if ".vscode" in parts:
        return "vscode"
    if ".github" in parts:
        return "github"
    if name == "skill.md":
        return "skill"
    return "mcp"


def scan_config_file(
    path: Path,
    *,
    workspace_root: Path,
    source: str,
    provider: str,
    scope: str,
    redact_prefix: Path | None = None,
) -> tuple[Finding, ...]:
    """Scan one explicitly selected configuration file without executing it."""
    if path.is_symlink() or not path.is_file():
        return ()
    source_root = workspace_root if scope == "workspace" else path.parent
    findings: list[Finding] = []
    if path.suffix.lower() == ".toml":
        payload = _load_toml(path)
        if payload is not None and provider == "codex":
            findings.extend(_scan_codex(path, source_root, workspace_root, payload))
    else:
        payload = _load_json(path)
        if payload is not None:
            if "servers" in payload or "mcpServers" in payload:
                findings.extend(_scan_mcp(path, source_root, workspace_root, payload))
            if path.name.startswith("settings"):
                findings.extend(_scan_agent_settings(path, source_root, payload))
    contextualized = _with_context(
        findings,
        provider=provider,
        scope=scope,
        source=source,
        redact_prefix=redact_prefix,
    )
    return tuple(sorted(set(contextualized)))


def _candidate_files(root: Path) -> Iterable[Path]:
    names = {
        ".claude.json",
        ".mcp.json",
        "claude_desktop_config.json",
        "mcp.json",
        "settings.json",
        "settings.local.json",
        "SKILL.md",
    }
    ignore_path = root / ".wakindexignore"
    try:
        ignore_patterns = tuple(
            line.strip()
            for line in ignore_path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        )
    except OSError:
        ignore_patterns = ()
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            path.resolve().relative_to(root.resolve())
        except (OSError, ValueError):
            continue
        relative = path.resolve().relative_to(root.resolve()).as_posix()
        if any(fnmatch.fnmatchcase(relative, pattern) for pattern in ignore_patterns):
            continue
        is_codex_config = path.name == "config.toml" and ".codex" in path.parts
        is_workflow = (
            ".github" in path.parts
            and "workflows" in path.parts
            and path.suffix in {".yml", ".yaml"}
        )
        if path.name in names or is_codex_config or is_workflow:
            yield path


def discover_workspace_configs(root: Path) -> tuple[WorkspaceConfigTarget, ...]:
    """Return supported workspace configuration files in deterministic order."""
    root = root.resolve()
    return tuple(
        WorkspaceConfigTarget(
            source=_relative(path, root),
            provider=_provider_for(path),
            path=path,
        )
        for path in sorted(_candidate_files(root), key=lambda item: item.as_posix())
    )


def scan_repository(root: Path) -> Manifest:
    """Scan supported workspace configuration beneath root without executing it."""
    root = root.resolve()
    findings: set[Finding] = set()
    for target in discover_workspace_configs(root):
        path = target.path
        source = target.source
        provider = target.provider
        if path.name == "SKILL.md":
            findings.update(
                _with_context(_scan_skill(path, root), provider=provider, scope="workspace")
            )
        elif ".github" in path.parts and "workflows" in path.parts:
            findings.update(
                _with_context(_scan_workflow(path, root), provider=provider, scope="workspace")
            )
        else:
            findings.update(
                scan_config_file(
                    path,
                    workspace_root=root,
                    source=source,
                    provider=provider,
                    scope="workspace",
                )
            )
    return Manifest(root=".", findings=tuple(sorted(findings)))
