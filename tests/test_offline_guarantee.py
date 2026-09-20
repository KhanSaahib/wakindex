"""Description: Regression tests that keep the runtime free of required outbound network calls."""

import ast
from pathlib import Path

import pytest

SRC_DIR = Path(__file__).parent.parent / "src" / "wakindex"

# Calls that reach a remote host. http.server and socketserver are inbound listeners bound to
# loopback by the local UI and dashboard, so they are deliberately absent from this list.
FORBIDDEN_CALLS = {
    ("urllib.request", "urlopen"),
    ("urllib.request", "Request"),
    ("http.client", "HTTPConnection"),
    ("http.client", "HTTPSConnection"),
    ("socket", "create_connection"),
    ("socket", "getaddrinfo"),
    ("socket", "gethostbyname"),
    ("ftplib", "FTP"),
    ("smtplib", "SMTP"),
}
FORBIDDEN_MODULES = {
    "requests",
    "httpx",
    "urllib3",
    "aiohttp",
    "urllib.request",
    "ftplib",
    "smtplib",
}


def source_files():
    return sorted(SRC_DIR.rglob("*.py"))


@pytest.mark.parametrize("path", source_files(), ids=lambda p: p.name)
def test_runtime_module_imports_no_outbound_client(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name not in FORBIDDEN_MODULES, (
                    f"{path.name} imports {alias.name}; the runtime must not make remote calls"
                )
        elif isinstance(node, ast.ImportFrom) and node.module:
            assert node.module not in FORBIDDEN_MODULES, (
                f"{path.name} imports from {node.module}; the runtime must not make remote calls"
            )


@pytest.mark.parametrize("path", source_files(), ids=lambda p: p.name)
def test_runtime_module_calls_no_outbound_api(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    forbidden_attrs = {attribute for _, attribute in FORBIDDEN_CALLS}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in forbidden_attrs:
            pytest.fail(f"{path.name} calls {func.attr}; the runtime must not make remote calls")


def test_servers_bind_to_loopback_only():
    """The local UI and dashboard are inbound listeners; neither may bind a routable address."""
    # S104 flags the literal below as a bind address. It is the string this test forbids, not an
    # address this test binds.
    all_interfaces = "0.0.0.0"  # noqa: S104
    for name in ("ui.py", "dashboard.py"):
        source = (SRC_DIR / name).read_text(encoding="utf-8")
        assert all_interfaces not in source, f"{name} must not bind all interfaces"
        assert "127.0.0.1" in source, f"{name} must bind loopback explicitly"
