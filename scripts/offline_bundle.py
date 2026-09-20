"""Description: Prepare and use an offline dependency bundle for building and testing wakindex."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LOCK_FILE = REPO_ROOT / "requirements-dev.txt"
BUNDLE_DIR = REPO_ROOT / "vendor" / "wheels"
# The build backend declared in pyproject.toml. Bundled so that an editable install and a wheel
# build both work without network access; pip cannot fetch a backend offline.
BUILD_BACKEND = "hatchling>=1.25"
# hatchling imports "editables" only when producing an editable wheel, so pip would try to
# fetch it at install time. Bundling it keeps "install" working with no network.
BUILD_EXTRA = "editables"


def _run(command: list[str], *, allow_network: bool) -> int:
    """Run a command, printing it first so the operator can reproduce it by hand."""
    env_note = "" if allow_network else "  [offline: --no-index]"
    print(f"$ {' '.join(command)}{env_note}", flush=True)
    # Argument vectors are built from module constants and the operator's own --python path.
    # No shell, and nothing here comes from scanned configuration or agent-controlled input.
    return subprocess.call(command)  # noqa: S603


def fetch(python: str) -> int:
    """Download every pinned dependency into the bundle. This step requires network access."""
    if not LOCK_FILE.exists():
        print(f"missing lock file: {LOCK_FILE}", file=sys.stderr)
        return 1
    BUNDLE_DIR.mkdir(parents=True, exist_ok=True)
    code = _run(
        [
            python,
            "-m",
            "pip",
            "download",
            "--requirement",
            str(LOCK_FILE),
            "--require-hashes",
            "--dest",
            str(BUNDLE_DIR),
        ],
        allow_network=True,
    )
    if code != 0:
        return code
    code = _run(
        [python, "-m", "pip", "download", BUILD_BACKEND, BUILD_EXTRA, "--dest", str(BUNDLE_DIR)],
        allow_network=True,
    )
    if code != 0:
        return code
    return _run(
        [python, "-m", "pip", "wheel", str(REPO_ROOT), "--no-deps", "--wheel-dir", str(BUNDLE_DIR)],
        allow_network=True,
    )


def install(python: str) -> int:
    """Install the project and its dev dependencies from the bundle, without network access."""
    if not BUNDLE_DIR.exists():
        print(
            f"missing bundle: {BUNDLE_DIR}. Run 'fetch' on a connected host first.",
            file=sys.stderr,
        )
        return 1
    code = _run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(BUNDLE_DIR),
            "--requirement",
            str(LOCK_FILE),
        ],
        allow_network=False,
    )
    if code != 0:
        return code
    code = _run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(BUNDLE_DIR),
            BUILD_BACKEND,
            BUILD_EXTRA,
        ],
        allow_network=False,
    )
    if code != 0:
        return code
    return _run(
        [
            python,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--find-links",
            str(BUNDLE_DIR),
            "--no-build-isolation",
            "--editable",
            str(REPO_ROOT),
        ],
        allow_network=False,
    )


def verify(python: str) -> int:
    """Run the checks that must pass with outbound network disabled."""
    for command in ([python, "-m", "pytest"], [python, "-m", "ruff", "check", str(REPO_ROOT)]):
        code = _run(command, allow_network=False)
        if code != 0:
            return code
    return 0


def inventory() -> int:
    """Print the dependency inventory: runtime dependencies and pinned development tools."""
    print("runtime dependencies: none")
    print("development dependencies (pinned in requirements-dev.txt):")
    for line in LOCK_FILE.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith((" ", "#", "-")):
            requirement = line.split(";")[0].rstrip(" \\")
            print(f"  {requirement}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command", choices=("fetch", "install", "verify", "inventory"), help="bundle step to run"
    )
    parser.add_argument(
        "--python", default=sys.executable, help="interpreter to install into (default: current)"
    )
    args = parser.parse_args(argv)

    if args.command == "fetch":
        return fetch(args.python)
    if args.command == "install":
        return install(args.python)
    if args.command == "verify":
        return verify(args.python)
    return inventory()


if __name__ == "__main__":
    raise SystemExit(main())
