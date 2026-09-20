"""Description: Reproducible survivor-reporting fixture; not a production isolation proof."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProcessIdentity:
    """Identify one process instance without trusting a reusable PID alone."""

    pid: int
    start_ticks: str
    boot_id: str


def inspect_process(pid: int) -> ProcessIdentity | None:
    """Read identity, treating disappearance differently from denied inspection."""
    try:
        stat = (Path("/proc") / str(pid) / "stat").read_text()
    except FileNotFoundError:
        return None
    # comm can contain spaces or parentheses, so fields begin after its final closing paren.
    tail = stat.rsplit(")", 1)[1].split()
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    return ProcessIdentity(pid, tail[19], boot_id)


def verify(expected: tuple[ProcessIdentity, ...], *, inspect=inspect_process) -> dict:
    """Return an aggregate failure for survivors or incomplete inspection of the known scope.

    The caller must supply every relevant process, including a known escapee. An empty known
    set is not a complete-boundary proof; this fixture makes no production containment claim.
    """
    survivors = []
    unknown = []
    for original in expected:
        try:
            current = inspect(original.pid)
        except (OSError, ValueError, IndexError):
            unknown.append(asdict(original))
            continue
        if current == original:
            survivors.append(asdict(original))
    success = bool(expected) and not survivors and not unknown
    return {
        "scope": "fixture-known-processes",
        "containment_verified": success,
        "state": "stopped" if success else "containment-unverified",
        "exit_code": 0 if success else 6,
        "survivors": survivors,
        "inspection_unknown": unknown,
        "production_boundary_verified": False,
    }


def run_fixture(mode: str) -> dict:
    """Stop a tracked child; optionally leave a second known child alive during verification."""
    children = []
    try:
        for _ in range(2):
            # Fixed fixture code only. No discovered config or agent input is executed.
            children.append(
                subprocess.Popen(  # noqa: S603
                    [sys.executable, "-c", "import time; time.sleep(10)"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
            )
        identities = tuple(inspect_process(child.pid) for child in children)
        if any(identity is None for identity in identities):
            raise RuntimeError("fixture process exited before identity capture")
        children[0].kill()
        children[0].wait(timeout=2)
        if mode == "contained":
            children[1].kill()
            children[1].wait(timeout=2)

        def observe(pid: int):
            if mode == "verification-error" and pid == children[1].pid:
                raise PermissionError("injected inspection failure")
            return inspect_process(pid)

        return verify(identities, inspect=observe)
    finally:
        # Only these fixture children are terminated; never enumerate or signal host processes.
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--fixture", choices=("contained", "survivor", "verification-error"), required=True
    )
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("the process fixture requires Linux /proc")
    result = run_fixture(args.fixture)
    print(json.dumps(result, sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
