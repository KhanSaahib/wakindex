"""Description: Regression tests for truthful aggregate survivor verification in the fixture."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "containment_probe.py"
spec = importlib.util.spec_from_file_location("containment_probe", SCRIPT)
probe = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = probe
spec.loader.exec_module(probe)


@pytest.mark.parametrize(
    "mode,code", [("contained", 0), ("survivor", 6), ("verification-error", 6)]
)
@pytest.mark.skipif(sys.platform != "linux", reason="fixture requires Linux /proc")
def test_fixture_aggregate_exit_status(mode, code):
    run = subprocess.run(  # noqa: S603 - fixed fixture script and parametrized modes only
        [sys.executable, str(SCRIPT), "--fixture", mode],
        capture_output=True,
        text=True,
        timeout=8,
    )
    assert run.returncode == code, run.stderr
    result = json.loads(run.stdout)
    assert result["exit_code"] == code
    assert result["containment_verified"] is (code == 0)
    assert result["production_boundary_verified"] is False
    if mode == "survivor":
        assert result["survivors"]
    if mode == "verification-error":
        assert result["inspection_unknown"]
    # The fault-injected survivor must be cleaned up when the fixture completes.
    for original in result["survivors"] + result["inspection_unknown"]:
        current = probe.inspect_process(original["pid"])
        assert current != probe.ProcessIdentity(**original)


def test_simulated_uninterruptible_process_is_not_success():
    identity = probe.ProcessIdentity(123, "456", "boot-fixture")
    result = probe.verify((identity,), inspect=lambda pid: identity)
    assert result["state"] == "containment-unverified"
    assert result["exit_code"] == 6


def test_pid_reuse_does_not_mistake_a_new_process_for_a_survivor():
    original = probe.ProcessIdentity(123, "456", "boot-fixture")
    replacement = probe.ProcessIdentity(123, "999", "boot-fixture")
    assert probe.verify((original,), inspect=lambda pid: replacement)["exit_code"] == 0


def test_an_empty_observation_set_cannot_pass():
    assert probe.verify(())["state"] == "containment-unverified"
