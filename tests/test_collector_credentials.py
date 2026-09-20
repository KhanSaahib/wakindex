"""Description: Tests that credential references are recorded without their values."""

import json
import os
import subprocess
import sys
import time

import pytest

from wakindex.collectors.base import Budget, CollectorContext, run_collectors
from wakindex.collectors.credentials import CredentialCollector
from wakindex.store import open_store

NOW = "2026-09-20T18:00:00Z"
UNTIL = "2026-09-20T18:05:00Z"

CANARY_VALUE = "canary-9f3a7c21-must-never-be-recorded"
CANARY_NAME = "WAKINDEX_TEST_API_TOKEN"


def make_context(budget=None):
    return CollectorContext("s:test", NOW, UNTIL, budget=budget or Budget())


@pytest.fixture
def process_holding_a_canary():
    """A real child process whose environment holds the canary.

    The canary must be in the environment at exec time. Setting os.environ in the test process
    would not appear in /proc/self/environ, which is fixed when the process starts -- a test
    written that way passes whether or not the collector leaks, which is worse than no test.
    """
    environment = {**os.environ, CANARY_NAME: CANARY_VALUE}
    child = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-c", "import sys; sys.stdin.read()"],
        env=environment,
        stdin=subprocess.PIPE,
    )
    for _ in range(200):
        if os.path.exists(f"/proc/{child.pid}/environ"):
            break
        time.sleep(0.01)
    try:
        yield child.pid
    finally:
        child.stdin.close()
        child.wait(timeout=10)


def test_the_canary_environment_is_actually_set(process_holding_a_canary):
    """Guards the fixture itself. If the canary is not there, every leak test below is vacuous."""
    raw = open(f"/proc/{process_holding_a_canary}/environ", "rb").read()
    assert CANARY_VALUE.encode() in raw


def test_the_credential_name_is_recorded(process_holding_a_canary):
    snapshot = run_collectors([CredentialCollector(process_holding_a_canary)], make_context())
    assert f"credential_ref:env:{CANARY_NAME}" in {f.object for f in snapshot.findings}


def test_the_credential_value_never_reaches_the_snapshot(process_holding_a_canary):
    """Searched for by value, not checked field by field.

    Checking individual fields only proves the fields someone thought of are clean. Searching the
    serialized snapshot for the canary catches a leak through any field, including one added
    later by someone who never read this test.
    """
    snapshot = run_collectors([CredentialCollector(process_holding_a_canary)], make_context())
    assert CANARY_VALUE not in json.dumps(snapshot.as_dict())


def test_the_credential_value_never_reaches_the_store(tmp_path, process_holding_a_canary):
    snapshot = run_collectors([CredentialCollector(process_holding_a_canary)], make_context())

    database = tmp_path / "graph.db"
    with open_store(database, NOW) as store:
        store.put_snapshot(snapshot, NOW)

    assert CANARY_VALUE.encode() not in database.read_bytes()


def test_the_credential_value_never_reaches_the_evidence_sidecar(process_holding_a_canary):
    snapshot = run_collectors([CredentialCollector(process_holding_a_canary)], make_context())
    assert CANARY_VALUE not in json.dumps(snapshot.evidence_sidecar())


def test_a_non_credential_variable_is_not_recorded(process_holding_a_canary):
    """Recording every variable would bury the credential references among the noise."""
    snapshot = run_collectors([CredentialCollector(process_holding_a_canary)], make_context())
    objects = {f.object for f in snapshot.findings}

    assert "credential_ref:env:PATH" not in objects
    assert "credential_ref:env:HOME" not in objects


# -- uncertainty about remote scope ---------------------------------------------------------


def test_every_finding_states_that_remote_scope_is_unknown(process_holding_a_canary):
    """Holding a token is not evidence of what it authorizes, and an offline host cannot ask."""
    snapshot = run_collectors([CredentialCollector(process_holding_a_canary)], make_context())

    assert snapshot.findings
    for finding in snapshot.findings:
        assert "unknown" in finding.evidence[0].detail


def test_no_finding_claims_enforcement():
    snapshot = run_collectors([CredentialCollector()], make_context())
    assert all(f.enforcement.status == "unknown" for f in snapshot.findings)


# -- files ------------------------------------------------------------------------------------


def test_a_credential_file_is_recorded_by_path(tmp_path):
    aws = tmp_path / ".aws"
    aws.mkdir()
    (aws / "credentials").write_text(f"aws_secret_access_key = {CANARY_VALUE}\n")

    snapshot = run_collectors([CredentialCollector(home=tmp_path)], make_context())
    objects = {f.object for f in snapshot.findings}

    assert f"credential_ref:file:{aws / 'credentials'}" in objects


def test_a_credential_files_contents_are_never_read(tmp_path):
    aws = tmp_path / ".aws"
    aws.mkdir()
    (aws / "credentials").write_text(f"aws_secret_access_key = {CANARY_VALUE}\n")

    snapshot = run_collectors([CredentialCollector(home=tmp_path)], make_context())
    assert CANARY_VALUE not in json.dumps(snapshot.as_dict())


def test_absent_credential_files_are_not_recorded(tmp_path):
    snapshot = run_collectors([CredentialCollector(home=tmp_path)], make_context())
    assert not [f for f in snapshot.findings if f.object.startswith("credential_ref:file:")]


# -- failure paths ------------------------------------------------------------------------------


def test_an_unreadable_environment_is_unknown_not_an_absence_of_credentials():
    snapshot = run_collectors([CredentialCollector(pid=2**30)], make_context())

    assert not [f for f in snapshot.findings if f.object.startswith("credential_ref:env:")]
    assert any(u.object_prefix == "credential_ref:env:" for u in snapshot.unknowns)


def test_environment_enumeration_is_bounded(process_holding_a_canary):
    context = make_context(budget=Budget(max_entries_per_scope=1))
    run_collectors([CredentialCollector(process_holding_a_canary)], context)

    snapshot = context.snapshot()
    env_findings = [f for f in snapshot.findings if f.object.startswith("credential_ref:env:")]
    assert len(env_findings) <= 1
    assert any(u.code == "collector_bounded_out" for u in snapshot.unknowns)
