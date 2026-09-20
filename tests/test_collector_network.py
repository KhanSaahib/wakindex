"""Description: Tests for the network collector and the observed/inferred reachability split."""

import socket

import pytest

from wakindex.collectors.base import Budget, CollectorContext, run_collectors
from wakindex.collectors.network import NetworkCollector, parse_proc_address

NOW = "2026-09-20T18:00:00Z"
UNTIL = "2026-09-20T18:05:00Z"


def make_context(budget=None):
    return CollectorContext("s:test", NOW, UNTIL, budget=budget or Budget())


def objects(snapshot, prefix=""):
    return {f.object for f in snapshot.findings if f.object.startswith(prefix)}


# -- address decoding ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("0100007F:1F90", "127.0.0.1:8080"),
        ("0100007F:0050", "127.0.0.1:80"),
        ("00000000:0016", "0.0.0.0:22"),
        ("0101A8C0:01BB", "192.168.1.1:443"),
        ("00000000000000000000000001000000:0050", "[::1]:80"),
    ],
)
def test_decodes_proc_addresses(raw, expected):
    """The words are little-endian and the port is not, so a naive hex read is silently wrong."""
    assert parse_proc_address(raw) == expected


@pytest.mark.parametrize("raw", ["", "garbage", "0100007F", "0100007F:", "ZZZZZZZZ:0050", "AB:CD"])
def test_an_undecodable_address_is_none_rather_than_a_plausible_guess(raw):
    """A wrong destination in an access inventory is worse than a missing one."""
    assert parse_proc_address(raw) is None


# -- observed sockets ------------------------------------------------------------------------


def test_a_listening_socket_is_recorded_as_observed():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        snapshot = run_collectors([NetworkCollector()], make_context())
        assert f"resource:net:tcp-listen/127.0.0.1:{port}" in objects(snapshot)
    finally:
        server.close()


def test_an_established_connection_is_recorded_as_observed():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    client = socket.create_connection(("127.0.0.1", port))
    accepted, _ = server.accept()
    try:
        snapshot = run_collectors([NetworkCollector()], make_context())
        connections = [
            f
            for f in snapshot.findings
            if f.object == f"resource:net:tcp/127.0.0.1:{port}"
        ]
        assert connections
        assert connections[0].classification == "observed"
    finally:
        accepted.close()
        client.close()
        server.close()


def test_listeners_and_connections_are_distinguishable():
    """A process accepting connections and one making them are different access facts.

    The sockets are created here rather than assumed. A test that reads whatever the host happens
    to have open passes for the wrong reason on a busy machine and fails on an empty namespace,
    which is precisely where this collector runs.
    """
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    client = socket.create_connection(("127.0.0.1", port))
    accepted, _ = server.accept()
    try:
        snapshot = run_collectors([NetworkCollector()], make_context())
        kinds = {f.object.split("/")[0] for f in snapshot.findings}
        assert "resource:net:tcp-listen" in kinds
        assert "resource:net:tcp" in kinds
    finally:
        accepted.close()
        client.close()
        server.close()


def test_unix_sockets_are_distinguished_from_ip_sockets(tmp_path):
    """A network namespace does not contain filesystem unix sockets, so they are a separate
    reach class: a process with no route can still reach a host service through one."""
    path = tmp_path / "probe.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)
    try:
        snapshot = run_collectors([NetworkCollector()], make_context())
        assert f"resource:net:unix/{path}" in objects(snapshot)
    finally:
        server.close()


# -- inferred reachability ---------------------------------------------------------------------


def test_routed_reachability_is_inferred_never_observed():
    """A route says a packet could leave. It is not evidence anything answered or authorized."""
    snapshot = run_collectors([NetworkCollector()], make_context())
    egress = [f for f in snapshot.findings if f.object.startswith("resource:net:egress/")]

    for finding in egress:
        if finding.object == "resource:net:egress/none":
            continue
        assert finding.classification == "inferred"
        assert finding.confidence == "low"
        assert "not attempted" in finding.evidence[0].detail


def test_no_socket_finding_is_ever_inferred():
    snapshot = run_collectors([NetworkCollector()], make_context())
    sockets = [f for f in snapshot.findings if not f.object.startswith("resource:net:egress/")]
    assert all(f.classification == "observed" for f in sockets)


def test_an_absent_default_route_is_stated_rather_than_left_empty():
    """An empty network section reads like a collector that did not run."""
    context = make_context()
    collector = NetworkCollector()
    collector._read = lambda ctx, name: "Iface\tDestination\tGateway\n" if name == "route" else None
    collector._record_routes(context)

    snapshot = context.snapshot()
    assert "resource:net:egress/none" in objects(snapshot)
    assert snapshot.findings[0].classification == "observed"
    assert "no default route" in snapshot.findings[0].evidence[0].detail


def test_a_default_route_is_recorded_with_its_gateway():
    context = make_context()
    collector = NetworkCollector()
    route = "Iface\tDestination\tGateway\neth0\t00000000\t0101A8C0\t0003\t0\t0\t0\t00000000\n"
    collector._read = lambda ctx, name: route if name == "route" else None
    collector._record_routes(context)

    egress = objects(context.snapshot(), "resource:net:egress/")
    assert egress == {"resource:net:egress/192.168.1.1 via eth0"}


# -- the collector must not generate the traffic it describes ------------------------------------


def test_the_collector_opens_no_connection_and_resolves_no_name():
    """Probing would make the inventory produce the traffic it exists to describe."""
    import ast
    from pathlib import Path

    source = Path(__file__).parent.parent / "src" / "wakindex" / "collectors" / "network.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    forbidden = {
        "connect",
        "create_connection",
        "getaddrinfo",
        "gethostbyname",
        "socket",
        "urlopen",
    }

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            assert name not in forbidden, f"network collector calls {name}"


# -- failure paths --------------------------------------------------------------------------------


def test_an_unreadable_table_is_unknown_not_an_absence_of_sockets():
    snapshot = run_collectors([NetworkCollector(pid=2**30)], make_context())

    assert snapshot.findings == ()
    assert snapshot.unknowns
    assert all(u.object_prefix.startswith("resource:net:") for u in snapshot.unknowns)


def test_socket_enumeration_is_bounded():
    """Fed a synthetic table so the bound is exercised regardless of what the host has open."""
    context = make_context(budget=Budget(max_entries_per_scope=2))
    collector = NetworkCollector()
    rows = "\n".join(
        f"  {index}: 0100007F:{index:04X} 00000000:0000 0A" for index in range(1, 11)
    )
    table = f"  sl  local_address rem_address st\n{rows}\n"
    collector._read = lambda ctx, name: table if name == "tcp" else None
    collector._record_ip_sockets(context, "tcp")

    snapshot = context.snapshot()
    assert len(snapshot.findings) == 2
    assert any(u.code == "collector_bounded_out" for u in snapshot.unknowns)


def test_an_undecodable_socket_line_records_an_unknown_rather_than_a_wrong_address():
    context = make_context()
    collector = NetworkCollector()
    table = "  sl  local_address\n   0: NOTHEX:ZZZZ NOTHEX:ZZZZ 0A\n"
    collector._read = lambda ctx, name: table if name == "tcp" else None
    collector._record_ip_sockets(context, "tcp")

    snapshot = context.snapshot()
    assert snapshot.findings == ()
    assert snapshot.unknowns[0].code == "partial_enumeration"
