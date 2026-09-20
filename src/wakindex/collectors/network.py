"""Description: Collector for network posture, separating observed sockets from inferred reach."""

from __future__ import annotations

import ipaddress
from pathlib import Path

from wakindex.collectors.base import CollectorContext
from wakindex.graph import Evidence

PROC = Path("/proc")

# /proc/net/tcp state column. Only these two say anything an inventory should record.
_STATE_ESTABLISHED = "01"
_STATE_LISTEN = "0A"

_SCOPE = ("can-connect", "resource:net:")


def parse_proc_address(raw: str) -> str | None:
    """Decode a `HEXADDR:HEXPORT` pair from /proc/net into `address:port`.

    The address is stored as little-endian 32-bit words and the port as big-endian, so a naive
    hex decode produces a plausible-looking address that is simply wrong. A wrong destination in
    an access inventory is worse than a missing one, which is why this returns None on anything
    it cannot decode exactly.
    """
    head, separator, tail = raw.partition(":")
    if not separator or len(tail) != 4:
        return None
    try:
        port = int(tail, 16)
    except ValueError:
        return None

    if len(head) == 8:
        try:
            packed = int(head, 16).to_bytes(4, "little")
        except ValueError:
            return None
        return f"{ipaddress.IPv4Address(packed)}:{port}"

    if len(head) == 32:
        words = [head[index : index + 8] for index in range(0, 32, 8)]
        try:
            packed = b"".join(int(word, 16).to_bytes(4, "little") for word in words)
        except ValueError:
            return None
        return f"[{ipaddress.IPv6Address(packed)}]:{port}"

    return None


class NetworkCollector:
    """Record what a process is connected to, and separately what it could reach.

    The split is the point. An established connection is a fact. A destination that a route makes
    reachable is a possibility, and recording it as though it were observed would inflate the
    inventory with traffic that never happened.

    The collector never opens a connection and never resolves a name. Probing reachability would
    make the inventory generate the traffic it exists to describe, and on an offline profile it
    would be the one component breaking the offline guarantee.
    """

    name = "network"
    scopes = (_SCOPE,)

    def __init__(self, pid: int | str = "self") -> None:
        self.pid = pid

    def collect(self, context: CollectorContext) -> None:
        self._record_ip_sockets(context, "tcp")
        self._record_ip_sockets(context, "tcp6")
        self._record_ip_sockets(context, "udp")
        self._record_ip_sockets(context, "udp6")
        self._record_unix_sockets(context)
        self._record_routes(context)

    def _net_path(self, name: str) -> Path:
        return PROC / str(self.pid) / "net" / name

    def _read(self, context: CollectorContext, name: str) -> str | None:
        try:
            return context.read_proc_text(self._net_path(name))
        except FileNotFoundError:
            # A kernel without this protocol table is not a process with no sockets.
            context.unknown(
                relation=_SCOPE[0],
                object_prefix=f"resource:net:{name}",
                code="unsupported_platform",
                detail=f"/proc/{self.pid}/net/{name} is not present",
            )
        except PermissionError as err:
            context.unknown(
                relation=_SCOPE[0],
                object_prefix=f"resource:net:{name}",
                code="collector_permission_denied",
                detail=f"reading net/{name}: {err.strerror or 'permission denied'}",
            )
        except OSError as err:
            context.unknown(
                relation=_SCOPE[0],
                object_prefix=f"resource:net:{name}",
                code="partial_enumeration",
                detail=f"reading net/{name}: {type(err).__name__}",
            )
        return None

    # -- sockets ----------------------------------------------------------------------

    def _record_ip_sockets(self, context: CollectorContext, table: str) -> None:
        text = self._read(context, table)
        if text is None:
            return

        protocol = table.rstrip("6")
        for line in context.bounded(
            text.splitlines()[1:],
            relation=_SCOPE[0],
            object_prefix=f"resource:net:{protocol}",
            detail=f"{table} sockets of pid {self.pid}",
        ):
            fields = line.split()
            if len(fields) < 4:
                continue
            state = fields[3]
            if state == _STATE_LISTEN:
                self._emit_socket(context, protocol, fields[1], table, listening=True)
            elif state == _STATE_ESTABLISHED:
                self._emit_socket(context, protocol, fields[2], table, listening=False)

    def _emit_socket(
        self, context: CollectorContext, protocol: str, raw: str, table: str, *, listening: bool
    ) -> None:
        address = parse_proc_address(raw)
        if address is None:
            context.unknown(
                relation=_SCOPE[0],
                object_prefix=f"resource:net:{protocol}",
                code="partial_enumeration",
                detail=f"undecodable address in net/{table}",
            )
            return

        kind = f"{protocol}-listen" if listening else protocol
        context.emit(
            collector=self.name,
            discriminator=f"{kind}-{address}",
            subject=f"session:{context.session_id}",
            relation="can-connect",
            object=f"resource:net:{kind}/{address}",
            classification="observed",
            confidence="high",
            evidence=(
                Evidence(
                    source=f"proc_net_{table}",
                    collector=f"collect.{self.name}",
                    collected_at=context.now,
                    detail=(
                        f"listening socket on {address}"
                        if listening
                        else f"established connection to {address}"
                    ),
                ),
            ),
        )

    def _record_unix_sockets(self, context: CollectorContext) -> None:
        """Record filesystem-backed unix sockets.

        These are a separate reachability class from IP: a network namespace does not contain
        them, so a process with no route can still reach a host service through one.
        """
        text = self._read(context, "unix")
        if text is None:
            return

        for line in context.bounded(
            text.splitlines()[1:],
            relation=_SCOPE[0],
            object_prefix="resource:net:unix",
            detail=f"unix sockets of pid {self.pid}",
        ):
            fields = line.split()
            if len(fields) < 8:
                continue
            path = fields[7]
            context.emit(
                collector=self.name,
                discriminator=f"unix-{path}",
                subject=f"session:{context.session_id}",
                relation="can-connect",
                object=f"resource:net:unix/{path}",
                classification="observed",
                confidence="high",
                evidence=(
                    Evidence(
                        source="proc_net_unix",
                        collector=f"collect.{self.name}",
                        collected_at=context.now,
                        detail=f"unix socket at {path}",
                    ),
                ),
            )

    # -- routes -----------------------------------------------------------------------

    def _record_routes(self, context: CollectorContext) -> None:
        """Record routed reachability as inferred, and record its absence explicitly.

        A route is not proof that anything answers, nor that a remote service would authorize the
        call, so these are `inferred`. The absence of a default route is recorded as its own
        finding rather than as silence: an empty network section reads like a collector that did
        not run, while "no default route" is a statement an operator can rely on.
        """
        text = self._read(context, "route")
        if text is None:
            return

        gateways: list[str] = []
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 3:
                continue
            interface, destination, gateway = fields[0], fields[1], fields[2]
            if destination != "00000000":
                continue
            decoded = parse_proc_address(f"{gateway}:0000")
            address = decoded.rsplit(":", 1)[0] if decoded else None
            gateways.append(f"{address} via {interface}" if address else interface)

        if not gateways:
            context.emit(
                collector=self.name,
                discriminator="egress-none",
                subject=f"session:{context.session_id}",
                relation="can-connect",
                object="resource:net:egress/none",
                classification="observed",
                confidence="high",
                evidence=(
                    Evidence(
                        source="proc_net_route",
                        collector=f"collect.{self.name}",
                        collected_at=context.now,
                        detail="no default route; no external destination is reachable by route",
                    ),
                ),
            )
            return

        for gateway in gateways:
            context.emit(
                collector=self.name,
                discriminator=f"egress-{gateway}",
                subject=f"session:{context.session_id}",
                relation="can-connect",
                object=f"resource:net:egress/{gateway}",
                classification="inferred",
                confidence="low",
                evidence=(
                    Evidence(
                        source="proc_net_route",
                        collector=f"collect.{self.name}",
                        collected_at=context.now,
                        detail=(
                            f"default route {gateway}; reachability inferred from the route "
                            "table, not attempted, and not evidence of remote authorization"
                        ),
                    ),
                ),
            )
