"""Description: Collector for the effective principal, groups, and capabilities of a process."""

from __future__ import annotations

from pathlib import Path

from wakindex.collectors.base import CollectorContext
from wakindex.graph import Evidence

PROC = Path("/proc")

# /proc/<pid>/status reports uid and gid as four values in this order.
_ID_KINDS = ("real", "effective", "saved", "filesystem")


class PrincipalCollector:
    """Record who a process actually is, separating effective authority from real authority.

    The two are not interchangeable. A process whose real uid is unprivileged but whose effective
    uid is the operator's holds the operator's authority right now, and collapsing them into one
    "user" would hide exactly the case the supported profile refuses to run.
    """

    name = "principal"
    scopes = (
        ("grants", "principal:uid:"),
        ("grants", "principal:gid:"),
        ("grants", "principal:capability:"),
    )

    def __init__(self, pid: int, operator_uid: int | None = None) -> None:
        self.pid = pid
        self.operator_uid = operator_uid

    def collect(self, context: CollectorContext) -> None:
        status = self._read_status(context)
        if status is None:
            return

        subject = f"process_identity:pid:{self.pid}"
        self._record_ids(context, status, subject, "Uid", "uid")
        self._record_ids(context, status, subject, "Gid", "gid")
        self._record_groups(context, status, subject)
        self._record_capabilities(context, status, subject)

    # -- reading ------------------------------------------------------------------------

    def _read_status(self, context: CollectorContext) -> dict[str, str] | None:
        """Parse /proc/<pid>/status, or record why it could not be read.

        A total read failure means none of this collector's three declared scopes were seen, not
        just uid. `guard` only covers the one scope it is given, so a failure here must also cover
        gid and capability explicitly -- otherwise they read back as silently empty rather than
        unknown, which is the failure mode this framework exists to prevent.
        """
        status: dict[str, str] = {}
        read_ok = False
        with context.guard(
            relation="grants",
            object_prefix="principal:uid:",
            detail=f"reading /proc/{self.pid}/status",
        ):
            text = context.read_proc_text(PROC / str(self.pid) / "status")
            for line in text.splitlines():
                key, separator, value = line.partition(":")
                if separator:
                    status[key.strip()] = value.strip()
            read_ok = True
        if not read_ok:
            detail = f"reading /proc/{self.pid}/status failed; see the principal:uid: unknown"
            for kind in ("gid", "capability"):
                context.unknown(
                    relation="grants",
                    object_prefix=f"principal:{kind}:",
                    code="partial_enumeration",
                    detail=detail,
                )
            return None
        return status or None

    # -- recording ----------------------------------------------------------------------

    def _record_ids(
        self,
        context: CollectorContext,
        status: dict[str, str],
        subject: str,
        field: str,
        kind: str,
    ) -> None:
        raw = status.get(field)
        if raw is None:
            context.unknown(
                relation="grants",
                object_prefix=f"principal:{kind}:",
                code="partial_enumeration",
                detail=f"/proc/{self.pid}/status has no {field} line",
            )
            return

        values = raw.split()
        for position, value in enumerate(values[: len(_ID_KINDS)]):
            context.emit(
                collector=self.name,
                discriminator=f"{self.pid}-{kind}-{_ID_KINDS[position]}",
                subject=subject,
                relation="grants",
                object=f"principal:{kind}:{value}",
                classification="observed",
                confidence="high",
                evidence=(
                    Evidence(
                        source="proc_status",
                        collector=f"collect.{self.name}",
                        collected_at=context.now,
                        detail=f"{field} {_ID_KINDS[position]} = {value}",
                    ),
                ),
            )

        self._flag_shared_authority(context, values, kind, subject)

    def _flag_shared_authority(
        self, context: CollectorContext, values: list[str], kind: str, subject: str
    ) -> None:
        """Record the unsupported profile where the process shares the operator's identity.

        This is not a finding about a resource; it is a finding that the containment story does
        not apply at all, so it is recorded rather than left for a reader to infer.
        """
        if kind != "uid" or self.operator_uid is None or len(values) < 2:
            return
        if int(values[1]) != self.operator_uid:
            return
        context.emit(
            collector=self.name,
            discriminator=f"{self.pid}-shares-operator-identity",
            subject=subject,
            relation="can-delegate",
            object=f"principal:uid:{self.operator_uid}",
            classification="observed",
            confidence="high",
            evidence=(
                Evidence(
                    source="proc_status",
                    collector=f"collect.{self.name}",
                    collected_at=context.now,
                    detail=(
                        f"effective uid {self.operator_uid} equals the operator uid; "
                        "this is an unsupported profile and cannot be contained"
                    ),
                ),
            ),
        )

    def _record_groups(
        self, context: CollectorContext, status: dict[str, str], subject: str
    ) -> None:
        raw = status.get("Groups")
        if raw is None:
            context.unknown(
                relation="grants",
                object_prefix="principal:gid:",
                code="partial_enumeration",
                detail=f"/proc/{self.pid}/status has no Groups line",
            )
            return

        # A gid can appear more than once in the Groups line - inside a user namespace the
        # unmapped gid repeats - and the same group twice is one grant, not two.
        groups = context.bounded(
            list(dict.fromkeys(raw.split())),
            relation="grants",
            object_prefix="principal:gid:",
            detail=f"supplementary groups of pid {self.pid}",
        )
        for gid in groups:
            context.emit(
                collector=self.name,
                discriminator=f"{self.pid}-group-{gid}",
                subject=subject,
                relation="grants",
                object=f"principal:gid:{gid}",
                classification="observed",
                confidence="high",
                evidence=(
                    Evidence(
                        source="proc_status",
                        collector=f"collect.{self.name}",
                        collected_at=context.now,
                        detail=f"supplementary group {gid}",
                    ),
                ),
            )

    def _record_capabilities(
        self, context: CollectorContext, status: dict[str, str], subject: str
    ) -> None:
        """Record the effective capability mask.

        A capability line that is missing is recorded as unknown rather than as an empty set. An
        empty set means the process holds no capabilities; an unreadable one means nobody knows,
        and reporting the second as the first would understate what the process can do.
        """
        raw = status.get("CapEff")
        if raw is None:
            context.unknown(
                relation="grants",
                object_prefix="principal:capability:",
                code="collector_permission_denied",
                detail=f"/proc/{self.pid}/status has no CapEff line",
            )
            return

        context.emit(
            collector=self.name,
            discriminator=f"{self.pid}-capeff",
            subject=subject,
            relation="grants",
            object=f"principal:capability:effective/{raw}",
            classification="observed",
            confidence="high",
            evidence=(
                Evidence(
                    source="proc_status",
                    collector=f"collect.{self.name}",
                    collected_at=context.now,
                    detail=f"CapEff mask {raw}",
                ),
            ),
        )
