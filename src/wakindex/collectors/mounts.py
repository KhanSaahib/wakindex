"""Description: Collector for the mount table visible to a process, including propagation mode."""

from __future__ import annotations

from pathlib import Path

from wakindex.collectors.base import CollectorContext
from wakindex.graph import Evidence

PROC = Path("/proc")

# Optional fields in /proc/<pid>/mountinfo end at this separator, after which the layout is fixed.
_OPTIONAL_TERMINATOR = "-"
_PROPAGATION_KEYS = ("shared", "master", "propagate_from", "unbindable")


class MountCollector:
    """Record the mount table a process can see.

    Propagation mode is recorded because it decides whether the perimeter is a snapshot or a
    moving target: a shared mount can carry a mount created on the host into the sandbox after
    launch, so a boundary that looked complete at launch may not be.

    The collector reads the mount table and nothing else. Walking or statting under a mount point
    would mean touching whatever is mounted there, which for an adversarial mount is the point.
    """

    name = "mounts"
    scopes = (("can-read", "resource:mount:"),)

    def __init__(self, pid: int | str = "self") -> None:
        self.pid = pid

    def collect(self, context: CollectorContext) -> None:
        text = self._read_mountinfo(context)
        if text is None:
            return

        for line in context.bounded(
            text.splitlines(),
            relation="can-read",
            object_prefix="resource:mount:",
            detail=f"mount table of pid {self.pid}",
        ):
            with context.guard(
                relation="can-read",
                object_prefix="resource:mount:",
                detail="parsing a mountinfo line",
            ):
                self._record_mount(context, line)

    def _read_mountinfo(self, context: CollectorContext) -> str | None:
        """Read the mount table, or record that the whole filesystem scope was not seen.

        An unreadable mount table is not an empty mount table. Returning nothing would say the
        process sees no filesystem at all, which is the most reassuring possible lie.
        """
        try:
            return context.read_proc_text(PROC / str(self.pid) / "mountinfo")
        except PermissionError as err:
            context.unknown(
                relation="can-read",
                object_prefix="resource:mount:",
                code="collector_permission_denied",
                detail=f"reading mountinfo of pid {self.pid}: {err.strerror or 'denied'}",
            )
        except OSError as err:
            context.unknown(
                relation="can-read",
                object_prefix="resource:mount:",
                code="partial_enumeration",
                detail=f"reading mountinfo of pid {self.pid}: {type(err).__name__}",
            )
        return None

    def _record_mount(self, context: CollectorContext, line: str) -> None:
        parsed = parse_mountinfo_line(line)
        if parsed is None:
            return

        mount_point = parsed["mount_point"]
        writable = parsed["writable"]
        propagation = parsed["propagation"]

        context.emit(
            collector=self.name,
            discriminator=f"{parsed['mount_id']}-{mount_point}",
            subject=f"session:{context.session_id}",
            relation="can-write" if writable else "can-read",
            object=f"resource:mount:{mount_point}",
            classification="declared",
            confidence="high",
            evidence=(
                Evidence(
                    source="proc_mountinfo",
                    collector=f"collect.{self.name}",
                    collected_at=context.now,
                    detail=(
                        f"{parsed['fs_type']} from {parsed['source']} at {mount_point}, "
                        f"{'rw' if writable else 'ro'}, propagation {propagation}"
                    ),
                ),
            ),
        )


def parse_mountinfo_line(line: str) -> dict[str, object] | None:
    """Parse one /proc/<pid>/mountinfo line.

    Format: mount_id parent_id major:minor root mount_point options [optional...] - fs source opts
    The optional field count varies, which is why the separator is found rather than an index
    assumed.
    """
    fields = line.split()
    if len(fields) < 7 or _OPTIONAL_TERMINATOR not in fields:
        return None

    separator = fields.index(_OPTIONAL_TERMINATOR)
    if separator + 2 >= len(fields):
        return None

    options = fields[5].split(",")
    optional = fields[6:separator]
    super_options = fields[separator + 3].split(",") if len(fields) > separator + 3 else []

    # A mount is writable only if neither the mount options nor the superblock says read-only.
    writable = "ro" not in options and "ro" not in super_options

    return {
        "mount_id": fields[0],
        "mount_point": fields[4],
        "fs_type": fields[separator + 1],
        "source": fields[separator + 2],
        "writable": writable,
        "propagation": _propagation(optional),
    }


def _propagation(optional: list[str]) -> str:
    """Name the propagation mode. `private` is the absence of every propagation marker."""
    modes = [field for field in optional if field.split(":")[0] in _PROPAGATION_KEYS]
    return ",".join(modes) if modes else "private"
