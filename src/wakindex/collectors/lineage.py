"""Description: Collector for process lineage, cwd, root, and inherited descriptors."""

from __future__ import annotations

import os
from pathlib import Path

from wakindex.collectors.base import CollectorContext
from wakindex.graph import Evidence

PROC = Path("/proc")


class LineageCollector:
    """Walk a managed process tree and record its descendants and inherited resources.

    A process tree is not a stable structure to read. Descendants exit and appear while the walk
    is in progress, and a descriptor's target can be renamed between reading the link and writing
    the record. None of that is an edge case here: an agent under observation has every reason to
    fork faster than it is read, so the races are what the collector is judged on.
    """

    name = "lineage"
    scopes = (
        ("contains", "process_identity:pid:"),
        ("can-read", "resource:file:"),
    )

    def __init__(self, root_pid: int) -> None:
        self.root_pid = root_pid

    def collect(self, context: CollectorContext) -> None:
        pids = self._walk_tree(context)
        for pid in context.bounded(
            [str(pid) for pid in pids],
            relation="contains",
            object_prefix="process_identity:pid:",
            detail=f"descendants of pid {self.root_pid}",
        ):
            self._record_process(context, int(pid))

    # -- tree walk ----------------------------------------------------------------------

    def _walk_tree(self, context: CollectorContext) -> list[int]:
        """Collect the root and its descendants breadth first.

        A process that exits mid-walk is skipped rather than fatal: it is gone, and recording it
        as present would be wrong. A process that appears mid-walk may be missed, so the walk
        re-reads the frontier once and records a partial_enumeration unknown if the set grew --
        an agent that forks while being read must not be able to hide a descendant for free.
        """
        seen: list[int] = []
        first = self._descendants(context, self.root_pid, seen)
        second_pass: list[int] = []
        self._descendants(context, self.root_pid, second_pass)

        if set(second_pass) - set(first):
            context.unknown(
                relation="contains",
                object_prefix="process_identity:pid:",
                code="partial_enumeration",
                detail=(
                    f"process tree of pid {self.root_pid} changed during the walk; "
                    f"{len(set(second_pass) - set(first))} descendant(s) appeared"
                ),
            )
        return sorted(set(first) | set(second_pass))

    def _descendants(self, context: CollectorContext, pid: int, seen: list[int]) -> list[int]:
        frontier = [pid]
        while frontier:
            current = frontier.pop()
            if current in seen:
                continue
            if not (PROC / str(current)).exists():
                continue
            seen.append(current)
            frontier.extend(self._children(context, current))
        return seen

    def _children(self, context: CollectorContext, pid: int) -> list[int]:
        """Read a process's children. A vanished process is gone, not an error."""
        children: list[int] = []
        task_dir = PROC / str(pid) / "task"
        try:
            tasks = sorted(entry.name for entry in os.scandir(task_dir))
        except FileNotFoundError:
            return children
        except PermissionError as err:
            context.unknown(
                relation="contains",
                object_prefix=f"process_identity:pid:{pid}",
                code="collector_permission_denied",
                detail=f"listing tasks of pid {pid}: {err.strerror or 'permission denied'}",
            )
            return children

        for task in tasks:
            try:
                raw = context.read_proc_text(task_dir / task / "children")
            except FileNotFoundError:
                continue
            except PermissionError as err:
                context.unknown(
                    relation="contains",
                    object_prefix=f"process_identity:pid:{pid}",
                    code="collector_permission_denied",
                    detail=f"reading children of pid {pid}: {err.strerror or 'denied'}",
                )
                continue
            children.extend(int(value) for value in raw.split())
        return children

    # -- per-process records --------------------------------------------------------------

    def _record_process(self, context: CollectorContext, pid: int) -> None:
        subject = f"session:{context.session_id}"
        identity = f"process_identity:pid:{pid}"

        if not (PROC / str(pid)).exists():
            # It was alive during the walk and is gone now. Say so rather than dropping it: the
            # descendant existed, and a reader deciding whether the tree was contained needs it.
            context.unknown(
                relation="contains",
                object_prefix=identity,
                code="partial_enumeration",
                detail=f"pid {pid} exited between the walk and the record",
            )
            return

        context.emit(
            collector=self.name,
            discriminator=f"contains-{pid}",
            subject=subject,
            relation="contains",
            object=identity,
            classification="observed",
            confidence="high",
            evidence=(
                Evidence(
                    source="proc_tree",
                    collector=f"collect.{self.name}",
                    collected_at=context.now,
                    detail=f"descendant of pid {self.root_pid}",
                ),
            ),
        )

        for link, label in (("cwd", "working directory"), ("root", "filesystem root")):
            self._record_link(context, pid, identity, link, label)
        self._record_descriptors(context, pid, identity)

    def _record_link(
        self, context: CollectorContext, pid: int, identity: str, link: str, label: str
    ) -> None:
        target = self._read_link(context, PROC / str(pid) / link)
        if target is None:
            return
        context.emit(
            collector=self.name,
            discriminator=f"{link}-{pid}",
            subject=identity,
            relation="can-read",
            object=f"resource:file:{target}",
            classification="observed",
            confidence="high",
            evidence=(
                Evidence(
                    source=f"proc_{link}",
                    collector=f"collect.{self.name}",
                    collected_at=context.now,
                    detail=f"{label} of pid {pid}",
                ),
            ),
        )

    def _record_descriptors(self, context: CollectorContext, pid: int, identity: str) -> None:
        """Record open descriptors as inherited access.

        Targets are read as link targets only. Opening the file to learn more about it would make
        the collector read content it discovered, and an inherited descriptor is exactly the kind
        of thing an adversary would point at something it wants read.
        """
        fd_dir = PROC / str(pid) / "fd"
        try:
            entries = sorted(entry.name for entry in os.scandir(fd_dir))
        except FileNotFoundError:
            return
        except PermissionError as err:
            context.unknown(
                relation="can-read",
                object_prefix=f"resource:file:/proc/{pid}/fd",
                code="collector_permission_denied",
                detail=f"listing descriptors of pid {pid}: {err.strerror or 'denied'}",
            )
            return

        for fd in context.bounded(
            entries,
            relation="can-read",
            object_prefix=f"resource:file:/proc/{pid}/fd",
            detail=f"descriptors of pid {pid}",
        ):
            target = self._read_link(context, fd_dir / fd)
            if target is None:
                continue
            context.emit(
                collector=self.name,
                discriminator=f"fd-{pid}-{fd}",
                subject=identity,
                relation="can-read",
                object=f"resource:file:{target}",
                classification="observed",
                confidence="high",
                evidence=(
                    Evidence(
                        source="proc_fd",
                        collector=f"collect.{self.name}",
                        collected_at=context.now,
                        detail=f"descriptor {fd} of pid {pid}",
                    ),
                ),
            )

    def _read_link(self, context: CollectorContext, path: Path | str) -> str | None:
        """Read a link target, reporting what was observed rather than guessing after a rename.

        A target that has been renamed or deleted under us is reported as what the kernel says --
        including a "(deleted)" suffix -- because the alternative is inventing a path that may now
        belong to a different file.

        A failed read is scoped to the whole `resource:file:` namespace this relation uses, not
        to the process identity: the finding this read would have produced is named by its
        *target* path, which is exactly what a failed read never learns, so there is no narrower
        prefix this unknown could name and still cover it. `AccessUnknown` has no per-subject
        scope to narrow this to just this pid's own findings either. This over-covers -- a failed
        readlink for one pid can mark an unrelated pid's can-read/file finding as indeterminate
        rather than removed -- but that is the safe direction of error: reporting a real access
        removal as "unknown, scan failed here" is a false negative for containment, and this
        system's stated rule is to never let unknown look safe.
        """
        link = Path(path)
        try:
            return os.readlink(link)
        except FileNotFoundError:
            return None
        except PermissionError as err:
            context.unknown(
                relation="can-read",
                object_prefix="resource:file:",
                code="collector_permission_denied",
                detail=f"reading link {link.name}: {err.strerror or 'permission denied'}",
            )
            return None
        except OSError as err:
            context.unknown(
                relation="can-read",
                object_prefix="resource:file:",
                code="partial_enumeration",
                detail=f"reading link {link.name}: {type(err).__name__}",
            )
            return None
