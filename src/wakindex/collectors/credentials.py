"""Description: Collector for credential references, recording names and never values."""

from __future__ import annotations

import re
from pathlib import Path

from wakindex.collectors.base import CollectorContext
from wakindex.graph import Evidence

PROC = Path("/proc")

# Environment variable names that look like they hold credential material. Matching is on the
# NAME only. The value is never recorded, never logged, and never passed anywhere: the collector
# splits on the first "=" and discards the right-hand side immediately.
SECRET_NAME_PATTERN = re.compile(
    r"(?i)(token|secret|password|passwd|credential|api[_-]?key|private[_-]?key|auth|session)"
)

# Well-known credential-bearing paths worth recording when a process can see them. These are
# checked for existence only; none of them is ever opened.
_CREDENTIAL_PATHS = (
    "~/.aws/credentials",
    "~/.config/gh/hosts.yml",
    "~/.docker/config.json",
    "~/.netrc",
    "~/.ssh/id_rsa",
    "~/.ssh/id_ed25519",
    "~/.kube/config",
)


class CredentialCollector:
    """Record which credentials a session can reach, by reference only.

    Two rules shape this collector. Values never leave the parse: a name is enough to tell an
    operator what the agent holds, and a value in an inventory is a second copy of a secret in a
    place nobody is guarding.

    Remote scope is explicitly uncertain. Holding a token is not evidence of what it authorizes,
    and an offline collector cannot ask the issuer. Every finding here says so, because a reader
    who assumes otherwise will under- or over-estimate the blast radius in whichever direction is
    convenient.
    """

    name = "credentials"
    scopes = (
        ("can-delegate", "credential_ref:env:"),
        ("can-delegate", "credential_ref:file:"),
    )

    def __init__(self, pid: int | str = "self", home: Path | None = None) -> None:
        self.pid = pid
        self.home = home or Path.home()

    def collect(self, context: CollectorContext) -> None:
        self._record_environment(context)
        self._record_credential_files(context)

    # -- environment ----------------------------------------------------------------------

    def _record_environment(self, context: CollectorContext) -> None:
        """Record credential-shaped environment variable names.

        /proc/<pid>/environ holds NAME=VALUE pairs. Only the name survives this function.
        """
        try:
            raw = context.read_proc_text(PROC / str(self.pid) / "environ")
        except PermissionError as err:
            context.unknown(
                relation="can-delegate",
                object_prefix="credential_ref:env:",
                code="collector_permission_denied",
                detail=f"reading environ of pid {self.pid}: {err.strerror or 'denied'}",
            )
            return
        except OSError as err:
            context.unknown(
                relation="can-delegate",
                object_prefix="credential_ref:env:",
                code="partial_enumeration",
                detail=f"reading environ of pid {self.pid}: {type(err).__name__}",
            )
            return

        names = [entry.split("=", 1)[0] for entry in raw.split("\0") if "=" in entry]
        del raw

        for variable in context.bounded(
            [name for name in names if SECRET_NAME_PATTERN.search(name)],
            relation="can-delegate",
            object_prefix="credential_ref:env:",
            detail=f"environment of pid {self.pid}",
        ):
            context.emit(
                collector=self.name,
                discriminator=f"env-{variable}",
                subject=f"session:{context.session_id}",
                relation="can-delegate",
                object=f"credential_ref:env:{variable}",
                classification="observed",
                confidence="high",
                evidence=(
                    Evidence(
                        source="proc_environ",
                        collector=f"collect.{self.name}",
                        collected_at=context.now,
                        detail=(
                            f"environment variable {variable} is set; its value was not read "
                            "and what it authorizes remotely is unknown"
                        ),
                    ),
                ),
            )

    # -- files ----------------------------------------------------------------------------

    def _record_credential_files(self, context: CollectorContext) -> None:
        """Record credential files the session can see.

        Existence is checked and nothing is opened. Reading one to confirm what it holds would
        make the inventory the thing that exposes the credential.
        """
        for candidate in context.bounded(
            list(_CREDENTIAL_PATHS),
            relation="can-delegate",
            object_prefix="credential_ref:file:",
            detail="well-known credential paths",
        ):
            path = Path(candidate.replace("~", str(self.home), 1))
            with context.guard(
                relation="can-delegate",
                object_prefix=f"credential_ref:file:{path}",
                detail=f"checking {candidate}",
            ):
                if not path.exists():
                    continue
                context.emit(
                    collector=self.name,
                    discriminator=f"file-{candidate}",
                    subject=f"session:{context.session_id}",
                    relation="can-delegate",
                    object=f"credential_ref:file:{path}",
                    classification="observed",
                    confidence="high",
                    evidence=(
                        Evidence(
                            source="filesystem",
                            collector=f"collect.{self.name}",
                            collected_at=context.now,
                            detail=(
                                f"credential file present at {candidate}; it was not opened and "
                                "what it authorizes remotely is unknown"
                            ),
                        ),
                    ),
                )
