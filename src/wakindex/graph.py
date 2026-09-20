"""Description: Access graph records, snapshot normalization, and snapshot diff semantics."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime
from typing import Any

SCHEMA_VERSION = "1.0"
SCHEMA_MAJOR = 1

NODE_KINDS = frozenset(
    {
        "environment",
        "principal",
        "session",
        "process_identity",
        "resource",
        "tool_server",
        "credential_ref",
        "policy_revision",
        "enforcement_boundary",
    }
)
RELATIONS = frozenset(
    {
        "can-read",
        "can-write",
        "can-execute",
        "can-connect",
        "can-invoke",
        "can-delegate",
        "inherits",
        "grants",
        "contains",
        "revokes",
    }
)
CLASSIFICATIONS = frozenset({"declared", "observed", "inferred", "enforced"})
CONFIDENCES = frozenset({"high", "medium", "low"})
ENFORCEMENT_STATUSES = frozenset({"enforced", "unenforced", "unsupported", "unknown"})
ENFORCEMENT_MECHANISMS = frozenset(
    {
        "landlock-fs",
        "landlock-net",
        "landlock-scope",
        "netns",
        "mountns",
        "pidns",
        "cgroup-v2",
        "broker",
        "none",
    }
)
UNKNOWN_CODES = frozenset(
    {
        "collector_permission_denied",
        "collector_timeout",
        "collector_bounded_out",
        "unsupported_platform",
        "partial_enumeration",
        "agent_config_unreadable",
    }
)

# Shapes of credential material that must never reach a stored or exported record. Collectors
# carry references such as an environment variable name; a value that looks like a secret is a
# collector defect, and failing the write is safer than persisting it and redacting later.
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}"),
    re.compile(r"(?i)\b(?:password|passwd|secret|token)\s*[=:]\s*\S{6,}"),
)


class ContractError(ValueError):
    """A record violates the access graph contract."""


class SchemaIncompatible(ContractError):
    """A record's schema major version does not match this implementation."""


class SecretInEvidence(ContractError):
    """A record carries something shaped like a credential value."""


def _require(value: str, allowed: frozenset[str], field: str) -> str:
    if value not in allowed:
        raise ContractError(f"{field}: {value!r} is not one of {sorted(allowed)}")
    return value


def _require_node_id(value: str, field: str) -> str:
    kind = value.split(":", 1)[0]
    if kind not in NODE_KINDS:
        raise ContractError(f"{field}: {value!r} does not start with a known node kind")
    return value


def _require_schema(value: str) -> str:
    if not re.fullmatch(r"\d+\.\d+", value):
        raise ContractError(f"schema_version: {value!r} is not MAJOR.MINOR")
    if int(value.split(".")[0]) != SCHEMA_MAJOR:
        raise SchemaIncompatible(f"schema_version {value} is not major version {SCHEMA_MAJOR}")
    return value


def reject_secrets(text: str, field: str) -> str:
    """Raise if the text is shaped like credential material."""
    for pattern in SECRET_PATTERNS:
        if pattern.search(text):
            raise SecretInEvidence(f"{field}: value matches a credential pattern and was rejected")
    return text


def _copy_extensions(data: dict[str, Any]) -> dict[str, Any]:
    """Copy JSON evidence without aliases and apply the same secret-pattern guard."""
    encoded = json.dumps(data, allow_nan=False)
    reject_secrets(encoded, "evidence extensions")
    return json.loads(encoded)


def _extensions(data: dict[str, Any], known: set[str]) -> dict[str, Any]:
    return _copy_extensions({key: value for key, value in data.items() if key not in known})


def _export(extensions: dict[str, Any], known: dict[str, Any]) -> dict[str, Any]:
    if extensions.keys() & known.keys():
        raise ContractError("evidence extensions cannot override known fields")
    return {**_copy_extensions(extensions), **known}


@dataclass(frozen=True)
class Evidence:
    """Why a finding was recorded. Lives in the sidecar, never in the normalized form."""

    source: str
    collector: str
    collected_at: str
    detail: str
    extensions: dict[str, Any] = field(default_factory=dict, kw_only=True)

    def __post_init__(self) -> None:
        reject_secrets(self.detail, "evidence.detail")

    def as_dict(self) -> dict[str, Any]:
        return _export(
            self.extensions,
            {
                "source": self.source,
                "collector": self.collector,
                "collected_at": self.collected_at,
                "detail": self.detail,
            },
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Evidence:
        return cls(
            source=data["source"],
            collector=data["collector"],
            collected_at=data["collected_at"],
            detail=data["detail"],
            extensions=_extensions(data, {"source", "collector", "collected_at", "detail"}),
        )


@dataclass(frozen=True)
class Freshness:
    """When a finding was collected and how long it may be trusted."""

    collected_at: str
    valid_until: str
    stale: bool = False
    extensions: dict[str, Any] = field(default_factory=dict, kw_only=True)

    def __post_init__(self) -> None:
        if type(self.stale) is not bool:
            raise ContractError("freshness.stale must be a boolean")
        if _timestamp(self.valid_until) < _timestamp(self.collected_at):
            raise ContractError("freshness.valid_until precedes collected_at")

    def as_of(self, now: str) -> Freshness:
        """Return this freshness marked stale if the validity window has closed at `now`."""
        expired = _timestamp(now) >= _timestamp(self.valid_until)
        return replace(self, stale=self.stale or expired)

    def as_dict(self) -> dict[str, Any]:
        return _export(
            self.extensions,
            {
                "collected_at": self.collected_at,
                "valid_until": self.valid_until,
                "stale": self.stale,
            },
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Freshness:
        return cls(
            data["collected_at"],
            data["valid_until"],
            data.get("stale", False),
            extensions=_extensions(data, {"collected_at", "valid_until", "stale"}),
        )


def _timestamp(value: str) -> datetime:
    """Parse a timestamp with a known offset; never echo untrusted input in errors."""
    pattern = r"[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}"
    pattern += r"(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})"
    if not isinstance(value, str) or not re.fullmatch(pattern, value):
        raise ContractError("freshness timestamp requires RFC3339 with a known offset")
    if value.endswith("-00:00"):
        raise ContractError("freshness timestamp has an unknown offset")
    try:
        return datetime.fromisoformat(value.upper().replace("Z", "+00:00"))
    except ValueError:
        raise ContractError("invalid freshness timestamp") from None


@dataclass(frozen=True)
class Enforcement:
    """Whether a boundary covers this access, and which mechanism provides it."""

    status: str
    mechanism: str
    policy_revision: int | None = None
    extensions: dict[str, Any] = field(default_factory=dict, kw_only=True)

    def __post_init__(self) -> None:
        _require(self.status, ENFORCEMENT_STATUSES, "enforcement.status")
        _require(self.mechanism, ENFORCEMENT_MECHANISMS, "enforcement.mechanism")
        if self.status == "enforced" and self.mechanism == "none":
            raise ContractError("enforcement: status 'enforced' requires a mechanism")

    def as_dict(self) -> dict[str, Any]:
        return _export(
            self.extensions,
            {
                "status": self.status,
                "mechanism": self.mechanism,
                "policy_revision": self.policy_revision,
            },
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Enforcement:
        return cls(
            data["status"],
            data["mechanism"],
            data.get("policy_revision"),
            extensions=_extensions(data, {"status", "mechanism", "policy_revision"}),
        )


@dataclass(frozen=True)
class AccessUnknown:
    """A scope a collector could not see. Absence of evidence is recorded, never implied."""

    unknown_id: str
    session_id: str
    relation: str
    object_prefix: str
    code: str
    detail: str
    collected_at: str
    schema_version: str = SCHEMA_VERSION
    extensions: dict[str, Any] = field(default_factory=dict, kw_only=True)
    scope_extensions: dict[str, Any] = field(default_factory=dict, kw_only=True)

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        _require(self.relation, RELATIONS, "unknown.scope.relation")
        _require(self.code, UNKNOWN_CODES, "unknown.code")
        reject_secrets(self.detail, "unknown.detail")

    def covers(self, finding: AccessFinding) -> bool:
        """True when this unknown makes statements about the finding indeterminate."""
        return finding.relation == self.relation and finding.object.startswith(self.object_prefix)

    def as_dict(self) -> dict[str, Any]:
        return _export(
            self.extensions,
            {
                "schema_version": self.schema_version,
                "unknown_id": self.unknown_id,
                "session_id": self.session_id,
                "scope": _export(
                    self.scope_extensions,
                    {"relation": self.relation, "object_prefix": self.object_prefix},
                ),
                "code": self.code,
                "detail": self.detail,
                "collected_at": self.collected_at,
            },
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AccessUnknown:
        scope = data["scope"]
        return cls(
            unknown_id=data["unknown_id"],
            session_id=data["session_id"],
            relation=scope["relation"],
            object_prefix=scope["object_prefix"],
            code=data["code"],
            detail=data["detail"],
            collected_at=data["collected_at"],
            schema_version=data.get("schema_version", SCHEMA_VERSION),
            extensions=_extensions(
                data,
                {
                    "schema_version",
                    "unknown_id",
                    "session_id",
                    "scope",
                    "code",
                    "detail",
                    "collected_at",
                },
            ),
            scope_extensions=_extensions(scope, {"relation", "object_prefix"}),
        )


@dataclass(frozen=True)
class AccessFinding:
    """One edge of the access graph, with provenance and enforcement status."""

    finding_id: str
    session_id: str
    subject: str
    relation: str
    object: str
    classification: str
    confidence: str
    evidence: tuple[Evidence, ...]
    freshness: Freshness
    enforcement: Enforcement
    schema_version: str = SCHEMA_VERSION
    extensions: dict[str, Any] = field(default_factory=dict, kw_only=True)

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        _require_node_id(self.subject, "subject")
        _require_node_id(self.object, "object")
        _require(self.relation, RELATIONS, "relation")
        _require(self.classification, CLASSIFICATIONS, "classification")
        _require(self.confidence, CONFIDENCES, "confidence")
        if not self.evidence:
            raise ContractError(f"{self.finding_id}: a finding must carry evidence")
        if self.classification == "enforced" and self.enforcement.status != "enforced":
            raise ContractError(
                f"{self.finding_id}: classification 'enforced' requires enforcement status "
                "'enforced'; only an installed boundary supports a negative claim"
            )

    def normalized(self) -> dict[str, Any]:
        """The stable projection used for diffing. Carries no timestamp, pid, inode or evidence."""
        return {
            "finding_id": self.finding_id,
            "subject": self.subject,
            "relation": self.relation,
            "object": self.object,
            "classification": self.classification,
            "enforcement_status": self.enforcement.status,
            "enforcement_mechanism": self.enforcement.mechanism,
            "policy_revision": self.enforcement.policy_revision,
        }

    def as_dict(self) -> dict[str, Any]:
        return _export(
            self.extensions,
            {
                "schema_version": self.schema_version,
                "finding_id": self.finding_id,
                "session_id": self.session_id,
                "subject": self.subject,
                "relation": self.relation,
                "object": self.object,
                "classification": self.classification,
                "confidence": self.confidence,
                "evidence": [item.as_dict() for item in self.evidence],
                "freshness": self.freshness.as_dict(),
                "enforcement": self.enforcement.as_dict(),
            },
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AccessFinding:
        return cls(
            finding_id=data["finding_id"],
            session_id=data["session_id"],
            subject=data["subject"],
            relation=data["relation"],
            object=data["object"],
            classification=data["classification"],
            confidence=data["confidence"],
            evidence=tuple(Evidence.from_dict(item) for item in data["evidence"]),
            freshness=Freshness.from_dict(data["freshness"]),
            enforcement=Enforcement.from_dict(data["enforcement"]),
            schema_version=data.get("schema_version", SCHEMA_VERSION),
            extensions=_extensions(
                data,
                {
                    "schema_version",
                    "finding_id",
                    "session_id",
                    "subject",
                    "relation",
                    "object",
                    "classification",
                    "confidence",
                    "evidence",
                    "freshness",
                    "enforcement",
                },
            ),
        )


@dataclass(frozen=True)
class Snapshot:
    """One collection pass over a session: what was found, and what could not be seen."""

    session_id: str
    findings: tuple[AccessFinding, ...]
    unknowns: tuple[AccessUnknown, ...] = ()
    schema_version: str = SCHEMA_VERSION
    extensions: dict[str, Any] = field(default_factory=dict, kw_only=True)

    def __post_init__(self) -> None:
        _require_schema(self.schema_version)
        seen: set[str] = set()
        for finding in self.findings:
            if finding.finding_id in seen:
                raise ContractError(f"duplicate finding_id in snapshot: {finding.finding_id}")
            seen.add(finding.finding_id)

    def normalized(self) -> list[dict[str, Any]]:
        """Findings in stable order. Two scans of an unchanged environment produce equal output."""
        return [finding.normalized() for finding in sorted(self.findings, key=_by_finding_id)]

    def normalized_json(self) -> str:
        """Canonical bytes for the normalized form, for equality checks and stored digests."""
        return json.dumps(self.normalized(), sort_keys=True, separators=(",", ":"))

    def evidence_sidecar(self) -> dict[str, Any]:
        """Volatile detail keyed by finding id, kept out of the normalized form."""
        return {
            finding.finding_id: {
                "evidence": [item.as_dict() for item in finding.evidence],
                "freshness": finding.freshness.as_dict(),
                "confidence": finding.confidence,
            }
            for finding in sorted(self.findings, key=_by_finding_id)
        }

    def covering_unknown(self, finding: AccessFinding) -> AccessUnknown | None:
        """The unknown that makes this finding's scope indeterminate, if any."""
        for unknown in self.unknowns:
            if unknown.covers(finding):
                return unknown
        return None

    def marked_stale(self, now: str) -> Snapshot:
        """Return a copy with every finding's freshness evaluated at `now`."""
        findings = tuple(
            replace(finding, freshness=finding.freshness.as_of(now)) for finding in self.findings
        )
        return replace(self, findings=findings)

    def as_dict(self) -> dict[str, Any]:
        ordered = sorted(self.findings, key=_by_finding_id)
        return _export(
            self.extensions,
            {
                "schema_version": self.schema_version,
                "session_id": self.session_id,
                "findings": [finding.as_dict() for finding in ordered],
                "unknowns": [unknown.as_dict() for unknown in self.unknowns],
            },
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Snapshot:
        return cls(
            session_id=data["session_id"],
            findings=tuple(AccessFinding.from_dict(item) for item in data["findings"]),
            unknowns=tuple(AccessUnknown.from_dict(item) for item in data.get("unknowns", ())),
            schema_version=data.get("schema_version", SCHEMA_VERSION),
            extensions=_extensions(data, {"schema_version", "session_id", "findings", "unknowns"}),
        )


def _by_finding_id(finding: AccessFinding) -> str:
    return finding.finding_id


@dataclass(frozen=True)
class SnapshotDiff:
    """The difference between two snapshots, keeping scan failure distinct from lost access."""

    added: tuple[str, ...]
    removed: tuple[str, ...]
    changed: tuple[str, ...]
    indeterminate: tuple[str, ...]
    carried_unknowns: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "added": list(self.added),
            "removed": list(self.removed),
            "changed": list(self.changed),
            "indeterminate": list(self.indeterminate),
            "carried_unknowns": list(self.carried_unknowns),
        }

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.changed or self.indeterminate)


def diff(before: Snapshot, after: Snapshot) -> SnapshotDiff:
    """Compare two snapshots.

    A finding present in `before` and missing from `after` is `removed` only when `after` has no
    unknown covering its scope. When a collector failed over that scope the finding is
    `indeterminate` instead: a scan failure is not evidence that access was revoked.
    """
    before_by_id = {finding.finding_id: finding for finding in before.findings}
    after_by_id = {finding.finding_id: finding for finding in after.findings}

    added = sorted(set(after_by_id) - set(before_by_id))
    changed = sorted(
        finding_id
        for finding_id in set(before_by_id) & set(after_by_id)
        if before_by_id[finding_id].normalized() != after_by_id[finding_id].normalized()
    )

    removed: list[str] = []
    indeterminate: list[str] = []
    for finding_id in sorted(set(before_by_id) - set(after_by_id)):
        if after.covering_unknown(before_by_id[finding_id]) is None:
            removed.append(finding_id)
        else:
            indeterminate.append(finding_id)

    return SnapshotDiff(
        added=tuple(added),
        removed=tuple(removed),
        changed=tuple(changed),
        indeterminate=tuple(indeterminate),
        carried_unknowns=tuple(sorted(unknown.unknown_id for unknown in after.unknowns)),
    )
