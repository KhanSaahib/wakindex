"""Description: Capability policy validation, canonical matching, and deterministic evaluation."""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

SCHEMA_VERSION = "1.0"
SCHEMA_MAJOR = 1

CAPABILITIES = frozenset(
    {
        "file.read",
        "file.write",
        "file.exec",
        "proc.spawn",
        "net.connect",
        "net.bind",
        "tool.invoke",
        "cred.use",
    }
)
EFFECTS = frozenset({"allow", "deny"})

REASON_CODES = frozenset(
    {
        "ALLOW_RULE",
        "DENY_DEFAULT",
        "DENY_EXPLICIT_RULE",
        "DENY_BUDGET_EXCEEDED",
        "DENY_SESSION_STOPPING",
        "DENY_REVISION_MISMATCH",
        "DENY_UNSUPPORTED_ENFORCEMENT",
        "DENY_LEASE_EXPIRED",
        "DENY_SCHEMA_INCOMPATIBLE",
    }
)

ENFORCEMENT_KINDS = frozenset({"os", "broker", "advisory"})

BUDGET_LIMITS = frozenset({"cpu_ms", "memory_bytes", "pids", "storage_bytes", "wall_ms"})

# Match keys a rule may carry. Anything else is a validation error rather than an ignored key: a
# misspelled selector would narrow nothing and quietly widen the rule it was meant to restrict.
_MATCH_KEYS = frozenset({"any", "path", "path_prefix", "host", "tool", "method"})
_RULE_KEYS = frozenset({"id", "effect", "capability", "match", "reason_code"})
_REVISION_KEYS = frozenset(
    {
        "schema_version",
        "revision",
        "parent_revision",
        "created_at",
        "created_by",
        "rules",
        "budgets",
    }
)

_RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class PolicyError(ValueError):
    """A policy document or request is not valid."""


class PolicyInvalid(PolicyError):
    """The document failed validation. The whole revision is rejected, never partially loaded."""


class PolicySchemaIncompatible(PolicyError):
    """The document's schema major version is not understood. Fails closed."""


def canonical_json(document: Any) -> str:
    """Serialize with sorted keys and no insignificant whitespace, for stable digests."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), allow_nan=False)


def canonical_path(raw: str) -> str | None:
    """Normalize an absolute path for segment-wise comparison.

    Returns None for anything that cannot be reduced to an absolute path with no traversal left
    in it. A path the evaluator cannot canonicalize is denied rather than matched loosely, since
    a loose match is the direction of error that grants access.
    """
    if not isinstance(raw, str) or not raw.startswith("/") or "\x00" in raw:
        return None
    normalized = posixpath.normpath(raw)
    if not normalized.startswith("/") or normalized.startswith("/.."):
        return None
    return normalized


def path_within(candidate: str, prefix: str) -> bool:
    """True when `candidate` is `prefix` or lies beneath it, compared by path segment.

    Segment-wise rather than string-wise on purpose. A string prefix test would report
    `/home/op/project-secrets` as inside `/home/op/project`, silently granting a sibling
    directory because its name happens to start with an allowed one.
    """
    if candidate is None or prefix is None:
        return False
    if candidate == prefix:
        return True
    return candidate.startswith(prefix.rstrip("/") + "/")


@dataclass(frozen=True)
class Rule:
    """One policy rule. Frozen: an accepted revision is never edited in place.

    `frozen=True` only stops `rule.match = ...` from reassigning the attribute; it does nothing
    to protect a mutable dict already bound to that attribute. `rule.match["path_prefix"] = "/"`
    would otherwise succeed silently and change what this rule matches from underneath every
    holder of this object, including one already sitting in a cache keyed by `revision_digest`.
    `__post_init__` replaces whatever mapping was passed in with a read-only view over a private
    copy, so no caller's own dict can alias it either.
    """

    id: str
    effect: str
    capability: str
    match: Mapping[str, Any]
    reason_code: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "match", MappingProxyType(dict(self.match)))

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "effect": self.effect,
            "capability": self.capability,
            "match": dict(self.match),
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True)
class Budgets:
    """Resource limits carried by a revision. Absent limits are not enforced by this evaluator.

    Same mutability gap as `Rule.match`, same fix: `object.__setattr__` in `__post_init__` swaps
    in a read-only view over a private copy so `revision.budgets.limits["pids"] = 0` cannot widen
    a budget out from under an evaluator that already decided a revision's digest identifies it.
    """

    limits: Mapping[str, int]

    def __post_init__(self) -> None:
        object.__setattr__(self, "limits", MappingProxyType(dict(self.limits)))

    def as_dict(self) -> dict[str, int]:
        return dict(self.limits)


@dataclass(frozen=True)
class PolicyRevision:
    """An immutable, content-addressed policy revision."""

    revision: int
    parent_revision: int | None
    created_at: str
    created_by: str
    rules: tuple[Rule, ...]
    budgets: Budgets
    schema_version: str = SCHEMA_VERSION

    @property
    def revision_digest(self) -> str:
        """SHA-256 over canonical JSON. Stable across key order and whitespace."""
        return "sha256:" + hashlib.sha256(canonical_json(self.as_dict()).encode()).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "revision": self.revision,
            "parent_revision": self.parent_revision,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "rules": [rule.as_dict() for rule in self.rules],
            "budgets": self.budgets.as_dict(),
        }

    def to_json(self) -> str:
        return canonical_json(self.as_dict())


# -- validation ----------------------------------------------------------------------------


def _reject_unknown(data: dict[str, Any], allowed: frozenset[str], where: str) -> None:
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise PolicyInvalid(f"{where}: unknown field(s) {unknown}")


def _require_choice(value: Any, allowed: frozenset[str], where: str) -> str:
    """Check membership only for strings.

    `value in frozenset` raises TypeError on an unhashable value such as a list, which turns a
    malformed document into an unexpected crash instead of a clean rejection. Authority-bearing
    input must always fail closed with a validation error a caller can report.
    """
    if not isinstance(value, str) or value not in allowed:
        raise PolicyInvalid(f"{where}: must be one of {sorted(allowed)}")
    return value


def _require_mapping(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PolicyInvalid(f"{where}: expected an object")
    if any(not isinstance(key, str) for key in value):
        raise PolicyInvalid(f"{where}: keys must be strings")
    return value


def _validate_match(match: Any, rule_id: str, capability: str) -> dict[str, Any]:
    where = f"rule {rule_id} match"
    data = _require_mapping(match, where)
    _reject_unknown(data, _MATCH_KEYS, where)
    if not data:
        raise PolicyInvalid(f"{where}: must select something; use {{'any': true}} to mean all")

    if "any" in data:
        if data["any"] is not True:
            raise PolicyInvalid(f"{where}: 'any' may only be true")
        if len(data) != 1:
            raise PolicyInvalid(f"{where}: 'any' cannot be combined with another selector")
        return dict(data)

    if capability.startswith("file.") or capability == "proc.spawn":
        allowed = {"path", "path_prefix"}
    elif capability.startswith("net."):
        allowed = {"host"}
    elif capability == "tool.invoke":
        allowed = {"tool", "method"}
    else:
        allowed = set()
    if set(data) - allowed:
        raise PolicyInvalid(f"{where}: selectors are not supported for {capability}")

    for key in ("path", "path_prefix"):
        if key in data and canonical_path(data[key]) is None:
            raise PolicyInvalid(f"{where}: {key} must be an absolute path without traversal")
    for key in ("host", "tool", "method"):
        if key in data and (not isinstance(data[key], str) or not data[key]):
            raise PolicyInvalid(f"{where}: {key} must be a non-empty string")
    if "path" in data and "path_prefix" in data:
        raise PolicyInvalid(f"{where}: path and path_prefix are mutually exclusive")
    return dict(data)


def _validate_rule(raw: Any, index: int, seen: set[str]) -> Rule:
    where = f"rules[{index}]"
    data = _require_mapping(raw, where)
    _reject_unknown(data, _RULE_KEYS, where)

    missing = sorted(_RULE_KEYS - set(data))
    if missing:
        raise PolicyInvalid(f"{where}: missing field(s) {missing}")

    rule_id = data["id"]
    if not isinstance(rule_id, str) or not _RULE_ID.match(rule_id):
        raise PolicyInvalid(f"{where}: id must match {_RULE_ID.pattern}")
    if rule_id in seen:
        raise PolicyInvalid(f"{where}: duplicate rule id {rule_id!r}")
    seen.add(rule_id)

    effect = _require_choice(data["effect"], EFFECTS, f"{where}: effect must be")
    capability = _require_choice(
        data["capability"], CAPABILITIES, f"{where}: capability must be"
    )
    reason_code = _require_choice(
        data["reason_code"], REASON_CODES, f"{where}: reason_code must be"
    )

    expected = "ALLOW_RULE" if effect == "allow" else "DENY_EXPLICIT_RULE"
    if reason_code != expected:
        raise PolicyInvalid(
            f"{where}: effect {effect!r} requires reason_code {expected!r}; a rule whose "
            "stated reason contradicts its effect would explain a decision it did not make"
        )

    return Rule(
        id=rule_id,
        effect=effect,
        capability=capability,
        match=_validate_match(data["match"], rule_id, capability),
        reason_code=reason_code,
    )


def _validate_budgets(raw: Any) -> Budgets:
    data = _require_mapping(raw, "budgets")
    _reject_unknown(data, BUDGET_LIMITS, "budgets")
    limits: dict[str, int] = {}
    for name, value in data.items():
        if type(value) is not int or value < 0:
            raise PolicyInvalid(f"budgets.{name}: must be a non-negative integer")
        limits[name] = value
    return Budgets(limits)


def validate_revision(document: Any) -> PolicyRevision:
    """Validate a policy document and return an immutable revision.

    All-or-nothing by design. One bad rule rejects the whole document, because a partially loaded
    policy is a gap that no operator can see: the surviving rules look like the whole policy.
    """
    data = _require_mapping(document, "policy")

    version = data.get("schema_version", SCHEMA_VERSION)
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+", version):
        raise PolicyInvalid("schema_version must be MAJOR.MINOR")
    if int(version.split(".")[0]) != SCHEMA_MAJOR:
        raise PolicySchemaIncompatible(
            f"policy schema_version {version} is not major version {SCHEMA_MAJOR}"
        )

    _reject_unknown(data, _REVISION_KEYS, "policy")

    revision = data.get("revision")
    if type(revision) is not int or revision < 0:
        raise PolicyInvalid("revision must be a non-negative integer")

    parent = data.get("parent_revision")
    if parent is not None and (type(parent) is not int or parent >= revision):
        raise PolicyInvalid("parent_revision must be null or a lower revision number")

    for name in ("created_at", "created_by"):
        if not isinstance(data.get(name), str) or not data[name]:
            raise PolicyInvalid(f"{name} must be a non-empty string")

    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise PolicyInvalid("rules must be a list")

    seen: set[str] = set()
    rules = tuple(_validate_rule(raw, index, seen) for index, raw in enumerate(raw_rules))

    return PolicyRevision(
        revision=revision,
        parent_revision=parent,
        created_at=data["created_at"],
        created_by=data["created_by"],
        rules=rules,
        budgets=_validate_budgets(data.get("budgets", {})),
        schema_version=version,
    )


# -- evaluation ----------------------------------------------------------------------------


@dataclass(frozen=True)
class Request:
    """One authorization question. Budget usage is supplied, never read by the evaluator."""

    session_id: str
    capability: str
    resource: str
    usage: dict[str, int] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if not isinstance(self.capability, str) or self.capability not in CAPABILITIES:
            raise PolicyError(f"unknown capability {self.capability!r}")
        usage = {} if self.usage is None else self.usage
        _validate_budgets(usage)
        object.__setattr__(self, "usage", dict(usage))


@dataclass(frozen=True)
class Decision:
    """The outcome, bound to the exact revision that produced it."""

    session_id: str
    policy_revision: int
    revision_digest: str
    capability: str
    resource: str
    effect: str
    reason_code: str
    matched_rule_id: str | None
    enforcement: str
    schema_version: str = SCHEMA_VERSION

    @property
    def allowed(self) -> bool:
        return self.effect == "allow"

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "policy_revision": self.policy_revision,
            "revision_digest": self.revision_digest,
            "capability": self.capability,
            "resource": self.resource,
            "effect": self.effect,
            "reason_code": self.reason_code,
            "matched_rule_id": self.matched_rule_id,
            "enforcement": self.enforcement,
        }


def _resource_path(resource: str) -> str | None:
    """Extract the canonical path from a `resource:file:` identity, or None."""
    if not isinstance(resource, str) or not resource.startswith("resource:file:"):
        return None
    return canonical_path(resource[len("resource:file:") :])


def _resource_tool(resource: str) -> tuple[str | None, str | None]:
    """Split a `tool_server:...#method` identity into tool and method."""
    if not isinstance(resource, str) or not resource.startswith("tool_server:"):
        return None, None
    body = resource.split(":", 2)[-1]
    tool, separator, method = body.partition("#")
    return tool or None, (method if separator else None)


def _resource_host(resource: str) -> str | None:
    if not isinstance(resource, str):
        return None
    for prefix in ("resource:net:host/", "resource:net:tcp/", "resource:net:udp/"):
        if resource.startswith(prefix):
            return resource[len(prefix) :].rsplit(":", 1)[0].strip("[]")
    return None


def rule_matches(rule: Rule, request: Request) -> bool:
    """True when the rule's capability and selector both cover the request."""
    if rule.capability != request.capability:
        return False

    # Even a wildcard does not authorize an uninterpretable filesystem identity.
    if request.capability.startswith("file.") or request.capability == "proc.spawn":
        if _resource_path(request.resource) is None:
            return False

    match = rule.match
    if match.get("any") is True:
        return True

    if "path" in match:
        return _resource_path(request.resource) == canonical_path(match["path"])
    if "path_prefix" in match:
        return path_within(_resource_path(request.resource), canonical_path(match["path_prefix"]))

    if "host" in match:
        return _resource_host(request.resource) == match["host"]

    if "tool" in match or "method" in match:
        tool, method = _resource_tool(request.resource)
        if "tool" in match and tool != match["tool"]:
            return False
        if "method" in match and method != match["method"]:
            return False
        return tool is not None

    return False


def _specificity(rule: Rule) -> tuple[int, int, str]:
    """Order matching rules for reporting only. Never affects the outcome.

    Higher sorts first: an exact path or a fully qualified tool method beats a prefix, a longer
    prefix beats a shorter one, and the rule id breaks ties so the order is total. Two evaluators
    reading the same revision must name the same rule.
    """
    match = rule.match
    if "path" in match:
        return (3, len(canonical_path(match["path"]) or ""), rule.id)
    if "tool" in match and "method" in match:
        return (3, len(match["tool"]) + len(match["method"]), rule.id)
    if "path_prefix" in match:
        return (2, len(canonical_path(match["path_prefix"]) or ""), rule.id)
    if "host" in match or "tool" in match or "method" in match:
        return (2, 0, rule.id)
    return (1, 0, rule.id)


def _most_specific(rules: list[Rule]) -> Rule:
    def order(rule: Rule) -> tuple[int, int, str]:
        kind, length, rule_id = _specificity(rule)
        return (-kind, -length, rule_id)

    return sorted(rules, key=order)[0]


def _exceeded_budget(revision: PolicyRevision, request: Request) -> str | None:
    """Name the first exceeded limit, comparing only values the caller supplied."""
    for name in sorted(revision.budgets.limits):
        used = request.usage.get(name)
        if used is not None and used >= revision.budgets.limits[name]:
            return name
    return None


def evaluate(
    revision: PolicyRevision, request: Request, *, enforcement: str = "broker"
) -> Decision:
    """Decide one capability request against one revision.

    The order is total so that two evaluators cannot disagree:

    1. An exceeded budget denies, regardless of any rule.
    2. Any matching deny rule denies. No allow, however specific, overrides it.
    3. A matching allow rule allows.
    4. Nothing matched: deny by default. Absence is never permission.

    There is no model inference anywhere in this path, and none may be added: an authorization
    decision that cannot be reproduced from the revision alone is not an authorization decision.
    """
    if enforcement not in ENFORCEMENT_KINDS:
        raise PolicyError(f"unknown enforcement kind {enforcement!r}")
    # Request holds a caller-visible mapping; validate again at the decision boundary.
    _validate_budgets(request.usage)

    def decide(effect: str, reason: str, rule_id: str | None) -> Decision:
        return Decision(
            session_id=request.session_id,
            policy_revision=revision.revision,
            revision_digest=revision.revision_digest,
            capability=request.capability,
            resource=request.resource,
            effect=effect,
            reason_code=reason,
            matched_rule_id=rule_id,
            enforcement=enforcement,
        )

    exceeded = _exceeded_budget(revision, request)
    if exceeded is not None:
        return decide("deny", "DENY_BUDGET_EXCEEDED", None)

    matching = [rule for rule in revision.rules if rule_matches(rule, request)]

    denies = [rule for rule in matching if rule.effect == "deny"]
    if denies:
        return decide("deny", "DENY_EXPLICIT_RULE", _most_specific(denies).id)

    allows = [rule for rule in matching if rule.effect == "allow"]
    if allows:
        return decide("allow", "ALLOW_RULE", _most_specific(allows).id)

    return decide("deny", "DENY_DEFAULT", None)


def explain(revision: PolicyRevision, request: Request) -> dict[str, Any]:
    """Return the decision plus every rule that matched, for operator `why` output.

    The decision names one rule. An operator narrowing a policy needs to see the others, or they
    will remove the named rule and be surprised that the outcome did not change.
    """
    decision = evaluate(revision, request)
    matching = [rule for rule in revision.rules if rule_matches(rule, request)]
    return {
        "decision": decision.as_dict(),
        "matched_rules": [rule.as_dict() for rule in sorted(matching, key=lambda r: r.id)],
        "budgets": revision.budgets.as_dict(),
        "exceeded_budget": _exceeded_budget(revision, request),
    }
